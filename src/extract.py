"""函数抽取模块：用 tree-sitter 从源码中切出函数。

为什么需要这个模块
------------------
模型（``VulnClassifier``）一次前向只对**一段代码**输出**一个**结论 ——
``src/models.py`` 用的是 [CLS] 池化，整段输入被压成一个向量。所以
"这个文件里有几个函数有漏洞"这种问题**模型自己答不了**，必须由外部
先抽出函数、逐个推理、再聚合。本模块负责其中的第一步。

为什么用 tree-sitter 而不是正则 / ast
-------------------------------------
- 正则切不准：函数体里的花括号、字符串里的 ``"{"``、嵌套定义都会骗过它。
- 标准库 ``ast`` 只能解析 Python，覆盖不了 C / C++ / JS / TS / PHP。
- tree-sitter 是增量式解析器，**自带语法错误恢复**：遇到坏代码不会抛异常，
  而是把无法解析的部分标成 ``ERROR`` 节点，其余部分照常给出正确的树。
  这对扫描"别人的项目"是刚需 —— 那些代码不保证能编译。

支持的语言
----------
============  ================================================================
语言键         扩展名
============  ================================================================
``c``         .c .h
``cpp``       .cc .cpp .cxx .hpp .hh .hxx
``python``    .py .pyw .pyi
``javascript`` .js .mjs .cjs .jsx
``typescript`` .ts
``tsx``       .tsx
``php``       .php .php3 .php5 .phtml
============  ================================================================

新增语言只需改两处：``LANGUAGE_BY_EXT`` 和 ``FUNCTION_TYPES``（外加
``_PARSER_MODULES`` 里登记语法包），不用动抽取逻辑。

两个容易踩的坑（本模块已规避）
------------------------------
1. **绝不读 ``Node.start_point`` / ``Node.end_point``**：本机 py312 环境下
   （tree-sitter 0.26.0 + tree-sitter-python 0.25.0），读 ``start_point.row``
   会**非确定性段错误**（access violation：同样的输入，同一份代码，
   每次崩在哪个文件/哪一行都不一样）。实测 ``start_point`` 对象本身、
   以及 ``.column`` 都安全，**只有 ``.row`` 会崩** —— 属于绑定层缺陷，
   与本项目代码无关。因此本模块的行号**一律由字节偏移推导**（数 ``\\n``），
   既绕开该缺陷，又不绑定 tree-sitter 版本，且与 ``row`` 语义严格一致
   （行同样以 ``\\n`` 分隔）。顺带也避开了 ``column`` 那个坑：它是
   **行内字节偏移**，有中文注释时和编辑器的字符列号对不上。
2. **非 UTF-8 文件**：文件以 bytes 为真相源解析（而非先 decode 再解析），
   这样 ``start_byte``/``end_byte`` 始终指向**原始文件**的字节位置。
   GBK 等编码的文件不会崩，行号与字节偏移都准确，只有 ``code`` 文本里
   可能出现替换符。

输出示例
--------
>>> funcs, ok = extract_functions("int add(int a){return a;}", "c")
>>> funcs[0].name, funcs[0].start_line, funcs[0].end_line
('add', 1, 1)
"""

from __future__ import annotations

import os
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# ----------------------------------------------------------------------------
# 语言注册表（扩展点）
# ----------------------------------------------------------------------------

#: 扩展名 → 语言键。``.h`` 一律归 C —— 头文件无法从扩展名区分 C / C++，
#: 选 C 是因为 C 的语法是 C++ 的子集，纯 C 头文件能被正确解析；
#: 反之用 C++ 解析器去解析带 C 特有写法的头文件反而容易出 ERROR。
LANGUAGE_BY_EXT: dict[str, str] = {
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".py": "python",
    ".pyw": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".php": "php",
    ".php3": "php",
    ".php5": "php",
    ".phtml": "php",
}

#: 语言键 → 函数定义的语法节点类型。
#:
#: 各语言的注意点：
#:
#: - **C / C++ / Python**：都只有 ``function_definition``。类内联方法和类方法
#:   用的也是这个节点（C++ 没有 ``method_definition``，别照抄 JS）。
#: - **JS / TS**：``method_definition`` 用于类方法，且名字字段是
#:   ``property_identifier`` 而非 ``identifier``（本模块统一走 ``name`` 字段，
#:   不关心具体类型）。
#:
#:   这里**故意不收** ``arrow_function`` / ``function_expression``：它们是
#:   匿名的，硬要给个名字只能靠赋值语句反推（``const f = () => ...``），
#:   误判率高（``obj.handler = async () => ...`` 该叫什么？）。属于后续扩展点。
#: - **TS**：``method_signature`` / ``function_signature`` 是接口里**没有函数体**
#:   的声明，不属于函数，因此不登记（天然被排除）。
#: - **PHP**：类方法是 ``method_declaration``，顶层函数是 ``function_definition``。
FUNCTION_TYPES: dict[str, frozenset[str]] = {
    "c": frozenset({"function_definition"}),
    "cpp": frozenset({"function_definition"}),
    "python": frozenset({"function_definition"}),
    "javascript": frozenset({
        "function_declaration",
        "generator_function_declaration",
        "method_definition",
    }),
    "typescript": frozenset({
        "function_declaration",
        "generator_function_declaration",
        "method_definition",
    }),
    "tsx": frozenset({
        "function_declaration",
        "generator_function_declaration",
        "method_definition",
    }),
    "php": frozenset({"function_definition", "method_declaration"}),
}

#: 包裹型节点：函数本体是它的子节点，但**代码片段必须包含包裹层**。
#:
#: - ``template_declaration``（C++）：``template<class T> T max(T a, T b) {...}``
#:   丢掉 ``template<...>`` 的话，模型看到的就是一段类型不明的普通函数。
#: - ``decorated_definition``（Python）：``@app.route("/x")`` 这类装饰器往往
#:   携带关键语义（这是不是一个 HTTP 入口），必须保留。
WRAPPER_TYPES: frozenset[str] = frozenset({
    "template_declaration",
    "decorated_definition",
})

#: 语言键 → (语法包模块名, 取 Language capsule 的函数名)。
#:
#: 语法包必须按语言分开安装（PyPI 上没有 all-in-one 的 ``tree-sitter-languages``）。
#: 注意 PHP 和 TypeScript 的取用函数**不叫** ``language``：
#: PHP 是 ``language_php``，TypeScript 因支持 TS/TSX 两套语法而暴露
#: ``language_typescript`` / ``language_tsx``。
_PARSER_MODULES: dict[str, tuple[str, str]] = {
    "c": ("tree_sitter_c", "language"),
    "cpp": ("tree_sitter_cpp", "language"),
    "python": ("tree_sitter_python", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "php": ("tree_sitter_php", "language_php"),
}

#: 名字型节点：C/C++ 沿 declarator 链下钻到底后，期望落在这些类型上。
_NAME_LIKE_TYPES: frozenset[str] = frozenset({
    "identifier",
    "field_identifier",
    "type_identifier",
    "namespace_identifier",
    "qualified_identifier",
    "operator_name",
    "destructor_name",
    "name",
    "property_identifier",
})

#: 单文件体积上限（字节）。超过就不解析 —— 一般是打包产物或数据集，不是源码。
MAX_FILE_BYTES: int = 2_000_000

#: 取不到名字时的占位符（不抛异常，保证扫描不中断）
ANONYMOUS: str = "<anonymous>"


# ----------------------------------------------------------------------------
# 数据结构
# ----------------------------------------------------------------------------


@dataclass
class FunctionInfo:
    """抽到的一个函数。

    属性
    ----
    name : str
        函数名。C++ 类外方法会带类名限定（``A::n``）；取不到时为 ``<anonymous>``。
    start_line, end_line : int
        1-based 行号，**闭区间**（``end_line`` 指向函数体最后一行）。
        解析出多字节字符时行号依然准确（行号与字节无关）。
    start_byte, end_byte : int
        UTF-8 字节偏移，半开区间 ``[start_byte, end_byte)``，
        指向**原始文件**的位置。
    code : str
        完整函数源码。装饰器 / ``template`` 包裹层已包含在内。
    node_type : str
        触发的语法节点类型，便于排查"这个名字为什么没抽出来"。
    language : str
        语言键。
    depth : int
        嵌套深度，0 = 顶层。类方法算 0（类不是函数）。
    parent_name : str | None
        外层函数名；顶层函数为 None。
    """

    name: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    code: str
    node_type: str
    language: str
    depth: int
    parent_name: str | None = None

    def to_dict(self, include_code: bool = True) -> dict:
        """转成可 JSON 序列化的字典（``include_code=False`` 时省略源码，用于瘦身）。"""
        d = {
            "name": self.name,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
            "node_type": self.node_type,
            "language": self.language,
            "depth": self.depth,
            "parent_name": self.parent_name,
        }
        if include_code:
            d["code"] = self.code
        return d


@dataclass
class FileExtraction:
    """一个文件的抽取结果。

    属性
    ----
    path : str
        文件路径（原样保存，便于报告里显示）。
    language : str | None
        识别出的语言；扩展名不认识时为 None。
    parse_ok : bool
        tree-sitter 是否零错误解析完（``False`` 表示文件里有语法错误，
        但通常仍能抽出错误区之外的那些函数）。
    functions : list[FunctionInfo]
        抽到的函数，按出现顺序排列。
    num_bytes : int
        文件字节数。
    functions_discarded : int
        因与 ``ERROR`` 区域相交而被丢弃的函数个数。**这个计数必须对外可见** ——
        丢弃是正确决定（错误恢复会配错花括号产生假 span，不能喂给模型），
        但静默丢弃会让人误以为文件里只有这么几个函数。
    error : str | None
        文件级错误原因（读失败 / 体积超限 / 二进制 / 扩展名不认识），
        正常时为 None。注意它和 ``parse_ok=False`` 是两回事：
        前者是"根本没解析"，后者是"解析了但有语法错"。
    """

    path: str
    language: str | None
    parse_ok: bool
    functions: list[FunctionInfo]
    num_bytes: int = 0
    functions_discarded: int = 0
    error: str | None = None


# ----------------------------------------------------------------------------
# 解析器加载（单例缓存）
# ----------------------------------------------------------------------------


@lru_cache(maxsize=None)
def _load_parser(language: str):
    """加载并缓存某语言的 Parser。

    参数
    ----
    language : str
        语言键，必须在 ``FUNCTION_TYPES`` 里。

    返回
    ----
    tree_sitter.Parser

    说明
    ----
    用 ``lru_cache`` 做单例：语法包的加载和 ``Language`` 构造都有开销，
    扫描上万文件时不能每次重来。``Parser`` 本身不是线程安全的，
    但本项目是单线程扫描，够用。
    """
    from tree_sitter import Language, Parser

    if language not in _PARSER_MODULES:
        raise ValueError(
            f"不支持的语言：{language!r}。可选：{sorted(_PARSER_MODULES)}"
        )
    module_name, capsule_fn = _PARSER_MODULES[language]
    try:
        module = __import__(module_name)
    except ImportError as exc:  # pragma: no cover - 依赖缺失时的兜底
        pkg = module_name.replace("_", "-")
        raise RuntimeError(
            f"缺少语法包 {module_name}，请先安装：pip install {pkg}"
        ) from exc
    return Parser(Language(getattr(module, capsule_fn)()))


# ----------------------------------------------------------------------------
# 内部工具
# ----------------------------------------------------------------------------


def _node_text(node, source: bytes) -> str:
    """取节点的源码文本。

    参数
    ----
    node : tree_sitter.Node
    source : bytes
        解析用的**原始字节**。

    说明
    ----
    刻意不用 ``node.text``：该属性在不同 tree-sitter 版本里返回 bytes 或 str
    不一致（本机 0.26.0 实测返回 bytes），直接从字节源切片再解码最稳定。
    非 UTF-8 部分用 ``errors="replace"`` 兜底，绝不抛异常。
    """
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _newline_offsets(source: bytes) -> list[int]:
    """收集源码里每个 ``\\n`` 的字节偏移（升序）。

    用 ``bytes.find`` 逐跳扫描而不是 ``for i, b in enumerate(source)``：
    前者在 C 层找字节，后者每个字节都要回一趟 Python，大文件上差一个量级。

    参数
    ----
    source : bytes
        解析用的原始字节。

    返回
    ----
    list[int]
        换行符的字节偏移，升序；无换行时为空列表。
    """
    offsets: list[int] = []
    pos = source.find(b"\n")
    while pos != -1:
        offsets.append(pos)
        pos = source.find(b"\n", pos + 1)
    return offsets


def _line_of(offset: int, newlines: list[int]) -> int:
    """字节偏移 → 1-based 行号。

    语义与 tree-sitter 的 ``point.row + 1`` **严格一致**：行由 ``\\n`` 分隔，
    与多字节字符无关，所以中文注释不会让行号错位。

    做法是数"该偏移之前有多少个换行符"：偏移落在第 n 个换行之后，
    就说明它前面有 n 个换行，即处于第 n+1 行。

    注意 ``end_byte`` 是**半开区间**的右端（指向最后一个字符的下一格），
    恰好等于行尾换行的位置时算作**上一行的结尾** —— 这正是 tree-sitter
    ``end_point`` 的约定，所以函数末行号不会多算一行。

    参数
    ----
    offset : int
        字节偏移。
    newlines : list[int]
        ``_newline_offsets`` 的结果。

    返回
    ----
    int
        1-based 行号。
    """
    return bisect_left(newlines, offset) + 1


def _collect_error_ranges(node, acc: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """递归收集所有 ``ERROR`` 节点的字节区间。"""
    if node.type == "ERROR":
        acc.append((node.start_byte, node.end_byte))
    for child in node.children:
        _collect_error_ranges(child, acc)
    return acc


def _merge_ranges(ranges: list[tuple[int, int]]) -> tuple[list[int], list[int]]:
    """把可能嵌套/重叠的区间合并成互不重叠的有序区间。

    返回
    ----
    tuple[list[int], list[int]]
        ``(starts, ends)``，按起点升序，且任意两区间不相交，
        供 ``_overlaps_any`` 做二分查找。

    说明
    ----
    树节点的 span 天然是"嵌套或互斥"的，但 ``ERROR`` 节点之间可能嵌套
    （一个 ERROR 套着另一个），所以合并一次更稳妥。
    """
    if not ranges:
        return [], []
    ranges = sorted(ranges)
    starts = [ranges[0][0]]
    ends = [ranges[0][1]]
    for s, e in ranges[1:]:
        if s <= ends[-1]:  # 与上一个区间重叠/相接 → 合并
            ends[-1] = max(ends[-1], e)
        else:
            starts.append(s)
            ends.append(e)
    return starts, ends


def _overlaps_any(start: int, end: int, starts: list[int], ends: list[int]) -> bool:
    """判断 ``[start, end)`` 是否与任一区间相交（二分查找，O(log n)）。"""
    if not starts:
        return False
    i = bisect_right(starts, start)
    # 前一个区间可能跨越 start
    if i > 0 and ends[i - 1] > start:
        return True
    # 后一个区间的起点可能落在 [start, end) 内
    return i < len(starts) and starts[i] < end


def _c_family_name(fn_node, source: bytes) -> str:
    """从 C / C++ 的 ``function_definition`` 里挖出函数名。

    为什么不能统一走 ``name`` 字段
    ------------------------------
    C / C++ 的函数名**不在** ``name`` 字段里，而是藏在 ``declarator`` 链深处::

        static void *get_item(int id) {...}
        function_definition
          └─ pointer_declarator        (declarator=)
               └─ function_declarator  (declarator=)
                    └─ identifier      (declarator=)  ← "get_item"

    类方法链更短（``function_declarator`` → ``field_identifier``），
    类外方法会遇到 ``qualified_identifier``（``A::n``）。

    做法：沿 ``declarator`` 字段一路下钻，直到某个节点没有 ``declarator``
    子字段为止。若落点不是"名字型"节点（极少数古怪声明，如函数指针返回值），
    就在它的子树里找最后一个 identifier 兜底。
    """
    node = fn_node.child_by_field_name("declarator")
    if node is None:
        return ANONYMOUS
    while True:
        inner = node.child_by_field_name("declarator")
        if inner is None:
            break
        node = inner
    if node.type in _NAME_LIKE_TYPES:
        return _node_text(node, source).strip() or ANONYMOUS
    # 兜底：子树里最后一个名字型节点
    found = None
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type in _NAME_LIKE_TYPES:
            found = cur
        stack.extend(cur.children)
    return _node_text(found, source).strip() if found else ANONYMOUS


def _name_of(node, language: str, source: bytes) -> str:
    """取函数名。优先 ``name`` 字段，C/C++ 走 declarator 链。"""
    named = node.child_by_field_name("name")
    if named is not None:
        return _node_text(named, source).strip() or ANONYMOUS
    if language in ("c", "cpp"):
        return _c_family_name(node, source)
    return ANONYMOUS


def _inner_function(wrapper, fn_types: frozenset[str]):
    """在包裹节点（``template_declaration`` / ``decorated_definition``）里找函数本体。

    注意别依赖字段名：``decorated_definition`` 的内层是 ``definition=`` 字段，
    而 ``template_declaration`` 的内层**没有字段名**。所以按"第一个函数类型
    的子节点"来找，两种都覆盖。

    找不到就返回 None（例如 ``template<class T> class A {...}`` 是模板类，
    不是函数），此时调用方会对包裹节点做常规下钻。
    """
    for child in wrapper.children:
        if child.type in fn_types:
            return child
    return None


def _walk(
    node,
    language: str,
    source: bytes,
    fn_types: frozenset[str],
    depth: int,
    parent_name: str | None,
    starts: list[int],
    ends: list[int],
    newlines: list[int],
    out: list[FunctionInfo],
) -> int:
    """深度优先遍历语法树，收集函数节点。

    返回
    ----
    int
        因与 ERROR 区域相交而丢弃的函数个数。
    """
    discarded = 0
    for child in node.children:
        name = None

        if child.type in WRAPPER_TYPES:
            inner = _inner_function(child, fn_types)
            if inner is not None:
                # span 取包裹节点（保住 @装饰器 / template<...>），名字取内层函数
                name = _name_of(inner, language, source)
                start, end = child.start_byte, child.end_byte
                if _overlaps_any(start, end, starts, ends):
                    discarded += 1
                else:
                    out.append(FunctionInfo(
                        name=name,
                        start_line=_line_of(start, newlines),
                        end_line=_line_of(end, newlines),
                        start_byte=start,
                        end_byte=end,
                        code=_node_text(child, source),
                        node_type=child.type,
                        language=language,
                        depth=depth,
                        parent_name=parent_name,
                    ))
                # 只递归内层函数的子节点 —— 递归包裹节点会把内层函数重复收一次
                discarded += _walk(inner, language, source, fn_types,
                                   depth + 1, name, starts, ends, newlines, out)
                continue
            # 包裹层里没有函数（模板类等）→ 落到下面做常规下钻

        if child.type in fn_types:
            name = _name_of(child, language, source)
            start, end = child.start_byte, child.end_byte
            if _overlaps_any(start, end, starts, ends):
                discarded += 1
            else:
                out.append(FunctionInfo(
                    name=name,
                    start_line=_line_of(start, newlines),
                    end_line=_line_of(end, newlines),
                    start_byte=start,
                    end_byte=end,
                    code=_node_text(child, source),
                    node_type=child.type,
                    language=language,
                    depth=depth,
                    parent_name=parent_name,
                ))
            discarded += _walk(child, language, source, fn_types,
                               depth + 1, name, starts, ends, newlines, out)
            continue

        discarded += _walk(child, language, source, fn_types,
                           depth, parent_name, starts, ends, newlines, out)
    return discarded


# ----------------------------------------------------------------------------
# 对外接口
# ----------------------------------------------------------------------------


def detect_language(path: str | os.PathLike) -> str | None:
    """按扩展名识别语言。

    参数
    ----
    path : str | os.PathLike
        文件路径（只看扩展名，不读内容）。

    返回
    ----
    str | None
        语言键；扩展名不在 ``LANGUAGE_BY_EXT`` 里时返回 None。
    """
    return LANGUAGE_BY_EXT.get(Path(path).suffix.lower())


def supported_extensions() -> list[str]:
    """返回全部受支持的扩展名（供扫描器过滤文件用）。"""
    return sorted(LANGUAGE_BY_EXT)


def _extract_from_source(
    source: bytes, language: str
) -> tuple[list[FunctionInfo], bool, int]:
    """真正的抽取实现：**以字节为真相源**。

    参数
    ----
    source : bytes
        解析用的原始字节。
    language : str
        语言键。

    返回
    ----
    tuple[list[FunctionInfo], bool, int]
        ``(函数列表, parse_ok, 被丢弃的函数数)``。
    """
    parser = _load_parser(language)
    tree = parser.parse(source)
    root = tree.root_node
    parse_ok = not root.has_error

    starts, ends = _merge_ranges(_collect_error_ranges(root, []))
    newlines = _newline_offsets(source)
    fn_types = FUNCTION_TYPES[language]

    out: list[FunctionInfo] = []
    discarded = _walk(root, language, source, fn_types, 0, None,
                      starts, ends, newlines, out)
    # 按出现顺序排列（外层函数起点早于内层，天然满足"先外后内"）
    out.sort(key=lambda f: (f.start_byte, -f.end_byte))
    return out, parse_ok, discarded


def extract_functions(code: str, language: str) -> tuple[list[FunctionInfo], bool]:
    """从一段源码文本中抽取所有函数。

    参数
    ----
    code : str
        源码文本。
    language : str
        语言键，见 ``FUNCTION_TYPES``。

    返回
    ----
    tuple[list[FunctionInfo], bool]
        ``(函数列表, parse_ok)``。``parse_ok=False`` 表示源码有语法错误，
        但错误区**之外**的函数仍然会被正常抽出。

    说明
    ----
    这里把字符串编码成 UTF-8 再解析（``extract_from_file`` 走的是
    直接传原始字节的内部函数，字节偏移对应原始文件）。因此对
    **已经是字符串**的输入，``start_byte`` 是"这段字符串的 UTF-8 编码"里的
    偏移，而不是某个文件里的偏移。

    与 ``ERROR`` 区域相交的函数会被丢弃 —— tree-sitter 的错误恢复有时会
    配错花括号，产出跨函数的假 span，那种"函数"喂给模型只会制造噪声。
    丢弃是静默的（本函数不返回计数），文件级调用请看
    ``extract_from_file(...).functions_discarded``。

    示例
    ----
    >>> funcs, ok = extract_functions("int add(int a){return a;}", "c")
    >>> funcs[0].name
    'add'
    """
    functions, parse_ok, _discarded = _extract_from_source(
        code.encode("utf-8"), language
    )
    return functions, parse_ok


def extract_from_file(
    path: str | os.PathLike,
    max_bytes: int = MAX_FILE_BYTES,
) -> FileExtraction:
    """抽取单个文件里的所有函数。

    参数
    ----
    path : str | os.PathLike
        文件路径。
    max_bytes : int
        体积上限（字节），超过则跳过不解析。

    返回
    ----
    FileExtraction
        抽不到函数或文件有问题时**不抛异常**，而是把原因写进
        ``error`` 字段（扫描整个项目时，一个坏文件不应该中断整轮扫描）。
    """
    p = Path(path)
    language = detect_language(p)

    try:
        raw = p.read_bytes()
    except OSError as exc:
        return FileExtraction(
            path=str(p), language=language, parse_ok=False, functions=[],
            error=f"read_error: {exc}",
        )

    num_bytes = len(raw)

    if language is None:
        return FileExtraction(
            path=str(p), language=None, parse_ok=False, functions=[],
            num_bytes=num_bytes, error="no_language",
        )
    if num_bytes > max_bytes:
        return FileExtraction(
            path=str(p), language=language, parse_ok=False, functions=[],
            num_bytes=num_bytes, error="too_large",
        )
    # NUL 字节是二进制文件的强信号（源码里不该出现）
    if b"\x00" in raw:
        return FileExtraction(
            path=str(p), language=language, parse_ok=False, functions=[],
            num_bytes=num_bytes, error="binary",
        )

    functions, parse_ok, discarded = _extract_from_source(raw, language)
    return FileExtraction(
        path=str(p), language=language, parse_ok=parse_ok,
        functions=functions, num_bytes=num_bytes,
        functions_discarded=discarded,
    )
