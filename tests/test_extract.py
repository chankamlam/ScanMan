"""``src/extract.py`` 的单元测试。

设计原则
--------
所有用例都用**内联合成的代码串**，不读真实文件（``tmp_path`` 除外）——
抽取逻辑的正确性不该取决于某台机器上恰好存在的某个文件。文件级行为
（扩展名识别、读失败、二进制、体积超限）用 ``tmp_path`` 现造。

跑法
----
>>> python -m pytest tests/ -v
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from src.extract import (
    ANONYMOUS,
    extract_from_file,
    extract_functions,
    supported_extensions,
)

EXTRACT_SRC = Path(__file__).resolve().parent.parent / "src" / "extract.py"


def names(funcs) -> list[str]:
    """抽出函数名列表，断言时可读性好得多。"""
    return [f.name for f in funcs]


# ---------------------------------------------------------------------------
# 基本抽取
# ---------------------------------------------------------------------------


def test_c_single_function():
    """C 单函数：名字、行号、节点类型、语言都要对。"""
    funcs, ok = extract_functions("int add(int a, int b) {\n    return a + b;\n}\n", "c")
    assert ok is True
    assert len(funcs) == 1
    f = funcs[0]
    assert f.name == "add"
    assert (f.start_line, f.end_line) == (1, 3)
    assert f.node_type == "function_definition"
    assert f.language == "c"
    assert f.depth == 0
    assert f.parent_name is None
    assert f.code == "int add(int a, int b) {\n    return a + b;\n}"


def test_multiple_top_level_functions_in_source_order():
    """多个顶层函数按出现顺序排列。"""
    src = "int a() { return 1; }\nint b() { return 2; }\nint c() { return 3; }\n"
    funcs, ok = extract_functions(src, "c")
    assert ok is True
    assert names(funcs) == ["a", "b", "c"]
    assert [f.start_line for f in funcs] == [1, 2, 3]


def test_python_nested_function_depth_and_parent():
    """嵌套函数记 depth 与 parent_name，且外层排在前面。"""
    src = "def outer():\n    def inner():\n        pass\n    return inner\n"
    funcs, ok = extract_functions(src, "python")
    assert ok is True
    assert names(funcs) == ["outer", "inner"]
    outer, inner = funcs
    assert (outer.depth, outer.parent_name) == (0, None)
    assert (inner.depth, inner.parent_name) == (1, "outer")
    assert (inner.start_line, inner.end_line) == (2, 3)


def test_python_class_method_is_depth_zero():
    """类不是函数，所以类方法的 depth 仍是 0、parent_name 是 None。"""
    src = "class A:\n    def m(self):\n        return 1\n"
    funcs, _ = extract_functions(src, "python")
    assert names(funcs) == ["m"]
    assert (funcs[0].depth, funcs[0].parent_name) == (0, None)
    assert (funcs[0].start_line, funcs[0].end_line) == (2, 3)


def test_cpp_method_name_forms():
    """C++ 三种方法/函数名字都要取对：类内、类外限定名、普通函数。

    类内方法走 ``field_identifier``，类外方法走 ``qualified_identifier``
    （要连类名一起返回 ``A::n``）—— 这两条 declarator 链形态不同，
    是最容易取错名字的地方。
    """
    src = (
        "int plain(int x) { return x; }\n"
        "class A {\n"
        "public:\n"
        "    int m(int x) { return x; }\n"
        "};\n"
        "int A::n(int y) { return y; }\n"
    )
    funcs, ok = extract_functions(src, "cpp")
    assert ok is True
    assert names(funcs) == ["plain", "m", "A::n"]


def test_c_pointer_return_name():
    """指针返回值的 declarator 链更深，名字同样要挖出来。"""
    funcs, ok = extract_functions("static void *get_item(int id) { return 0; }\n", "c")
    assert ok is True
    assert names(funcs) == ["get_item"]


# ---------------------------------------------------------------------------
# 包裹层：装饰器 / 模板
# ---------------------------------------------------------------------------


def test_decorator_wrapper_keeps_decorator_in_code():
    """装饰器包裹层：名字取内层函数，但 code 必须**含装饰器**。

    装饰器常带关键语义（``@app.route`` 说明这是 HTTP 入口），
    丢掉它模型就看不到。
    """
    src = '@app.route("/x")\ndef handler(a):\n    return a\n'
    funcs, ok = extract_functions(src, "python")
    assert ok is True
    assert names(funcs) == ["handler"]
    f = funcs[0]
    assert f.node_type == "decorated_definition"
    assert f.code.startswith('@app.route("/x")')
    assert (f.start_line, f.end_line) == (1, 3)


def test_template_wrapper_keeps_template_in_code():
    """C++ 模板包裹层：code 必须含 ``template<...>``，否则参数类型会变得无意义。"""
    src = "template<class T>\nT maxv(T a, T b) { return a > b ? a : b; }\n"
    funcs, ok = extract_functions(src, "cpp")
    assert ok is True
    assert names(funcs) == ["maxv"]
    f = funcs[0]
    assert f.node_type == "template_declaration"
    assert f.code.startswith("template<class T>")
    assert (f.start_line, f.end_line) == (1, 2)


def test_template_class_is_not_a_function():
    """模板类里没有函数本体时，包裹层不该被当成函数。"""
    src = "template<class T>\nclass Holder {\n    T v;\n};\n"
    funcs, ok = extract_functions(src, "cpp")
    assert ok is True
    assert names(funcs) == []


# ---------------------------------------------------------------------------
# 故意不收的节点（设计取舍，写成测试固定住）
# ---------------------------------------------------------------------------


def test_ts_interface_signature_excluded():
    """TS 接口里没有函数体的方法签名不是函数，只有类里的实现才收。"""
    src = (
        "interface I { m(): void; }\n"
        "abstract class B { abstract n(): void; }\n"
        "class C { m(): void {} }\n"
        "function g(): void {}\n"
    )
    funcs, ok = extract_functions(src, "typescript")
    assert ok is True
    assert names(funcs) == ["m", "g"]


def test_js_arrow_function_excluded():
    """箭头函数是匿名的，本期不收（靠赋值反推命名误判率高）。"""
    src = (
        "const h = (x) => x * 2;\n"
        "const k = function (y) { return y; };\n"
        "function f() { return 1; }\n"
    )
    funcs, ok = extract_functions(src, "javascript")
    assert ok is True
    assert names(funcs) == ["f"]


def test_js_class_method_and_generator():
    """JS 类方法与生成器函数都要收（各自的节点类型不同）。"""
    src = "class C { m(x) { return x; } }\nfunction* g() { yield 1; }\n"
    funcs, ok = extract_functions(src, "javascript")
    assert ok is True
    assert names(funcs) == ["m", "g"]
    assert {f.node_type for f in funcs} == {"method_definition", "generator_function_declaration"}


def test_php_top_level_and_method():
    """PHP 顶层函数与类方法分属两种节点类型。"""
    src = (
        "<?php\n"
        "function top($x) { return $x; }\n"
        "class C {\n"
        "    public function meth($y) { return $y; }\n"
        "}\n"
    )
    funcs, ok = extract_functions(src, "php")
    assert ok is True
    assert names(funcs) == ["top", "meth"]
    assert [f.start_line for f in funcs] == [2, 4]


# ---------------------------------------------------------------------------
# 语法错误容错
# ---------------------------------------------------------------------------


def test_syntax_error_discards_functions_inside_error_region():
    """错误恢复会配错花括号、产出跨函数的假 span，这类函数必须丢弃。

    输入是"未闭合的类"：``good`` 在出错点之前（保留），
    类内 ``m`` 与 ``free_fn`` 都落在 ERROR 区间里（丢弃、计数）。
    丢弃是**静默**的，所以计数必须能对上，否则会让人误以为文件里就这么多函数。
    """
    src = (
        "int good() { return 1; }\n"
        "class A {\n"
        "  void m() {}\n"
        "int free_fn() { return 2; }\n"
    )
    funcs, ok, discarded = _extract_with_discard_count(src, "cpp")
    assert ok is False
    assert names(funcs) == ["good"]
    assert discarded == 2


def test_syntax_error_without_overlap_keeps_functions():
    """普通的语法错误不该误伤——没和 ERROR 相交的函数照样收。"""
    src = "int good(void) { return 1; }\n@@@ nonsense @@@\nint other(void) { return 3; }\n"
    funcs, ok = extract_functions(src, "c")
    assert ok is False
    assert names(funcs) == ["good", "other"]


def test_never_returns_box_overlapping_error_nodes():
    """不变式：返回的每个函数都不与任何 ERROR 区间相交。

    这是"不把垃圾喂给模型"的底线保证，比逐个用例的期望值更值得钉死。
    """
    from src.extract import (
        FUNCTION_TYPES,
        _collect_error_ranges,
        _load_parser,
        _merge_ranges,
    )

    src = (
        "int a() { return 1; }\n"
        "class A {\n"
        "  void m() {}\n"
        "int free_fn() { return 2; }\n"
        "@@@\n"
        "int b() { return 3; }\n"
    )
    raw = src.encode("utf-8")
    tree = _load_parser("cpp").parse(raw)
    starts, ends = _merge_ranges(_collect_error_ranges(tree.root_node, []))

    funcs, _ = extract_functions(src, "cpp")
    for f in funcs:
        for s, e in zip(starts, ends):
            assert f.end_byte <= s or f.start_byte >= e, (
                f"函数 {f.name} [{f.start_byte},{f.end_byte}) 与 ERROR [{s},{e}) 相交"
            )
    assert FUNCTION_TYPES  # 保持导入被使用，避免 linter 误删


# ---------------------------------------------------------------------------
# 边界输入
# ---------------------------------------------------------------------------


def test_empty_source():
    """空输入不报错、零函数。"""
    funcs, ok = extract_functions("", "python")
    assert funcs == []
    assert ok is True


def test_crlf_line_numbers():
    """CRLF 换行时行号仍按行数算（``\\r`` 不该把行号带偏）。"""
    src = "int a() {\r\n    return 1;\r\n}\r\nint b() {\r\n    return 2;\r\n}\r\n"
    funcs, ok = extract_functions(src, "c")
    assert ok is True
    assert names(funcs) == ["a", "b"]
    assert [(f.start_line, f.end_line) for f in funcs] == [(1, 3), (4, 6)]


def test_multibyte_prefix_line_and_byte_offsets():
    """多字节字符：行号按 ``\\n`` 数，字节偏移按 UTF-8 算，两者互不干扰。

    这行号以前是从 tree-sitter 的 ``point.row`` 拿的，而读 ``.row``
    会触发非确定性段错误（见 ``test_no_point_api_usage``），
    现在改由字节偏移推导 —— 这个用例同时守住"推导结果与 row 语义一致"。
    """
    prefix = "# 中文注释\n"
    src = prefix + "def f():\n    pass\n"
    funcs, ok = extract_functions(src, "python")
    assert ok is True
    assert names(funcs) == ["f"]
    f = funcs[0]
    assert f.start_line == 2
    assert f.start_byte == len(prefix.encode("utf-8"))
    assert f.code == "def f():\n    pass"


def test_non_utf8_bytes_do_not_crash():
    """非 UTF-8 文件（如 GBK）：行号与字节偏移仍准确，文本用替换符兜底。"""
    raw = "int a() { /* 中文 */ return 1; }\n".encode("gbk")
    f = _first_from_bytes(raw, "c")
    assert f.name == "a"
    assert f.start_line == 1
    assert f.start_byte == 0


def test_anonymous_function_gets_placeholder():
    """取不到名字时给占位符而不是抛异常（扫描不能因为一个怪函数就中断）。"""
    # K&R 风格声明会让 declarator 链落到非名字型节点上
    funcs, ok = extract_functions("int f(a, b) int a; int b; { return a + b; }\n", "c")
    assert ok is True
    assert len(funcs) == 1
    assert funcs[0].name != ""  # 要么是 f，要么是 ANONYMOUS，总之不能是空串
    assert ANONYMOUS  # 占位符常量对外可见


# ---------------------------------------------------------------------------
# 文件级行为
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("a.c", "c"),
        ("a.h", "c"),  # 头文件无法区分 C/C++，统一按 C 处理
        ("a.cpp", "cpp"),
        ("a.cc", "cpp"),
        ("a.hpp", "cpp"),
        ("a.py", "python"),
        ("a.pyi", "python"),
        ("a.js", "javascript"),
        ("a.mjs", "javascript"),
        ("a.jsx", "javascript"),
        ("a.ts", "typescript"),
        ("a.tsx", "tsx"),
        ("a.php", "php"),
        ("a.phtml", "php"),
        ("a.txt", None),
        ("noext", None),
    ],
)
def test_language_detection_by_extension(tmp_path, filename, expected):
    """扩展名 → 语言键，大小写不敏感。"""
    p = tmp_path / filename
    p.write_text("x", encoding="utf-8")
    assert extract_from_file(p).language == expected


def test_extract_from_file_roundtrip_offsets(tmp_path):
    """文件级：``code`` 必须等于按字节区间从原文件切出来的那一段。

    这条保证了 ``start_byte``/``end_byte`` 对**原始文件**有效，
    扫描报告里的行号才能和编辑器对上。
    """
    src = (
        "// 第一行是中文注释\n"
        "int a() {\n"
        "    return 1;\n"
        "}\n"
        "int b() {\n"
        "    return 2;\n"
        "}\n"
    )
    p = tmp_path / "sample.c"
    # 显式写字节而不是 write_text：Windows 上 write_text 会把 \n 换行成 \r\n，
    # 那样同一个测试在 Windows 和 Linux 上跑的就不是同一份输入了
    p.write_bytes(src.encode("utf-8"))
    raw = p.read_bytes()

    r = extract_from_file(p)
    assert r.error is None
    assert r.parse_ok is True
    assert names(r.functions) == ["a", "b"]
    # 中文注释占一行（多字节），函数行号仍按行数算
    assert [(f.start_line, f.end_line) for f in r.functions] == [(2, 4), (5, 7)]
    assert r.num_bytes == len(raw)
    for f in r.functions:
        assert f.code == raw[f.start_byte:f.end_byte].decode("utf-8")


@pytest.mark.parametrize(
    "content,filename,expected_error",
    [
        (b"hello", "note.txt", "no_language"),
        (b"int a;\x00\x01", "bin.c", "binary"),
    ],
)
def test_extract_from_file_reports_reason_instead_of_raising(
    tmp_path, content, filename, expected_error
):
    """文件有问题时**不抛异常**，而是把原因写进 ``error`` 字段继续扫下一个文件。"""
    p = tmp_path / filename
    p.write_bytes(content)
    r = extract_from_file(p)
    assert r.error == expected_error
    assert r.functions == []
    assert r.parse_ok is False


def test_extract_from_file_too_large(tmp_path):
    """超过体积上限就不解析（一般是打包产物或数据集，不是源码）。"""
    p = tmp_path / "big.c"
    p.write_text("int a() { return 1; }\n" * 100, encoding="utf-8")
    r = extract_from_file(p, max_bytes=50)
    assert r.error == "too_large"
    assert r.functions == []
    assert r.num_bytes > 50


def test_extract_from_file_missing_path(tmp_path):
    """文件不存在也不能抛 —— 扫描时目录可能正在被改动。"""
    r = extract_from_file(tmp_path / "does_not_exist.c")
    assert r.error is not None
    assert r.error.startswith("read_error")
    assert r.functions == []


def test_empty_file_on_disk(tmp_path):
    """空文件：零函数、无错误。"""
    p = tmp_path / "empty.py"
    p.write_text("", encoding="utf-8")
    r = extract_from_file(p)
    assert r.functions == []
    assert r.error is None
    assert r.num_bytes == 0


def test_supported_extensions_covers_all_families():
    """扩展名清单对外可见（扫描器要靠它过滤文件）。"""
    exts = supported_extensions()
    assert exts == sorted(exts)
    for e in (".c", ".cpp", ".py", ".js", ".ts", ".tsx", ".php"):
        assert e in exts


# ---------------------------------------------------------------------------
# 序列化
# ---------------------------------------------------------------------------


def test_to_dict_can_omit_code():
    """``include_code=False`` 用于给扫描报告瘦身（函数多时体积差很多）。"""
    funcs, _ = extract_functions("int a() { return 1; }\n", "c")
    full = funcs[0].to_dict()
    lean = funcs[0].to_dict(include_code=False)
    assert full["code"] == "int a() { return 1; }"
    assert "code" not in lean
    assert lean["name"] == "a"
    assert set(lean) | {"code"} == set(full)


# ---------------------------------------------------------------------------
# 回归守卫
# ---------------------------------------------------------------------------


def test_no_point_api_usage():
    """**回归守卫**：``src/extract.py`` 不得再出现 ``start_point`` / ``end_point``。

    本机 py312 环境（tree-sitter 0.26.0 + tree-sitter-python 0.25.0）下，
    读 ``Node.start_point.row`` 会触发**非确定性段错误**：同样的输入、
    同一份代码，每轮崩在哪个文件、哪一行都不一样 —— 排查成本极高。
    实测 ``start_point`` 对象本身和 ``.column`` 都安全，只有 ``.row`` 会崩，
    属于绑定层缺陷，与本项目无关。

    行号现已改为由字节偏移推导（见 ``_line_of``），因此这条守卫用 AST
    检查属性访问，而不是文本匹配 —— 文档里可以放心地继续说明这个坑。
    """
    tree = ast.parse(EXTRACT_SRC.read_text(encoding="utf-8"))
    offenders = [
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr in {"start_point", "end_point"}
    ]
    assert not offenders, f"不得使用 {offenders}：读 .row 会段错误，行号请用 _line_of"


# ---------------------------------------------------------------------------
# 测试内部小工具
# ---------------------------------------------------------------------------


def _extract_with_discard_count(src: str, language: str):
    """走内部接口拿"被丢弃数" —— 公开接口 ``extract_functions`` 不返回它。"""
    from src.extract import _extract_from_source

    return _extract_from_source(src.encode("utf-8"), language)


def _first_from_bytes(raw: bytes, language: str):
    """直接喂原始字节（模拟非 UTF-8 文件），返回第一个函数。"""
    from src.extract import _extract_from_source

    funcs, _ok, _disc = _extract_from_source(raw, language)
    assert funcs, "没有抽到任何函数"
    return funcs[0]
