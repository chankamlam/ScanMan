"""把原始数据集统一成训练用的 JSONL（数据预处理总入口）。

这个脚本是整条流水线的第一步，负责把 CVEfixes 原始数据清洗成统一格式，
并划分成 train / val / test 三份。

支持数据源
----------
============  ================================================================
cvefixes      CVEfixes 1.0.8 函数级衍生版（13k CVE，27 种语言）
bigvul        BigVul，C/C++ 函数级，带 CWE；标签噪声是文献公认的问题
diversevul    DiverseVul，C/C++ 函数级，项目覆盖面比 BigVul 广得多
codexglue     CodeXGLUE defect detection（Devign），C/C++ 函数级
merged        上述四源合并去重（推荐用于单语言场景，见 build_merged 的说明）
============  ================================================================

原始数据用 ``scripts/download_data.py --datasets <名字>`` 下载。

接入新数据集：在下面的 ``BUILDERS`` 里注册一个构建器即可，其余流程
（过滤 / 截断 / 去重 / 分组划分 / 标签编码）都是数据源无关的。

处理流程（6 步）
----------------
    ① 抽取        从 parquet / jsonl 里读出字段，统一成 9 个字段的记录
    ② 长度过滤    丢掉短于 min_code_chars 的碎片（基本没有语义）
    ③ 头尾截断    超过 max_code_chars 的按 6:4 保留头尾
    ④ 去重        按代码内容的 MD5 去重
    ⑤ 分组划分    按 group_id（CVE + commit）分组划分 8:1:1，防止数据泄漏
    ⑥ 标签编码    分类任务把 CWE 字符串换成 0~N 的数字编号，长尾合并成 OTHER

产出（写入 data/processed/）
---------------------------
<source>_detection_{train,val,test}.jsonl    二分类：label 0=安全 1=漏洞
<source>_classification_{train,val,test}.jsonl 多分类：仅漏洞样本，label 为 CWE 类别 id
<source>_detection_label_map.json            二分类标签映射
<source>_classification_label_map.json       类别 id -> CWE 名称
<source>_stats.json                          统计信息（每个 split 的条数、标签分布）

统一字段
--------
id          唯一标识，如 "CVE-2023-4432-vuln" / "CVE-2023-4432-fixed"
code        源码片段（已做头尾截断）
label       检测任务：0/1；分类任务：CWE 类别编号
cwe         原始 CWE 编号，如 "CWE-79"（安全样本为空）
cwe_name    CWE 英文全称
source      数据源标识
language    编程语言
project     所属开源项目
group_id    防泄漏分组键（CVE + commit hash）
code_hash   代码内容的 MD5

用法
----
    python scripts/build_dataset.py --source cvefixes
    python scripts/build_dataset.py --source cvefixes --task detection   # 只构建检测数据
    python scripts/build_dataset.py --source cvefixes --task classification
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import load_config, resolve_path  # noqa: E402
from src.utils import ensure_dir, get_logger, human_int, truncate_code, write_jsonl  # noqa: E402

log = get_logger("build_dataset")

# ---------------------------------------------------------------- 工具函数


def _md5(text: str) -> str:
    """算字符串的 MD5 指纹，用于去重。

    参数
    ----
    text : str
        代码文本。

    返回
    ----
    str
        32 位十六进制字符串。

    说明
    ----
    ``errors="ignore"`` 保证遇到无法解码的字符也不会崩。
    用 MD5 而不是 Python 内置 hash()，是因为内置 hash 每次进程启动都不一样，
    无法跨运行去重。
    """
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()


def _clean_code(code: Any) -> str:
    """清洗代码文本：统一换行符 + 去掉首尾空白。

    参数
    ----
    code : Any
        原始代码，可能是 str、None 或其他类型。

    返回
    ----
    str
        清洗后的代码；非字符串输入返回空串。

    为什么要统一换行符
    ------------------
    Windows 上是 ``\\r\\n``，Linux 上是 ``\\n``，Mac 老版本是 ``\\r``。
    不统一的话，同一段代码在不同平台算出的 MD5 不一样，去重会失效。
    """
    if not isinstance(code, str):
        return ""
    return code.replace("\r\n", "\n").replace("\r", "\n").strip()


def _norm_cwe(raw: Any) -> str:
    """把各种写法的 CWE 统一成 ``'CWE-<数字>'`` 格式。

    参数
    ----
    raw : Any
        原始 CWE 值，可能是 ``'CWE-79'`` / ``'79'`` / ``'cwe_79'`` / None。

    返回
    ----
    str
        规范化后的 CWE 编号；无法识别时返回空串。

    背景
    ----
    原始数据里 CWE 的写法并不统一：
        CVEfixes 写 ``'CWE-79'``
        也可能写 ``79`` / ``'cwe_79'``，或者干脆是 ``None``
        NVD 原始数据里还有 ``'NVD-CWE-noinfo'`` 这种"没查到"的占位值
    如果不统一，同一个 CWE-79 会被当成好几个不同的类别。

    实现
    ----
    先把前缀 ``CWE-`` / ``CWE`` 剥掉，然后只保留数字字符，
    最后用 ``int()`` 去掉前导零（``CWE-079`` → ``CWE-79``）。
    """
    if raw is None:
        return ""
    s = str(raw).strip().upper()
    # 这些取值代表"没有有效信息"，统一当空处理
    if not s or s in {"NAN", "NONE", "NVD-CWE-NOINFO", "NVD-CWE-OTHER"}:
        return ""
    # 剥掉前缀
    if s.startswith("CWE-"):
        s = s[4:]
    if s.startswith("CWE"):
        s = s[3:].lstrip("-_ ")
    # 只留数字
    digits = "".join(ch for ch in s if ch.isdigit())
    if not digits:
        return ""
    # int() 顺便去掉前导零
    return f"CWE-{int(digits)}"


def _iter_parquet_rows(
    path: Path, columns: list[str] | None = None, batch_size: int = 64
) -> Iterator[dict]:
    """流式读取 parquet 文件，逐行吐出字典。

    参数
    ----
    path : Path
        parquet 文件路径。
    columns : list[str] | None
        只读取指定的列。**强烈建议传入**——CVEfixes 里有些代码字段
        单个值能到几十 MB，只读需要的列能省大量内存和时间。
    batch_size : int
        每批读多少行，默认 64。

    返回
    ----
    Iterator[dict]
        一行一个字典的生成器。

    为什么要流式读而不是一次读全表
    ------------------------------
    ``pq.read_table(path)`` 会把整个文件解压到内存。
    CVEfixes 的单个 parquet 有 400+ MB，解压后可能几 GB，
    再加上超长的代码字符串，很容易 OOM。
    ``iter_batches`` 一次只解压 64 行，内存占用恒定。
    """
    import pyarrow.parquet as pq

    pf = pq.ParquetFile(path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=columns):
        for row in batch.to_pylist():
            yield row


# ---------------------------------------------------------------- 各数据源构建器


def build_cvefixes(raw_dir: Path, cfg: dict) -> Iterator[dict]:
    """CVEfixes：每条 CVE 记录产出「漏洞版本」与「修复版本」两条样本。

    参数
    ----
    raw_dir : Path
        原始数据根目录（通常是 ``data/raw``）。
    cfg : dict
        完整配置。

    返回
    ----
    Iterator[dict]
        统一格式的记录流。

    核心逻辑
    --------
    一条 CVEfixes 记录里有两个代码字段：

        vulnerable_code  修复前的代码 → 有漏洞 → label=1
        fixed_code       修复后的代码 → 已修复 → label=0

    两个版本来自同一个 commit，代码差异往往只有几行。因此它们
    **共用同一个 group_id**，划分数据集时会被分到同一个 split，
    避免"测试集里出现训练集的近邻副本"这种数据泄漏。

    字段映射
    --------
        cve_id           → id 前缀、group_id 组成部分
        hash             → group_id 组成部分（commit hash）
        repo_url         → project（取最后一段作为项目名）
        cwe_id           → cwe（规范化成 CWE-数字）
        cwe_name         → cwe_name
        language         → language
    """
    # 3 个 parquet 分片，按文件名排序保证读取顺序固定
    files = sorted((raw_dir / "cvefixes").glob("train-*.parquet"))
    if not files:
        log.warning("未找到 cvefixes parquet：%s", raw_dir / "cvefixes")
        return
    # 只读需要的列。CVEfixes 还有 diff_with_context 等超长字段，不读能省大量内存
    cols = [
        "cve_id", "hash", "repo_url", "cwe_id", "cwe_name",
        "language", "vulnerable_code", "fixed_code",
    ]
    for fp in files:
        for row in _iter_parquet_rows(fp, cols):
            cwe = _norm_cwe(row.get("cwe_id"))
            cwe_name = (row.get("cwe_name") or "").strip()
            lang = (row.get("language") or "").strip()
            # 分组键：同一 CVE 的同一 commit → 同一个 group
            group = f"cvefixes::{row.get('cve_id')}::{row.get('hash')}"
            vuln = _clean_code(row.get("vulnerable_code"))
            fixed = _clean_code(row.get("fixed_code"))

            # ---- 漏洞版本 → label=1 ----
            if vuln:
                yield {
                    "id": f"{row.get('cve_id')}-vuln",
                    "code": vuln, "label": 1, "cwe": cwe, "cwe_name": cwe_name,
                    "source": "cvefixes", "language": lang,
                    # "https://github.com/apache/xxx" → "xxx"
                    "project": (row.get("repo_url") or "").rsplit("/", 1)[-1],
                    "group_id": group,
                }

            # ---- 修复版本 → label=0 ----
            # 注意：修复版本不带 CWE（它是"安全"样本，没有漏洞类型可言）
            if fixed:
                yield {
                    "id": f"{row.get('cve_id')}-fixed",
                    "code": fixed, "label": 0, "cwe": "", "cwe_name": "",
                    "source": "cvefixes", "language": lang,
                    "project": (row.get("repo_url") or "").rsplit("/", 1)[-1],
                    "group_id": group,
                }


def build_bigvul(raw_dir: Path, cfg: dict) -> Iterator[dict]:
    """BigVul：按 ``vul`` 字段区分漏洞函数与安全函数。

    参数
    ----
    raw_dir : Path
        原始数据根目录。
    cfg : dict
        完整配置。

    返回
    ----
    Iterator[dict]

    BigVul 的标签语义
    -----------------
    BigVul 的每个 CVE 修复提交里包含两类函数：

        vul=1  这个函数就是被修复的漏洞函数
               → func_before（修复前）是漏洞  → label=1
               → func_after （修复后）是安全的 → label=0（难负样本）

        vul=0  同一提交里跟漏洞无关的其他函数（只是碰巧一起改了）
               → 视为安全函数 → label=0

    为什么要把 func_after 也加进来
    ------------------------------
    漏洞版本和修复版本只差几行，是一对"极难的负样本"。
    模型必须学会分辨这细小的差异，而不是靠"这段代码看起来像不像
    有漏洞的样子"来蒙。加入后模型的判别能力会明显提升。

    注意：BigVul 里 vul=0 的函数数量远多于 vul=1（约 16:1），
    类别极度不平衡，训练时建议开 ``imbalance: weighted_loss``。
    """
    mapping = {"train": "train.parquet", "val": "val.parquet", "test": "test.parquet"}
    # BigVul 的列名带空格和大小写，照抄原始字段名
    cols = ["CVE ID", "CWE ID", "func_before", "func_after", "vul", "lang", "project", "commit_id"]
    for split, fname in mapping.items():
        fp = raw_dir / "bigvul" / fname
        if not fp.exists():
            log.warning("缺少 BigVul 文件: %s", fp)
            continue
        for row in _iter_parquet_rows(fp, cols):
            cwe = _norm_cwe(row.get("CWE ID"))
            lang = (row.get("lang") or "").strip()
            project = (row.get("project") or "").strip()
            commit = str(row.get("commit_id") or "")
            # 同一 commit 的所有函数分到同一组
            group = f"bigvul::{commit}"
            before = _clean_code(row.get("func_before"))
            after = _clean_code(row.get("func_after"))
            # vul 字段可能是字符串 '1' 也可能是布尔 True，统一判断
            is_vul = str(row.get("vul")).strip() in {"1", "True", "true"}

            if not before:
                continue

            if is_vul:
                # ---- 漏洞函数（修复前）→ label=1 ----
                yield {
                    "id": f"bigvul::{commit}::before",
                    "code": before, "label": 1, "cwe": cwe,
                    "cwe_name": "", "source": "bigvul",
                    "language": lang, "project": project, "group_id": group,
                }
                # ---- 修复后版本 → label=0（难负样本） ----
                # after != before 的判断很重要：BigVul 里有些行两个字段完全一样，
                # 那样就是重复数据，直接跳过
                if after and after != before:
                    yield {
                        "id": f"bigvul::{commit}::after",
                        "code": after, "label": 0, "cwe": "",
                        "cwe_name": "", "source": "bigvul",
                        "language": lang, "project": project, "group_id": group,
                    }
            else:
                # ---- 同一提交里与漏洞无关的函数 → label=0 ----
                yield {
                    "id": f"bigvul::{commit}::irrelevant",
                    "code": before, "label": 0, "cwe": "",
                    "cwe_name": "", "source": "bigvul",
                    "language": lang, "project": project, "group_id": group,
                }


def build_diversevul(raw_dir: Path, cfg: dict) -> Iterator[dict]:
    """DiverseVul：target=1 为漏洞函数，target=0 为安全函数（无 CWE 字段）。"""
    for split, fname in [("train", "train.jsonl"), ("val", "valid.jsonl"), ("test", "test.jsonl")]:
        fp = raw_dir / "diversevul" / fname
        if not fp.exists():
            log.warning("缺少 DiverseVul 文件: %s", fp)
            continue
        with open(fp, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                code = _clean_code(o.get("func"))
                if not code:
                    continue
                idx = o.get("idx")
                project = (o.get("project") or "").strip()
                yield {
                    "id": f"diversevul::{project}::{idx}",
                    "code": code,
                    "label": 1 if str(o.get("target")).strip() in {"1", "1.0"} else 0,
                    "cwe": "", "cwe_name": "", "source": "diversevul",
                    "language": "C/C++", "project": project,
                    "group_id": f"diversevul::{project}::{idx}",
                }


def build_codexglue(raw_dir: Path, cfg: dict) -> Iterator[dict]:
    """CodeXGLUE defect detection：func + target(0/1)。"""
    mapping = {"train": "train.parquet", "val": "val.parquet", "test": "test.parquet"}
    for split, fname in mapping.items():
        fp = raw_dir / "codexglue" / fname
        if not fp.exists():
            log.warning("缺少 CodeXGLUE 文件: %s", fp)
            continue
        for i, row in enumerate(_iter_parquet_rows(fp)):
            code = _clean_code(row.get("func"))
            if not code:
                continue
            yield {
                "id": f"codexglue::{split}::{i}",
                "code": code,
                "label": 1 if int(row.get("target") or 0) == 1 else 0,
                "cwe": "", "cwe_name": "", "source": "codexglue",
                "language": "C/C++", "project": "", "group_id": f"codexglue::{split}::{i}",
            }


def build_merged(raw_dir: Path, cfg: dict) -> Iterator[dict]:
    """四源合并；由调用方统一去重。

    为什么"合并"能提升效果（本项目实测的结论）
    ------------------------------------------
    四个源各有短板，互补之后分布更接近真实项目：

        bigvul       函数级，但项目只有 275 个、正例仅 5.2%（1:18 太极端）
        diversevul   函数级，项目数上千，把"项目多样性"补了上来
        codexglue    函数级，量小但标签体系独立
        cvefixes     27 种语言，可惜是 diff 碎片（只有 8.6% 含完整函数）

    ``build_merged`` 只是**按顺序串联**四个构建器，不做任何额外处理 ——
    去重、长度过滤、分组划分都由调用方统一负责（见 ``main`` 里的处理流程），
    这样四个源的口径完全一致，不会出现"某个源偷偷多洗了一遍"的情况。

    注意：四个源的 ``group_id`` 前缀各不相同（``bigvul::`` / ``cvefixes::``
    等），天然不会互相串组，所以合并后按 ``group_id`` 划分依然安全。
    """
    for fn in (build_cvefixes, build_bigvul, build_diversevul, build_codexglue):
        yield from fn(raw_dir, cfg)


BUILDERS: dict[str, Callable[[Path, dict], Iterator[dict]]] = {
    "cvefixes": build_cvefixes,
    "bigvul": build_bigvul,
    "diversevul": build_diversevul,
    "codexglue": build_codexglue,
    "merged": build_merged,
}


# ---------------------------------------------------------------- 划分与落盘


def split_groups(
    records: list[dict], ratios: tuple[float, float, float], seed: int
) -> dict[str, list[dict]]:
    """按 group_id 分组划分 train / val / test。

    参数
    ----
    records : list[dict]
        去重后的记录列表。
    ratios : tuple[float, float, float]
        ``(训练比例, 验证比例, 测试比例)``，通常是 ``(0.8, 0.1, 0.1)``。
    seed : int
        随机种子，固定后划分结果可复现。

    返回
    ----
    dict
        ``{"train": [...], "val": [...], "test": [...]}``。

    ⚠️ 这是本项目最重要的一个设计
    ------------------------------
    很多教程直接对**样本**做随机划分：

        random.shuffle(records); train = records[:8000]; ...

    在本项目的数据上这样做会出大问题。以 CVEfixes 为例，
    同一个 CVE 会产出两条样本：

        {"code": "char buf[10]; strcpy(buf, user_input);", "label": 1}   # 漏洞版本
        {"code": "char buf[10]; strncpy(buf, user_input, 10);", "label": 0}  # 修复版本

    两者只差一个函数名。如果随机划分，很可能一条进训练集、另一条进测试集，
    模型在测试集上遇到的是"训练样本的近邻副本"，指标会虚高到 0.99，
    但换到真实的新漏洞上表现一塌糊涂。

    正确做法：**以 group_id（CVE + commit hash）为单位划分**，
    同一个 CVE 的所有样本要么全在训练集，要么全在测试集。
    这样测试集才是真正的"未见过的漏洞"。
    """
    import random

    # ---- 1. 把同一个 group_id 的记录聚到一起 ----
    groups: dict[str, list[dict]] = collections.OrderedDict()
    for r in records:
        groups.setdefault(r["group_id"], []).append(r)

    # ---- 2. 打乱分组顺序（不是打乱样本） ----
    keys = list(groups.keys())
    random.Random(seed).shuffle(keys)

    # ---- 3. 按比例切三段 ----
    n = len(keys)
    n_train = int(n * ratios[0])
    n_val = int(n * ratios[1])
    buckets = {
        "train": keys[:n_train],
        "val": keys[n_train:n_train + n_val],
        "test": keys[n_train + n_val:],
    }
    # ---- 4. 把分组展开回记录列表 ----
    return {k: [r for g in v for r in groups[g]] for k, v in buckets.items()}


def cap_samples(records: list[dict], limit: int | None, seed: int) -> list[dict]:
    """限制记录数量（调试用）。

    参数
    ----
    records : list[dict]
        记录列表。
    limit : int | None
        上限。None 或已经小于等于上限时原样返回。
    seed : int
        随机种子，保证每次采样结果一致。

    返回
    ----
    list[dict]
        截断后的列表。
    """
    if limit is None or len(records) <= limit:
        return records
    import random

    return random.Random(seed).sample(records, limit)


def prepare_task_data(
    records: list[dict],
    task: str,
    cfg: dict,
    label_map: dict[str, int] | None = None,
) -> tuple[list[dict], dict[str, int], dict[str, str]]:
    """按任务类型筛选样本并编码标签。

    参数
    ----
    records : list[dict]
        去重后的全部记录。
    task : str
        ``detection`` 或 ``classification``。
    cfg : dict
        配置（用到 ``task.min_class_samples`` 和 ``task.top_k_classes``）。
    label_map : dict | None
        预留参数，暂未使用。

    返回
    ----
    tuple
        ``(编码后的记录列表, CWE名称→编号 映射, 编号→CWE名称 映射)``。

    两个任务的区别
    --------------
    **detection（二分类）**：所有记录都保留，label 本来就是 0/1。

    **classification（多分类）**：只保留"有漏洞 + 带 CWE 编号"的样本
    （因为安全样本没有漏洞类型可分类），然后把 CWE 字符串换成 0~N 的数字编号。

    长尾类别处理（classification 专属）
    -----------------------------------
    41 个 CWE 的样本量差异极大：CWE-79 有 1103 条，CWE-1333 可能只有 30 条。
    如果每个类别都单独成类，模型在只有 1~2 条样本的类别上只会死记硬背。

    处理办法：样本量 < ``min_class_samples`` 的类别全部合并成一个 ``OTHER`` 类。
    这样模型至少能学会"这是一个不常见的漏洞类型"，而不是乱猜。

    ⚠️ 注意类别数
    --------------
    最终类别数 = 保留的 CWE 数 **+ 1**（OTHER 类）。
    这个 +1 很容易漏，漏了会导致 CrossEntropyLoss 报
    "weight tensor should be defined either for all N classes"。
    """
    # ---- 1. 按任务筛选样本 ----
    if task == "classification":
        # 分类任务：只要"有漏洞"且"CWE 编号有效"的样本
        pool = [r for r in records if r["label"] == 1 and r["cwe"]]
    else:
        # 检测任务：全部保留（记得 copy，避免修改原列表）
        pool = list(records)

    # ---- 2. 分类任务：编码 CWE 标签 ----
    if task == "classification":
        # 统计每个 CWE 有多少条样本
        counter = collections.Counter(r["cwe"] for r in pool)
        min_n = cfg["task"].get("min_class_samples", 30)
        top_k = cfg["task"].get("top_k_classes")
        # most_common() 按样本量降序排列，只保留样本量达标的
        kept = [(c, n) for c, n in counter.most_common() if n >= min_n]
        # 再按配置限制类别总数
        if top_k:
            kept = kept[:top_k]
        keep_set = {c for c, _ in kept}  # noqa: F841  （保留以便调试）
        # CWE 名称 → 编号（0, 1, 2, ...）
        cwe_to_id = {c: i for i, (c, _) in enumerate(kept)}
        # OTHER 类的编号排在最后
        other_id = len(cwe_to_id)
        # 编号 → CWE 名称（推理时用来把编号翻译回名字）
        id_to_name = {str(i): c for c, i in cwe_to_id.items()}
        id_to_name[str(other_id)] = "OTHER"
        # 把每条样本的 label 从 CWE 字符串换成数字编号；
        # 不在保留列表里的（长尾类别）统一映射到 other_id
        for r in pool:
            r["label"] = cwe_to_id.get(r["cwe"], other_id)
        return pool, cwe_to_id, id_to_name

    # ---- 3. 检测任务：标签本来就是 0/1，只需确保是 int ----
    for r in pool:
        r["label"] = int(r["label"])
    return pool, {"0": 0, "1": 1}, {"0": "safe", "1": "vulnerable"}


def main() -> None:
    """命令行入口：抽取 → 过滤去重 → 按任务落盘。"""
    parser = argparse.ArgumentParser(description="构建漏洞检测 / 分类数据集")
    parser.add_argument("--config", default="configs/config.yaml")
    parser.add_argument("--source", default=None,
                        help="cvefixes | bigvul | diversevul | codexglue | merged，"
                             "默认取配置文件")
    parser.add_argument("--task", default=None, help="detection|classification|both，默认 both")
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--max-samples", type=int, default=None,
                        help="每个数据源最多保留的原始样本数（调试用）")
    args = parser.parse_args()

    cfg = load_config(args.config)
    source = args.source or cfg["data"]["source"]
    out_dir = ensure_dir(resolve_path(args.out_dir or cfg["data"]["cache_dir"]))
    raw_dir = resolve_path(args.raw_dir)
    seed = cfg["seed"]

    if source not in BUILDERS:
        raise SystemExit(f"未知数据源 {source}，可选：{list(BUILDERS)}")

    tasks = ["detection", "classification"] if args.task in (None, "both") else [args.task]

    # ---------------- 1. 抽取 ----------------
    log.info("从 %s 抽取原始记录 ...", source)
    raw_records: list[dict] = []
    min_chars = cfg["data"]["min_code_chars"]
    trunc_chars = cfg["data"]["max_code_chars"]
    dropped_short = 0
    for r in BUILDERS[source](raw_dir, cfg):
        code = r["code"]
        if len(code) < min_chars:
            dropped_short += 1
            continue
        # 先做字符级头尾截断，避免超长文件撑爆内存
        r["code"] = truncate_code(code, trunc_chars)
        raw_records.append(r)
        if args.max_samples and len(raw_records) >= args.max_samples:
            break
    log.info("抽取完成：%s 条（过滤掉过短样本 %s 条）",
             human_int(len(raw_records)), human_int(dropped_short))

    # ---------------- 2. 去重 ----------------
    if cfg["data"]["dedup"]:
        seen: set[str] = set()
        deduped = []
        for r in raw_records:
            h = _md5(r["code"])
            if h in seen:
                continue
            seen.add(h)
            r["code_hash"] = h
            deduped.append(r)
        log.info("去重：%s -> %s", human_int(len(raw_records)), human_int(len(deduped)))
        raw_records = deduped

    ratios = (cfg["data"]["train_ratio"], cfg["data"]["val_ratio"], cfg["data"]["test_ratio"])
    stats: dict[str, Any] = {"source": source, "total_raw": len(raw_records), "tasks": {}}

    # ---------------- 3. 按任务落盘 ----------------
    for task in tasks:
        records, cwe_to_id, id_to_name = prepare_task_data(raw_records, task, cfg)
        if not records:
            log.warning("[%s] 无可用样本，跳过", task)
            continue

        splits = split_groups(records, ratios, seed)
        splits["train"] = cap_samples(splits["train"], cfg["data"]["max_train_samples"], seed)
        splits["val"] = cap_samples(splits["val"], cfg["data"]["max_eval_samples"], seed)
        splits["test"] = cap_samples(splits["test"], cfg["data"]["max_eval_samples"], seed)

        task_stats: dict[str, Any] = {}
        for split in ("train", "val", "test"):
            out_path = out_dir / f"{source}_{task}_{split}.jsonl"
            n = write_jsonl(splits[split], out_path)
            dist = collections.Counter(r["label"] for r in splits[split])
            task_stats[split] = {"n": n, "label_dist": dict(sorted(dist.items()))}
            log.info("[%s/%s] %s 条 -> %s", task, split, human_int(n), out_path.name)

        label_map_path = out_dir / f"{source}_{task}_label_map.json"
        # 注意：分类任务真实类别数 = 保留的 CWE 数 + 1（长尾合并出的 OTHER 类）
        num_labels = len(id_to_name) if task == "classification" else 2
        with open(label_map_path, "w", encoding="utf-8") as f:
            json.dump(
                {"task": task, "num_labels": num_labels,
                 "id2name": id_to_name, "name2id": cwe_to_id},
                f, ensure_ascii=False, indent=2,
            )
        stats["tasks"][task] = {
            "num_labels": num_labels,
            "splits": task_stats,
        }
        log.info("[%s] 类别数 = %d，标签映射 -> %s",
                 task, stats["tasks"][task]["num_labels"], label_map_path.name)

    with open(out_dir / f"{source}_stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    log.info("统计信息 -> %s", (out_dir / f'{source}_stats.json').name)
    log.info("全部完成 ✅")


if __name__ == "__main__":
    main()
