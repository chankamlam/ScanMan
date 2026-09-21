"""分布对齐 spike：量化"训练用的 diff 碎片"与"真实项目里的完整函数"差多远。

为什么要做这个 spike
--------------------
``build_dataset.py`` 喂给模型的**不是函数**，而是 CVE 修复提交里的 diff 片段
（``vulnerable_code`` = 删除行的拼接）。在真实项目上扫描时，``src/extract.py``
抽出来的是**完整函数** —— 两者在长度、结构、语法完整性上都不是一个分布。
本脚本不改任何东西，只负责**把差距量出来**，用数据回答：

    "现有检测模型直接拿去扫真实项目，到底还能不能用？"

三段统计
--------
(a) **训练侧结构**：复算训练/测试数据的结构指标（签名开头占比、完全无签名占比、
    长度分位），给出"碎片化"的基线。
(b) **真实项目结构**：用 ``src.extract`` 抽真实仓库，按同口径算指标，
    和 (a) 摆在一起对比。
(c) **带标签实测**：拿同一批带标签数据跑三组 F1，看性能随"离训练分布的距离"
    怎么衰减：

    ======  ==========================================================
    组      数据
    ======  ==========================================================
    A       测试集全体（训练同分布的碎片）
    B       A 里"含函数签名"的子集（碎片里比较像代码的那些）
    C       ``docs/test_cases/detection_test_cases.jsonl``：
            人工手写的 20 条**完整函数**（真实扫描的形态）
    ======  ==========================================================

判定规则
--------
组 C 只有 20 个样本，F1 的噪声大约 ±10 个点，所以**不拿它跟 A 比小数点**。
只有当 **C 的 F1 比 A 低超过 15 个点，或 C 的 recall < 0.5** 时，才判定
"分布漂移是实质性的"，结论写进 ``docs/07_漏洞分类设计方案.md``。

数据只读
--------
默认输入都在本仓库内（``data/processed/`` 与 ``outputs/``），本脚本**只读**它们；
``--out`` 经 ``resolve_path`` 一律落在本仓库的 ``outputs/`` 下。
换数据源/检查点用 ``--train`` / ``--test`` / ``--ckpt`` 覆盖。

用法
----
    # 只做 (a)(b) 结构统计，不需要模型权重
    python scripts/spike_align.py --no-model

    # 全量（需要训练好的检查点）
    python scripts/spike_align.py
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import resolve_path  # noqa: E402
from src.extract import extract_from_file, supported_extensions  # noqa: E402
from src.metrics import compute_binary_metrics  # noqa: E402
from src.utils import (  # noqa: E402
    ensure_dir,
    get_logger,
    human_int,
    read_jsonl,
    to_int_label,
)

log = get_logger("spike")

#: 项目根：数据与检查点默认都在本仓库下（相对路径按项目根解析）。
ROOT = Path(__file__).resolve().parent.parent

DEFAULT_TRAIN = ROOT / "data/processed/cvefixes_detection_train.jsonl"
DEFAULT_TEST = ROOT / "data/processed/cvefixes_detection_test.jsonl"
DEFAULT_CKPT = ROOT / "outputs/cvefixes_detection_6ep/best"
DEFAULT_CASES = ROOT / "docs/test_cases/detection_test_cases.jsonl"
DEFAULT_SCAN_DIR = ROOT / "src"

#: "这段代码看起来像函数声明"的正则（只看前 200 字符，够用且快）。
#:
#: 这是**粗判**，不是解析：目的是把"泛泛的 diff 碎片"和"带签名的代码块"
#: 分开，不是精确识别函数。真正解析函数是 ``src/extract.py`` 的事。
SIG_HEAD = re.compile(
    r"^\s*(?:async\s+)?def\s+\w+"                        # python
    r"|\bfunction\s+\w+\s*\("                            # php / js
    r"|=>\s*\{"                                          # js 箭头函数
    r"|^\s*[\w\*&:<>,\[\]\s()]+?\b\w+\s*\([^;{]*\)\s*(?:const\s*)?\{"  # c/cpp：签名与 { 同行
    r"|^\s*[\w\*&:<>,\[\]\s()]+?\b\w+\s*\([^;{]*\)\s*$"  # c/cpp：{ 换到下一行
    r"|^\s*(?:public|private|protected|static|virtual|inline|extern)\b.*\(",
    re.MULTILINE,
)

#: 控制关键字开头的行**不是**函数声明。没有这个过滤的话，
#: ``if (!verify(x)) {``、``while (n--) {`` 这类碎片会被误判成"有签名"，
#: 而那恰恰是 diff 碎片里最常见的内容。
CONTROL_KEYWORDS = re.compile(
    r"^\s*(?:if|for|while|switch|catch|else|do|return|case|default)\b"
)


def _declaration_lines(code: str, limit: int = 200) -> list[str]:
    """挑出"可能是函数声明"的行（已排除控制语句与注释行）。"""
    out = []
    for line in code[:limit].splitlines():
        s = line.strip()
        if not s or s.startswith(("//", "#", "*", "/*")):
            continue
        if CONTROL_KEYWORDS.match(line):
            continue
        out.append(line)
    return out


def looks_like_signature(code: str) -> bool:
    """代码里是否出现"函数声明"特征（只看前 200 字符）。

    这是**粗判**，不是为了精确识别函数（那是 ``src/extract.py`` 的活），
    只是为了把"泛泛的 diff 碎片"和"带签名的代码块"分开。
    """
    return any(SIG_HEAD.match(line) for line in _declaration_lines(code))


def starts_with_signature(code: str) -> bool:
    """代码是否**以**函数声明开头（跳过空行与注释行）。

    与 ``looks_like_signature`` 的区别：这个更严格，用来区分
    "整段就是一个函数"（开头即签名）和"只是碰巧包含了一段签名"。
    """
    lines = _declaration_lines(code)
    return bool(lines) and bool(SIG_HEAD.match(lines[0]))


def length_stats(codes: list[str]) -> dict:
    """长度分布（字符数）：中位数与各分位，用来刻画"碎片 vs 完整函数"。"""
    if not codes:
        return {}
    lens = np.array([len(c) for c in codes])
    pct = np.percentile(lens, [10, 25, 50, 75, 90, 99])
    return {
        "n": int(len(lens)),
        "mean": float(lens.mean()),
        "p10": float(pct[0]),
        "p25": float(pct[1]),
        "median": float(pct[2]),
        "p75": float(pct[3]),
        "p90": float(pct[4]),
        "p99": float(pct[5]),
        "max": int(lens.max()),
        "under_100_chars": float((lens < 100).mean()),
    }


def structural_stats(codes: list[str]) -> dict:
    """结构指标：签名占比 + 长度分布。"""
    n = len(codes)
    if n == 0:
        return {"n": 0}
    stats = {
        "n": n,
        "starts_with_signature": sum(starts_with_signature(c) for c in codes) / n,
        "contains_signature": sum(looks_like_signature(c) for c in codes) / n,
    }
    stats["no_signature"] = 1.0 - stats["contains_signature"]
    stats.update(length_stats(codes))
    return stats


# ---------------------------------------------------------------------------
# (a) 训练侧结构统计
# ---------------------------------------------------------------------------


def analyse_training_data(path: Path, max_samples: int | None) -> dict:
    """读训练/测试 JSONL，算结构指标。"""
    if not path.exists():
        log.warning("数据文件不存在，跳过：%s", path)
        return {}

    codes: list[str] = []
    for i, rec in enumerate(read_jsonl(path)):
        if max_samples is not None and i >= max_samples:
            break
        codes.append(rec.get("code") or "")

    stats = structural_stats(codes)
    log.info("(a) %s -> %s 条", path.name, human_int(stats.get("n", 0)))
    return stats


# ---------------------------------------------------------------------------
# (b) 真实项目结构统计
# ---------------------------------------------------------------------------


def analyse_project(root: Path, max_files: int | None = None) -> dict:
    """用 ``src.extract`` 抽真实项目里的函数，按同口径算结构指标。"""
    exts = set(supported_extensions())
    files = sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in exts
        and not any(part.startswith(".") for part in p.relative_to(root).parts)
        and "__pycache__" not in p.parts
    )
    if max_files is not None:
        files = files[:max_files]

    codes: list[str] = []
    depths: list[int] = []
    for p in files:
        res = extract_from_file(p)
        for f in res.functions:
            codes.append(f.code)
            depths.append(f.depth)

    stats = structural_stats(codes)
    if depths:
        d = np.array(depths)
        stats["depth_top_level"] = float((d == 0).mean())
        stats["depth_max"] = int(d.max())
    stats["files"] = len(files)
    log.info("(b) %s -> %d 个文件、%s 个函数",
             root, len(files), human_int(stats.get("n", 0)))
    return stats


# ---------------------------------------------------------------------------
# (c) 三组带标签实测
# ---------------------------------------------------------------------------


def load_labelled(path: Path) -> tuple[list[str], np.ndarray]:
    """读带 ``label`` 字段的 JSONL，返回 (codes, labels)。

    ``label`` 不是整数（如人工用例里的 ``"CWE-120"``）时跳过该条 ——
    这里算的是二分类指标，字符串标签没法参与比较。
    """
    codes, labels = [], []
    skipped = 0
    for rec in read_jsonl(path):
        if "label" not in rec:
            continue
        lab = to_int_label(rec["label"])
        if lab is None:
            skipped += 1
            continue
        codes.append(rec.get("code") or "")
        labels.append(lab)
    if skipped:
        log.warning("%s 里有 %d 条样本的 label 不是整数，已跳过", path.name, skipped)
    return codes, np.asarray(labels, dtype=int)


def evaluate_group(predictor, probs_to_logits, name: str, codes: list[str],
                   labels: np.ndarray, batch_size: int) -> dict:
    """对一组数据算指标。"""
    if not codes:
        log.warning("组 %s 没有样本，跳过", name)
        return {}

    chunks = []
    for i in range(0, len(codes), batch_size):
        chunks.append(predictor.predict_probs(codes[i:i + batch_size]))
    probs = np.concatenate(chunks, axis=0)

    # compute_binary_metrics 内部会再 softmax 一次，所以这里先还原成 logits
    m = compute_binary_metrics(labels, probs_to_logits(probs),
                               threshold=predictor.threshold)
    m["n"] = len(codes)
    m["positive_rate"] = float(labels.mean())
    log.info("(c) %-28s n=%-5d F1=%.4f  P=%.4f  R=%.4f",
             name, m["n"], m["f1"], m["precision"], m["recall"])
    return m


def print_stats(title: str, stats: dict) -> None:
    """把一段结构统计打印成表。"""
    if not stats:
        print(f"  {title}: 无数据")
        return
    print(f"  {title}")
    print(f"    样本数            {human_int(stats['n'])}")
    print(f"    以签名开头        {stats['starts_with_signature']:.1%}")
    print(f"    含函数签名        {stats['contains_signature']:.1%}")
    print(f"    完全无签名        {stats['no_signature']:.1%}")
    print(f"    长度中位数        {stats['median']:.0f} 字符")
    print(f"    长度 p25 / p75    {stats['p25']:.0f} / {stats['p75']:.0f}")
    print(f"    长度 p90 / p99    {stats['p90']:.0f} / {stats['p99']:.0f}")
    print(f"    短于 100 字符     {stats['under_100_chars']:.1%}")


def main() -> int:
    parser = argparse.ArgumentParser(description="分布对齐 spike（碎片 vs 完整函数）")
    parser.add_argument("--train-jsonl", default=str(DEFAULT_TRAIN))
    parser.add_argument("--test-jsonl", default=str(DEFAULT_TEST))
    parser.add_argument("--cases", default=str(DEFAULT_CASES),
                        help="人工手写的完整函数用例（组 C）")
    parser.add_argument("--scan-dir", default=str(DEFAULT_SCAN_DIR),
                        help="(b) 段要统计的真实项目目录")
    parser.add_argument("--checkpoint", default=str(DEFAULT_CKPT))
    parser.add_argument("--out", default="outputs/spike_align.json")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--max-samples", type=int, default=None,
                        help="(a) 段最多读多少条（调试用）")
    parser.add_argument("--device", default=None)
    parser.add_argument("--no-model", action="store_true",
                        help="跳过 (c) 段：不加载模型，只做结构统计")
    args = parser.parse_args()

    report: dict = {"sections": {}}

    # ================= (a) 训练侧结构 =================
    print("\n" + "=" * 72)
    print("(a) 训练侧结构（CVEfixes 处理后数据）")
    print("=" * 72)
    train_stats = analyse_training_data(Path(args.train_jsonl), args.max_samples)
    test_stats = analyse_training_data(Path(args.test_jsonl), args.max_samples)
    print_stats("train", train_stats)
    print_stats("test", test_stats)
    report["sections"]["a_training"] = {"train": train_stats, "test": test_stats}

    # ================= (b) 真实项目结构 =================
    print("\n" + "=" * 72)
    print(f"(b) 真实项目结构（{args.scan_dir}）")
    print("=" * 72)
    proj_stats = analyse_project(Path(args.scan_dir))
    print_stats("真实项目函数", proj_stats)
    report["sections"]["b_project"] = proj_stats

    # ---- 结构对比结论 ----
    if train_stats and proj_stats:
        ratio = proj_stats["median"] / max(train_stats["median"], 1)
        print("\n  对比：")
        print(f"    长度中位数  训练碎片 {train_stats['median']:.0f} 字符"
              f" -> 真实函数 {proj_stats['median']:.0f} 字符（{ratio:.1f} 倍）")
        print(f"    完全无签名  训练碎片 {train_stats['no_signature']:.1%}"
              f" -> 真实函数 {proj_stats['no_signature']:.1%}")
        print(f"    以签名开头  训练碎片 {train_stats['starts_with_signature']:.1%}"
              f" -> 真实函数 {proj_stats['starts_with_signature']:.1%}")
        report["sections"]["median_length_ratio"] = float(ratio)

    # ================= (c) 三组 F1 =================
    if args.no_model:
        print("\n" + "=" * 72)
        print("(c) 已跳过（--no-model）")
        print("=" * 72)
    else:
        print("\n" + "=" * 72)
        print("(c) 三组带标签实测")
        print("=" * 72)
        from scripts.evaluate import probs_to_logits
        from scripts.predict import VulnPredictor

        predictor = VulnPredictor(args.checkpoint, device=args.device)
        if predictor.task != "detection":
            log.error("检查点任务是 %r，不是 detection，无法算二分类指标。", predictor.task)
            return 2
        log.info("模型就绪 | 设备=%s | 阈值=%.4f", predictor.device, predictor.threshold)

        groups: dict[str, dict] = {}

        # ---- 组 A：测试集全体（碎片，训练同分布） ----
        codes_a, labels_a = load_labelled(Path(args.test_jsonl))
        groups["A_test_all"] = evaluate_group(
            predictor, probs_to_logits, "A 测试集全体", codes_a, labels_a, args.batch_size)

        # ---- 组 B：A 里含签名的子集 ----
        idx_b = [i for i, c in enumerate(codes_a) if looks_like_signature(c)]
        codes_b = [codes_a[i] for i in idx_b]
        labels_b = labels_a[idx_b]
        groups["B_test_with_signature"] = evaluate_group(
            predictor, probs_to_logits, "B 其中含签名", codes_b, labels_b, args.batch_size)

        # ---- 组 C：手写完整函数（真实扫描形态） ----
        codes_c, labels_c = load_labelled(Path(args.cases))
        groups["C_handwritten_functions"] = evaluate_group(
            predictor, probs_to_logits, "C 手写完整函数", codes_c, labels_c, args.batch_size)

        report["sections"]["c_groups"] = groups

        # ---- 判定 ----
        a = groups.get("A_test_all") or {}
        c = groups.get("C_handwritten_functions") or {}
        if a and c:
            drop = a["f1"] - c["f1"]
            drifted = drop > 0.15 or c["recall"] < 0.5
            report["sections"]["verdict"] = {
                "f1_drop_a_to_c": float(drop),
                "c_recall": float(c["recall"]),
                "distribution_shift_is_material": bool(drifted),
                "rule": "C 的 F1 比 A 低 >15 点，或 C 的 recall < 0.5",
            }
            print("\n" + "-" * 72)
            print(f"  判定：A->C 的 F1 落差 {drop:+.4f}，C 的 recall {c['recall']:.4f}")
            print("  结论：" + ("**分布漂移实质性存在** —— "
                              "现有模型不能直接用于真实项目扫描，需要函数级数据重训。"
                              if drifted else
                              "漂移在可接受范围内（注意 C 只有 20 条，噪声约 ±10 点）。"))

    # ---- 写盘 ----
    out_path = resolve_path(args.out)
    ensure_dir(out_path.parent)
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print("\n" + "=" * 72)
    log.info("spike 结果 -> %s", out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
