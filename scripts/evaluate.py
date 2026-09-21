"""在**任意数据集**上完整评估一个已训练好的检查点（不只是看准确率）。

和 ``predict.py`` 的区别
------------------------
``predict.py`` 是"给一段代码，告我有没有漏洞"——面向使用。
``evaluate.py`` 是"给一批带标签的数据，告我模型到底有多好"——面向实验。
它会把 precision / recall / F1 / MCC / ROC-AUC / PR-AUC 一次全算出来，
还会打印混淆矩阵和（检测任务的）阈值扫描表。

为什么需要它
------------
``train.py`` 结束时虽然也会在测试集上评估，但那是**固定在 0.5 阈值**的。
而漏洞检测里最该看的其实是"目标召回率下的精确率"。本脚本支持任意阈值，
并且能用 ``--sweep`` 把所有阈值一次列出来。

用法
----
    # 用检查点自带的阈值（best/threshold.json）
    python scripts/evaluate.py --checkpoint outputs/cvefixes_detection_6ep/best ^
        --input data/processed/cvefixes_detection_test.jsonl

    # 指定阈值 + 打印阈值扫描表
    python scripts/evaluate.py --checkpoint outputs/cvefixes_detection_6ep/best ^
        --input data/processed/cvefixes_detection_test.jsonl ^
        --threshold 0.11 --sweep

    # 换一个数据集评估（比如 BigVul 的测试集，看跨数据集泛化）
    python scripts/evaluate.py --checkpoint outputs/cvefixes_detection_6ep/best ^
        --input data/processed/bigvul_detection_test.jsonl --sweep

输入格式
--------
JSONL，每行至少要有 ``code`` 和 ``label`` 两个字段
（``code`` 源码，``label`` 检测任务为 0/1，分类任务为类别编号）。
``data/processed/*_test.jsonl`` 直接就能用。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ⚠️ 用限定名 ``scripts.predict``，不要裸写 ``import predict``：
# scripts/ 与项目根同时在 sys.path 上时，裸 import 会生成两个模块对象、
# 两个 VulnPredictor 类，isinstance / 身份比较会静默失效（serve.py 的
# 模块 docstring 第 0 条记了这件事）。
from scripts.predict import VulnPredictor  # noqa: E402
from src.config import resolve_path  # noqa: E402
from src.metrics import (  # noqa: E402
    SWEEP_THRESHOLDS,
    compute_binary_metrics,
    compute_multiclass_metrics,
    per_class_report,
)
from src.utils import get_logger, human_int, to_int_label  # noqa: E402

log = get_logger("evaluate")


def load_dataset(path: Path) -> tuple[list[str], np.ndarray]:
    """读 JSONL，返回 (代码列表, 标签数组)。

    参数
    ----
    path : Path
        JSONL 文件路径。

    返回
    ----
    tuple[list[str], np.ndarray]
        ``(codes, labels)``。没有 ``label`` 字段的行会被跳过。
    """
    codes: list[str] = []
    labels: list[int] = []
    skipped = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            if "label" not in o:
                continue
            # label 可能是 "CWE-120" 这类字符串（人工用例），转不了就跳过，
            # 不要 int() 直接抛 ValueError 把整轮评估打断。
            lab = to_int_label(o["label"])
            if lab is None:
                skipped += 1
                continue
            codes.append(o.get("code") or "")
            labels.append(lab)
    if skipped:
        log.warning("有 %s 条样本的 label 不是整数（例如 CWE 名字），已跳过、"
                    "不计入指标：%s", human_int(skipped), path.name)
    return codes, np.asarray(labels, dtype=int)


def probs_to_logits(probs: np.ndarray) -> np.ndarray:
    """把 softmax 概率还原成 logits。

    参数
    ----
    probs : np.ndarray
        形状 ``(N, K)`` 的概率矩阵（每行和为 1）。

    返回
    ----
    np.ndarray
        形状 ``(N, K)`` 的 logits。

    原理
    ----
    ``softmax`` 对"整体平移"是不变的：``softmax(z + c) == softmax(z)``。
    所以取对数就能还原出一组等价的 logits，喂回 ``src.metrics`` 里的函数
    （它们内部还会再 softmax 一次）得到的结果与原始概率完全一致。
    加 ``1e-12`` 是防止 ``log(0)``。
    """
    return np.log(np.clip(probs, 1e-12, None))


def print_binary_report(metrics: dict, threshold: float) -> None:
    """打印检测任务的指标与混淆矩阵。"""
    print("-" * 62)
    print(f"{'accuracy':<12}{metrics['accuracy']:.4f}")
    print(f"{'precision':<12}{metrics['precision']:.4f}")
    print(f"{'recall':<12}{metrics['recall']:.4f}   <-- 漏报率 {1-metrics['recall']:.2%}")
    print(f"{'f1':<12}{metrics['f1']:.4f}")
    print(f"{'mcc':<12}{metrics['mcc']:.4f}   (不平衡数据上比 F1 更可靠)")
    print(f"{'roc_auc':<12}{metrics['roc_auc']:.4f}")
    print(f"{'pr_auc':<12}{metrics['pr_auc']:.4f}   (只看正例的排序质量)")
    print("-" * 62)
    print("混淆矩阵：")
    print(f"{'':>12}{'预测安全':>10}{'预测漏洞':>10}")
    print(f"{'实际安全':>12}{metrics['tn']:>10}{metrics['fp']:>10}")
    print(f"{'实际漏洞':>12}{metrics['fn']:>10}{metrics['tp']:>10}")
    print(f"\n漏报 FN = {metrics['fn']}（真漏洞被判安全，最严重）")
    print(f"误报 FP = {metrics['fp']}（安全代码被判漏洞，多看一眼）")
    print(f"判定阈值 = {threshold:.3f}")


def main() -> None:
    """命令行入口。"""
    parser = argparse.ArgumentParser(description="在带标签的数据集上完整评估检查点")
    parser.add_argument("--checkpoint", required=True, help="检查点目录（含 best/）")
    parser.add_argument("--input", required=True, help="带 label 字段的 JSONL")
    parser.add_argument("--threshold", type=float, default=None,
                        help="检测任务的判定阈值（默认用检查点自带的）")
    parser.add_argument("--device", default=None,
                        help="cpu | cuda | mps | cuda:1，默认自动（CUDA > MPS > CPU）")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--sweep", action="store_true", help="额外打印阈值扫描表")
    parser.add_argument("--max-samples", type=int, default=None, help="只评估前 N 条（调试）")
    args = parser.parse_args()

    in_path = resolve_path(args.input)
    if not in_path.exists():
        raise SystemExit(f"输入文件不存在: {in_path}")

    codes, y = load_dataset(in_path)
    if args.max_samples:
        codes, y = codes[: args.max_samples], y[: args.max_samples]
    if len(codes) == 0:
        raise SystemExit("输入里没有带 label 的样本")

    print("=" * 62)
    print(f"数据集   : {in_path.name}")
    print(f"检查点   : {args.checkpoint}")
    print(f"样本数   : {human_int(len(y))}")

    # ---- 加载模型 ----
    predictor = VulnPredictor(args.checkpoint, device=args.device,
                              threshold=args.threshold)
    task = predictor.task
    if task == "detection":
        n_pos = int((y == 1).sum())
        print(f"漏洞样本 : {human_int(n_pos)}（{n_pos/len(y):.1%}）")
    print(f"任务     : {task} | 类别数 {predictor.num_labels} | 设备 {predictor.device}")
    print("=" * 62)

    # ---- 批量前向 ----
    t0 = time.time()
    chunks = []
    for i in range(0, len(codes), args.batch_size):
        chunks.append(predictor.predict_probs(codes[i: i + args.batch_size]))
        done = min(i + args.batch_size, len(codes))
        print(f"\r  已推理 {done}/{len(codes)}", end="", flush=True)
    print(f"\r  推理完成，用时 {time.time()-t0:.1f} s" + " " * 20)
    probs = np.concatenate(chunks, axis=0)
    logits = probs_to_logits(probs)

    # ---- 算指标 ----
    if task == "detection":
        th = predictor.threshold
        metrics = compute_binary_metrics(y, logits, threshold=th)
        print_binary_report(metrics, th)

        if args.sweep:
            print("\n阈值扫描：")
            print(f"{'阈值':>6}{'precision':>11}{'recall':>9}{'f1':>9}{'漏报FN':>8}{'误报FP':>8}")
            print("-" * 51)
            for t in SWEEP_THRESHOLDS:
                m = compute_binary_metrics(y, logits, threshold=t)
                print(f"{t:>6.2f}{m['precision']:>11.4f}{m['recall']:>9.4f}"
                      f"{m['f1']:>9.4f}{m['fn']:>8}{m['fp']:>8}")
    else:
        # 不传 top_k，用默认的 (3, 5)：Top-5 是分类任务的主指标（见 docs/07 4.3）
        metrics = compute_multiclass_metrics(y, logits)
        print("-" * 62)
        for k in ("accuracy", "macro_f1", "weighted_f1", "micro_f1",
                  "top3_accuracy", "top5_accuracy"):
            if k in metrics:
                print(f"{k:<14}{metrics[k]:.4f}")
        names = [predictor.id2name.get(i, str(i)) for i in range(predictor.num_labels)]
        print("\n逐类别明细：")
        print(per_class_report(y, logits, names))

    print("\n" + "=" * 62)
    print("提示：想看/改判定阈值，用 scripts/tune_threshold.py（会写进 best/threshold.json）")


if __name__ == "__main__":
    main()
