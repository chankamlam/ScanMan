"""扫判定阈值：找出"达到目标召回率"所需的最优阈值（漏洞检测专用）。

为什么需要这个脚本
------------------
``train.py`` 训练完给的是"概率"，把概率变成"有漏洞/安全"还需要一个阈值，
默认是 0.5。但 0.5 只是个约定俗成的数字，不是最优的。

漏洞检测场景里 **漏报（FN）比误报（FP）严重得多**：漏掉一个真漏洞可能被利用，
误报只是让开发者多看一眼。所以正确做法是：**先定一个可接受的召回率目标，
再在满足该目标的前提下把精确率做到最高**。

实测（CVEfixes，6 轮模型，测试集 1,902 条）::

    默认阈值 0.500  ->  recall 0.782  precision 0.719  F1 0.749  漏报 186
    调优阈值 0.215  ->  recall 0.902  precision 0.661  F1 0.763  漏报  84

召回率翻过 90%，F1 反而还涨了一点，代价是误报从 261 涨到 394。

⚠️ 方法论：阈值应该**在验证集上调，在测试集上报告**。
在测试集上调阈值属于"偷看答案"，report 出来的数字会偏乐观。
所以本脚本默认 ``--split val`` 调参，并自动把结果同时打印到另一个 split 上做对照。

用法
----
    # 看看阈值表（不改任何东西）
    python scripts/tune_threshold.py --run outputs/cvefixes_detection_6ep

    # 目标召回率 90%，并把选出来的阈值写进检查点
    python scripts/tune_threshold.py --run outputs/cvefixes_detection_6ep ^
        --target-recall 0.90 --write

    # 之后 predict.py 会自动读取 best/threshold.json 里的阈值
    python scripts/predict.py --checkpoint outputs/cvefixes_detection_6ep/best --file demo.c

产物
----
``<run>/best/threshold.json``::

    {"threshold": 0.215, "target_recall": 0.9, "tuned_on": "val",
     "recall": 0.9004, "precision": 0.6486, "f1": 0.7541, "fn": 85, "fp": 416}
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import resolve_path  # noqa: E402
from src.utils import ensure_dir, get_logger  # noqa: E402

log = get_logger("tune_threshold")


def load_probs(run_dir: Path, split: str) -> tuple[np.ndarray, np.ndarray]:
    """读取某次训练保存的预测概率与真实标签。

    参数
    ----
    run_dir : Path
        训练输出目录，例如 ``outputs/cvefixes_detection_6ep``。
    split : str
        ``val`` 或 ``test``。

    返回
    ----
    tuple[np.ndarray, np.ndarray]
        ``(概率数组, 标签数组)``。概率是"有漏洞"这一类的概率，形状 ``(N,)``。

    说明
    ----
    这两个文件是 ``train.py`` 训练结束后自动保存的
    （见 train.py 里 ``np.save(run_dir / f"probs_{split}.npy", probs)``）。
    所以只要训练跑完过一次，就不用重新推理。
    """
    p_path = run_dir / f"probs_{split}.npy"
    y_path = run_dir / f"labels_{split}.npy"
    if not p_path.exists() or not y_path.exists():
        raise FileNotFoundError(
            f"找不到 {p_path.name} / {y_path.name}。\n"
            f"这两个文件只有**检测任务**训练结束时才会生成。\n"
            f"如果这是分类任务的目录，本脚本不适用。"
        )
    return np.load(p_path), np.load(y_path).astype(int)


def metrics_at(probs: np.ndarray, y: np.ndarray, t: float) -> dict:
    """算某个阈值下的混淆矩阵与各项指标（不依赖 sklearn，避免额外开销）。"""
    pred = (probs >= t).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    acc = (tp + tn) / len(y) if len(y) else 0.0
    return {"threshold": float(t), "precision": precision, "recall": recall,
            "f1": f1, "accuracy": acc, "tn": tn, "fp": fp, "fn": fn, "tp": tp}


def sweep(probs: np.ndarray, y: np.ndarray) -> list[dict]:
    """扫一组常用阈值，返回指标列表。"""
    return [metrics_at(probs, y, t) for t in
            (0.50, 0.45, 0.40, 0.35, 0.30, 0.25, 0.20, 0.15, 0.10)]


def best_for_recall(probs: np.ndarray, y: np.ndarray, target: float) -> dict | None:
    """在"召回率 >= target"的所有阈值里，挑精确率最高的那个。

    参数
    ----
    probs, y : np.ndarray
        概率与真实标签。
    target : float
        目标召回率，例如 0.90。

    返回
    ----
    dict | None
        找到时返回该阈值下的指标字典，达不到目标返回 None。
    """
    best = None
    for t in np.arange(0.01, 1.0, 0.005):
        m = metrics_at(probs, y, float(t))
        if m["recall"] >= target and (best is None or m["precision"] > best["precision"]):
            best = m
    return best


def print_table(title: str, rows: list[dict]) -> None:
    """把阈值表打印成对齐的表格。"""
    print(f"\n{title}")
    print(f"{'阈值':>6}{'precision':>11}{'recall':>9}{'f1':>9}"
          f"{'漏报FN':>8}{'误报FP':>8}{'判为漏洞':>10}")
    print("-" * 62)
    for m in rows:
        print(f"{m['threshold']:>6.2f}{m['precision']:>11.4f}{m['recall']:>9.4f}"
              f"{m['f1']:>9.4f}{m['fn']:>8}{m['fp']:>8}{m['tp']+m['fp']:>10}")


def main() -> None:
    """命令行入口。"""
    parser = argparse.ArgumentParser(description="扫描并选择漏洞检测的判定阈值")
    parser.add_argument("--run", required=True,
                        help="训练输出目录，例如 outputs/cvefixes_detection_6ep")
    parser.add_argument("--split", default="val", choices=["val", "test"],
                        help="在哪个集合上调阈值（默认 val，避免偷看测试集）")
    parser.add_argument("--target-recall", type=float, default=0.90,
                        help="目标召回率，默认 0.90")
    parser.add_argument("--write", action="store_true",
                        help="把选出的阈值写进 <run>/best/threshold.json")
    args = parser.parse_args()

    run_dir = resolve_path(args.run)
    if not run_dir.exists():
        raise SystemExit(f"目录不存在: {run_dir}")

    # ---- 读数据 ----
    probs, y = load_probs(run_dir, args.split)
    other = "test" if args.split == "val" else "val"
    print("=" * 62)
    print(f"运行目录   : {run_dir.name}")
    print(f"调参集合   : {args.split}  （{len(y)} 条，漏洞 {y.sum()} 条，占 {y.mean():.1%}）")
    print(f"目标召回率 : {args.target_recall:.0%}")
    print("=" * 62)

    print_table(f"【{args.split}】阈值扫描", sweep(probs, y))

    best = best_for_recall(probs, y, args.target_recall)
    if best is None:
        print(f"\n❌ 在 {args.split} 上达不到 {args.target_recall:.0%} 的召回率。"
              f"最高只能到 {metrics_at(probs, y, 0.01)['recall']:.4f}。")
        print("   说明模型本身排不出来——需要更好的模型/更多数据，不能只靠调阈值。")
        return

    print(f"\n✅ 达到 {args.target_recall:.0%} 召回率的最优阈值 = {best['threshold']:.3f}")
    print(f"   [{args.split}] recall={best['recall']:.4f}  precision={best['precision']:.4f}  "
          f"f1={best['f1']:.4f}  漏报={best['fn']}  误报={best['fp']}")

    # ---- 关键：这个阈值搬到另一个集合上还成立吗 ----
    try:
        p2, y2 = load_probs(run_dir, other)
        m2 = metrics_at(p2, y2, best["threshold"])
        print(f"   [{other}] recall={m2['recall']:.4f}  precision={m2['precision']:.4f}  "
              f"f1={m2['f1']:.4f}  漏报={m2['fn']}  误报={m2['fp']}")
        gap = abs(m2["recall"] - best["recall"])
        if gap <= 0.03:
            print(f"   ↑ 与 {args.split} 的召回率只差 {gap:.1%}，说明两个集合难度接近，"
                  f"阈值迁移性良好")
        else:
            print(f"   ↑ 与 {args.split} 的召回率差了 {gap:.1%}：两个集合难度不同。"
                  f"以 {args.split} 为准（{other} 只是参考，不能拿来调参）")
    except FileNotFoundError:
        pass

    if args.write:
        out = {
            "threshold": best["threshold"],
            "target_recall": args.target_recall,
            "tuned_on": args.split,
            "recall": best["recall"],
            "precision": best["precision"],
            "f1": best["f1"],
            "fn": best["fn"],
            "fp": best["fp"],
        }
        path = ensure_dir(run_dir / "best") / "threshold.json"
        path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        log.info("阈值已写入 %s", path)
        log.info("之后 predict.py 会自动使用该阈值（可用 --threshold 临时覆盖）")
    else:
        print("\n提示：加 --write 可以把该阈值写进 <run>/best/threshold.json，"
              "predict.py 会自动读取。")


if __name__ == "__main__":
    main()
