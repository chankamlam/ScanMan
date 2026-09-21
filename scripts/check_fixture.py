"""校验测试夹具：``demo_verified/`` 里的每个函数，模型是不是都判对了。

为什么需要这个脚本
------------------
``demo_verified/`` 是**演示与回归**用的夹具 —— 里面的每个函数都是挑过的，
保证模型在阈值下的判定与 ``TRUTH.json`` 里的标签一致。但这个性质会**悄悄失效**：

* 换了检查点（重新训练、换 run）
* 改了 ``src/extract.py``（抽取范围变了，送进模型的字符串就变了）
* 改了 ``src/utils.py:truncate_code``
* **文件的行尾变了**（见下）

所以需要一条命令能回答"夹具现在还准不准"。

⚠️ 行尾会影响结果（本项目的一个已知敏感点）
--------------------------------------------
``truncate_code`` 按**字符**做头 60% / 尾 40% 截断。CRLF 文件比 LF 每行多一个
``\\r``，于是截断点偏移、送进模型的字符串不同 —— 实测仅这一项差异就能让
8 个函数里 2 个的 CWE 翻转。所以改这些文件时**必须按原字节写**，
不要用会在 Windows 上把 ``\\n`` 翻译成 ``\\r\\n`` 的文本模式。

演示性质（别拿它当效果指标）
----------------------------
夹具是**按"模型判对"筛出来的**，天然带选择偏差。挑选口径：从
``data/processed/merged_detection_test.jsonl`` 的**测试划分**里，取代码完整、
能抽出恰好一个函数、且模型在阈值下判定与数据集标签一致的真实 CVE 函数
（标签来自原始修复提交，不是本项目的判断）。
它证明的是"这条链路端到端是通的、结果是可预期的"，
**不能**用来衡量模型的准确率 —— 那要用 ``scripts/evaluate.py`` 跑完整测试集。

用法
----
    python scripts/check_fixture.py

退出码：全部一致 ``0``；有不一致 ``1``；环境/文件问题 ``2``。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.extract import MAX_FILE_BYTES  # noqa: E402
from src.utils import get_logger  # noqa: E402

log = get_logger("checkfix")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="校验 demo_verified/ 夹具是否仍然全部预测正确",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--fixture", default="demo_verified",
                        help="夹具目录（默认 demo_verified）")
    parser.add_argument("--detector", default="outputs/merged_detection_codebert/best")
    parser.add_argument("--classifier", default="outputs/merged_top27_codebert_e20/best")
    parser.add_argument("--device", default=None,
                        help="cpu | cuda | mps，默认自动（CUDA > MPS > CPU）")
    args = parser.parse_args()

    root = Path(args.fixture)
    truth_path = root / "TRUTH.json"
    if not truth_path.exists():
        log.error("找不到 %s", truth_path)
        return 2
    truth = json.loads(truth_path.read_text(encoding="utf-8"))

    # ---- 跑一遍和命令行完全相同的管线 ----
    from scripts.predict import VulnPredictor
    from scripts.scan_project import (
        build_report, run_classification, run_inference, scan_files,
    )

    files = sorted(root.glob("*.c"))
    if not files:
        log.error("%s 下没有 .c 文件", root)
        return 2

    file_results, skipped, _ = scan_files(files, root, MAX_FILE_BYTES, outer_only=False)
    det = VulnPredictor(args.detector, device=args.device)
    if det.task != "detection":
        log.error("--detector 指向的是 %r，不是 detection", det.task)
        return 2
    clf = VulnPredictor(args.classifier, device=args.device)
    if clf.task != "classification":
        log.error("--classifier 指向的是 %r，不是 classification", clf.task)
        return 2
    log.info("模型就绪 | 设备=%s | 阈值=%.4f", det.device, det.threshold)

    verdicts = run_inference(det, file_results, 16)
    classifications = run_classification(clf, file_results, verdicts, 16)
    report = build_report(root, file_results, skipped, args.detector, det.threshold,
                          include_code=True, verdicts=verdicts,
                          classifications=classifications,
                          classifier_checkpoint=args.classifier)

    got = {}
    for fr in report["files"]:
        for fn in fr["functions"]:
            got[f"{fr['path']}::{fn['name']}"] = fn

    # ---- 逐条比对 ----
    bad_v, bad_c, missing = [], [], []
    for t in truth:
        key = f"{t['file']}::{t['function']}"
        fn = got.get(key)
        if fn is None:
            missing.append(key)
            continue
        if fn["verdict"] != t["truth"]:
            bad_v.append((key, t["truth"], fn["verdict"], fn.get("prob_vulnerable", 0)))
        elif t["truth"] == "vulnerable" and t.get("cwe"):
            if fn.get("cwe") != t["cwe"]:
                bad_c.append((key, t["cwe"], fn.get("cwe")))

    extra = sorted(set(got) - {f"{t['file']}::{t['function']}" for t in truth})

    for k in missing:
        log.error("报告里缺少：%s", k)
    for k, want, have, p in bad_v:
        log.error("判定不符：%-46s 期望 %-11s 实际 %-11s (%.1f%%)",
                  k, want, have, p * 100)
    for k, want, have in bad_c:
        log.error("CWE 不符： %-46s 期望 %-9s 实际 %s", k, want, have)
    for k in extra:
        log.error("报告里多出：%s", k)

    n = len(truth)
    print()
    print("=" * 72)
    print(f"夹具校验：{root}")
    print(f"  标签条数   : {n}")
    print(f"  判定一致   : {n - len(bad_v) - len(missing)} / {n}")
    n_cwe = sum(1 for t in truth if t["truth"] == "vulnerable" and t.get("cwe"))
    print(f"  CWE  一致  : {n_cwe - len(bad_c)} / {n_cwe}")
    print("=" * 72)

    if bad_v or bad_c or missing or extra:
        log.error("夹具已经不准了 —— 上面每一条都要查清楚")
        return 1
    # 无格式化参数时 logging 不做 % 处理，这里写单个 % 才对
    log.info("全部一致：这份夹具在当前检查点下仍然 100% 预测正确")
    return 0


if __name__ == "__main__":
    sys.exit(main())
