"""扫描整个项目：抽取函数 → 逐个推理 → 按文件汇总"有几个函数有漏洞"。

为什么需要这个脚本
------------------
模型（``VulnClassifier``）用 [CLS] 池化，一次前向只对**一段代码**输出**一个**
结论 —— 它自己答不了"这个文件里有几个函数有漏洞"。所以流程必须是：

    遍历项目文件 → 用 tree-sitter 抽出每个函数 → 逐函数推理 → 按文件聚合统计

``src/extract.py`` 负责第一、二步，本脚本负责串起来并产出报告。

用法
----
    # 只抽取，不推理（不需要模型权重，任何机器都能跑）
    python scripts/scan_project.py src/

    # 连推理一起做（需要训练好的检查点）
    python scripts/scan_project.py . --checkpoint outputs/merged_detection_codebert/best

    # 只要顶层函数、跳过测试目录、不把源码写进报告
    python scripts/scan_project.py . --checkpoint <ckpt> --outer-only \
        --skip-dir tests --no-code --output outputs/scan_result.json

    # 两级级联：检测命中后，再判断"是哪一类 CWE"（需要两个模型）
    python scripts/scan_project.py . \
        --checkpoint outputs/<检测run>/best \
        --classifier outputs/<分类run>/best

两级级联
--------
``--checkpoint``（检测）与 ``--classifier``（分类）是**两个独立的模型**，
必须分开传，不能共用一个参数：``VulnPredictor`` 一个实例只能是一个任务，
而检测检查点跑到这里会被下面的任务校验直接拒掉。

第二级**只对检测命中的函数跑**，理由见 ``run_classification`` 的 docstring ——
简言之，分类数据里没有"安全"这一类，拿安全函数去分类只会得到噪声。

关于截断（重要）
----------------
**不要在这里再截断代码**。推理器的 ``predict_probs`` 内部已经对每条输入调过
``truncate_code``（头 60% + 尾 40%，与训练时完全一致），扫描侧再做一次只会
让输入分布和训练时对不上。函数原样交给推理器即可。

退出码
------
扫描过程**恒返回 0**：单个文件读不了、语法错、编码怪，都记进报告的 ``skipped``
字段继续扫下一个 —— 扫别人的项目时这是常态，不该中断整轮扫描。
（若日后要拿它做 CI 卡点，可在此基础上加 ``--fail-on-suspicious`` 之类的开关。）
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import resolve_path  # noqa: E402
from src.extract import (  # noqa: E402
    MAX_FILE_BYTES,
    extract_from_file,
    supported_extensions,
)
from src.utils import ensure_dir, get_logger, human_int  # noqa: E402

log = get_logger("scan")

#: 报告格式版本。CI 集成方按它判断字段有没有变，改动 schema 时必须递增。
SCHEMA_VERSION = 1

#: 默认跳过的目录名。
#:
#: 这些目录里几乎不会有"需要审的源码"：要么是版本控制元数据，要么是第三方
#: 依赖（扫它们等于把整个生态的漏洞都算到自己头上），要么是构建产物。
#: 想要全扫就传 ``--no-skip``。
DEFAULT_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "bower_components", "vendor", "third_party",
    "__pycache__", ".venv", "venv", "env", ".env", "site-packages", ".tox", ".eggs",
    "dist", "build", "target",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea", ".vscode",
})


def iter_source_files(
    root: Path,
    skip_dirs: frozenset[str],
    respect_skip: bool,
) -> list[Path]:
    """遍历目录，返回所有扩展名受支持的源码文件。

    参数
    ----
    root : Path
        扫描根目录。
    skip_dirs : frozenset[str]
        要跳过的目录名（按名字匹配，不区分层级）。
    respect_skip : bool
        False 时什么都不跳（``--no-skip``）。

    返回
    ----
    list[Path]
        按相对路径排序的文件列表。

    说明
    ----
    输出**必须确定**：同一份代码扫两次，报告要能逐字节比对（CI 里靠它判断
    "这次扫描和上次有没有区别"）。``os.walk`` 本身不保证顺序，所以这里
    对 ``dirnames`` 原地排序，最后再按相对路径整体排一次。
    """
    exts = set(supported_extensions())
    found: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(root):
        kept = [
            d for d in dirnames
            if not (respect_skip and (d in skip_dirs or d.startswith(".")))
        ]
        dirnames[:] = sorted(kept)  # 原地赋值才是 os.walk 认的"剪枝"方式
        for fn in filenames:
            if Path(fn).suffix.lower() in exts:
                found.append(Path(dirpath) / fn)

    return sorted(found, key=lambda p: p.relative_to(root).as_posix())


def scan_files(
    files: list[Path],
    root: Path,
    max_bytes: int,
    outer_only: bool,
) -> tuple[list[dict], list[dict], int]:
    """逐个文件抽取函数。

    参数
    ----
    files : list[Path]
        待扫描的文件。
    root : Path
        扫描根目录（用来算报告里的相对路径）。
    max_bytes : int
        单文件体积上限，传给 ``extract_from_file``。
    outer_only : bool
        只保留顶层函数（丢掉闭包与嵌套定义）。

    返回
    ----
    tuple[list[dict], list[dict], int]
        ``(文件结果列表, 跳过列表, 函数总数)``。

    说明
    ----
    单个文件出任何问题都**不抛异常**，而是记进跳过列表继续 ——
    扫描第三方项目时，坏文件是常态而非例外。
    """
    results: list[dict] = []
    skipped: list[dict] = []
    total = 0

    for p in files:
        rel = p.relative_to(root).as_posix()
        try:
            res = extract_from_file(p, max_bytes=max_bytes)
        except Exception as exc:  # noqa: BLE001 - 扫描器绝不能因为一个文件挂掉
            skipped.append({"path": rel, "reason": f"{type(exc).__name__}: {exc}"})
            continue

        if res.error:
            # 读失败 / 二进制 / 体积超限 / 扩展名不认识，都在这里
            skipped.append({"path": rel, "reason": res.error})
            continue

        funcs = res.functions
        if outer_only:
            funcs = [f for f in funcs if f.depth == 0]
        total += len(funcs)

        results.append({
            "path": rel,
            "language": res.language,
            "parse_ok": res.parse_ok,
            "num_bytes": res.num_bytes,
            "function_count": len(funcs),
            "functions_discarded": res.functions_discarded,
            "functions": funcs,
        })

    return results, skipped, total


def run_inference(
    predictor,
    file_results: list[dict],
    batch_size: int,
) -> dict[tuple[int, int], dict]:
    """对已抽出的函数逐个推理。

    参数
    ----
    predictor : VulnPredictor
        已加载的推理器（``task`` 必须为 ``detection``）。
    file_results : list[dict]
        抽取结果，``functions`` 里是 ``FunctionInfo`` 对象。
    batch_size : int
        推理批大小。

    返回
    ----
    dict[tuple[int, int], dict]
        ``{(文件下标, 函数下标): 判定结果}``。用**位置**作键而不是改
        ``FunctionInfo`` 对象：``src/extract.py`` 是纯粹的抽取模块，
        不该为"有没有推理过"多出几个字段。

    说明
    ----
    这里刻意复用 ``VulnPredictor.predict()`` 而不是自己拿概率比阈值：
    判定逻辑（默认 0.5 → ``best/threshold.json`` → ``--threshold`` 覆盖）
    只在 ``predict.py`` 里实现一次，扫描结果才能和 ``scripts/predict.py``
    逐条对齐。
    """
    from tqdm import tqdm

    # 压平成一维：记下 (文件下标, 函数下标)，推理完照着位置对回去
    items: list[tuple[int, int, str]] = [
        (fi, gi, f.code)
        for fi, fr in enumerate(file_results)
        for gi, f in enumerate(fr["functions"])
    ]
    if not items:
        return {}

    verdicts: dict[tuple[int, int], dict] = {}
    for i in tqdm(range(0, len(items), batch_size), desc="推理", unit="batch"):
        chunk = items[i:i + batch_size]
        preds = predictor.predict([code for _, _, code in chunk])
        for (fi, gi, _), pred in zip(chunk, preds):
            verdicts[(fi, gi)] = pred
    return verdicts


def run_classification(
    classifier,
    file_results: list[dict],
    verdicts: dict[tuple[int, int], dict],
    batch_size: int,
) -> dict[tuple[int, int], dict]:
    """第二级：对**检测命中**的函数跑分类，给出 CWE 类别。

    参数
    ----
    classifier : VulnPredictor
        已加载的推理器（``task`` 必须为 ``classification``）。
    file_results, verdicts : 第一级的产物
        只有 ``verdicts`` 里判定为 ``vulnerable`` 的函数才会被送进来。
    batch_size : int
        推理批大小。

    返回
    ----
    dict[tuple[int, int], dict]
        ``{(文件下标, 函数下标): 分类结果}``，**只包含真正跑过分类的项**。

    为什么只对命中函数跑（docs/07 3.2）
    -----------------------------------
    1. **数据决定了不能喂安全函数**：分类训练数据全部取自漏洞样本
       （``build_dataset.py`` 只取 ``label==1`` 且有 ``cwe`` 的），
       类别里**没有"安全"这一项**。拿安全函数去分类，等于逼模型在 27 个
       CWE 里硬挑一个 —— 结果必然是噪声，而且长得和真结果一模一样，
       审查的人根本分不出来。
    2. **省算力**：真实仓库的命中率通常远小于 1，逐函数跑两个模型纯属浪费。

    这也和 ``build_report`` 里的写入条件严格对应：``cwe`` 只会出现在
    ``verdict == "vulnerable"`` 的函数节点上。
    """
    from tqdm import tqdm

    items: list[tuple[int, int, str]] = [
        (fi, gi, f.code)
        for fi, fr in enumerate(file_results)
        for gi, f in enumerate(fr["functions"])
        if verdicts.get((fi, gi), {}).get("verdict") == "vulnerable"
    ]
    # 一个命中的都没有就别进模型：predict([]) 会一路走到 tokenizer 和前向，
    # 白白吃一次空 batch（run_inference 里同样的守卫）
    if not items:
        return {}

    results: dict[tuple[int, int], dict] = {}
    for i in tqdm(range(0, len(items), batch_size), desc="分类", unit="batch"):
        chunk = items[i:i + batch_size]
        preds = classifier.predict([code for _, _, code in chunk])
        for (fi, gi, _), pred in zip(chunk, preds):
            results[(fi, gi)] = pred
    return results


def build_report(
    root: Path,
    file_results: list[dict],
    skipped: list[dict],
    checkpoint: str | None,
    threshold: float | None,
    include_code: bool,
    verdicts: dict[tuple[int, int], dict],
    classifications: dict[tuple[int, int], dict] | None = None,
    classifier_checkpoint: str | None = None,
) -> dict:
    """把扫描结果组装成可 JSON 序列化的报告。

    字段设计以"CI 要稳定消费"为准：顶层键名固定，新增字段只加不改；
    ``schema_version`` 用于将来做破坏性变更时让消费方感知。

    路径一律用 POSIX 风格的**相对路径**（``as_posix()``）：报告要能在
    Windows 上生成、在 Linux CI 里比对，绝对路径和反斜杠都不满足这个要求。

    两级级联（见 docs/07 第三节）
    -----------------------------
    ``verdicts`` 是第一级（检测）的结果，``classifications`` 是第二级的结果，
    后者只对**检测命中**的函数存在。两者都是"有就写、没有就不写"的**可选**
    字段：没跑推理的报告不会冒出一个 ``verdict: null``，没跑分类的报告也不会
    冒出一个 ``cwe: null`` —— 否则消费方会把它误读成"模型判定为安全/无类别"。
    """
    languages: dict[str, int] = {}
    functions_total = 0
    suspicious_total = 0
    classified_total = 0

    out_files = []
    for fi, fr in enumerate(file_results):
        functions_total += fr["function_count"]
        lang = fr["language"] or "unknown"
        languages[lang] = languages.get(lang, 0) + fr["function_count"]

        out_funcs = []
        file_suspicious = 0
        for gi, f in enumerate(fr["functions"]):
            d = f.to_dict(include_code=include_code)
            pred = verdicts.get((fi, gi))
            if pred is not None:
                d["verdict"] = pred["verdict"]
                d["confidence"] = float(pred["confidence"])
                d["prob_vulnerable"] = float(pred["prob_vulnerable"])
                if pred["verdict"] == "vulnerable":
                    file_suspicious += 1
                    # 第二级（分类）只在检测命中时才可能有过结果。
                    # 注意 predict.py 返回的键叫 ``topk``，报告里叫 ``cwe_topk``
                    # —— 换个更明确的名字，免得消费方以为它是通用的 top-k。
                    cls = (classifications or {}).get((fi, gi))
                    if cls is not None:
                        d["cwe"] = cls["cwe"]
                        d["cwe_topk"] = cls["topk"]
                        classified_total += 1
            # 没给 checkpoint 时**不写** verdict 字段，避免报告里出现
            # "verdict: null" 这种容易被误读成"模型判定为安全"的歧义
            out_funcs.append(d)

        suspicious_total += file_suspicious
        out_files.append({
            "path": fr["path"],
            "language": fr["language"],
            "parse_ok": fr["parse_ok"],
            "num_bytes": fr["num_bytes"],
            "function_count": fr["function_count"],
            "suspicious_count": file_suspicious,
            "functions_discarded": fr["functions_discarded"],
            "functions": out_funcs,
        })

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "scanman",
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "root": str(root),
        "checkpoint": checkpoint,
        "threshold": threshold,
        # 只增不改：新键，不影响老消费方；没跑分类时为 null
        "classifier_checkpoint": classifier_checkpoint,
        "summary": {
            "files_scanned": len(out_files),
            "files_skipped": len(skipped),
            "functions_total": functions_total,
            "functions_suspicious": suspicious_total,
            # 跑过分类的函数数（= 命中函数里成功拿到 CWE 的那些）
            "functions_classified": classified_total,
            "languages": languages,
        },
        "skipped": skipped,
        "files": out_files,
    }


def print_summary(report: dict, top_n: int = 10) -> None:
    """在终端打印人类可读的摘要（报告本身是给程序读的）。"""
    s = report["summary"]
    print()
    print("=" * 72)
    print("扫描结果")
    print("=" * 72)
    print(f"  扫描根目录 : {report['root']}")
    print(f"  文件       : {human_int(s['files_scanned'])} 个"
          f"（跳过 {human_int(s['files_skipped'])} 个）")
    print(f"  函数       : {human_int(s['functions_total'])} 个")
    if report["checkpoint"]:
        print(f"  检查点     : {report['checkpoint']}")
        print(f"  判定阈值   : {report['threshold']:.4f}")
        print(f"  可疑函数   : {human_int(s['functions_suspicious'])} 个"
              f"（占 {s['functions_suspicious'] / max(s['functions_total'], 1):.1%}）")
        # "只增不改"：老报告里没有这两个键，用 .get 兜底，不要让旧报告打不出来
        if report.get("classifier_checkpoint"):
            print(f"  分类器     : {report['classifier_checkpoint']}")
            print(f"  已分类     : {human_int(s.get('functions_classified', 0))} 个"
                  f"（命中函数的 CWE 结果）")
    else:
        print("  推理       : 未启用（未提供 --checkpoint，只做函数抽取）")
    if s["languages"]:
        langs = "、".join(f"{k} {v}" for k, v in sorted(s["languages"].items()))
        print(f"  语言分布   : {langs}")

    # ---- 最可疑的若干个函数：按"有漏洞的概率"降序 ----
    if report["checkpoint"]:
        cands = [
            (f["prob_vulnerable"], fr["path"], f)
            for fr in report["files"]
            for f in fr["functions"]
            if f.get("verdict") == "vulnerable"
        ]
        if cands:
            cands.sort(key=lambda t: -t[0])
            print()
            print(f"  最可疑的 {min(top_n, len(cands))} 个函数：")
            for prob, path, f in cands[:top_n]:
                # 跑过分类就有 cwe 字段，没有就不显示 —— 不留空位
                cwe = f.get("cwe")
                cwe_col = f"  {cwe:<10}" if cwe else ""
                print(f"    {path}:{f['start_line']:<6} {f['name']:<32} "
                      f"conf={prob:.3f}{cwe_col}")

    if report["skipped"]:
        print()
        print(f"  跳过的文件（共 {len(report['skipped'])} 个，原因分布）：")
        reasons: dict[str, int] = {}
        for it in report["skipped"]:
            key = it["reason"].split(":")[0]
            reasons[key] = reasons.get(key, 0) + 1
        for k, v in sorted(reasons.items(), key=lambda kv: -kv[1]):
            print(f"    {k:<20} {v}")
    print("=" * 72)


def main() -> int:
    """命令行入口：解析参数 → 遍历 → 抽取 →（可选）推理 → 写报告。"""
    parser = argparse.ArgumentParser(
        description="扫描项目文件，报告每个文件里有多少个函数可能存在漏洞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", type=str, help="要扫描的目录（或单个文件）")
    parser.add_argument("--output", default="outputs/scan_result.json",
                        help="报告输出路径（相对路径按项目根目录解析）")
    parser.add_argument("--checkpoint", default=None,
                        help="微调后的检测模型目录；不给则只抽取不推理")
    parser.add_argument("--classifier", default=None,
                        help="微调后的分类模型目录。给定时对**检测命中**的函数"
                             "再跑一级 CWE 分类，报告里多出 cwe/cwe_topk 字段")
    parser.add_argument("--device", default=None,
                        help="cpu | cuda | mps | cuda:1，默认自动（CUDA > MPS > CPU）")
    parser.add_argument("--batch-size", type=int, default=16, help="推理批大小")
    parser.add_argument("--threshold", type=float, default=None,
                        help="判定阈值（默认读检查点的 best/threshold.json，没有则 0.5）")
    parser.add_argument("--max-file-size", type=int, default=MAX_FILE_BYTES,
                        help=f"单文件体积上限（字节，默认 {MAX_FILE_BYTES:,}），超过则跳过")
    parser.add_argument("--outer-only", action="store_true",
                        help="只统计顶层函数（丢嵌套函数与闭包）")
    parser.add_argument("--skip-dir", action="append", default=[],
                        metavar="NAME",
                        help="额外跳过的目录名，可重复指定")
    parser.add_argument("--no-skip", action="store_true",
                        help="不跳过任何目录（默认跳过 .git/node_modules/venv 等）")
    parser.add_argument("--no-code", action="store_true",
                        help="报告里不写函数源码（体积小很多）")
    args = parser.parse_args()

    root = Path(args.path)
    if not root.is_absolute():
        root = Path.cwd() / root
    root = root.resolve()
    if not root.exists():
        log.error("路径不存在: %s", root)
        return 2

    # ---- 1. 遍历 ----
    skip_dirs = DEFAULT_SKIP_DIRS | frozenset(args.skip_dir)
    if root.is_file():
        files = [root]
        root = root.parent  # 让报告里的相对路径有意义
    else:
        files = iter_source_files(root, skip_dirs, respect_skip=not args.no_skip)
    log.info("找到 %s 个候选源码文件", human_int(len(files)))
    if not files:
        log.warning("没有找到任何受支持扩展名的文件，检查一下路径或扩展名")

    # ---- 2. 抽取 ----
    file_results, skipped, _total = scan_files(
        files, root, args.max_file_size, args.outer_only
    )
    n_funcs = sum(fr["function_count"] for fr in file_results)
    log.info("抽取完成：%s 个文件里共 %s 个函数（跳过 %d 个文件）",
             human_int(len(file_results)), human_int(n_funcs), len(skipped))

    # ---- 3. 推理（可选） ----
    threshold = None
    verdicts: dict[tuple[int, int], dict] = {}
    if args.checkpoint:
        from scripts.predict import VulnPredictor  # 延迟导入：不推理时不需要 torch

        predictor = VulnPredictor(args.checkpoint, device=args.device,
                                  threshold=args.threshold)
        if predictor.task != "detection":
            # 分类模型输出的是 CWE 类别，没有"有没有漏洞"这个概念，
            # 拿它当检测器用只会得到一堆无意义的结论，直接拒绝。
            log.error("检查点任务是 %r，不是 detection —— 请换用检测模型。",
                      predictor.task)
            return 2
        threshold = predictor.threshold
        log.info("模型加载完成 | 设备=%s | 阈值=%.4f",
                 predictor.device, predictor.threshold)

        verdicts = run_inference(predictor, file_results, args.batch_size)
        n_susp = sum(1 for v in verdicts.values() if v["verdict"] == "vulnerable")
        log.info("推理完成：可疑函数 %s 个", human_int(n_susp))

    # ---- 3b. 第二级分类（可选，必须有检测结果才有意义） ----
    classifications: dict[tuple[int, int], dict] = {}
    if args.classifier:
        if not args.checkpoint:
            # 级联的前提是"检测先命中"。没有第一级就没有命中集合，
            # 硬跑分类只能把所有函数都当可疑喂进去 —— 那正是要避免的用法。
            log.error("--classifier 需要配合 --checkpoint 一起用："
                      "分类只对检测命中的函数跑，没有检测结果就没有命中集合。")
            return 2
        from scripts.predict import VulnPredictor  # 延迟导入：不推理时不需要 torch

        classifier = VulnPredictor(args.classifier, device=args.device)
        if classifier.task != "classification":
            log.error("--classifier 指向的检查点任务是 %r，不是 classification。",
                      classifier.task)
            return 2
        log.info("分类器加载完成 | 设备=%s | 类别数=%d",
                 classifier.device, classifier.num_labels)

        classifications = run_classification(
            classifier, file_results, verdicts, args.batch_size
        )
        log.info("分类完成：%s 个命中函数给出了 CWE 类别", human_int(len(classifications)))

    # ---- 4. 写报告 ----
    report = build_report(root, file_results, skipped, args.checkpoint,
                          threshold, include_code=not args.no_code,
                          verdicts=verdicts,
                          classifications=classifications,
                          classifier_checkpoint=args.classifier)
    out_path = resolve_path(args.output)
    ensure_dir(out_path.parent)
    # ensure_ascii=False：中文注释/路径按原样写，人也能直接读
    out_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print_summary(report)
    log.info("报告已写入 -> %s", out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
