"""把已构建好的分类数据重新打标，减少类别数（长尾 CWE 归并成 OTHER）。

为什么需要这个脚本
------------------
``build_dataset.py`` 里**已经有**长尾归并逻辑（``min_class_samples`` +
``top_k_classes`` 两个配置项），但那段逻辑跑在**从原始数据构建**的时候。
而 ``merged`` 这个数据源的构建器**不在本仓库里**（``BUILDERS`` 目前只注册
了 ``cvefixes``），所以没法"改配置重跑一遍"。

于是这个脚本换个角度：直接对**已经构建好的** JSONL 重新打标。

它做什么、不做什么
------------------
**做**：只改 ``label`` 列的值，以及重新生成 ``label_map.json``。

**不做**：代码一个字符都不改，样本一条都不增删，train/val/test 的划分完全不变。
所以它**不是数据清洗**（数据本身没有毛病），而是**标签体系的重新设计** ——
把"保留 Top-40 个 CWE"改成"保留 Top-N 个"，剩下的倒进 OTHER。

这是同一件事的两种规模，不是两种东西。原始的 ``min_class_samples`` 归并
已经把 220 种 CWE 里的 180 种倒进了 OTHER，本脚本只是把这条线往下移。

为什么按 ``cwe`` 字段统计，而不是按 ``label``
---------------------------------------------
原始数据里 ``cwe`` 字段**保留着归一化后的原始编号**（如 ``CWE-1333``），
即使这条样本的 ``label`` 早就被归并成 OTHER 了。

按 ``label`` 统计只能看到"现存的 40 个类"，会漏掉那些已经消失在 OTHER 里的
长尾类；按 ``cwe`` 统计才能还原出完整的 220 种类别分布，从而算出**真正**
的 Top-N —— 这和 ``build_dataset.py`` 的口径一致。

排序口径
--------
和 ``build_dataset.py`` 一样：**在全部记录（三个 split 合并）上按样本量降序**，
因为原脚本也是在划分之前就对所有记录编码标签的。沿用同一口径，结果才能和
已有数据对齐、可复现。

用法
----
    # 保留 Top-27 + OTHER = 28 类（本项目的选定配置）
    python scripts/relabel_classes.py --source merged --top-k 27

    # 更激进的归并，11 类
    python scripts/relabel_classes.py --source merged --top-k 10

    # 顺带按样本量过滤（默认不启用，只按 top-k 截断）
    python scripts/relabel_classes.py --source merged --top-k 27 --min-class-samples 50

产出（写入 data/processed/）
---------------------------
``<out>_classification_{train,val,test}.jsonl``   重新打标后的样本
``<out>_classification_label_map.json``           新的类别映射
``<out>_stats.json``                              统计信息

``<out>`` 默认是 ``{source}_top{k}``（如 ``merged_top27``）。**用新名字而不是
覆盖原文件**，这样 41 类版本和 28 类版本能并存 —— 训练时只换 ``--source``
就能做"类别数"的对照实验，不用来回重新生成数据。
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import load_config, resolve_path  # noqa: E402
from src.utils import get_logger, human_int, write_jsonl  # noqa: E402

log = get_logger("relabel_classes")

SPLITS = ("train", "val", "test")
#: OTHER 的固定类名。``id2name`` 里排在被保留类别之后
OTHER_NAME = "OTHER"


def read_jsonl(path: Path) -> list[dict]:
    """读 JSONL 成列表。空行跳过，坏行直接抛 —— 宁可在打标前崩掉。"""
    rows: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{lineno} 不是合法 JSON：{exc}") from exc
    return rows


def build_class_list(
    cwe_counter: collections.Counter, top_k: int | None, min_class_samples: int | None
) -> list[str]:
    """按样本量降序选出要**保留**的 CWE 列表。

    参数
    ----
    cwe_counter : collections.Counter
        ``{原始 CWE 编号: 样本数}``。
    top_k : int | None
        最多保留多少个类别；``None`` 表示不限制。
    min_class_samples : int | None
        样本量低于该值的类别一律不保留；``None`` 表示不启用这道过滤。

    返回
    ----
    list[str]
        保留的 CWE 编号，**已按样本量降序**（决定编号顺序，必须稳定）。

    说明
    ----
    ``most_common()`` 在样本量相同时的顺序取决于插入顺序，为了让结果完全可复现，
    这里显式加一个 ``cwe`` 字符串作为第二排序键。
    """
    ordered = sorted(cwe_counter.items(), key=lambda kv: (-kv[1], kv[0]))
    if min_class_samples is not None:
        ordered = [(c, n) for c, n in ordered if n >= min_class_samples]
    if top_k is not None:
        ordered = ordered[:top_k]
    return [c for c, _ in ordered]


def relabel_split(rows: list[dict], cwe_to_id: dict[str, int], other_id: int) -> list[dict]:
    """把一批样本的 ``label`` 换成新编号。

    只动 ``label`` 一个字段，其余原样保留（``cwe`` / ``cwe_name`` 也不动 ——
    留着原始编号，将来再改类别体系时还能复算）。

    ``copy`` 而不是原地改：调用方还要用原数据做前后对比统计。
    """
    out = []
    for r in rows:
        r2 = dict(r)
        # 不在保留列表里的（长尾类别）统一落到 OTHER
        r2["label"] = cwe_to_id.get(r["cwe"], other_id)
        out.append(r2)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="对已构建的分类数据重新打标，把长尾 CWE 归并成 OTHER 以减少类别数",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--source", default="merged",
                        help="要重新打标的数据源前缀，默认 merged")
    parser.add_argument("--top-k", type=int, default=27,
                        help="保留多少个 CWE 类别（不含 OTHER），默认 27 → 共 28 类")
    parser.add_argument("--min-class-samples", type=int, default=None,
                        help="样本量低于该值的类别不保留（默认不启用，只按 --top-k 截断）")
    parser.add_argument("--out", default=None,
                        help="输出前缀，默认 {source}_top{top-k}")
    parser.add_argument("--task", default="classification",
                        help="任务名，默认 classification")
    args = parser.parse_args()

    cfg = load_config()
    data_dir: Path = resolve_path(cfg["data"]["cache_dir"])

    out_name = args.out or f"{args.source}_top{args.top_k}"
    if out_name == args.source:
        # 覆盖原文件会让两个版本无法并存，也失去了回退的余地
        raise SystemExit(f"--out 不能和 --source 相同（{out_name}），否则会覆盖原始数据")

    # ---- 1. 读入三个 split ----
    raw: dict[str, list[dict]] = {}
    for split in SPLITS:
        p = data_dir / f"{args.source}_{args.task}_{split}.jsonl"
        if not p.exists():
            raise SystemExit(f"缺少数据文件 {p}")
        raw[split] = read_jsonl(p)
        log.info("读入 %-5s %s 条  (%s)", split, human_int(len(raw[split])), p.name)

    total = sum(len(v) for v in raw.values())

    # ---- 2. 在全部记录上按原始 cwe 统计，选出保留列表 ----
    # 用 cwe 而不是 label：label 已经把长尾并成 OTHER 了，看不出原始分布
    counter: collections.Counter = collections.Counter()
    for rows in raw.values():
        counter.update(r["cwe"] for r in rows if r.get("cwe"))

    kept = build_class_list(counter, args.top_k, args.min_class_samples)
    if not kept:
        raise SystemExit("没有选出任何类别，检查 --top-k / --min-class-samples")

    cwe_to_id = {c: i for i, c in enumerate(kept)}
    other_id = len(cwe_to_id)
    id_to_name = {str(i): c for c, i in cwe_to_id.items()}
    id_to_name[str(other_id)] = OTHER_NAME
    num_labels = len(id_to_name)

    log.info("原始 CWE 种类：%d 种", len(counter))
    log.info("保留 %d 个 CWE + OTHER = %d 类", len(kept), num_labels)

    # ---- 3. 重新打标并落盘 ----
    stats: dict[str, Any] = {
        "source": args.source, "out": out_name, "task": args.task,
        "top_k": args.top_k, "min_class_samples": args.min_class_samples,
        "num_labels": num_labels, "raw_cwe_kinds": len(counter),
        "kept": kept, "splits": {},
    }

    for split in SPLITS:
        before = collections.Counter(r["label"] for r in raw[split])
        rows = relabel_split(raw[split], cwe_to_id, other_id)
        after = collections.Counter(r["label"] for r in rows)

        out_path = data_dir / f"{out_name}_{args.task}_{split}.jsonl"
        n = write_jsonl(rows, out_path)

        # 样本数必须一条不差：本脚本只改标签，不增删样本
        if n != len(raw[split]):
            raise SystemExit(
                f"{split} 写出的条数 {n} 与读入的 {len(raw[split])} 不一致，"
                f"本脚本不应增删样本，请检查"
            )
        stats["splits"][split] = {
            "n": n,
            "classes_before": len(before),
            "classes_after": len(after),
            # 显式记一份 OTHER 的条数：label_dist 的键是 int，写进 JSON 后会被
            # 转成字符串，从里面取容易踩坑（第一版就踩了，打印出 0 条）
            "other_count": after.get(other_id, 0),
            "kept_count": n - after.get(other_id, 0),
            "label_dist": dict(sorted(after.items())),
        }
        log.info("%-5s %s 条 -> %s  (类别 %d -> %d)",
                 split, human_int(n), out_path.name, len(before), len(after))

    # ---- 4. 写标签映射与统计 ----
    lm_path = data_dir / f"{out_name}_{args.task}_label_map.json"
    with open(lm_path, "w", encoding="utf-8") as f:
        json.dump(
            {"task": args.task, "num_labels": num_labels,
             "id2name": id_to_name, "name2id": cwe_to_id},
            f, ensure_ascii=False, indent=2,
        )
    log.info("标签映射 -> %s", lm_path.name)

    stats_path = data_dir / f"{out_name}_stats.json"
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    # ---- 5. 打印前后对比，方便肉眼确认归并结果 ----
    merged_away = [c for c in counter if c not in cwe_to_id]
    other_n = stats["splits"]["train"]["other_count"]
    print()
    print("=" * 74)
    print(f"重新打标完成：{args.source}  ->  {out_name}")
    print("=" * 74)
    print(f"  样本总数   : {human_int(total)} 条（未增删）")
    print(f"  类别数     : {len(counter)} 种 CWE  ->  {len(kept)} 个 CWE + OTHER = {num_labels} 类")
    print(f"  保留的 CWE : {', '.join(kept)}")
    print(f"  归入 OTHER : {len(merged_away)} 种 CWE，训练集里 {human_int(other_n)} 条"
          f"（占 {other_n / max(stats['splits']['train']['n'], 1):.1%}）")
    print()
    print(f"  下一步：python scripts/train.py --task classification "
          f"--source {out_name} --run-name {out_name}_codebert")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
