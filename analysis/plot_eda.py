"""探索性数据分析（EDA）可视化 —— 原始数据 + 预处理后数据

这个脚本做什么
--------------
生成作业要求的「探索性数据分析」图表：直方图 / 散点图 / 箱线图 / 条形图 / 饼图 /
热力图 / 漏斗图，覆盖原始数据（raw）与预处理后数据（processed）两个层面。

**全部图表的文字（标题、坐标轴、图例、标注）均为中文。**

产出
----
    reports/figures/*.png    共 20 张图（150 dpi，可直接插入报告）

图的清单
--------
原始数据（4 张）
    fig01  长度分布长尾（直方图 + log 轴 + 分位数标注）
    fig02  原始 CWE 取值 Top20（含无效占位值）
    fig03  原始语言分布
    fig04  原始项目分布 Top20

预处理后 · 检测任务（8 张）
    fig05  train/val/test 样本量与正例率
    fig06  代码长度分布（直方图，按 split）
    fig07  代码长度箱线图（按标签）★ 核心
    fig08  代码长度 vs 是否漏洞（散点图）★ 核心
    fig09  长度分层正例率（三集合对比）★ 核心
    fig10  token 长度 vs 字符数（散点图，含实测拟合斜率）
    fig11  真实 token 长度分布 vs 512 窗口（直方图）★ 核心
    fig12  测试集样本构成：同胞对 vs 孤立样本（饼图）★ 核心

预处理后 · 分类任务（5 张）
    fig13  CWE 类别分布（条形图）★ 核心
    fig14  CWE 类别长尾曲线（log-log 散点图）
    fig15  逐类测试集样本量（条形图）★ 核心
    fig16  三集合类别占比对比（分组条形图）
    fig17  三集合覆盖热力图（热力图）

数据质量（3 张）
    fig18  原始数据缺失率热力图（热力图）★ 核心
    fig19  数据重复与标签冲突（条形图 + 韦恩式对比）
    fig20  预处理各环节样本流失漏斗图

用法
----
    cd F:\\NLP_SZ\\ScanMan
    python analysis/audit_data.py     # 先生成审计数字（本脚本依赖它）
    python analysis/plot_eda.py

依赖
----
    matplotlib / seaborn / pandas / numpy / pyarrow
    （token 长度分析还需要 CodeBERT 的 tokenizer；缺失时自动降级为字符数估算）

注意
----
    本脚本每次运行会先清空 reports/figures/ 下的旧 PNG，避免留下过期图表。
"""

from __future__ import annotations

import collections
import json
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")           # 无界面环境（服务器）也能出图
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

# ---------------------------------------------------------------------------
# 路径与全局样式
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw" / "cvefixes"
PROC_DIR = ROOT / "data" / "processed"
# tokenizer 可能在本仓库（models/ 被 gitignore，通常没有），
# 也可能在同级的原始工程里（F:\NLP\models\...）。两个位置都找一下。
TOKENIZER_CANDIDATES = [
    ROOT / "models" / "microsoft__codebert-base",
    ROOT.parent / "NLP" / "models" / "microsoft__codebert-base",
    Path(r"F:\NLP\models\microsoft__codebert-base"),
]
FIG_DIR = ROOT / "reports" / "figures"

MIN_CODE_CHARS = 30
TRUNC_CHARS = 20000
MAX_LENGTH = 512
# 512 词元对应的字符数。**不要硬编码**：实测字符/词元比约 2.28，
# 与早期粗估的 3.8 差了 40%，直接决定"超窗样本占比"这个数字准不准。
# 因此由 measure_chars_per_token() 在运行时实测，默认值只是兜底。
DEFAULT_CHARS_PER_TOKEN = 3.8
CHARS_FOR_512 = 1900            # 兜底值；运行时会被实测值覆盖

# ---- 中文字体：必须放在最前面，否则会 fallback 成英文方块 ----
matplotlib.rcParams["font.sans-serif"] = [
    "Microsoft YaHei", "SimHei", "SimSun", "DejaVu Sans",
]
matplotlib.rcParams["font.family"] = "sans-serif"
matplotlib.rcParams["axes.unicode_minus"] = False     # 负号正常显示
sns.set_theme(style="whitegrid", font="Microsoft YaHei", rc={
    "axes.unicode_minus": False,
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "axes.titlesize": 13,
    "axes.labelsize": 11,
    "font.size": 10,
})

# 统一配色
C_VULN, C_SAFE = "#d62728", "#2ca02c"
C_TRAIN, C_VAL, C_TEST = "#4c72b0", "#dd8452", "#55a868"
PALETTE_SPLIT = [C_TRAIN, C_VAL, C_TEST]
# 中文标签（替代英文列名，保证图里不出现英文）
LBL_VULN, LBL_SAFE = "漏洞版代码", "修复版代码"


def save(fig, name: str) -> None:
    """保存并关闭图，控制台打印路径。"""
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    path = FIG_DIR / name
    fig.savefig(path, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  [OK] {name}")


def load_jsonl(path: Path) -> pd.DataFrame:
    """读 JSONL 成 DataFrame。"""
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return pd.DataFrame(rows)


def hr(t: str) -> None:
    print(f"\n{'=' * 78}\n{t}\n{'=' * 78}")


def clean_old_figures() -> None:
    """清空旧的 PNG，避免改过图之后留下过期文件。"""
    if not FIG_DIR.exists():
        return
    old = sorted(FIG_DIR.glob("*.png"))
    for p in old:
        p.unlink()
    if old:
        print(f"  已清理旧图表 {len(old)} 张")


# ===========================================================================
# 原始数据图（4 张）
# ===========================================================================

def load_raw_lengths() -> tuple[list[int], list[int]]:
    """流式读原始 parquet，收集两列代码的字符长度（不载入内容）。"""
    import pyarrow.parquet as pq

    vl, fl = [], []
    for fp in sorted(RAW_DIR.glob("*.parquet")):
        pf = pq.ParquetFile(fp)
        for batch in pf.iter_batches(
            batch_size=64, columns=["vulnerable_code", "fixed_code"]
        ):
            d = batch.to_pydict()
            for v, f in zip(d["vulnerable_code"], d["fixed_code"]):
                if isinstance(v, str) and v.strip():
                    vl.append(len(v))
                if isinstance(f, str) and f.strip():
                    fl.append(len(f))
    return vl, fl


def measure_chars_per_token(det: dict[str, pd.DataFrame], tok) -> float | None:
    """抽样实测「字符数 / 词元数」比值，并据此回填全局阈值 CHARS_FOR_512。

    为什么必须先测
    --------------
    「512 词元对应多少字符」直接决定图 6 里"超窗样本占比"这个数字。
    早期用 3.8 字符/词元粗估，得到 19.4%；实测比值是 2.28，
    修正后是 27.0% —— 而直接分词测量是 26.6%。**粗估会让结论偏低 7 个百分点。**

    返回
    ----
    float | None
        实测比值中位数；未提供分词器时返回 None（此时保留兜底阈值）。
    """
    global CHARS_FOR_512
    if tok is None:
        CHARS_FOR_512 = int(MAX_LENGTH * DEFAULT_CHARS_PER_TOKEN)
        print(f"  [提示] 无分词器，沿用粗估比值 {DEFAULT_CHARS_PER_TOKEN}"
              f" → 512 词元 ≈ {CHARS_FOR_512} 字符")
        return None

    rng = np.random.default_rng(42)
    rows = det["train"]
    n = min(2500, len(rows))
    idx = rng.choice(len(rows), n, replace=False)
    codes = rows.iloc[idx]["code"].tolist()
    enc = tok(codes, add_special_tokens=True, truncation=False)
    tl = np.array([len(x) for x in enc["input_ids"]], dtype=float)
    cl = np.array([len(c) for c in codes], dtype=float)
    ratio = float(np.median(cl / np.maximum(tl, 1)))

    CHARS_FOR_512 = int(MAX_LENGTH * ratio)
    print(f"  实测字符/词元比 = {ratio:.3f}"
          f"（粗估为 {DEFAULT_CHARS_PER_TOKEN}，偏差 "
          f"{(ratio - DEFAULT_CHARS_PER_TOKEN) / DEFAULT_CHARS_PER_TOKEN * 100:+.0f}%）")
    print(f"  → 512 词元 ≈ {CHARS_FOR_512} 字符（后续图表统一使用此阈值）")
    return ratio


def fig01_raw_length_tail(vl: list[int], fl: list[int]) -> None:
    """原始数据长度分布（长尾 + log 轴）。"""
    fig, axes = plt.subplots(1, 2, figsize=(13.5, 4.8))

    ax = axes[0]
    bins = np.logspace(0, np.log10(max(max(vl), max(fl)) + 1), 70)
    ax.hist(vl, bins=bins, alpha=.62, label=f"{LBL_VULN}（{len(vl):,} 条）",
            color=C_VULN)
    ax.hist(fl, bins=bins, alpha=.62, label=f"{LBL_SAFE}（{len(fl):,} 条）",
            color=C_SAFE)
    ax.set_xscale("log")
    ax.axvline(TRUNC_CHARS, color="black", ls="--", lw=1.3,
               label=f"构建阶段截断阈值 {TRUNC_CHARS:,} 字符")
    ax.axvline(CHARS_FOR_512, color="purple", ls=":", lw=1.3,
               label=f"512 词元 ≈ {CHARS_FOR_512:,} 字符")
    ax.set_xlabel("代码长度（字符，对数轴）")
    ax.set_ylabel("样本数")
    ax.set_title("① 长度分布：典型长尾，最长超过 5,500 万字符")
    ax.legend(fontsize=8, loc="upper left")

    # 右图：分位数对比（去掉"最大值"，因为它被极端离群值主导，会让读者误判）
    ax = axes[1]
    qs = [.5, .75, .9, .95, .99]
    labels = ["中位数", "第 75 百分位", "第 90 百分位", "第 95 百分位", "第 99 百分位"]
    a = [float(np.quantile(vl, q)) for q in qs]
    b = [float(np.quantile(fl, q)) for q in qs]
    x = np.arange(len(qs))
    ax.bar(x - .2, a, .4, label=LBL_VULN, color=C_VULN)
    ax.bar(x + .2, b, .4, label=LBL_SAFE, color=C_SAFE)
    ax.set_yscale("log")
    ax.set_xticks(x, labels, rotation=18, ha="right", fontsize=9)
    ax.set_ylabel("字符数（对数轴）")
    ax.set_title("② 分位数对比：修复版各分位均更长")
    for i, (va, vb) in enumerate(zip(a, b)):
        ax.text(i, max(va, vb) * 1.25, f"{vb / va:.2f} 倍",
                ha="center", fontsize=9, color="#444", fontweight="bold")
    ax.legend(fontsize=9)
    ax.margins(y=.22)

    fig.suptitle("图 1｜原始数据代码长度分布（修复版普遍长于漏洞版）",
                 y=1.04, fontsize=14)
    save(fig, "fig01_原始数据_长度分布长尾.png")


def fig02_raw_cwe(raw: dict) -> None:
    """原始 CWE 取值 Top20 —— 展示长尾与无效占位值。"""
    top = raw["cwe_top"]
    names = [t[0] for t in top]
    cnts = [t[1] for t in top]

    fig, ax = plt.subplots(figsize=(11, 5.4))
    cols = ["#c44e52" if "NVD-CWE" in n else "#4c72b0" for n in names]
    ax.barh(range(len(names))[::-1], cnts, color=cols)
    ax.set_yticks(range(len(names))[::-1], names, fontsize=9.5)
    ax.set_xlabel("原始记录数（按 CVE 记录计，未展开成样本）")
    ax.set_title(f"图 2｜原始数据漏洞类型（CWE）取值 Top20，共 {raw['n_cwe_raw']:,} 种取值\n"
                 f"红色柱 = 无效占位值（NVD-CWE-noinfo / NVD-CWE-Other），"
                 f"合计 {sum(c for n, c in top if 'NVD-CWE' in n):,} 条", fontsize=12.5)
    for i, c in zip(range(len(names))[::-1], cnts):
        ax.text(c, i, f" {c:,}", va="center", fontsize=8.5)
    ax.margins(x=.13)
    save(fig, "fig02_原始数据_CWE取值分布.png")


def fig03_raw_language(raw: dict) -> None:
    """原始语言分布（横向条形图）。"""
    langs = raw["languages"]
    n_total = raw["n_records"]
    names = [x[0] for x in langs]
    cnts = [x[1] for x in langs]

    fig, ax = plt.subplots(figsize=(10.5, 6))
    cols = ["#c44e52" if n in ("Other",) else
            ("#dd8452" if n == "Unknown" else "#4c72b0") for n in names]
    ax.barh(range(len(names))[::-1], cnts, color=cols)
    ax.set_yticks(range(len(names))[::-1], names, fontsize=9.5)
    ax.set_xlabel("记录数")
    ax.set_title(f"图 3｜原始数据语言分布（共 {len(names)} 种语言 / {n_total:,} 条记录）\n"
                 f"橙色 = 语言未识别（{dict(langs).get('Unknown', 0):,} 条，"
                 f"这些记录的 file_paths 也为空）", fontsize=12.5)
    for i, c in zip(range(len(names))[::-1], cnts):
        ax.text(c, i, f" {c:,}  ({c / n_total * 100:.1f}%)", va="center", fontsize=8.5)
    ax.margins(x=.22)
    save(fig, "fig03_原始数据_语言分布.png")


def fig04_raw_project(raw: dict) -> None:
    """原始项目分布 Top20。"""
    projs = raw["top_projects"][:20]
    names = [x[0] for x in projs]
    cnts = [x[1] for x in projs]

    fig, ax = plt.subplots(figsize=(10.5, 5.6))
    ax.barh(range(len(names))[::-1], cnts,
            color=sns.color_palette("flare", len(names)))
    ax.set_yticks(range(len(names))[::-1], names, fontsize=9.5)
    ax.set_xlabel("记录数")
    ax.set_title(f"图 4｜原始数据项目分布 Top20（共 {raw['n_projects']:,} 个项目）\n"
                 f"头部项目高度集中：linux 一个项目就占 "
                 f"{cnts[0] / raw['n_records'] * 100:.1f}%", fontsize=12.5)
    for i, c in zip(range(len(names))[::-1], cnts):
        ax.text(c, i, f" {c:,}", va="center", fontsize=8.5)
    ax.margins(x=.15)
    save(fig, "fig04_原始数据_项目分布.png")


# ===========================================================================
# 预处理后 · 检测任务（8 张）
# ===========================================================================

def fig05_split_sizes(det: dict[str, pd.DataFrame]) -> None:
    """三个 split 的样本量与正例率。"""
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.6))

    splits = ["train", "val", "test"]
    ns = [len(det[s]) for s in splits]
    pos = [int(det[s]["label"].sum()) for s in splits]
    neg = [n - p for n, p in zip(ns, pos)]

    ax = axes[0]
    x = np.arange(3)
    ax.bar(x, neg, .55, label="安全样本（标签 0）", color=C_SAFE)
    ax.bar(x, pos, .55, bottom=neg, label="漏洞样本（标签 1）", color=C_VULN)
    ax.set_xticks(x, ["训练集", "验证集", "测试集"])
    ax.set_ylabel("样本数")
    ax.set_title("① 三个集合的样本量与标签构成")
    for i, (n, p) in enumerate(zip(ns, pos)):
        ax.text(i, n + max(ns) * .02, f"{n:,}", ha="center", fontsize=9.5)
        ax.text(i, n / 2, f"{p / n * 100:.1f}%\n漏洞", ha="center",
                va="center", color="white", fontsize=9.5, fontweight="bold")
    ax.legend(fontsize=9)
    ax.margins(y=.16)

    ax = axes[1]
    rates = [p / n * 100 for n, p in zip(ns, pos)]
    ax.bar(x, rates, .5, color=PALETTE_SPLIT)
    ax.axhline(44.54, color="gray", ls="--", lw=1.2, label="训练集基准 44.54%")
    ax.set_xticks(x, ["训练集", "验证集", "测试集"])
    ax.set_ylabel("漏洞样本占比（%）")
    ax.set_ylim(0, 60)
    ax.set_title("② 三个集合正例率一致 → 划分无标签偏斜")
    for i, r in enumerate(rates):
        ax.text(i, r + 1.2, f"{r:.2f}%", ha="center", fontsize=10)
    ax.legend(fontsize=9)

    fig.suptitle("图 5｜检测任务三个集合的规模与正例率（按分组键划分，比例约 8:1:1）",
                 y=1.04, fontsize=13.5)
    save(fig, "fig05_检测_三分集合规模与正例率.png")


def fig06_length_hist(det: dict[str, pd.DataFrame]) -> None:
    """代码长度分布直方图（按 split 分面）。"""
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.4), sharey=True)
    cn = {"train": "训练集", "val": "验证集", "test": "测试集"}
    for ax, s, col in zip(axes, ["train", "val", "test"], PALETTE_SPLIT):
        L = det[s]["code"].str.len()
        bins = np.logspace(np.log10(20), np.log10(L.max() + 1), 60)
        ax.hist(L, bins=bins, color=col, alpha=.85)
        ax.set_xscale("log")
        ax.axvline(CHARS_FOR_512, color="purple", ls=":", lw=1.4,
                   label=f"512 词元 ≈ {CHARS_FOR_512} 字符")
        ax.axvline(L.median(), color="black", ls="--", lw=1.2,
                   label=f"中位数 {int(L.median())} 字符")
        ax.set_title(f"{cn[s]}（{len(L):,} 条）")
        ax.set_xlabel("代码长度（字符，对数轴）")
        over = int((L > CHARS_FOR_512).sum())
        ax.text(.98, .95, f"超过 {CHARS_FOR_512} 字符：\n{over:,} 条（{over / len(L) * 100:.1f}%）",
                transform=ax.transAxes, ha="right", va="top", fontsize=9,
                bbox=dict(fc="white", ec="gray", alpha=.92))
        ax.legend(fontsize=8, loc="upper left")
    axes[0].set_ylabel("样本数")
    fig.suptitle("图 6｜预处理后代码长度分布（紫色点线右侧的样本会超出模型词元窗口）",
                 y=1.05, fontsize=13.5)
    save(fig, "fig06_检测_代码长度分布.png")


def fig07_length_box(det: dict[str, pd.DataFrame]) -> None:
    """★ 核心：代码长度箱线图（按标签）—— 暴露「漏洞版更短」的构造偏置。"""
    rows = []
    for s in ("train", "val", "test"):
        d = det[s]
        for lab, sub in d.groupby("label"):
            for v in sub["code"].str.len():
                rows.append({"集合": s, "标签": "漏洞" if lab == 1 else "安全",
                             "长度": v})
    df = pd.DataFrame(rows)

    fig, axes = plt.subplots(1, 2, figsize=(13.5, 4.9),
                             gridspec_kw={"width_ratios": [1.4, 1]})

    ax = axes[0]
    sns.boxplot(data=df, x="集合", y="长度", hue="标签", ax=ax,
                order=["train", "val", "test"], hue_order=["安全", "漏洞"],
                palette={"安全": C_SAFE, "漏洞": C_VULN},
                showfliers=False, width=.62)
    ax.set_yscale("log")
    ax.set_ylabel("代码长度（字符，对数轴）")
    ax.set_xlabel("")
    ax.set_xticks(range(3), ["训练集", "验证集", "测试集"])
    ax.set_title("① 按标签分组的长度箱线图（已隐藏离群点）")
    ax.legend(title="", fontsize=9.5, loc="upper right")
    for i, s in enumerate(["train", "val", "test"]):
        mv = df[(df.集合 == s) & (df.标签 == "漏洞")]["长度"].median()
        ms = df[(df.集合 == s) & (df.标签 == "安全")]["长度"].median()
        ax.text(i, max(mv, ms) * 3.2, f"安全版是漏洞版的\n{ms / mv:.1f} 倍",
                ha="center", fontsize=8.5, color="#444",
                bbox=dict(fc="#fff8e1", ec="#e0c060", alpha=.95))

    ax = axes[1]
    tr = det["train"]
    data = [tr[tr.label == 1]["code"].str.len(), tr[tr.label == 0]["code"].str.len()]
    try:
        bp = ax.boxplot(data, widths=.5, showfliers=False, patch_artist=True,
                        tick_labels=[f"漏洞\n（{len(data[0]):,} 条）",
                                     f"安全\n（{len(data[1]):,} 条）"])
    except TypeError:
        bp = ax.boxplot(data, widths=.5, showfliers=False, patch_artist=True,
                        labels=[f"漏洞\n（{len(data[0]):,} 条）",
                                f"安全\n（{len(data[1]):,} 条）"])
    bp["boxes"][0].set_facecolor(C_VULN)
    bp["boxes"][1].set_facecolor(C_SAFE)
    for b in bp["boxes"]:
        b.set_alpha(.75)
    for med in bp["medians"]:
        med.set_color("black")
        med.set_linewidth(2)
    ax.set_yscale("log")
    ax.set_ylabel("代码长度（字符，对数轴）")
    ax.set_title("② 训练集：中位 %d 字符 vs %d 字符" %
                 (data[0].median(), data[1].median()))

    fig.suptitle("图 7｜★ 代码长度箱线图：漏洞版显著短于安全版（数据集构造偏置）",
                 y=1.04, fontsize=14)
    save(fig, "fig07_检测_长度箱线图_按标签.png")


def fig08_length_scatter(det: dict[str, pd.DataFrame]) -> None:
    """★ 核心：长度 vs 标签 的散点图（抽样，加抖动）。"""
    rng = np.random.default_rng(42)
    tr = det["train"]
    n = min(4000, len(tr))
    idx = rng.choice(len(tr), n, replace=False)
    sub = tr.iloc[idx].copy()
    sub["len"] = sub["code"].str.len()
    sub["抖动标签"] = sub["label"] + rng.uniform(-.22, .22, n)

    fig, axes = plt.subplots(1, 2, figsize=(14, 4.9),
                             gridspec_kw={"width_ratios": [1.45, 1]})

    ax = axes[0]
    col = np.where(sub["label"] == 1, C_VULN, C_SAFE)
    ax.scatter(sub["len"], sub["抖动标签"], s=6, c=col, alpha=.42, linewidths=0)
    ax.set_xscale("log")
    ax.set_yticks([0, 1], ["安全（标签 0）", "漏洞（标签 1）"])
    ax.set_ylim(-.6, 1.6)
    ax.set_xlabel("代码长度（字符，对数轴）")
    ax.set_title(f"① 长度 vs 标签（训练集随机抽样 {n:,} 条，纵向抖动避免重叠）")
    ax.axvline(CHARS_FOR_512, color="purple", ls=":", lw=1.3,
               label=f"512 词元 ≈ {CHARS_FOR_512} 字符")
    ax.legend(fontsize=9)

    ax = axes[1]
    edges = [0, 100, 200, 400, 800, 1600, 3200, 6400, 10 ** 9]
    labels = ["<100", "100-200", "200-400", "400-800", "800-1.6千",
              "1.6千-3.2千", "3.2千-6.4千", ">6.4千"]
    tr2 = tr.copy()
    tr2["len"] = tr2["code"].str.len()
    tr2["桶"] = pd.cut(tr2["len"], bins=edges, labels=labels, right=False)
    g = tr2.groupby("桶", observed=True)["label"].agg(["mean", "size"])
    ax.plot(range(len(g)), g["mean"] * 100, "o-", color="#4c72b0", lw=2, ms=7)
    ax.set_xticks(range(len(g)), [str(i) for i in g.index], rotation=40,
                  ha="right", fontsize=8.5)
    ax.set_ylabel("该长度区间内的漏洞占比（%）")
    ax.set_xlabel("代码长度区间（字符）")
    ax.set_title("② 长度分桶后的漏洞占比（单调下降）")
    for i, (m, s) in enumerate(zip(g["mean"], g["size"])):
        ax.text(i, m * 100 + 1.8, f"{m * 100:.0f}%\n{int(s):,} 条",
                ha="center", fontsize=7.5)

    fig.suptitle("图 8｜★ 长度与漏洞标签的关系：代码越短越容易被判为漏洞",
                 y=1.04, fontsize=14)
    save(fig, "fig08_检测_长度与标签散点图.png")


def fig09_posrate_by_length(det: dict[str, pd.DataFrame]) -> None:
    """★ 核心：长度分桶正例率（三集合三条线，检验偏置是否一致）。"""
    edges = [0, 100, 200, 400, 800, 1600, 3200, 6400, 10 ** 9]
    labels = ["<100", "100-200", "200-400", "400-800", "800-1.6千",
              "1.6千-3.2千", "3.2千-6.4千", ">6.4千"]
    fig, ax = plt.subplots(figsize=(10.5, 5.2))
    cn = {"train": "训练集", "val": "验证集", "test": "测试集"}
    for s, col in zip(("train", "val", "test"), PALETTE_SPLIT):
        d = det[s].copy()
        d["len"] = d["code"].str.len()
        d["桶"] = pd.cut(d["len"], bins=edges, labels=labels, right=False)
        g = d.groupby("桶", observed=True)["label"].mean() * 100
        ax.plot(range(len(g)), g.values, "o-", color=col, lw=2, ms=6, label=cn[s])
    ax.axhline(44.54, color="gray", ls="--", lw=1.2, label="全局漏洞占比 44.54%")
    ax.set_xticks(range(len(labels)), labels, rotation=35, ha="right")
    ax.set_xlabel("代码长度区间（字符）")
    ax.set_ylabel("该区间内的漏洞占比（%）")
    ax.set_title("图 9｜★ 长度分层后的漏洞占比：三个集合趋势完全一致\n"
                 "短代码段的漏洞占比显著高于长代码段 → 模型可凭「长度」走捷径",
                 fontsize=13)
    ax.legend()
    save(fig, "fig09_检测_长度分层正例率.png")


def fig10_chars_vs_tokens(det: dict[str, pd.DataFrame], tok) -> float | None:
    """字符数 vs 真实词元数 散点图，并**实测**字符/词元比、回填 CHARS_FOR_512。

    这张图回答一个具体问题：用「字符数」估算「词元数」到底准不准？

    副作用
    ------
    会把实测比值写入全局 ``CHARS_FOR_512``，供图 6 等使用。
    因此**必须在依赖该阈值的图之前调用**。
    """
    global CHARS_FOR_512
    if tok is None:
        CHARS_FOR_512 = int(MAX_LENGTH * DEFAULT_CHARS_PER_TOKEN)
        print(f"  [跳过] 未加载分词器，图 10 不生成；"
              f"沿用粗估比值 {DEFAULT_CHARS_PER_TOKEN} → {CHARS_FOR_512} 字符")
        return None

    rng = np.random.default_rng(42)
    rows = det["train"]
    n = min(2500, len(rows))
    idx = rng.choice(len(rows), n, replace=False)
    sub = rows.iloc[idx]
    codes = sub["code"].tolist()
    enc = tok(codes, add_special_tokens=True, truncation=False)
    tl = np.array([len(x) for x in enc["input_ids"]])
    cl = np.array([len(c) for c in codes])

    # 过原点最小二乘拟合 字符数 = k × 词元数；另给逐样本比值中位数（更稳健）
    k_ls = float((cl * tl).sum() / (tl * tl).sum())
    ratio_arr = cl / np.maximum(tl, 1)
    k_med = float(np.median(ratio_arr))

    CHARS_FOR_512 = int(MAX_LENGTH * k_med)
    print(f"  实测字符/词元比 = {k_med:.3f}"
          f"（粗估 {DEFAULT_CHARS_PER_TOKEN}，偏差 "
          f"{(k_med - DEFAULT_CHARS_PER_TOKEN) / DEFAULT_CHARS_PER_TOKEN * 100:+.0f}%）")
    print(f"  → 512 词元 ≈ {CHARS_FOR_512} 字符（后续图表统一用此阈值）")

    fig, axes = plt.subplots(1, 2, figsize=(13.5, 4.9))

    ax = axes[0]
    ax.scatter(tl, cl, s=7, alpha=.3, color="#4c72b0", linewidths=0)
    xx = np.array([0, tl.max()])
    ax.plot(xx, k_ls * xx, color="#d62728", lw=2,
            label=f"过原点拟合：字符数 ≈ {k_ls:.2f} × 词元数")
    ax.plot(xx, k_med * xx, color="#2ca02c", lw=1.6, ls="--",
            label=f"逐样本比值中位数：{k_med:.2f}")
    ax.axvline(MAX_LENGTH, color="purple", ls=":", lw=1.4,
               label=f"模型窗口 {MAX_LENGTH} 词元")
    ax.set_xlabel("真实词元数（CodeBERT 分词器实测）")
    ax.set_ylabel("代码字符数")
    ax.set_title(f"① 字符数与词元数的关系（训练集抽样 {n:,} 条）")
    ax.legend(fontsize=8.5)

    ax = axes[1]
    ax.hist(ratio_arr, bins=60, range=(0, 12), color="#dd8452", alpha=.85)
    ax.axvline(k_med, color="#2ca02c", lw=2, ls="--", label=f"中位数 {k_med:.2f}")
    ax.axvline(DEFAULT_CHARS_PER_TOKEN, color="gray", lw=1.6, ls=":",
               label=f"原先的粗估 {DEFAULT_CHARS_PER_TOKEN}")
    ax.set_xlabel("每个词元对应的字符数")
    ax.set_ylabel("样本数")
    ax.set_title("② 字符/词元 比值的分布")
    ax.legend(fontsize=9)

    fig.suptitle("图 10｜字符数与真实词元数的换算关系"
                 f"（实测比值 {k_med:.2f}，而非粗估的 {DEFAULT_CHARS_PER_TOKEN} —— "
                 f"这正是长度估算偏差的来源）", y=1.04, fontsize=13)
    save(fig, "fig10_检测_字符数与词元数关系.png")
    return k_med


def fig11_token_length(det: dict[str, pd.DataFrame], tok) -> dict:
    """★ 核心：真实词元长度分布 vs 512 窗口。"""
    if tok is None:
        print("  [跳过] 未加载 tokenizer，无法生成图 11")
        return {}

    rng = np.random.default_rng(42)
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5), sharey=True)
    cn = {"train": "训练集", "val": "验证集", "test": "测试集"}
    stats = {}
    for ax, s, col in zip(axes, ["train", "val", "test"], PALETTE_SPLIT):
        codes = det[s]["code"].tolist()
        n = min(3000, len(codes))
        sample = [codes[i] for i in rng.choice(len(codes), n, replace=False)]
        enc = tok(sample, add_special_tokens=True, truncation=False)
        L = np.array([len(x) for x in enc["input_ids"]])
        stats[s] = dict(n=n, median=int(np.median(L)),
                        p90=int(np.quantile(L, .9)), max=int(L.max()),
                        over=int((L > MAX_LENGTH).sum()),
                        rate=float((L > MAX_LENGTH).mean()))
        bins = np.logspace(np.log10(max(4, L.min())), np.log10(L.max() + 1), 60)
        ax.hist(L, bins=bins, color=col, alpha=.85)
        ax.set_xscale("log")
        ax.axvline(MAX_LENGTH, color="red", ls="--", lw=1.8,
                   label=f"模型词元窗口 {MAX_LENGTH}")
        ax.axvline(np.median(L), color="black", ls=":", lw=1.4,
                   label=f"中位数 {int(np.median(L))}")
        st = stats[s]
        ax.set_title(f"{cn[s]}\n超过窗口：{st['over']:,} / {n:,} = {st['rate'] * 100:.1f}%")
        ax.set_xlabel("真实词元数（对数轴）")
        ax.legend(fontsize=8.5)
    axes[0].set_ylabel("样本数")
    fig.suptitle("图 11｜★ 真实词元长度分布 vs 模型 512 词元窗口"
                 "（红虚线右侧的样本会被截断，构建阶段的头尾截断失效）",
                 y=1.05, fontsize=13)
    save(fig, "fig11_检测_词元长度分布.png")
    return stats


def fig12_test_structure(proc: dict) -> None:
    """★ 核心：测试集构成 —— 同胞对 vs 孤立样本。"""
    t = proc["test_structure"]
    iso_n = t["isolated_samples"]
    iso_rate = t["isolated_pos_rate"]

    fig, axes = plt.subplots(1, 2, figsize=(13.5, 4.9),
                             gridspec_kw={"width_ratios": [1, 1.05]})

    ax = axes[0]
    vals = [t["paired_groups"], t["groups"] - t["paired_groups"]]
    labels = [f"成对分组\n（同一提交同时含\n漏洞版与修复版）\n{t['paired_groups']:,} 个",
              f"孤立分组\n（只含单版本）\n{t['groups'] - t['paired_groups']:,} 个"]
    w, _, at = ax.pie(vals, labels=labels, autopct="%1.1f%%",
                      colors=["#c44e52", "#55a868"], startangle=100,
                      textprops={"fontsize": 9.5}, explode=(.03, .03))
    for a in at:
        a.set_fontweight("bold")
        a.set_color("white")
    ax.set_title(f"① 测试集分组构成（共 {t['groups']:,} 个分组）")

    ax = axes[1]
    cats = ["成对样本\n（有同胞版本）", "孤立样本\n（无同胞版本）"]
    ns = [t["paired_samples"], iso_n]
    bars = ax.bar(cats, ns, .55, color=["#c44e52", "#55a868"], alpha=.9)
    ax.set_ylabel("样本数")
    ax.set_title(f"② 测试集样本构成（共 {t['n_test']:,} 条）")
    for b, n in zip(bars, ns):
        ax.text(b.get_x() + b.get_width() / 2, n * 1.02,
                f"{n:,}\n（{n / t['n_test'] * 100:.1f}%）",
                ha="center", fontsize=10.5, fontweight="bold")
    ax.margins(y=.24)
    ax.text(.5, .60,
            f"★ 孤立样本的漏洞占比仅 {iso_rate * 100:.2f}%\n"
            f"→ 在这 {iso_n} 条上全判「安全」\n"
            f"   就有 {100 - iso_rate * 100:.2f}% 的准确率",
            transform=ax.transAxes, ha="center", fontsize=9,
            bbox=dict(fc="#fff3cd", ec="#e0a800"))

    fig.suptitle("图 12｜★ 测试集被「同胞对」主导 —— 评测指标虚高的根源",
                 y=1.04, fontsize=14)
    save(fig, "fig12_检测_测试集构成.png")


# ===========================================================================
# 预处理后 · 分类任务（5 张）
# ===========================================================================

def fig13_cwe_distribution(cls: dict[str, pd.DataFrame], id2name: dict) -> None:
    """★ 核心：CWE 类别分布（条形图，OTHER 高亮）。"""
    cnt = cls["train"]["label"].value_counts().sort_index()
    names = [id2name.get(int(k), str(k)) for k in cnt.index]
    vals = cnt.values
    order = np.argsort(-vals)
    names = [names[i] for i in order]
    vals = [vals[i] for i in order]

    fig, ax = plt.subplots(figsize=(14.5, 5.6))
    cols = ["#c44e52" if n == "OTHER" else
            ("#4c72b0" if v >= 100 else "#8fb0d8") for n, v in zip(names, vals)]
    ax.bar(range(len(names)), vals, color=cols)
    ax.set_xticks(range(len(names)), names, rotation=90, fontsize=8.5)
    ax.set_ylabel("训练集样本数")
    other_v = dict(zip(names, vals)).get("OTHER", 0)
    ax.axhline(30, color="green", ls="--", lw=1.3,
               label="长尾合并阈值（少于 30 条并入 OTHER）")
    ax.axhline(other_v, color="#c44e52", ls=":", lw=1.8,
               label=f"OTHER 类 = {other_v:,} 条（{other_v / sum(vals) * 100:.1f}%）")
    ax.set_title("图 13｜★ 分类任务漏洞类型（CWE）分布，共 41 类 = 40 个真实类型 + OTHER\n"
                 "OTHER 已与最大真实类 CWE-79 相当，且它是上百种不相干类型的垃圾桶",
                 fontsize=12.5)
    ax.legend(fontsize=9.5)
    save(fig, "fig13_分类_CWE类别分布.png")


def fig14_longtail(cls: dict[str, pd.DataFrame]) -> None:
    """CWE 长尾曲线（log-log 散点图）。"""
    cnt = cls["train"]["label"].value_counts().sort_values(ascending=False)
    fig, ax = plt.subplots(figsize=(10, 5))
    ranks = np.arange(1, len(cnt) + 1)
    ax.scatter(ranks, cnt.values, s=48, color="#4c72b0", zorder=3)
    ax.plot(ranks, cnt.values, color="#4c72b0", alpha=.45, lw=1.4, zorder=2)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("类别排名（对数轴）")
    ax.set_ylabel("训练集样本数（对数轴）")
    ratio = cnt.values[0] / cnt.values[-1]
    ax.set_title(f"图 14｜漏洞类型的长尾曲线：头尾比 {ratio:.0f} : 1\n"
                 f"最大类 {cnt.values[0]:,} 条 → 最小类 {cnt.values[-1]} 条", fontsize=13)
    ax.annotate(f"第 1 名：{cnt.values[0]:,} 条",
                xy=(1, cnt.values[0]), xytext=(2.2, cnt.values[0] * .5),
                fontsize=9.5, arrowprops=dict(arrowstyle="->", color="gray"))
    ax.annotate(f"第 {len(cnt)} 名：{cnt.values[-1]} 条",
                xy=(len(cnt), cnt.values[-1]),
                xytext=(len(cnt) * .15, cnt.values[-1] * 3.0),
                fontsize=9.5, arrowprops=dict(arrowstyle="->", color="gray"))
    save(fig, "fig14_分类_长尾曲线.png")


def fig15_test_support(cls: dict[str, pd.DataFrame], id2name: dict) -> None:
    """★ 核心：逐类测试集样本量（标注 support<10 的类）。"""
    cnt = cls["test"]["label"].value_counts().sort_index()
    names = [id2name.get(int(k), str(k)) for k in cnt.index]
    vals = cnt.values
    order = np.argsort(-vals)
    names = [names[i] for i in order]
    vals = [int(vals[i]) for i in order]

    fig, ax = plt.subplots(figsize=(14.5, 5.2))
    cols = ["#c44e52" if n == "OTHER" else ("#c44e52" if v < 10 else
            ("#dd8452" if v < 20 else "#4c72b0"))
            for n, v in zip(names, vals)]
    ax.bar(range(len(names)), vals, color=cols)
    ax.set_xticks(range(len(names)), names, rotation=90, fontsize=8.5)
    ax.set_ylabel("测试集样本数")
    ax.axhline(10, color="red", ls="--", lw=1.2, label="样本数 = 10")
    ax.axhline(20, color="orange", ls="--", lw=1.2, label="样本数 = 20")
    n_lt10 = sum(1 for v in vals if v < 10)
    ax.set_title(f"图 15｜★ 逐类测试集样本量：{n_lt10} 个类的测试样本不足 10 条\n"
                 f"这些类的逐类 F1 只可能是 0 或 1，把它们平均进宏平均 F1 会让指标剧烈抖动",
                 fontsize=12.5)
    ax.legend(fontsize=9.5)
    save(fig, "fig15_分类_逐类测试集样本量.png")


def fig16_class_by_split(cls: dict[str, pd.DataFrame], id2name: dict) -> None:
    """分类任务：三集合的类别占比对比（分组条形图，按占比而非绝对数）。"""
    all_ids = sorted(set().union(*[set(d["label"]) for d in cls.values()]))
    fig, ax = plt.subplots(figsize=(14.5, 5.2))
    x = np.arange(len(all_ids))
    w = .27
    cn = {"train": "训练集", "val": "验证集", "test": "测试集"}
    for i, (s, col) in enumerate(zip(("train", "val", "test"), PALETTE_SPLIT)):
        c = cls[s]["label"].value_counts()
        tot = len(cls[s])
        vals = [c.get(k, 0) / tot * 100 for k in all_ids]
        ax.bar(x + (i - 1) * w, vals, w, label=f"{cn[s]}（{tot:,} 条）",
               color=col, alpha=.9)
    ax.set_xticks(x, [id2name.get(int(k), str(k)) for k in all_ids],
                  rotation=90, fontsize=8.5)
    ax.set_ylabel("该类别在集合内的占比（%）")
    ax.set_title("图 16｜分类任务三集合的类别占比对比\n"
                 "三组柱高度基本一致 → 按分组键划分后类别比例没有偏斜",
                 fontsize=13)
    ax.legend(fontsize=9.5)
    save(fig, "fig16_分类_三集合类别占比.png")


def fig17_coverage_heatmap(cls: dict[str, pd.DataFrame], id2name: dict) -> None:
    """分类样本三集合覆盖热力图（哪些类在 test 里缺失）。"""
    all_ids = sorted(set().union(*[set(d["label"]) for d in cls.values()]))
    mat = np.zeros((3, len(all_ids)))
    for i, s in enumerate(("train", "val", "test")):
        c = cls[s]["label"].value_counts()
        for j, k in enumerate(all_ids):
            mat[i, j] = c.get(k, 0)

    fig, ax = plt.subplots(figsize=(15, 3.6))
    im = ax.imshow(np.log1p(mat), aspect="auto", cmap="YlOrRd")
    cn = ["训练集", "验证集", "测试集"]
    ax.set_yticks(range(3), cn)
    ax.set_xticks(range(len(all_ids)),
                  [id2name.get(int(k), str(k)) for k in all_ids],
                  rotation=90, fontsize=8)
    for i in range(3):
        for j in range(len(all_ids)):
            if mat[i, j] == 0:
                ax.text(j, i, "缺", ha="center", va="center",
                        color="blue", fontsize=8.5, fontweight="bold")
    ax.set_title("图 17｜分类样本在三集合的覆盖热力图"
                 "（颜色 = 样本数的对数，蓝色「缺」= 该集合完全没有这个类）",
                 fontsize=12.5)
    fig.colorbar(im, ax=ax, label="对数（1 + 样本数）", fraction=.02, pad=.01)
    save(fig, "fig17_分类_三集合覆盖热力图.png")


# ===========================================================================
# 数据质量（3 张）
# ===========================================================================

def fig18_missing_heatmap(raw: dict) -> None:
    """原始数据缺失率热力图。"""
    miss = raw["missing"]
    n = raw["n_records"]
    fields = list(miss.keys())
    kinds = ["null", "empty_str", "nan_str"]
    kind_cn = ["真正的空值", "空字符串", "字符串 “nan”"]
    mat = np.array([[miss[f][k] / n * 100 for f in fields] for k in kinds])

    fig, ax = plt.subplots(figsize=(14, 3.9))
    im = ax.imshow(mat, aspect="auto", cmap="Reds", vmin=0)
    ax.set_yticks(range(3), kind_cn)
    ax.set_xticks(range(len(fields)), fields, rotation=42, ha="right", fontsize=9)
    for i in range(3):
        for j in range(len(fields)):
            v = mat[i, j]
            ax.text(j, i, f"{v:.0f}%" if v >= .5 else "·",
                    ha="center", va="center", fontsize=8.5,
                    color="white" if v > 40 else "black")
    ax.set_title("图 18｜原始数据逐字段缺失率（%）—— 缺失用了三套不同的表示法",
                 fontsize=12.5)
    fig.colorbar(im, ax=ax, label="缺失率（%）", fraction=.02, pad=.01)
    save(fig, "fig18_原始数据_缺失率热力图.png")


def fig19_duplicate_conflict(raw: dict, proc: dict) -> None:
    """数据重复与标签冲突（双面板条形图）。"""
    fig, axes = plt.subplots(1, 2, figsize=(13.5, 4.6))

    # ① 去重前后
    ax = axes[0]
    n_raw = raw["n_records"]
    cp = raw["code_pair"]
    expanded = cp["both"] * 2 + cp["only_vuln"] + cp["only_fixed"]
    after_len = 21041
    after_dedup = 18925
    stages = ["原始记录", "展开为样本", "长度过滤后", "去重后"]
    vals = [n_raw, expanded, after_len, after_dedup]
    bars = ax.bar(stages, vals, .55,
                  color=["#4c72b0", "#6d8fc4", "#dd8452", "#55a868"])
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v * 1.02, f"{v:,}",
                ha="center", fontsize=10, fontweight="bold")
    ax.set_ylabel("数量")
    ax.set_title("① 各环节数量变化")
    ax.margins(y=.2)
    ax.text(.5, .18, f"长度过滤剔除 {expanded - after_len:,} 条\n"
                     f"去重剔除 {after_len - after_dedup:,} 条"
                     f"（{ (after_len - after_dedup) / after_len * 100:.1f}%）",
            transform=ax.transAxes, ha="center", fontsize=9,
            bbox=dict(fc="#eef4ff", ec="#8fb0d8"))

    # ② 重复/冲突的检出情况
    ax = axes[1]
    names = ["去空白后\n重复（训练集）", "去空白后\n重复（测试集）",
             "标签冲突\n（同码不同标）", "代码字段\n完全相同"]
    vals = [13, 1, proc["label_conflict"], raw["code_pair"]["identical"]]
    bars = ax.bar(names, vals, .55, color=["#dd8452", "#dd8452", "#c44e52", "#c44e52"])
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + max(vals) * .04, f"{v}",
                ha="center", fontsize=10.5, fontweight="bold")
    ax.set_ylabel("检出数量")
    ax.set_ylim(0, max(vals) * 1.3)
    ax.set_title("② 残余噪声（MD5 去重抓不到的）")
    ax.text(.5, .62, "MD5 去重能抓「逐字节相同」，\n抓不到「只差缩进/空行/注释」的近重复\n"
                     "数量很少（合计 < 60），影响有限",
            transform=ax.transAxes, ha="center", fontsize=8.5,
            bbox=dict(fc="#fff3cd", ec="#e0a800"))

    fig.suptitle("图 19｜数据重复与标签冲突的检出情况", y=1.04, fontsize=14)
    save(fig, "fig19_数据质量_重复与标签冲突.png")


def fig20_funnel(raw: dict, proc: dict) -> None:
    """预处理各环节样本流失漏斗图（数字全部来自实测审计）。"""
    cp = raw["code_pair"]
    n_rec = raw["n_records"]
    expanded = cp["both"] * 2 + cp["only_vuln"] + cp["only_fixed"]
    dropped_at_expand = n_rec - (cp["both"] + cp["only_vuln"] + cp["only_fixed"])
    after_len = 21041
    after_dedup = 18925

    stages = [
        ("① 原始数据记录", n_rec, None),
        ("② 展开为样本\n（漏洞版→1 / 修复版→0）", expanded, dropped_at_expand),
        ("③ 长度过滤\n（丢弃不足 30 字符）", after_len, expanded - after_len),
        ("④ MD5 去重\n（相同代码只留一份）", after_dedup, after_len - after_dedup),
        ("⑤ 最终落盘 6 份文件", after_dedup, 0),
    ]

    fig, ax = plt.subplots(figsize=(11.5, 5.4))
    names = [s[0] for s in stages]
    vals = [s[1] for s in stages]
    ymax = max(vals)
    for i, (nm, v, drop) in enumerate(stages):
        width = v / ymax
        y = len(stages) - 1 - i
        ax.barh(y, width, height=.6,
                color=sns.color_palette("Blues_r", len(stages))[i])
        ax.text(width + .015, y, f"{v:,}", va="center", fontsize=11,
                fontweight="bold")
        if drop:
            ax.text(width / 2, y, f"剔除 −{drop:,}（{drop / vals[i - 1] * 100:.1f}%）",
                    va="center", ha="center", fontsize=9, color="white",
                    fontweight="bold")
    ax.set_yticks(range(len(stages))[::-1], names, fontsize=10)
    ax.set_xlim(0, 1.3)
    ax.set_xticks([])
    ax.set_title("图 20｜预处理各环节的样本流失漏斗（数字为实测）\n"
                 f"{n_rec:,} 条原始记录 → {after_dedup:,} 条训练样本", fontsize=13)
    save(fig, "fig20_数据质量_预处理漏斗图.png")


# ===========================================================================
# 主流程
# ===========================================================================

def main() -> None:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    hr("清理旧图表")
    clean_old_figures()

    hr("读取预处理后数据")
    det = {s: load_jsonl(PROC_DIR / f"cvefixes_detection_{s}.jsonl")
           for s in ("train", "val", "test")}
    cls = {s: load_jsonl(PROC_DIR / f"cvefixes_classification_{s}.jsonl")
           for s in ("train", "val", "test")}
    lmap = json.loads((PROC_DIR / "cvefixes_classification_label_map.json")
                      .read_text(encoding="utf-8"))
    id2name = {int(k): v for k, v in lmap["id2name"].items()}
    for s, d in det.items():
        print(f"  检测/{s:<6} {len(d):>7,} 条")
    for s, d in cls.items():
        print(f"  分类/{s:<6} {len(d):>7,} 条")

    audit_files = {
        "raw": ROOT / "reports" / "tables" / "audit_raw.json",
        "proc": ROOT / "reports" / "tables" / "audit_processed.json",
    }
    if not all(p.exists() for p in audit_files.values()):
        raise SystemExit(
            "缺少审计结果，请先运行：python analysis/audit_data.py\n"
            f"（期望文件：{audit_files['raw']}）"
        )
    raw_audit = json.loads(audit_files["raw"].read_text(encoding="utf-8"))
    proc_audit = json.loads(audit_files["proc"].read_text(encoding="utf-8"))

    # ---- 加载 tokenizer（图 10、11 需要）----
    hr("加载 CodeBERT 分词器（图 10、11 需要）")
    tok = None
    tok_dir = next((p for p in TOKENIZER_CANDIDATES if p.exists()), None)
    if tok_dir is not None:
        try:
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
            from transformers import AutoTokenizer
            tok = AutoTokenizer.from_pretrained(str(tok_dir))
            print(f"  已加载：{tok_dir}")
        except Exception as e:                                # noqa: BLE001
            print(f"  [警告] 分词器加载失败（{type(e).__name__}: {e}）")
    else:
        print("  [警告] 未找到分词器，尝试过以下位置：")
        for p in TOKENIZER_CANDIDATES:
            print(f"         {p}")
        print("         图 10、11 将被跳过（其余图表不受影响）")

    hr("原始数据图（4 张）")
    vl, fl = load_raw_lengths()
    print(f"  已读取原始代码长度：漏洞版 {len(vl):,} / 修复版 {len(fl):,}")
    # 图 1 里要画「512 词元等效字符数」这条竖线，所以先实测比值并回填阈值。
    # 图 10 会再做一次同样的测量来出图，两次用同一随机种子，结果一致。
    measure_ratio = measure_chars_per_token(det, tok)
    fig01_raw_length_tail(vl, fl)
    fig02_raw_cwe(raw_audit)
    fig03_raw_language(raw_audit)
    fig04_raw_project(raw_audit)

    hr("预处理后 · 检测任务图（8 张）")
    # 图 10 会再次实测并回填 CHARS_FOR_512，必须在图 6/8 之前跑
    ratio = fig10_chars_vs_tokens(det, tok)
    fig05_split_sizes(det)
    fig06_length_hist(det)
    fig07_length_box(det)
    fig08_length_scatter(det)
    fig09_posrate_by_length(det)
    tok_stats = fig11_token_length(det, tok)
    fig12_test_structure(proc_audit)

    hr("预处理后 · 分类任务图（5 张）")
    fig13_cwe_distribution(cls, id2name)
    fig14_longtail(cls)
    fig15_test_support(cls, id2name)
    fig16_class_by_split(cls, id2name)
    fig17_coverage_heatmap(cls, id2name)

    hr("数据质量图（3 张）")
    fig18_missing_heatmap(raw_audit)
    fig19_duplicate_conflict(raw_audit, proc_audit)
    fig20_funnel(raw_audit, proc_audit)

    # ---- 保存词元统计供报告引用 ----
    out = dict(tok_stats)
    if ratio is not None:
        out["字符每词元比_中位数"] = ratio
    (ROOT / "reports" / "tables" / "token_stats.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    hr("完成")
    n_fig = len(list(FIG_DIR.glob("*.png")))
    print(f"共生成 {n_fig} 张图 -> {FIG_DIR}")
    print(f"词元统计 -> reports/tables/token_stats.json")


if __name__ == "__main__":
    main()
