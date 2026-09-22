"""按汇报稿编号重出 7 张图。

只做两件事：
    1. 改标题里的「图 N」序号
    2. 用新文件名另存

**不改任何绘图逻辑、样式、数据。** 所有绘图函数都从 plot_eda 复用；
唯一的技巧是把 plot_eda.save() 临时换成"捕获 figure 而不落盘"，
这样就能在保存前把标题序号改掉。

编号映射（汇报稿口径）
    原图 3  → 图 1   原始数据语言分布
    原图 20 → 图 2   预处理样本流失漏斗图
    原图 1  → 图 3   原始数据长度分布长尾
    原图 11 → 图 4   词元长度分布
    原图 5  → 图 5   三分集合规模与正例率
    原图 7  → 图 6   长度箱线图（按标签）
    原图 8  → 图 7   长度与标签散点图

用法
----
    python analysis/make_report_figures.py
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt          # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import plot_eda as P                     # noqa: E402

OUT = P.ROOT / "reports" / "figures_selected"

# 绘图函数名, 原编号, 新编号, 中文标签
PLAN = [
    ("fig03_raw_language",    3, 1, "原始数据语言分布"),
    ("fig20_funnel",         20, 2, "预处理样本流失漏斗图"),
    ("fig01_raw_length_tail", 1, 3, "原始数据长度分布长尾"),
    ("fig11_token_length",   11, 4, "词元长度分布"),
    ("fig05_split_sizes",     5, 5, "三分集合规模与正例率"),
    ("fig07_length_box",      7, 6, "长度箱线图_按标签"),
    ("fig08_length_scatter",  8, 7, "长度与标签散点图"),
]


def renumber(fig, old_no: int, new_no: int) -> str:
    """把标题里的「图 old｜」改成「图 new｜」，返回改动后的标题文本。

    注意：本项目的图有两种标题写法——
      · 多子图的图用 fig.suptitle()（图 1、5、6、7、8、11、20 等）
      · 单子图的图用 ax.set_title()（图 2、3、4 等，没有 suptitle）
    两种都要处理，否则单子图那张的序号改不掉。
    """
    pattern = re.compile(rf"图 {old_no}｜")

    def fix(text: str) -> str:
        out = pattern.sub(f"图 {new_no}｜", text)
        if out == text and f"图 {old_no}" in text:          # 兜底
            out = text.replace(f"图 {old_no}", f"图 {new_no}", 1)
        return out

    suptitle = fig.get_suptitle() or ""
    if suptitle:
        fig._suptitle.set_text(fix(suptitle))
        return fig.get_suptitle()

    # 没有 suptitle：改各 axes 的标题
    changed = []
    for ax in fig.axes:
        t = ax.get_title()
        if t:
            ax.set_title(fix(t), fontsize=ax.title.get_fontsize())
            changed.append(ax.get_title())
    return " ／ ".join(changed)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for p in OUT.glob("*.png"):
        p.unlink()

    # ---- 把 P.save 换成"捕获 figure"----
    captured: list = []
    original_save = P.save

    def capture(fig, name):                # noqa: ARG001  (name 用不上)
        captured.append(fig)               # 只留引用，不落盘、不关闭

    P.save = capture

    try:
        print("读取数据 ...")
        det = {s: P.load_jsonl(P.PROC_DIR / f"cvefixes_detection_{s}.jsonl")
               for s in ("train", "val", "test")}
        raw = json.loads((P.ROOT / "reports" / "tables" / "audit_raw.json")
                         .read_text(encoding="utf-8"))
        proc = json.loads((P.ROOT / "reports" / "tables" / "audit_processed.json")
                          .read_text(encoding="utf-8"))

        tok = None
        tok_dir = next((p for p in P.TOKENIZER_CANDIDATES if p.exists()), None)
        if tok_dir is not None:
            try:
                os.environ.setdefault("HF_HUB_OFFLINE", "1")
                os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
                from transformers import AutoTokenizer
                tok = AutoTokenizer.from_pretrained(str(tok_dir))
                print(f"分词器: {tok_dir}")
            except Exception as e:                            # noqa: BLE001
                print(f"[警告] 分词器加载失败: {e}")

        # 图 3、图 4 里有一条「512 词元 ≈ N 字符」的竖线，先实测比值回填
        scratch = P.fig10_chars_vs_tokens(det, tok)
        for f in captured:
            plt.close(f)
        captured.clear()
        print(f"字符/词元 = {scratch:.3f}  →  512 词元 ≈ {P.CHARS_FOR_512} 字符\n")

        print("开始出图：")
        for fname, old_no, new_no, label in PLAN:
            fn = getattr(P, fname)

            # 按各函数原签名传参（不碰逻辑，只负责调用）
            if fname == "fig03_raw_language":
                fn(raw)
            elif fname == "fig20_funnel":
                fn(raw, proc)
            elif fname == "fig01_raw_length_tail":
                vl, fl = P.load_raw_lengths()
                fn(vl, fl)
            elif fname == "fig11_token_length":
                fn(det, tok)
            else:                                   # 其余三个都只收 det
                fn(det)

            if not captured:
                print(f"  [跳过] {label}：未捕获到图")
                continue

            fig = captured.pop()
            title = renumber(fig, old_no, new_no)
            out = OUT / f"图{new_no}_{label}.png"
            fig.savefig(out, bbox_inches="tight", facecolor="white")
            plt.close(fig)
            print(f"  [OK] {out.name}")
            print(f"       标题：{title}")
    finally:
        P.save = original_save

    figs = sorted(OUT.glob("图*.png"))
    print(f"\n完成，共 {len(figs)} 张 -> {OUT}")
    for p in figs:
        print(f"  {p.name}")


if __name__ == "__main__":
    main()
