"""预处理单元测试：验证清洗 / 截断 / CWE 规范化 / 标签映射是否与文档一致。

运行方式（不需要 GPU，秒级完成）：
    cd /d <项目根>\\ScanMan
    set PYTHONPATH=%CD%
    python docs\\test_cases\\test_preprocess.py

全部用例通过时最后输出 "全部通过"。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.build_dataset import (  # noqa: E402
    _clean_code,
    _md5,
    _norm_cwe,
    split_groups,
)
from src.utils import truncate_code  # noqa: E402

PASS, FAIL = 0, 0


def check(name: str, got, want) -> None:
    """比对单个断言，打印结果。"""
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}\n         期望: {want!r}\n         实际: {got!r}")


# ---------------------------------------------------------------- 1. 代码清洗
print("\n[1] _clean_code —— 统一换行符 + 去首尾空白")
check("Windows 换行 \\r\\n → \\n", _clean_code("a\r\nb"), "a\nb")
check("老 Mac 换行 \\r → \\n", _clean_code("a\rb"), "a\nb")
check("去掉首尾空白", _clean_code("  \n code \n  "), "code")
check("非字符串返回空串", _clean_code(None), "")
check("数字也返回空串", _clean_code(123), "")
check("中间的空行保留", _clean_code("a\n\n\nb"), "a\n\n\nb")
check("注释不删", _clean_code("// 注释\nx=1"), "// 注释\nx=1")
check("缩进不压缩", _clean_code("def f():\n    pass"), "def f():\n    pass")

# ---------------------------------------------------------------- 2. CWE 规范化
print("\n[2] _norm_cwe —— 各种写法统一成 CWE-<数字>")
check("标准写法", _norm_cwe("CWE-79"), "CWE-79")
check("纯数字", _norm_cwe("79"), "CWE-79")
check("下划线小写", _norm_cwe("cwe_79"), "CWE-79")
check("去前导零", _norm_cwe("CWE-079"), "CWE-79")
check("None → 空", _norm_cwe(None), "")
check("nan → 空", _norm_cwe("nan"), "")
check("NVD-CWE-noinfo → 空", _norm_cwe("NVD-CWE-noinfo"), "")
check("NVD-CWE-other → 空", _norm_cwe("NVD-CWE-Other"), "")
check("纯文字 → 空", _norm_cwe("CWE-noinfo"), "")
check("空格包裹", _norm_cwe("  cwe-89  "), "CWE-89")

# ---------------------------------------------------------------- 3. 头尾截断
print("\n[3] truncate_code —— 头 60% + 尾 40%")
check("未超长时原样返回", truncate_code("abc", max_chars=10), "abc")
check("恰好等于上限时原样返回", truncate_code("a" * 10, max_chars=10), "a" * 10)
check(
    "超长时保留头 6 + 尾 4",
    truncate_code("a" * 100, max_chars=10, head_ratio=0.6),
    "aaaaaa\n/* ... [中间代码已截断] ... */\naaaa",
)
truncated = truncate_code("a" * 100, max_chars=10, head_ratio=0.6)
check("截断后长度 = 上限 + 占位注释", len(truncated), 10 + len("\n/* ... [中间代码已截断] ... */\n"))
check("空字符串安全", truncate_code("", max_chars=10), "")
check("占位注释说明从哪里断的", "[中间代码已截断]" in truncated, True)

# ---------------------------------------------------------------- 4. 去重指纹
print("\n[4] _md5 —— 跨平台一致，可跨进程去重")
check("换行符统一后指纹相同", _md5(_clean_code("a\r\nb")), _md5("a\nb"))
check("不同内容指纹不同", _md5("a") == _md5("b"), False)
check("指纹是 32 位十六进制", len(_md5("x")), 32)

# ---------------------------------------------------------------- 5. 防泄漏分组划分
print("\n[5] split_groups —— 同一 group_id 必须落在同一个 split")


def make_records() -> list[dict]:
    """造 100 个组，每组 2 条（模拟 CVEfixes 的 vuln/fixed 一对）。"""
    recs = []
    for i in range(100):
        gid = f"cvefixes::CVE-2024-{i:04d}::hash{i}"
        recs.append({"group_id": gid, "code": f"vuln {i}", "label": 1})
        recs.append({"group_id": gid, "code": f"fixed {i}", "label": 0})
    return recs


splits = split_groups(make_records(), (0.8, 0.1, 0.1), seed=42)
check("划分比例约 8:1:1（按组）", [len(splits[s]) for s in ("train", "val", "test")], [160, 20, 20])

train_gids = {r["group_id"] for r in splits["train"]}
val_gids = {r["group_id"] for r in splits["val"]}
test_gids = {r["group_id"] for r in splits["test"]}
check("训练/验证集无重叠组", len(train_gids & val_gids), 0)
check("训练/测试集无重叠组", len(train_gids & test_gids), 0)
check("验证/测试集无重叠组", len(val_gids & test_gids), 0)
check("所有组都被用到", len(train_gids) + len(val_gids) + len(test_gids), 100)
# 每个组都是成对的（vuln + fixed），所以完整划分后每组必须有 2 条
group_sizes = {}
for split in ("train", "val", "test"):
    for r in splits[split]:
        group_sizes[r["group_id"]] = group_sizes.get(r["group_id"], 0) + 1
check("每对 vuln/fixed 都没有被拆开", set(group_sizes.values()), {2})

same_seed = split_groups(make_records(), (0.8, 0.1, 0.1), seed=42)
check("同种子结果可复现", same_seed["test"] == splits["test"], True)

# ---------------------------------------------------------------- 6. 标签映射文件
print("\n[6] 标签映射文件自检")
lm_path = ROOT / "data" / "processed" / "cvefixes_classification_label_map.json"
if lm_path.exists():
    lm = json.loads(lm_path.read_text(encoding="utf-8"))
    check("分类类别数 = 41", lm["num_labels"], 41)
    check("编号 0 是 CWE-79", lm["id2name"]["0"], "CWE-79")
    check("编号 40 是 OTHER", lm["id2name"]["40"], "OTHER")
    check("id2name 与 name2id 互为逆映射", lm["name2id"][lm["id2name"]["6"]], 6)
    check("id2name 覆盖全部 41 类", len(lm["id2name"]), 41)
else:
    print(f"  [SKIP] 找不到 {lm_path}，请先运行 scripts/build_dataset.py")

dm_path = ROOT / "data" / "processed" / "cvefixes_detection_label_map.json"
if dm_path.exists():
    dm = json.loads(dm_path.read_text(encoding="utf-8"))
    check("检测类别数 = 2", dm["num_labels"], 2)
    check("0 = safe", dm["id2name"]["0"], "safe")
    check("1 = vulnerable", dm["id2name"]["1"], "vulnerable")

# ---------------------------------------------------------------- 7. 数据文件自检
print("\n[7] 处理后数据文件自检")
proc = ROOT / "data" / "processed"
for task, expect in (("detection", 18925), ("classification", 7291)):
    total = 0
    for split in ("train", "val", "test"):
        p = proc / f"cvefixes_{task}_{split}.jsonl"
        if not p.exists():
            print(f"  [SKIP] 缺少 {p.name}")
            continue
        n = sum(1 for line in p.open(encoding="utf-8") if line.strip())
        total += n
    if total:
        check(f"cvefixes {task} 合计 {expect} 条", total, expect)

# ---------------------------------------------------------------- 汇总
print("\n" + "=" * 60)
print(f"通过 {PASS} 项，失败 {FAIL} 项")
print("=" * 60)
if FAIL:
    sys.exit(1)
print("全部通过")
