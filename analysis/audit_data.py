"""数据集质量审计 —— 原始数据（raw）与预处理后数据（processed）

这个脚本做什么
--------------
分两段审计，覆盖作业要求的「数据处理环节：缺失 / 异常 / 重复」：

    第一段：data/raw/cvefixes/*.parquet   （原始数据）
        - 逐字段缺失统计（真正的 null + 空串 + "nan" 字符串占位）
        - 异常值检测（超长代码、长度分布离群、字段取值异常）
        - 重复检测（精确重复 / 重复 cve_id / 重复 commit hash）
        - 标签与 CWE 字段的一致性检查
        - 语言、项目分布

    第二段：data/processed/*.jsonl        （预处理后数据）
        - 6 份 train/val/test 的规模与标签分布
        - 数据泄漏三层检查（group_id / MD5 / 去空白）
        - 标签冲突（同一段代码同时带 0 和 1）
        - 关键问题的量化证据：
            * 测试集里"成对样本"（同胞对）占比
            * 超过 tokenizer 512 窗口的样本占比（头尾截断失效的影响面）
            * 分类任务长尾 / OTHER 类膨胀
        - 语言、项目分布

产出
----
    reports/tables/audit_raw.json        原始数据审计原始数字
    reports/tables/audit_processed.json  处理后数据审计原始数字
    console                              人类可读的审计报告

用法
----
    cd F:\\NLP_SZ\\ScanMan
    python analysis/audit_data.py

注意
----
只读。不修改 data/ 下的任何文件。
"""

from __future__ import annotations

import collections
import hashlib
import json
import statistics
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 路径与常量
# ---------------------------------------------------------------------------
# 本文件位于 <root>/analysis/ 下，往上找一级就是项目根
ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "data" / "raw" / "cvefixes"
PROC_DIR = ROOT / "data" / "processed"
OUT_DIR = ROOT / "reports" / "tables"

SEED = 42

# 与 configs/config.yaml 保持一致，审计口径才对得上
MIN_CODE_CHARS = 30      # data.min_code_chars
TRUNC_CHARS = 20000      # data.max_code_chars（构建阶段的字符级头尾截断）
MAX_LENGTH = 512         # model.max_length（tokenizer 窗口）

# 超过这个字符数的代码，几乎必然超过 512 token
# 依据：实测 CVEfixes 约 3.8 字符/token（见报告 §3.3 的推算）
CHARS_FOR_512_TOKENS = 1900


def hr(title: str = "", ch: str = "=") -> None:
    """打印一条分隔线，让控制台输出可读。"""
    if title:
        print(f"\n{ch * 78}\n{title}\n{ch * 78}")
    else:
        print(ch * 78)


def pct(a: float, b: float) -> str:
    """安全计算百分比字符串。"""
    return f"{a / b * 100:.2f}%" if b else "n/a"


def md5(text: str) -> str:
    """代码内容的 MD5，与 build_dataset.py 里的 _md5 完全一致。"""
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def norm_ws(text: str) -> str:
    """去掉所有空白字符后的指纹，用于抓"只差缩进/空行"的近重复。"""
    return "".join(text.split())


# ---------------------------------------------------------------------------
# 第一段：原始数据审计
# ---------------------------------------------------------------------------

# 需要逐字段检查缺失的列
RAW_COLS = [
    "cve_id", "hash", "repo_url", "cwe_id", "cwe_name", "language",
    "vulnerable_code", "fixed_code", "commit_message", "cve_description",
    "severity", "cvss3_base_score", "commit_date", "file_paths",
]


def audit_raw() -> dict:
    """流式审计原始 parquet，返回统计字典。

    为什么要流式读
    --------------
    CVEfixes 单个 parquet 有 400~550 MB，全表解压后内存占用很大；
    而且 vulnerable_code 单值可能有几十 MB。用 iter_batches 一次只解压
    一批，内存占用恒定。
    """
    import pyarrow.parquet as pq

    hr("第一段：原始数据审计  data/raw/cvefixes/*.parquet")

    files = sorted(RAW_DIR.glob("*.parquet"))
    if not files:
        raise SystemExit(f"未找到 parquet：{RAW_DIR}")
    print(f"分片数：{len(files)}")
    for f in files:
        print(f"  {f.name:34s} {f.stat().st_size / 1048576:8.1f} MB")

    # ---- 累加器 ----
    n_total = 0
    # 每个字段的缺失计数：null / 空串 / 字符串 "nan" 占位
    miss = {c: {"null": 0, "empty_str": 0, "nan_str": 0} for c in RAW_COLS}
    cve_ids: list[str] = []
    hashes: list[str] = []
    langs = collections.Counter()
    projects = collections.Counter()
    cwe_raw = collections.Counter()
    # 代码长度：只保留分位数需要的统计量，同时记录超长样本
    vuln_len: list[int] = []
    fixed_len: list[int] = []
    over_20k_vuln = 0
    over_20k_fixed = 0
    over_512tok_vuln = 0
    over_512tok_fixed = 0
    empty_pair = 0          # 两个代码字段都空
    only_vuln = 0           # 只有 vulnerable_code
    only_fixed = 0          # 只有 fixed_code
    both = 0                # 两个都有
    identical_pair = 0      # vuln == fixed（完全一样）
    # 可疑的 severity / score 取值
    sev_vals = collections.Counter()
    invalid_score = 0

    for fp in files:
        pf = pq.ParquetFile(fp)
        cols = [c for c in RAW_COLS if c in pf.schema_arrow.names]
        for batch in pf.iter_batches(batch_size=64, columns=cols):
            for row in batch.to_pylist():
                n_total += 1
                # --- 缺失统计 ---
                for c in cols:
                    v = row.get(c)
                    if v is None:
                        miss[c]["null"] += 1
                    elif isinstance(v, str):
                        if v.strip() == "":
                            miss[c]["empty_str"] += 1
                        elif v.strip().lower() == "nan":
                            miss[c]["nan_str"] += 1
                    elif isinstance(v, list) and len(v) == 0:
                        miss[c]["empty_str"] += 1

                # --- 标识与分组字段 ---
                cid = row.get("cve_id")
                if cid:
                    cve_ids.append(str(cid))
                h = row.get("hash")
                if h:
                    hashes.append(str(h))

                # --- 分类维度 ---
                langs[(row.get("language") or "(空)").strip() or "(空)"] += 1
                url = row.get("repo_url") or ""
                projects[url.rsplit("/", 1)[-1] if url else "(空)"] += 1
                cwe_raw[(row.get("cwe_id") or "(空)").strip() or "(空)"] += 1

                # --- 代码字段质量 ---
                v = row.get("vulnerable_code")
                f = row.get("fixed_code")
                v_ok = isinstance(v, str) and v.strip() != ""
                f_ok = isinstance(f, str) and f.strip() != ""
                if v_ok and f_ok:
                    both += 1
                    lv, lf = len(v), len(f)
                    vuln_len.append(lv)
                    fixed_len.append(lf)
                    if lv > TRUNC_CHARS:
                        over_20k_vuln += 1
                    if lf > TRUNC_CHARS:
                        over_20k_fixed += 1
                    if lv > CHARS_FOR_512_TOKENS:
                        over_512tok_vuln += 1
                    if lf > CHARS_FOR_512_TOKENS:
                        over_512tok_fixed += 1
                    if v == f:
                        identical_pair += 1
                elif v_ok:
                    only_vuln += 1
                elif f_ok:
                    only_fixed += 1
                else:
                    empty_pair += 1

                # --- 严重级 / CVSS 分数异常 ---
                sev_vals[str(row.get("severity")).strip()] += 1
                sc = row.get("cvss3_base_score")
                if sc is not None and not (0.0 <= float(sc) <= 10.0):
                    invalid_score += 1

    # ---- 汇总 ----
    def q(arr: list[int], p: float) -> float:
        a = sorted(arr)
        return a[min(len(a) - 1, int(p * (len(a) - 1)))] if a else 0

    dup_cve = len(cve_ids) - len(set(cve_ids))
    dup_hash = len(hashes) - len(set(hashes))

    result = {
        "n_records": n_total,
        "n_files": len(files),
        "missing": miss,
        "n_unique_cve": len(set(cve_ids)),
        "n_unique_hash": len(set(hashes)),
        "dup_cve_id": dup_cve,
        "dup_hash": dup_hash,
        "top_cve_multi": collections.Counter(cve_ids).most_common(5),
        "languages": langs.most_common(),
        "n_projects": len(projects),
        "top_projects": projects.most_common(10),
        "cwe_top": cwe_raw.most_common(15),
        "n_cwe_raw": len(cwe_raw),
        "code_pair": {
            "both": both, "only_vuln": only_vuln,
            "only_fixed": only_fixed, "empty_both": empty_pair,
            "identical": identical_pair,
        },
        "len_vuln": {
            "median": q(vuln_len, .5), "p90": q(vuln_len, .9),
            "p99": q(vuln_len, .99), "max": max(vuln_len) if vuln_len else 0,
            "over_20k": over_20k_vuln,
            "over_512tok": over_512tok_vuln,
            "n": len(vuln_len),
        },
        "len_fixed": {
            "median": q(fixed_len, .5), "p90": q(fixed_len, .9),
            "p99": q(fixed_len, .99), "max": max(fixed_len) if fixed_len else 0,
            "over_20k": over_20k_fixed,
            "over_512tok": over_512tok_fixed,
            "n": len(fixed_len),
        },
        "severity_values": sev_vals.most_common(),
        "invalid_cvss3": invalid_score,
    }

    # ---- 控制台报告 ----
    hr("1.1 规模与重复", "-")
    print(f"记录总数           : {n_total:,}")
    print(f"唯一 cve_id        : {result['n_unique_cve']:,}   （重复 {dup_cve:,} 条，"
          f"即一个 CVE 有多个修复提交）")
    print(f"唯一 commit hash   : {result['n_unique_hash']:,}   （重复 {dup_hash:,} 条）")
    print(f"项目数             : {result['n_projects']:,}")
    print(f"CWE 原始取值数      : {result['n_cwe_raw']:,}")

    hr("1.2 缺失情况（null / 空串 / 'nan' 字符串占位）", "-")
    print(f"{'字段':<22}{'null':>10}{'空串':>10}{'\"nan\"':>10}{'缺失率':>10}")
    for c in RAW_COLS:
        if c not in miss:
            continue
        m = miss[c]
        bad = m["null"] + m["empty_str"] + m["nan_str"]
        print(f"{c:<22}{m['null']:>10,}{m['empty_str']:>10,}{m['nan_str']:>10,}"
              f"{pct(bad, n_total):>10}")

    hr("1.3 代码字段质量（两条样本的来源）", "-")
    pc = result["code_pair"]
    print(f"vuln + fixed 都有  : {pc['both']:>8,}  ({pct(pc['both'], n_total)})"
          f"   ← 一条记录产出 2 条训练样本")
    print(f"只有 vulnerable    : {pc['only_vuln']:>8,}  ({pct(pc['only_vuln'], n_total)})")
    print(f"只有 fixed         : {pc['only_fixed']:>8,}  ({pct(pc['only_fixed'], n_total)})")
    print(f"两个都没有         : {pc['empty_both']:>8,}  ({pct(pc['empty_both'], n_total)})")
    print(f"vuln == fixed      : {pc['identical']:>8,}  ({pct(pc['identical'], pc['both'])}"
          f" of 成对记录)  ← 同一段代码产出矛盾标签")

    hr("1.4 长度异常（字符数）", "-")
    for name, key in (("vulnerable_code", "len_vuln"), ("fixed_code", "len_fixed")):
        L = result[key]
        print(f"{name}: n={L['n']:,}  中位={L['median']:,}  p90={L['p90']:,}  "
              f"p99={L['p99']:,}  max={L['max']:,}")
        print(f"    超过构建截断阈值 {TRUNC_CHARS:,} 字符: {L['over_20k']:,} "
              f"({pct(L['over_20k'], L['n'])})")
        print(f"    超过 512 token 等效字符数 {CHARS_FOR_512_TOKENS:,}: "
              f"{L['over_512tok']:,} ({pct(L['over_512tok'], L['n'])})  "
              f"← 这段会被 tokenizer 砍掉")

    hr("1.5 字段取值异常", "-")
    print("severity 取值分布（注意字符串 'nan' 不是真正的空值）:")
    for v, c in result["severity_values"][:8]:
        print(f"    {v:<20} {c:>8,}")
    print(f"\ncvss3_base_score 超出 [0,10] 的记录: {invalid_score:,}")

    hr("1.6 语言分布（前 12）", "-")
    for v, c in result["languages"][:12]:
        print(f"    {v:<18} {c:>8,}  {pct(c, n_total):>8}")

    return result


# ---------------------------------------------------------------------------
# 第二段：预处理后数据审计
# ---------------------------------------------------------------------------

def load_jsonl(path: Path) -> list[dict]:
    """读一份 JSONL。"""
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def audit_processed() -> dict:
    """审计 data/processed 下的 6 份 jsonl + 标签映射 + 统计。"""
    hr("第二段：预处理后数据审计  data/processed/*.jsonl")

    det = {s: load_jsonl(PROC_DIR / f"cvefixes_detection_{s}.jsonl")
           for s in ("train", "val", "test")}
    cls = {s: load_jsonl(PROC_DIR / f"cvefixes_classification_{s}.jsonl")
           for s in ("train", "val", "test")}
    lmap_c = json.loads((PROC_DIR / "cvefixes_classification_label_map.json")
                        .read_text(encoding="utf-8"))
    stats = json.loads((PROC_DIR / "cvefixes_stats.json").read_text(encoding="utf-8"))

    result: dict = {}

    # ---- 2.1 规模与标签分布 ----
    hr("2.1 规模与标签分布", "-")
    print(f"{'任务':<16}{'split':<8}{'样本数':>10}{'正例':>10}{'正例率':>10}{'group数':>10}")
    result["detection"] = {}
    for s, rows in det.items():
        pos = sum(r["label"] for r in rows)
        gs = len({r["group_id"] for r in rows})
        result["detection"][s] = {"n": len(rows), "pos": pos,
                                  "pos_rate": pos / len(rows), "groups": gs}
        print(f"{'detection':<16}{s:<8}{len(rows):>10,}{pos:>10,}"
              f"{pct(pos, len(rows)):>10}{gs:>10,}")
    result["classification"] = {}
    for s, rows in cls.items():
        cnt = collections.Counter(r["label"] for r in rows)
        result["classification"][s] = {
            "n": len(rows), "classes": len(cnt),
            "other": cnt.get(40, 0),
            "min_nonzero": min((v for k, v in cnt.items() if k != 40), default=0),
            "max": max(cnt.values()),
        }
        c = result["classification"][s]
        print(f"{'classification':<16}{s:<8}{len(rows):>10,}{'—':>10}"
              f"{'—':>10}{'—':>10}   类别 {c['classes']}, OTHER {c['other']}")

    # ---- 2.2 数据泄漏（三层） ----
    hr("2.2 数据泄漏检查（防泄漏设计是这个项目最对的地方）", "-")
    gid = {s: {r["group_id"] for r in rows} for s, rows in det.items()}
    hsh = {s: {r["code_hash"] for r in rows} for s, rows in det.items()}
    nws = {s: {norm_ws(r["code"]) for r in rows} for s, rows in det.items()}
    leak = {
        "group_t_v": len(gid["train"] & gid["val"]),
        "group_t_te": len(gid["train"] & gid["test"]),
        "group_v_te": len(gid["val"] & gid["test"]),
        "md5_t_te": len(hsh["train"] & hsh["test"]),
        "md5_t_v": len(hsh["train"] & hsh["val"]),
        "nows_t_te": len(nws["train"] & nws["test"]),
    }
    result["leakage"] = leak
    print(f"{'检查项':<40}{'交叉数':>10}{'判定':>12}")
    rows_chk = [
        ("group_id 交叉 train∩val", leak["group_t_v"], "必须为 0"),
        ("group_id 交叉 train∩test", leak["group_t_te"], "必须为 0"),
        ("group_id 交叉 val∩test", leak["group_v_te"], "必须为 0"),
        ("MD5 指纹交叉 train∩val", leak["md5_t_v"], "必须为 0"),
        ("MD5 指纹交叉 train∩test", leak["md5_t_te"], "必须为 0"),
        ("去空白指纹交叉 train∩test", leak["nows_t_te"],
         f"{pct(leak['nows_t_te'], len(det['test']))} of test"),
    ]
    for name, val, note in rows_chk:
        flag = "✅ 通过" if val == 0 else ("⚠️ 轻微" if val < 20 else "❌ 严重")
        print(f"{name:<40}{val:>10,}   {flag}  ({note})")

    # ---- 2.3 标签冲突与近重复 ----
    hr("2.3 标签冲突与近重复（噪声）", "-")
    # 标签冲突：同一段代码（去空白后）同时出现 label=0 和 label=1
    allrows = det["train"] + det["val"] + det["test"]
    by_hash: dict[str, set[int]] = collections.defaultdict(set)
    for r in allrows:
        by_hash[norm_ws(r["code"])].add(r["label"])
    conflict = sum(1 for v in by_hash.values() if len(v) > 1)
    result["label_conflict"] = conflict
    print(f"标签冲突指纹数（同一段代码同时带 0 和 1）: {conflict:,}")
    print("  → 模型在完全相同的输入上会收到相反的梯度，属于数据集固有噪声")

    # 近重复：同一份数据内部，去空白后重复
    for s in ("train", "val", "test"):
        codes = [norm_ws(r["code"]) for r in det[s]]
        dup = len(codes) - len(set(codes))
        print(f"  {s:<6} 去空白后重复 {dup:,} 条 ({pct(dup, len(codes))})")

    # ---- 2.4 ★ 测试集结构：成对样本（基准虚高的根源） ----
    hr("2.4 ★ 测试集结构：同胞对占比（基准虚高的根源）", "-")
    by_g: dict[str, list[dict]] = collections.defaultdict(list)
    for r in det["test"]:
        by_g[r["group_id"]].append(r)
    paired = [g for g, v in by_g.items() if len({x["label"] for x in v}) == 2]
    paired_set = set(paired)
    n_pair_samples = sum(len(by_g[g]) for g in paired)
    iso = [r for r in det["test"] if r["group_id"] not in paired_set]
    result["test_structure"] = {
        "groups": len(by_g), "paired_groups": len(paired),
        "paired_samples": n_pair_samples, "n_test": len(det["test"]),
        "isolated_samples": len(iso),
        "isolated_pos_rate": (sum(r["label"] for r in iso) / len(iso)) if iso else 0,
    }
    t = result["test_structure"]
    print(f"测试集 group 总数                : {t['groups']:,}")
    print(f"其中「同时含漏洞版+修复版」的成对 group : {t['paired_groups']:,} "
          f"({pct(t['paired_groups'], t['groups'])})")
    print(f"属于成对组的样本数               : {t['paired_samples']:,} / {t['n_test']:,} "
          f"({pct(t['paired_samples'], t['n_test'])})")
    print(f"★ 孤立样本（无同胞）              : {t['isolated_samples']:,} "
          f"({pct(t['isolated_samples'], t['n_test'])})")
    print(f"  孤立样本正例率                 : {pct(t['isolated_pos_rate'] * len(iso), len(iso))}")
    print("\n  → 测试集里近九成样本是「同一 commit 的漏洞版/修复版」，")
    print("    模型很擅长比较这两行 diff，但这不是「发现新漏洞」的能力。")

    # ---- 2.5 ★ 超窗样本占比（头尾截断失效的影响面） ----
    hr("2.5 ★ 超过 512 token 窗口的样本占比（截断失效影响面）", "-")
    over = {}
    print(f"{'split':<8}{'n':>8}{'中位字符':>12}{'>1900字符':>12}{'占比':>10}")
    for s, rows in det.items():
        L = sorted(len(r["code"]) for r in rows)
        o = sum(1 for x in L if x > CHARS_FOR_512_TOKENS)
        over[s] = {"n": len(L), "median": L[len(L) // 2], "over": o,
                   "rate": o / len(L)}
        print(f"{s:<8}{len(L):>8,}{L[len(L)//2]:>12,}{o:>12,}{pct(o, len(L)):>10}")
    result["over_window"] = over
    print(f"\n  阈值说明：{CHARS_FOR_512_TOKENS} 字符 ≈ 512 token（实测约 3.8 字符/token）")
    print("  → 这些样本的「尾部」会被 tokenizer 的 truncation=True 再砍一次，")
    print("    构建阶段精心保留的头尾结构在它们身上实际失效。")

    # ---- 2.6 分类任务长尾 ----
    hr("2.6 分类任务长尾与 OTHER 类膨胀", "-")
    cnt_tr = collections.Counter(r["label"] for r in cls["train"])
    cnt_te = collections.Counter(r["label"] for r in cls["test"])
    id2 = {int(k): v for k, v in lmap_c["id2name"].items()}
    other_tr = cnt_tr.get(40, 0)
    result["class_longtail"] = {
        "num_labels": lmap_c["num_labels"],
        "other_train": other_tr, "other_rate": other_tr / len(cls["train"]),
        "max_class_train": max(cnt_tr.values()),
        "min_nonzero_test": min(v for k, v in cnt_te.items() if k != 40),
        "suport_lt10_classes": sum(1 for k, v in cnt_te.items() if v < 10),
        "suport_ge20_classes": sum(1 for k, v in cnt_te.items() if v >= 20),
    }
    lt = result["class_longtail"]
    print(f"类别数（含 OTHER）          : {lt['num_labels']}")
    print(f"OTHER 类在训练集占比        : {pct(other_tr, len(cls['train']))} "
          f"({other_tr:,} 条)")
    print(f"最大真实类（训练集）        : {lt['max_class_train']:,} 条")
    print(f"测试集最小非零类样本数      : {lt['min_nonzero_test']} 条  ← 单条样本决定 0 或 1")
    print(f"测试集 support < 10 的类数  : {lt['suport_lt10_classes']}")
    print(f"测试集 support >= 20 的类数 : {lt['suport_ge20_classes']}")
    print("\n  训练集各类样本数（降序，前 12）:")
    for k, v in cnt_tr.most_common(12):
        print(f"    {id2.get(k, '?'):<12} {v:>7,}  {pct(v, len(cls['train'])):>8}")

    # ---- 2.7 语言与项目分布 ----
    hr("2.7 语言与项目分布（检测训练集）", "-")
    lang = collections.Counter(r.get("language") or "(空)" for r in det["train"])
    proj = collections.Counter(r.get("project") or "(空)" for r in det["train"])
    result["languages_processed"] = lang.most_common()
    result["n_projects_processed"] = len(proj)
    for v, c in lang.most_common(12):
        print(f"    {v:<18} {c:>8,}  {pct(c, len(det['train'])):>8}")
    print(f"\n  项目数: {len(proj):,}   最大项目: {proj.most_common(3)}")

    # ---- 2.8 与 stats.json 的一致性 ----
    hr("2.8 与 cvefixes_stats.json 的一致性校验", "-")
    s_total = stats.get("total_raw", -1)
    s_det_tr = stats["tasks"]["detection"]["splits"]["train"]["n"]
    ok = (s_total == 18925 and s_det_tr == len(det["train"]))
    print(f"stats.total_raw        = {s_total:,}")
    print(f"stats.detection.train  = {s_det_tr:,}")
    print(f"实测 detection train   = {len(det['train']):,}")
    print(f"一致性: {'✅ 通过' if ok else '❌ 不一致'}")
    result["stats_consistent"] = ok

    return result


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    raw = audit_raw()
    proc = audit_processed()

    hr("审计完成", "=")
    (OUT_DIR / "audit_raw.json").write_text(
        json.dumps(raw, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    (OUT_DIR / "audit_processed.json").write_text(
        json.dumps(proc, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"原始数据审计数字 -> {OUT_DIR / 'audit_raw.json'}")
    print(f"处理后数据审计数字 -> {OUT_DIR / 'audit_processed.json'}")
    print("\n提示：可视化请跑 analysis/plot_eda.py")


if __name__ == "__main__":
    main()
