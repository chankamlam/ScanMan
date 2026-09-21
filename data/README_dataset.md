# 数据集说明（Dataset Card）

本目录记录 ScanMan 项目所使用的漏洞数据集，包括来源、许可证、字段、规模与构建方式。

> **构建器支持 4 个数据源及四源合并版**（`cvefixes` / `bigvul` / `diversevul` /
> `codexglue` / `merged`），见 `scripts/build_dataset.py` 的 `BUILDERS`。
> **下载脚本目前只提供 CVEfixes**（`python scripts/download_data.py --datasets cvefixes`），
> 其余数据源需自行按构建器要求的字段与文件布局准备到 `data/raw/` 下。

---

## 一、总览

| 数据源 | 原始数据 | 检测样本（二分类） | 分类样本（CWE 多分类） | 类别数 |
|--------|----------|-------------------|----------------------|--------|
| CVEfixes | 13,000 条 CVE 修复记录 | **18,925** | **7,291** | 40 个 CWE（41 类） |
| BigVul | 223,003 个函数 / 3,754 CVE | **174,161** | **7,346** | 26 |
| DiverseVul | 523,956 个函数 / 933 项目 | **505,690** | —（无 CWE 字段） | — |
| CodeXGLUE | 27,318 个函数 | **27,254** | —（仅二分类） | — |
| **merged** | 四源合并 | **539,124** | **14,637** | 40 |

> 上表为各源的构建规模；`merged` 逐源合并后再统一去重、按 `group_id` 划分。
> 现有演示报告使用的 `merged_top27` 分类数据是 `scripts/relabel_classes.py --top-k 27`
> 在 `merged` 分类数据上重标得到的（27 个 CWE + `OTHER`，共 28 类）。

**磁盘占用**：`data/raw` 约 2.1 GB，`data/processed` 约 1.9 GB。`data/raw/` 与
`data/processed/` 均不纳入 Git，需用下载脚本或 `scripts/build_dataset.py` 重新准备。

**CVEfixes 划分明细（实测）**

| 任务 | train | val | test | 正例率 |
|------|-------|-----|------|--------|
| 检测（二分类） | 15,147 | 1,876 | 1,902 | 44.5% |
| 分类（CWE） | 5,832 | 729 | 730 | — |

---

## 二、CVEfixes 详情

- **论文**：Bhandari, Nanz, Sabetta. *CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software.* MSR 2021.
- **来源**：从 NVD 抓取 CVE 记录，关联到开源项目的修复提交，抽取代码 diff 还原出修复前/后代码。
- **官方版本**：v1.0.8（截至 2024-07-23），覆盖 12,107 个修复提交、4,249 个项目。
- **本仓库使用**：HuggingFace `hitoshura25/cvefixes` —— 官方 SQL dump 的**函数级衍生版**，12,987 条修复记录、11,726 个 CVE、4,205 个仓库。
- **下载**：
  - 官方全量（12.7 GB SQL dump，CC-BY-4.0）：https://zenodo.org/records/13118970
  - 官方工具链：https://github.com/secureIT-project/CVEfixes
  - 函数级版（本仓库采用，HF 镜像标 Apache-2.0）：https://huggingface.co/datasets/hitoshura25/cvefixes
  - 重新下载：`python scripts/download_data.py --datasets cvefixes`

### 原始字段

`cve_id`, `hash`, `repo_url`, `cve_description`, `cvss2_base_score`, `cvss3_base_score`, `severity`, `cwe_id`, `cwe_name`, `cwe_description`, `commit_message`, `language`, `file_paths`, `diff_stats`, `diff_with_context`, `vulnerable_code`, `fixed_code`, `security_keywords` 等。

### 标签来源

- **检测** → `vulnerable_code`（label=1）/ `fixed_code`（label=0）
- **分类** → `cwe_id`（原始 269 个取值，保留 Top-40 后其余并入 `OTHER`）

### 数据分布特点（实测）

| 维度 | 实测值 |
|------|--------|
| 语言分布 | C 27.3%、PHP 20.3%、Other 10.1%、JavaScript 7.9%、Python 7.8%、C++ 5.5%，其余 Java / Ruby / Go 等 |
| 项目数 | 3,642 |
| 代码长度 | 中位 384 字符、均值 1,870 字符，超过 8,000 字符的占 6.3% |
| 分组数（train） | 8,526 个 group，平均每组 1.8 条样本 |
| 组内标签构成 | 77.7% 的 group 同时含漏洞版与修复版 |
| 分类长尾 | 40 个 CWE 中 24 个样本不足 100 条，最小的类仅 37 条 |

**特点小结**

- **多语言**：覆盖 6 种以上语言，比 C/C++ 单语数据集更接近真实工程。注意主流代码预训练模型（CodeBERT / GraphCodeBERT）的语料是 CodeSearchNet 的 6 种语言，**不含 C/C++**，而 C 恰是本数据集占比最大的语言。
- **正负均衡**：检测任务 55:45，无需采样即可直接训练。
- **分类长尾明显**：40 类中有 24 类不足 100 条，评估必须看 macro-F1，accuracy 会被头部类别主导。
- **修复版与漏洞版成对**：同一 CVE 的 vulnerable / fixed 共用 `group_id`，划分时不会分到不同 split，避免近邻泄漏。

---

## 三、统一后的数据格式

### 文件命名

```text
data/processed/
├── cvefixes_detection_train.jsonl / _val.jsonl / _test.jsonl
├── cvefixes_classification_train.jsonl / _val.jsonl / _test.jsonl
├── cvefixes_detection_label_map.json
├── cvefixes_classification_label_map.json
└── cvefixes_stats.json
```

### 记录字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | str | 唯一标识，如 `CVE-2023-4432-vuln`（漏洞版）/ `CVE-2023-4432-fixed`（修复版） |
| `code` | str | 源码片段（已做头尾截断） |
| `label` | int | 检测：0/1；分类：CWE 类别 id |
| `cwe` | str | 原始 CWE 编号，如 `CWE-79`（安全样本为空） |
| `cwe_name` | str | CWE 英文全称 |
| `source` | str | 数据源标识，固定为 `cvefixes` |
| `language` | str | 编程语言 |
| `project` | str | 所属开源项目（取自 `repo_url` 最后一段） |
| `group_id` | str | 防泄漏分组键（CVE + commit hash） |
| `code_hash` | str | 代码内容的 MD5，用于去重 |

### 标签映射示例（`cvefixes_classification_label_map.json`）

```json
{
  "task": "classification",
  "num_labels": 41,
  "id2name": {
    "0": "CWE-79",   "1": "CWE-125", "2": "CWE-89",  "3": "CWE-20",
    "4": "CWE-787",  "5": "CWE-119", "6": "CWE-22",  "7": "CWE-476",
    "...": "...",
    "40": "OTHER"
  }
}
```

`num_labels = 保留的 CWE 类别数 + 1`（末尾 `OTHER` 用于承接长尾类别）。

> **注意**：分类任务的标签 id 与 `cvefixes_stats.json` 中的分布一一对应，
> 训练和评估必须使用同一个 label_map；换数据源后 id 语义会变化。

---

## 四、构建流程（`scripts/build_dataset.py`）

```text
CVEfixes 原始数据 (parquet)
   ↓ ① 字段归一化：统一成 id / code / label / cwe / group_id
   ↓ ② 长度过滤：丢弃 < 30 字符的碎片
   ↓ ③ 头尾截断：> 20,000 字符时按 6:4 保留头尾（中间插入截断标记）
   ↓ ④ MD5 去重：同一段代码只保留一份（18,925 条即去重后的结果）
   ↓ ⑤ 按 group_id 分组划分 8:1:1（防数据泄漏）
   ↓ ⑥ 分类任务：CWE 频次统计 → 样本量 < 30 的合并为 OTHER → 取 Top-40
统一 JSONL + 标签映射 + 统计信息
```

**关键：为什么按 `group_id` 而不是按样本随机划分？**
CVEfixes 中同一 CVE 的「漏洞版本」与「修复版本」往往只差几行。若随机划分，
测试集里会出现训练集的近似副本，指标会虚高。以 CVE+commit 为单位划分后，
测试集才是真正"未见过的漏洞"。

### 两处截断阈值（容易混淆）

| 参数 | 位置 | 默认值 | 作用 |
|------|------|--------|------|
| `data.max_code_chars` | `configs/config.yaml` | 20,000 | **构建数据**时按 6:4 保留头尾，防止超长文件撑爆内存 |
| `model.max_code_chars` | `configs/config.yaml` | 8,000 | **送入 tokenizer 前**的字符级截断 |
| `model.max_length` | `configs/config.yaml` | 512 | tokenizer 的 token 上限，按**前 512 个 token** 截断 |

> ⚠️ 注意第三条：`truncation=True` 保留的是**前** 512 个 token，
> 按代码约 3.5~4 字符/token 估算只覆盖约 1,800~2,000 字符。
> 因此对超过该长度的样本（训练集约占 18%），第 ③ 步刻意保留的「尾部」
> 可能进不了模型。若要真正发挥头尾截断的设计意图，可把 `data.max_code_chars`
> 降到 2,000 左右再重新构建数据。

### 复现验证

```bash
python scripts/build_dataset.py --source cvefixes --out-dir /tmp/cvefixes_check
```

输出应与本目录现有文件逐字节一致（检测 15,147 / 1,876 / 1,902，分类 5,832 / 729 / 730）。

---

## 五、引用

```bibtex
@inproceedings{bhandari2021cvefixes,
  title={CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software},
  author={Bhandari, Guru and Nanz, Sebastian and Sabetta, Antonino},
  booktitle={MSR}, year={2021}
}
```
