# 代码漏洞检测与漏洞分类 —— BERT 微调全流程

用 CVE 数据集微调 BERT 系代码预训练模型，实现两个任务：

| 任务 | 类型 | 输入 | 输出 |
|------|------|------|------|
| **漏洞检测** | 二分类 | 一段源码 | `safe` / `vulnerable` + 置信度 |
| **漏洞分类** | 多分类 | 一段漏洞源码 | CWE 类型（CWE-79 / CWE-89 / CWE-125 …）+ Top-5 |

数据集、模型权重、代码、脚本**都已下载并跑通**，位于 `D:\workbuddy_workspace\vuln_bert`，开箱即用。

### 📚 详细文档在 `docs/`

| 文档 | 内容 |
|------|------|
| [`docs/01_数据集与模型全解析.md`](docs/01_数据集与模型全解析.md) | 原始数据字段 → 清洗规则 → 模型输入 → 训练方式 → 推理输出，六问全解析 |
| [`docs/02_模型运行完整流程与测试用例.md`](docs/02_模型运行完整流程与测试用例.md) | 9 步完整操作流程 + 测试用例 + 排错手册 + 验收清单 |
| [`docs/03_项目交接与迁移指南.md`](docs/03_项目交接与迁移指南.md) | **要把项目同步给别人跑、或自己换电脑时看这份**：同步清单、验收步骤、必改的路径 |
| [`docs/check_all.bat`](docs/check_all.bat) | 一键跑完环境自检 → 单元测试 → 冒烟训练 → 批量推理（约 40 秒） |

### 当前完成状态

| 项目 | 状态 | 位置 / 说明 |
|------|------|-------------|
| CVEfixes 原始文件 | ✅ 已下载 1.1 GB | `data/raw/cvefixes/` |
| 统一格式训练数据 | ✅ 已生成 56 MB | `data/processed/cvefixes_*.jsonl`（检测 1.89 万 / 分类 7,291，见下节表格） |
| CodeBERT 预训练权重 | ✅ 已下载 477 MB | `models/microsoft__codebert-base/` |
| 完整代码流水线 | ✅ 已编写并验证 | `src/` + `scripts/` |
| 训练 → 评估 → 推理 | ✅ 已端到端跑通 | 冒烟测试产物见 `outputs/demo_detection/` |
| 依赖环境 | ✅ 已装好隔离 venv | `C:\Users\awu70\.workbuddy\binaries\python\envs\vuln_bert` |

> ✅ **正式训练已完成**（2026-09-16，conda `py312` + RTX 3060 Laptop 6 GB，全量 15,147 条 × 3 轮，约 27 分钟）：
> 测试集 **F1 = 0.7521**，accuracy 0.7618，ROC-AUC 0.8396。参数在 `outputs/cvefixes_detection_codebert-base/best/`。
> 详细指标与阈值分析见 [`docs/01_数据集与模型全解析.md`](docs/01_数据集与模型全解析.md) 第 5.9 节。
>
> ⚠️ 注意：本项目有**两套 Python 环境**——conda `py312`（有 CUDA，训练用）和隔离 venv
> `C:\Users\awu70\.workbuddy\binaries\python\envs\vuln_bert`（CPU 版，只跑流程）。
> 环境对照见 [`docs/02_模型运行完整流程与测试用例.md`](docs/02_模型运行完整流程与测试用例.md) 第 1.1 节。

### 📘 看不懂这份代码？看教学版

本项目的代码是"工程写法"（`src/` + `scripts/` 分层、抽象较多），
如果觉得抽象、不好理解，**另有一份功能完全相同、但逐行中文注释的教学版**：

```
D:\workbuddy_workspace\vuln_bert_教学版\
```

教学版采用编号目录 + 编号脚本的组织方式，每个文件都能单独运行看效果：

| | 本工程版 | 教学版 |
|---|---|---|
| 目录 | `src/` + `scripts/` | `_01_data/` `_02_bert检测/` `_03_bert分类/` |
| 文件 | `train.py` / `predict.py` | `_05_bert模型训练代码_gpu.py` / `_06_bert_predict_fun.py` |
| 配置 | `configs/config.yaml` | 每个模块一个 `_01_config.py` 类 |
| 注释 | 函数级 + 关键逻辑 | **逐行中文注释** |
| 数据 | 自己构建 | 复用工程版已构建好的数据 |
| 适合 | 真正做实验、跑对比 | **学习、跟练、理解每一步** |

两边用的是同一份数据和同一个模型，结果完全一致。

---

## 一、目录结构

```
vuln_bert/
├── README.md                      ← 本文件（完整操作手册）
├── requirements.txt               ← 依赖清单
├── configs/
│   └── config.yaml                ← 训练配置（模型/任务/数据/超参）
├── src/                           ← 可复用模块
│   ├── config.py                  ← 配置加载
│   ├── utils.py                   ← 种子、日志、头尾截断
│   ├── models.py                  ← VulnClassifier（BERT + 分类头）
│   ├── metrics.py                 ← 二分类/多分类指标
│   └── datasets.py                ← Torch Dataset + 动态 padding
├── scripts/                       ← 可执行脚本
│   ├── check_env.py               ← ① 环境自检
│   ├── download_data.py           ← ② 下载数据集
│   ├── download_model.py          ← ③ 下载预训练模型
│   ├── build_dataset.py           ← ④ 构建统一训练数据
│   ├── train.py                   ← ⑤ 微调训练
│   └── predict.py                 ← ⑥ 推理
├── data/
│   ├── raw/                       ← 原始数据（CVEfixes，已下载 1.1 GB）
│   └── processed/                 ← 构建好的 JSONL（已生成 56 MB）
├── models/                        ← 预训练权重（CodeBERT 已下载 477 MB）
└── outputs/
    ├── README.md                  ← 产物说明
    └── demo_detection/            ← 冒烟测试产物（仅验证流程可跑通，非可用模型）
```

---

## 二、数据集（CVEfixes，已下载完成，共 1.1 GB）

### 2.1 使用的数据集

| 数据源 | 论文/来源 | 原始规模 | 检测样本 | 分类类别 | 磁盘 |
|--------|-----------|----------|----------|----------|------|
| **CVEfixes** | MSR 2021（CVE 官方修复提交） | 13,000 条 CVE | **18,925** | **40 个 CWE**（41 类） | 1.1 GB |

> 分类任务的类别数 = 保留的 CWE 数 + 1（长尾类别合并出的 `OTHER` 类）。

> **本项目只使用 CVEfixes 一个数据源**，BigVul / DiverseVul / CodeXGLUE 及其合并版已从代码和数据中移除。

**为什么选 CVEfixes**：规模适中（1.9 万条，单卡 1~2 小时可训完）、正负样本均衡（安全 55% / 漏洞 45%）、40 个 CWE 类别覆盖 XSS、SQL 注入、缓冲区溢出、路径遍历等主流漏洞，且检测与分类两个任务共用同一套划分。

### 2.2 下载渠道

| 数据集 | 官方渠道 | 本仓库脚本 |
|--------|----------|-----------|
| CVEfixes（原始 SQL 全量 12 GB） | https://zenodo.org/records/13118970 · https://github.com/secureIT-project/CVEfixes | — |
| CVEfixes（函数级衍生版，本仓库采用） | https://huggingface.co/datasets/hitoshura25/cvefixes | `--datasets cvefixes` |

```bash
# 查看可用数据集
python scripts/download_data.py --list

# 下载（国内网络慢时换镜像）
python scripts/download_data.py --datasets cvefixes
python scripts/download_data.py --datasets all --mirror hf-mirror
```

### 2.3 统一后的数据格式

`data/processed/<source>_<task>_{train,val,test}.jsonl`，每行一条：

```json
{
  "id": "CVE-2023-4432-vuln",
  "code": "<input id=\"apiKey\" ... value=\"<?=($apiKey ? $apiKey : '')?>\">",
  "label": 1,
  "cwe": "CWE-79",
  "cwe_name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  "source": "cvefixes",
  "language": "PHP",
  "project": "invoiceplane",
  "group_id": "cvefixes::CVE-2023-4432::<commit>"
}
```

- **检测任务**：`label` = 0（安全）/ 1（漏洞）
- **分类任务**：`label` = CWE 类别 id（0~38），39 = `OTHER`（长尾合并）
- **`group_id` 用于防泄漏**：同一漏洞的「漏洞版本」和「修复版本」被强制分到同一个 split，避免模型靠"见过近似代码"刷分。

标签映射见 `data/processed/<source>_<task>_label_map.json`，统计见 `<source>_stats.json`。

---

## 三、预训练模型下载渠道

代码漏洞检测领域的事实标准是 **CodeBERT** 系列。全部可通过脚本离线下载到 `models/`：

| 模型 | HuggingFace | ModelScope（国内） | 参数量 | 说明 |
|------|-------------|-------------------|--------|------|
| **microsoft/codebert-base** ⭐ | https://huggingface.co/microsoft/codebert-base | https://www.modelscope.cn/models/microsoft/codebert-base | 125M | **推荐首选**。CodeSearchNet 6 语言预训练 |
| microsoft/graphcodebert-base | https://huggingface.co/microsoft/graphcodebert-base | 同上搜索 | 125M | 加入数据流图（DFG）预训练，漏洞任务通常更强 |
| microsoft/unixcoder-base | https://huggingface.co/microsoft/unixcoder-base | 同上搜索 | 125M | 代码 + AST + 注释三模态 |
| bert-base-uncased | https://huggingface.co/google-bert/bert-base-uncased | https://www.modelscope.cn/models/tiansz/bert-base-uncased | 110M | 通用英文 BERT，作对照基线 |
| Salesforce/codet5-base | https://huggingface.co/Salesforce/codet5-base | — | 220M | Encoder-Decoder，可做漏洞修复生成 |

```bash
python scripts/download_model.py --list                  # 查看可选模型
python scripts/download_model.py --models codebert       # 下载（已执行）
python scripts/download_model.py --models codebert,graphcodebert --mirror hf-mirror
```

**国内加速**：若 huggingface.co 访问慢，任选其一
```bash
# 方式 A：脚本参数
python scripts/download_model.py --models codebert --mirror hf-mirror
# 方式 B：环境变量（对所有 transformers / datasets 调用生效）
set HF_ENDPOINT=https://hf-mirror.com      # Windows CMD
export HF_ENDPOINT=https://hf-mirror.com   # Linux / macOS / Git Bash
# 方式 C：ModelScope 下载后，把本地目录路径直接传给 --model
```

---

## 四、环境准备

```bash
cd D:\workbuddy_workspace\vuln_bert

# 1) 创建虚拟环境（推荐 Python 3.9~3.12）
python -m venv .venv
.venv\Scripts\activate                  # Windows
# source .venv/bin/activate             # Linux/macOS

# 2) 安装依赖
pip install -r requirements.txt

# 3) 【有 GPU 必做】装 CUDA 版 PyTorch（先查驱动支持的 CUDA 版本：nvidia-smi）
pip install torch --index-url https://download.pytorch.org/whl/cu121

# 4) 自检
python scripts/check_env.py
```

`check_env.py` 会报告 Python 版本、依赖、GPU 型号与显存、原始数据、处理后数据、本地模型是否就绪。

> **显存对照**：`max_length=512, batch_size` 建议 —— 8 GB→8，16 GB→16，24 GB→32，40 GB+→64。
> 显存不足时优先降 `batch_size`，再考虑把 `max_length` 降到 256，并配合 `gradient_accumulation_steps` 保持等效 batch。

---

## 五、完整操作步骤

### 步骤 1｜环境自检
```bash
python scripts/check_env.py
```

### 步骤 2｜下载数据集（已完成，可跳过）
```bash
python scripts/download_data.py --datasets all
```

### 步骤 3｜下载预训练模型（CodeBERT 已完成，可跳过）
```bash
python scripts/download_model.py --models codebert
```

### 步骤 4｜构建训练数据
```bash
# CVEfixes（1.9 万条检测 + 7,291 条分类，40 类 CWE）
python scripts/build_dataset.py --source cvefixes

# 只构建其中一个任务
python scripts/build_dataset.py --source cvefixes --task detection
python scripts/build_dataset.py --source cvefixes --task classification
```
产物写入 `data/processed/`。构建过程含：长度过滤 → 字符级头尾截断（8000 字符）→ MD5 去重 → **按 `group_id` 分组划分**（8:1:1）。

### 步骤 5｜微调训练

**任务 A：漏洞检测（二分类）**
```bash
python scripts/train.py --task detection --source cvefixes --model microsoft/codebert-base
```

**任务 B：漏洞分类（CWE 多分类）**
```bash
python scripts/train.py --task classification --source cvefixes --model microsoft/codebert-base
```

**快速冒烟测试（CPU 也能跑通，约 1 分钟）**
```bash
python scripts/train.py --task detection --source cvefixes ^
    --epochs 1 --batch-size 8 --max-length 128 ^
    --max-train-samples 200 --max-eval-samples 100
```

**常用覆盖参数**（命令行优先于 `configs/config.yaml`）

| 参数 | 说明 |
|------|------|
| `--model` | 预训练模型名或本地路径（如 `models/microsoft__codebert-base`） |
| `--epochs` / `--batch-size` / `--lr` | 训练轮数 / 批大小 / 学习率 |
| `--max-length` | 最大 token 长度（512 / 256 / 128） |
| `--max-train-samples` | 限制训练样本数，调试用 |
| `--imbalance` | `weighted_loss`（默认）/ `balanced_sampler` / `none` |
| `--run-name` | 输出子目录名 |
| `--cpu` | 强制 CPU |

训练产物（`outputs/<run_name>/`）：
```
config.yaml            生效配置（可复现）
best/pytorch_model.bin 验证集最优权重
best/tokenizer.json    分词器
best/label_map.json    标签映射
results.json           每轮指标 + 测试集指标
report_test.txt        逐类别 P/R/F1 明细（分类任务）
probs_test.npy         预测概率（可用于画 PR/ROC 曲线）
logits_test.npy / labels_test.npy
```

### 步骤 6｜推理

```bash
# 单段代码
python scripts/predict.py --checkpoint outputs/cvefixes_detection_codebert-base/best ^
  --code "void f(char *s){ char buf[10]; strcpy(buf, s); }"

# 从文件读取
python scripts/predict.py --checkpoint <ckpt> --file test.c

# 批量（JSONL，字段 code），自动与 gold 标签比对准确率
python scripts/predict.py --checkpoint <ckpt> ^
  --input data/processed/cvefixes_detection_test.jsonl --output outputs/preds.jsonl
```

输出示例（检测）：
```
判定结果 : vulnerable
置信度   : 0.9987
安全概率 : 0.0013
漏洞概率 : 0.9987
```
输出示例（分类）：
```
预测 CWE : CWE-787  (置信度 0.6120)
Top-5    :
   CWE-787      0.6120
   CWE-125      0.1903
   CWE-119      0.0881
   ...
```

### 步骤 7｜对比实验（建议）
```bash
# 换模型
python scripts/train.py --model microsoft/graphcodebert-base --run-name gcb_detection
# 换不平衡策略
python scripts/train.py --imbalance balanced_sampler --run-name bs_detection
# 对照基线
python scripts/train.py --model bert-base-uncased --run-name bert_base_detection
```
所有 `outputs/*/results.json` 可直接横向比较。

---

## 六、关键设计说明

**1. 头尾截断（head+tail）**
漏洞代码的关键信息（参数校验、循环边界、`free()`）常出现在函数首尾。`src/utils.py::truncate_code` 按 6:4 保留头尾，比直接截断尾部保留更多有效信息。

**2. 按 group 划分，杜绝数据泄漏**
同一 CVE 的「漏洞版本」和「修复版本」差异极小。若随机划分，测试集会出现训练集的近邻副本，指标虚高。本项目以 `group_id`（CVE + commit hash）为单位划分。

**3. 分层学习率**
编码器 `2e-5`、分类头 `1e-4`（`head_learning_rate`）。随机初始化的分类头需要更大步长才能跟上预训练权重。

**4. 类别不平衡处理**
CVEfixes 检测任务正负样本大致均衡（漏洞约 45%），但分类任务的 40 个 CWE 类别长尾明显（最小类 37 条、最大类 1,349 条），
因此默认 `weighted_loss`（按类别频率倒数加权交叉熵），也可切 `balanced_sampler`。

**5. 长尾 CWE 合并**
CWE 分布极度长尾。`min_class_samples=30` + `top_k_classes=40`：样本量不足 30 的类别合并为 `OTHER`，避免模型在 1~2 个样本的类别上过拟合。

---

## 七、常见问题

**Q1：`CUDA out of memory`**
```bash
python scripts/train.py --batch-size 4 --max-length 256
```
并在 `configs/config.yaml` 里设 `gradient_accumulation_steps: 4` 保持等效 batch = 16。

**Q2：下载超时 / 连接被重置**
```bash
set HF_ENDPOINT=https://hf-mirror.com
python scripts/download_data.py --datasets cvefixes
```
`download_data.py` 支持断点续传，重复执行会自动跳过已完成的文件。

**Q3：Windows 上 DataLoader 报多进程错误**
`configs/config.yaml` 中 `num_workers: 0`（默认已设）。

**Q4：CPU 训练太慢**
单条 512-token 样本在 CPU 上约 2~3 条/秒。务必用 `--max-train-samples 200` 先跑通流程，正式训练换 GPU。GPU（RTX 3090）上 CVEfixes 检测任务约 **15 分钟/epoch**。

**Q5：检测任务 F1 只有 0.6 左右，正常吗？**
正常。代码漏洞检测本身是困难任务（文献中 CodeBERT 在 BigVul/Devign 这类真实分布数据集上 F1 多在 **0.55~0.65**）。
在 CVEfixes 这类"修复前后对比"数据上，由于漏洞版与修复版常只差几行、相似度较高，指标通常会显著高于上述区间。
若结果异常低，优先检查：
1. 是否误用 `--max-train-samples` 导致训练不足；
2. 分类任务是否因长尾类别拉低 macro-F1（看 `report_test.txt` 的加权 F1）。

**Q6：想用 CVEfixes 官方全量（12 GB SQL dump）**
```bash
curl -L -o CVEfixes_v1.0.8.zip https://zenodo.org/records/13118970/files/CVEfixes_v1.0.8.zip
# 解压后需 PostgreSQL 导入，再自行导出 vulnerable_code / fixed_code 字段
```
数据量大且需要数据库环境，除非做全量实验，否则建议用本仓库已下载的函数级衍生版。

**Q7：`transformers` 版本差异导致报错**
本项目在 `transformers 5.17` + `torch 2.14` 上验证通过。若报 `AutoModel` 相关错误，先 `pip install -U "transformers>=4.45"`。

---

## 八、参考文献

1. Bhandari et al. **CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software.** MSR 2021.
2. Feng et al. **CodeBERT: A Pre-Trained Model for Programming and Natural Languages.** EMNLP 2020.
3. Guo et al. **GraphCodeBERT: Pre-training Code Representations with Data Flow.** ICLR 2021.
7. Zhou et al. **Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks.** NeurIPS 2019.
