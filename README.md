# ScanMan · 扫描超人

基于 CodeBERT 的**代码漏洞检测与 CWE 分类**项目：把一个源文件或整个项目目录丢进去，
逐函数判断"这里有没有漏洞"，并对命中的函数给出 CWE 类型，最后汇总成 JSON 报告，
可以在网页上查看。

```text
源文件 / 项目目录
    → 函数抽取（tree-sitter，拿到源码、函数名、行号）
    → 漏洞检测（safe / vulnerable + 漏洞概率）
    → 对命中函数做 CWE 分类（可选，第二级模型）
    → JSON 报告 → 网页展示
```

两级模型是**级联**的：分类器只处理检测命中的函数。分类数据里没有"安全"这一类，
喂安全函数等于逼模型在 27 个 CWE 里硬猜，产出的是看起来很像真的噪声。

---

## 当前能力

| 功能 | 当前实现 |
| --- | --- |
| 漏洞检测 | 二分类。支持单段代码、文件内容、JSONL 批量推理；判定阈值可调 |
| CWE 分类 | 已实现训练、推理及项目扫描中的两级级联；演示分类模型为 27 个 CWE + `OTHER`，共 28 类 |
| 项目扫描 | 支持目录或单个文件，统计各文件的函数数、可疑函数数，保留函数位置和可选源码 |
| 数据处理 | 构建器支持 CVEfixes、BigVul、DiverseVul、CodeXGLUE 及四源合并 `merged`；下载脚本目前只提供 CVEfixes |
| Web 扫描与展示 | React + TypeScript + Vite + Ant Design。可查看静态 JSON 报告，也可上传源文件调用本地 Flask 后端真跑模型 |
| 训练与评估 | 类别加权、平衡采样、混合精度、梯度累积、早停、检测阈值调优、分类 Top-k 指标 |

---

## 它是怎么工作的

| 环节 | 代码入口 | 职责 |
| --- | --- | --- |
| 函数抽取 | `src/extract.py` | 用 tree-sitter 按语法切函数，恢复行号与字节偏移。**以字节为真相源**，所以能正确处理 GBK 等非 UTF-8 文件 |
| 模型 | `src/models.py`、`src/data.py` | 预训练编码器 + 分类头；样本预处理与动态 padding |
| 推理 | `scripts/predict.py` | `VulnPredictor`：加载检查点、跑单条/批量推理 |
| 扫描汇总 | `scripts/scan_project.py` | 抽取 → 检测 → 分类 → 组装报告。**命令行和网页版共用这四个函数**，保证结果逐条一致 |
| Web 后端 | `scripts/serve.py` | 把 HTTP 请求翻译成对上面那条管线的调用，不含任何扫描逻辑 |
| 前端 | `web/` | 文件上传、调用后端、报告可视化（概率分布 / 文件排行 / CWE 分布 / 热力图） |
| 数据与训练 | `scripts/build_dataset.py`、`scripts/train.py` 等 | 见 `docs/09_命令参考.md` |

每一步的数据形态变化、以及它由哪个函数完成，见
[`docs/10_全链路贯通手册.md`](docs/10_全链路贯通手册.md)。

---

## 目录结构

```text
ScanMan/
├── configs/config.yaml         # 默认配置
├── src/                        # 配置、数据、模型、指标、函数抽取、通用工具
├── scripts/                    # 下载、构建、训练、推理、评估、扫描及 Web 后端
├── tests/                      # 抽取、级联、预测指标及 Web 接口测试
├── web/                        # 文件上传、扫描和报告展示前端
│   ├── src/                    # 页面、组件、数据接口和报告类型
│   └── public/                 # 三种扫描模式的示例报告
├── demo_verified/              # 唯一的测试夹具：test_NN.c + TRUTH.json（演示与回归）
├── docs/                       # 设计、流程、历史实验与排查记录
├── data/                       # 数据说明；raw/、processed/ 内容不纳入 Git
├── models/                     # 下载后生成的基础模型目录，不纳入 Git
├── outputs/                    # 实验记录、示例报告和本地模型产物
├── requirements.txt
└── LICENSE
```

---

## 快速开始

详细命令、全部参数、数据构建与训练流程都在 **[`docs/09_命令参考.md`](docs/09_命令参考.md)**。
这里只给两条最短路径。

### 路径一：只看现成的报告（不需要 Python、GPU 或模型权重）

```bash
cd web
npm install
npm run dev
```

打开终端显示的地址（默认 <http://localhost:5173>），点「示例报告」即可。也可以直接用地址打开：

| 地址 | 内容 |
| --- | --- |
| `?r=sample_report.json` | 检测 + CWE 分类 |
| `?r=sample_report_detection_only.json` | 仅检测（没有 CWE） |
| `?r=sample_report_extract_only.json` | 仅抽取函数（**没有任何判定**） |

### 路径二：在网页上传文件、真跑模型

```powershell
# 1. 环境（Python 3.12）
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install flask        # Web 后端需要，但不在 requirements.txt 里

# 2. 基础模型（models/ 不提交，新克隆的仓库没有）
python scripts/download_model.py --models codebert

# 3. 起后端（模型在后台加载，前十几秒 /api/health 返回 loading）
python scripts/serve.py
```

另开一个终端在 `web/` 下 `npm run dev`，然后点左栏「添加文件」→ 选受支持的源文件 →
等页眉显示模型就绪 → 点「开始检测」。

上传限制：一次最多 32 个文件、单文件不超过 2,000,000 字节，文件名只允许字母、数字、点、
下划线和连字符。服务只绑 `127.0.0.1`，不对外网开放。

> 只想确认"链路是通的"、不看效果？`python -m pytest tests/` 用桩推理器跑完整条链路，
> **不需要模型权重**，几秒钟出结果。

---

## 模型与已有实验

现有演示报告使用以下两个检查点：

| 用途 | 检查点 |
| --- | --- |
| 检测模型 | `outputs/merged_detection_codebert/best` |
| CWE 分类模型 | `outputs/merged_top27_codebert_e20/best` |

| 实验 | 测试集指标 | 记录位置 |
| --- | --- | --- |
| 合并数据检测 `merged_detection_codebert` | 阈值 0.5：Precision 0.3774、Recall 0.6779、F1 0.4848、ROC-AUC 0.8717 | [results.json](outputs/merged_detection_codebert/results.json) |
| 28 类分类 `merged_top27_codebert_e20` | Accuracy 0.3333、Macro-F1 0.2392、Top-3 0.6041、Top-5 0.7438；最优轮次 14 | [results.json](outputs/merged_top27_codebert_e20/results.json) |

演示检测模型的 [threshold.json](outputs/merged_detection_codebert/best/threshold.json) 记录的是
**0.67**，按验证集 F1 选择，该文件记录的是**验证集**指标。上表检测结果是 0.5 口径，
不能直接当作 0.67 下的测试成绩；分类指标来自分类测试集，也不等于整个两级扫描流程的准确率。

> ⚠️ 阈值的两种选法差别很大，`tune_threshold.py` 的**默认是 `--criterion recall`（目标 0.90）**，
> 会选出比 0.67 低得多的阈值。改完阈值务必重跑 `scripts/check_fixture.py`。
> 对比数据见 [`docs/09`](docs/09_命令参考.md) 第 5 节。

仓库还保留 CVEfixes 检测、BigVul 分类和不同训练轮数的对照记录，可在 `outputs/` 查看；
每个目录里有什么见 [`docs/05_训练产物说明.md`](docs/05_训练产物说明.md)。
Git **不包含**模型权重、完整分词器、原始数据及处理后的训练集。

### `demo_verified/` 是唯一的测试夹具

13 个 C 文件、30 个函数，`TRUTH.json` 记录每个函数的标签和 CWE。
它存在的意义是**演示与回归** —— 每个函数都保证在演示检查点下判得对（30/30 判定、23/23 CWE），
所以界面上看到的结果是预期内的，可以随时用 `python scripts/check_fixture.py` 复查。

> ⚠️ **它不能用来衡量模型效果。** 夹具是按"模型判对"筛出来的，带选择偏差；
> 而且里面一部分是**截断过的真实片段**，不是完整函数。
> 演示用的检测器在完整测试集上是 **F1 0.4848 / accuracy 0.8648 / ROC-AUC 0.8717**。
> 注意别和 `cvefixes_detection_codebert-base`（F1 0.7521）搞混 —— 那是另一个模型，
> 用的是单一 CVEfixes 数据源。要看当前检查点的真实水平请用 `scripts/evaluate.py`。

---

## 能力边界

### 支持抽取的扩展名

| 语言 | 扩展名 |
| --- | --- |
| C | `.c`、`.h`（`.h` 按 C 解析） |
| C++ | `.cc`、`.cpp`、`.cxx`、`.hpp`、`.hh`、`.hxx` |
| Python | `.py`、`.pyw`、`.pyi` |
| JavaScript / JSX | `.js`、`.mjs`、`.cjs`、`.jsx` |
| TypeScript / TSX | `.ts`、`.tsx` |
| PHP | `.php`、`.php3`、`.php5`、`.phtml` |

抽取器覆盖上述语法**不代表模型对各语言具有相同准确率**。当前不抽取 JavaScript 箭头函数、
Python lambda 等部分表达式形式；与语法错误区域重叠的函数会被丢弃并计数。

### 不做什么

模型按**代码片段**预测，不提供跨函数数据流分析、漏洞行精确定位或自动修复 ——
报告里的行号是**函数**的位置。扫描发现可疑函数不会让进程返回非零退出码；
单文件处理失败会记入报告继续扫描。要用在 CI 里，需要自己依据报告设置失败条件。

### 一个必须知道的实测结论

**这个检测器对短小的、手写的教科书式 C 代码基本不响应。**

实测四批自造探针（教科书式短函数 → 真实体量 → 内核/OpenSSL 风格 → 残缺风格）共 31 个函数，
概率**最高只到 54%，多数落在 10~36%**，远低于 0.67 的判定阈值；而它对自己训练分布内的
真实代码能给到 78~92%。连"不安全版 vs 安全版"的排序都常常是反的
（`copy_hostname` 14.4% < `copy_hostname_safe` 18.3%）。

原因是它微调自四源合并（CVEfixes / BigVul / DiverseVul / CodeXGLUE）的**真实 CVE 修复提交**，
短片段不在其训练分布内。**所以演示素材只能取自真实代码，"自己写几个有漏洞的例子"这条路走不通。**
详细分析见 [`docs/07_漏洞分类设计方案.md`](docs/07_漏洞分类设计方案.md) 第 6 节。

### 报告格式

JSON 报告的 `schema_version` 为 `1`，顶层字段：

| 字段 | 含义 |
| --- | --- |
| `schema_version`、`tool` | 报告版本（当前 `1`）、生成工具名 |
| `root`、`generated_at` | 扫描来源、报告生成时间 |
| `checkpoint`、`threshold` | 检测检查点与实际阈值；未检测时为 `null` |
| `classifier_checkpoint` | 分类检查点；未启用分类时为 `null` |
| `summary` | 文件数、函数数、可疑函数数、已分类函数数、各语言的函数数 |
| `files[]` | 文件相对路径、解析状态、函数数、可疑数及函数列表 |
| `skipped[]` | 因读取失败、二进制内容、超出大小限制等原因跳过的文件 |

函数字段**按扫描阶段出现**，未运行的阶段是**省略**而不是填 `null`：

- 抽取后：`name`、`start_line`、`end_line`、字节位置、`language`、`depth`、`node_type`、
  `parent_name`（嵌套函数的父函数名或 `null`；行号从 1 开始）
- `code` 默认包含，传 `--no-code` 时省略
- `verdict`、`confidence`、`prob_vulnerable`：仅在检测后出现
- `cwe`、`cwe_topk`：仅在函数被判为 vulnerable 且运行了分类器时出现

`confidence` 是当前判定类别的概率；**比较函数的漏洞风险应该用 `prob_vulnerable`**。
统计的是模型判为可疑的**函数数量**，同一个函数即使可能包含多处问题也只计一个。

完整契约（每一步的类型定义 + 字段出现条件表）见
[`docs/08_全流程与接口规范.md`](docs/08_全流程与接口规范.md)。

---

## 测试与文档

```bash
python -m pytest tests/ -v                  # 抽取 / 级联 / 预测指标 / Web 接口（桩推理器，不需要权重）
python docs/test_cases/test_preprocess.py   # 数据预处理断言
python scripts/check_fixture.py             # 复验 demo_verified/ 夹具是否仍全部判对
```

| 文档 | 内容 |
| --- | --- |
| [文档索引](docs/README.md) | 详细文档导航 |
| [命令参考](docs/09_命令参考.md) | **全部脚本的命令与参数** |
| [全链路贯通手册](docs/10_全链路贯通手册.md) | **从原始数据到网页点击的完整数据流**：每一步用了哪个文件的哪个函数、做了什么变换 |
| [数据集与模型全解析](docs/01_数据集与模型全解析.md) | 数据字段、预处理、模型设计与历史实验 |
| [模型运行完整流程与测试用例](docs/02_模型运行完整流程与测试用例.md) | 操作流程、测试用例与排错 |
| [项目交接与迁移指南](docs/03_项目交接与迁移指南.md) | 迁移文件与环境说明 |
| [数据集卡片](docs/04_数据集卡片.md) | 数据集来源、许可与引用 |
| [训练产物说明](docs/05_训练产物说明.md) | 检查点和输出文件说明 |
| [问题排查与改动记录](docs/06_问题排查与改动记录.md) | 历史问题与修改依据 |
| [漏洞分类设计方案](docs/07_漏洞分类设计方案.md) | 级联与 CWE 分类的设计背景 |
| [全流程与接口规范](docs/08_全流程与接口规范.md) | 数据流、报告字段和能力边界 |

部分详细文档和配置注释保留了旧版状态、本机路径及历史实验口径。
**当前支持范围与命令以本 README 和 [`docs/09`](docs/09_命令参考.md) 为准**，
具体实验的类别数、阈值与指标以对应 run 的产物为准。

---

项目代码采用 [MIT License](LICENSE)。外部数据集、预训练模型及真实项目样例的许可
需分别遵循其来源要求。
