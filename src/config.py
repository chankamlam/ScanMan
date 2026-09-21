"""配置加载模块。

把 YAML 配置文件读成嵌套字典，并用内置默认值补齐缺失字段。
这样带来两个好处：
    1. 配置文件可以只写"想改的项"，其余自动用默认值
    2. 就算不传配置文件（cfg = load_config()），也能拿到一份完整可用的配置

数据结构
--------
配置是一个三层嵌套字典::

    {
      "seed": 42,
      "model":     {"name": ..., "max_length": 512, ...},
      "task":      {"type": "detection", "num_labels": 2, ...},
      "data":      {"source": "cvefixes", "train_ratio": 0.8, ...},
      "training":  {"epochs": 3, "batch_size": 16, ...},
      "inference": {"checkpoint": None, "batch_size": 16},
    }

访问方式就是普通的字典取值：``cfg["model"]["max_length"]``。
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

from .utils import PROJECT_ROOT

# ---------------------------------------------------------------------------
# 默认配置
# ---------------------------------------------------------------------------
# 这些值就是项目的"出厂设置"。configs/config.yaml 里写的内容会覆盖它们，
# 命令行参数（--epochs 等）又会在 train.py 里覆盖配置文件的取值。
# 优先级：命令行参数 > config.yaml > DEFAULTS
DEFAULTS: dict[str, Any] = {
    # 全局随机种子，保证实验可复现
    "seed": 42,

    # ---------------- 预训练模型 ----------------
    "model": {
        # 支持 HuggingFace 上的模型名，也支持本地目录路径
        # 推荐：microsoft/codebert-base（代码领域 BERT）
        "name": "microsoft/codebert-base",
        # 一条样本最多切成多少个 token。CodeBERT 上限 512。
        # 显存不够时可以降到 256，精度损失通常很小。
        "max_length": 512,
        # token 级头尾截断时，头部保留的内容 token 比例。
        # 例如 max_length=512、head_ratio=0.6 时，510 个内容 token
        # 会保留为前 306 个和后 204 个。
        "head_ratio": 0.6,
        # Dropout 比例，防止过拟合
        "dropout": 0.1,
        # 池化方式：cls = 取 [CLS] 位置的向量；mean = 对所有 token 求平均
        "pooling": "cls",
    },

    # ---------------- 任务 ----------------
    "task": {
        # detection      = 二分类（0=安全代码，1=存在漏洞）
        # classification = 多分类（预测 CWE 漏洞类型）
        "type": "detection",
        # 类别数。detection 固定为 2；classification 会被 label_map.json 覆盖
        "num_labels": 2,
        # 分类任务：样本量少于该值的 CWE 会被合并成 OTHER，避免长尾过拟合
        "min_class_samples": 30,
        # 分类任务：最多保留多少个 CWE 类别（按样本量降序取）
        "top_k_classes": 40,
    },

    # ---------------- 数据 ----------------
    "data": {
        # 数据源标识，对应 scripts/build_dataset.py 里注册的构建器
        # 当前只支持 cvefixes
        "source": "cvefixes",
        # 训练 / 验证 / 测试 的划分比例（按 group_id 分组划分）
        "train_ratio": 0.8,
        "val_ratio": 0.1,
        "test_ratio": 0.1,
        # 是否按代码内容的 MD5 去重
        "dedup": True,
        # 长度过滤：短于该值的碎片直接丢弃
        "min_code_chars": 30,
        # 长度截断：超过该值的做头尾截断
        "max_code_chars": 20000,
        # 类别不平衡处理策略：
        #   none             不做处理
        #   weighted_loss    加权交叉熵（按类别频率倒数加权），推荐
        #   balanced_sampler 加权随机采样（让每个 batch 类别更均衡）
        "imbalance": "weighted_loss",
        # 训练 / 评估样本上限（None 表示不限制）
        # 调试时设成 2000 之类的小数字，几分钟就能跑完一轮
        "max_train_samples": None,
        "max_eval_samples": None,
        # 构建好的数据存放目录
        "cache_dir": "data/processed",
    },

    # ---------------- 训练 ----------------
    "training": {
        "output_dir": "outputs",
        "run_name": "run",
        # 训练轮数。3 轮通常就够；再多容易过拟合
        "epochs": 3,
        "batch_size": 16,
        # 评估时的批大小可以开大一点（不存梯度，显存占用小）
        "eval_batch_size": 32,
        # 编码器学习率。微调预训练模型要小，2e-5 是经典取值
        "learning_rate": 2.0e-5,
        # 分类头学习率。随机初始化的层需要更大步长才能跟上
        "head_learning_rate": 1.0e-4,
        "weight_decay": 0.01,
        # 学习率预热比例（前 10% 的步数从 0 线性升到目标学习率）
        "warmup_ratio": 0.1,
        # 梯度裁剪阈值，防止梯度爆炸
        "max_grad_norm": 1.0,
        # 混合精度：auto | fp16 | bf16 | no
        # auto 会在 GPU 上自动选 bf16（如果支持）否则 fp16，CPU 上退化为 no
        "precision": "auto",
        # 梯度累积步数。显存不够时设成 4，等效 batch = batch_size * 4
        "gradient_accumulation_steps": 1,
        # 早停：验证指标连续 N 轮不提升就停止训练
        "early_stopping_patience": 2,
        # 评估策略：epoch（每轮评估一次）
        "eval_strategy": "epoch",
        "eval_steps": 500,
        "save_total_limit": 2,
        # 每多少步打印一次训练日志
        "log_steps": 50,
        # DataLoader 进程数。Windows 下建议 0，避免多进程启动报错
        "num_workers": 0,
        # 训练结束后是否自动在测试集上评估
        "run_test_after_train": True,
    },

    # ---------------- 推理 ----------------
    "inference": {
        # 留空则使用 outputs/<run_name>/best
        "checkpoint": None,
        "batch_size": 16,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """递归合并两个字典，``override`` 中的值优先。

    与 ``dict.update()`` 的区别
    ---------------------------
    ``update()`` 是浅合并：``{"a": {"x": 1}}`` 更新到 ``{"a": {"y": 2}}``
    会直接把整个 ``a`` 替换掉，``y`` 就丢了。
    本函数会递归进去，最终得到 ``{"a": {"x": 1, "y": 2}}``。

    参数
    ----
    base : dict
        基础字典（默认值）。
    override : dict
        覆盖字典（用户配置）。

    返回
    ----
    dict
        合并后的新字典（不会修改传入的两个字典）。
    """
    out = copy.deepcopy(base)  # 深拷贝，避免污染 DEFAULTS
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            # 两边都是字典 → 继续往里递归
            out[k] = _deep_merge(out[k], v)
        else:
            # 其他情况直接覆盖
            out[k] = v
    return out


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """加载 YAML 配置，缺失字段用 DEFAULTS 补齐。

    参数
    ----
    path : str | Path | None
        配置文件路径。可以是相对路径（相对于项目根目录），
        也可以传 None 表示只用默认配置。

    返回
    ----
    dict
        合并后的完整配置字典。

    异常
    ----
    FileNotFoundError
        指定的配置文件不存在。

    示例
    ----
    >>> cfg = load_config("configs/config.yaml")
    >>> cfg["model"]["max_length"]
    512
    """
    cfg = copy.deepcopy(DEFAULTS)
    if path is not None:
        p = Path(path)
        # 相对路径统一按"项目根目录"解析，这样在任何 cwd 下都能找到文件
        if not p.is_absolute():
            p = PROJECT_ROOT / p
        if not p.exists():
            raise FileNotFoundError(f"配置文件不存在: {p}")
        with open(p, "r", encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
        cfg = _deep_merge(cfg, user_cfg)
    return cfg


def resolve_path(path_like: str | Path) -> Path:
    """把配置里的相对路径解析成基于项目根目录的绝对路径。

    参数
    ----
    path_like : str | Path
        可能是相对路径（如 ``"data/raw"``）或绝对路径。

    返回
    ----
    Path
        绝对路径。

    为什么需要它
    ------------
    配置文件里写 ``data/raw`` 这样的相对路径更好看、更好迁移，
    但脚本可能从任意目录启动，直接用相对路径会找不到文件。
    统一经过这个函数转成绝对路径就稳了。
    """
    p = Path(path_like)
    return p if p.is_absolute() else (PROJECT_ROOT / p)


def dump_config(cfg: dict[str, Any], path: str | Path) -> None:
    """把当前生效的配置写盘，方便日后复现实验。

    参数
    ----
    cfg : dict
        配置字典。
    path : str | Path
        输出路径（通常是 ``outputs/<run_name>/config.yaml``）。

    说明
    ----
    训练时命令行参数会覆盖配置文件，所以磁盘上那份 config.yaml 未必等于
    实际生效的配置。把合并后的结果另存一份，才能准确还原实验。
    ``sort_keys=False`` 保持字段原始顺序，人读起来更顺。
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
