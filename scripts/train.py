"""微调 BERT 做代码漏洞检测 / 漏洞分类（训练主脚本）。

本脚本负责整条训练流水线：

    读取配置 → 加载数据 → 建模型 → 建优化器 → 逐轮训练 → 每轮评估
        → 保存最优模型 → 早停判断 → 训练结束在测试集上做最终评估

设计要点
--------
1. **手写训练循环**（不用 transformers 的 Trainer）
   虽然 Trainer 更省事，但手写循环能看清每一步在做什么，
   也方便加分层学习率、梯度累积、加权损失这些定制逻辑。

2. **分层学习率**
   编码器 2e-5，分类头 1e-4。随机初始化的分类头需要更大步长。

3. **混合精度（AMP）**
   GPU 上自动用 bf16（Ampere 及以上）或 fp16，显存占用减半、速度提升约 30%。
   用 GradScaler 防止 fp16 下梯度下溢。

4. **梯度累积**
   batch_size=16 显存不够时，可以设 batch_size=4 + gradient_accumulation_steps=4，
   等效 batch 仍是 16，但显存占用只有 1/4。

5. **早停**
   验证指标连续 patience 轮不提升就停，避免过拟合和无谓计算。

用法
----
    # 用配置文件（推荐）
    python scripts/train.py --config configs/config.yaml

    # 命令行覆盖常用参数
    python scripts/train.py --task classification --source cvefixes --model microsoft/codebert-base

    # 快速冒烟测试（CPU 也能在几分钟内跑完）
    python scripts/train.py --epochs 1 --max-train-samples 2000 --batch-size 8

    # 换模型做对比实验（数据源固定为 cvefixes）
    python scripts/train.py --model microsoft/graphcodebert-base --run-name gcb
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader, WeightedRandomSampler
from transformers import get_linear_schedule_with_warmup

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import dump_config, load_config, resolve_path  # noqa: E402
from src.data import DynamicPaddingCollator, VulnDataset, load_jsonl_records  # noqa: E402
from src.metrics import (  # noqa: E402
    compute_binary_metrics,
    compute_multiclass_metrics,
    format_metrics,
    per_class_report,
    softmax,
)
from src.models import (  # noqa: E402
    VulnClassifier,
    build_tokenizer,
    count_parameters,
    get_parameter_groups,
)
from src.utils import ensure_dir, get_logger, human_int, set_seed  # noqa: E402

log = get_logger("train")


# ---------------------------------------------------------------- 辅助


def pick_device() -> torch.device:
    """自动选择运算设备。

    返回
    ----
    torch.device
        优先级：CUDA（NVIDIA 显卡）> MPS（Apple Silicon）> CPU。

    说明
    ----
    ``getattr(torch.backends, "mps", None)`` 是因为旧版 PyTorch 没有 mps 后端，
    直接访问会 AttributeError，用 getattr 兜底更稳。
    """
    if torch.cuda.is_available():
        return torch.device("cuda")
    if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def resolve_precision(precision: str, device: torch.device) -> str:
    """把配置里的 auto 解析成具体精度。

    参数
    ----
    precision : str
        ``auto`` / ``fp16`` / ``bf16`` / ``no``。
    device : torch.device
        当前设备。

    返回
    ----
    str
        实际使用的精度。

    规则
    ----
    - CPU / MPS：强制 ``no``（这些设备不支持 CUDA AMP）
    - 配置写了具体值：直接用
    - 配置是 auto：能上 bf16 就上 bf16，否则用 fp16

    为什么优先 bf16
    ---------------
    bf16 的指数位和 fp32 一样宽（8 位），动态范围大，
    **不需要 GradScaler 做梯度缩放**就不会下溢，训练更稳定。
    但它需要 Ampere 架构（sm_80）及以上，比如 A100 / RTX 30 系 / RTX 40 系。
    """
    if device.type != "cuda":
        return "no"
    if precision != "auto":
        return precision
    if torch.cuda.is_bf16_supported():
        return "bf16"
    return "fp16"


def autocast_context(precision: str):
    """返回一个自动混合精度的上下文管理器。

    参数
    ----
    precision : str
        精度模式。

    返回
    ----
    contextmanager
        在 ``with`` 块内，矩阵乘法等运算会自动用半精度执行，
        其余部分（如 LayerNorm、softmax）仍保持 fp32 以保证数值稳定。

    说明
    ----
    不启用混合精度时返回 ``contextlib.nullcontext()``（什么都不做的空上下文），
    这样调用处就不需要写 if/else，代码更干净。
    """
    if precision == "fp16":
        return torch.autocast(device_type="cuda", dtype=torch.float16)
    if precision == "bf16":
        return torch.autocast(device_type="cuda", dtype=torch.bfloat16)
    import contextlib

    return contextlib.nullcontext()


def build_optimizer_scheduler(model, cfg, num_training_steps: int):
    """构造优化器和学习率调度器。

    参数
    ----
    model : VulnClassifier
        待训练模型。
    cfg : dict
        完整配置。
    num_training_steps : int
        总训练步数（用于算预热步数和学习率衰减曲线）。

    返回
    ----
    tuple[AdamW, LambdaLR]
        ``(优化器, 调度器)``。

    学习率调度说明
    --------------
    ``get_linear_schedule_with_warmup`` 产生的学习率曲线是"先升后降"：

        lr
         │      ╱‾‾‾‾‾╲
         │    ╱         ╲
         │  ╱             ╲___
         └────────────────────→ step
          ↑预热↑   ↑  线性衰减  ↑

    **预热**（前 warmup_ratio 比例的步数）：学习率从 0 线性升到目标值。
    预训练模型的权重已经很好了，一上来就用大学习率会把它们"冲坏"，
    所以要先小步走一段，让新增的分类头先适应。

    **衰减**：之后线性降到 0，让训练后期收敛得更稳。
    """
    tcfg = cfg["training"]
    # 分层学习率的参数组
    groups = get_parameter_groups(
        model,
        base_lr=tcfg["learning_rate"],
        head_lr=tcfg["head_learning_rate"],
        weight_decay=tcfg["weight_decay"],
    )
    # betas 是 Adam 的一阶/二阶动量衰减率，0.9/0.999 是 BERT 微调的标配
    optimizer = torch.optim.AdamW(groups, betas=(0.9, 0.999), eps=1e-8)
    warmup_steps = int(num_training_steps * tcfg["warmup_ratio"])
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=warmup_steps, num_training_steps=num_training_steps
    )
    return optimizer, scheduler


def make_class_weights(records: list[dict], num_labels: int, device: torch.device):
    """按类别频率的倒数计算交叉熵权重，用于缓解类别不平衡。

    参数
    ----
    records : list[dict]
        训练集记录，每条要有 ``label`` 字段。
    num_labels : int
        类别总数。
    device : torch.device
        权重张量放到哪个设备。

    返回
    ----
    torch.Tensor
        形状 ``(num_labels,)`` 的权重张量。

    计算方式
    --------
    ``weight[i] = 总样本数 / (类别数 × 第i类的样本数)``

    举例：两类数据，安全 16000 条、漏洞 4000 条
        安全类权重 = 20000 / (2 × 16000) = 0.625
        漏洞类权重 = 20000 / (2 × 4000)  = 2.5
    也就是说，把漏洞样本的损失放大 4 倍，逼模型认真学少数类。

    边界处理
    --------
    ``counts[counts == 0] = 1.0`` 防止某个类别样本数为 0 时除零。
    """
    counts = np.bincount([int(r["label"]) for r in records], minlength=num_labels).astype(float)
    counts[counts == 0] = 1.0
    weights = counts.sum() / (num_labels * counts)
    log.info("类别权重: %s", np.round(weights, 3).tolist())
    return torch.tensor(weights, dtype=torch.float32, device=device)


# ---------------------------------------------------------------- 训练 / 评估


def train_one_epoch(model, loader, optimizer, scheduler, cfg, device, precision, epoch,
                    criterion=None):
    """训练一个 epoch（把训练集完整过一遍）。

    参数
    ----
    model : VulnClassifier
        模型。
    loader : DataLoader
        训练集数据加载器。
    optimizer : torch.optim.Optimizer
        优化器。
    scheduler
        学习率调度器。
    cfg : dict
        配置。
    device : torch.device
        设备。
    precision : str
        混合精度模式。
    epoch : int
        当前轮次（仅用于日志）。
    criterion : nn.Module | None
        损失函数。为 None 时用模型自带的 CrossEntropyLoss。

    返回
    ----
    float
        本轮的平均损失。

    训练五步曲（每个 batch 都做一遍）
    --------------------------------
        1. 前向传播  logits = model(inputs)
        2. 计算损失  loss = criterion(logits, labels)
        3. 梯度清零  optimizer.zero_grad()
        4. 反向传播  loss.backward()
        5. 参数更新  optimizer.step()

    梯度累积的处理
    --------------
    ``loss = loss / accum``：把损失缩小 accum 倍再反传，
    这样累积 accum 个 batch 的梯度后，等效于一次大 batch 的更新。
    参数更新只在 ``step % accum == 0`` 时执行。
    """
    model.train()  # 开启 Dropout 和 BatchNorm 的训练行为
    tcfg = cfg["training"]
    accum = max(1, int(tcfg["gradient_accumulation_steps"]))
    total = len(loader)
    running_loss, seen = 0.0, 0  # 累计损失、累计处理过的样本数
    t0 = time.time()
    # set_to_none=True 比置零更省内存（直接把梯度张量设为 None）
    optimizer.zero_grad(set_to_none=True)

    for step, batch in enumerate(loader, start=1):
        # meta 是元信息字典，不是张量，不能送进模型
        batch.pop("meta", None)
        labels = batch.pop("labels").to(device)
        inputs = {k: v.to(device) for k, v in batch.items()}

        with autocast_context(precision):
            out = model(**inputs)
            logits = out["logits"]
            if criterion is not None:
                loss = criterion(logits.view(-1, model.num_labels), labels.view(-1))
            else:
                loss = out["loss"]

        # ---- 损失缩放：为梯度累积做准备 ----
        # 反传前先把损失缩小 accum 倍，累积 accum 个 batch 后梯度刚好等于
        # 一次大 batch 的梯度。不缩放的话梯度会放大 accum 倍，相当于学习率也放大了。
        loss = loss / accum
        loss.backward()  # 反向传播：自动求导算出每个参数的梯度

        # ---- 累积够了就更新一次参数 ----
        if step % accum == 0 or step == total:
            # 梯度裁剪：把所有梯度的整体范数限制在 max_grad_norm 以内。
            # 不加的话，偶尔出现的超大梯度会把参数"踢飞"，导致 loss 变成 NaN。
            torch.nn.utils.clip_grad_norm_(model.parameters(), tcfg["max_grad_norm"])
            optimizer.step()          # 参数更新：新参数 = 旧参数 - 学习率 × 梯度
            scheduler.step()          # 学习率调度器前进一步
            optimizer.zero_grad(set_to_none=True)  # 清空梯度，准备下一轮累积

        # 统计损失：乘回 accum 还原成真实损失，乘 batch 大小方便加权平均
        running_loss += loss.item() * accum * labels.size(0)
        seen += labels.size(0)

        # ---- 定期打印日志 ----
        if step % tcfg["log_steps"] == 0 or step == total:
            elapsed = time.time() - t0
            log.info(
                "epoch %d | step %d/%d | loss %.4f | lr %.2e | %.1f samples/s",
                epoch, step, total, running_loss / max(seen, 1),
                scheduler.get_last_lr()[0],   # 当前学习率，看预热/衰减是否符合预期
                seen / max(elapsed, 1e-6),    # 吞吐量，用于估算剩余时间
            )
    return running_loss / max(seen, 1)


@torch.no_grad()  # 装饰器：整个函数内不记录梯度，省显存也更快
def evaluate(model, loader, cfg, device, precision, task: str, num_labels: int):
    """在给定数据集上评估模型。

    参数
    ----
    model : VulnClassifier
        待评估模型。
    loader : DataLoader
        验证集或测试集。
    cfg : dict
        配置。
    device : torch.device
        设备。
    precision : str
        混合精度模式。
    task : str
        ``detection`` 或 ``classification``，决定用哪套指标。
    num_labels : int
        类别数。

    返回
    ----
    tuple
        ``(指标字典, 主指标值, 真实标签数组, logits 数组)``。
        返回后两个是为了让调用方可以画图或做错误分析。

    关键细节
    --------
    - ``model.eval()``：关闭 Dropout，让结果稳定可复现
    - ``@torch.no_grad()``：不构建计算图，显存占用大幅下降
    - ``.float()``：混合精度下 logits 可能是 fp16，转回 fp32 再算指标，
      避免精度损失影响 AUC 这类对数值敏感的计算
    """
    model.eval()  # 切到评估模式
    all_logits, all_labels = [], []
    for batch in loader:
        batch.pop("meta", None)
        labels = batch.pop("labels")
        inputs = {k: v.to(device) for k, v in batch.items()}
        with autocast_context(precision):
            out = model(**inputs)
        # 累积到 CPU 上（放 GPU 上累积会爆显存）
        all_logits.append(out["logits"].float().cpu().numpy())
        all_labels.append(labels.numpy())

    # 把所有 batch 的结果拼成一个完整数组
    logits = np.concatenate(all_logits, axis=0)
    y_true = np.concatenate(all_labels, axis=0)

    # ---- 按任务类型选指标 ----
    if task == "detection":
        metrics = compute_binary_metrics(y_true, logits)
        main = metrics["f1"]            # 二分类主指标用 F1
    else:
        metrics = compute_multiclass_metrics(y_true, logits)
        main = metrics["macro_f1"]      # 多分类主指标用宏 F1（类别等权）
    return metrics, main, y_true, logits


# ---------------------------------------------------------------- 主流程


def main() -> None:
    """训练主流程。

    执行顺序：
        1. 解析命令行参数
        2. 加载配置，命令行参数覆盖配置
        3. 固定随机种子、选择设备、确定精度
        4. 加载 train/val/test 数据和标签映射
        5. 建 tokenizer、模型、DataLoader、损失函数、优化器
        6. 逐轮训练 + 每轮验证，保存验证集最优的模型
        7. 早停判断
        8. 加载最优模型，在测试集上做最终评估并保存结果
    """
    # ---- 命令行参数 ----
    # 所有参数默认值都是 None，只有用户显式传了才会覆盖配置，
    # 这样就实现了"命令行 > 配置文件 > 内置默认值"的优先级
    parser = argparse.ArgumentParser(description="微调 BERT 做漏洞检测/分类")
    parser.add_argument("--config", default="configs/config.yaml")
    parser.add_argument("--task", choices=["detection", "classification"], default=None)
    parser.add_argument("--source", default=None)
    parser.add_argument("--model", default=None, help="覆盖预训练模型名或本地路径")
    parser.add_argument("--run-name", default=None)
    parser.add_argument("--epochs", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("--lr", type=float, default=None)
    parser.add_argument("--max-length", type=int, default=None)
    parser.add_argument("--max-train-samples", type=int, default=None)
    parser.add_argument("--max-eval-samples", type=int, default=None)
    parser.add_argument("--log-steps", type=int, default=None)
    parser.add_argument("--eval-steps", type=int, default=None)
    parser.add_argument("--num-workers", type=int, default=None)
    parser.add_argument("--output-dir", default=None, help="输出根目录，默认 outputs")
    parser.add_argument("--imbalance", choices=["none", "weighted_loss", "balanced_sampler"],
                        default=None)
    parser.add_argument("--cpu", action="store_true", help="强制使用 CPU")
    args = parser.parse_args()

    cfg = load_config(args.config)

    # ---- 命令行覆盖配置文件 ----
    if args.task:
        cfg["task"]["type"] = args.task
    if args.source:
        cfg["data"]["source"] = args.source
    if args.model:
        cfg["model"]["name"] = args.model
    if args.epochs is not None:
        cfg["training"]["epochs"] = args.epochs
    if args.batch_size is not None:
        cfg["training"]["batch_size"] = args.batch_size
    if args.lr is not None:
        cfg["training"]["learning_rate"] = args.lr
    if args.max_length is not None:
        cfg["model"]["max_length"] = args.max_length
    if args.max_train_samples is not None:
        cfg["data"]["max_train_samples"] = args.max_train_samples
    if args.max_eval_samples is not None:
        cfg["data"]["max_eval_samples"] = args.max_eval_samples
    if args.log_steps is not None:
        cfg["training"]["log_steps"] = args.log_steps
    if args.eval_steps is not None:
        cfg["training"]["eval_steps"] = args.eval_steps
    if args.num_workers is not None:
        cfg["training"]["num_workers"] = args.num_workers
    if args.output_dir:
        cfg["training"]["output_dir"] = args.output_dir
    if args.imbalance:
        cfg["data"]["imbalance"] = args.imbalance

    task = cfg["task"]["type"]
    source = cfg["data"]["source"]
    if args.run_name:
        cfg["training"]["run_name"] = args.run_name
    else:
        cfg["training"]["run_name"] = f"{source}_{task}_{cfg['model']['name'].split('/')[-1]}"

    set_seed(cfg["seed"])
    device = torch.device("cpu") if args.cpu else pick_device()
    precision = resolve_precision(cfg["training"]["precision"], device)

    log.info("=" * 78)
    log.info("任务=%s | 数据源=%s | 模型=%s", task, source, cfg["model"]["name"])
    log.info("设备=%s | 精度=%s | 随机种子=%d", device, precision, cfg["seed"])
    log.info("=" * 78)

    # ---- 数据 ----
    data_dir = resolve_path(cfg["data"]["cache_dir"])
    paths = {s: data_dir / f"{source}_{task}_{s}.jsonl" for s in ("train", "val", "test")}
    for p in paths.values():
        if not p.exists():
            raise SystemExit(
                f"缺少数据文件 {p}\n请先运行: python scripts/build_dataset.py --source {source}"
            )

    # ---- 读取标签映射 ----
    # label_map.json 是 build_dataset.py 生成的，记录"类别数"和"编号 -> CWE名称"
    # 有它就以它为准；没有就用兜底值（检测任务固定 2 类）
    label_map_path = data_dir / f"{source}_{task}_label_map.json"
    if label_map_path.exists():
        lm = json.loads(label_map_path.read_text(encoding="utf-8"))
        num_labels = int(lm["num_labels"])
        # JSON 的键都是字符串，转成 int 方便后面按下标取名称
        id2name = {int(k): v for k, v in lm["id2name"].items()}
    else:
        num_labels = 2 if task == "detection" else int(cfg["task"]["num_labels"])
        id2name = {0: "safe", 1: "vulnerable"} if task == "detection" else {}

    # ---- 加载三个数据集 ----
    train_records = load_jsonl_records(paths["train"])
    val_records = load_jsonl_records(paths["val"])
    test_records = load_jsonl_records(paths["test"])

    # 训练/评估样本上限（用于快速调试；配置里默认 null 表示不限制）
    # 用固定种子采样，保证每次调试拿到的子集一样，结果可比
    def _cap(records: list[dict], limit) -> list[dict]:
        if limit is None or len(records) <= int(limit):
            return records
        import random

        log.info("按配置截断样本：%s -> %s", human_int(len(records)), human_int(int(limit)))
        return random.Random(cfg["seed"]).sample(records, int(limit))

    train_records = _cap(train_records, cfg["data"]["max_train_samples"])
    val_records = _cap(val_records, cfg["data"]["max_eval_samples"])
    test_records = _cap(test_records, cfg["data"]["max_eval_samples"])

    # ---- 安全网：以数据中实际出现的最大标签为准 ----
    # 万一标签映射文件和数据对不上（比如改了数据没重新生成映射），
    # 直接用 max_label + 1 当类别数，避免 CrossEntropyLoss 报
    # "weight tensor should be defined either for all N classes" 这类错误。
    observed = max(
        (int(r["label"]) for r in train_records + val_records + test_records),
        default=0,
    ) + 1
    if observed > num_labels:
        log.warning("标签映射声明 %d 类，但数据中实际出现 %d 类，按数据修正", num_labels, observed)
        num_labels = observed

    log.info("样本数  train=%s  val=%s  test=%s  类别数=%d",
             human_int(len(train_records)), human_int(len(val_records)),
             human_int(len(test_records)), num_labels)

    # ---- 建 tokenizer 和模型 ----
    tokenizer = build_tokenizer(cfg["model"]["name"])
    model = VulnClassifier(
        cfg["model"]["name"],
        num_labels=num_labels,
        dropout=cfg["model"]["dropout"],
        pooling=cfg["model"]["pooling"],
    ).to(device)  # 直接搬到目标设备
    total_p, train_p = count_parameters(model)
    log.info("模型参数量: 总计 %.1fM，可训练 %.1fM", total_p / 1e6, train_p / 1e6)

    # ---- 建 Dataset 和批处理器 ----
    collator = DynamicPaddingCollator(tokenizer)
    ds_kwargs = dict(
        tokenizer=tokenizer,
        max_length=cfg["model"]["max_length"],
        max_code_chars=cfg["model"]["max_code_chars"],
    )
    train_ds = VulnDataset(train_records, **ds_kwargs)
    val_ds = VulnDataset(val_records, **ds_kwargs)
    test_ds = VulnDataset(test_records, **ds_kwargs)

    nw = int(cfg["training"]["num_workers"])
    # pin_memory=True 把数据放进"锁页内存"，GPU 拷贝更快（只在 CUDA 上有效）
    pin = device.type == "cuda"

    # ---- 可选：平衡采样器 ----
    # 与加权损失的区别：
    #   加权损失  每条样本都参与训练，只是少数类的损失被放大
    #   平衡采样  少数类样本被更频繁地抽到，让每个 batch 类别更均衡
    # 两者选一个即可，同时用会过度补偿。
    sampler = None
    if cfg["data"]["imbalance"] == "balanced_sampler" and task == "detection":
        labels_arr = np.array([int(r["label"]) for r in train_records])
        counts = np.bincount(labels_arr, minlength=num_labels).astype(float)
        counts[counts == 0] = 1.0
        # 每条样本的采样权重 = 它所属类别的频率倒数
        weights = 1.0 / counts[labels_arr]
        sampler = WeightedRandomSampler(
            torch.as_tensor(weights, dtype=torch.double), len(weights), replacement=True
        )
        log.info("启用 WeightedRandomSampler 平衡采样")

    # ---- 建 DataLoader ----
    # 注意 shuffle 和 sampler 不能同时用：用了 sampler 就由它决定顺序
    train_loader = DataLoader(
        train_ds,
        batch_size=cfg["training"]["batch_size"],
        shuffle=sampler is None,
        sampler=sampler,
        collate_fn=collator,
        num_workers=nw,
        pin_memory=pin,
    )
    val_loader = DataLoader(
        val_ds, batch_size=cfg["training"]["eval_batch_size"], shuffle=False,
        collate_fn=collator, num_workers=nw, pin_memory=pin,
    )
    test_loader = DataLoader(
        test_ds, batch_size=cfg["training"]["eval_batch_size"], shuffle=False,
        collate_fn=collator, num_workers=nw, pin_memory=pin,
    )

    # ---- 损失函数 ----
    # CrossEntropyLoss 内部 = log_softmax + NLLLoss，所以模型输出必须是原始 logits
    criterion = None
    if cfg["data"]["imbalance"] == "weighted_loss":
        criterion = torch.nn.CrossEntropyLoss(
            weight=make_class_weights(train_records, num_labels, device)
        )
        log.info("启用加权交叉熵损失")
    else:
        criterion = torch.nn.CrossEntropyLoss()

    # ---- 优化器 + 学习率调度器 ----
    # total_steps 用于算预热步数和衰减曲线，必须和实际更新次数一致，
    # 所以这里要除以梯度累积步数（累积时每 accum 个 batch 才更新一次）
    accum = max(1, int(cfg["training"]["gradient_accumulation_steps"]))
    steps_per_epoch = math.ceil(len(train_loader) / accum)
    total_steps = steps_per_epoch * int(cfg["training"]["epochs"])
    optimizer, scheduler = build_optimizer_scheduler(model, cfg, total_steps)
    log.info("优化步数: 每 epoch %d 步，共 %d 步（梯度累积 %d）", steps_per_epoch, total_steps, accum)

    # ---- 输出目录 ----
    # 每次实验一个子目录：outputs/<run_name>/
    # 里面放 config.yaml（复现用）、best/（最优权重）、results.json（指标）
    run_dir = ensure_dir(resolve_path(cfg["training"]["output_dir"]) / cfg["training"]["run_name"])
    best_dir = ensure_dir(run_dir / "best")
    dump_config(cfg, run_dir / "config.yaml")

    # ---- 训练循环 ----
    # best_score  目前最好的验证指标（-1 保证第一轮一定刷新）
    # best_epoch  最好成绩出现在第几轮
    # patience    连续多少轮没提升，用于早停
    best_score, best_epoch, patience = -1.0, -1, 0
    history: list[dict] = []   # 记录每轮指标，最后写进 results.json
    patience_limit = int(cfg["training"]["early_stopping_patience"])

    for epoch in range(1, int(cfg["training"]["epochs"]) + 1):
        log.info("-" * 78)

        # 1) 训练一轮
        train_loss = train_one_epoch(
            model, train_loader, optimizer, scheduler, cfg, device, precision, epoch, criterion
        )

        # 2) 在验证集上评估
        val_metrics, val_score, _, _ = evaluate(
            model, val_loader, cfg, device, precision, task, num_labels
        )
        log.info("epoch %d 完成 | train_loss=%.4f | val: %s", epoch, train_loss,
                 format_metrics(val_metrics))
        history.append({"epoch": epoch, "train_loss": train_loss, "val": val_metrics})

        # 3) 指标变好就保存
        # 注意：判断依据是"验证集"而不是"训练集"。
        # 训练集指标一定越来越好，用它会保存到过拟合的模型。
        if val_score > best_score:
            best_score, best_epoch, patience = val_score, epoch, 0
            # 只保存参数（state_dict），不保存整个模型对象。
            # 前者约 500MB，后者会连带 pickle 一堆类定义，更大且不利于迁移。
            torch.save(model.state_dict(), best_dir / "pytorch_model.bin")
            # 分词器也要一起保存，推理时才能保证切词方式完全一致
            tokenizer.save_pretrained(best_dir)
            # 标签映射也存一份，推理时才能把编号翻译回 CWE 名称
            with open(best_dir / "label_map.json", "w", encoding="utf-8") as f:
                json.dump({"task": task, "num_labels": num_labels,
                           "id2name": {str(k): v for k, v in id2name.items()}},
                          f, ensure_ascii=False, indent=2)
            log.info("✅ 新的最佳模型已保存（%s=%.4f）-> %s",
                     "f1" if task == "detection" else "macro_f1", best_score, best_dir)
        else:
            # 4) 没提升就累计 patience，到上限就早停
            patience += 1
            log.info("验证指标未提升（%d/%d）", patience, patience_limit)
            if patience >= patience_limit:
                log.info("触发早停，停止训练")
                break

    # ---- 用测试集做最终评估 ----
    # 关键：先加载"验证集最优"的权重，而不是用最后一轮的权重。
    # 最后一轮可能已经过拟合，验证集最优的那个才是泛化最好的。
    log.info("=" * 78)
    log.info("加载最佳模型（epoch %d, %s=%.4f）",
             best_epoch, "f1" if task == "detection" else "macro_f1", best_score)
    model.load_state_dict(torch.load(best_dir / "pytorch_model.bin", map_location=device))
    model.to(device)

    results = {"task": task, "source": source, "model": cfg["model"]["name"],
               "best_epoch": best_epoch, "history": history}
    for split_name, loader in (("val", val_loader), ("test", test_loader)):
        metrics, score, y_true, logits = evaluate(
            model, loader, cfg, device, precision, task, num_labels
        )
        log.info("[%s] %s", split_name.upper(), format_metrics(metrics))
        results[split_name] = metrics

        # 分类任务额外输出逐类别明细（找出哪些 CWE 完全学不会）
        if task == "classification" and id2name:
            names = [id2name.get(i, str(i)) for i in range(num_labels)]
            report = per_class_report(y_true, logits, names)
            (run_dir / f"report_{split_name}.txt").write_text(report, encoding="utf-8")
            # 保存原始 logits 和标签，方便事后画 ROC / PR 曲线或做错误分析
            np.save(run_dir / f"logits_{split_name}.npy", logits)
            np.save(run_dir / f"labels_{split_name}.npy", y_true)
            if split_name == "test":
                log.info("测试集分类报告：\n%s", report)
        elif task == "detection":
            np.save(run_dir / f"logits_{split_name}.npy", logits)
            np.save(run_dir / f"labels_{split_name}.npy", y_true)
            # 单独存一份"有漏洞"的概率，画 PR 曲线时直接能用
            probs = softmax(logits)[:, 1]
            np.save(run_dir / f"probs_{split_name}.npy", probs)

    # ---- 汇总结果落盘 ----
    with open(run_dir / "results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    log.info("训练完成 ✅ 结果已保存 -> %s", run_dir / "results.json")


if __name__ == "__main__":
    main()
