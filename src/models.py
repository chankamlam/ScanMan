"""模型定义：BERT 编码器 + 线性分类头。

本模块只做一件事——把预训练好的代码模型改造成一个分类器。

整体结构::

    input_ids (B, L)
        ↓
    ┌─────────────────────┐
    │  预训练编码器        │   ← CodeBERT / GraphCodeBERT / BERT
    │  (124M 参数)         │      这部分权重是"预训练好的"，微调时会一起更新
    └─────────────────────┘
        ↓ last_hidden_state (B, L, 768)
    ┌─────────────────────┐
    │  池化 Pooling        │   ← 取 [CLS] 向量，或对所有 token 求平均
    └─────────────────────┘
        ↓ (B, 768)
    ┌─────────────────────┐
    │  Dropout            │   ← 训练时随机丢弃 10% 神经元，防止过拟合
    └─────────────────────┘
        ↓
    ┌─────────────────────┐
    │  Linear(768, K)     │   ← 随机初始化，K = 类别数
    └─────────────────────┘
        ↓
    logits (B, K)          ← 未归一化的分数，交给 CrossEntropyLoss

为什么这样设计？
----------------
预训练编码器已经"读懂"了代码语法和语义，我们只需要在它后面接一个很小的
分类头，用漏洞数据微调。这就是迁移学习——用少量标注数据获得远超
从零训练的效果。编码器 124M 参数 + 分类头不到 1K 参数。
"""

from __future__ import annotations

import torch
import torch.nn as nn
from transformers import AutoConfig, AutoModel, AutoTokenizer


class VulnClassifier(nn.Module):
    """在预训练编码器之上接一个线性分类头。

    参数
    ----
    model_name_or_path : str
        HuggingFace 模型名（如 ``microsoft/codebert-base``）或本地目录路径。
    num_labels : int
        类别数。检测任务 = 2，分类任务 = CWE 类别数（含 OTHER）。
    dropout : float
        Dropout 比例，默认 0.1。
    pooling : str
        ``"cls"`` 取 [CLS] 位置向量；``"mean"`` 对所有 token 求平均。
        [CLS] 是 BERT 专门为句子级任务训练的位置，通常效果更好。
    """

    def __init__(
        self,
        model_name_or_path: str,
        num_labels: int = 2,
        dropout: float = 0.1,
        pooling: str = "cls",
    ) -> None:
        super().__init__()
        self.num_labels = num_labels
        self.pooling = pooling

        # ---- 1. 读取模型配置 ----
        hf_config = AutoConfig.from_pretrained(model_name_or_path)

        # ---- 2. 加载预训练编码器（不含任何任务头） ----
        # 用 AutoModel 而不是 AutoModelForSequenceClassification，原因：
        #   a) 我们想自己控制分类头的结构（Dropout 位置、池化方式）
        #   b) AutoModel 更通用，CodeBERT / GraphCodeBERT / UniXcoder 都能加载
        self.encoder = AutoModel.from_pretrained(model_name_or_path, config=hf_config)

        # ---- 3. 取出隐藏层维度 ----
        # 绝大多数 BERT 系模型是 768，用 getattr 兜底避免个别模型字段名不同
        hidden = getattr(hf_config, "hidden_size", None) or getattr(
            hf_config, "d_model", 768
        )
        self.hidden_size = hidden

        # ---- 4. 判断模型是否接受 token_type_ids ----
        # RoBERTa 系（CodeBERT / UniXcoder）没有"句子A/句子B"的概念，
        # 不接受 token_type_ids 参数。如果硬传进去会报 TypeError。
        # 这里自动探测一次，前向传播时按需过滤。
        self.accepts_token_type_ids = getattr(hf_config, "type_vocab_size", 0) > 1

        # ---- 5. 分类头 ----
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Linear(hidden, num_labels)

        # 分类头是随机初始化的，用正态分布初始化权重比默认的均匀分布更稳
        self._init_weights(self.classifier)

    @staticmethod
    def _init_weights(module: nn.Module) -> None:
        """初始化线性层权重。

        参数
        ----
        module : nn.Module
            待初始化的模块。

        说明
        ----
        均值 0、标准差 0.02 是 BERT 原论文的初始化方式，
        与预训练权重的量级匹配，能让训练初期更稳定。
        """
        if isinstance(module, nn.Linear):
            module.weight.data.normal_(mean=0.0, std=0.02)
            if module.bias is not None:
                module.bias.data.zero_()

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor | None = None,
        token_type_ids: torch.Tensor | None = None,
        labels: torch.Tensor | None = None,
        **kwargs,
    ) -> dict[str, torch.Tensor]:
        """前向传播。

        参数
        ----
        input_ids : torch.Tensor
            形状 ``(B, L)``，分词后的 token 编号。
        attention_mask : torch.Tensor | None
            形状 ``(B, L)``，1 表示真实 token，0 表示 padding。
            必须传，否则模型会把 padding 也当成有效内容。
        token_type_ids : torch.Tensor | None
            句子类型标记，RoBERTa 系模型不使用。
        labels : torch.Tensor | None
            形状 ``(B,)``，真实标签。传了就顺便算损失，不传只返回 logits。
        **kwargs
            吞掉多余的参数（例如 DataLoader 带过来的 ``meta``），避免报错。

        返回
        ----
        dict
            ``{"logits": (B, K)}``，若传了 labels 则额外含 ``{"loss": 标量}``。
        """
        # meta 是元信息，不是张量，直接丢掉
        kwargs.pop("meta", None)

        # 模型不接受 token_type_ids 就置空（CodeBERT 属于这种情况）
        if not self.accepts_token_type_ids:
            token_type_ids = None

        # ---- 1. 过编码器 ----
        outputs = self.encoder(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
            return_dict=True,  # 返回带属性名的对象，比元组好读
        )
        last_hidden = outputs.last_hidden_state  # (B, L, H)

        # ---- 2. 池化：把 (B, L, H) 压成 (B, H) ----
        if self.pooling == "mean":
            # 平均池化：只对真实 token 求平均，padding 位置要屏蔽掉
            mask = attention_mask.unsqueeze(-1).float() if attention_mask is not None else None
            if mask is not None:
                # 分子：掩码加权求和；分母：真实 token 个数（clamp 防止除 0）
                pooled = (last_hidden * mask).sum(1) / mask.sum(1).clamp(min=1e-9)
            else:
                pooled = last_hidden.mean(1)
        else:
            # [CLS] 池化：取第 0 个位置的向量
            # BERT 预训练时就用这个位置做"下一句预测"，它天然承载了整句语义
            pooled = last_hidden[:, 0, :]

        # ---- 3. 分类头：Dropout → Linear ----
        logits = self.classifier(self.dropout(pooled))

        # ---- 4. 组装输出 ----
        result: dict[str, torch.Tensor] = {"logits": logits}
        if labels is not None:
            # CrossEntropyLoss 内部会做 log_softmax + NLLLoss，
            # 所以这里传入的必须是**未归一化的 logits**，不要提前 softmax
            loss_fct = nn.CrossEntropyLoss()
            result["loss"] = loss_fct(logits.view(-1, self.num_labels), labels.view(-1))
        return result


def build_tokenizer(model_name_or_path: str):
    """加载分词器。

    参数
    ----
    model_name_or_path : str
        模型名或本地路径。

    返回
    ----
    transformers.PreTrainedTokenizerFast

    说明
    ----
    ``use_fast=True`` 使用 Rust 实现的分词器，速度比纯 Python 版快 10 倍以上。
    CodeBERT 用的是 BPE 分词器（需要 vocab.json + merges.txt），
    AutoTokenizer 会自动识别该用哪一类。
    """
    return AutoTokenizer.from_pretrained(model_name_or_path, use_fast=True)


def count_parameters(model: nn.Module) -> tuple[int, int]:
    """统计模型参数量。

    参数
    ----
    model : nn.Module
        任意 PyTorch 模型。

    返回
    ----
    tuple[int, int]
        ``(总参数量, 可训练参数量)``。

    用途
    ----
    训练前打印一下，心里有数。CodeBERT 微调通常是"总计 124.6M，
    可训练 124.6M"——因为我们是全参数微调，没有冻结任何层。
    如果以后改成只训分类头，可训练参数量会降到几万。
    """
    total = sum(p.numel() for p in model.parameters())
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    return total, trainable


def get_parameter_groups(
    model: VulnClassifier, base_lr: float, head_lr: float, weight_decay: float
) -> list[dict]:
    """构造分层学习率的参数组。

    参数
    ----
    model : VulnClassifier
        待训练的模型。
    base_lr : float
        编码器学习率（通常 2e-5）。
    head_lr : float
        分类头学习率（通常 1e-4，比编码器大 5 倍）。
    weight_decay : float
        权重衰减系数（L2 正则）。

    返回
    ----
    list[dict]
        可直接传给 ``torch.optim.AdamW`` 的参数组列表。

    为什么分类头要用更大的学习率
    ---------------------------
    编码器的权重是"预训练好的、已经很好的"，只需要小幅微调；
    而分类头是随机初始化的，一开始输出完全是噪声，
    需要用更大的步长才能快速收敛。经验上 head_lr ≈ 5 × base_lr 效果最好。

    为什么 bias 和 LayerNorm 不做权重衰减
    ------------------------------------
    权重衰减会把参数往 0 拉。对普通权重这是正则化，有好处；
    但 bias 和 LayerNorm 的缩放参数本来就该接近 1，
    强行往 0 拉反而会损害模型表达能力。这是 BERT 微调的通行做法。
    """
    no_decay = ["bias", "LayerNorm.weight"]
    groups = [
        {
            # 组1：编码器里需要衰减的权重
            "params": [
                p for n, p in model.encoder.named_parameters()
                if not any(nd in n for nd in no_decay)
            ],
            "lr": base_lr,
            "weight_decay": weight_decay,
        },
        {
            # 组2：编码器里的 bias / LayerNorm，不衰减
            "params": [
                p for n, p in model.encoder.named_parameters()
                if any(nd in n for nd in no_decay)
            ],
            "lr": base_lr,
            "weight_decay": 0.0,
        },
        {
            # 组3：分类头，用更大的学习率
            "params": list(model.classifier.parameters()),
            "lr": head_lr,
            "weight_decay": weight_decay,
        },
    ]
    return groups
