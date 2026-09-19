"""数据加载模块：Torch Dataset + 动态 padding 批处理器。

PyTorch 的数据管道由三部分组成：

    Dataset    负责"怎么取第 i 条数据"        → VulnDataset
    CollateFn  负责"怎么把一批数据拼成一个张量" → DynamicPaddingCollator
    DataLoader 负责"多进程读取、打乱、分批"     → 由 train.py 组装

本模块的设计要点
----------------
1. **按需分词**：不在初始化时把全部样本 tokenize 好，而是在 ``__getitem__``
   里逐条处理。这样 50 万条数据也只占几十 MB 内存。
2. **动态 padding**：不统一补齐到 512，而是补到"本 batch 最长的那条"。
   代码长度差异极大（短则几十 token，长则上千），动态 padding 能省掉
   大量无效计算，实测训练速度可提升 2~3 倍。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import torch
from torch.utils.data import Dataset

from .utils import truncate_code


class VulnDataset(Dataset):
    """代码漏洞数据集。

    每条样本是一个 dict，至少包含::

        {"code": "void f(char*s){...}", "label": 1, "cwe": "CWE-79", ...}

    继承 ``torch.utils.data.Dataset`` 需要实现三个方法：
        __init__      初始化（存下数据引用）
        __len__       返回样本总数
        __getitem__   返回第 idx 条样本

    参数
    ----
    records : list[dict]
        记录列表，通常由 ``load_jsonl_records`` 从 JSONL 读入。
    tokenizer
        HuggingFace 分词器对象。
    max_length : int
        最大 token 数，超过会被截断。
    max_code_chars : int
        送入分词器前的字符级头尾截断阈值。
    """

    def __init__(
        self,
        records: list[dict[str, Any]],
        tokenizer,
        max_length: int = 512,
        max_code_chars: int = 8000,
    ) -> None:
        self.records = records
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.max_code_chars = max_code_chars

    def __len__(self) -> int:
        """返回样本总数，DataLoader 靠它决定一个 epoch 要取多少次。"""
        return len(self.records)

    def __getitem__(self, idx: int) -> dict[str, Any]:
        """取出第 idx 条样本，并现场完成分词。

        参数
        ----
        idx : int
            样本下标，取值范围 ``[0, len(self))``。

        返回
        ----
        dict
            包含分词结果 + ``labels`` + ``meta`` 的字典。
            ``meta`` 是元信息，不参与计算，但评估和错误分析时很有用
            （比如想看看模型在哪些 CWE 上错得多）。

        注意
        ----
        这里 ``padding=False``：不在这里补齐，留给 collate_fn 统一做，
        这样才能实现"补到本 batch 最长"的动态 padding。
        """
        rec = self.records[idx]

        # ---- 1. 取代码并做头尾截断（防止超长样本拖慢整体） ----
        code = truncate_code(rec.get("code") or "", self.max_code_chars)

        # ---- 2. 分词 ----
        # truncation=True  超长截断
        # padding=False    不补齐（交给 collate_fn）
        # return_attention_mask=True  生成 0/1 掩码，告诉模型哪些是真实 token
        enc = self.tokenizer(
            code,
            truncation=True,
            max_length=self.max_length,
            padding=False,
            return_attention_mask=True,
        )

        # ---- 3. 组装返回值 ----
        item = {k: v for k, v in enc.items()}
        item["labels"] = int(rec["label"])

        # 附带元信息，供评估 / 错误分析使用（不参与前向计算）
        item["meta"] = {
            "id": rec.get("id", ""),
            "cwe": rec.get("cwe", ""),
            "cwe_name": rec.get("cwe_name", ""),
            "source": rec.get("source", ""),
            "language": rec.get("language", ""),
        }
        return item


class DynamicPaddingCollator:
    """把 batch 内样本 padding 到"本 batch 最长"的长度。

    参数
    ----
    tokenizer
        HuggingFace 分词器，用它的 ``pad()`` 方法做补齐。
    pad_to_multiple_of : int | None
        补齐长度对齐到该值的整数倍，默认 8。
        GPU 对 8 的倍数长度计算效率更高（Tensor Core 要求），
        所以补到 104 不如补到 104（8 的倍数）来得快。

    为什么需要动态 padding
    ---------------------
    假设一个 batch 里有 3 条样本，长度分别是 40 / 120 / 800：

    - 固定 padding 到 512：每条的 attention 计算量都是 512，
      3 条共 1536 个位置的无效计算 → 浪费严重
    - 动态 padding 到 808（本 batch 最长）：只有后两条需要补，
      计算量从 1536 降到约 808 → 快近一倍

    在代码数据集上（长短差异极大）这个优化收益非常明显。
    """

    def __init__(self, tokenizer, pad_to_multiple_of: int | None = 8) -> None:
        self.tokenizer = tokenizer
        self.pad_to_multiple_of = pad_to_multiple_of

    def __call__(self, features: list[dict[str, Any]]) -> dict[str, Any]:
        """把一批样本拼成一个可直接喂给模型的字典。

        参数
        ----
        features : list[dict]
            ``VulnDataset.__getitem__`` 返回的若干条样本组成的列表。

        返回
        ----
        dict
            ``{"input_ids": (B,L), "attention_mask": (B,L),
               "labels": (B,), "meta": [ ... ]}``

        实现细节
        --------
        ``f.pop(...)`` 会**就地删除**键，所以处理完 labels 和 meta 之后，
        features 里就只剩分词结果（input_ids / attention_mask /
        可能还有 token_type_ids），正好可以直接丢给 ``tokenizer.pad()``。
        """
        # ---- 1. 摘出 meta 和 labels（它们不是分词器认识的字段） ----
        metas = [f.pop("meta", {}) for f in features]
        labels = torch.tensor([f.pop("labels") for f in features], dtype=torch.long)

        # ---- 2. 剩余的字段交给 tokenizer.pad 做动态补齐 ----
        # padding=True 表示补到本 batch 最长，而不是补到 max_length
        batch = self.tokenizer.pad(
            features,
            padding=True,
            pad_to_multiple_of=self.pad_to_multiple_of,
            return_tensors="pt",
        )

        # ---- 3. 把 labels 和 meta 装回去 ----
        batch["labels"] = labels
        batch["meta"] = metas
        return batch


def load_jsonl_records(path: str | Path) -> list[dict[str, Any]]:
    """把 JSONL 文件读成 list。

    参数
    ----
    path : str | Path
        JSONL 文件路径。

    返回
    ----
    list[dict]
        记录列表。

    说明
    ----
    这里一次性读进内存（而不是用生成器），因为：
        1. 训练时需要 shuffle，必须能随机访问；
        2. 几十万条记录（约 1~2 GB）在现代机器上完全放得下。
    如果数据规模再大一个量级，就该换成 ``datasets`` 库的磁盘映射方案了。
    """
    import json

    records: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def iter_batches(records: Iterable[dict], batch_size: int) -> Iterable[list[dict]]:
    """把记录切成固定大小的 batch（生成器）。

    参数
    ----
    records : Iterable[dict]
        记录流。
    batch_size : int
        每批多少条。

    返回
    ----
    Iterable[list[dict]]
        一批一批地吐出。

    用途
    ----
    批量推理时用（不需要 shuffle 和 collate_fn 的场景）。
    最后一个不足 batch_size 的批次也会被吐出。
    """
    buf: list[dict] = []
    for r in records:
        buf.append(r)
        if len(buf) >= batch_size:
            yield buf
            buf = []
    # 处理最后不满一批的剩余数据
    if buf:
        yield buf
