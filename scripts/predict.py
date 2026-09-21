"""加载微调后的模型做推理（漏洞检测 / CWE 分类）。

三种使用方式
------------
1. **单段代码**：直接传字符串，适合快速验证
2. **读文件**：把一段代码存成 .c/.php 文件后传入
3. **批量推理**：传 JSONL，逐条预测并输出结果；如果输入里有 ``label`` 字段，
   脚本还会自动跟真实标签对比，顺便报一个准确率

用法
----
    # 单段代码（二分类）
    python scripts/predict.py --checkpoint outputs/cvefixes_detection_codebert-base/best \
        --code "void f(char*s){char b[10];strcpy(b,s);}"

    # 从文件读取代码
    python scripts/predict.py --checkpoint <ckpt> --file test.c

    # 批量推理（JSONL，需含 code 字段）
    python scripts/predict.py --checkpoint <ckpt> --input data/processed/cvefixes_detection_test.jsonl \
        --output outputs/preds.jsonl

检查点目录需要包含
------------------
    best/pytorch_model.bin    模型权重
    best/tokenizer.json       分词器（保证切词方式与训练时一致）
    best/label_map.json       任务类型 + 类别数 + 编号->CWE名称
    config.yaml               训练时的配置（用于还原模型结构）
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import resolve_path  # noqa: E402
from src.data import tokenize_head_tail  # noqa: E402
from src.metrics import softmax  # noqa: E402
from src.models import VulnClassifier, build_tokenizer  # noqa: E402
from src.utils import get_logger, truncate_code  # noqa: E402

log = get_logger("predict")


class VulnPredictor:
    """推理器：把 tokenizer + 模型封装起来，对外只暴露 predict()。

    参数
    ----
    checkpoint : str | Path
        检查点目录，通常是 ``outputs/<run_name>/best``。
    device : str | None
        设备，``"cpu"`` / ``"cuda"`` / ``"cuda:1"``。为 None 时自动选择。
    max_length : int
        最大 token 长度（会被 config.yaml 里的值覆盖）。
    head_ratio : float
        token 级头尾截断时，头部保留的 token 比例（会被 config.yaml 里的值覆盖）。

    设计思路
    --------
    把"加载模型"和"预测"分开：初始化一次、预测多次。
    批量推理时不会反复加载 500MB 权重，速度快很多。
    """

    def __init__(self, checkpoint: str | Path, device: str | None = None,
                 max_length: int = 512, head_ratio: float | None = None,
                 threshold: float | None = None):
        # ---- 1. 定位检查点目录 ----
        self.ckpt = Path(checkpoint)
        if not self.ckpt.is_absolute():
            self.ckpt = resolve_path(self.ckpt)
        if not self.ckpt.exists():
            raise FileNotFoundError(f"模型目录不存在: {self.ckpt}")

        # ---- 2. 读标签映射，确定任务类型和类别数 ----
        # 这一步很关键：模型最后的线性层输出维度必须和训练时一致，
        # 否则 load_state_dict 会因为形状不匹配而报错。
        meta = {}
        lm_path = self.ckpt / "label_map.json"
        if lm_path.exists():
            meta = json.loads(lm_path.read_text(encoding="utf-8"))
        self.task = meta.get("task", "detection")
        self.num_labels = int(meta.get("num_labels", 2))
        self.id2name = {int(k): v for k, v in meta.get("id2name", {}).items()}

        # ---- 2.5 判定阈值（只对检测任务有意义） ----
        # 概率 > 阈值 才判为"有漏洞"。默认 0.5，但 0.5 只是个约定俗成的数字：
        # 漏洞检测里漏报比误报严重，实际落地通常把阈值调低来换召回率。
        # scripts/tune_threshold.py 会把调好的值写进 best/threshold.json，这里自动读取。
        self.threshold = 0.5
        th_path = self.ckpt / "threshold.json"
        if th_path.exists():
            try:
                self.threshold = float(
                    json.loads(th_path.read_text(encoding="utf-8"))["threshold"]
                )
            except (KeyError, ValueError, json.JSONDecodeError):
                pass  # 文件坏了就用默认值，不打断推理
        if threshold is not None:  # 命令行显式指定时优先级最高
            self.threshold = float(threshold)

        # ---- 3. 从训练时的 config.yaml 还原模型结构 ----
        # 为什么需要它：VulnClassifier 要先构造出正确结构（编码器 + 指定维度的分类头），
        # 才能把权重 load 进去。用哪个预训练模型、max_length 是多少，
        # 这些信息只有 config.yaml 里有。
        base_model = "microsoft/codebert-base"
        max_code_chars = None
        cfg_path = self.ckpt.parent / "config.yaml"
        if cfg_path.exists():
            import yaml

            c = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            model_cfg = c.get("model", {})
            base_model = model_cfg.get("name", base_model)
            max_length = model_cfg.get("max_length", max_length)
            if "head_ratio" in model_cfg:
                # 新 checkpoint：token 级头尾截断。
                head_ratio = float(model_cfg["head_ratio"])
            else:
                # 旧 checkpoint：继续使用字符级截断，保证训练/推理一致。
                max_code_chars = int(model_cfg.get("max_code_chars", 8000))

        if head_ratio is None and max_code_chars is None:
            # 没有 config 时按当前默认逻辑处理。
            head_ratio = 0.6

        # ---- 4. 加载分词器（从检查点目录加载，保证与训练一致） ----
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
        self.max_length = max_length
        self.head_ratio = head_ratio
        self.max_code_chars = max_code_chars
        self.tokenizer = build_tokenizer(str(self.ckpt))

        # ---- 5. 建模型并加载权重 ----
        self.model = VulnClassifier(
            base_model, num_labels=self.num_labels, pooling="cls"
        )
        # map_location="cpu" 先加载到 CPU，再 .to(device) 搬过去。
        # 直接加载到 GPU 上在显存不足时会失败，绕一下更稳。
        state = torch.load(self.ckpt / "pytorch_model.bin", map_location="cpu")
        self.model.load_state_dict(state)
        # eval() 关闭 Dropout，保证同样的输入每次得到同样的输出
        self.model.to(self.device).eval()

    @torch.no_grad()
    def predict_probs(self, codes: list[str]) -> np.ndarray:
        """批量前向，返回 softmax 之后的概率矩阵。

        参数
        ----
        codes : list[str]
            待预测的代码片段列表。

        返回
        ----
        np.ndarray
            形状 ``(N, K)``，每行一个样本，K = 类别数。
            检测任务 K=2（第 1 列是"有漏洞"的概率），分类任务 K=41。

        为什么要单独抽出来
        ------------------
        ``predict()`` 只返回"人类可读"的结果（判定 + 置信度），
        但算 F1/AUC 这类指标需要原始概率。``scripts/evaluate.py`` 用这个方法，
        避免为了拿到概率再去写一遍预处理逻辑。
        """
        # ---- 1. 预处理：必须和训练时使用完全相同的长度规则 ----
        if self.head_ratio is not None:
            # 新 checkpoint：token 级头尾截断。
            features = [
                tokenize_head_tail(
                    self.tokenizer,
                    code or "",
                    max_length=self.max_length,
                    head_ratio=self.head_ratio,
                )
                for code in codes
            ]
            enc = self.tokenizer.pad(
                features,
                padding=True,
                return_tensors="pt",
            )
        else:
            # 旧 checkpoint：保留旧的字符级截断 + tokenizer 右截断，
            # 否则历史模型会出现训练/推理 preprocessing mismatch。
            legacy_codes = [
                truncate_code(code or "", self.max_code_chars or 8000)
                for code in codes
            ]
            enc = self.tokenizer(
                legacy_codes,
                truncation=True,
                max_length=self.max_length,
                padding=True,
                return_tensors="pt",
            )
        enc = {k: v.to(self.device) for k, v in enc.items()}

        # ---- 3. 过滤模型不认识的字段 ----
        # RoBERTa 系（CodeBERT）不接受 token_type_ids，传进去会报错
        if not getattr(self.model, "accepts_token_type_ids", True):
            enc.pop("token_type_ids", None)

        # ---- 4. 前向传播 + 转概率 ----
        logits = self.model(**enc)["logits"].float().cpu().numpy()
        return softmax(logits)

    @torch.no_grad()
    def predict(self, codes: list[str]) -> list[dict]:
        """批量预测。

        参数
        ----
        codes : list[str]
            待预测的代码片段列表。

        返回
        ----
        list[dict]
            每条代码一个结果字典：

            检测任务::

                {"label": 1, "verdict": "vulnerable", "confidence": 0.9987,
                 "prob_safe": 0.0013, "prob_vulnerable": 0.9987, "threshold": 0.215}

            注意：检测任务的判定用的是 ``self.threshold``（默认 0.5，可被
            ``best/threshold.json`` 或构造参数覆盖），不是简单的 argmax。

            分类任务::

                {"label": 2, "cwe": "CWE-89", "confidence": 0.612,
                 "topk": [{"cwe": "CWE-89", "prob": 0.612}, ...]}
        """
        # ---- 前向传播：复用 predict_probs，避免把预处理写两遍 ----
        probs = self.predict_probs(codes)

        # ---- 按任务类型组织输出 ----
        results = []
        for i in range(len(codes)):
            p = probs[i]
            if self.task == "detection":
                # 按阈值判定，而不是 argmax —— 这样可以通过调阈值来控制召回率
                prob_vuln = float(p[1])
                idx = 1 if prob_vuln >= self.threshold else 0
                results.append({
                    "label": idx,
                    "verdict": "vulnerable" if idx == 1 else "safe",
                    "confidence": float(p[idx]),
                    "prob_safe": float(p[0]),
                    "prob_vulnerable": float(p[1]),
                    "threshold": self.threshold,
                })
            else:
                # ---- 分类任务：按概率从大到小排序，输出 Top-5 ----
                # argsort 默认升序，[::-1] 反转成降序
                order = p.argsort()[::-1]
                results.append({
                    "label": int(order[0]),   # 概率最大的那个类别
                    "cwe": self.id2name.get(int(order[0]), str(order[0])),
                    "confidence": float(p[order[0]]),
                    # Top-5 候选：CWE 类别有 41 个，只给一个答案不够用，
                    # 给候选列表让开发者自己判断更有实用价值
                    "topk": [
                        {"cwe": self.id2name.get(int(j), str(j)), "prob": float(p[j])}
                        for j in order[: min(5, len(p))]
                    ],
                })
        return results


def main() -> None:
    """命令行入口：解析参数 → 建推理器 → 按模式执行。"""
    parser = argparse.ArgumentParser(description="漏洞检测 / 分类推理")
    parser.add_argument("--checkpoint", required=True, help="微调后的模型目录（含 best/）")
    parser.add_argument("--code", default=None, help="直接传入一段代码")
    parser.add_argument("--file", default=None, help="从文件读取代码")
    parser.add_argument("--input", default=None, help="批量输入 JSONL（需含 code 字段）")
    parser.add_argument("--output", default=None, help="批量输出 JSONL")
    parser.add_argument("--device", default=None, help="cpu | cuda | cuda:1")
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--threshold", type=float, default=None,
                        help="检测任务的判定阈值（默认读 best/threshold.json，没有则 0.5）")
    args = parser.parse_args()

    # 加载模型（只做一次，后面复用）
    predictor = VulnPredictor(args.checkpoint, device=args.device,
                              threshold=args.threshold)
    log.info("模型加载完成 | 任务=%s | 类别数=%d | 设备=%s",
             predictor.task, predictor.num_labels, predictor.device)
    if predictor.task == "detection":
        src = ("命令行 --threshold" if args.threshold is not None
               else ("best/threshold.json" if (Path(args.checkpoint) / "threshold.json").exists()
                     else "默认值"))
        log.info("判定阈值 = %.3f（来源：%s）", predictor.threshold, src)

    # ==================== 模式一：单条预测 ====================
    if args.code or args.file:
        # errors="ignore" 保证读到非法编码字符时不会崩
        code = args.code if args.code else Path(args.file).read_text(encoding="utf-8", errors="ignore")
        res = predictor.predict([code])[0]
        print("\n" + "=" * 60)
        if predictor.task == "detection":
            print(f"判定结果 : {res['verdict']}")
            print(f"置信度   : {res['confidence']:.4f}")
            print(f"安全概率 : {res['prob_safe']:.4f}")
            print(f"漏洞概率 : {res['prob_vulnerable']:.4f}")
            print(f"判定阈值 : {res['threshold']:.3f}")
        else:
            print(f"预测 CWE : {res['cwe']}  (置信度 {res['confidence']:.4f})")
            print("Top-5    :")
            for it in res["topk"]:
                print(f"   {it['cwe']:<12} {it['prob']:.4f}")
        print("=" * 60 + "\n")
        return

    if not args.input:
        parser.error("请提供 --code / --file / --input 之一")

    # ==================== 模式三：批量推理 ====================
    # 逐行读入 JSONL（每行一条记录，至少要有 code 字段）
    records = []
    with open(args.input, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    log.info("批量推理 %d 条", len(records))

    # 没指定输出路径就自动生成：把 .jsonl 换成 .pred.jsonl
    out_path = Path(args.output) if args.output else Path(args.input).with_suffix(".pred.jsonl")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    correct = total = 0  # 用于统计与真实标签的一致率
    with open(out_path, "w", encoding="utf-8") as f:
        # 按 batch_size 分批推理（比一条一条快得多）
        for i in range(0, len(records), args.batch_size):
            chunk = records[i:i + args.batch_size]
            preds = predictor.predict([r.get("code", "") for r in chunk])
            for r, p in zip(chunk, preds):
                row = {"id": r.get("id"), "pred": p}
                # 如果输入数据自带 label（比如测试集），顺便算个准确率
                if "label" in r:
                    row["gold"] = r["label"]
                    total += 1
                    correct += int(int(p["label"]) == int(r["label"]))
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
            # \r 让进度在同一行刷新
            print(f"\r  已处理 {min(i+args.batch_size, len(records))}/{len(records)}", end="")
    print()
    if total:
        log.info("与 gold 标签对比准确率: %.4f (%d/%d)", correct / total, correct, total)
    log.info("预测结果 -> %s", out_path)


if __name__ == "__main__":
    main()
