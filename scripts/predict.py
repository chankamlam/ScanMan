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
    max_code_chars : int
        字符级截断阈值（会被 config.yaml 里的值覆盖）。

    设计思路
    --------
    把"加载模型"和"预测"分开：初始化一次、预测多次。
    批量推理时不会反复加载 500MB 权重，速度快很多。
    """

    def __init__(self, checkpoint: str | Path, device: str | None = None,
                 max_length: int = 512, max_code_chars: int = 8000,
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
        cfg_path = self.ckpt.parent / "config.yaml"
        if cfg_path.exists():
            import yaml

            c = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            base_model = c.get("model", {}).get("name", base_model)
            max_length = c.get("model", {}).get("max_length", max_length)
            max_code_chars = c.get("model", {}).get("max_code_chars", max_code_chars)

        base_model = _resolve_backbone(base_model)

        # ---- 4. 加载分词器（从检查点目录加载，保证与训练一致） ----
        # 自动选设备的优先级与 train.py::pick_device 保持一致：CUDA > MPS > CPU
        if device:
            self.device = torch.device(device)
        elif torch.cuda.is_available():
            self.device = torch.device("cuda")
        elif getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
            self.device = torch.device("mps")
        else:
            self.device = torch.device("cpu")
        self.max_length = max_length
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
            检测任务 K=2（第 1 列是"有漏洞"的概率）；
            分类任务 K=label_map.json 里的类别数（演示模型 28，CVEfixes 41）。

        为什么要单独抽出来
        ------------------
        ``predict()`` 只返回"人类可读"的结果（判定 + 置信度），
        但算 F1/AUC 这类指标需要原始概率。``scripts/evaluate.py`` 用这个方法，
        避免为了拿到概率再去写一遍预处理逻辑。
        """
        # ---- 1. 预处理：头尾截断（必须和训练时用同样的规则） ----
        codes = [truncate_code(c or "", self.max_code_chars) for c in codes]

        # ---- 2. 分词 ----
        # 推理时 padding=True 是"补到本 batch 最长"，比补到 512 更快
        enc = self.tokenizer(
            codes, truncation=True, max_length=self.max_length,
            padding=True, return_tensors="pt",
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
                    # Top-5 候选：CWE 类别有几十个，只给一个答案不够用，
                    # 给候选列表让开发者自己判断更有实用价值
                    "topk": [
                        {"cwe": self.id2name.get(int(j), str(j)), "prob": float(p[j])}
                        for j in order[: min(5, len(p))]
                    ],
                })
        return results


def _resolve_backbone(name: str) -> str:
    """把 config.yaml 里的 ``model.name`` 解析成能被 transformers 加载的字符串。

    为什么需要这一步
    ----------------
    ``config.yaml`` 支持两种写法（配置里自己写着"也可以直接填本地目录，
    例如 ``models/microsoft__codebert-base``"），但 ``AutoConfig.from_pretrained``
    **只认 HF repo id 或真实存在的路径**，不会按项目根目录解析相对路径：

    .. code-block:: text

        OSError: Repo id must use alphanumeric chars, '-', '_' or '.'.
        The name cannot start or end with '-' or '.'
        and the maximum length is 96: 'models\\microsoft__codebert-base'

    老检查点（``outputs/cvefixes_detection_6ep`` 等）的 config 里存的就是这种
    相对路径，于是"换个目录就跑不起来"—— 本函数就是修这个。

    解析顺序
    --------
    1. 按项目根解析成本地绝对路径，**存在就用它**（离线、可复现，首选）
    2. 解析后不存在 → 原样返回，交给 transformers 当 HF id 处理
       （走 HF 缓存或联网下载）。这时打一条 warning，免得"本地权重没拷过来"
       被静默地降级成"从网上重新拉了一个"，两者虽同名但不是一回事。

    ``microsoft/codebert-base`` 这种本来就是 HF id 的写法会走到第 2 步，
    行为与改动前完全一致。
    """
    candidate = resolve_path(name.replace("\\", "/"))
    if candidate.exists():
        return str(candidate)

    # 只有"看起来就是在指本地目录"的写法才警告。``microsoft/codebert-base``
    # 是标准的 HF repo id，解析不到本地是**正常**的，对它报警只会制造噪声，
    # 让人以后忽略这个警告。
    looks_local = (
        Path(name).is_absolute()
        or "\\" in name
        or name.startswith(("./", "../", "models/"))
    )
    if not looks_local:
        return name

    # 本地目录没拷过来（换机器很常见）时，还能从目录名还原出 HF repo id：
    # download_model.py 存盘时把 "microsoft/codebert-base" 写成了
    # "microsoft__codebert-base"（``scripts/download_model.py:119``），
    # 反过来把 ``__`` 换回 ``/`` 就是原 repo id，直接走 HF 缓存。
    # 这比直接放弃强得多，也解释了目录名里那两个下划线的来历。
    repo_id = Path(name.replace("\\", "/")).name.replace("__", "/")
    if "__" in Path(name.replace("\\", "/")).name:
        log.warning("本地模型目录 %s 不存在，按目录名还原成 HF repo id %r 加载",
                    candidate, repo_id)
        return repo_id

    log.warning("本地模型目录 %s 不存在，原样交给 HuggingFace 处理", candidate)
    return name


def is_correct(pred: dict, gold, task: str) -> bool | None:
    """判断单条预测是否命中 gold 标签。

    返回 ``True`` / ``False`` 表示对错，``None`` 表示**这条没法比**（不计入统计）。

    为什么要单独抽一个函数
    ----------------------
    **检测和分类的 gold 长得不一样**，早期版本一律写 ``int(r["label"])``，
    结果在分类任务上直接崩：

    - 检测任务的 gold 一定是 int（0=安全 / 1=漏洞）
    - 分类任务的 gold 有**两种形态**：正式测试集里是类别下标（int），
      而人工手写的用例（``docs/test_cases/``）里是 CWE 名字（``"CWE-120"``）
      —— ``int("CWE-120")`` 抛 ValueError，而且崩在文件已经打开写入之后，
      会留下一个半截的 JSONL。

    三种情形的处理
    --------------
    ==================  ============================================
    gold 形态            怎么比
    ==================  ============================================
    ``"CWE-120"`` 等名字  比预测出的 ``cwe`` 字段（大小写/空格不敏感）
    ``1`` / ``"1"`` 等下标 比 ``label`` 字段
    其它（None/词典/...）  返回 ``None``，跳过，不算错也不算对
    ==================  ============================================

    失败一律返回 ``None`` 而不是 ``False``：**"比不了"和"猜错了"是两回事**，
    混在一起会把准确率算低，也会掩盖数据格式问题。
    """
    if gold is None:
        return None

    # CWE 名字形态：分类任务按名字比，检测任务没法比（返回 None）
    if isinstance(gold, str) and gold.strip().upper().startswith("CWE-"):
        if task != "classification":
            return None
        return str(pred.get("cwe", "")).strip().upper() == gold.strip().upper()

    # 其余一律按"类别下标"比
    try:
        return int(pred["label"]) == int(gold)
    except (ValueError, TypeError, KeyError):
        return None


def main() -> None:
    """命令行入口：解析参数 → 建推理器 → 按模式执行。"""
    parser = argparse.ArgumentParser(description="漏洞检测 / 分类推理")
    parser.add_argument("--checkpoint", required=True, help="微调后的模型目录（含 best/）")
    parser.add_argument("--code", default=None, help="直接传入一段代码")
    parser.add_argument("--file", default=None, help="从文件读取代码")
    parser.add_argument("--input", default=None, help="批量输入 JSONL（需含 code 字段）")
    parser.add_argument("--output", default=None, help="批量输出 JSONL")
    parser.add_argument("--device", default=None,
                        help="cpu | cuda | mps | cuda:1，默认自动（CUDA > MPS > CPU）")
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

    correct = total = n_gold = 0  # 用于统计与真实标签的一致率
    with open(out_path, "w", encoding="utf-8") as f:
        # 按 batch_size 分批推理（比一条一条快得多）
        for i in range(0, len(records), args.batch_size):
            chunk = records[i:i + args.batch_size]
            preds = predictor.predict([r.get("code", "") for r in chunk])
            for r, p in zip(chunk, preds):
                row = {"id": r.get("id"), "pred": p}
                # 如果输入数据自带 gold 标签（比如测试集），顺便算个准确率。
                # gold 可能是 int（类别下标），也可能是 "CWE-120"（人工用例），
                # 比不了的情况返回 None —— 跳过，别把准确率算错（见 is_correct）。
                gold = r.get("label", r.get("expect_cwe"))
                if gold is not None:
                    row["gold"] = gold
                    n_gold += 1
                    ok = is_correct(p, gold, predictor.task)
                    if ok is not None:
                        total += 1
                        correct += int(ok)
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
            # \r 让进度在同一行刷新
            print(f"\r  已处理 {min(i+args.batch_size, len(records))}/{len(records)}", end="")
    print()
    if total:
        log.info("与 gold 标签对比准确率: %.4f (%d/%d)", correct / total, correct, total)
    elif n_gold:
        # 有 gold 但一条都比不了（比如检测模型跑分类用例，或标签格式不认识）。
        # 说清楚是"没法比"而不是"全错"，否则容易被误读成准确率 0。
        log.warning("有 %d 条带 gold 标签，但格式与 %s 任务对不上，全部跳过未计入准确率",
                    n_gold, predictor.task)
    log.info("预测结果 -> %s", out_path)


if __name__ == "__main__":
    main()
