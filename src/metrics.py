"""评估指标模块。

本模块负责把模型的原始输出（logits）换算成人类能看懂的性能指标。

为什么要区分"检测"和"分类"两套指标？
------------------------------------
- **检测任务**是二分类，我们只关心"有漏洞"这个正类。
  所以用 binary 口径的 precision/recall/F1，再加上 AUC、MCC。
- **分类任务**是多分类（41 个 CWE），类别之间不平衡，
  所以用 macro 口径（每个类别等权），并补充 Top-k 准确率。

指标速查
--------
========================  ==========================================
指标                       含义
========================  ==========================================
accuracy                  准确率：预测对的占比
precision                 精确率：预测为"有漏洞"的里面，真的有多少
recall                    召回率：真的有漏洞的里面，找出来多少
f1                        precision 和 recall 的调和平均
roc_auc                   ROC 曲线下面积，衡量排序能力，0.5=瞎猜
pr_auc                    精确率-召回率曲线下面积，不平衡数据更敏感
mcc                       Matthews 相关系数，-1~1，不平衡数据最可靠
macro_f1                  先算每个类别的 F1 再平均（类别等权）
weighted_f1               按类别样本量加权的 F1
topk_accuracy             前 k 个预测里包含正确答案的比例
========================  ==========================================
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)


def softmax(logits: np.ndarray) -> np.ndarray:
    """把 logits 转成概率（数值稳定版）。

    参数
    ----
    logits : np.ndarray
        形状 ``(N, K)``，模型输出的原始分数（未归一化）。

    返回
    ----
    np.ndarray
        形状 ``(N, K)``，每行加起来等于 1 的概率。

    为什么要减去最大值
    ------------------
    朴素写法 ``exp(x) / sum(exp(x))`` 在 x 很大时会溢出（exp(1000) = inf）。
    减去每行最大值后，指数部分最大是 ``exp(0)=1``，绝不会溢出，
    而数学结果完全等价::

        softmax(x) = softmax(x - max(x))
    """
    x = logits - logits.max(axis=-1, keepdims=True)
    e = np.exp(x)
    return e / e.sum(axis=-1, keepdims=True)


def compute_binary_metrics(
    y_true: np.ndarray, logits: np.ndarray, threshold: float = 0.5
) -> dict[str, Any]:
    """计算二分类（漏洞检测）的全套指标。

    参数
    ----
    y_true : np.ndarray
        形状 ``(N,)``，真实标签，取值 0（安全）或 1（有漏洞）。
    logits : np.ndarray
        形状 ``(N, 2)``，模型输出的原始分数。
    threshold : float
        判定阈值。概率 >= 该值就判为"有漏洞"。默认 0.5。

        为什么这个参数很重要
        --------------------
        漏洞检测里 **漏报（FN）比误报（FP）严重得多**：漏掉一个真漏洞可能被利用，
        误报只是让开发者多看一眼。所以实际落地时通常把阈值调低，
        用一点 precision 换大量 recall。实测（CVEfixes 6 轮模型）：

            阈值 0.50 -> recall 0.782, precision 0.719, FN=186
            阈值 0.215 -> recall 0.902, precision 0.661, FN=84   ← 召回率翻过 90%

        阈值怎么选？用 ``scripts/tune_threshold.py`` 扫一遍，它会输出
        "达到目标召回率所需的最优阈值"，并写进检查点目录的 ``threshold.json``。

    返回
    ----
    dict
        包含 accuracy / precision / recall / f1 / mcc / roc_auc / pr_auc
        以及混淆矩阵四个量 tn / fp / fn / tp，外加实际使用的 ``threshold``。

    混淆矩阵的含义
    --------------
    ==============  ==================  ==================
                    预测安全             预测有漏洞
    ==============  ==================  ==================
    **实际安全**      TN（对的）            FP（误报）
    **实际有漏洞**    FN（漏报）            TP（对的）
    ==============  ==================  ==================

    对漏洞检测来说 **FN 比 FP 严重得多**：漏掉一个真漏洞可能被利用，
    而误报只是让开发者多看一眼。所以实际落地时经常调低判定阈值，
    牺牲一点 precision 换取更高的 recall。
    """
    # 取"有漏洞"这一列的概率
    probs = softmax(logits)[:, 1]
    # 按给定阈值转成 0/1 预测
    y_pred = (probs >= threshold).astype(int)
    y_true = y_true.astype(int)

    metrics: dict[str, Any] = {
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        # zero_division=0：如果某个类别一条都没预测出来，不让 sklearn 报警告
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        # MCC 在不平衡数据上比 F1 更可靠；只有单一类别时无定义，给 0
        "mcc": float(matthews_corrcoef(y_true, y_pred)) if len(set(y_true)) > 1 else 0.0,
    }

    # AUC 系列需要真实标签里同时存在 0 和 1 才能计算
    if len(set(y_true)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_true, probs))
        metrics["pr_auc"] = float(average_precision_score(y_true, probs))
    else:
        metrics["roc_auc"] = float("nan")
        metrics["pr_auc"] = float("nan")

    # 混淆矩阵四个量
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    metrics.update({"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)})
    return metrics


def compute_multiclass_metrics(
    y_true: np.ndarray, logits: np.ndarray, top_k: int | Sequence[int] = (3, 5)
) -> dict[str, Any]:
    """计算多分类（CWE 分类）的全套指标。

    参数
    ----
    y_true : np.ndarray
        形状 ``(N,)``，真实类别编号。
    logits : np.ndarray
        形状 ``(N, K)``。
    top_k : int
        计算 Top-k 准确率时的 k，默认 3。

    返回
    ----
    dict
        accuracy / macro_f1 / weighted_f1 / micro_f1 / top{k}_accuracy。

    为什么主指标选 macro_f1 而不是 accuracy
    --------------------------------------
    41 个 CWE 类别极度不平衡（CWE-79 有 1103 条，CWE-1333 只有 30 条）。
    如果看 accuracy，模型只要把所有样本都猜成 CWE-79 就能拿到不低的分数，
    但这对少数类毫无用处。macro_f1 给每个类别相同的权重，
    能真实反映模型在长尾类别上的表现。
    """
    probs = softmax(logits)
    y_pred = probs.argmax(axis=-1)
    y_true = y_true.astype(int)

    metrics: dict[str, Any] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        # macro：每个类别等权，长尾类别不会被淹没
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        # weighted：按类别样本量加权，接近总体表现
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        # micro：所有样本一视同仁，多分类下等于 accuracy
        "micro_f1": float(f1_score(y_true, y_pred, average="micro", zero_division=0)),
    }

    # ---- Top-k 准确率 ----
    # 用途：给出 Top-5 候选让开发者自己挑，比只给一个答案实用得多。
    #
    # 默认同时算 Top-3 和 Top-5：
    # - Top-5 是**分类任务的主指标**（见 docs/07 4.3）—— 类别长尾严重，
    #   只报 Top-1 会把"正确答案排第 2"算成完全错误，低估模型。
    #   实际使用中审查者拿到 5 个候选去核对，比拿到一个错的答案有用。
    # - Top-3 保留，是因为历史结果里一直是这个口径，便于前后对比。
    #
    # top_k 传 int 就只算那一个（老调用方的行为不变），传序列就每个都算。
    ks = (top_k,) if isinstance(top_k, int) else tuple(top_k)
    for k in ks:
        # 类别数比 k 少时按类别数封顶：否则 Top-5 在 3 类问题上恒等于 1.0，
        # 这个数字没有意义，报出来只会误导（键名也跟着变成实际生效的 k）
        k = min(int(k), probs.shape[1])
        topk_pred = np.argsort(-probs, axis=1)[:, :k]  # 每行取概率最大的 k 个下标
        metrics[f"top{k}_accuracy"] = float(
            np.mean([yt in row for yt, row in zip(y_true, topk_pred)])
        )
    return metrics


def per_class_report(
    y_true: np.ndarray, logits: np.ndarray, label_names: list[str]
) -> str:
    """生成逐类别的 P/R/F1 明细文本。

    参数
    ----
    y_true : np.ndarray
        真实标签。
    logits : np.ndarray
        模型输出分数。
    label_names : list[str]
        类别名称列表，如 ``["CWE-79", "CWE-125", ..., "OTHER"]``。

    返回
    ----
    str
        可直接打印或写文件的表格文本。

    输出示例::

        class                                 prec   recall       f1   support
        -----------------------------------------------------------------------
        CWE-79                              0.8412   0.9021   0.8706      1103
        CWE-125                             0.7013   0.6528   0.6762       288
        ...

    用途
    ----
    只看总体 F1 不知道问题出在哪。这张表能立刻看出：
    哪些 CWE 学得好、哪些完全学不会（F1=0），从而决定是补数据还是合并类别。
    """
    y_pred = softmax(logits).argmax(axis=-1)
    labels = list(range(len(label_names)))
    p, r, f, s = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    # 手工拼表格，比 pandas 轻量
    lines = [f"{'class':<34}{'prec':>9}{'recall':>9}{'f1':>9}{'support':>10}"]
    lines.append("-" * 71)
    for i, name in enumerate(label_names):
        lines.append(f"{name[:33]:<34}{p[i]:>9.4f}{r[i]:>9.4f}{f[i]:>9.4f}{int(s[i]):>10}")
    return "\n".join(lines)


def format_metrics(metrics: dict[str, Any]) -> str:
    """把指标字典格式化成一行可读文本，方便打印日志。

    参数
    ----
    metrics : dict
        指标字典。

    返回
    ----
    str
        形如 ``accuracy=0.9123 | f1=0.8901 | roc_auc=0.9654``。

    说明
    ----
    浮点数统一保留 4 位小数，整数（如 tp/fn）原样输出。
    """
    parts = []
    for k, v in metrics.items():
        if isinstance(v, float):
            parts.append(f"{k}={v:.4f}")
        else:
            parts.append(f"{k}={v}")
    return " | ".join(parts)
