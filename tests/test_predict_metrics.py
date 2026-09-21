"""预测结果比对 + 多分类指标的回归测试。

覆盖两处曾经出过错、且分类任务一定会踩到的地方：

1. ``scripts/predict.py`` 的 ``is_correct`` —— 早期版本一律写
   ``int(r["label"])``，分类任务的 gold 是 ``"CWE-120"`` 这种字符串时
   直接 ``ValueError`` 崩掉批量推理（见 docs/07 第五节）。
2. ``src/metrics.py`` 的 Top-k —— 原先只算 Top-3，而 ``predict.py``
   推理输出的是 Top-5，两边口径不一致；分类的主指标恰恰是 Top-5。
"""

import numpy as np

from scripts.predict import is_correct
from src.metrics import compute_multiclass_metrics


# ===========================================================================
# is_correct：预测与 gold 的比对规则
# ===========================================================================
# 两个"预测结果"的样本，字段与 predict.py 里 predict() 的真实返回一致
DET_PRED = {"label": 1, "verdict": "vulnerable", "confidence": 0.9}
CLS_PRED = {"label": 2, "cwe": "CWE-89", "confidence": 0.7,
            "topk": [{"cwe": "CWE-89", "prob": 0.7}]}


def test_detection_比_int():
    """检测任务：gold 是 0/1，直接比下标。"""
    assert is_correct(DET_PRED, 1, "detection") is True
    assert is_correct(DET_PRED, 0, "detection") is False


def test_数字字符串按下标比():
    """``"1"`` 这种形态按类别下标处理，不是 CWE 名字。"""
    assert is_correct(DET_PRED, "1", "detection") is True
    assert is_correct(CLS_PRED, "2", "classification") is True


def test_分类任务比_CWE_名字():
    """人工用例里 gold 是 ``"CWE-89"``，比预测出的 cwe 字段。"""
    assert is_correct(CLS_PRED, "CWE-89", "classification") is True
    assert is_correct(CLS_PRED, "CWE-79", "classification") is False


def test_CWE_名字大小写与空格不敏感():
    """手工写的用例不该因为大小写/空格被判错。"""
    for gold in ("cwe-89", " CWE-89 ", "cwe-89 "):
        assert is_correct(CLS_PRED, gold, "classification") is True


def test_比不了返回_None_而不是_False():
    """**这是本函数存在的理由**：「比不了」和「猜错了」必须区分开。

    混在一起会把准确率算低，还会把数据格式问题掩盖成"模型效果差"。
    """
    assert is_correct(CLS_PRED, None, "classification") is None
    assert is_correct(CLS_PRED, {"nested": 1}, "classification") is None
    assert is_correct(CLS_PRED, "根本没法解析", "classification") is None


def test_检测模型遇到_CWE_标签不硬比():
    """检测检查点跑分类用例时，CWE 字符串没有对应字段可比 —— 跳过。"""
    assert is_correct(DET_PRED, "CWE-89", "detection") is None


def test_预测缺字段不崩():
    """预测结果结构异常时返回 None，绝不能让批量推理崩掉。"""
    assert is_correct({}, 5, "classification") is None
    assert is_correct({"label": None}, 5, "classification") is None


# ===========================================================================
# compute_multiclass_metrics：Top-k
# ===========================================================================
def _fake(n: int = 200, n_classes: int = 27, seed: int = 0):
    rng = np.random.default_rng(seed)
    y = rng.integers(0, n_classes, n)
    logits = rng.normal(size=(n, n_classes))
    return y, logits


def test_默认同时给_top3_和_top5():
    y, logits = _fake()
    m = compute_multiclass_metrics(y, logits)
    assert "top3_accuracy" in m
    assert "top5_accuracy" in m
    # Top-5 一定不比 Top-3 差：前 3 名是前 5 名的子集
    assert m["top5_accuracy"] >= m["top3_accuracy"]


def test_传_int_时只算那一个_保持老调用方行为():
    y, logits = _fake()
    assert list(k for k in compute_multiclass_metrics(y, logits, top_k=3) if k.startswith("top")) \
        == ["top3_accuracy"]
    assert list(k for k in compute_multiclass_metrics(y, logits, top_k=9) if k.startswith("top")) \
        == ["top9_accuracy"]


def test_类别数少于k时按类别数封顶():
    """2 类问题报 top5_accuracy 恒等于 1.0，是误导性的假指标。

    封顶后键名变成实际生效的 k，数字才有意义。
    """
    y, logits = _fake(n=50, n_classes=2)
    tops = [k for k in compute_multiclass_metrics(y, logits) if k.startswith("top")]
    assert tops == ["top2_accuracy"]


def test_top5_高于随机基线才算学到东西():
    """纯随机 logits 的 Top-5 应接近 5/27 ≈ 0.185，远高于 Top-1。"""
    y, logits = _fake(n=5000, n_classes=27, seed=1)
    m = compute_multiclass_metrics(y, logits)
    assert 0.10 < m["top5_accuracy"] < 0.28
    assert m["top5_accuracy"] > m["accuracy"]
