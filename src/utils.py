"""通用工具模块。

本文件集中存放整个项目都会用到的小工具函数，避免在多个脚本里重复造轮子：
    - 目录管理：ensure_dir
    - 实验可复现：set_seed
    - 日志打印：get_logger
    - 代码截断：truncate_code  ← 本项目最关键的一个预处理函数
    - JSONL 读写：read_jsonl / write_jsonl
    - 数字格式化：human_int

使用示例
--------
>>> from src.utils import set_seed, get_logger, truncate_code
>>> set_seed(42)
>>> log = get_logger("demo")
>>> log.info("hello")
"""

from __future__ import annotations

import json
import logging
import numbers
import os
import random
import sys
from pathlib import Path
from typing import Any, Iterable

import numpy as np

# ---------------------------------------------------------------------------
# 项目根目录
# ---------------------------------------------------------------------------
# __file__            -> .../ScanMan/src/utils.py
# .resolve().parent   -> .../ScanMan/src
# .parent             -> .../ScanMan        ← 项目根目录
# 这样无论从哪个目录启动脚本，都能用 PROJECT_ROOT 拼出正确的绝对路径
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def ensure_dir(path: str | os.PathLike) -> Path:
    """确保目录存在，不存在就创建（已存在也不会报错）。

    参数
    ----
    path : str | Path
        目标目录，可以是相对路径，也可以是绝对路径。

    返回
    ----
    Path
        规范化后的 Path 对象，方便链式使用，例如：
        ``ensure_dir("outputs") / "best"``

    为什么需要它
    ------------
    写文件前如果不先建目录，Windows 上会直接抛 FileNotFoundError。
    ``exist_ok=True`` 保证重复调用是安全的（幂等）。
    """
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def set_seed(seed: int = 42) -> None:
    """固定所有随机源，保证实验可复现。

    深度学习里有 4 个地方会产生随机性，必须全部固定：
        1. Python 内置 random        → random.seed()
        2. NumPy                     → np.random.seed()
        3. PyTorch（CPU + 所有 GPU） → torch.manual_seed() / cuda.manual_seed_all()
        4. Python 的哈希随机化        → 环境变量 PYTHONHASHSEED
           （影响 set/dict 的遍历顺序，进而影响数据划分顺序）

    注意
    ----
    这里 **没有** 开启 ``torch.use_deterministic_algorithms(True)``。
    完全确定性会让训练速度下降 20%~50%，对调参实验来说不划算。
    如果论文复现需要严格一致，可以手动加上。
    """
    random.seed(seed)
    np.random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    try:
        import torch

        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        # cudnn.benchmark=True：让 cudnn 自动挑选最快的卷积算法
        # 代价是每次运行结果可能有极小差异，但换来明显提速
        torch.backends.cudnn.benchmark = True
    except ImportError:  # pragma: no cover
        # 如果环境里还没装 torch（比如只想跑数据处理），就跳过这部分
        pass


def get_logger(name: str = "scanman", level: int = logging.INFO) -> logging.Logger:
    """构造一个输出到标准输出的 logger。

    参数
    ----
    name : str
        logger 名字。同名 logger 在 Python 中是全局唯一的。
    level : int
        日志级别，默认 INFO。

    返回
    ----
    logging.Logger

    设计要点
    --------
    - **幂等**：函数开头的 ``if logger.handlers: return`` 保证重复调用
      不会重复添加 handler（否则同一条日志会被打印好几遍）。
    - ``logger.propagate = False``：阻止日志向 root logger 冒泡，
      避免被其他库的 handler 重复输出。
    - 日志格式固定为 ``[时:分:秒] 级别 消息``，训练时方便肉眼扫。

    使用示例
    --------
    >>> log = get_logger("train")
    >>> log.info("开始训练")
    [12:00:00] INFO    开始训练
    """
    logger = logging.getLogger(name)
    # 已经有 handler 说明之前初始化过，直接复用，防止日志重复打印
    if logger.handlers:
        return logger
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    )
    logger.addHandler(handler)
    # 不要向上传递给 root logger，否则会被重复输出
    logger.propagate = False
    return logger


def truncate_code(code: str, max_chars: int = 8000, head_ratio: float = 0.6) -> str:
    """对代码做「头 + 尾」截断。

    参数
    ----
    code : str
        原始代码文本。
    max_chars : int
        截断后最多保留多少个字符，默认 8000。
    head_ratio : float
        头部保留的比例，默认 0.6（即头 60%、尾 40%）。

    返回
    ----
    str
        截断后的代码；如果原文本没超长则原样返回。

    为什么要头尾都留（这是本项目的一个关键设计）
    -------------------------------------------
    代码漏洞的关键信息高度集中在两个位置：

    - **函数头部**：参数声明、输入校验、边界检查、缓冲区大小定义
      （例如 ``char buf[10]`` 就决定了后面会不会溢出）
    - **函数尾部**：返回值处理、内存释放（``free``/``close``）、
      错误分支、锁的释放

    如果像常规做法那样只保留前 N 个字符，函数尾部的 ``free()``、
    ``return`` 检查就全丢了，模型很难判断出 use-after-free、资源泄漏类漏洞。
    实测头尾保留策略明显优于单纯截尾。

    中间被丢弃的部分会用一句注释占位，让模型知道"这里断过"。

    示例
    ----
    >>> truncate_code("a" * 100, max_chars=10, head_ratio=0.6)
    'aaaaaa\\n/* ... [中间代码已截断] ... */\\naaaa'
    """
    code = code or ""
    if len(code) <= max_chars:
        return code
    # 按比例算出头部和尾部各保留多少字符
    head_len = int(max_chars * head_ratio)
    tail_len = max_chars - head_len
    return code[:head_len] + "\n/* ... [中间代码已截断] ... */\n" + code[-tail_len:]


def read_jsonl(path: str | os.PathLike) -> Iterable[dict]:
    """逐行读取 JSONL 文件（生成器，内存友好）。

    参数
    ----
    path : str | Path
        JSONL 文件路径，每行是一个独立 JSON 对象。

    返回
    ----
    Iterable[dict]
        生成器，逐个吐出解析后的字典。

    说明
    ----
    这里用 ``yield`` 而不是一次性读进 list，所以即使文件有几十 GB，
    内存占用也只有一行的大小。解析失败的行会被静默跳过（容错）。
    """
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                # 单行损坏不影响整体，跳过即可
                continue


def write_jsonl(records: Iterable[dict], path: str | os.PathLike) -> int:
    """把记录写入 JSONL 文件。

    参数
    ----
    records : Iterable[dict]
        待写入的记录。
    path : str | Path
        输出路径，父目录会自动创建。

    返回
    ----
    int
        实际写入的条数。

    说明
    ----
    ``ensure_ascii=False`` 让中文按原样写入而不是转义成 ``\\u4e2d\\u6587``，
    既省空间，人也能直接看懂。
    """
    ensure_dir(Path(path).parent)
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    return n


def human_int(n: int) -> str:
    """把整数格式化成带千分位的字符串，便于日志阅读。

    示例
    ----
    >>> human_int(15147)
    '15,147'
    """
    return f"{n:,}"


def to_int_label(value: Any) -> int | None:
    """把 gold 标签转成 ``int``；转不了就返回 ``None``。

    为什么需要它
    ------------
    同一个 ``label`` 字段在不同文件里有**两种形态**：

    - 正式测试集（``data/processed/*_test.jsonl``）里是类别下标（int）
    - 人工用例（``docs/test_cases/classification_test_cases.jsonl``）里是
      CWE 名字（``"CWE-120"``）

    早期各脚本一律写 ``int(rec["label"])``，遇到 CWE 名字直接
    ``ValueError`` 崩掉整个批量流程。统一走这个函数，让调用方决定
    "比不了就跳过"，而不是让脚本挂掉。

    参数
    ----
    value : Any
        原始标签值。

    返回
    ----
    int | None
        能安全转成整数时返回该整数（bool 视为非法，避免 ``True -> 1`` 这种
        静默误读）；否则返回 ``None``。
    """
    if value is None or isinstance(value, bool):
        return None
    # numpy 的整数类型不是内置 int，但都属于 numbers.Integral
    if isinstance(value, numbers.Integral):
        return int(value)
    if isinstance(value, float):
        return int(value) if float(value).is_integer() else None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            return None
    return None
