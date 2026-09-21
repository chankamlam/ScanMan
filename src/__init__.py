"""代码漏洞检测 / 漏洞分类（BERT 微调）工具包。

本包把可复用的逻辑拆成 6 个模块，脚本只负责"串流程"：

    config.py    配置加载（YAML + 默认值合并）
    utils.py     通用工具（种子、日志、头尾截断、JSONL 读写）
    data.py      Torch Dataset + 动态 padding 批处理器
    models.py    VulnClassifier（BERT 编码器 + 线性分类头）
    metrics.py   二分类 / 多分类评估指标
    extract.py   tree-sitter 函数抽取（把源码切成一个个函数）

注意
----
数据加载模块**故意不叫** ``datasets.py``：HuggingFace 有个同名第三方包 ``datasets``，
一旦 ``src/`` 被加进 sys.path（PyCharm 把 src 标记为 Sources Root、或手动设了
PYTHONPATH），``import datasets`` 就会加载到本项目的这个文件而不是真正的那个包，
报出 ``ImportError: attempted relative import with no known parent package``。
改名成 ``data.py`` 之后，两种启动方式都不会再互相干扰。

典型用法
--------
>>> from src.config import load_config
>>> from src.models import VulnClassifier, build_tokenizer
>>> from src.data import VulnDataset, DynamicPaddingCollator
"""

__version__ = "1.0.0"
