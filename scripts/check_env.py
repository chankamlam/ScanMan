"""环境自检脚本 —— 训练前先跑这个。

作用
----
一次性检查 4 件事，把问题提前暴露出来：

    1. Python 版本是否够新
    2. 依赖包是否装全（torch / transformers / sklearn ...）
    3. 有没有 GPU、显存多大、建议的 batch_size
    4. 数据是否已下载、是否已构建、预训练模型是否完整

用法
----
    python scripts/check_env.py

输出里的标记含义：
    [ OK ]   正常
    [WARN]   不致命，但建议处理（比如没 GPU 会跑得很慢）
    [FAIL]   必须解决，否则后面一定跑不起来
"""

from __future__ import annotations

import importlib
import json
import platform
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 把项目根目录加入模块搜索路径
# ---------------------------------------------------------------------------
# 本文件位于 scripts/ 下，直接运行 `python scripts/check_env.py` 时，
# Python 只会把 scripts/ 加入 sys.path，导致 `from src.config import ...` 报错。
# 下面这行把上一级目录（项目根目录）也加进去，问题就解决了。
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import resolve_path  # noqa: E402
from src.utils import PROJECT_ROOT, human_int  # noqa: E402

# 三种状态标记，统一在这里定义，避免各处硬编码字符串写错
OK, WARN, BAD = "[ OK ]", "[WARN]", "[FAIL]"


def check_python() -> None:
    """检查 Python 版本与运行平台。

    PyTorch 2.x 要求 Python >= 3.8，但 3.9 以下很多新语法不支持，
    所以低于 3.9 时给出警告。
    """
    print(f"{OK} Python {sys.version.split()[0]}  ({platform.system()} {platform.machine()})")
    if sys.version_info < (3, 9):
        print(f"{WARN} 建议使用 Python 3.9+")


def check_packages() -> dict:
    """逐个导入依赖包，检查是否安装并打印版本号。

    返回
    ----
    dict
        ``{包名: 版本号}``，只包含成功导入的包。

    说明
    ----
    用 ``importlib.import_module`` 而不是直接 import，是为了能按字符串名字
    循环检查，也方便捕获 ImportError 继续往下走（而不是直接崩掉）。

    这里额外做了一件事：**识别"被项目内同名文件顶替"的情况**。
    最典型的是本项目曾经的 ``src/datasets.py`` 和第三方包 ``datasets`` 重名——
    只要 ``src/`` 出现在 sys.path 上（PyCharm 把 src 标成 Sources Root、
    或手工设了 PYTHONPATH），``import datasets`` 就会加载到项目自己的那个文件，
    报出 ``attempted relative import with no known parent package``，
    而这里只能看到一句"未安装"，非常容易误判成"包没装"。
    所以导入失败时先查一次项目里有没有同名文件；导入成功时也确认一下
    加载到的是不是真的第三方包。
    """
    pkgs = ["torch", "transformers", "datasets", "pandas", "pyarrow",
            "sklearn", "numpy", "yaml", "requests", "huggingface_hub"]
    found = {}
    for p in pkgs:
        try:
            m = importlib.import_module(p)
        except ImportError:
            shadow = find_project_namesake(p)
            if shadow:
                print(f"{BAD} {p:<16} 被项目内同名文件顶替，不是没安装")
                print(f"       顶替者：{shadow}")
                print(f"       原因：import {p} 加载到了它，而不是第三方包。")
                print(f"       处理：给该文件改名，或不要把 src/ 加进 "
                      f"PYTHONPATH / PyCharm 的 Sources Root。")
            else:
                print(f"{BAD} {p:<16} 未安装")
            continue

        # 即使导入成功，也要确认加载的不是项目内部的同名文件
        origin = getattr(m, "__file__", None)
        if origin and is_inside_project(origin):
            print(f"{BAD} {p:<16} 加载到了项目内文件，不是真正的第三方包")
            print(f"       实际加载：{origin}")
            print(f"       处理：给该文件改名。")
            continue

        ver = getattr(m, "__version__", "?")
        found[p] = ver
        print(f"{OK} {p:<16} {ver}")
    return found


def find_project_namesake(pkg: str) -> str | None:
    """在项目目录里查找与第三方包同名的 ``.py`` 文件。

    参数
    ----
    pkg : str
        包名，例如 ``datasets``。

    返回
    ----
    str | None
        找到时返回该文件的路径，没找到返回 None。

    只查 ``<项目根>/``、``<项目根>/src/``、``<项目根>/scripts/`` 三处，
    这三处正是可能被塞进 sys.path 的位置。
    """
    for sub in (PROJECT_ROOT, PROJECT_ROOT / "src", PROJECT_ROOT / "scripts"):
        f = sub / f"{pkg}.py"
        if f.exists():
            return str(f)
    return None


def is_inside_project(path: str) -> bool:
    """判断某个文件路径是否落在项目目录内部。

    参数
    ----
    path : str
        模块的 ``__file__``。

    返回
    ----
    bool
        在项目内部返回 True。

    说明：第三方包装在 site-packages 里，一定不在项目目录下，
    所以"在项目内部"就等价于"被同名文件顶替了"。
    """
    try:
        resolved = Path(path).resolve()
    except OSError:
        return False
    return resolved == PROJECT_ROOT or PROJECT_ROOT in resolved.parents


def check_hardware() -> None:
    """检查 GPU 是否可用，并给出 batch_size 建议。

    显存与 batch_size 的经验对照（max_length=512 时）：
        8 GB   → batch_size 8
        16 GB  → batch_size 16
        24 GB  → batch_size 32
        40 GB+ → batch_size 64

    如果没有 GPU，会提示如何安装 CUDA 版 PyTorch。
    """
    try:
        import torch
    except ImportError:
        print(f"{BAD} torch 未安装，跳过硬件检查")
        return

    if torch.cuda.is_available():
        n = torch.cuda.device_count()
        print(f"{OK} CUDA 可用，GPU 数量 = {n}")
        for i in range(n):
            p = torch.cuda.get_device_properties(i)
            print(f"       GPU{i}: {p.name}  显存 {p.total_memory/1024**3:.1f} GB  "
                  f"算力 sm_{p.major}{p.minor}")
        # bf16 需要 Ampere 架构（sm_80）以上，比如 A100 / RTX 30 系
        print(f"{OK} 混合精度：fp16=支持, bf16="
              f"{'支持' if torch.cuda.is_bf16_supported() else '不支持'}")
        print("     建议 batch_size：8GB→8, 16GB→16, 24GB→32, 40GB+→64")
    else:
        print(f"{WARN} 未检测到 CUDA，将使用 CPU 训练（非常慢，仅适合冒烟测试）")
        print("      如需 GPU：pip install torch --index-url "
              "https://download.pytorch.org/whl/cu121")


def check_data() -> None:
    """检查原始数据和处理后的数据是否就绪。

    分两部分检查：
        data/raw/        下载的原始数据集（parquet / jsonl）
        data/processed/  构建好的训练数据（统一 JSONL + 标签映射）
    """
    # ---------------- 原始数据 ----------------
    raw = resolve_path("data/raw")
    print("\n--- 原始数据 data/raw ---")
    if not raw.exists():
        print(f"{WARN} 目录不存在，请运行 python scripts/download_data.py --datasets all")
        return
    total = 0
    for sub in sorted(raw.iterdir()):
        if sub.is_dir():
            # 排除还没下完的 .part 临时文件
            files = [f for f in sub.rglob("*") if f.is_file() and not f.name.endswith(".part")]
            size = sum(f.stat().st_size for f in files)
            total += size
            print(f"{OK if files else WARN} {sub.name:<24} {len(files)} 个文件  "
                  f"{size/1048576:.1f} MB")
    print(f"     合计 {total/1048576:.1f} MB")

    # ---------------- 处理后数据 ----------------
    print("\n--- 处理后数据 data/processed ---")
    proc = resolve_path("data/processed")
    if not proc.exists() or not any(proc.glob("*.jsonl")):
        print(f"{WARN} 尚未构建，请运行 python scripts/build_dataset.py --source cvefixes")
        return
    # 遍历每个数据源的统计文件，打印规模信息
    for stats_file in sorted(proc.glob("*_stats.json")):
        st = json.loads(stats_file.read_text(encoding="utf-8"))
        print(f"{OK} 数据源 {st['source']}  原始 {human_int(st['total_raw'])} 条")
        for task, info in st.get("tasks", {}).items():
            parts = ", ".join(f"{k}={human_int(v['n'])}" for k, v in info["splits"].items())
            print(f"       {task:<16} 类别数={info['num_labels']:<4} {parts}")


def check_models() -> None:
    """检查本地是否已经下载了预训练模型。

    判断标准很简单：目录里有 config.json 就说明是完整的 HuggingFace 模型目录。
    没有也不影响训练——transformers 会自动从网上下载。
    """
    print("\n--- 本地模型 models/ ---")
    md = resolve_path("models")
    if not md.exists() or not any(md.iterdir()):
        print(f"{WARN} 为空，将自动从 HuggingFace 在线拉取（也可先运行 download_model.py）")
        return
    for d in sorted(md.iterdir()):
        has = (d / "config.json").exists()
        print(f"{OK if has else WARN} {d.name}  "
              f"{'完整' if has else '不完整'}")


def main() -> None:
    """按顺序执行所有检查项。"""
    print("=" * 78)
    print(" 代码漏洞检测 / 漏洞分类 —— BERT 微调环境自检")
    print("=" * 78)
    check_python()
    print("\n--- Python 依赖 ---")
    check_packages()
    print("\n--- 硬件 ---")
    check_hardware()
    check_data()
    check_models()
    print("\n" + "=" * 78)
    print("自检结束。若有 FAIL 项，请按提示先解决再训练。")
    print("=" * 78)


if __name__ == "__main__":
    main()
