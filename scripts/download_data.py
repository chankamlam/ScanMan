"""数据集下载脚本。

从 HuggingFace 下载 CVEfixes 漏洞数据集，并支持国内镜像加速。

用法
----
    python scripts/download_data.py --list                    # 查看可用数据集
    python scripts/download_data.py --datasets cvefixes       # 下载 CVEfixes
    python scripts/download_data.py --datasets all --mirror hf-mirror   # 用国内镜像

断点续传
--------
每个文件先下载到 ``xxx.part``，下完才改名成正式文件名。
中途中断后重新执行，会从已下载的字节数继续，不会白下。
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import resolve_path  # noqa: E402
from src.utils import ensure_dir, get_logger, human_int  # noqa: E402

log = get_logger("download")

# ---------------------------------------------------------------------------
# 数据集清单
# ---------------------------------------------------------------------------
# 结构：数据集名 -> {repo: HF仓库, files: 仓库内文件列表, subdir: 本地子目录,
#                    desc: 说明, size: 大致体积}
#
# 为什么只留 CVEfixes？
#   它直接来自 NVD 的 CVE 修复提交，带 CWE 标注，检测（二分类）和
#   分类（CWE 多分类）两个任务都能做。其他数据集（BigVul / DiverseVul /
#   CodeXGLUE）已从本项目移除。
DATASETS: dict[str, dict] = {
    "cvefixes": {
        "repo": "hitoshura25/cvefixes",
        # 3 个 parquet 分片，用列表推导式生成文件名
        "files": [f"data/train-{i:05d}-of-00003.parquet" for i in range(3)],
        "subdir": "cvefixes",
        "desc": "CVEfixes 1.0.8 函数级衍生版：13,000 条 CVE 修复记录，含 vulnerable_code / "
                "fixed_code / cwe_id（269 个 CWE）。漏洞检测 + 漏洞分类首选。",
        "size": "~1.2 GB",
    },
}

# 支持的下载源。国内访问 huggingface.co 慢时换成 hf-mirror.com
MIRRORS = {
    "huggingface": "https://huggingface.co",
    "hf-mirror": "https://hf-mirror.com",
    "modelscope": "https://www.modelscope.cn",
}


def download_file(repo: str, filename: str, dest: Path, endpoint: str) -> bool:
    """下载单个文件，支持断点续传。

    参数
    ----
    repo : str
        HuggingFace 仓库名，例如 ``hitoshura25/cvefixes``。
    filename : str
        仓库内的文件相对路径，例如 ``data/train-00000-of-00003.parquet``。
    dest : Path
        本地保存路径（完整文件名，不带 .part）。
    endpoint : str
        下载站点前缀，例如 ``https://huggingface.co``。

    返回
    ----
    bool
        下载成功返回 True，失败返回 False。

    断点续传原理
    ------------
    1. 检查 ``dest.part`` 是否存在，存在就取它的大小作为已下载字节数 pos
    2. 请求头带上 ``Range: bytes={pos}-``，告诉服务器"从第 pos 字节开始给我"
    3. 服务器返回 206 Partial Content 时用追加模式（"ab"）写文件
    4. 下完后把 .part 改名成正式文件名（改名是原子操作，不会出现半个文件）
    """
    import requests

    url = f"{endpoint}/datasets/{repo}/resolve/main/{filename}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")  # 临时文件名

    # 看看之前下到哪了
    pos = tmp.stat().st_size if tmp.exists() else 0

    headers = {"User-Agent": "vuln-bert-downloader/1.0"}
    if pos:
        headers["Range"] = f"bytes={pos}-"
        log.info("断点续传 %s（已下载 %s）", dest.name, human_int(pos))

    try:
        # stream=True 表示不一次性把响应读进内存，而是边收边写
        with requests.get(url, stream=True, timeout=60, headers=headers,
                          allow_redirects=True) as r:
            # 416 = Range 超出文件大小，说明其实已经下完了
            if r.status_code == 416:
                tmp.rename(dest)
                return True
            r.raise_for_status()

            total = int(r.headers.get("Content-Length", 0)) + pos
            # 只有服务器真的返回了 206 才用追加模式，否则说明它忽略了 Range，要重下
            mode = "ab" if pos and r.status_code == 206 else "wb"
            if mode == "wb":
                pos = 0
            done = pos
            with open(tmp, mode) as f:
                # 每次读 1MB，兼顾速度和内存
                for chunk in r.iter_content(chunk_size=1 << 20):
                    if not chunk:
                        continue
                    f.write(chunk)
                    done += len(chunk)
                    if total:
                        pct = done / total * 100
                        # \r 让进度在同一行刷新，而不是刷屏
                        print(f"\r    {dest.name}: {pct:5.1f}%  "
                              f"({done/1048576:.1f}/{total/1048576:.1f} MB)", end="", flush=True)
        print()
        tmp.rename(dest)  # 下载完成，改名
        return True
    except Exception as e:  # noqa: BLE001
        print()
        log.error("下载失败 %s: %s", url, e)
        return False


def main() -> None:
    """命令行入口。"""
    parser = argparse.ArgumentParser(description="下载代码漏洞数据集")
    parser.add_argument("--datasets", default="all",
                        help="逗号分隔的数据集名，或 all")
    parser.add_argument("--list", action="store_true", help="列出可用数据集")
    parser.add_argument("--mirror", default=None,
                        help="huggingface | hf-mirror | 自定义 https:// 前缀")
    parser.add_argument("--raw-dir", default="data/raw")
    args = parser.parse_args()

    # ---- 只列出数据集，不下载 ----
    if args.list:
        print("\n可用数据集：\n" + "=" * 76)
        for k, v in DATASETS.items():
            print(f"\n  {k}   [{v['size']}]   -> data/raw/{v['subdir']}/")
            print(f"    来源: https://huggingface.co/datasets/{v['repo']}")
            print(f"    说明: {v['desc']}")
        print("\n" + "=" * 76 + "\n")
        return

    # ---- 确定下载源 ----
    # 优先级：命令行参数 > 环境变量 HF_ENDPOINT > 默认官方源
    endpoint = args.mirror or os.environ.get("HF_ENDPOINT") or MIRRORS["huggingface"]
    if endpoint in MIRRORS:
        endpoint = MIRRORS[endpoint]
    endpoint = endpoint.rstrip("/")
    log.info("下载源: %s", endpoint)

    # ---- 解析要下载哪些数据集 ----
    names = list(DATASETS) if args.datasets == "all" else [s.strip() for s in args.datasets.split(",")]
    raw_dir = resolve_path(args.raw_dir)
    ensure_dir(raw_dir)

    failed: list[str] = []
    for name in names:
        if name not in DATASETS:
            log.warning("跳过未知数据集: %s", name)
            continue
        spec = DATASETS[name]
        log.info("=" * 76)
        log.info("开始下载 %s -> %s", name, raw_dir / spec["subdir"])
        for fn in spec["files"]:
            dest = raw_dir / spec["subdir"] / Path(fn).name
            # 已经下好的直接跳过，支持重复运行
            if dest.exists() and dest.stat().st_size > 0:
                log.info("已存在，跳过: %s", dest.name)
                continue
            ok = download_file(spec["repo"], fn, dest, endpoint)
            if not ok:
                failed.append(f"{name}/{fn}")

    # ---- 汇总结果 ----
    log.info("=" * 76)
    if failed:
        log.error("以下文件下载失败，请重试或换镜像源：\n  " + "\n  ".join(failed))
    else:
        log.info("全部数据集下载完成 ✅  原始数据位于 %s", raw_dir)


if __name__ == "__main__":
    main()
