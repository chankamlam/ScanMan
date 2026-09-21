"""Web 后端：把「上传几个源文件 → 真跑模型 → 返回扫描报告」做成两个 HTTP 接口。

为什么需要这个脚本
------------------
``scripts/scan_project.py`` 是**命令行**工具：它要一个目录路径，扫完写文件。
而浏览器出于安全**拿不到本地文件的绝对路径**（``<input type=file>`` 只给文件名），
所以网页版必须先让用户选文件、把**内容**读出来 POST 上来，由服务端落盘再走同一条管线。

本脚本只做「HTTP ↔ 原有管线」的适配，**不重写任何扫描逻辑**：
``scan_files`` / ``run_inference`` / ``run_classification`` / ``build_report``
四个函数直接从 ``scripts.scan_project`` import，保证网页版和命令行版**结果逐条一致**。

用法
----
    # 默认就用项目里这两个检查点，监听 127.0.0.1:8000（要和 web/vite.config.ts 的 proxy 对上）
    python scripts/serve.py

    # 换模型 / 换端口
    python scripts/serve.py --detector outputs/<run>/best --port 8000

前端在 ``web/``，另开一个终端 ``npm run dev`` 起在 5173。

接口
----
``GET  /api/health``
    模型状态。前端靠它显示「加载中／就绪／失败」，并据此决定「开始检测」能不能点。

``POST /api/scan``
    请求 ``{"files": [{"client_id": ..., "name": ..., "content_b64": ...}]}``，
    返回 ``{"report": <ScanReport>, "uploads": [...]}``。
    报告 schema 见 ``docs/08_全流程与接口规范.md`` 第 3 节，与前端 ``web/src/types.ts`` 一一对应。

几个必须知道的约束（踩过就知道疼）
----------------------------------
1. **锁必须包住整个 handler，不只是推理那一段。**
   ``src/extract.py`` 的 ``_load_parser`` 是 ``lru_cache`` 的**共享单例**，
   而它自己的 docstring 写着「``Parser`` 本身不是线程安全的」。
   抽取发生在 GPU 之外 —— 若只锁住推理，两个并发请求会同时对**同一个 Parser**
   调 ``parse()``，而 tree-sitter 是 C 扩展，冲突表现为 **access violation，
   直接杀进程**，没有 traceback、没有日志。所以这里用一把粗锁，不细分粒度。

2. **模型加载和 torch 导入都必须发生在 ``app.run()`` 之后。**
   ``scripts/predict.py`` 顶层就 ``import torch``，在 Windows 上要 5~15 秒。
   若在模块顶层导入，8000 端口要等 torch 导完才打开，前端第一次请求拿到的是
   ECONNREFUSED，界面显示「连不上后端」—— 比「模型加载中」糟得多。
   同理 ``debug=True`` 会触发 reloader **再起一个子进程**重跑整个模块，
   那就是 1 GB 权重 × 2 + 两个 CUDA context，6 GB 卡直接 OOM。

3. **上传的字节必须原样落盘。**
   前端用 base64 传原始字节，而不是读成 UTF-8 字符串。
   因为 ``src/extract.py`` 是**以字节为真相源**的（能正确处理 GBK 等非 UTF-8 文件），
   中间做一次 UTF-8 往返会让字节偏移改变，于是 ``start_line`` / ``end_line`` 全错，
   界面上源码行号指向错误的位置。

退出码
------
正常退出 ``0``；参数或环境有问题（模型目录不存在、任务类型不对）``2``。
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import io
import re
import shutil
import sys
import tempfile
import threading
import traceback
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, jsonify, request  # noqa: E402

from src.config import resolve_path  # noqa: E402
from src.extract import (  # noqa: E402
    LANGUAGE_BY_EXT,
    MAX_FILE_BYTES,
    extract_functions,
)
from src.utils import get_logger  # noqa: E402

# ⚠️ 一律用限定名 `scripts.xxx`，**不要**裸写 `import predict`。
# `scripts/` 没有 __init__.py，靠隐式命名空间包工作；脚本启动时 `<root>/scripts`
# 和 `<root>` 会同时在 sys.path 上，裸 import 会生成**两个模块对象、两个类**，
# isinstance / 身份比较会静默失效。
from scripts.scan_project import (  # noqa: E402
    build_report,
    run_classification,
    run_inference,
    scan_files,
)

log = get_logger("serve")

#: 一次请求最多接受几个文件。
MAX_FILES = 32

#: 请求体上限。base64 有 4/3 膨胀，再留一点 JSON 开销。
#: 不设这个的话 Flask 会把整个请求体缓冲进内存 —— `extract_from_file` 里的
#: too_large 分支生效时，字节**早已在内存里**了。
MAX_CONTENT_LENGTH = 64 * 1024 * 1024

#: 文件名白名单。一行就能消灭「路径穿越 / 空名 / 超长名 / 控制字符」整类问题。
SAFE_NAME = re.compile(r"[A-Za-z0-9._-]{1,120}")

#: Windows 保留设备名。往目录里写一个叫 `NUL` 的文件在 Windows 上不会干净地失败。
_WIN_RESERVED = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + [f"COM{i}" for i in range(1, 10)]
    + [f"LPT{i}" for i in range(1, 10)]
)

#: 扫描互斥锁。粗粒度是刻意的，理由见模块 docstring 第 1 条。
SCAN_LOCK = threading.Lock()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# ============================================================================
# 上传参数
# ============================================================================


@dataclass
class Upload:
    """一个通过校验的上传文件。"""

    client_id: str
    name: str
    data: bytes


class UploadError(ValueError):
    """请求体不合法。消息会原样回给前端，所以要写成人能看懂的中文。"""


def _parse_uploads(payload) -> list[Upload]:
    """把请求体校验并解码成一组 :class:`Upload`。

    这里拒绝的东西**要返回 400，而不是记进报告的 skipped** ——
    前端需要把「你传错文件了」和「这个文件解析不了」分开显示：
    前者是用户的错，改一下就好；后者是扫描器的结论，是报告的一部分。
    """
    if not isinstance(payload, dict):
        raise UploadError("请求体必须是 JSON 对象")
    raw = payload.get("files")
    if not isinstance(raw, list) or not raw:
        raise UploadError("files 必须是非空数组")
    if len(raw) > MAX_FILES:
        raise UploadError(f"一次最多 {MAX_FILES} 个文件，收到 {len(raw)} 个")

    uploads: list[Upload] = []
    for i, item in enumerate(raw):
        where = f"第 {i + 1} 个文件"
        if not isinstance(item, dict):
            raise UploadError(f"{where}不是对象")

        client_id = item.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            raise UploadError(f"{where}缺少 client_id")

        name = item.get("name")
        if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
            raise UploadError(
                f"{where}的文件名不合法：{name!r}（只允许字母、数字、点、下划线、连字符）"
            )
        if name.split(".")[0].upper() in _WIN_RESERVED:
            raise UploadError(f"{where}的文件名 {name!r} 是 Windows 保留名，换一个")

        ext = Path(name).suffix.lower()
        if ext not in LANGUAGE_BY_EXT:
            raise UploadError(
                f"{where}的扩展名 {ext or '(无)'} 不受支持；"
                f"支持：{'、'.join(sorted(LANGUAGE_BY_EXT))}"
            )

        b64 = item.get("content_b64")
        if not isinstance(b64, str):
            raise UploadError(f"{where}缺少 content_b64")
        try:
            data = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise UploadError(f"{where}的 base64 解不开：{exc}") from exc

        if not data:
            raise UploadError(f"{where}是空文件")
        if len(data) > MAX_FILE_BYTES:
            raise UploadError(
                f"{where}有 {len(data):,} 字节，超过上限 {MAX_FILE_BYTES:,} 字节"
            )

        uploads.append(Upload(client_id=client_id, name=name, data=data))

    return uploads


# ============================================================================
# 模型
# ============================================================================


class ModelRegistry:
    """检测器 + 分类器，进程内只加载一次。

    ``status`` 的语义是给前端看的：**只有 ``ready`` 才代表「点了就快」**。
    所以权重加载完之后还要做两件预热，全都完成了才翻 ``ready``：

    * **tree-sitter parser** —— ``_load_parser`` 是懒加载的，每个语言第一次解析
      要付 ``__import__`` 语法包的开销。全项目没有任何预热调用，这里补上。
    * **第一次 CUDA 前向** —— cuDNN / cuBLAS 的句柄创建和 kernel JIT
      在笔记本的 3060 上要好几秒。不预热的话用户第一次点「开始检测」会觉得卡住了。
    """

    def __init__(
        self,
        detector_path: str,
        classifier_path: str,
        device: str | None,
        batch_size: int = 16,
    ):
        # 用 resolve_path 解析：相对路径按**项目根**算，从任何 cwd 启动都对
        self.detector_path = str(resolve_path(detector_path))
        self.classifier_path = str(resolve_path(classifier_path))
        self.device_arg = device
        self.batch_size = batch_size

        self.status = "loading"  # loading | ready | error
        self.error: str | None = None

        self.detector = None
        self.classifier = None
        self.device: str | None = None
        self.gpu: str | None = None
        self.threshold: float | None = None
        self.num_labels: int | None = None

    # ---------------------------------------------------------------- 加载

    def load(self) -> None:
        """在后台线程里调用。失败不抛异常，把消息记进 ``error``。"""
        try:
            # 延迟导入：`scripts/predict.py` 顶层就 import torch，
            # 放在这里才不会拖住 8000 端口的开启（见模块 docstring 第 2 条）
            import torch

            from scripts.predict import VulnPredictor

            self.gpu = (
                torch.cuda.get_device_name(0) if torch.cuda.is_available() else None
            )

            log.info("正在加载检测模型：%s", self.detector_path)
            detector = VulnPredictor(self.detector_path, device=self.device_arg)
            # 校验任务类型：`merged_top27_codebert_e20` 和 `merged_detection_codebert`
            # 只差一个路径段，复制粘贴极易搞反，而拿分类模型当检测器用
            # 只会得到一堆无意义的结论。
            if detector.task != "detection":
                raise RuntimeError(
                    f"--detector 指向的检查点任务是 {detector.task!r}，不是 detection"
                )

            log.info("正在加载分类模型：%s", self.classifier_path)
            classifier = VulnPredictor(self.classifier_path, device=self.device_arg)
            if classifier.task != "classification":
                raise RuntimeError(
                    f"--classifier 指向的检查点任务是 {classifier.task!r}，不是 classification"
                )

            self.detector = detector
            self.classifier = classifier
            self.device = str(detector.device)
            self.threshold = detector.threshold
            self.num_labels = classifier.num_labels
            log.info(
                "模型就绪 | 设备=%s | 阈值=%.4f | 类别数=%d",
                self.device, self.threshold, self.num_labels,
            )

            self._preheat()

        except Exception as exc:  # noqa: BLE001 - 加载失败要能让前端看见原因
            self.status = "error"
            self.error = f"{type(exc).__name__}: {exc}"
            log.error("模型加载失败：%s\n%s", self.error, traceback.format_exc())
            return

        self.status = "ready"
        log.info("预热完成，可以开始检测")

    def _preheat(self) -> None:
        """把「第一次调用」的开销提前吃掉，让 ``ready`` 真的意味着快。"""
        # 语法包：用公开的 extract_functions，而不是去够 _load_parser 这个私有函数。
        # 这段探针同时是合法 C 和合法 C++，所以两种语言共用一份。
        probe = "int scanman_warmup(void) { return 0; }"
        for lang in ("c", "cpp"):
            try:
                extract_functions(probe, lang)
            except Exception as exc:  # noqa: BLE001 - 预热失败不该拖垮启动
                log.warning("预热 %s 语法包失败（不影响使用）：%s", lang, exc)

        # CUDA：跑一次真实前向，把 cuDNN/cuBLAS 的初始化代价付掉
        try:
            self.detector.predict([probe])
        except Exception as exc:  # noqa: BLE001
            log.warning("检测模型预热失败（不影响使用）：%s", exc)

    # ---------------------------------------------------------------- 状态

    def health(self) -> dict:
        return {
            "status": self.status,
            "models_loaded": self.status == "ready",
            "device": self.device,
            "gpu": self.gpu,
            "detector": self.detector_path,
            "classifier": self.classifier_path,
            "threshold": self.threshold,
            "num_labels": self.num_labels,
            "error": self.error,
        }


#: 进程内唯一的注册表。在 ``main()`` 里填充 —— 模块顶层不碰它。
registry: ModelRegistry | None = None


# ============================================================================
# 扫描
# ============================================================================


def _run_scan(uploads: list[Upload]) -> tuple[dict, list[dict]]:
    """落盘 → 抽取 → 检测 → 分类 → 组装报告。

    调用方必须已持有 :data:`SCAN_LOCK`。
    """
    assert registry is not None and registry.detector and registry.classifier

    # 每个上传开一个子目录：`build_report` 用 relative_to(root) 算路径，
    # 全部平铺的话两个同名的 test.c 会**静默互相覆盖**（侧栏显示 2 行、
    # 报告里只有 1 条），而且下标和报告条目会对不上。
    tmp = Path(tempfile.mkdtemp(prefix="scanman_web_"))
    try:
        paths: list[Path] = []
        rel_of: list[str] = []
        for i, up in enumerate(uploads):
            sub = tmp / f"{i:04d}"
            sub.mkdir()
            # write_bytes：原样落盘，不做任何编码转换（见模块 docstring 第 3 条）
            (sub / up.name).write_bytes(up.data)
            paths.append(sub / up.name)
            rel_of.append(f"{i:04d}/{up.name}")

        file_results, skipped, _total = scan_files(
            paths, tmp, MAX_FILE_BYTES, outer_only=False
        )
        log.info(
            "已抽取：%d 个文件 / %d 个函数（跳过 %d 个）",
            len(file_results), sum(fr["function_count"] for fr in file_results), len(skipped),
        )

        # run_inference / run_classification 内部无条件调 tqdm 打进度条，
        # 在 HTTP 场景下只会污染控制台。包一层把 stderr 吃掉，
        # 而不去改 scan_project.py —— 那是命令行和 CI 在用的公共代码。
        with contextlib.redirect_stderr(io.StringIO()):
            verdicts = run_inference(registry.detector, file_results, registry.batch_size)
            classifications = run_classification(
                registry.classifier, file_results, verdicts, registry.batch_size
            )

        report = build_report(
            tmp,
            file_results,
            skipped,
            registry.detector_path,
            registry.threshold,
            include_code=True,
            verdicts=verdicts,
            classifications=classifications,
            classifier_checkpoint=registry.classifier_path,
        )

        # root 是临时目录路径，对看报告的人没有意义，覆写掉。
        # 注意是改**响应里的副本**，不是改 build_report —— 它是带 schema_version
        # 的 CI 契约，tests/test_scan_cascade.py 用「只增不改」把它钉死了。
        report["root"] = f"本次上传的 {len(uploads)} 个文件"

        return report, _upload_receipt(uploads, rel_of, file_results, skipped)
    finally:
        # ignore_errors：Windows 上还有句柄没关时 rmtree 会抛 PermissionError，
        # 从 finally 抛出去会把**已经成功的 200 换成 500**，用户白等一场。
        shutil.rmtree(tmp, ignore_errors=True)


def _upload_receipt(
    uploads: list[Upload],
    rel_of: list[str],
    file_results: list[dict],
    skipped: list[dict],
) -> list[dict]:
    """把每个上传和报告里的条目对上，回执给前端。

    为什么不让前端自己按文件名或下标猜：``scan_files`` 在异常和 ``res.error``
    两条路径上都是 ``continue``，**跳过的文件根本不进 file_results** ——
    ``report.files`` 是上传集合的**带洞子序列**，下标对齐会错位，文件名对齐死于重名。
    这里由服务端显式回执，前端只需做一次 Map join。
    """
    scanned = {fr["path"] for fr in file_results}
    reasons = {it["path"]: it["reason"] for it in skipped}

    receipt = []
    for up, rel in zip(uploads, rel_of):
        row = {"client_id": up.client_id, "name": up.name, "path": rel}
        if rel in scanned:
            row["status"] = "scanned"
        else:
            row["status"] = "skipped"
            row["reason"] = reasons.get(rel, "未知原因")
        receipt.append(row)
    return receipt


# ============================================================================
# 路由
# ============================================================================


@app.get("/api/health")
def api_health():
    """模型状态。前端靠它决定「开始检测」能不能点。"""
    if registry is None:
        return jsonify({"status": "loading", "models_loaded": False, "error": None})
    return jsonify(registry.health())


@app.post("/api/scan")
def api_scan():
    """上传源码 → 真跑模型 → 返回报告。"""
    # 先做纯校验再抢锁：请求体不合法时没必要占着扫描锁
    try:
        uploads = _parse_uploads(request.get_json(silent=True))
    except UploadError as exc:
        return jsonify({"error": str(exc)}), 400

    if registry is None or registry.status != "ready":
        status = registry.status if registry else "loading"
        return jsonify({
            "error": "模型还没就绪" if status == "loading" else "模型加载失败",
            "status": status,
            "detail": registry.error if registry else None,
        }), 503

    # 拿不到锁就立刻拒绝，**不排队**：用户可能已经关掉页面了，
    # 排队的那个扫描还是会照样烧 GPU。
    if not SCAN_LOCK.acquire(blocking=False):
        return jsonify({"error": "已有扫描正在进行，请等它跑完再试"}), 409

    try:
        report, receipt = _run_scan(uploads)
    except Exception as exc:  # noqa: BLE001 - 兜底，别让前端只看到一片 HTML 错误页
        log.error("扫描失败：%s\n%s", exc, traceback.format_exc())
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500
    finally:
        SCAN_LOCK.release()

    s = report["summary"]
    log.info(
        "扫描完成：%d 个函数，%d 个命中，%d 个给出了 CWE",
        s["functions_total"], s["functions_suspicious"], s["functions_classified"],
    )
    return jsonify({"report": report, "uploads": receipt})


@app.errorhandler(413)
def api_too_large(_exc):
    """Max-Content-Length 触发时 Flask 默认返回 HTML，前端解不动。"""
    return jsonify({
        "error": f"请求体超过上限 {MAX_CONTENT_LENGTH // (1024 * 1024)} MB，少传几个文件"
    }), 413


@app.errorhandler(404)
def api_not_found(_exc):
    return jsonify({"error": "没有这个接口"}), 404


# ============================================================================
# 入口
# ============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ScanMan 的 Web 后端：上传源码文件，真跑模型，返回扫描报告",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--detector", default="outputs/merged_detection_codebert/best",
        help="检测模型目录（相对路径按项目根解析）",
    )
    parser.add_argument(
        "--classifier", default="outputs/merged_top27_codebert_e20/best",
        help="分类模型目录（相对路径按项目根解析）",
    )
    parser.add_argument("--device", default=None,
                        help="cpu | cuda | mps | cuda:1，默认自动（CUDA > MPS > CPU）")
    parser.add_argument(
        "--port", type=int, default=8000,
        help="监听端口。**必须和 web/vite.config.ts 里 proxy 的 target 一致**",
    )
    parser.add_argument("--batch-size", type=int, default=16, help="推理批大小")
    args = parser.parse_args()

    global registry

    # 先确认模型目录存在，别等用户传完文件才发现路径写错了
    for label, path in (("检测", args.detector), ("分类", args.classifier)):
        resolved = resolve_path(path)
        if not resolved.exists():
            log.error("%s模型目录不存在：%s", label, resolved)
            return 2

    registry = ModelRegistry(
        args.detector, args.classifier, args.device, batch_size=args.batch_size
    )
    # 后台加载：端口先开，前端能立刻拿到 status=loading，而不是 ECONNREFUSED
    threading.Thread(target=registry.load, daemon=True, name="model-loader").start()

    log.info("监听 http://127.0.0.1:%d （前端 dev server 在 5173）", args.port)
    log.info("模型在后台加载，启动后前十几秒 /api/health 会返回 status=loading")

    # 只绑 127.0.0.1，**绝不 0.0.0.0**：这是个无鉴权、会把任意内容
    # 喂给 C 解析器并写盘的开发服务器，而这台是笔记本，可能在公共 Wi-Fi 上。
    #
    # use_reloader=False 是必须的：reloader 会再起一个子进程重跑整个模块，
    # 那就是 1 GB 权重 × 2 + 两个 CUDA context，6 GB 卡直接 OOM。
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False,
            threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
