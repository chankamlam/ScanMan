"""``scripts/serve.py``（Web 后端）的测试。

后端只该做一件事：**把 HTTP 请求翻译成对原有管线的调用**。
所以这里测的全是「翻译」这一层 —— 校验、落盘、回执、拒绝 ——
而不是扫描逻辑本身（那由 ``test_scan_cascade.py`` 覆盖）。

全部用**桩推理器**，不加载权重、不碰 GPU、不起真服务，跑一次 < 1 秒。

三条最要紧的约定
----------------
1. **字节必须原样落盘**。``src/extract.py`` 以字节为真相源解析（能正确处理
   GBK 等非 UTF-8 文件）。如果中间做了 UTF-8 往返，字节偏移会变，于是
   ``start_byte`` / ``start_line`` 全错，界面上的源码行号指向错误的位置。
   ``test_非utf8文件的字节偏移不受影响`` 就是钉这条的。
2. **参数错误返回 400，不记进报告的 skipped**。前端要能区分「你传错文件了」
   和「这个文件解析不了」—— 后者是扫描器的结论，是报告的一部分。
3. **同名文件不能互相覆盖**。全部平铺在临时目录里的话，两个 ``t.c``
   会静默覆盖彼此，侧栏显示 2 行而报告里只有 1 条。
"""

import base64
import threading

import pytest

import scripts.serve as serve
from scripts.serve import MAX_FILE_BYTES, SCAN_LOCK, UploadError, _parse_uploads


# ===========================================================================
# 桩推理器（照抄 test_scan_cascade.py 的做法：不继承真的类）
# ===========================================================================
class StubPredictor:
    """假的 ``VulnPredictor``：按代码里有没有 BAD 标记来判定。"""

    def __init__(self, task: str):
        self.task = task
        self.calls: list[str] = []

    def predict(self, codes: list[str]) -> list[dict]:
        self.calls.extend(codes)
        return [self._one(c) for c in codes]

    def _one(self, code: str) -> dict:
        if self.task == "detection":
            hit = "BAD" in code
            return {
                "label": int(hit),
                "verdict": "vulnerable" if hit else "safe",
                "confidence": 0.9 if hit else 0.1,
                "prob_safe": 0.1 if hit else 0.9,
                "prob_vulnerable": 0.9 if hit else 0.1,
            }
        return {
            "label": 0,
            "cwe": "CWE-119",
            "confidence": 0.8,
            "topk": [{"cwe": "CWE-119", "prob": 0.8},
                     {"cwe": "CWE-20", "prob": 0.1}],
        }


# ===========================================================================
# 夹具与工具
# ===========================================================================
@pytest.fixture
def client(monkeypatch):
    """把全局 registry 换成一个「已就绪 + 桩模型」的实例，返回 Flask 测试客户端。"""
    reg = serve.ModelRegistry("det/best", "clf/best", device=None, batch_size=8)
    reg.detector = StubPredictor("detection")
    reg.classifier = StubPredictor("classification")
    reg.status = "ready"
    reg.threshold = 0.5
    reg.num_labels = 28
    reg.device = "cpu"
    monkeypatch.setattr(serve, "registry", reg)

    serve.app.config["TESTING"] = True
    with serve.app.test_client() as c:
        yield c


def post(client, files: list[tuple[str, str, bytes]]):
    """``[(client_id, name, raw_bytes)]`` → 调一次 ``POST /api/scan``。"""
    body = {
        "files": [
            {
                "client_id": cid,
                "name": name,
                "content_b64": base64.b64encode(raw).decode("ascii"),
            }
            for cid, name, raw in files
        ]
    }
    return client.post("/api/scan", json=body)


VULN_C = b"int bad_copy(char *dst, char *src) { BAD strcpy(dst, src); return 0; }"
SAFE_C = b"int add(int a, int b) { return a + b; }"


# ===========================================================================
# 1. 文件名与内容校验 —— 全部应该是 400，不是 skipped
# ===========================================================================
@pytest.mark.parametrize("bad_name", [
    "../../etc/passwd",      # 路径穿越
    "a/b.c",                 # 路径分隔符
    "..\\..\\x.c",           # Windows 反斜杠穿越
    "NUL",                   # Windows 保留设备名
    "con.c",                 # 保留名带扩展名（大小写不敏感）
    "",                      # 空名
    "x" * 200 + ".c",        # 超长
])
def test_非法文件名被拒(bad_name):
    with pytest.raises(UploadError):
        _parse_uploads({"files": [{
            "client_id": "c1", "name": bad_name, "content_b64": "YQ==",
        }]})


@pytest.mark.parametrize("bad_ext", ["x.txt", "x", "x.exe", "x.c.txt"])
def test_不支持的扩展名被拒(bad_ext):
    with pytest.raises(UploadError):
        _parse_uploads({"files": [{
            "client_id": "c1", "name": bad_ext, "content_b64": "YQ==",
        }]})


def test_扩展名白名单包含_h_因为头文件归_c():
    """.h 在 LANGUAGE_BY_EXT 里归 C —— 别在 serve 层再拦一道。"""
    ups = _parse_uploads({"files": [{
        "client_id": "c1", "name": "foo.h", "content_b64": "YQ==",
    }]})
    assert ups[0].name == "foo.h"


def test_非法输入返回400而不是塞进skipped(client):
    """这是本文件的核心区分：参数错 → 400；文件解析不了 → 报告里的 skipped。"""
    resp = post(client, [("c1", "x.txt", b"int f(void);")])
    assert resp.status_code == 400
    assert "扩展名" in resp.get_json()["error"]


def test_空文件和超大文件被拒(client):
    assert post(client, [("c1", "t.c", b"")]).status_code == 400
    assert post(client, [("c1", "t.c", b"a" * (MAX_FILE_BYTES + 1))]).status_code == 400


def test_files_为空或超量被拒(client):
    assert client.post("/api/scan", json={"files": []}).status_code == 400
    many = [{"client_id": f"c{i}", "name": "t.c", "content_b64": "YQ=="}
            for i in range(serve.MAX_FILES + 1)]
    assert client.post("/api/scan", json={"files": many}).status_code == 400


def test_坏base64被拒(client):
    resp = client.post("/api/scan", json={"files": [
        {"client_id": "c1", "name": "t.c", "content_b64": "这不是 base64!!"},
    ]})
    assert resp.status_code == 400


# ===========================================================================
# 2. 字节保真（本文件最重要的一组）
# ===========================================================================
def test_base64往返后字节完全一致():
    """解出来必须和进去的一模一样，包括 NUL 和非法 UTF-8 序列。"""
    raw = b"\x00\xff\xfe int f(void){}\r\n\x80\x81"
    ups = _parse_uploads({"files": [{
        "client_id": "c1", "name": "t.c",
        "content_b64": base64.b64encode(raw).decode("ascii"),
    }]})
    assert ups[0].data == raw


def test_非utf8文件的字节偏移不受影响(client):
    """GBK 编码的 C 文件：``start_byte`` 必须还是 GBK 里的真实偏移。

    这是**唯一**能钉住「字节没被 UTF-8 往返糟蹋」的断言：
    如果前端用了 ``readAsText()``（按 UTF-8 解码），中文字符会变成替换字符
    U+FFFD —— 而它编码回 UTF-8 是 3 字节，GBK 里一个中文字是 2 字节，
    于是 ``start_byte`` 必然对不上。

    行号倒是对得上（换行数没变），所以**光测行号是测不出这个 bug 的**。
    """
    prefix = "/* 中文注释：这段是 GBK 编码的说明文字 */\n".encode("gbk")
    body = b"int add(int a, int b) { return a + b; }\n"
    src = prefix + body

    # 先确认这份样例真的能区分对错（别让测试自己变成空转）
    assert len(src) != len(src.decode("utf-8", errors="replace").encode("utf-8"))

    resp = post(client, [("c1", "gbk.c", src)])
    assert resp.status_code == 200

    fns = resp.get_json()["report"]["files"][0]["functions"]
    assert len(fns) == 1
    assert fns[0]["name"] == "add"
    assert fns[0]["start_byte"] == len(prefix), "字节偏移错位 —— 内容被当文本处理过"
    # 止于 `}`，不含结尾换行（tree-sitter 的节点范围就是函数体本身）
    assert fns[0]["end_byte"] == len(src) - 1
    assert fns[0]["start_line"] == 2


def test_含NUL的文件被当成二进制跳过而不是报错(client):
    """二进制不是「参数错」，是扫描器的正常结论 —— 走 skipped，返回 200。"""
    resp = post(client, [("c1", "bin.c", b"\x00\x01\x02\x03")])
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["report"]["files"] == []
    assert body["uploads"][0]["status"] == "skipped"
    assert "binary" in body["uploads"][0]["reason"]


# ===========================================================================
# 3. 同名文件与回执对齐
# ===========================================================================
def test_同名文件不互相覆盖(client):
    """两个都叫 t.c 的文件必须都进报告，各自一扫。"""
    resp = post(client, [("c1", "t.c", VULN_C), ("c2", "t.c", SAFE_C)])
    assert resp.status_code == 200
    report = resp.get_json()["report"]

    assert report["summary"]["files_scanned"] == 2, "同名文件被覆盖了"
    paths = sorted(fr["path"] for fr in report["files"])
    assert paths == ["0000/t.c", "0001/t.c"]


def test_回执按client_id精确对齐(client):
    """client_id → 报告条目，一次 join 就能对上，前端不用猜。"""
    resp = post(client, [
        ("aaa", "vuln.c", VULN_C),
        ("bbb", "safe.c", SAFE_C),
        ("ccc", "bin.c", b"\x00\x01"),        # 这个会被跳过
    ])
    receipt = {u["client_id"]: u for u in resp.get_json()["uploads"]}
    assert set(receipt) == {"aaa", "bbb", "ccc"}

    assert receipt["aaa"]["status"] == "scanned"
    assert receipt["bbb"]["status"] == "scanned"
    assert receipt["ccc"]["status"] == "skipped"
    assert receipt["ccc"]["reason"]

    # 报告里的 path 和回执里的 path 是同一个名字空间
    report_paths = {fr["path"] for fr in resp.get_json()["report"]["files"]}
    assert receipt["aaa"]["path"] in report_paths
    assert receipt["ccc"]["path"] not in report_paths, "跳过的文件不该出现在 files 里"


def test_跳过的文件让报告成为带洞子序列(client):
    """下标对齐会错位 —— 这正是回执要用 client_id 而不是下标的原因。"""
    resp = post(client, [
        ("c1", "bin.c", b"\x00\x01"),   # 跳过
        ("c2", "ok.c", VULN_C),          # 成功
    ])
    report = resp.get_json()["report"]
    assert len(report["files"]) == 1
    assert report["files"][0]["path"] == "0001/ok.c", "路径里的序号必须还是原来那个"


# ===========================================================================
# 4. 级联与报告契约
# ===========================================================================
def test_只对命中函数跑分类(client):
    resp = post(client, [("c1", "f.c", VULN_C + b"\n" + SAFE_C)])
    clf = serve.registry.classifier
    assert len(clf.calls) == 1, "分类器只该看到有 BAD 的那个函数"
    assert "bad_copy" in clf.calls[0]


def test_报告过只增不改的老字段断言(client):
    """复用 ``test_scan_cascade.py`` 钉的那套契约，保证 Web 路径产出同样的报告。"""
    report = post(client, [("c1", "f.c", VULN_C)]).get_json()["report"]
    for key in ("schema_version", "tool", "generated_at", "root", "checkpoint",
                "threshold", "classifier_checkpoint", "summary", "skipped", "files"):
        assert key in report, f"顶层键 {key} 丢了"
    for key in ("files_scanned", "files_skipped", "functions_total",
                "functions_suspicious", "functions_classified", "languages"):
        assert key in report["summary"], f"summary 键 {key} 丢了"

    fn = report["files"][0]["functions"][0]
    assert fn["verdict"] == "vulnerable"
    assert fn["cwe"] == "CWE-119"
    assert "cwe_topk" in fn and "topk" not in fn
    assert report["schema_version"] == 1


def test_root被覆写成人类可读的说明(client):
    """临时目录路径对看报告的人没有意义，但**不能去改 build_report**。"""
    report = post(client, [("c1", "f.c", VULN_C)]).get_json()["report"]
    assert "tmp" not in report["root"].lower()
    assert "1" in report["root"]


def test_include_code为真所以能看源码(client):
    fn = post(client, [("c1", "f.c", VULN_C)]).get_json()["report"]["files"][0]["functions"][0]
    assert "bad_copy" in fn["code"]


# ===========================================================================
# 5. 并发：不排队，直接 409
# ===========================================================================
def test_已有扫描在进行时返回409而不是排队(client):
    """排队更糟：用户可能已经关掉页面，排队的扫描还是会照样烧 GPU。"""
    assert SCAN_LOCK.acquire(blocking=False)
    try:
        resp = post(client, [("c1", "f.c", VULN_C)])
        assert resp.status_code == 409
        assert "已有扫描" in resp.get_json()["error"]
    finally:
        SCAN_LOCK.release()


def test_锁在扫描后被释放(client):
    """一次成功之后锁必须是放开的，否则第二次就永远 409 了。"""
    assert post(client, [("c1", "f.c", VULN_C)]).status_code == 200
    assert post(client, [("c1", "f.c", VULN_C)]).status_code == 200
    assert SCAN_LOCK.acquire(blocking=False), "扫描完没把锁还回来"
    SCAN_LOCK.release()


def test_扫描出错也会把锁还回来(client, monkeypatch):
    """finally 里必须 release —— 否则一次异常会让后端永久卡死。"""
    def boom(*_a, **_kw):
        raise RuntimeError("模拟推理炸了")

    monkeypatch.setattr(serve.registry.detector, "predict", boom)
    assert post(client, [("c1", "f.c", VULN_C)]).status_code == 500
    assert SCAN_LOCK.acquire(blocking=False), "异常路径没把锁还回来"
    SCAN_LOCK.release()


# ===========================================================================
# 6. 模型没就绪
# ===========================================================================
@pytest.mark.parametrize("status", ["loading", "error"])
def test_模型没就绪时返回503(client, status):
    serve.registry.status = status
    serve.registry.error = "FileNotFoundError: 没有这个目录" if status == "error" else None
    resp = post(client, [("c1", "f.c", VULN_C)])
    assert resp.status_code == 503
    assert resp.get_json()["status"] == status


def test_健康检查在加载中也能用(monkeypatch):
    """端口要比模型先开 —— 前端要能拿到 status=loading，而不是 ECONNREFUSED。"""
    monkeypatch.setattr(serve, "registry", None)
    with serve.app.test_client() as c:
        body = c.get("/api/health").get_json()
    assert body["status"] == "loading"
    assert body["models_loaded"] is False


def test_健康检查报的是就绪状态(client):
    body = client.get("/api/health").get_json()
    assert body["status"] == "ready"
    assert body["models_loaded"] is True
    assert body["num_labels"] == 28
    assert body["threshold"] == 0.5


# ===========================================================================
# 7. 并发压力：真并发下别把 parser 搞坏
# ===========================================================================
def test_并发请求不会同时进扫描段(client):
    """锁的粒度是整个 handler —— 并发时第二个进来应该直接拿到 409。"""
    results: list[int] = []
    started = threading.Event()

    def slow_predict(codes):
        started.set()
        # 占住锁足够久，让另一个线程能撞上来
        threading.Event().wait(0.3)
        return StubPredictor("detection").predict(codes)

    serve.registry.detector.predict = slow_predict

    def worker():
        with serve.app.test_client() as c:
            results.append(post(c, [("c1", "f.c", VULN_C)]).status_code)

    t = threading.Thread(target=worker)
    t.start()
    started.wait(timeout=2)
    second = post(client, [("c2", "f.c", VULN_C)]).status_code
    t.join(timeout=5)

    assert second == 409, f"并发时第二个请求应该被拒，实际 {second}"
    assert results == [200]
