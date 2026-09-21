"""两级级联（检测 → 分类）的回归测试。

这是 ``scripts/scan_project.py`` 的第一组测试 —— 在加级联之前，这个脚本
一行测试都没有。级联引入的行为约定必须钉死，否则日后改动很容易悄悄破坏：

1. **只对检测命中的函数跑分类**。分类数据里没有"安全"这一类
   （``build_dataset.py`` 只取 ``label==1`` 且有 ``cwe`` 的样本），
   喂安全函数等于逼模型在 27 个 CWE 里硬猜，产出的是看起来很像真的噪声。
2. **报告字段只增不改**。新增 ``cwe`` / ``cwe_topk`` / ``functions_classified``
   都是可选字段，``SCHEMA_VERSION`` 保持 1（约定见 docs/07 184 行）。
3. **检测结论与分类结果解耦**。``suspicious_count`` 必须只由检测 verdict
   决定；分类器给出了 CWE 不代表某个函数就"更可疑"了。

测试全部用**桩推理器**，不加载任何真实权重 —— 这样跑一次不到 1 秒，
换台机器 clone 下来也能直接跑。
"""

import pytest

from scripts.scan_project import build_report, run_classification, run_inference
from src.extract import extract_functions

# 一个"有漏洞"的函数（内容里有 BAD 标记，桩检测器据此判定）
VULN_C = "int bad_copy(char *dst, char *src) { BAD strcpy(dst, src); return 0; }"
# 一个干净函数
SAFE_C = "int add(int a, int b) { return a + b; }"


# ===========================================================================
# 桩推理器
# ===========================================================================
class StubPredictor:
    """假的 ``VulnPredictor``：不加载权重，按代码内容返回预设结果。

    只实现扫描侧真正用到的那部分接口（``task`` 和 ``predict``），
    刻意不继承真的类 —— 级联的约定不该依赖 ``VulnPredictor`` 的内部实现。
    """

    def __init__(self, task: str):
        self.task = task
        self.calls: list[str] = []  # 收到的所有代码，用来断言"喂了哪些"

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


def make_file_results(*snippets: str) -> list[dict]:
    """把若干段 C 代码打包成 ``scan_files`` 会产出的那种 file_results。"""
    out = []
    for i, code in enumerate(snippets):
        funcs, parse_ok = extract_functions(code, "c")
        out.append({
            "path": f"f{i}.c",
            "language": "c",
            "parse_ok": parse_ok,
            "num_bytes": len(code),
            "function_count": len(funcs),
            "functions_discarded": 0,
            "functions": funcs,
        })
    return out


@pytest.fixture
def cascaded():
    """跑完整的两级级联，返回 (report, 检测桩, 分类桩)。"""
    file_results = make_file_results(VULN_C, SAFE_C)
    det, clf = StubPredictor("detection"), StubPredictor("classification")
    verdicts = run_inference(det, file_results, batch_size=8)
    classifications = run_classification(clf, file_results, verdicts, batch_size=8)
    report = build_report(
        root=None, file_results=file_results, skipped=[],  # type: ignore[arg-type]
        checkpoint="det/best", threshold=0.5, include_code=True,
        verdicts=verdicts, classifications=classifications,
        classifier_checkpoint="clf/best",
    )
    return report, det, clf


# ===========================================================================
# 1. 只对命中函数跑分类
# ===========================================================================
def test_只把命中函数喂给分类器(cascaded):
    """**本文件最重要的一条**：分类器只应该看到有 BAD 标记的那个函数。"""
    _, _, clf = cascaded
    assert len(clf.calls) == 1, f"分类器应只收到 1 个函数，实际 {len(clf.calls)} 个"
    assert "bad_copy" in clf.calls[0]
    assert "add" not in clf.calls[0], "安全函数不该被送去分类"


def test_一个命中都没有时完全不调分类器():
    """没有命中就别进模型 —— predict([]) 会白走一次 tokenizer 和前向。"""
    file_results = make_file_results(SAFE_C, SAFE_C)
    det, clf = StubPredictor("detection"), StubPredictor("classification")
    verdicts = run_inference(det, file_results, batch_size=8)
    assert run_classification(clf, file_results, verdicts, batch_size=8) == {}
    assert clf.calls == [], "没有命中时分类器一次都不该被调用"


def test_空文件列表不崩():
    """扫描一个没有函数的目录：两级都不该炸。"""
    det, clf = StubPredictor("detection"), StubPredictor("classification")
    assert run_inference(det, [], batch_size=8) == {}
    assert run_classification(clf, [], {}, batch_size=8) == {}


# ===========================================================================
# 2. 报告字段只增不改
# ===========================================================================
def test_cwe_字段只出现在命中函数上(cascaded):
    report, _, _ = cascaded
    for fr in report["files"]:
        for f in fr["functions"]:
            if f["verdict"] == "vulnerable":
                assert f["cwe"] == "CWE-119"
                assert f["cwe_topk"][0]["cwe"] == "CWE-119"
            else:
                # 没跑分类就不写键，避免 "cwe: null" 被误读成"没有类别"
                assert "cwe" not in f
                assert "cwe_topk" not in f


def test_键名是_cwe_topk_不是_topk(cascaded):
    """``predict.py`` 返回的键叫 ``topk``，报告里必须改名成 ``cwe_topk``。"""
    report, _, _ = cascaded
    hits = [f for fr in report["files"] for f in fr["functions"]
            if f["verdict"] == "vulnerable"]
    assert hits, "样例里应该至少有一个命中"
    assert "cwe_topk" in hits[0]
    assert "topk" not in hits[0]


def test_不传分类器时报告里没有分类痕迹():
    """老调用方（只做检测）拿到的报告不该多出任何分类字段。"""
    file_results = make_file_results(VULN_C, SAFE_C)
    det = StubPredictor("detection")
    verdicts = run_inference(det, file_results, batch_size=8)
    report = build_report(
        root=None, file_results=file_results, skipped=[],  # type: ignore[arg-type]
        checkpoint="det/best", threshold=0.5, include_code=True, verdicts=verdicts,
    )
    for fr in report["files"]:
        for f in fr["functions"]:
            assert "cwe" not in f and "cwe_topk" not in f
    assert report["classifier_checkpoint"] is None
    assert report["summary"]["functions_classified"] == 0


def test_schema_version_不递增(cascaded):
    """新增可选字段不递增 schema_version（docs/07 184 行的约定）。"""
    report, _, _ = cascaded
    assert report["schema_version"] == 1


def test_老字段一个都没少(cascaded):
    """只增不改 —— 老消费方依赖的键必须全都还在。"""
    report, _, _ = cascaded
    for key in ("schema_version", "tool", "generated_at", "root",
                "checkpoint", "threshold", "summary", "skipped", "files"):
        assert key in report, f"顶层键 {key} 丢了"
    for key in ("files_scanned", "files_skipped", "functions_total",
                "functions_suspicious", "languages"):
        assert key in report["summary"], f"summary 键 {key} 丢了"
    f0 = report["files"][0]["functions"][0]
    for key in ("name", "start_line", "end_line", "start_byte", "end_byte",
                "node_type", "language", "depth", "parent_name", "code",
                "verdict", "confidence", "prob_vulnerable"):
        assert key in f0, f"函数节点键 {key} 丢了"


# ===========================================================================
# 3. 检测与分类解耦
# ===========================================================================
def test_可疑计数只由检测结论决定(cascaded):
    """分类器给了 CWE 不代表函数"更可疑"，计数不能因此变化。"""
    report, _, _ = cascaded
    s = report["summary"]
    assert s["functions_suspicious"] == 1        # 只有 bad_copy
    assert s["functions_classified"] == 1        # 只有它跑了分类
    assert report["files"][0]["suspicious_count"] == 1
    assert report["files"][1]["suspicious_count"] == 0


def test_分类结果和检测结果一一对应(cascaded):
    """报告里每个 cwe 都必须挂在某个 verdict==vulnerable 的函数上。"""
    report, _, _ = cascaded
    n_cwe = sum(1 for fr in report["files"] for f in fr["functions"] if "cwe" in f)
    assert n_cwe == report["summary"]["functions_classified"]
