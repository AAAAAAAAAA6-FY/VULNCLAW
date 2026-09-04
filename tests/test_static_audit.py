# -*- coding: utf-8 -*-
"""SP11 静态审计通道（C1/C2）测试。"""
import json
import os

import pytest

import vulnclaw.core.static_audit as sa


@pytest.fixture
def repo(tmp_path):
    """构造一个无 git 的源码目录（src 保留，tests/node_modules 剔除）。"""
    root = tmp_path / "demo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app").mkdir()
    (root / "tests").mkdir()
    (root / "node_modules").mkdir()
    (root / "src" / "main.py").write_text('import os\n\ndef run():\n    return os.getenv("X")\n', encoding="utf-8")
    (root / "src" / "app" / "pay.py").write_text("def pay():\n    return 1\n", encoding="utf-8")
    (root / "src" / "helper.ts").write_text("export const a = 1;\n", encoding="utf-8")
    (root / "tests" / "test_x.py").write_text("def test_x():\n    pass\n", encoding="utf-8")
    (root / "node_modules" / "pkg.js").write_text("module.exports = {};\n", encoding="utf-8")
    (root / "README.md").write_text("docs\n", encoding="utf-8")
    return str(root)


class TestCollectCandidates:
    def test_walk_fallback_filters(self, repo):
        cfg = sa.StaticAuditConfig(diff_only=True, symbol_trim=False)
        cands = sa.collect_candidates(repo, cfg, changed_only_files=None)
        rels = {c["path"] for c in cands}
        assert "src/main.py" in rels
        assert "src/app/pay.py" in rels
        assert "src/helper.ts" in rels
        assert not any("tests" in r or "node_modules" in r for r in rels)
        assert "README.md" not in rels

    def test_changed_only_files(self, repo):
        cfg = sa.StaticAuditConfig(diff_only=False)
        cands = sa.collect_candidates(repo, cfg, changed_only_files=["src/main.py"])
        assert [c["path"] for c in cands] == ["src/main.py"]

    def test_blob_hash_stable(self, repo):
        p = repo + "\\src\\main.py"
        h1 = sa._blob_hash(p)
        h2 = sa._blob_hash(p)
        assert h1 == h2 and h1.startswith("sha1:")


class TestBudgetAndCache:
    def test_budget_truncation_drops_low_priority(self, repo, monkeypatch):
        # 放大仓库：token 估算越过预算硬顶（小仓库估算会舍入为 0）
        big = os.path.join(repo, "src", "big_payload.py")
        with open(big, "w", encoding="utf-8") as f:
            f.write("\n".join("x = %d" % i for i in range(120)))
        cfg = sa.StaticAuditConfig(max_cost_usd=0.0001, symbol_trim=False)
        monkeypatch.setattr(sa, "detect_runtime",
                            lambda c=None: {"node_ok": False, "deepsec_ok": False,
                                            "model_key": False, "usable": False})
        res = sa.run_static_audit(repo, cfg, out_json=str(repo + "\\res.json"))
        assert res["budget"]["over_budget"] is True
        assert res["budget"]["truncated_files"]
        assert res["findings_count"] == 0
        assert res["degraded"] is True

    def test_cache_skip_reduces_audit_set(self, repo, monkeypatch):
        cfg = sa.StaticAuditConfig(diff_only=True, symbol_trim=False)
        monkeypatch.setattr(sa, "detect_runtime",
                            lambda c=None: {"node_ok": False, "deepsec_ok": False,
                                            "model_key": False, "usable": False})
        r1 = sa.run_static_audit(repo, cfg, out_json=str(repo + "\\r1.json"))
        assert r1["cache_hits"] == 0
        r2 = sa.run_static_audit(repo, cfg, out_json=str(repo + "\\r2.json"))
        assert r2["cache_hits"] == r1["candidates_total"]
        assert r2["audited_files"] == 0


class TestSymbolTrim:
    def test_trim_keeps_changed_fn_drops_others(self):
        content = (
            '"""doc"""\n'
            'import os\n'
            'import json\n\n'
            'def secret():\n'
            '    return "leak"\n\n'
            'def touched():\n'
            '    return os.getenv("K")\n\n'
            'def another():\n'
            '    pass\n'
        )
        out = sa._trim_python_slices(content, [(7, 8)])
        assert "def touched" in out and "os.getenv" in out
        assert "def secret" not in out
        assert "def another" not in out
        assert '"""doc"""' in out and "import os" in out

    def test_trim_no_changed_lines_returns_full(self):
        content = "def a():\n    pass\n"
        assert sa._trim_python_slices(content, []) == content

    def test_trim_syntax_error_degrades(self):
        out = sa._trim_python_slices("def broken(:\n", [(1, 2)])
        assert "def broken" in out  # 不崩溃，降级全量


class FakeProc:
    def __init__(self, stdout="[]", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class TestInvocationAndNormalize:
    def test_normalize_contract(self):
        raw = {"type": "ssrf_to_metadata", "severity": "HIGH", "title": "t",
               "line": 12, "cvss": 8.1}
        f = sa._normalize_finding(raw, "src\\app\\pay.py")
        assert f["source"] == "deepsec"
        assert f["severity"] == "High"
        assert f["method"] == "static"
        assert f["url"] == "repo://src/app/pay.py"
        assert f["verdict"] == "likely"
        for k in ("type", "title", "severity", "description", "evidence", "remediation",
                  "recommendation", "url", "parameter", "method", "confidence",
                  "cvss", "source", "verdict", "lifecycle"):
            assert k in f

    def test_mocked_invoke_produces_findings(self, repo, monkeypatch):
        cfg = sa.StaticAuditConfig(diff_only=False, symbol_trim=False)
        monkeypatch.setattr(
            sa, "detect_runtime",
            lambda c=None: {"node_ok": True, "node_version": "v22.0.0", "deepsec_ok": True,
                            "model_key": True, "usable": True})
        payload = json.dumps([{"type": "sqli", "severity": "critical", "title": "inject",
                               "line": 3}])
        monkeypatch.setattr(sa, "_invoke_deepsec",
                            lambda rp, files, c: FakeProc(stdout=payload))
        monkeypatch.setattr(sa, "_changed_line_ranges", lambda rp, rel: [])
        res = sa.run_static_audit(repo, cfg, out_json=str(repo + "\\r.json"))
        assert res["findings_count"] == 3
        assert all(f["source"] == "deepsec" for f in res["findings"])
        assert not res["degraded"]

    def test_deepsec_exit_failure_records_failed(self, repo, monkeypatch):
        cfg = sa.StaticAuditConfig(diff_only=False, symbol_trim=False)
        monkeypatch.setattr(
            sa, "detect_runtime",
            lambda c=None: {"node_ok": True, "node_version": "v22.0.0", "deepsec_ok": True,
                            "model_key": True, "usable": True})
        monkeypatch.setattr(sa, "_invoke_deepsec",
                            lambda rp, files, c: FakeProc(stdout="", stderr="boom", returncode=1))
        monkeypatch.setattr(sa, "_changed_line_ranges", lambda rp, rel: [])
        res = sa.run_static_audit(repo, cfg, out_json=str(repo + "\\r.json"))
        assert res["findings_count"] == 0
        ledger = json.load(open(res["ledger_path"], encoding="utf-8"))
        assert any(r["status"] == "failed" for r in ledger["rows"])  # 失败留痕


class TestRunDegraded:
    def test_env_missing_degrades_gracefully(self, repo, monkeypatch):
        cfg = sa.StaticAuditConfig(diff_only=False, symbol_trim=False)
        monkeypatch.setattr(sa, "detect_runtime",
                            lambda c=None: {"node_ok": False, "node_version": "",
                                            "deepsec_ok": False, "model_key": False,
                                            "usable": False})
        res = sa.run_static_audit(repo, cfg, out_json=str(repo + "\\r.json"))
        assert res["degraded"] is True
        assert res["findings"] == []
        ledger = json.load(open(res["ledger_path"], encoding="utf-8"))
        env_rows = {r["engine"] for r in ledger["rows"] if r["asset"] == "env"}
        assert env_rows == {"env.node", "env.deepsec_cli", "env.model_key"}
        assert any(r["status"] == "skipped" for r in ledger["rows"] if r["asset"] == "env")

    def test_dry_run_no_invocation(self, repo, monkeypatch):
        cfg = sa.StaticAuditConfig(diff_only=False, symbol_trim=False)
        monkeypatch.setattr(
            sa, "detect_runtime",
            lambda c=None: {"node_ok": True, "node_version": "v22.0.0", "deepsec_ok": True,
                            "model_key": True, "usable": True})
        called = []
        monkeypatch.setattr(sa, "_invoke_deepsec", lambda *a: called.append(a) or FakeProc())
        res = sa.run_static_audit(repo, cfg, out_json=str(repo + "\\r.json"), dry_run=True)
        assert called == []
        assert res["dry_run"] is True


class TestAuditLedger:
    def test_snapshot_schema(self, tmp_path):
        led = sa.AuditLedger(target="t")
        led.record_run("src/a.py", "deepsec.cli", findings=2)
        led.record_skipped("env", "env.node", "missing")
        snap = led.snapshot()
        assert snap["kind"] == "static_audit"
        assert snap["source"] == "machine_observed"
        assert snap["rollup"]["by_engine"]["deepsec.cli"]["findings"] == 2
        assert any(g["engine"] == "env.node" for g in snap["gaps"])

    def test_try_register_sp3_is_bool(self, tmp_path):
        led = sa.AuditLedger(target="t")
        led.record_skipped("env", "env.node", "missing")
        assert isinstance(led.try_register_sp3(), bool)