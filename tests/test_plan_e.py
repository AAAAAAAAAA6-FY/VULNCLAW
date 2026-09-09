# -*- coding: utf-8 -*-
"""E 方案契约测试：交叉验证层（开源工具对照）——不触网、快速、fail-open 验证。"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
try:
    import vulnclaw.bootstrap  # noqa: F401
except ImportError:  # 缺少可选依赖时仍允许测试导入
    pass

from vulnclaw.core import settings as _settings_mod  # noqa: F401
from vulnclaw.config.settings import settings
from vulnclaw.modules.vuln_scanner.cross_verify import (
    cross_check_findings,
    _find_spec,
    _apply_biz_rule,
    _is_biz,
)


def run(coro):
    return asyncio.run(coro)


def _v(typ, **kw):
    d = {"type": typ, "url": "http://127.0.0.1:9865/x?p=1", "parameter": "p",
         "severity": "High", "confidence": "medium", "evidence": "引擎证据"}
    d.update(kw)
    return d


# ---------- 规格匹配 ----------

def test_spec_cmdi_commix():
    s = _find_spec(_v("命令注入"))
    assert s and s["kind"] == "commix"


def test_spec_ssti_nuclei():
    s = _find_spec(_v("ssti 模板注入"))
    assert s and s["kind"] == "nuclei" and "ssti" in s["nuclei_tags"]


def test_spec_smuggling():
    s = _find_spec(_v("请求走私 HTTP Request Smuggling"))
    assert s and "smuggling" in s["nuclei_tags"]


def test_spec_cache_poison():
    s = _find_spec(_v("Cache Poisoning"))
    assert s and "cache-poison" in s["nuclei_tags"]


def test_spec_config_class():
    s = _find_spec(_v("HSTS header 缺失"))
    assert s and s["kind"] == "nuclei"


def test_spec_unknown_none():
    assert _find_spec(_v("未知漏洞类型 abc")) is None


def test_spec_ssrf():
    s = _find_spec(_v("SSRF"))
    assert s and "ssrf" in s["nuclei_tags"]


def test_spec_xxe():
    s = _find_spec(_v("XXE"))
    assert s and "xxe" in s["nuclei_tags"]


def test_spec_lfi_rfi():
    s = _find_spec(_v("LFI 路径遍历"))
    assert s and "lfi" in s["nuclei_tags"]
    s2 = _find_spec(_v("RFI"))
    assert s2 and "rfi" in s2["nuclei_tags"]


def test_spec_deserialization():
    s = _find_spec(_v("反序列化 Java deserialization"))
    assert s and "deserialization" in s["nuclei_tags"]


def test_spec_jwt():
    s = _find_spec(_v("JWT 算法混淆"))
    assert s and "jwt" in s["nuclei_tags"]


def test_spec_cve_component():
    s = _find_spec(_v("已知漏洞组件 CVE-2021-44228"))
    assert s and "cve" in s["nuclei_tags"]


# ---------- E3 业务逻辑规则化 ----------

def test_biz_rule_pending():
    v = _v("IDOR 水平越权", evidence="引擎证据")
    assert _is_biz(v)
    _apply_biz_rule(v)
    assert v.get("cross_tool_pending") is True


def test_biz_rule_diff_skips_pending():
    v = _v("水平越权", evidence="差分对比：userA 可读 userB 资源")
    _apply_biz_rule(v)
    assert not v.get("cross_tool_pending")


def test_biz_rule_oracle_field_skips_pending():
    v = _v("越权接口", evidence="普通", oracle_observation={"userB": True})
    _apply_biz_rule(v)
    assert not v.get("cross_tool_pending")


def test_biz_rule_hard_proof_skips_pending():
    v = _v("BOLA 越权", evidence="普通", burp_verified=True)
    _apply_biz_rule(v)
    assert not v.get("cross_tool_pending")


# ---------- 对照层主流程（fail-open） ----------

def test_cross_disabled(monkeypatch):
    monkeypatch.setattr(settings, "cross_check_enabled", False)
    findings = [_v("命令注入")]
    assert run(cross_check_findings(findings)) == 0
    assert "cross_tool_checked" not in findings[0]
    monkeypatch.setattr(settings, "cross_check_enabled", True)


def test_cross_commix_missing(monkeypatch):
    import types
    fake_sh = types.SimpleNamespace(which=lambda _n: None)
    monkeypatch.setattr("vulnclaw.modules.vuln_scanner.cross_verify.shutil", fake_sh)
    findings = [_v("命令注入")]
    assert run(cross_check_findings(findings)) == 0
    assert findings[0]["cross_tool_checked"] is True
    assert not findings[0].get("cross_tool_confirmed")  # fail-open：保留原判定


def test_cross_biz_rules_run_no_tool(monkeypatch):
    import types
    fake_sh = types.SimpleNamespace(which=lambda _n: None)
    monkeypatch.setattr("vulnclaw.modules.vuln_scanner.cross_verify.shutil", fake_sh)
    findings = [_v("竞态条件 race", evidence="普通")]
    run(cross_check_findings(findings))
    assert findings[0].get("cross_tool_pending") is True  # 无工具 → 走规则


def test_cross_nuclei_no_hit(monkeypatch):
    async def fake_run_tool(name, args=None, timeout=None, **kw):
        return {"success": True, "stdout": "", "stderr": "", "returncode": 0}
    monkeypatch.setattr("vulnclaw.core.tool_registry.run_tool", fake_run_tool)
    findings = [_v("SSTI 模板注入")]
    run(cross_check_findings(findings))
    assert findings[0].get("cross_tool_checked") is True
    assert not findings[0].get("cross_tool_confirmed")


def test_cross_nuclei_hit(monkeypatch, tmp_path):
    import json as _json
    (tmp_path / "nuclei_out.jsonl").write_text(
        _json.dumps({"template-id": "ssti/custom-template", "matched-at": "http://x/", "info": {"name": "SSTI"}}),
        encoding="utf-8",
    )
    captured = {}

    async def fake_run_tool(name, args=None, timeout=None, **kw):
        captured["args"] = list(args or [])
        return {"success": True, "stdout": "", "returncode": 0}

    monkeypatch.setattr("vulnclaw.core.tool_registry.run_tool", fake_run_tool)
    monkeypatch.setattr("vulnclaw.modules.vuln_scanner.cross_verify.tempfile.TemporaryDirectory",
                        lambda prefix=None: _FakeTd(tmp_path))
    findings = [_v("SSTI 模板注入")]
    run(cross_check_findings(findings))
    assert findings[0].get("cross_tool_confirmed") is True
    assert "Nuclei" in findings[0].get("cross_tool_evidence", "")
    assert "-tags" in captured.get("args", [])


class _FakeTd:
    """临时目录替身：让 _run_nuclei 的输出文件落在 tmp_path 下，可被测试预置命中。"""
    def __init__(self, path):
        self._path = path

    def __enter__(self):
        return str(self._path)

    def __exit__(self, *exc):
        return False


# ---------- 证据链 / 审核门消费 ----------

def test_sigma_cross_tool_confirmed():
    from vulnclaw.ai.v100.phases.phases_report import _sigma_score
    v = _v("SSTI", ai_verdict="真实漏洞", cross_tool_confirmed=True)
    score, _ = _sigma_score(v)
    assert score >= 4  # 交叉实锤(+2) + AI 背书(+2)


def test_evidence_chain_includes_cross_tool():
    from vulnclaw.ai.v100.phases.phases_report import _build_evidence_chain
    v = _v("SSTI", cross_tool_evidence="[Nuclei(ssti) 独立判定命中] 模板 x @ url")
    chain = _build_evidence_chain(v)
    assert any("开源对照" in p for p in chain)
