# -*- coding: utf-8 -*-
"""SP6: skill payload × exploit_chain 三腿沉淀闭环测试。"""
import pytest
from vulnclaw.core import knowledge
from vulnclaw.deepsec.exploit_chain import ExploitChain


class TestSkillPayloads:
    def test_def_payloads_loaded(self):
        assert knowledge.SKILLS["sqli_error_based"].get("payloads")
        assert knowledge.SKILLS["lfi_file_read"].get("payloads")

    def test_register_dedup_and_merge(self, tmp_path, monkeypatch):
        monkeypatch.setattr(knowledge, "_payload_ledger_path", lambda: str(tmp_path / "sp.json"))
        knowledge.reset_payload_ledger()
        assert knowledge.register_payload("lfi_file_read", "aaa") is True
        assert knowledge.register_payload("lfi_file_read", "aaa") is False  # 幂等去重
        ups = knowledge.skill_payloads("lfi_file_read")
        assert "aaa" in ups
        assert "....//....//....//....//etc/passwd" in ups  # 静态腿合并

    def test_register_persists(self, tmp_path, monkeypatch):
        monkeypatch.setattr(knowledge, "_payload_ledger_path", lambda: str(tmp_path / "sp.json"))
        knowledge.reset_payload_ledger()
        knowledge.register_payload("sqli_error_based", "x' AND 1=1 --")
        assert "x' AND 1=1 --" in knowledge.skill_payloads("sqli_error_based")


@pytest.mark.asyncio
async def test_lfi_chain_consumes_skill_payload_and_sinks(tmp_path, monkeypatch):
    """LFI 利用链直接引用技能包 payload，命中后反向沉降进台账。"""
    import vulnclaw.core.utils as cu
    monkeypatch.setattr(knowledge, "_payload_ledger_path", lambda: str(tmp_path / "sp.json"))
    knowledge.reset_payload_ledger()

    async def fake_get(url, session=None, timeout=8, **kw):
        return ("200", "root:0:0:root:/root:/bin/bash\nbin:x:1:1:")

    monkeypatch.setattr(cu, "async_get", fake_get)
    chain = ExploitChain(target="http://lab/", session=None, dangerous=True)
    finding = {"url": "http://lab/file.jsp", "parameter": "file"}
    result = await chain._exploit_lfi(finding)
    assert "root" in result.get("evidence", "")
    import json
    data = json.load(open(str(tmp_path / "sp.json"), encoding="utf-8"))
    assert len(data.get("lfi_file_read", [])) >= 1  # 生成腿沉降


@pytest.mark.asyncio
async def test_sqli_probe_uses_skill_payload_and_sinks(tmp_path, monkeypatch):
    """SQLi 非危险模式：技能 payload 内联探测命中 → 证据 + 沉降。"""
    import vulnclaw.core.utils as cu
    monkeypatch.setattr(knowledge, "_payload_ledger_path", lambda: str(tmp_path / "sp.json"))
    knowledge.reset_payload_ledger()

    async def fake_get(url, session=None, timeout=8, **kw):
        return ("200", "You have an error in your SQL syntax near '1")

    monkeypatch.setattr(cu, "async_get", fake_get)
    chain = ExploitChain(target="http://lab/", session=None, dangerous=False)
    finding = {"url": "http://lab/list.jsp", "parameter": "uid"}
    result = await chain._exploit_sqli(finding)
    assert "探测命中" in result.get("evidence", "")
    import json
    data = json.load(open(str(tmp_path / "sp.json"), encoding="utf-8"))
    assert len(data.get("sqli_error_based", [])) >= 1
