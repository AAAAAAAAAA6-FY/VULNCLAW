# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""Z3.1: POCGenerator LLM 动态生成测试。

覆盖：开关关 → 静态骨架不调 LLM；LLM 合法 JSON → 返回生成 code；
      LLM 异常 → 硬回退静态不崩；模板命中 → 不触发 LLM；批量打标。
"""
import pytest

from vulnclaw.core.settings import settings
from vulnclaw.deepsec.poc_generator import POCGenerator


class _CountingLLM:
    def __init__(self, result=None, exc=None):
        self.result = result
        self.exc = exc
        self.calls = 0
        self.kwargs = None

    async def ask(self, *args, **kwargs):
        self.calls += 1
        self.kwargs = kwargs
        if self.exc:
            raise self.exc
        return self.result


_LLM_OK = {
    "code": (
        "import requests\n"
        "def verify():\n"
        "    r = requests.get('http://t/x', params={'q': '1'}, timeout=10)\n"
        "    return r.elapsed.total_seconds() > 3\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    print('vuln' if verify() else 'safe')\n"
    ),
    "description": "时间盲注验证 PoC",
    "validation_steps": ["step1"],
}

_UNKNOWN_FINDING = {
    "type": "time_based_blind_notmapped",
    "url": "http://t/x",
    "parameter": "q",
    "payload": "' AND SLEEP(3)-- ",
    "severity": "High",
}

_TEMPLATE_FINDING = {
    "type": "sql_injection",
    "url": "http://t/x",
    "parameter": "q",
    "payload": "1' OR '1'='1",
}


@pytest.fixture(autouse=True)
def _clean_switch():
    """默认开，测试用例内自行关。"""
    settings.enable_llm_poc = True
    yield


@pytest.mark.asyncio
async def test_switch_off_falls_back_static(monkeypatch):
    """开关关 → 静态骨架，且 LLM 零调用。"""
    llm = _CountingLLM(result=_LLM_OK)
    monkeypatch.setattr("vulnclaw.ai.core.get_llm_client", lambda: llm)
    settings.enable_llm_poc = False
    gen = POCGenerator()
    poc = await gen.generate(_UNKNOWN_FINDING)
    assert "requests" in poc            # 静态骨架
    assert "verify()" in poc
    assert gen._last_origin == "generic"
    assert llm.calls == 0               # 开关关 → 不触达 LLM


@pytest.mark.asyncio
async def test_llm_success_returns_generated_code(monkeypatch):
    """LLM 返回合法 JSON → 使用生成的 code 并打 origin=llm。"""
    llm = _CountingLLM(result=_LLM_OK)
    monkeypatch.setattr("vulnclaw.ai.core.get_llm_client", lambda: llm)
    gen = POCGenerator()
    poc = await gen.generate(_UNKNOWN_FINDING)
    assert "requests" in poc
    assert "verify()" in poc
    assert gen._last_origin == "llm"
    assert gen._last_description == "时间盲注验证 PoC"
    assert llm.calls == 1
    assert llm.kwargs["usage_site"] == "pocgen"     # SP8 调用点打标
    assert llm.kwargs["force_json"] is True


@pytest.mark.asyncio
async def test_llm_failure_falls_back_static(monkeypatch):
    """LLM 抛异常 → 硬回退静态骨架，不阻断。"""
    llm = _CountingLLM(exc=RuntimeError("api down"))
    monkeypatch.setattr("vulnclaw.ai.core.get_llm_client", lambda: llm)
    gen = POCGenerator()
    poc = await gen.generate(_UNKNOWN_FINDING)
    assert "requests" in poc
    assert gen._last_origin == "generic"
    assert llm.calls == 1


@pytest.mark.asyncio
async def test_llm_invalid_json_falls_back_static(monkeypatch):
    """LLM 输出非法 JSON → 解析失败 → 回退静态。"""
    llm = _CountingLLM(result="{not valid json")
    monkeypatch.setattr("vulnclaw.ai.core.get_llm_client", lambda: llm)
    gen = POCGenerator()
    poc = await gen.generate(_UNKNOWN_FINDING)
    assert "requests" in poc
    assert gen._last_origin == "generic"


@pytest.mark.asyncio
async def test_template_hit_skips_llm(monkeypatch):
    """有模板命中 → 走模板渲染，不触发 LLM。"""
    llm = _CountingLLM(result=_LLM_OK)
    monkeypatch.setattr("vulnclaw.ai.core.get_llm_client", lambda: llm)
    gen = POCGenerator()
    poc = await gen.generate(_TEMPLATE_FINDING)
    assert gen._last_origin == "template"
    assert llm.calls == 0
    assert poc.strip()  # 模板产物非空


@pytest.mark.asyncio
async def test_generate_batch_marks_origin(monkeypatch):
    """批量路径按 origin 打 template 字段。"""
    llm = _CountingLLM(result=_LLM_OK)
    monkeypatch.setattr("vulnclaw.ai.core.get_llm_client", lambda: llm)
    gen = POCGenerator()
    results = await gen.generate_batch([
        dict(_TEMPLATE_FINDING, id="f1"),
        dict(_UNKNOWN_FINDING, id="f2"),
    ])
    by_id = {r["finding_id"]: r for r in results}
    assert by_id["f1"]["template"] == "sqli.py.j2"
    assert by_id["f2"]["template"] == "llm"