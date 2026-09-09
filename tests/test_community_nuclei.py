# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""C 方案契约测试：通用检测外置到 Nuclei/社区（社区检测线 + 证据化验证）。

覆盖：模板健康 / 端点收集 / fail-closed / run_nuclei_community_line /
evidence AI 验证（prompt 含 matched，输出契约不变）/ 开关回滚 / 挂载行为。
全部离线，不经真实网络、不触真 nuclei。
"""
import asyncio

import pytest

from vulnclaw.config import settings
from vulnclaw.modules.vuln_scanner import (collect_line_targets,
                                           nuclei_template_health,
                                           run_nuclei_community_line)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ---------------- 1. 模板健康 ----------------

def test_health_invalid_dir(monkeypatch):
    monkeypatch.setattr(settings, "nuclei_template_dir", "/nonexistent/nuclei-templates-xyz")
    count, ok = nuclei_template_health(min_count=300)
    assert count == 0 and ok is False  # 目录缺失 → fail-closed


def test_health_zero_min(monkeypatch, tmp_path):
    # 目录存在但 0 模板 + 阈值 0 → 健康（0 >= 0）。目录缺失必须 fail-closed（即使阈值 0）。
    monkeypatch.setattr(settings, "nuclei_template_dir", str(tmp_path))
    count, ok = nuclei_template_health(min_count=0)
    assert count == 0 and ok


# ---------------- 2. 端点收集 ----------------

def test_collect_zero_budget_returns_empty():
    assert _run(collect_line_targets({"alive_assets": ["https://a.test/"]}, 0)) == []


def test_collect_alive_assets_priority():
    brief = {
        "alive_assets": [{"url": "https://a.test/", "status": 200}],
        "js_endpoints": ["https://a.test/app.js"],
        "apis": ["https://a.test/api/v1"],
    }
    out = _run(collect_line_targets(brief, 2))
    assert out == ["https://a.test", "https://a.test/app.js"]


def test_collect_dedup_and_budget():
    brief = {
        "alive_assets": ["https://x.test/", "https://x.test/"],
        "js_endpoints": ["https://x.test/x.js", "https://x.test/x.js?ver=1"],
        "found_dirs": ["/admin"],
    }
    out = _run(collect_line_targets(brief, 10))
    # 相对路径 /admin 不入列；重复去重
    assert out == ["https://x.test", "https://x.test/x.js"]


def test_collect_ignores_non_http():
    brief = {"js_endpoints": ["data:text/html,x", "ftp://f.test/", "https://ok.test/z"]}
    out = _run(collect_line_targets(brief, 10))
    assert out == ["https://ok.test/z"]


# ---------------- 3. fail-closed ----------------

def test_line_fail_closed_when_no_templates(monkeypatch):
    from vulnclaw.modules.vuln_scanner import cve_nuclei as _cn
    monkeypatch.setattr(_cn, "nuclei_template_health", lambda *a, **k: (10, False))
    assert _run(run_nuclei_community_line("https://t.test/", {}, min_templates=300)) == []


def test_line_single_endpoint_error_skips(monkeypatch):
    from vulnclaw.modules.vuln_scanner import cve_nuclei as _cn
    monkeypatch.setattr(_cn, "nuclei_template_health", lambda *a, **k: (1000, True))
    async def _boom(*a, **k):
        raise RuntimeError("nuclei 异常")
    monkeypatch.setattr(_cn, "run_nuclei_async", _boom)
    assert _run(run_nuclei_community_line("https://t.test/", {})) == []


def test_line_passes_args_and_tags_target(monkeypatch):
    from vulnclaw.modules.vuln_scanner import cve_nuclei as _cn
    calls = []
    monkeypatch.setattr(_cn, "nuclei_template_health", lambda *a, **k: (1000, True))
    async def _fake_nuclei(url, severity="", timeout=0):
        calls.append((url, severity, timeout))
        return [{"template": "tpl-x", "severity": "high", "matched": "https://t.test/x",
                 "url": url, "info": "desc"}]
    monkeypatch.setattr(_cn, "run_nuclei_async", _fake_nuclei)
    out = _run(run_nuclei_community_line(
        "https://t.test/", {"alive_assets": ["https://t.test/a"]},
        severity="critical,high", timeout=99, budget=2))
    assert len(out) == 2
    assert all(r["line_target"] for r in out)
    urls = {c[0] for c in calls}
    assert "https://t.test" in urls and "https://t.test/a" in urls
    assert all(c[1] == "critical,high" and c[2] == 99 for c in calls)


def test_line_dedup_across_targets(monkeypatch):
    from vulnclaw.modules.vuln_scanner import cve_nuclei as _cn
    monkeypatch.setattr(_cn, "nuclei_template_health", lambda *a, **k: (1000, True))
    async def _fake_nuclei(url, severity="", timeout=0):
        return [{"template": "tpl-y", "severity": "medium", "matched": "https://t.test/m",
                 "url": url, "info": "d"}]
    monkeypatch.setattr(_cn, "run_nuclei_async", _fake_nuclei)
    out = _run(run_nuclei_community_line(
        "https://t.test/", {"alive_assets": ["https://t.test/"]}, budget=2))
    assert len(out) == 1  # 主域根与 alive 相同 → 去重


# ---------------- 4. AI 验证证据增强 ----------------

def test_verify_evidence_prompt_contains_matched(monkeypatch):
    from vulnclaw.modules.vuln_scanner import verify_ai as _va
    seen_prompts = []

    class _FakeClient:
        async def ask(self, prompt, **kw):
            seen_prompts.append(prompt)
            return '[{"index": 0, "is_real": true, "confidence": "高", "reason": "证据实锤"}]'

    async def _fake_limiter(*a, **k):
        pass

    def _fake_get_client():
        return _FakeClient()

    monkeypatch.setattr(_va, "get_vuln_llm_client", _fake_get_client)
    monkeypatch.setattr(_va, "_AI_VERIFY_FAILED", False)
    monkeypatch.setattr(_va, "_last_fail_time", 0.0)
    monkeypatch.setattr(_va, "_vuln_limiter", type("L", (), {"acquire": _fake_limiter})())

    results = [{"template": "cve-x", "severity": "critical",
                "info": "desc x", "matched": "MATCHED-EVIDENCE-0123"}]
    out = _run(_va.verify_nuclei_with_ai_async(results, "https://t.test/", evidence=True))
    assert out[0]["ai_verdict"] == "真实漏洞"
    assert "MATCHED-EVIDENCE-0123" in seen_prompts[0]


def test_verify_contract_keys_present(monkeypatch):
    """输出契约不变：ai_verdict / confidence / ai_reason 三键齐全。"""
    from vulnclaw.modules.vuln_scanner import verify_ai as _va

    class _FakeClient:
        async def ask(self, prompt, **kw):
            return '[{"index": 0, "is_real": false, "confidence": "低", "reason": "无利用价值"}]'

    async def _fake_limiter():
        pass

    def _fake_get_client():
        return _FakeClient()

    monkeypatch.setattr(_va, "get_vuln_llm_client", _fake_get_client)
    monkeypatch.setattr(_va, "_AI_VERIFY_FAILED", False)
    monkeypatch.setattr(_va, "_last_fail_time", 0.0)
    monkeypatch.setattr(_va, "_vuln_limiter", type("L", (), {"acquire": _fake_limiter})())

    results = [{"template": "t", "severity": "high", "info": "d", "matched": "m"}]
    out = _run(_va.verify_nuclei_with_ai_async(results, "https://t.test/", evidence=False))
    assert "ai_verdict" in out[0]
    assert "confidence" in out[0]
    assert "ai_reason" in out[0]


# ---------------- 5. 开关回滚 ----------------

def test_community_line_switch_off(monkeypatch):
    from vulnclaw.ai.v100.phases import phases_taskgen as _ptg
    monkeypatch.setattr(settings, "nuclei_community_line", False)
    h = _ptg._run_nuclei_community_line
    async def _stub(self):
        return await h(self)
    assert _run(_stub(None)) == 0


def test_settings_defaults():
    assert settings.nuclei_community_line is True
    assert settings.nuclei_line_min_templates == 300
    assert settings.nuclei_line_endpoint_budget == 10
    assert settings.nuclei_line_severity == "critical,high"
    assert settings.nuclei_line_timeout == 300
    assert settings.nuclei_ai_evidence is True
