# -*- coding: utf-8 -*-
"""编排产线测试：声明线与元orphic 线的开关、端点收集与 finding 上报。

产线函数通过 bind_phase_methods 绑到 orchestrator，这里用轻量 fake self 直接调用。
"""
import pytest

from vulnclaw.ai.v100.phases import phases_taskgen as p
from vulnclaw.config.settings import settings


class _FakeSelf:
    """最小 orchestrator 替身：只需 _recon_brief / target / _add_finding。"""

    def __init__(self, brief=None, target="https://x.test/a?b=1"):
        self._recon_brief = brief if brief is not None else {}
        self.target = target
        self.findings = []

    def _add_finding(self, f):
        self.findings.append(f)


# ---------------------------------------------------------------- 端点收集
def test_collect_probe_endpoints_dedupes_and_prioritizes_query():
    brief = {
        "crawled_endpoints": ["https://x.test/plain", "https://x.test/q?a=1",
                              "https://x.test/plain"],
        "forms": [{"action": "https://x.test/form?x=1"}],
    }
    out = p._collect_probe_endpoints(brief, "https://x.test/target?z=1")
    assert len(out) == len(set(out))                       # 去重
    assert "https://x.test/plain" in out
    assert "?" in out[0]                                    # 带 query 的排前面


def test_collect_probe_endpoints_ignores_non_http():
    out = p._collect_probe_endpoints({"crawled_endpoints": ["/relative", "not-a-url"]}, "")
    assert out == []


# ---------------------------------------------------------------- 声明线
@pytest.mark.asyncio
async def test_vulnspec_line_disabled_returns_zero(monkeypatch):
    monkeypatch.setattr(settings, "vulnspec_line_enabled", False, raising=False)
    assert await p._run_vulnspec_line(_FakeSelf()) == 0


@pytest.mark.asyncio
async def test_vulnspec_line_reports_findings(monkeypatch):
    from vulnclaw.core import vulnspec as vs

    monkeypatch.setattr(settings, "vulnspec_line_enabled", True, raising=False)
    monkeypatch.setattr(settings, "vulnspec_max_endpoints", 5, raising=False)

    class _Runner:
        def __init__(self, *a, **k):
            pass

        async def run(self, spec, **kw):
            return [{"type": "sql_error", "url": spec.url}]

    monkeypatch.setattr(vs, "SpecRunner", _Runner, raising=False)

    fake = _FakeSelf(brief={"crawled_endpoints": ["https://x.test/a?b=1"]})
    made = await p._run_vulnspec_line(fake)
    assert made >= 1
    assert fake.findings and fake.findings[0]["type"] == "sql_error"


@pytest.mark.asyncio
async def test_vulnspec_line_no_endpoints_returns_zero(monkeypatch):
    monkeypatch.setattr(settings, "vulnspec_line_enabled", True, raising=False)
    assert await p._run_vulnspec_line(_FakeSelf(brief={}, target="")) == 0


# ---------------------------------------------------------------- 元orphic 线
@pytest.mark.asyncio
async def test_metamorphic_line_disabled_returns_zero(monkeypatch):
    monkeypatch.setattr(settings, "metamorphic_line_enabled", False, raising=False)
    assert await p._run_metamorphic_line(_FakeSelf()) == 0


@pytest.mark.asyncio
async def test_metamorphic_line_reports_findings(monkeypatch):
    from vulnclaw.engines import metamorphic_engines as me

    monkeypatch.setattr(settings, "metamorphic_line_enabled", True, raising=False)
    monkeypatch.setattr(settings, "metamorphic_max_endpoints", 5, raising=False)

    class _Engine:
        def __init__(self, *a, **k):
            pass

        async def probe_spec(self, spec, **kw):
            return [{"type": "idor_candidate", "url": spec.url}]

    monkeypatch.setattr(me, "MetamorphicEngine", _Engine, raising=False)

    fake = _FakeSelf(brief={"crawled_endpoints": ["https://x.test/u?id=1"]})
    made = await p._run_metamorphic_line(fake)
    assert made >= 1
    assert fake.findings and fake.findings[0]["type"] == "idor_candidate"
