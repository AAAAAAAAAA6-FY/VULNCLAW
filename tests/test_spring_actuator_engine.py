# SpringActuatorEngine 行为正反例（Agent6 跨版本矩阵收口）。
# 行为级引擎无"边界版本"概念：暴露=TP，禁用/鉴权=TN。
# mock 模块级 async_get，纯离线、毫秒级。
import pytest

from vulnclaw.engines import leak_logic_engines as mod

BASE = "http://127.0.0.1:8091"


def _mk(responses):
    async def fake(url, session=None, timeout=None, no_retry=False, **kw):
        r = responses.get(url)
        return r if r is not None else (404, "", {})

    return fake


@pytest.mark.asyncio
async def test_actuator_env_leak_detected(monkeypatch):
    """actuator/env 200 + propertySources 特征 → 环境配置泄露（TP）。"""
    responses = {
        f"{BASE}/actuator/env": (
            200,
            '{"propertySources":[{"name":"applicationConfig"}]}',
            {"content-type": "application/json"},
        )
    }
    monkeypatch.setattr(mod, "async_get", _mk(responses))
    findings = await mod.SpringActuatorEngine().scan(f"{BASE}/", None)
    assert any("环境配置泄露" in f["type"] for f in findings), findings


@pytest.mark.asyncio
async def test_actuator_health_exposed_detected(monkeypatch):
    """actuator/health 200 + status:up → health 端点暴露（TP）。"""
    responses = {
        f"{BASE}/actuator/health": (200, '{"status":"up"}', {"content-type": "application/json"})
    }
    monkeypatch.setattr(mod, "async_get", _mk(responses))
    findings = await mod.SpringActuatorEngine().scan(f"{BASE}/", None)
    assert any("health端点暴露" in f["type"] for f in findings), findings


@pytest.mark.asyncio
async def test_actuator_heapdump_detected(monkeypatch):
    """actuator/heapdump 返回 cafebabe 魔数 → heapdump 泄露（TP）。"""
    responses = {
        f"{BASE}/actuator/heapdump": (
            200,
            "\xca\xfe\xba\xbe" + "A" * 2000,
            {"content-type": "application/octet-stream"},
        )
    }
    monkeypatch.setattr(mod, "async_get", _mk(responses))
    findings = await mod.SpringActuatorEngine().scan(f"{BASE}/", None)
    assert any("heapdump" in f["type"] for f in findings), findings


@pytest.mark.asyncio
async def test_actuator_absent_no_fp(monkeypatch):
    """全部端点 404 → 不得检出（TN）。"""
    monkeypatch.setattr(mod, "async_get", _mk({}))
    findings = await mod.SpringActuatorEngine().scan(f"{BASE}/", None)
    assert findings == [], findings


@pytest.mark.asyncio
async def test_actuator_plain_html_no_fp(monkeypatch):
    """actuator 200 但普通 HTML（无特征、非 JSON）→ 不得检出（TN）。"""
    responses = {
        f"{BASE}/actuator": (200, "<html><body>dashboard</body></html>", {"content-type": "text/html"})
    }
    monkeypatch.setattr(mod, "async_get", _mk(responses))
    findings = await mod.SpringActuatorEngine().scan(f"{BASE}/", None)
    assert findings == [], findings
