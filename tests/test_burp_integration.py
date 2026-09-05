# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""Burp 集成回归测试（两块砖的防线）：

砖1 _verify_with_burp_repeater：基线 vs 载荷的重放对比验证
    （回显信号 / 5xx 突变信号 / Burp 历史基线 / 守卫与异常安全）。
砖2 fetch_burp_issues 可执行工具（TOOL_REGISTRY 注册 + Burp 可用性分支）
    + MCP burp.scan 接线。

全部离线：假 burp_client + monkeypatch async_get / execute_tool，不碰网络。
"""
import json
import types

import pytest

import vulnclaw.core.utils as core_utils
from vulnclaw.ai.v100.phases.phases_verify import _verify_with_burp_repeater


# ============================================================
# 砖 1：Repeater 重放对比验证
# ============================================================
class _FakeBurpClient:
    def __init__(self, history=None, fail_history=False):
        self.history = history or []
        self.fail_history = fail_history

    async def get_history_since(self, timestamp, limit=50):
        if self.fail_history:
            raise RuntimeError("bridge down")
        return self.history


def _orch(burp_available=True, client=None):
    orch = types.SimpleNamespace()
    orch.burp_available = burp_available
    orch.burp_client = client if client is not None else _FakeBurpClient()
    orch.session = object()
    return orch


def _vuln(payload="<script>alert(1)</script>", param="q", url="http://t/search"):
    return {"type": "XSS", "url": url, "parameter": param,
            "payload": payload, "severity": "High"}


@pytest.mark.asyncio
async def test_repeater_confirms_on_payload_reflection(monkeypatch):
    """攻击响应回显载荷而基线没有 → 确认（payload_reflected），基线+攻击共 2 次请求。"""
    calls = []

    async def fake_async_get(url, **kw):
        calls.append(url)
        if "q=" in url:  # build_attack_url 注入参数后的攻击请求
            return 200, "<div>echo <script>alert(1)</script></div>", {}
        return 200, "<div>normal page</div>", {}

    monkeypatch.setattr(core_utils, "async_get", fake_async_get)
    res = await _verify_with_burp_repeater(
        _orch(client=_FakeBurpClient(history=[])), _vuln())
    assert res["confirmed"] is True
    assert "payload_reflected" in res["signals"]
    assert res["verification_method"] == "burp_replay_diff"
    assert len(calls) == 2  # 基线 + 攻击


@pytest.mark.asyncio
async def test_repeater_confirms_on_status_shift(monkeypatch):
    """基线 200 → 攻击 500（报错型注入特征）→ 确认（status_shift_5xx）。"""

    async def fake_async_get(url, **kw):
        if "q=" in url:
            return 500, "SQL syntax error near", {}
        return 200, "normal page", {}

    monkeypatch.setattr(core_utils, "async_get", fake_async_get)
    res = await _verify_with_burp_repeater(
        _orch(), _vuln(payload="' AND 1=1--"))
    assert res["confirmed"] is True
    assert "status_shift_5xx" in res["signals"]


@pytest.mark.asyncio
async def test_repeater_uses_burp_history_baseline(monkeypatch):
    """Burp 历史里有该 URL → 用它当基线，不再直连（只发 1 次攻击请求）。"""
    hist = [{"url": "http://t/search", "status": 200, "body": "cached normal"}]
    seen = []

    async def fake_async_get(url, **kw):
        seen.append(url)
        return 500, "error page", {}

    monkeypatch.setattr(core_utils, "async_get", fake_async_get)
    res = await _verify_with_burp_repeater(
        _orch(client=_FakeBurpClient(history=hist)), _vuln(payload="' AND 1=1--"))
    assert len(seen) == 1
    assert res["baseline_status"] == 200
    assert res["confirmed"] is True  # 基线 200 → 攻击 500


@pytest.mark.asyncio
async def test_repeater_burp_unavailable():
    res = await _verify_with_burp_repeater(_orch(burp_available=False), _vuln())
    assert res == {"confirmed": False, "reason": "burp_unavailable"}


@pytest.mark.asyncio
async def test_repeater_missing_payload_returns_insufficient():
    v = _vuln()
    v["payload"] = ""
    res = await _verify_with_burp_repeater(_orch(), v)
    assert res["confirmed"] is False
    assert res["reason"] == "insufficient_param_payload"


@pytest.mark.asyncio
async def test_repeater_never_raises(monkeypatch):
    """历史桥挂了 + 网络也挂了 → 返回未确认而不是抛异常（绝不影响验证主流程）。"""
    client = _FakeBurpClient(fail_history=True)

    async def boom(url, **kw):
        raise RuntimeError("net down")

    monkeypatch.setattr(core_utils, "async_get", boom)
    res = await _verify_with_burp_repeater(_orch(client=client), _vuln())
    assert res["confirmed"] is False


# ============================================================
# 砖 2：fetch_burp_issues 可执行工具 + MCP burp.scan
# ============================================================
@pytest.mark.asyncio
async def test_fetch_burp_issues_registered():
    from vulnclaw.ai.tools import TOOL_REGISTRY

    assert "fetch_burp_issues" in TOOL_REGISTRY  # 幽灵 metadata 名已成为真工具


@pytest.mark.asyncio
async def test_fetch_burp_issues_unavailable(monkeypatch):
    import vulnclaw.ai.burp as burp_mod

    monkeypatch.setattr(burp_mod, "get_burp_client", lambda: None)
    from vulnclaw.ai.tools import execute_tool

    res = await execute_tool("fetch_burp_issues", url="http://t/")
    assert res["success"] is False
    assert res["burp_available"] is False


@pytest.mark.asyncio
async def test_fetch_burp_issues_burp_not_running(monkeypatch):
    import vulnclaw.ai.burp as burp_mod

    class _C:
        async def get_status(self):
            return False

    monkeypatch.setattr(burp_mod, "get_burp_client", lambda: _C())
    from vulnclaw.ai.tools import execute_tool

    res = await execute_tool("fetch_burp_issues", url="http://t/")
    assert res["success"] is False
    assert "REST API" in res["error"]


@pytest.mark.asyncio
async def test_fetch_burp_issues_collects(monkeypatch):
    import vulnclaw.ai.burp as burp_mod

    class _C:
        async def get_status(self):
            return True

        async def scan_and_collect(self, urls=None, wait_timeout=120):
            assert urls == ["http://t/"]
            return [{"type": "SQL injection", "severity": "High", "url": "http://t/"}]

    monkeypatch.setattr(burp_mod, "get_burp_client", lambda: _C())
    from vulnclaw.ai.tools import execute_tool

    res = await execute_tool("fetch_burp_issues", url="http://t/")
    assert res["success"] is True
    assert res["count"] == 1


@pytest.mark.asyncio
async def test_mcp_burp_scan_routes_and_normalizes_url(monkeypatch):
    """MCP burp.scan → execute_tool('fetch_burp_issues')；无协议 URL 自动补全。"""
    import vulnclaw.ai.tools as tools_mod

    seen = {}

    async def fake_execute(name, **kw):
        seen["name"] = name
        seen["url"] = kw.get("url")
        return {"tool": name, "success": True, "count": 2, "issues": []}

    monkeypatch.setattr(tools_mod, "execute_tool", fake_execute)
    from vulnclaw.core.mcp_server import MCPJsonRpcHandler

    res = await MCPJsonRpcHandler._tool_burp_scan(
        types.SimpleNamespace(), {"url": "t/"})
    assert seen["name"] == "fetch_burp_issues"
    assert seen["url"] == "https://t/"
    payload = json.loads(res["content"][0]["text"])
    assert payload["count"] == 2


# ============================================================
# 砖 3：真 Intruder（扩展桥 1.1.0+/vulnclaw/intruder + 工具 + MCP 接线）
# ============================================================
class _FakeResp:
    def __init__(self, status=200, body=None):
        self.status = status
        self._body = body if body is not None else {"status": "ok", "count": 2, "ok": 2,
                                                    "results": [{"ok": True, "payload": "a",
                                                                 "status": 200, "length": 10, "ms": 5}]}

    async def json(self, content_type=None):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, resp):
        self.resp = resp
        self.posts = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.posts.append({"url": url, "data": data})
        return self.resp


def _client():
    from vulnclaw.ai.burp import BurpClient

    return BurpClient()


@pytest.mark.asyncio
async def test_burp_intruder_registered():
    from vulnclaw.ai.tools import TOOL_REGISTRY

    assert "burp_intruder" in TOOL_REGISTRY


@pytest.mark.asyncio
async def test_run_intruder_posts_to_bridge(monkeypatch):
    import vulnclaw.ai.burp as burp_mod

    sess = _FakeSession(_FakeResp(200))
    async def fake_shared():
        return sess
    monkeypatch.setattr(burp_mod, "get_shared_session", fake_shared)
    res = await _client().run_intruder(
        "http://t/?q=FUZZ", ["a", "b", " ", "c"], marker="FUZZ")
    assert res is not None and res["count"] == 2
    assert sess.posts[0]["url"].endswith("/vulnclaw/intruder")
    body = json.loads(sess.posts[0]["data"].decode("utf-8"))
    assert body["payloads"] == ["a", "b", "c"]  # 空白 payload 剔除
    assert body["marker"] == "FUZZ" and body["method"] == "GET"


@pytest.mark.asyncio
async def test_run_intruder_bridge_down_returns_none(monkeypatch):
    import vulnclaw.ai.burp as burp_mod

    sess = _FakeSession(_FakeResp(404))
    async def fake_shared():
        return sess
    monkeypatch.setattr(burp_mod, "get_shared_session", fake_shared)
    assert await _client().run_intruder("http://t/?q=FUZZ", ["a"]) is None


@pytest.mark.asyncio
async def test_burp_intruder_tool_executes(monkeypatch):
    import vulnclaw.ai.burp as burp_mod
    import vulnclaw.core.danger_guard as dg_mod

    monkeypatch.setattr(
        dg_mod.guard, "require_tool_approval", lambda *a, **k: True)

    class _C:
        async def run_intruder(self, url, payloads, **kw):
            assert url == "http://t/?q=FUZZ"
            assert payloads == ["a", "b"]
            return {"status": "ok", "count": 2, "ok": 2,
                    "results": [{"ok": True, "payload": "a", "status": 200,
                                 "length": 5, "ms": 3}]}
    monkeypatch.setattr(burp_mod, "get_burp_client", lambda: _C())
    from vulnclaw.ai.tools import execute_tool

    res = await execute_tool(
        "burp_intruder", url="http://t/?q=FUZZ", payloads="a,b")
    assert res["success"] is True and res["count"] == 2
    assert res["results"][0]["status"] == 200


@pytest.mark.asyncio
async def test_burp_intruder_tool_guard_denied(monkeypatch):
    import vulnclaw.core.danger_guard as dg_mod

    monkeypatch.setattr(
        dg_mod.guard, "require_tool_approval", lambda *a, **k: False)
    from vulnclaw.ai.tools import execute_tool

    res = await execute_tool("burp_intruder", url="http://t/?q=FUZZ", payloads="a")
    assert res["success"] is False and res.get("guard_denied") is True


@pytest.mark.asyncio
async def test_burp_intruder_tool_bridge_unavailable(monkeypatch):
    import vulnclaw.ai.burp as burp_mod
    import vulnclaw.core.danger_guard as dg_mod

    monkeypatch.setattr(dg_mod.guard, "require_tool_approval", lambda *a, **k: True)

    class _C:
        async def run_intruder(self, url, payloads, **kw):
            return None  # 桥未运行
    monkeypatch.setattr(burp_mod, "get_burp_client", lambda: _C())
    from vulnclaw.ai.tools import execute_tool

    res = await execute_tool("burp_intruder", url="http://t/?q=FUZZ", payloads="a")
    assert res["success"] is False and res["burp_available"] is False
    assert "fallback_hint" in res


@pytest.mark.asyncio
async def test_mcp_burp_intruder_routes(monkeypatch):
    """MCP burp.intruder → execute_tool('burp_intruder')；URL 自动补协议。"""
    import vulnclaw.ai.tools as tools_mod

    seen = {}

    async def fake_execute(name, **kw):
        seen["name"] = name
        seen["url"] = kw.get("url")
        seen["payloads"] = kw.get("payloads")
        return {"tool": name, "success": True, "count": 2, "ok": 2, "results": []}

    monkeypatch.setattr(tools_mod, "execute_tool", fake_execute)
    from vulnclaw.core.mcp_server import MCPJsonRpcHandler

    res = await MCPJsonRpcHandler._tool_burp_intruder(
        types.SimpleNamespace(), {"url": "t/?q=FUZZ", "payloads": "a,b"})
    assert seen["name"] == "burp_intruder"
    assert seen["url"] == "https://t/?q=FUZZ"
    assert seen["payloads"] == "a,b"
    payload = json.loads(res["content"][0]["text"])
    assert payload["ok"] == 2
