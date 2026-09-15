# -*- coding: utf-8 -*-
"""工作流8：出站白名单 + 平台级 SSRF/DNS-rebinding 防护（主链路接线回归）。

背景：防护实现（core/http_client.py: check_egress/check_ssrf）原本只挂在 httpx 路径
（默认关闭），而主链路 aiohttp（core/utils._http_request）未接 → 默认配置下防护等于
不存在。本组用例锁死"已接线 + 默认零行为变更"。

覆盖：
  A 默认 off：零拦截（回归门禁，绝不改变现有扫描行为）
  B 出站白名单：非白名单 host 拦截、白名单（含 fnmatch 通配）放行
  C SSRF 防护：SSRF_GUARD=1 → 回环/私网拦截；SSRF_ALLOW_PRIVATE 精确放行
  D DNS-rebinding：首次解析记录 → 重解析不一致立即拦截
  E 主链路集成：aiohttp 路径命中拦截返回 (0, 原因, {})；默认 off 时正常请求不受影响
"""
import itertools
import socket

import pytest
import pytest_asyncio
from aiohttp import web

from vulnclaw.config.settings import settings


@pytest.fixture(autouse=True)
def _clean_guard_state(monkeypatch):
    """每个用例还原三个开关 + DNS 解析历史，避免用例间污染。"""
    from vulnclaw.core import http_client

    monkeypatch.setattr(settings, "egress_allowlist", "")
    monkeypatch.setattr(settings, "ssrf_guard", "0")
    monkeypatch.setattr(settings, "ssrf_allow_private", "")
    monkeypatch.setattr(http_client, "_first_resolved", {})
    yield


def _reason(url: str):
    from vulnclaw.core.utils import _egress_ssrf_block_reason

    return _egress_ssrf_block_reason(url)


# ============================================================
# A. 默认 off：零行为变更
# ============================================================
def test_default_off_is_noop():
    """两个开关都关时：任何 URL 都不得被拦（含回环/私网）。"""
    assert _reason("http://evil.example.com/") is None
    assert _reason("http://127.0.0.1:8080/") is None
    assert _reason("http://10.0.0.1/") is None


# ============================================================
# B. 出站白名单（EGRESS_ALLOWLIST）
# ============================================================
def test_egress_allowlist_blocks_and_allows(monkeypatch):
    monkeypatch.setattr(settings, "egress_allowlist", "*.corp.internal, allowed.test")
    assert _reason("http://evil.com/") is not None, "非白名单 host 未被拦截"
    assert _reason("http://a.corp.internal/") is None, "通配白名单主机被误拦"
    assert _reason("http://allowed.test/") is None, "精确白名单主机被误拦"


# ============================================================
# C. SSRF 防护（SSRF_GUARD=1）
# ============================================================
def test_ssrf_guard_blocks_loopback(monkeypatch):
    monkeypatch.setattr(settings, "ssrf_guard", "1")
    assert _reason("http://127.0.0.1/") is not None, "回环地址未被 SSRF 防护拦截"


def test_ssrf_guard_allows_whitelisted_private(monkeypatch):
    monkeypatch.setattr(settings, "ssrf_guard", "1")
    monkeypatch.setattr(settings, "ssrf_allow_private", "127.0.0.1")
    assert _reason("http://127.0.0.1/") is None, "SSRF_ALLOW_PRIVATE 内的回环被误拦"


# ============================================================
# D. DNS-rebinding
# ============================================================
def test_dns_rebinding_detected(monkeypatch):
    """同一 host 两次解析到不同 IP（公网换公网）→ 第二次必须拦截。"""
    monkeypatch.setattr(settings, "ssrf_guard", "1")
    seq = itertools.count()

    def fake_getaddrinfo(host, port, *args, **kwargs):
        ip = "93.184.216.34" if next(seq) == 0 else "198.51.100.7"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert _reason("http://rebind.test/") is None, "首次解析（公网 IP）不应拦截"
    assert _reason("http://rebind.test/") is not None, "重解析不一致未被判为 DNS-rebinding"


# ============================================================
# E. 主链路（aiohttp）集成
# ============================================================
@pytest.mark.asyncio
async def test_http_request_blocked_returns_zero(monkeypatch):
    """主链路命中拦截：返回 (0, 原因, {})（与超时/网络错误同一约定），不得抛异常。"""
    monkeypatch.setattr(settings, "egress_allowlist", "only-this.test")
    from vulnclaw.core.utils import _http_request

    status, text, _headers = await _http_request("GET", "http://evil.test/", no_retry=True)
    assert status == 0
    assert "Blocked" in text


@pytest_asyncio.fixture
async def lab():
    app = web.Application()

    async def ok(request):
        return web.Response(text="alive")

    app.router.add_get("/ok", ok)
    from aiohttp.test_utils import TestServer

    server = TestServer(app)
    await server.start_server(host="127.0.0.1", port=None)
    try:
        yield f"http://127.0.0.1:{server.port}"
    finally:
        await server.close()


@pytest_asyncio.fixture
async def session():
    from aiohttp import ClientSession

    async with ClientSession() as s:
        yield s


@pytest.mark.asyncio
async def test_default_off_normal_request_ok(lab, session):
    """默认 off：aiohttp 主链路对回环靶场的正常请求不受任何影响（回归门禁）。"""
    from vulnclaw.core.utils import async_get

    status, text, _headers = await async_get(f"{lab}/ok", session=session, no_retry=True)
    assert status == 200
    assert text == "alive"
