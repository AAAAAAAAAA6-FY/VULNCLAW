# -*- coding: utf-8 -*-
"""OAuth redirect_uri 绕过增强测试（真实 OAuthEngine.test_redirect_uri_hijack 逻辑 + 本地 aiohttp 靶场）。

覆盖三类端点：
  · /oauth/authorize       —— buggy（校验缺失）：任意 redirect_uri 都把授权码下发至攻击者域（正例）
  · /oauth/authorize_vuln  —— 后缀/编码白名单校验可绕过（https://trusted.com.evil.com、%40 编码）→ 302 带 code 到 attacker（正例）
  · /oauth/authorize_safe  —— 严格域名白名单，非本域 redirect_uri 一律 400 无 code（反例，fail-closed）

运行：python -m pytest tests/test_oauth_redirect_bypass.py -q
"""
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from aiohttp import web, ClientSession
from aiohttp.test_utils import TestServer

from vulnclaw.engines.auth_engines import OAuthEngine


ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


def _build_app():
    async def authorize(request):
        # 正例：buggy"前缀校验"——naive 截取 '://' 与 '/' 之间字段并 startswith('trusted.com')，
        # 不识别 userinfo/@ 分隔，导致 https://trusted.com@evil.com/... 被误放行并把授权码下发攻击者域
        ru = request.query.get("redirect_uri", "")
        allowed = False
        if ru.startswith("http://") or ru.startswith("https://"):
            rest = ru.split("://", 1)[1]
            naive_host = rest.split("/", 1)[0]
            allowed = naive_host.startswith("trusted.com")
        if allowed:
            return web.Response(status=302, headers={"Location": "https://evil.com/callback?code=abc123"}, text="")
        return web.Response(status=400, text="bad redirect_uri")

    async def authorize_vuln(request):
        # 正例：buggy"后缀白名单"——endswith('trusted.com') 即放行，trusted.com.evil.com 与 %40 编码可绕过
        ru = request.query.get("redirect_uri", "")
        if ru.endswith("trusted.com") or "%40trusted.com" in ru:
            return web.Response(
                status=302, headers={"Location": "https://attacker.com/callback?code=abc123"}, text=""
            )
        return web.Response(status=400, text="bad redirect_uri")

    async def authorize_safe(request):
        # 反例：严格域名白名单，任何非本域 redirect_uri 返回 400 且不含授权码
        ru = request.query.get("redirect_uri", "")
        host = (urlparse(ru).hostname or "").lower()
        if host in ALLOWED_HOSTS:
            return web.Response(
                status=302, headers={"Location": "http://127.0.0.1:0/oauth/callback?code=ok"}, text=""
            )
        return web.Response(status=400, text="denied")

    app = web.Application()
    app.router.add_get("/oauth/authorize", authorize)
    app.router.add_get("/oauth/authorize_vuln", authorize_vuln)
    app.router.add_get("/oauth/authorize_safe", authorize_safe)
    return app


@pytest_asyncio.fixture
async def server():
    app = _build_app()
    srv = TestServer(app)
    await srv.start_server(host="127.0.0.1", port=None)
    try:
        yield srv
    finally:
        await srv.close()


@pytest_asyncio.fixture
async def session():
    async with ClientSession() as s:
        yield s


def _params(redirect_uri: str) -> dict:
    return {"client_id": "demo", "redirect_uri": redirect_uri, "response_type": "code"}


async def _run_bypass(engine: OAuthEngine, base: str, path: str, redirect_uri: str, session):
    url = f"{base}{path}"
    return await engine.test_redirect_uri_hijack(url, _params(redirect_uri), session)


@pytest.mark.asyncio
async def test_at_obfuscation_positive(server, session):
    """正例：/oauth/authorize 对 @ 混淆变体产出 finding（证据含攻击者域）。"""
    base = f"http://127.0.0.1:{server.port}"
    engine = OAuthEngine()
    f = await _run_bypass(
        engine, base, "/oauth/authorize", "https://trusted.com@evil.com/callback", session
    )
    assert f is not None, "应产出 redirect_uri 绕过 finding"
    evidence = f.get("evidence", "")
    assert "evil.com" in evidence or "redirect_uri" in evidence
    assert "绕过" in f.get("type", "") or "Redirect" in f.get("type", "")


@pytest.mark.asyncio
async def test_suffix_encoding_positive(server, session):
    """正例：/oauth/authorize_vuln 后缀/编码变体至少一个产出 finding。"""
    base = f"http://127.0.0.1:{server.port}"
    engine = OAuthEngine()
    for variant in ("https://trusted.com.evil.com", "https://evil.com%40trusted.com/"):
        f = await _run_bypass(engine, base, "/oauth/authorize_vuln", variant, session)
        assert f is not None, f"变体 {variant} 应产出 finding"
        assert "attacker.com" in f.get("evidence", "")


@pytest.mark.asyncio
async def test_safe_deny_negative(server, session):
    """反例：/oauth/authorize_safe 拒绝非本域 redirect_uri，不产 finding（fail-closed）。"""
    base = f"http://127.0.0.1:{server.port}"
    engine = OAuthEngine()
    for variant in ("https://trusted.com@evil.com/callback", "https://evil.com/callback"):
        f = await _run_bypass(engine, base, "/oauth/authorize_safe", variant, session)
        assert f is None, f"反例变体 {variant} 不应产出 finding（低误报铁律）"