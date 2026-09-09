# -*- coding: utf-8 -*-
"""ParsingShadowEngine（解析差异/语义分歧引擎）单元测试。

本地 aiohttp 靶场，覆盖：

正例：
  test_parsing_shadow_admin_flag_bypass   —— 鉴权参数"假值被忽略/取第一值"的语义分歧检出
  test_parsing_shadow_path_normalize     —— 路径归一化差异（403→200）的旁路检出

反例（误报控制）：
  test_parsing_shadow_no_fp_non_auth_param —— 非鉴权参数、所有变体一致 -> 0 findings
  test_parsing_shadow_no_fp_all_404       —— 所有路径/参数变体全 4xx -> 0 findings

运行：python -m pytest tests/test_parsing_shadow.py -v
"""
import pytest
import pytest_asyncio
from aiohttp import web, ClientSession
from aiohttp.test_utils import TestServer

from vulnclaw.engines.parsing_shadow import ParsingShadowEngine
from vulnclaw.engines.base import BaseEngine

# ---------------- 页面内容（互相区分、避免撞关键词） ----------------
HOME_PAGE = ("<html><body><h1>Home</h1><p>welcome to public index page of the demo app</p>"
             + "<p>static marketing content</p>" * 20 + "</body></html>")

PRIV_PAGE = ("<html><body><h1>Admin Panel - Authorized</h1><div>restricted dashboard</div>"
             + "<p>sensitive privileged user data record</p>" * 30 + "</body></html>")

ADMIN_PANEL = ("<html><body><h1>Admin Panel - Served</h1><div>private controls</div>"
               + "<p>administrative menu item with internal links</p>" * 30 + "</body></html>")

FORBIDDEN = "<html><body><h1>403 Forbidden</h1><p>access denied by server</p></body></html>"
NOT_FOUND = "<html><body><h1>404 Not Found</h1><p>the resource you requested does not exist</p></body></html>"
SAFE_ECHO = ("<html><body><h1>Echo</h1><p>same generic response regardless of any input</p>"
             + "<p>uniform body</p>" * 20 + "</body></html>")


# ---------------- 靶场 ----------------
def _build_app():
    async def _home(request):
        return web.Response(text=HOME_PAGE)

    # 鉴权语义端点：admin 精确等于 "true" 才返回业务页(200)，否则一律 403；
    # 同一参数重复出现时取 **第一个** 值（模拟 first-语义）。
    async def _auth(request):
        admin = request.query.get("admin")
        if admin == "true":
            return web.Response(text=PRIV_PAGE, status=200)
        return web.Response(text=FORBIDDEN, status=403)

    # 路径归一化：/admin 精确命中 -> 403；任何以 /admin 开头的变体（/admin/、/admin%2e%2e/、
    # /admin;x=1、大小写等）由兜底路由放行为业务页(200)，模拟网关与源站解析不一致。
    async def _admin(request):
        return web.Response(text=FORBIDDEN, status=403)

    async def _fallback(request):
        path = request.path
        if path.startswith("/admin"):
            return web.Response(text=ADMIN_PANEL, status=200)
        return web.Response(text=NOT_FOUND, status=404)

    # 所有参数变体响应一致的普通端点 + 一律拒绝端点
    async def _echo(request):
        return web.Response(text=SAFE_ECHO)

    async def _denyall(request):
        return web.Response(text=FORBIDDEN, status=403)

    app = web.Application()
    app.router.add_get("/", _home)
    app.router.add_get("/auth", _auth)
    app.router.add_get("/admin", _admin)
    app.router.add_get("/echo", _echo)
    app.router.add_get("/denyall", _denyall)
    app.router.add_get("/{tail:.*}", _fallback)
    return app


@pytest_asyncio.fixture
async def lab():
    app = _build_app()
    server = TestServer(app)
    await server.start_server(host="127.0.0.1", port=None)
    try:
        yield f"http://127.0.0.1:{server.port}"
    finally:
        await server.close()


@pytest_asyncio.fixture
async def session():
    async with ClientSession() as s:
        yield s


def _normal_resp():
    return (200, SAFE_ECHO, {})


# ---------------- 正例 ----------------
@pytest.mark.asyncio
async def test_parsing_shadow_admin_flag_bypass(lab, session):
    eng = ParsingShadowEngine()
    url = f"{lab}/auth?admin=false"
    result = await eng.check(url, "admin", _normal_resp(), "admin=false", session)
    assert result, "ParsingShadow 未检出鉴权参数语义分歧（假值被忽略）"
    assert result.get("type") == "parsing_shadow_auth_semantic_divergence", result.get("type")
    assert result.get("parameter") == "admin"
    # finding 字段齐全
    for field in ("type", "severity", "title", "description", "evidence", "remediation",
                  "recommendation", "url", "parameter", "method", "confidence", "cvss"):
        assert field in result, f"finding 缺少字段 {field}"


@pytest.mark.asyncio
async def test_parsing_shadow_path_normalize(lab, session):
    eng = ParsingShadowEngine()
    findings = await eng.scan(f"{lab}/admin", session)
    assert findings, "ParsingShadow 未检出路径归一化分歧（403→200）"
    assert any(f.get("type") == "parsing_shadow_path_normalization_bypass" for f in findings), findings


# ---------------- 反例（误报控制） ----------------
@pytest.mark.asyncio
async def test_parsing_shadow_no_fp_non_auth_param(lab, session):
    eng = ParsingShadowEngine()
    # 普通参数无鉴权语义 + 所有变体响应一致 -> check 应 inoperant
    url = f"{lab}/echo?q=hello"
    result = await eng.check(url, "q", _normal_resp(), "q=hello", session)
    assert result is None, f"非鉴权参数被误报: {result}"
    # scan 在"不区分"的普通页面上也不产出（基线 200，非 4xx）
    assert await eng.scan(f"{lab}/echo", session) == []


@pytest.mark.asyncio
async def test_parsing_shadow_no_fp_all_404(lab, session):
    eng = ParsingShadowEngine()
    # 所有路径变体全 4xx
    findings = await eng.scan(f"{lab}/locked", session)
    assert findings == [], f"全 404 路径被误报: {findings}"
    # 鉴权参数但目标对所有取值一律 4xx -> check 不报
    result = await eng.check(f"{lab}/denyall?admin=true", "admin", _normal_resp(), "admin=true", session)
    assert result is None, f"全 4xx 鉴权端点被误报: {result}"


@pytest.mark.asyncio
async def test_parsing_shadow_is_base_engine():
    eng = ParsingShadowEngine()
    assert isinstance(eng, BaseEngine)
    assert eng.name == "parsing_shadow"