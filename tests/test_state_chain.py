# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# tests/test_state_chain.py
"""
StateChainEngine 单元测试：二次存储触发 + 越序直达（2 正 2 反）。

运行：python -m pytest tests/test_state_chain.py -v
"""
import pytest
import pytest_asyncio
from aiohttp import web, ClientSession
from aiohttp.test_utils import TestServer

from vulnclaw.engines.state_chain import StateChainEngine

# 进程内"存储"（每个测试在 fixture 里清空）
_STORE = []
# 越序守卫开关：on 时 /admin/step3 无 cookie 返回 403 登录页
_GUARD = {"on": False}


def _build_app():
    app = web.Application()

    # 存储型注入点：带 stchain_ 标记的 q 被持久化
    async def _store(request):
        q = request.query.get("q", "")
        if q.startswith("stchain_"):
            _STORE.append(q)
        return web.Response(text="<html><body><h1>Store</h1><p>saved</p></body></html>")

    # 消费端点：回显已存储的标记
    async def _consume(request):
        lis = "".join(f"<li>{p}</li>" for p in _STORE)
        return web.Response(text=f"<html><body><h1>Consume</h1><ul>{lis}</ul><p>ok</p></body></html>")

    # 纯反射：只回显参数，不存储
    async def _reflect(request):
        q = request.query.get("q", "")
        return web.Response(text=f"<html><body><h1>Reflect</h1><div>{q}</div></body></html>")

    # 登录页（正常流程首步）
    async def _login(request):
        return web.Response(
            text="<html><body><h1>Login</h1><form action=/login>user pass</form>"
                 "<p>sign in</p></body></html>"
        )

    # 阶段端点：未加守卫时无 cookie 也返回 200 业务页（越序直达）
    async def _admin3(request):
        if _GUARD["on"]:
            return web.Response(
                text="<html><body><h1>Login</h1><p>please login</p></body></html>", status=403
            )
        return web.Response(
            text="<html><body><h1>Dashboard</h1>" + "<p>row</p>" * 40 + "</body></html>"
        )

    app.router.add_get("/store", _store)
    app.router.add_get("/consume", _consume)
    app.router.add_get("/reflect", _reflect)
    app.router.add_get("/login", _login)
    app.router.add_get("/admin/step3", _admin3)
    return app


@pytest_asyncio.fixture
async def lab():
    app = _build_app()
    server = TestServer(app)
    await server.start_server(host="127.0.0.1", port=None)
    try:
        _STORE.clear()
        _GUARD["on"] = False
        yield f"http://127.0.0.1:{server.port}"
    finally:
        await server.close()


@pytest_asyncio.fixture
async def session():
    async with ClientSession() as s:
        yield s


def _normal_resp():
    return (200, "<html><body></body></html>", {})


# ============================================================
# 正例
# ============================================================
@pytest.mark.asyncio
async def test_state_chain_second_order_detected(lab, session):
    eng = StateChainEngine()
    store_url = f"{lab}/store?q=x"
    consume_url = f"{lab}/consume"
    result = await eng.check(
        store_url, "q", _normal_resp(), "q=x", session, endpoints=[consume_url]
    )
    assert result, "未检出二次存储触发"
    type_l = str(result.get("type", "")).lower()
    assert "stored" in type_l or "second" in type_l, f"类型异常: {result.get('type')}"
    assert "stchain_" in str(result.get("evidence", "")), f"证据应含随机标记: {result}"


@pytest.mark.asyncio
async def test_state_chain_bypass_detected(lab, session):
    _GUARD["on"] = False
    eng = StateChainEngine()
    url = f"{lab}/admin/step3"
    result = await eng.check(url, "x", _normal_resp(), "", session)
    assert result, "未检出越序直达"
    type_l = str(result.get("type", "")).lower()
    assert "bypass" in type_l or "越序" in str(result.get("type", "")), \
        f"类型异常: {result.get('type')}"


# ============================================================
# 反例
# ============================================================
@pytest.mark.asyncio
async def test_state_chain_no_fp_on_guarded(lab, session):
    _GUARD["on"] = True
    eng = StateChainEngine()
    url = f"{lab}/admin/step3"
    result = await eng.check(url, "x", _normal_resp(), "", session)
    assert result is None, f"受保护端点上误报: {result}"


@pytest.mark.asyncio
async def test_state_chain_no_fp_on_pure_reflect(lab, session):
    eng = StateChainEngine()
    url = f"{lab}/reflect?q=x"
    consume_url = f"{lab}/consume"
    result = await eng.check(
        url, "q", _normal_resp(), "q=x", session, endpoints=[consume_url]
    )
    assert result is None, f"纯反射端点上误报: {result}"