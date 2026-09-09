# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# tests/test_deep_chimera.py
"""
DeepChimeraEngine（深藏复合漏洞引擎）单元测试。

覆盖三件事：
  1. 正例：多层编码载荷被"深藏回显点"（URL+HTML+JSON 多解剥壳）还原成可执行形态
     -> 必须检出 >=1 条 finding 且 type/severity/evidence 齐全；
  2. 反例：干净端点固定 200 纯净页面（无回显/无差异）-> 不得误报；
  3. 反例：httpbin 模式纯反射端点（只把参数原文回显，不做深度剥壳）
     -> 严格筛选器必须丢弃（0 条）。

运行：python -m pytest tests/test_deep_chimera.py -v
"""
import html

import pytest
import pytest_asyncio
from aiohttp import web, ClientSession
from aiohttp.test_utils import TestServer
from urllib.parse import unquote


def _deep_decode(q: str) -> str:
    """模拟"深藏回显点"：目标把 URL 编码 -> HTML 实体 -> JSON 转义逐层剥干净。"""
    d = q
    for _ in range(6):
        n = unquote(d)
        if n == d:
            break
        d = n
    d = html.unescape(d)
    d = d.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")
    return d


def _build_lab_app():
    async def _deep(request):
        q = request.query.get("q", "test")
        val = _deep_decode(q)
        return web.Response(
            text="<html>\n<body>\n<h1>Deep</h1>\n<div>" + val + "</div>\n"
            + ("<p>row</p>\n" * 40) + "</body>\n</html>"
        )

    async def _clean(request):
        return web.Response(
            text="<html>\n<body>\n<h1>Clean</h1>\n<div>fixed page no echo</div>\n"
            + ("<p>row</p>\n" * 40) + "</body>\n</html>"
        )

    async def _reflect(request):
        # httpbin 模式：只把参数原文回显（不做任何深度剥壳），留在编码/转义形态
        q = request.query.get("q", "")
        return web.Response(
            text="<html>\n<body>\n<h1>Reflect</h1>\n<div>" + q + "</div>\n"
            + ("<p>row</p>\n" * 40) + "</body>\n</html>"
        )

    app = web.Application()
    app.router.add_get("/deep", _deep)
    app.router.add_get("/clean", _clean)
    app.router.add_get("/reflect", _reflect)
    return app


@pytest_asyncio.fixture
async def lab_base():
    app = _build_lab_app()
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


def _dummy_normal():
    return (200, "<html><body><h1>placeholder</h1></body></html>", {})


# ============================================================
# 1. 正例：深藏回显点必须检出
# ============================================================
@pytest.mark.asyncio
async def test_deep_chimera_detects_encoded_injection(lab_base, session):
    from vulnclaw.engines.deep_chimera import DeepChimeraEngine

    eng = DeepChimeraEngine()
    url = f"{lab_base}/deep?q=x"
    result = await eng.check(url, "q", _dummy_normal(), "q=x", session)
    assert result, "DeepChimera 未检出多层编码深藏注入点"
    # 字段齐全
    for field in ("type", "severity", "title", "evidence", "url", "parameter", "confidence", "cvss"):
        assert field in result, f"finding 缺少字段: {field}"
    assert result.get("type") == "deep_chimera_encoded_injection"
    assert result.get("severity") in ("low", "medium", "high", "critical")
    assert isinstance(result.get("cvss"), float)
    assert result.get("parameter") == "q"


# ============================================================
# 2. 反例：干净端点不误报
# ============================================================
@pytest.mark.asyncio
async def test_deep_chimera_no_fp_on_clean(lab_base, session):
    from vulnclaw.engines.deep_chimera import DeepChimeraEngine

    eng = DeepChimeraEngine()
    url = f"{lab_base}/clean?q=x"
    result = await eng.check(url, "q", _dummy_normal(), "q=x", session)
    assert result is None, f"DeepChimera 在干净端点上误报: {result}"


# ============================================================
# 3. 反例：纯反射端点必须被筛选器丢弃
# ============================================================
@pytest.mark.asyncio
async def test_deep_chimera_no_fp_on_pure_reflection(lab_base, session):
    from vulnclaw.engines.deep_chimera import DeepChimeraEngine

    eng = DeepChimeraEngine()
    url = f"{lab_base}/reflect?q=x"
    result = await eng.check(url, "q", _dummy_normal(), "q=x", session)
    assert result is None, f"DeepChimera 对纯反射误报: {result}"