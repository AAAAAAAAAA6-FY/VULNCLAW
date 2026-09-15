# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# 验收：P2-1 httpbin 集成测试（OPTIMIZATION_ROADMAP.md）
#
# 用 vulnclaw 自身的 HTTP 层（core.utils.async_get）打 httpbin.org，验证
# 实时外网交互链路（GET/状态码回声/自定义头回声）在扫描管线里可用。
#
# 联网依赖：模块级 pytestmark 在 httpbin.org 不可达时整体 skip，避免离线 CI 抖动。
# 每个用例走 vulnclaw HTTP 客户端而非裸 urllib，确保测的是真实扫描链路。

import asyncio
import json
import urllib.request

import pytest

from vulnclaw.core.utils import async_get, async_post

HTTPBIN = "https://httpbin.org"


def _httpbin_reachable() -> bool:
    try:
        with urllib.request.urlopen(f"{HTTPBIN}/get", timeout=6) as r:
            return r.status == 200
    except Exception:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.network,
    pytest.mark.skipif(
        not _httpbin_reachable(),
        reason="httpbin.org 不可达（离线/网络受限），跳过 live 集成测试",
    ),
]


def test_httpbin_get_returns_200_and_json():
    """GET httpbin.org/get：状态码 200，且返回 JSON 含 url 字段。"""
    # proxy=None 强制直连（绕过代理池轮换）；use_shared=False 让每次调用在当前
    # asyncio.run 的事件循环内自建 session，避免复用旧循环已关闭的共享 session（Event loop is closed）。
    status, text, _ = asyncio.run(async_get(f"{HTTPBIN}/get", proxy=None, use_shared=False))
    assert status == 200
    data = json.loads(text)
    assert data.get("url") == f"{HTTPBIN}/get"


def test_httpbin_status_code_echo():
    """状态码回声：/status/404 应原样返回 404。"""
    status, _, _ = asyncio.run(async_get(f"{HTTPBIN}/status/404", proxy=None, use_shared=False))
    assert status == 404


def test_httpbin_custom_header_echo():
    """自定义请求头回声：vulnclaw 发出的头应被 httpbin 回显。"""
    status, text, _ = asyncio.run(
        async_get(f"{HTTPBIN}/headers", headers={"X-Vulnclaw-Test": "ping"}, proxy=None, use_shared=False)
    )
    assert status == 200
    data = json.loads(text)
    # httpbin 对自定义头保留原大小写，做大小写无关查找更稳
    echoed = {k.lower(): v for k, v in data["headers"].items()}
    assert echoed.get("x-vulnclaw-test") == "ping"


def test_httpbin_post_json_echo():
    """POST /post：vulnclaw 发出的 JSON body 应被 httpbin 原样回显（覆盖 method=POST + json 透传 + 响应解析）。"""
    payload = {"username": "alice", "scope": "read"}
    status, text, _ = asyncio.run(
        async_post(f"{HTTPBIN}/post", json=payload, proxy=None, use_shared=False)
    )
    assert status == 200
    data = json.loads(text)
    assert data.get("json") == payload


def test_httpbin_redirect_follows():
    """默认跟随重定向：/redirect/2 应最终落到 /get 并返回 200（验证扫描不漏掉重定向后的页面）。"""
    status, text, _ = asyncio.run(
        async_get(f"{HTTPBIN}/redirect/2", proxy=None, use_shared=False)
    )
    assert status == 200
    data = json.loads(text)
    assert data.get("url") == f"{HTTPBIN}/get"


def test_httpbin_response_headers_echo():
    """响应头读取：/response-headers 返回的自定义响应头应被 vulnclaw 解析到 headers（覆盖安全头/CORS 引擎所需的头读取链路）。"""
    status, _, headers = asyncio.run(
        async_get(
            f"{HTTPBIN}/response-headers?x-powered-by=vulnclaw&server-tag=scan",
            proxy=None, use_shared=False,
        )
    )
    assert status == 200
    norm = {k.lower(): v for k, v in headers.items()}
    assert norm.get("x-powered-by") == "vulnclaw"
    assert norm.get("server-tag") == "scan"
