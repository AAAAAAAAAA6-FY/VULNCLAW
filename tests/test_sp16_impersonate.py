# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP16.2（A 线）TLS 指纹伪装通道 单元测试。

覆盖（全部离线，不触网）：
- 开关默认关 -> impersonate_enabled() False（零行为回归）；
- curl_cffi 缺失 -> 请求函数返回 None（优雅降级不抛错）；
- 开启 + mock AsyncSession -> impersonate_request 走伪装通道，
  返回 (status, text, headers) 且把 browser 传给 curl_cffi；
- scanner.safe_request 接线：伪装可用时优先走 impersonate，
  不可用时照旧走 http2/aiohttp（monkeypatch 记录调用）。
"""
import asyncio
from typing import ClassVar

import pytest

from vulnclaw.core import impersonate as imp_mod
from vulnclaw.core.settings import settings


@pytest.fixture(autouse=True)
def _restore_impersonate_module_state():
    """本文件多处**直接给模块全局赋值**（CURL_CFFI_AVAILABLE / AsyncSession），
    这些赋值不会像 monkeypatch 那样自动回滚 → 污染同 worker 的后续用例
    （实测：把 `test_unavailable_module_returns_none` 从"跳过/返回 None"变成
    "伪装通道可用 → 返回真响应"，全量跑红、单独跑绿）。这里统一快照+还原。
    """
    saved = (
        imp_mod.CURL_CFFI_AVAILABLE,
        getattr(imp_mod, "AsyncSession", None),
        getattr(imp_mod, "_impersonate_session", None),
    )
    try:
        yield
    finally:
        imp_mod.CURL_CFFI_AVAILABLE = saved[0]
        imp_mod.AsyncSession = saved[1]
        if hasattr(imp_mod, "_impersonate_session"):
            imp_mod._impersonate_session = saved[2]


def _on(browser: str = "chrome") -> None:
    settings.http_impersonate = True
    settings.http_impersonate_browser = browser
    # SP24 §22.2 后 http_impersonate_rotate 默认开：钉死单元素池=单例语义，避免轮换首取非预期 browser
    settings.http_impersonate_pool = [browser]
    settings.http_impersonate_rotate = False


def _off() -> None:
    settings.http_impersonate = False
    settings.http_impersonate_browser = "chrome"
    settings.http_impersonate_rotate = True       # 恢复 SP24 默认值（防单例跨测试污染）
    settings.http_impersonate_pool = ["chrome", "firefox", "safari"]


# ---------- 开关 / 降级 ----------

def test_default_off_zero_regression():
    _off()
    assert imp_mod.impersonate_enabled() is False


def test_unavailable_module_returns_none():
    """curl_cffi 未装时的行为：不抛错、返回 None（调用方降级）。"""
    if imp_mod.CURL_CFFI_AVAILABLE:
        pytest.skip("curl_cffi 已安装，跳过无库降级用例")
    assert asyncio.run(imp_mod.impersonate_get("http://t/x")) is None
    assert asyncio.run(imp_mod.impersonate_post("http://t/x", json={"a": 1})) is None


# ---------- mock 伪装通道 ----------

class _FakeResp:
    status_code = 200
    text = "ok-body"
    headers: ClassVar[dict] = {"Server": "nginx"}


class _FakeAsyncSession:
    captured: ClassVar[dict] = {}

    def __init__(self, impersonate: str = ""):
        _FakeAsyncSession.captured["impersonate"] = impersonate

    async def request(self, method, url, **kwargs):
        _FakeAsyncSession.captured["method"] = method
        _FakeAsyncSession.captured["url"] = url
        _FakeAsyncSession.captured["kwargs"] = kwargs
        return _FakeResp()


def test_enabled_uses_impersonation_backend(monkeypatch):
    _on(browser="chrome")
    imp_mod.AsyncSession = _FakeAsyncSession
    imp_mod.CURL_CFFI_AVAILABLE = True
    body = asyncio.run(imp_mod.impersonate_get(
        "http://t/x?s=1", params={"id": "7"}, headers={"UA": "x"}, timeout=5))
    try:
        assert body == (200, "ok-body", {"Server": "nginx"})
        assert _FakeAsyncSession.captured["impersonate"] == "chrome"
        assert _FakeAsyncSession.captured["url"] == "http://t/x?s=1"
        assert _FakeAsyncSession.captured["kwargs"]["params"] == {"id": "7"}
        assert _FakeAsyncSession.captured["kwargs"]["headers"] == {"UA": "x"}
        assert _FakeAsyncSession.captured["kwargs"]["timeout"] == 5.0
        assert _FakeAsyncSession.captured["method"] == "GET"
    finally:
        _off()


def test_post_backend_passes_data_json(monkeypatch):
    _on()
    imp_mod.AsyncSession = _FakeAsyncSession
    imp_mod.CURL_CFFI_AVAILABLE = True
    body = asyncio.run(imp_mod.impersonate_post(
        "http://t/x", data={"a": "1"}, headers={"CT": "app/x"}))
    try:
        assert body == (200, "ok-body", {"Server": "nginx"})
        assert _FakeAsyncSession.captured["method"] == "POST"
        assert _FakeAsyncSession.captured["kwargs"]["data"] == {"a": "1"}
    finally:
        _off()


def test_backend_exception_returns_none(monkeypatch):
    _on()
    imp_mod.AsyncSession = _FakeAsyncSession
    imp_mod.CURL_CFFI_AVAILABLE = True
    try:
        async def boom(method, url, **kw):
            raise RuntimeError("network down")
        orig = _FakeAsyncSession.request
        _FakeAsyncSession.request = boom
        try:
            assert asyncio.run(imp_mod.impersonate_get("http://t/x")) is None
        finally:
            _FakeAsyncSession.request = orig
    finally:
        _off()


# ---------- scanner.safe_request 接线 ----------

@pytest.mark.asyncio
async def test_safe_request_prefers_impersonate(monkeypatch):
    """伪装可用时 GET 优先走伪装通道。"""
    from vulnclaw.core import scanner as sc_mod

    calls = {}

    async def fake_imp_get(url, session=None, headers=None, timeout=None, no_retry=False, **kw):
        calls["imp"] = url
        return (200, "imp-body", {"X": "1"})

    async def fake_aio_get(url, session=None, **kw):
        calls["aio"] = url
        return (200, "aio-body", {"X": "0"})

    monkeypatch.setattr(sc_mod, "_impersonate_available", lambda: True)
    monkeypatch.setattr(sc_mod, "_impersonate_request_api", lambda: (fake_imp_get, None))
    monkeypatch.setattr(sc_mod, "_http2_available", lambda: False)
    monkeypatch.setattr(sc_mod, "async_get", fake_aio_get)
    monkeypatch.setattr(sc_mod, "cache", {})
    monkeypatch.setattr(sc_mod, "_build_cache_key", lambda url, method, **kw: "k")
    resp = await sc_mod.safe_request("http://t/x", session=None)
    assert resp == (200, "imp-body", {"X": "1"})
    assert calls.get("imp") == "http://t/x"
    assert "aio" not in calls


@pytest.mark.asyncio
async def test_safe_request_falls_back_when_no_impersonate(monkeypatch):
    """伪装不可用时照旧走既有通道（零行为回归）。"""
    from vulnclaw.core import scanner as sc_mod

    calls = {}

    async def fake_aio_get(url, session=None, **kw):
        calls["aio"] = url
        return (200, "aio-body", {"X": "0"})

    monkeypatch.setattr(sc_mod, "_impersonate_available", lambda: False)
    monkeypatch.setattr(sc_mod, "_http2_available", lambda: False)
    monkeypatch.setattr(sc_mod, "async_get", fake_aio_get)
    monkeypatch.setattr(sc_mod, "cache", {})
    monkeypatch.setattr(sc_mod, "_build_cache_key", lambda url, method, **kw: "k2")
    resp = await sc_mod.safe_request("http://t/x", session=None)
    assert resp == (200, "aio-body", {"X": "0"})
    assert calls.get("aio") == "http://t/x"