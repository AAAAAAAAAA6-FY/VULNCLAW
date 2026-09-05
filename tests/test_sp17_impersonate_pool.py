# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP17.3（A 线）TLS 指纹链 单元测试。

覆盖（全部离线，不触网）：
- a) settings 新字段默认值（rotate/http2 关，pool 出厂 [[chrome, firefox, safari]]），零行为回归；
- b) 轮换池 round-robin 顺序 与"命中保持"/失败切换（monkeypatch 注入假会话）；
- c) 缺 curl_cffi 时池可用（len==0 / next() 返回 (None, None)/降级），不抛错；
- d) http2_fingerprint 输出结构（含 alpn_protocols / browser）；缺库时返回空 dict。
"""
import asyncio
from typing import ClassVar

import pytest

from vulnclaw.core import impersonate as imp_mod
from vulnclaw.core.settings import settings

# ---------- a) settings 默认值 ----------

def test_settings_defaults_zero_regression():
    # SP24 §22.2 后 http_impersonate_rotate 已默认打开（TLS 指纹轮换，curl_cffi 缺失自动降级）
    assert settings.http_impersonate_rotate is True
    assert list(settings.http_impersonate_pool or []) == ["chrome", "firefox", "safari"]


# ---------- 轮换池（用 monkeypatch 注入假会话） ----------

class _RecSession:
    """假会话：仅记录自身归属的 browser，足够支撑 next()。"""
    def __init__(self, name: str):
        self.name = name


def test_pool_round_robin_order():
    pool = imp_mod.ImpersonatePool(
        browsers=["chrome", "firefox", "safari"],
        session_factory=lambda b: _RecSession(b),
    )
    seen = []
    for _ in range(6):
        b, sess = pool.next()
        seen.append(b)
        assert sess.name == b
    # round-robin 循环两轮
    assert seen == ["chrome", "firefox", "safari", "chrome", "firefox", "safari"]
    assert len(pool) == 3


def test_pool_hit_streak_keeps_current():
    pool = imp_mod.ImpersonatePool(
        browsers=["chrome", "firefox"],
        session_factory=lambda b: _RecSession(b),
        hit_streak_keep=2,
    )
    b0, _ = pool.next()
    pool.report(miss=False)          # chrome 命中 -> 连续1
    b1, _ = pool.next()
    pool.report(miss=False)          # firefox 命中 -> 连续2
    # 连续命中达到 hit_streak_keep=2 -> 命中保持，沿用当前（firefox）
    b2, _ = pool.next()
    b3, _ = pool.next()
    assert (b0, b1) == ("chrome", "firefox")
    assert b2 == "firefox"
    assert b3 == "firefox"
    assert pool.hits == 2
    assert pool.misses == 0


def test_pool_miss_switches_fingerprint():
    pool = imp_mod.ImpersonatePool(
        browsers=["chrome", "firefox"],
        session_factory=lambda b: _RecSession(b),
        hit_streak_keep=2,
    )
    pool.next()
    pool.report(miss=False)          # chrome 命中 -> 连续1
    pool.next()
    pool.report(miss=True)           # firefox 失败 -> 连续重置
    b, _ = pool.next()               # 失败切换 -> 轮回 chrome
    assert b == "chrome"
    assert pool.misses == 1
    assert pool.hits == 1


# ---------- c) 缺 curl_cffi 时池可用（len 0 / 降级不抛错） ----------

def test_pool_empty_when_curl_unavailable(monkeypatch):
    monkeypatch.setattr(imp_mod, "CURL_CFFI_AVAILABLE", False)
    monkeypatch.setattr(imp_mod, "AsyncSession", None)
    pool = imp_mod.get_impersonate_pool(force_new=True)
    assert len(pool) == 0
    assert pool.next() == (None, None)     # 降级：返回空，不抛错
    assert asyncio.run(imp_mod.impersonate_get("http://t/x")) is None


# ---------- d) http2_fingerprint 输出结构 ----------

def test_http2_fingerprint_structure():
    if not imp_mod.CURL_CFFI_AVAILABLE:
        pytest.skip("curl_cffi 未安装，跳过有库结构用例")
    fp = imp_mod.http2_fingerprint("chrome")
    assert isinstance(fp, dict)
    assert fp["browser"] == "chrome"
    assert fp["impersonate"] == "chrome"
    assert fp["http2"] is True
    assert "h2" in list(fp["alpn_protocols"] or [])
    assert fp["settings_note"]


def test_http2_fingerprint_empty_when_unavailable(monkeypatch):
    monkeypatch.setattr(imp_mod, "CURL_CFFI_AVAILABLE", False)
    monkeypatch.setattr(imp_mod, "AsyncSession", None)
    assert imp_mod.http2_fingerprint("chrome") == {}


# ---------- 附加：rotate 打开时请求真正走池 ----------

class _FakeResp:
    status_code = 200
    text = "ok-body"
    headers: ClassVar[dict] = {"Server": "nginx"}


class _RotFakeAsyncSession:
    def __init__(self, impersonate: str = ""):
        self._imp = impersonate

    async def request(self, method, url, **kwargs):
        return _FakeResp()


def test_rotate_on_request_uses_pool(monkeypatch):
    monkeypatch.setattr(imp_mod, "CURL_CFFI_AVAILABLE", True)
    monkeypatch.setattr(imp_mod, "AsyncSession", _RotFakeAsyncSession)
    settings.http_impersonate_rotate = True
    settings.http_impersonate_pool = ["chrome", "firefox", "safari"]
    try:
        pool = imp_mod.get_impersonate_pool(force_new=True)  # 用 fake 会话重建
        body = asyncio.run(imp_mod.impersonate_get("http://t/x"))
        assert body == (200, "ok-body", {"Server": "nginx"})
        assert len(pool) == 3
        assert pool.hits == 1
        assert pool.current in ("chrome", "firefox", "safari")
    finally:
        settings.http_impersonate_rotate = False
