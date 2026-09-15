# -*- coding: utf-8 -*-
"""E5.1 scope 硬约束单测：域名/CIDR/IP 白名单矩阵 + event_hooks 拦截链路。"""
import asyncio
from types import SimpleNamespace

import pytest

from vulnclaw.core import http_client
from vulnclaw.core import utils as core_utils
from vulnclaw.core.http_client import (
    ScopeGuardError,
    url_in_scope,
    _scope_guard,
)

DOMAIN = ["example.com"]
CIDR = ["10.0.0.0/8"]
MIXED = ["example.com", "10.0.0.0/8", "192.168.1.5"]


class TestUrlInScope:
    def test_empty_scope_allows_all(self):
        assert url_in_scope("http://evil.com/x", []) is True

    def test_exact_domain(self):
        assert url_in_scope("http://example.com/x", DOMAIN) is True
        assert url_in_scope("https://www.example.com/x", DOMAIN) is True

    def test_subdomain(self):
        assert url_in_scope("https://a.b.example.com/x", DOMAIN) is True

    def test_suffix_spoof_rejected(self):
        assert url_in_scope("https://evil-example.com/x", DOMAIN) is False
        assert url_in_scope("https://notexample.com/x", DOMAIN) is False

    def test_wildcard_entry(self):
        assert url_in_scope("https://deep.app.internal.example.com/x", ["*.example.com"]) is True
        assert url_in_scope("https://evil.com/x", ["*.example.com"]) is False

    def test_cidr_and_ip(self):
        assert url_in_scope("http://10.1.2.3/x", CIDR) is True
        assert url_in_scope("http://11.1.2.3/x", CIDR) is False
        assert url_in_scope("http://192.168.1.5/x", ["192.168.1.5"]) is True
        assert url_in_scope("http://192.168.1.6/x", ["192.168.1.5"]) is False

    def test_mixed_scope(self):
        assert url_in_scope("https://api.example.com/x", MIXED) is True
        assert url_in_scope("http://10.0.0.9/x", MIXED) is True
        assert url_in_scope("http://evil.net/x", MIXED) is False


class TestScopeGuardHook:
    @staticmethod
    def _req(url):
        return SimpleNamespace(url=url)

    def test_guard_blocks_out_of_scope(self, monkeypatch):
        monkeypatch.setattr(http_client.settings, "allowed_scope", "example.com")
        with pytest.raises(ScopeGuardError):
            asyncio.run(_scope_guard(self._req("https://evil.net/x")))

    def test_guard_passes_in_scope(self, monkeypatch):
        monkeypatch.setattr(http_client.settings, "allowed_scope", "example.com")
        asyncio.run(_scope_guard(self._req("https://sub.example.com/x")))

    def test_guard_disabled_when_empty(self, monkeypatch):
        monkeypatch.setattr(http_client.settings, "allowed_scope", "")
        asyncio.run(_scope_guard(self._req("https://anything.example/x")))


class TestDefaultPathWiring:
    """E5.1 必须覆盖默认 aiohttp 出口（core.utils.async_get），而非仅 HTTP/2 路径。"""

    def test_default_path_blocks_out_of_scope(self, monkeypatch):
        monkeypatch.setattr(core_utils.settings, "allowed_scope", "example.com")
        with pytest.raises(ScopeGuardError):
            asyncio.run(core_utils.async_get("https://evil.net/x"))


class _RecordingCM:
    """假 async context manager：只记录 kwargs，不发真请求。"""

    async def __aenter__(self):
        raise RuntimeError("stop: 只验证 kwargs")

    async def __aexit__(self, *exc):
        return False


class _RecordingSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append(kwargs)
        return _RecordingCM()


class TestProxySemantics:
    """代理解析语义：**显式 proxy=None 必须真的直连**。

    踩过的坑（2026-09-12）：旧写法 `kwargs.pop('proxy', None) or settings.proxy or 池`
    会让 `async_get(url, proxy=None)` 依旧走配置代理——于是 phases_recon 里那句
    "直连重试"实际还在用同一个坏代理重试（等于没兜底），真实目标上表现为**静默零结果**。
    """

    def _call(self, monkeypatch, url="http://example.com/", **kw):
        monkeypatch.setattr(core_utils.settings, "allowed_scope", "")
        monkeypatch.setattr(core_utils.settings, "proxy", "http://127.0.0.1:8080")
        monkeypatch.setattr(core_utils, "_pool_active_proxy", lambda: None)
        session = _RecordingSession()
        asyncio.run(core_utils._http_request(
            "GET", url, session=session, no_retry=True, **kw))
        return session.calls[0]

    def test_explicit_none_means_direct(self, monkeypatch):
        assert "proxy" not in self._call(monkeypatch, proxy=None)

    def test_explicit_empty_means_direct(self, monkeypatch):
        assert "proxy" not in self._call(monkeypatch, proxy="")

    def test_omitted_uses_configured_proxy(self, monkeypatch):
        assert self._call(monkeypatch)["proxy"] == "http://127.0.0.1:8080"

    def test_localhost_bypasses_proxy(self, monkeypatch):
        assert "proxy" not in self._call(monkeypatch, url="http://localhost:9/")