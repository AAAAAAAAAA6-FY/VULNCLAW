# -*- coding: utf-8 -*-
"""E5.1 scope 硬约束单测：域名/CIDR/IP 白名单矩阵 + event_hooks 拦截链路。"""
import asyncio
from types import SimpleNamespace

import pytest

from vulnclaw.core import http_client
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