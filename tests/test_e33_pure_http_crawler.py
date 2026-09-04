# -*- coding: utf-8 -*-
"""E3.3 纯 HTTP 兜底爬虫专项测试：_extract_links_from_html / _normalize_url / _fallback_crawl。

运行: pytest tests/test_e33_pure_http_crawler.py -v
"""
import sys
import types
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from vulnclaw.modules.recon import (  # noqa: E402
    _extract_links_from_html,
    _normalize_url,
)


# ---------- fake aiohttp（纯内存，零网络） ----------
# 注意：aiohttp 的 session.get() 返回 _RequestContextManager（async context manager），
# 代码里 `async with sess.get(...) as resp` 不会 await 协程，所以 get 必须是同步方法。
class FakeResp:
    def __init__(self, status, html=""):
        self._status = status
        self._html = html

    @property
    def status(self):
        return self._status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self):
        return self._html


class FakeSession:
    """pages: {url: (status, html)}"""

    def __init__(self, pages):
        self._pages = pages
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def get(self, url, timeout=None, ssl=False):
        self.calls.append(url)
        status, html = self._pages.get(url, (404, ""))
        return FakeResp(status, html)


def _install_fake_aiohttp(monkeypatch, pages):
    fake = types.ModuleType("aiohttp")
    fake.ClientSession = lambda: FakeSession(pages)
    monkeypatch.setitem(sys.modules, "aiohttp", fake)


# ---------- _extract_links_from_html ----------
class TestExtractLinks:
    def test_href_src_action_datasrc_and_srcset(self):
        html = (
            '<a href="/a">A</a>'
            '<img src="/img.png" srcset="/s1.png 1x, /s2.png 2x">'
            '<script src="/app.js"></script>'
            '<form action="/submit"></form>'
            '<div data-src="/data"></div>'
        )
        links = _extract_links_from_html(html)
        assert "/a" in links
        assert "/img.png" in links
        assert "/app.js" in links
        assert "/submit" in links
        assert "/data" in links
        assert "/s1.png" in links
        assert "/s2.png" in links

    def test_empty_html(self):
        assert _extract_links_from_html("") == []
        assert _extract_links_from_html(None) == []


# ---------- _normalize_url ----------
class TestNormalizeUrl:
    def test_relative_path_resolved(self):
        assert _normalize_url("https://t.com/a/b", "/c") == "https://t.com/c"
        assert _normalize_url("https://t.com/a/b", "c") == "https://t.com/a/c"
        assert _normalize_url("https://t.com/a/b/", "../c") == "https://t.com/a/c"

    def test_fragment_stripped_query_kept(self):
        assert _normalize_url("https://t.com/p", "/p?x=1#sec") == "https://t.com/p?x=1"
        assert _normalize_url("https://t.com/p", "/p#sec") == "https://t.com/p"

    def test_protocol_relative(self):
        assert _normalize_url("https://t.com/p", "//cdn.t.com/x.js") == "https://cdn.t.com/x.js"

    def test_pseudo_protocol_filtered(self):
        for bad in ("javascript:alert(1)", "data:text/html,x", "mailto:a@b.c", "#frag", ""):
            assert _normalize_url("https://t.com/p", bad) == ""

    def test_absolute_same(self):
        assert _normalize_url("https://t.com/p", "https://t.com/q") == "https://t.com/q"


# ---------- _fallback_crawl (BFS) ----------
def _collector():
    from vulnclaw.modules.recon import EndpointCollector
    return EndpointCollector(session=None, burp_client=None)


class TestFallbackCrawl:
    @pytest.mark.asyncio
    async def test_no_links_returns_empty(self, monkeypatch):
        pages = {"https://t.com": (200, "<html><body>hello</body></html>")}
        _install_fake_aiohttp(monkeypatch, pages)
        out = await _collector()._fallback_crawl("t.com")
        assert out == set()

    @pytest.mark.asyncio
    async def test_follows_same_origin_one_level(self, monkeypatch):
        pages = {
            "https://t.com": (200, '<a href="/b">B</a><a href="/img.png">x</a>'),
            "https://t.com/b": (200, '<a href="/c">C</a>'),
            "https://t.com/c": (200, "<p>leaf</p>"),
        }
        _install_fake_aiohttp(monkeypatch, pages)
        out = await _collector()._fallback_crawl("t.com")
        assert "https://t.com/b" in out
        assert "https://t.com/c" in out
        assert "https://t.com/img.png" not in out  # 静态资源被过滤

    @pytest.mark.asyncio
    async def test_cross_domain_filtered(self, monkeypatch):
        pages = {
            "https://t.com": (200, '<a href="https://evil.com/x">x</a><a href="//cdn.t.com/y.js">y</a>'),
        }
        _install_fake_aiohttp(monkeypatch, pages)
        out = await _collector()._fallback_crawl("t.com")
        assert "https://evil.com/x" not in out
        assert "https://cdn.t.com/y.js" not in out  # 不同 host 一并过滤

    @pytest.mark.asyncio
    async def test_non_200_skipped(self, monkeypatch):
        pages = {
            "https://t.com": (200, '<a href="/b">B</a>'),
            "https://t.com/b": (500, "<html>err</html>"),
        }
        _install_fake_aiohttp(monkeypatch, pages)
        out = await _collector()._fallback_crawl("t.com")
        assert out == {"https://t.com/b"}  # 提取到但子页 500，无新端点；b 本身是有效端点

    @pytest.mark.asyncio
    async def test_max_urls_limit(self, monkeypatch):
        pages = {
            "https://t.com": (200, "".join(f'<a href="/p{i}">x</a>' for i in range(50))),
        }
        _install_fake_aiohttp(monkeypatch, pages)
        out = await _collector()._fallback_crawl("t.com", max_depth=1, max_urls=10)
        assert len(out) <= 10

    @pytest.mark.asyncio
    async def test_http_scheme_domain(self, monkeypatch):
        pages = {"http://t.com": (200, '<a href="/a">A</a>')}
        _install_fake_aiohttp(monkeypatch, pages)
        out = await _collector()._fallback_crawl("http://t.com")
        assert "http://t.com/a" in out
