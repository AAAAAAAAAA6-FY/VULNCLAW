# -*- coding: utf-8 -*-
"""会话与 Cookie 管理测试：域名校验 / CookieManager.add_cookies / Burp 导入 / 后台刷新。

运行: pytest tests/test_session_manager.py -v
"""
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from vulnclaw.core.session_manager import (  # noqa: E402
    _is_valid_cookie_domain,
    CookieManager,
    SessionManager,
)


class TestIsValidCookieDomain:
    """Cookie 域名有效性校验。"""

    def test_empty(self):
        assert _is_valid_cookie_domain("") is False

    def test_pure_tld(self):
        # 纯 TLD 无点
        assert _is_valid_cookie_domain("com") is False
        assert _is_valid_cookie_domain("org") is False

    def test_no_dot_host(self):
        assert _is_valid_cookie_domain("localhost") is False

    def test_simple_domain(self):
        assert _is_valid_cookie_domain("example.com") is True

    def test_leading_dot(self):
        assert _is_valid_cookie_domain(".example.com") is True

    def test_multi_level_domain(self):
        assert _is_valid_cookie_domain("example.co.uk") is True
        assert _is_valid_cookie_domain("sub.example.com") is True

    def test_ip_like(self):
        assert _is_valid_cookie_domain("192.168.1.1") is True


class TestCookieManager:
    """CookieManager.add_cookies 行为。"""

    @pytest.mark.asyncio
    async def test_add_valid_domain(self):
        cm = CookieManager()
        await cm.add_cookies("example.com", {"session": "abc"})
        assert cm.cookie_map["example.com"] == {"session": "abc"}
        assert cm.cookie_metadata["example.com"]["count"] == 1

    @pytest.mark.asyncio
    async def test_reject_invalid_domain(self):
        cm = CookieManager()
        await cm.add_cookies("com", {"session": "abc"})
        assert cm.cookie_map == {}

    @pytest.mark.asyncio
    async def test_empty_cookies_ignored(self):
        cm = CookieManager()
        await cm.add_cookies("example.com", {})
        assert cm.cookie_map == {}


class TestLoadFromBurpPlugin:
    """SessionManager.load_from_burp_plugin。"""

    def test_file_missing(self, monkeypatch, tmp_path):
        sm = SessionManager()
        missing = tmp_path / "missing.json"
        monkeypatch.setattr("os.path.expanduser", lambda p: str(missing))
        assert sm.load_from_burp_plugin() == 0

    def test_wrong_format(self, tmp_path):
        f = tmp_path / "cookies.json"
        f.write_text('["not", "a", "dict"]', encoding="utf-8")
        sm = SessionManager()
        assert sm.load_from_burp_plugin(str(f)) == 0

    def test_corrupted_json(self, tmp_path):
        f = tmp_path / "cookies.json"
        f.write_text("{not valid json", encoding="utf-8")
        sm = SessionManager()
        assert sm.load_from_burp_plugin(str(f)) == 0

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        data = {
            "example.com": {"session": "abc123", "csrf": "tok"},
            "sub.example.com": {"session": "xyz", "authorization": "Bearer eyJ0"},
        }
        f = tmp_path / "burp.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        sm = SessionManager()
        count = sm.load_from_burp_plugin(str(f))
        assert count == 2
        # authorization 归类为 token，不进入 Cookie
        assert sm.cookie_manager.cookie_map["example.com"] == {"session": "abc123", "csrf": "tok"}
        assert sm.cookie_manager.cookie_map["sub.example.com"] == {"session": "xyz"}
        assert sm.tokens.get("burp_sub_example_com") == {"authorization": "Bearer eyJ0"}
        # 仅含 token 的域名才建立会话；纯 Cookie 域名只写入 cookie_map
        assert "burp_example_com" not in sm.sessions
        assert "burp_sub_example_com" in sm.sessions
        await sm.close_all()

    @pytest.mark.asyncio
    async def test_target_domain_filter(self, tmp_path):
        data = {
            "https://example.com": {"session": "a"},
            "other.org": {"session": "b"},
            "sub.example.com": {"session": "c"},
        }
        f = tmp_path / "burp.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        sm = SessionManager()
        count = sm.load_from_burp_plugin(str(f), target_domain="example.com")
        assert count == 2  # example.com + sub.example.com
        assert "other.org" not in sm.cookie_manager.cookie_map
        assert "example.com" in sm.cookie_manager.cookie_map
        assert "sub.example.com" in sm.cookie_manager.cookie_map
        await sm.close_all()

    @pytest.mark.asyncio
    async def test_skip_invalid_domain(self, tmp_path):
        data = {"com": {"session": "a"}, "example.com": {"session": "b"}}
        f = tmp_path / "burp.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        sm = SessionManager()
        count = sm.load_from_burp_plugin(str(f))
        assert count == 1  # com 被跳过
        assert "com" not in sm.cookie_manager.cookie_map
        await sm.close_all()


class TestBackgroundReload:
    """后台 Cookie 文件重载。"""

    @pytest.mark.asyncio
    async def test_file_missing(self, monkeypatch, tmp_path):
        sm = SessionManager()
        missing = tmp_path / "nope.json"
        monkeypatch.setattr("os.path.expanduser", lambda p: str(missing))
        assert await sm._reload_cookies_from_file() is False

    @pytest.mark.asyncio
    async def test_disabled(self, monkeypatch, tmp_path):
        f = tmp_path / "c.json"
        f.write_text("{}", encoding="utf-8")
        monkeypatch.setattr("os.path.expanduser", lambda p: str(f))
        sm = SessionManager()
        sm._enabled_reload = False
        assert await sm._reload_cookies_from_file() is False

    @pytest.mark.asyncio
    async def test_same_mtime_skipped(self, monkeypatch, tmp_path):
        f = tmp_path / "c.json"
        f.write_text(json.dumps({"example.com": {"s": "1"}}), encoding="utf-8")
        monkeypatch.setattr("os.path.expanduser", lambda p: str(f))
        sm = SessionManager()
        assert await sm._reload_cookies_from_file(force=True) is True
        # mtime 未变化 -> 跳过
        assert await sm._reload_cookies_from_file() is False

    @pytest.mark.asyncio
    async def test_reload_updated(self, monkeypatch, tmp_path):
        f = tmp_path / "c.json"
        f.write_text(json.dumps({"example.com": {"s": "1"}}), encoding="utf-8")
        monkeypatch.setattr("os.path.expanduser", lambda p: str(f))
        sm = SessionManager()
        assert await sm._reload_cookies_from_file() is True
        assert sm.cookie_manager.cookie_map["example.com"] == {"s": "1"}

    @pytest.mark.asyncio
    async def test_corrupted_uses_backup(self, monkeypatch, tmp_path):
        f = tmp_path / "c.json"
        f.write_text("{corrupted", encoding="utf-8")
        (tmp_path / "c.json.bak").write_text(
            json.dumps({"example.com": {"s": "1"}}), encoding="utf-8")
        monkeypatch.setattr("os.path.expanduser", lambda p: str(f))
        sm = SessionManager()
        assert await sm._reload_cookies_from_file(force=True) is True
        assert sm.cookie_manager.cookie_map["example.com"] == {"s": "1"}

    @pytest.mark.asyncio
    async def test_corrupted_no_backup(self, monkeypatch, tmp_path):
        f = tmp_path / "c.json"
        f.write_text("{corrupted", encoding="utf-8")
        monkeypatch.setattr("os.path.expanduser", lambda p: str(f))
        sm = SessionManager()
        assert await sm._reload_cookies_from_file(force=True) is False

    def test_start_background_reload_no_loop(self):
        """无运行中事件循环时启动后台刷新 -> 不抛异常，跳过。"""
        sm = SessionManager()
        sm.start_background_reload()
        assert sm._reload_task is None
