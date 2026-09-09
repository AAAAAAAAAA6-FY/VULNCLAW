# -*- coding: utf-8 -*-
"""会话与 Cookie 管理测试：域名校验 / CookieManager.add_cookies / Burp 导入 / 后台刷新。

运行: pytest tests/test_session_manager.py -v
"""
import json
import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from vulnclaw.core.auth.session_manager import (  # noqa: E402
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
        monkeypatch.setattr("vulnclaw.core.auth.session_manager.resolve_burp_cookies_path", lambda: str(missing))
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
        monkeypatch.setattr("vulnclaw.core.auth.session_manager.resolve_burp_cookies_path", lambda: str(missing))
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


class TestBridgeAuthSync:
    """桥代理历史 → burp_cookies.json 增量同步（自动保鲜链路）。"""

    @pytest.mark.asyncio
    async def test_sync_extracts_auth_cookies(self, tmp_path, monkeypatch):
        from vulnclaw.core.auth.session_manager import (
            SessionManager, _bridge_proxy_history_path,
        )
        import os

        hist = tmp_path / "proxy_history.jsonl"
        hist.write_text(
            json.dumps({
                "ts": 123, "host": "www.audible.com", "status": 200,
                "request_headers": {"Cookie": "i18n-prefs=USD; at-main=AtzaTok1; _ga=analytics",
                                    "Host": "www.audible.com"},
            }) + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr("vulnclaw.core.auth.session_manager._BRIDGE_DIR_ENV", str(tmp_path))
        import vulnclaw.core.auth.session_manager as sm_mod
        monkeypatch.setattr(sm_mod, "resolve_burp_cookies_path",
                            lambda: str(tmp_path / "burp_cookies.json"))
        (tmp_path / "burp_cookies.json").write_text("{}", encoding="utf-8")

        sm = SessionManager()
        assert sm._sync_bridge_auth_cookies_to_file() is True

        data = json.loads((tmp_path / "burp_cookies.json").read_text(encoding="utf-8"))
        assert data["www.audible.com"]["at-main"] == "AtzaTok1"
        assert data["www.audible.com"]["i18n-prefs"] == "USD"
        assert "_ga" not in data["www.audible.com"]  # 分析 cookie 不入白名单
        assert data["_meta"]["source"].startswith("session_manager")

    @pytest.mark.asyncio
    async def test_sync_incremental_no_change(self, tmp_path, monkeypatch):
        from vulnclaw.core.auth.session_manager import SessionManager

        hist = tmp_path / "proxy_history.jsonl"
        hist.write_text(
            json.dumps({"host": "www.audible.com",
                        "request_headers": {"Cookie": "at-main=Same"}}) + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr("vulnclaw.core.auth.session_manager._BRIDGE_DIR_ENV", str(tmp_path))
        import vulnclaw.core.auth.session_manager as sm_mod
        cookie_file = tmp_path / "burp_cookies.json"
        cookie_file.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(sm_mod, "resolve_burp_cookies_path", lambda: str(cookie_file))

        sm = SessionManager()
        assert sm._sync_bridge_auth_cookies_to_file() is True
        mtime1 = os.path.getmtime(cookie_file)
        # 无新行 → 不再写盘
        assert sm._sync_bridge_auth_cookies_to_file() is False
        assert os.path.getmtime(cookie_file) == mtime1

    @pytest.mark.asyncio
    async def test_sync_then_reload_updates_session(self, tmp_path, monkeypatch):
        import os
        from vulnclaw.core.auth.session_manager import SessionManager

        hist = tmp_path / "proxy_history.jsonl"
        hist.write_text(
            json.dumps({"host": "audible.com",
                        "request_headers": {"Cookie": "session-token=TokX"}}) + "\n",
            encoding="utf-8",
        )
        cookie_file = tmp_path / "burp_cookies.json"
        cookie_file.write_text(json.dumps({"old.com": {"k": "v"}}), encoding="utf-8")
        monkeypatch.setattr("vulnclaw.core.auth.session_manager._BRIDGE_DIR_ENV", str(tmp_path))
        import vulnclaw.core.auth.session_manager as sm_mod
        monkeypatch.setattr(sm_mod, "resolve_burp_cookies_path", lambda: str(cookie_file))

        sm = SessionManager()
        assert sm._sync_bridge_auth_cookies_to_file() is True
        data = json.loads(cookie_file.read_text(encoding="utf-8"))
        assert data["old.com"] == {"k": "v"}          # 旧域保留
        assert data["audible.com"]["session-token"] == "TokX"  # 新增合并
