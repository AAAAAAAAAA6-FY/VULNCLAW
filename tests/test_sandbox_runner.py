# -*- coding: utf-8 -*-
"""SP1 无 Docker 自动降级沙箱链：进程级隔离执行 PoC（策略/执行/越界/超时）。"""
import asyncio
import sys
import textwrap

import pytest

import vulnclaw.core.sandbox_runner as sbox

# Py3.14 + Windows：Proactor 事件循环与 asyncio 子进程不兼容，创建子进程报
# WinError 6/50（本机环境缺陷，CI 的 Py3.11/3.12 无此问题）。
# 只豁免真正起子进程的用例，纯策略判定用例在本机照常执行。
_SKIP_WIN_PY314_SUBPROCESS = pytest.mark.skipif(
    sys.platform.startswith("win") and sys.version_info >= (3, 14),
    reason="Py3.14+Windows: Proactor 与 asyncio 子进程不兼容（WinError 6/50），CI Py3.11/3.12 正常",
)


def _echo_code() -> str:
    return textwrap.dedent('''
        import sys
        print("poc-ok-123")
        sys.exit(0)
    ''')


def _sleep_code() -> str:
    return textwrap.dedent('''
        import time
        time.sleep(30)
    ''')


class TestPolicy:
    def test_confirm_prefers_docker(self, monkeypatch):
        monkeypatch.setattr(sbox, "docker_available", lambda: True)
        p = sbox.sandbox_policy_for("confirm")
        assert p["execute"] is True
        assert p["backend"] == "docker"

    def test_confirm_falls_back_process(self, monkeypatch):
        monkeypatch.setattr(sbox, "docker_available", lambda: False)
        p = sbox.sandbox_policy_for("confirm")
        assert p["backend"] == "process"

    def test_likely_process(self, monkeypatch):
        monkeypatch.setattr(sbox, "docker_available", lambda: True)
        p = sbox.sandbox_policy_for("likely")
        assert p["backend"] == "process"

    def test_suspicious_no_exec(self):
        p = sbox.sandbox_policy_for("suspicious")
        assert p["execute"] is False


class TestProcessIsolation:
    @_SKIP_WIN_PY314_SUBPROCESS
    @pytest.mark.asyncio
    async def test_run_python_echo(self):
        res = await sbox.run_python_script(_echo_code(), verdict="likely", timeout=15)
        assert res.get("success") is True
        assert res.get("backend") == "process"
        assert "poc-ok-123" in res.get("stdout", "")

    @_SKIP_WIN_PY314_SUBPROCESS
    @pytest.mark.asyncio
    async def test_timeout_kills(self):
        res = await sbox.run_python_script(_sleep_code(), verdict="likely", timeout=2)
        assert res.get("timeout") is True
        assert res.get("success") is False

    @pytest.mark.asyncio
    async def test_suspicious_not_executed(self):
        res = await sbox.run_python_script(_echo_code(), verdict="suspicious")
        assert res.get("heuristic_only") is True
        assert res.get("blocked") is True


class TestScopeGate:
    @pytest.mark.asyncio
    async def test_out_of_scope_refused(self, monkeypatch):
        from vulnclaw.config.settings import settings
        monkeypatch.setattr(settings, "allowed_scope", "example.com")
        res = await sbox.run_python_script(_echo_code(), target="https://evil.net/x",
                                           verdict="likely")
        assert res.get("blocked") is True
        assert "越界" in res.get("error", "")

    @_SKIP_WIN_PY314_SUBPROCESS
    @pytest.mark.asyncio
    async def test_in_scope_allowed(self, monkeypatch):
        from vulnclaw.config.settings import settings
        monkeypatch.setattr(settings, "allowed_scope", "example.com")
        res = await sbox.run_python_script(_echo_code(), target="https://www.example.com/x",
                                           verdict="likely", timeout=15)
        assert res.get("success") is True


class TestScopeGateFailClosed:
    """P0-4：白名单校验异常必须 fail-closed（旧实现 return True = 反向默认）。"""

    def test_scope_check_exception_refuses(self, monkeypatch):
        from vulnclaw.config.settings import settings as st
        monkeypatch.setattr(st, "allowed_scope", "example.com")
        import vulnclaw.core.sandbox_runner as s2

        def _boom(_url):
            raise RuntimeError("scope parser exploded")

        monkeypatch.setattr("vulnclaw.core.http_client.url_in_scope", _boom)
        assert s2._target_in_scope("https://anything.test/x") is False

    def test_unset_scope_is_not_a_denial(self, monkeypatch):
        from vulnclaw.config.settings import settings as st
        monkeypatch.setattr(st, "allowed_scope", "")
        import vulnclaw.core.sandbox_runner as s2
        assert s2._target_in_scope("https://anything.test/x") is True

    def test_docker_probe_failure_is_not_fatal(self, monkeypatch):
        """P0-5：探测失败=不可用且不抛异常；缓存带 TTL 可恢复。"""
        import vulnclaw.core.sandbox_runner as s2
        s2._docker_cache.update({"checked": False, "ok": None, "ts": 0.0})
        monkeypatch.setattr(s2.shutil, "which", lambda _n: "/nonexistent/docker")
        assert s2.docker_available(timeout=1) is False
        assert s2._docker_cache["checked"] is True
        assert isinstance(s2._docker_cache["ts"], float)
        s2._docker_cache["ts"] = 0.0  # TTL 过期 → 重新探测
        assert s2.docker_available(timeout=1) is False


class TestCommandVector:
    @pytest.mark.asyncio
    async def test_blocked_non_interpreter(self):
        res = await sbox.run_command_argv(["powershell", "-c", "whoami"], verdict="likely")
        assert res.get("blocked") is True

    @_SKIP_WIN_PY314_SUBPROCESS
    @pytest.mark.asyncio
    async def test_run_interpreter_ok(self):
        import sys
        res = await sbox.run_command_argv(
            [sys.executable, "-c", "print('vec-ok')"], verdict="likely", timeout=15)
        assert res.get("success") is True
        assert "vec-ok" in res.get("stdout", "")