# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""E3.2: --diff 增量扫描 CLI 接线 单元测试。

覆盖：--diff 开关启用 settings.incremental_scan / 关闭不扰动 /
      设置失败降级全量 / cli.py scan 子命令把 --diff 转发到底层 scan_main argv。
"""
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _reset_incremental_flag():
    """每个用例前把增量开关复位为默认（False），防测试间串扰。"""
    from vulnclaw.config import settings

    settings.incremental_scan = False
    yield
    settings.incremental_scan = False


class TestApplyDiffFlag:
    """scan_main._apply_diff_flag：--diff -> 增量开关接线。"""

    def test_diff_off_keeps_incremental_off(self):
        from vulnclaw.config import settings
        from vulnclaw.scan_main import _apply_diff_flag

        assert _apply_diff_flag(SimpleNamespace(diff=False, target="http://t")) is False
        assert settings.incremental_scan is False

    def test_diff_on_enables_incremental(self, capsys):
        from vulnclaw.config import settings
        from vulnclaw.scan_main import _apply_diff_flag

        assert _apply_diff_flag(SimpleNamespace(diff=True, target="http://t")) is True
        assert settings.incremental_scan is True
        assert "[E3.2]" in capsys.readouterr().out

    def test_diff_flag_failure_degrades_full(self, monkeypatch):
        """settings 赋值抛异常 -> 返回 False（按全量兜底），不中断流程。"""
        from vulnclaw.scan_main import _apply_diff_flag

        broken = MagicMock()

        def _raise_setter(*a, **k):
            raise RuntimeError("env locked")

        type(broken).incremental_scan = property(_raise_setter, _raise_setter)
        monkeypatch.setattr("vulnclaw.scan_main.settings", broken)

        assert _apply_diff_flag(SimpleNamespace(diff=True, target="http://t")) is False


class TestCliForward:
    """cli.py `vulnclaw scan --diff` -> 底层 scan_main argv 转发。"""

    def test_scan_diff_forwarded(self, monkeypatch):
        import vulnclaw.cli as cli
        import vulnclaw.scan_main as sm

        captured = {}

        def _fake_main():
            captured["argv"] = list(sys.argv)

        monkeypatch.setattr(sm, "main", _fake_main)
        original_argv = list(sys.argv)
        try:
            cli.main(["scan", "-t", "http://t", "--diff"])
        finally:
            sys.argv = original_argv

        assert "--diff" in captured["argv"]
        assert captured["argv"][1] == "-t"

    def test_compat_style_diff_forwarded(self, monkeypatch):
        """兼容路径：python scan.py -t URL --diff 直接转发（不经子命令）。"""
        import vulnclaw.cli as cli
        import vulnclaw.scan_main as sm

        captured = {}

        def _fake_main():
            captured["argv"] = list(sys.argv)

        monkeypatch.setattr(sm, "main", _fake_main)
        original_argv = list(sys.argv)
        try:
            cli.main(["-t", "http://t", "--diff"])
        finally:
            sys.argv = original_argv

        assert "--diff" in captured["argv"]
        assert "-t" in captured["argv"]


class TestScanMainArgparse:
    """scan_main.main() 的 argparse 接受 --diff（请求转发路径可达）。"""

    def test_help_mentions_diff(self):
        import argparse
        import io
        import sys

        from vulnclaw import scan_main

        captured = io.StringIO()
        old_stdout, old_stderr, old_argv = sys.stdout, sys.stderr, sys.argv
        sys.argv = ["scan.py", "--help"]
        sys.stdout = captured
        sys.stderr = captured
        try:
            with pytest.raises(SystemExit) as exc:
                scan_main.main()
            assert exc.value.code == 0
        finally:
            sys.stdout, sys.stderr, sys.argv = old_stdout, old_stderr, old_argv
        assert "--diff" in captured.getvalue()