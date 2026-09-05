# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""SP19: _exploit_rce 的 RCE 确认判定逻辑测试。

覆盖 dangerous 模式下命令注入回显判定：
- 部分命令成功 -> rce_confirmed=True，evidence 只含成功命令
- 全部失败 -> rce_confirmed=False，evidence 注明未确认
- execute_command 抛异常 -> 优雅降级返回完整 dict
- 非 dangerous 模式 POC only 分支不受影响
"""
from unittest.mock import AsyncMock, patch

import pytest

from vulnclaw.deepsec.exploit_chain import ExploitChain
from vulnclaw.deepsec.shell_channel import ShellChannel

FINDING = {
    "url": "http://lab/cmd.jsp",
    "parameter": "cmd",
    "type": "command_injection",
    "severity": "High",  # 非 Critical：跳过 Metasploit 分支，直测 ShellChannel 路径
}

RESULT_KEYS = ("evidence", "poc", "rce_confirmed", "commands_tried", "commands_confirmed")


@pytest.mark.asyncio
async def test_partial_success_confirms_rce():
    """部分命令成功（id 有回显、其余为空）：rce_confirmed=True，evidence 只含成功命令。"""
    chain = ExploitChain(target="http://lab/", session=None, dangerous=True)
    with patch.object(
        ShellChannel,
        "execute_command",
        new=AsyncMock(side_effect=["uid=0(root) gid=0(root)", "", "", ""]),
    ):
        result = await chain._exploit_rce(FINDING)
    assert result["rce_confirmed"] is True
    assert result["commands_tried"] == 4
    assert result["commands_confirmed"] == 1
    assert "uid=0(root)" in result["evidence"]
    assert "$ whoami" not in result["evidence"]
    assert "POC only" not in result["evidence"]


@pytest.mark.asyncio
async def test_all_failed_not_confirmed():
    """全部命令失败（空串 / not found）：rce_confirmed=False，evidence 注明未确认。"""
    chain = ExploitChain(target="http://lab/", session=None, dangerous=True)
    with patch.object(
        ShellChannel,
        "execute_command",
        new=AsyncMock(side_effect=["", "sh: id: not found", "command not found", ""]),
    ):
        result = await chain._exploit_rce(FINDING)
    assert result["rce_confirmed"] is False
    assert result["commands_confirmed"] == 0
    assert "命令注入未得到有效回显，RCE 未确认" in result["evidence"]


@pytest.mark.asyncio
async def test_exception_degrades_gracefully():
    """execute_command 抛异常：不向上抛错，返回结构完整 dict 且 rce_confirmed=False。"""
    chain = ExploitChain(target="http://lab/", session=None, dangerous=True)
    with patch.object(
        ShellChannel,
        "execute_command",
        new=AsyncMock(side_effect=RuntimeError("shell channel down")),
    ):
        result = await chain._exploit_rce(FINDING)
    assert result["rce_confirmed"] is False
    assert result["commands_confirmed"] == 0
    assert "RCE 未确认" in result["evidence"]
    for key in RESULT_KEYS:
        assert key in result


@pytest.mark.asyncio
async def test_non_dangerous_poc_branch_unchanged():
    """非 dangerous 模式：直接返回 POC only，不执行命令、不加确认字段。"""
    chain = ExploitChain(target="http://lab/", session=None, dangerous=False)
    with patch.object(
        ShellChannel,
        "execute_command",
        new=AsyncMock(side_effect=AssertionError("非 dangerous 模式不应执行命令")),
    ):
        result = await chain._exploit_rce(FINDING)
    assert result["evidence"] == "POC only (non-dangerous mode)"
    assert result.get("poc")
    assert "rce_confirmed" not in result
