# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""A5.3 / A6.1 / A6.2 / A3.3 原生工具与知识库冒烟测试。"""
import os
import shutil

import pytest

from vulnclaw.ai.tools import TOOL_REGISTRY
from vulnclaw.core.sandbox import run_sandboxed, _is_allowed
from vulnclaw.core.knowledge import load_vuln_knowledge, format_knowledge_for_prompt


def test_native_tools_registered():
    for name in ("browser_explore", "auto_login", "shell"):
        assert name in TOOL_REGISTRY, f"{name} 未注册进 TOOL_REGISTRY"
        assert TOOL_REGISTRY[name].get_schema()["name"] == name


def test_sandbox_allowlist_logic():
    # 白名单命令 + 安全参数 -> 通过
    assert _is_allowed("echo", ["hello"]) is True
    assert _is_allowed("curl", ["-sS", "http://example.com"]) is True
    # 危险命令 / 组合 / 重定向 -> 拒绝
    assert _is_allowed("rm", ["-rf", "/"]) is False
    assert _is_allowed("echo", ["a", "&&", "rm", "-rf"]) is False
    assert _is_allowed("cat", [">", "/etc/passwd"]) is False


@pytest.mark.asyncio
async def test_sandbox_exec_allowed():
    # Windows 上 echo/cat 等非独立可执行，跳过端到端执行
    if os.name == "nt" and shutil.which("echo") is None:
        pytest.skip("echo 在 Windows 非独立可执行，跳过端到端执行")
    res = await run_sandboxed("echo", ["hello"])
    assert res["success"] is True
    assert "hello" in res["stdout"]


@pytest.mark.asyncio
async def test_sandbox_exec_blocked():
    res = await run_sandboxed("rm", ["-rf", "/"])
    assert res["success"] is False
    assert res.get("blocked") is True


def test_knowledge_load():
    kb = load_vuln_knowledge()
    assert isinstance(kb, dict)
    assert "Spring" in kb


def test_knowledge_prompt_format():
    out = format_knowledge_for_prompt(["Spring Boot", "Tomcat"])
    assert "Spring" in out
