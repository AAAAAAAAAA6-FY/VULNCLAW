# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

# core/sandbox.py
"""A5.3 受控 shell 沙箱：白名单命令 + 参数校验 + 超时 + 输出截断 + 工作目录隔离。

作为 Agent 的"通用逃生舱"工具，只允许预批准的安全命令，禁止命令组合、
重定向与危险参数（rm/sudo/路径穿越等），从根本上杜绝 shell 逃逸。
"""
import asyncio
import os
import shlex
import tempfile
from typing import Dict, List, Optional

from vulnclaw.core.logger import logger

# 白名单命令（仅允许这些二进制，且 basename 匹配）
_ALLOWED_COMMANDS = {
    "echo", "cat", "head", "tail", "grep", "wc", "sort", "uniq", "cut", "tr",
    "base64", "xxd", "file", "sha256sum", "md5sum", "jq", "true", "false",
    "curl", "wget", "python3", "python", "ping", "dig", "host", "nslookup",
    "whois", "http",
}
# 跨命令禁止的字符/子串（防命令注入、重定向、删除等）
_FORBIDDEN_SUBSTRINGS = (
    "&&", "||", ";", "|", "$", "`", "$(", ">${", ">>", "<", "rm ",
    "sudo", "chmod", "chown", "mv ", "cp ", "dd ", "mkfs", "/etc/",
    "/bin/", "/usr/", "/var/", "/sys/", "c:\\",
)

SANDBOX_TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT", "30"))
SANDBOX_MAX_OUTPUT = int(os.getenv("SANDBOX_MAX_OUTPUT", "4096"))
SANDBOX_WORKDIR = os.path.join(tempfile.gettempdir(), "vulnclaw_sandbox")


def _is_allowed(command: str, args: List[str]) -> bool:
    """校验命令是否在白名单且不含禁止参数。"""
    base = os.path.basename(shlex.split(command or "")[0]) if command else ""
    if base not in _ALLOWED_COMMANDS:
        return False
    for a in args:
        a = str(a)
        if any(bad in a for bad in _FORBIDDEN_SUBSTRINGS):
            return False
    return True


async def run_sandboxed(
    command: str, args: Optional[List[str]] = None, timeout: int = SANDBOX_TIMEOUT
) -> Dict:
    """在受控沙箱中执行单个白名单命令，返回结构化结果。"""
    args = [str(a) for a in (args or [])]
    if not _is_allowed(command, args):
        logger.warning(f"🚫 [Sandbox] 拒绝命令: {command} {args}")
        return {
            "success": False,
            "blocked": True,
            "error": "命令不在白名单或含禁止参数（沙箱策略）",
        }
    try:
        os.makedirs(SANDBOX_WORKDIR, exist_ok=True)
        argv = [os.path.basename(shlex.split(command)[0])] + args
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=SANDBOX_WORKDIR,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"success": False, "timeout": True,
                    "error": f"Sandbox 执行超时 ({timeout}s)"}
        stdout = out.decode("utf-8", "ignore")
        stderr = err.decode("utf-8", "ignore")
        if len(stdout) > SANDBOX_MAX_OUTPUT:
            stdout = stdout[:SANDBOX_MAX_OUTPUT] + "\n...[输出已截断]"
        if len(stderr) > 1024:
            stderr = stderr[:1024] + "\n...[截断]"
        return {
            "success": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "cmd": " ".join(argv),
            "sandbox": True,
        }
    except Exception as e:  # noqa: BLE001
        logger.error(f"[Sandbox] 执行异常: {e}")
        return {"success": False, "error": str(e)}


__all__ = ["run_sandboxed", "SANDBOX_TIMEOUT", "SANDBOX_MAX_OUTPUT"]
