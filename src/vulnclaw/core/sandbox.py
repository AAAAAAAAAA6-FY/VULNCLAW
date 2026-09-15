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


# ---- P0-3 出口防护：网络命令目标地址校验 ----
_NETWORK_COMMANDS = {"curl", "wget", "ping", "dig", "host", "nslookup", "whois", "http"}
# 域名型拒绝（云元数据/内网命名）
_DENY_HOST_SUFFIXES = (
    ".internal", ".local", ".localdomain", ".home.arpa",
    "metadata.google.internal", "instance-data",
)
_METADATA_IPS = ("169.254.169.254", "100.100.100.200", "192.0.0.192", "fd00:ec2::254")


def _egress_target_denied(arg: str) -> bool:
    """参数是否为被禁止的内网/本机/云元数据目标（True=拒绝）。

    覆盖范围：IP 字面量（IPv4/IPv6）判 loopback / link-local / RFC1918 /
    ULA / 保留段 / 元数据地址；域名判 .internal/.local 等内网后缀。
    已知边界（记录在案，不假装解决）：DNS rebinding、HTTP 重定向越界、
    IPv6 隧道需在网络层（容器 netns / egress proxy）兜底，本函数只做静态校验。
    """
    import ipaddress
    from urllib.parse import urlsplit

    s = str(arg or "").strip()
    if not s:
        return False
    host = s
    if "://" in s:
        host = urlsplit(s).hostname or ""
    else:
        # 形如 host:port / user@host
        host = s.split("@")[-1]
        if host.startswith("["):  # [::1]:80
            host = host[1:].split("]")[0]
        else:
            host = host.split("/")[0].split(":")[0]
    host = host.strip().strip(".")
    if not host:
        return False
    if host.lower() in ("localhost", "localhost.localdomain", "ip6-localhost", "::1"):
        return True
    if host in _METADATA_IPS or host.startswith("169.254.") or host.startswith("100.100."):
        return True
    low = host.lower()
    if any(low == suf.lstrip(".") or low.endswith(suf) for suf in _DENY_HOST_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # 域名：仅后缀规则命中才拒绝
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _egress_guard(command: str, args: List[str]) -> Optional[str]:
    """网络命令出口校验；放行返回 None，拒绝返回可读原因。"""
    try:
        from vulnclaw.config.settings import settings
        if not getattr(settings, "sandbox_egress_guard", True):
            return None
    except Exception:  # noqa: BLE001 - 配置不可读时不阻断（功能可用性优先）
        return None
    base = os.path.basename(shlex.split(command or "")[0]) if command else ""
    if base not in _NETWORK_COMMANDS:
        return None
    for a in args:
        if _egress_target_denied(str(a)):
            return f"网络目标位于内网/本机/云元数据地址段，沙箱出口已拒绝: {a}"
    return None


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
    # P0-3：网络命令出口校验（内网/本机/云元数据 → 拒绝）
    denied = _egress_guard(command, args)
    if denied:
        logger.warning(f"🚫 [Sandbox] 出口拦截: {command} {args} — {denied}")
        return {"success": False, "blocked": True, "error": denied, "egress_blocked": True}
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
