# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

from vulnclaw.core.tool_registry import run_tool, load_tool_config
import asyncio
import json

from vulnclaw.core.logger import logger
from typing import Dict, List, Optional

# ============================================================
# Interactsh - 带外域名获取
# ============================================================
async def get_interactsh_domain_async() -> Optional[str]:
    """
    获取一个 Interactsh 域名（用于带外测试）。
    修复（步骤0）：
      - 删除"随机 oast.fun 假域名"回退：假域名未向 interactsh 服务端注册，
        永远收不到回调，且会以 truthy 值堵死 OOBVerifier 的降级链
        （dnslog.cn → 本地DNS），导致 OOB 漏洞全部漏报。
      - 获取失败时返回 None，由调用方决定降级路径。
    """
    if not load_tool_config("interactsh-client"):
        logger.warning(
            "📡 [Interactsh] get_interactsh_domain_async: 未找到 interactsh-client"
            " (不在 PATH 中，且 thirdparty/interactsh-client(.exe) 也不存在)。"
            " 返回 None，由调用方降级（dnslog.cn / 本地DNS）"
        )
        return None
    try:
        logger.info("📡 [Interactsh] 启动客户端获取域名")
        result = await run_tool(
            "interactsh-client",
            args=["-silent", "-o", "stdout", "-q"],
            timeout=8,
        )
        if result.get("success"):
            domain = result.get("stdout", "").strip()
            if domain and '.' in domain and ' ' not in domain:
                logger.info(f"📡 [Interactsh] 获取到域名: {domain}")
                return domain
            logger.warning(
                f"📡 [Interactsh] exit=0 但输出不是合法域名: "
                f"stdout={result.get('stdout', '')[:200]!r}"
            )
        else:
            logger.warning(
                f"📡 [Interactsh] 异常退出 exit={result.get('returncode', -1)}; "
                f"stderr={result.get('stderr', result.get('error', ''))[:300]}"
            )
    except Exception as e:
        logger.warning(f"📡 [Interactsh] 获取失败: {e}")
    return None


# ============================================================
# 其他辅助工具
# ============================================================
async def get_interactsh_poll(domain: str, timeout: int = 15) -> List[Dict]:
    """
    轮询 Interactsh 回调（如果有客户端）。
    修复：用 get_tool_path 解析二进制；增加详细 warning 日志；超时 10→15s。
    """
    if not load_tool_config("interactsh-client"):
        logger.debug(f"[Interactsh poll] 二进制不存在，跳过轮询 domain={domain}")
        return []
    if not domain or '.' not in domain:
        return []
    try:
        result = await run_tool(
            "interactsh-client",
            args=["-poll", "-domain", domain, "-json"],
            timeout=15,
        )
        code = result.get("returncode", -1)
        out = result.get("stdout", "")
        err = result.get("stderr", result.get("error", ""))
        cmd = result.get("cmd", "interactsh-client -poll -domain " + domain + " -json")
        if code == 0 and out:
            interactions = []
            for idx, line in enumerate(out.splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    interactions.append(data)
                except json.JSONDecodeError as e:
                    logger.warning(f"📡 [Interactsh poll] JSON 行解析失败 L{idx}: {e} line[:200]={line[:200]}")
            if interactions:
                logger.info(f"📡 [Interactsh poll] domain={domain} 捕获 {len(interactions)} 条交互")
            return interactions
        if code != 0:
            logger.warning(
                f"📡 [Interactsh poll] exit={code}; stderr[:300]={(err or '')[:300]}"
            )
        return []
    except asyncio.TimeoutError:
        logger.warning(f"📡 [Interactsh poll] 超时 (> {timeout}s)；cmd={' '.join(cmd)}")
        return []
    except Exception as e:
        logger.warning(f"📡 [Interactsh poll] 异常: {e}；cmd={' '.join(cmd)}")
        return []


__all__ = [
    'run_arjun',
    'run_nuclei_async',
    'run_ffuf_async',
    'get_interactsh_domain_async',
    'get_interactsh_poll',
]
