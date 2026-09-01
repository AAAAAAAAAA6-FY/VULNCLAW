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
    """获取一个 Interactsh 域名（用于带外测试）。

    A1.1 收敛：统一委托 core/oob_channel.OOBChannel（provider=interactsh），
    消除与 oob_channel 的重复实现与行为漂移；申请/轮询走同一后端，回调自动进入
    A1.4 证据链审计。通道不可用返回 None，由调用方决定降级路径。
    """
    try:
        from vulnclaw.core.oob_channel import OOBChannel
        domain = await OOBChannel(provider="interactsh").request_domain()
        if domain:
            logger.info(f"📡 [Interactsh] 获取到域名: {domain}")
        else:
            logger.debug("📡 [Interactsh] 通道不可用，返回 None")
        return domain
    except Exception as e:  # noqa: BLE001
        logger.warning(f"📡 [Interactsh] 获取失败: {e}")
        return None


# ============================================================
# 其他辅助工具
# ============================================================
async def get_interactsh_poll(domain: str, timeout: int = 15) -> List[Dict]:
    """轮询 Interactsh 回调（A1.1：委托 OOBChannel，返回原始回调字典）。

    返回每个回调的原始 interactsh JSON 字典，并兼容 net_engines / verify 的
    kebab-case 键（raw-request / q-type），与旧实现形状一致，避免回归。
    """
    try:
        from vulnclaw.core.oob_channel import OOBChannel
        ch = OOBChannel(provider="interactsh")
        await ch.request_domain()  # 从缓存恢复已注册域名与会话文件
        items = await ch.poll(timeout=timeout)
        out: List[Dict] = []
        for it in (items or []):
            extra = getattr(it, "extra", None) or {}
            d = dict(extra)
            # 兼容旧消费者的 kebab-case 键
            d.setdefault("raw-request", d.get("raw_request", "") or "")
            d.setdefault("q-type", d.get("q-type") or d.get("type") or d.get("protocol") or "")
            d.setdefault("protocol", d.get("protocol", "") or "")
            out.append(d)
        if out:
            logger.info(f"📡 [Interactsh poll] 捕获 {len(out)} 条交互")
        return out
    except Exception as e:  # noqa: BLE001
        logger.debug(f"📡 [Interactsh poll] 异常: {e}")
        return []


__all__ = [
    'run_arjun',
    'run_nuclei_async',
    'run_ffuf_async',
    'get_interactsh_domain_async',
    'get_interactsh_poll',
]
