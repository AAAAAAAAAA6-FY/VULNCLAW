# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""B 方案: 双身份矩阵——把会话管理器的真实角色与匿名兜底身份统一为 A/B 双身份视图。

优先级（fail-closed）：
  1. 身份 A（主身份）= 扫描器现有登录态（真实角色，如 default / burp_<domain>）；
  2. 身份 B（副身份）按优先级：
     a) 会话管理器已有第 2+ 角色（如 instruction_auth 注册的多账号）→ 真实第二身份；
     b) IDOR_ROLE_COOKIES_FILE 配置的第二账号 Cookie 文件；
     c) idor_anon_pair=True 时，惰性创建/注入"匿名身份"（独立会话，无 Cookie/Authorization）；
  3. 任何原因拿不到身份 B → identity_b=None，调用方跳过端点，绝不降级为单身份猜测。
"""
import asyncio
import json
import os
from typing import List, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings

_TOKEN_KEYS = ("authorization", "x-api-key", "x-auth-token", "api-key")


class IdentityMatrix:
    """双会话差分所需的最小身份视图（持有会话管理器引用，不复制其状态）。"""

    def __init__(self, session_mgr, anon_session=None):
        self._mgr = session_mgr
        self._anon_session = anon_session   # 可为测试注入的伪会话
        self._role_a: Optional[str] = None
        self._role_b: Optional[str] = None
        self._anon = False
        self._tried_file = False

    # ---------------------------------------------------- 只读视图
    @property
    def identity_a(self) -> Optional[str]:
        return self._role_a

    @property
    def identity_b(self) -> Optional[str]:
        return self._role_b

    @property
    def anon(self) -> bool:
        """True=身份 B 是匿名兜底（未登录访问者）；False=真实第二账号。"""
        return self._anon

    def roles(self) -> List[str]:
        return [r for r in (self._role_a, self._role_b) if r]

    # ---------------------------------------------------- 身份解析
    async def ensure_second_identity(self, domain: str = "") -> Optional[str]:
        """解析并固化 A/B 双身份。返回身份 B role；不可用返回 None（fail-closed）。"""
        if self._role_b is not None:
            return self._role_b
        roles = self._mgr.get_roles() or []
        self._role_a = "default" if "default" in roles else (roles[0] if roles else None)
        if self._role_a is None:
            logger.info("ℹ️ [双身份矩阵] 无主身份会话，差分无意义（跳过）")
            return None
        if len(roles) >= 2:
            for r in roles:
                if r != self._role_a:
                    self._role_b = r
                    break
            logger.info(f"👥 [双身份矩阵] 双身份就绪: A={self._role_a} B={self._role_b}")
            return self._role_b
        _b_file = await self._load_role_file(domain)
        if _b_file is not None:
            return _b_file
        if getattr(settings, "idor_anon_pair", True):
            await self._ensure_anon()
            if self._anon_session is not None:
                self._role_b = "oracle_anon"
                self._anon = True
                logger.info("👤 [双身份矩阵] 无真实第二身份，启用匿名身份兜底")
                return self._role_b
        logger.info("ℹ️ [双身份矩阵] 无可用第二身份（fail-closed，不降级猜测）")
        return None

    async def _load_role_file(self, domain: str) -> Optional[str]:
        """读 IDOR_ROLE_COOKIES_FILE 的第二账号（identity_b）注册为真实角色。"""
        if self._tried_file or not domain:
            return None
        self._tried_file = True
        path = str(getattr(settings, "idor_role_cookies_file", "") or "").strip()
        if not path or not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[双身份矩阵] 角色文件解析失败: {e}")
            return None
        if not isinstance(data, dict):
            return None
        clean = domain.lower().lstrip(".")
        if clean.startswith("www."):
            clean = clean[4:]
        entry = data.get(clean)
        if not isinstance(entry, dict):
            entry = data.get(domain)
        if not isinstance(entry, dict):
            return None
        idb = entry.get("identity_b")
        if not isinstance(idb, dict) or not idb:
            return None
        cookies, tokens = {}, {}
        for k, v in idb.items():
            if k.lower() in _TOKEN_KEYS:
                tokens[k] = v
            else:
                cookies[k] = v
        self._mgr.add_session(
            role="oracle_b", cookie_dict=cookies or None,
            token_dict=tokens or None, domain=clean,
        )
        self._role_b = "oracle_b"
        logger.info("👥 [双身份矩阵] 已从角色文件注册第二账号 oracle_b")
        return self._role_b

    async def _ensure_anon(self) -> None:
        """创建/使用匿名会话（无 Cookie/Authorization）。测试可注入伪会话。"""
        if self._anon_session is not None:
            return
        import aiohttp
        headers = dict(getattr(self._mgr, "default_headers", {}) or {})
        headers.pop("Cookie", None)
        headers.pop("Authorization", None)
        try:
            asyncio.get_running_loop()
            loop_ok = True
        except RuntimeError:
            loop_ok = False
        if loop_ok:
            self._anon_session = aiohttp.ClientSession(
                headers=headers, connector=aiohttp.TCPConnector(ssl=False, limit=16))
            return
        _loop = asyncio.new_event_loop()

        async def _mk():
            return aiohttp.ClientSession(
                headers=headers, connector=aiohttp.TCPConnector(ssl=False, limit=16))

        try:
            asyncio.set_event_loop(_loop)
            self._anon_session = _loop.run_until_complete(_mk())
        finally:
            pass

    # ---------------------------------------------------- 请求分发
    async def request(self, identity: str, method: str, url: str, timeout: int = 10, **kwargs) -> tuple:
        """按身份发请求，返回 (status, text, headers)。匿名身份不经会话管理器（防被注入 Cookie）。"""
        if identity == "oracle_anon":
            if self._anon_session is None:
                return 0, "", {}
            try:
                async with self._anon_session.request(method, url, timeout=timeout, **kwargs) as resp:
                    text = await resp.text()
                    return resp.status, text, dict(resp.headers)
            except Exception:  # noqa: BLE001 - 网络失败按 fail-closed 处理
                return 0, "", {}
        return await self._mgr.request(identity, method, url, timeout=timeout, **kwargs)

    async def close(self) -> None:
        if self._anon_session is not None:
            try:
                await self._anon_session.close()
            except Exception:  # noqa: BLE001
                pass
            self._anon_session = None


__all__ = ["IdentityMatrix"]
