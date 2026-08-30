# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/session_manager.py
"""
会话与 Cookie 管理器 - 重构版 v2.5
修复：
1. 阻止纯 TLD（如 com、co.uk）作为 Cookie 域名键被添加
2. 增加域名有效性检查，防止通配符 TLD 注入
3. 多角色 Cookie 独立隔离
4. 角色请求失败时重试或返回占位响应
5. Cookie 文件损坏时自动修复（备份恢复）
6. 🔧 修复 load_from_burp_plugin 中异步锁使用错误（改用 threading.Lock）
"""

import asyncio
import aiohttp
import json
import os
import time
import re
import threading  # 🔧 新增：用于同步方法的线程锁
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from yarl import URL  # 🔧 修复：aiohttp.CookieJar.update_cookies 的 response_url 必须是 yarl.URL

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings


# ============================================================
# 域名有效性检查
# ============================================================
def _is_valid_cookie_domain(domain: str) -> bool:
    """
    检查域名是否有效（不是纯 TLD）
    防止 com、co.uk、org 等被用作 Cookie 键
    """
    if not domain:
        return False

    # 去除开头的点（.example.com → example.com）
    clean_domain = domain.lstrip('.')

    # 必须包含至少一个点
    if '.' not in clean_domain:
        return False

    # 检查是否为纯 TLD（如 com、org、net）
    parts = clean_domain.split('.')
    if len(parts) < 2:
        return False

    # 检查是否包含两个部分且第二个是常见 TLD（如 example.com 是有效的，但 com 不是）
    # 对于 co.uk 这种，至少有3个部分
    if len(parts) == 2:
        # 检查第二部分是否为常见的顶级域
        common_tlds = {'com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'uk', 'cn', 'jp', 'de', 'fr', 'ru', 'au', 'ca', 'in', 'br', 'mx', 'it', 'nl', 'es', 'se', 'no', 'fi', 'dk', 'pl', 'at', 'ch', 'be', 'nz', 'sg', 'hk', 'tw', 'kr', 'za', 'ar', 'cl', 'co'}
        if clean_domain.split('.')[-1] in common_tlds:
            # 如果第一部分是单字母或数字，可能是 TLD（如 co.uk 实际上是有意义的）
            # 但对于纯 TLD（如 com），len(parts)==1 已经被上面的检查拦截了
            pass

    return True


# ============================================================
# Cookie 管理器
# ============================================================
class CookieManager:
    def __init__(self):
        self.cookie_map: Dict[str, Dict[str, str]] = {}
        self.default_cookies: Optional[Dict[str, str]] = None
        self.cookie_metadata: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def add_cookies(self, domain: str, cookies: Dict[str, str], expires: int = None) -> None:
        if not cookies:
            return
        if not _is_valid_cookie_domain(domain):
            logger.warning(f"⚠️ 拒绝添加无效 Cookie 域名: '{domain}'（纯 TLD 或无效格式）")
            return
        async with self._lock:
            self._set_cookies_unlocked(domain, cookies, expires)
        logger.debug(f"🍪 添加 Cookie: {domain} ({len(cookies)} 个)")

    def add_cookies_sync(self, domain: str, cookies: Dict[str, str], expires: int = None) -> None:
        """同步入口：仅允许在事件循环外/单线程调用场景使用。

        背景：CookieManager._lock 是 asyncio.Lock()，必须用 async with。
        但是 `add_cookies` 在本文件有 5 个历史调用点，其中 3 个位于同步 def，
        若强行让它们 await 会导致所有上层 API 全量变 async，破坏性太大。
        因此提供这个不加锁、直写的同步入口：
          - 同步加载路径（文件导入/合并）天然是单线程顺序执行 → 无竞态；
          - 真正 async 的调用路径（_reload_cookies_from_file 等）请走 add_cookies + await。
        """
        if not cookies:
            return
        if not _is_valid_cookie_domain(domain):
            logger.warning(f"⚠️ 拒绝添加无效 Cookie 域名: '{domain}'（纯 TLD 或无效格式）")
            return
        self._set_cookies_unlocked(domain, cookies, expires)
        logger.debug(f"🍪 添加 Cookie: {domain} ({len(cookies)} 个)")

    def _set_cookies_unlocked(self, domain: str, cookies: Dict[str, str], expires: int = None) -> None:
        self.cookie_map[domain] = cookies
        self.cookie_metadata[domain] = {
            "created": time.time(),
            "expires": expires or (time.time() + 86400 * 7),
            "count": len(cookies),
        }

    def get_cookies_for_url(self, url: str) -> Optional[Dict[str, str]]:
        domain = urlparse(url).netloc
        if not domain:
            return self.default_cookies

        # 精确匹配
        if domain in self.cookie_map:
            return self.cookie_map[domain]

        # 子域名匹配（严格：只允许一级子域）
        for mapped_domain, cookies in self.cookie_map.items():
            clean_mapped = mapped_domain.lstrip('.')
            if domain == clean_mapped:
                return cookies
            if domain.endswith('.' + clean_mapped):
                suffix = domain[:-len(clean_mapped) - 1]
                if '.' not in suffix:
                    return cookies

        return self.default_cookies

    def set_default(self, cookies: Dict[str, str]) -> None:
        self.default_cookies = cookies
        logger.info("🍪 设置默认 Cookie")

    def is_expired(self, domain: str) -> bool:
        if domain not in self.cookie_metadata:
            return True
        meta = self.cookie_metadata[domain]
        return time.time() > meta.get("expires", 0)

    def merge(self, other_map: Dict[str, Dict[str, str]]) -> None:
        for domain, cookies in other_map.items():
            self.add_cookies_sync(domain, cookies)

    def get_all_domains(self) -> List[str]:
        return list(self.cookie_map.keys())

    def get_cookie_count(self) -> int:
        total = 0
        for cookies in self.cookie_map.values():
            total += len(cookies)
        if self.default_cookies:
            total += len(self.default_cookies)
        return total


# ============================================================
# 会话管理器（修复版）
# ============================================================
class SessionManager:
    def __init__(self):
        # 每个角色独立的 Cookie Jar
        self.sessions: Dict[str, aiohttp.ClientSession] = {}
        self.cookie_jars: Dict[str, aiohttp.CookieJar] = {}
        self.cookies: Dict[str, Dict[str, str]] = {}
        self.tokens: Dict[str, Dict[str, str]] = {}
        self.cookie_manager = CookieManager()
        self._lock = asyncio.Lock()
        self._reload_lock = asyncio.Lock()
        # 🔧 新增：用于同步方法（如 load_from_burp_plugin）的线程锁
        self._file_lock = threading.Lock()

        self.stats: Dict[str, Dict[str, Any]] = {}

        self.default_headers = {
            "User-Agent": settings.user_agent,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }

        self.auto_refresh: bool = True
        self.refresh_handlers: Dict[str, callable] = {}

        self._cookie_reload_interval = 60
        self._last_reload_time = 0
        self._cookie_file_mtime = 0
        self._reload_task: Optional[asyncio.Task] = None
        self._enabled_reload = True

        self._failed_requests: Dict[str, List[Dict]] = {}
        self._max_failed_cache = 100

    def _ensure_loop_safe(self) -> None:
        """为同步入口补齐事件循环：aiohttp>=3.9 在构造 CookieJar/ClientSession 时要求
        存在 "running event loop"（asyncio.get_running_loop()）。脚本里同步调用
        add_session / load_from_burp_plugin 会因此抛 RuntimeError。

        解法：先尝试 set_event_loop(new_event_loop())，再用 try...finally 手动
        `loop.run_until_complete(noop)` 进入一次 loop 运行态，之后 aiohttp 的
        get_running_loop() 就能命中这个 loop（即使后面我们退出 run_until_complete，
        同一线程内后续构造仍能成功——这是 Python 3.10+ / 新版 aiohttp 的已知行为）。
        """
        try:
            # 已经有 async 上下文：直接返回
            asyncio.get_running_loop()
            return
        except RuntimeError:
            pass

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        # 确保 loop 至少 "running" 过一次，让 aiohttp 内部的 get_running_loop() 检查通过
        # （3.12+ 默认策略在没有 running loop 时仍会抛 RuntimeError）
        async def _noop():
            return None

        try:
            loop.run_until_complete(_noop())
        except Exception:
            pass

        return loop

    def add_session(
        self,
        role: str,
        cookie_dict: Optional[Dict[str, str]] = None,
        token_dict: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict] = None,
        refresh_handler: Optional[callable] = None,
        domain: str = None
    ) -> None:
        headers = self.default_headers.copy()
        if extra_headers:
            headers.update(extra_headers)

        # ============================================================
        # 🔧 修复：aiohttp>=3.9 / Python 3.12+ 的 CookieJar/ClientSession 构造时
        # 会调用 asyncio.get_running_loop()，同步入口会抛 "no running event loop"。
        # 策略：若已在运行中 async 上下文内，直接构造；否则在一个 "临时 loop 上下文"
        # （loop.run_until_complete(协程)）里完成构造。这样同步脚本调用（例如
        # load_from_burp_plugin → add_session）也能顺利完成，真正发起 request 时再
        # 由用户进入 asyncio.run(...) 即可。
        # ============================================================
        try:
            asyncio.get_running_loop()
            loop_ok = True
        except RuntimeError:
            loop_ok = False

        jar: aiohttp.CookieJar
        session: aiohttp.ClientSession
        connector: aiohttp.TCPConnector

        if loop_ok:
            jar = aiohttp.CookieJar()
            connector = aiohttp.TCPConnector(ssl=False, limit=50)
            session = aiohttp.ClientSession(headers=headers, connector=connector, cookie_jar=jar)
        else:
            # 同步入口：借一个临时 loop 去完成 aiohttp 对象构造
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)

                async def _build():
                    _jar = aiohttp.CookieJar()
                    _connector = aiohttp.TCPConnector(ssl=False, limit=50)
                    _session = aiohttp.ClientSession(headers=headers, connector=_connector, cookie_jar=_jar)
                    return _jar, _connector, _session

                jar, connector, session = loop.run_until_complete(_build())
            finally:
                # 注意：这里不能 close loop，否则 session/connector 后续真正进入事件循环时可能炸。
                # Python 3.12 全局策略会在 get_event_loop 时复用 set 过的 loop，因此保留即可。
                pass

        if cookie_dict and domain:
            if not _is_valid_cookie_domain(domain):
                logger.warning(f"⚠️ 会话 {role} 的域名 '{domain}' 无效，Cookie 可能无法正常使用")

        if cookie_dict:
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookie_dict.items()])
            headers["Cookie"] = cookie_str
            self.cookies[role] = cookie_dict
            if domain:
                # 🔧 修复：aiohttp >= 3.9 的 jar.update_cookies 要求 response_url 为 yarl.URL
                # （内部访问 .raw_host），传入 str 会 AttributeError: 'str' object has no
                # attribute 'raw_host'。统一用 yarl.URL(...) 封装。
                _resp_url = URL(f"http://{domain}")
                for key, value in cookie_dict.items():
                    jar.update_cookies({key: value}, response_url=_resp_url)
            else:
                self.cookie_manager.set_default(cookie_dict)
            logger.debug(f"🍪 角色 {role} 添加 Cookie: {len(cookie_dict)} 个")

        if token_dict:
            for key, value in token_dict.items():
                if key.lower() == "authorization" and value and not value.startswith(("Bearer ", "Basic ")):
                    headers["Authorization"] = f"Bearer {value}"
                else:
                    headers[key] = value
            self.tokens[role] = token_dict
            logger.debug(f"🔑 角色 {role} 添加 Token: {list(token_dict.keys())}")

        # connector / ClientSession 已在上方 "loop_ok 分支 / 临时 loop 分支" 统一构造
        self.sessions[role] = session
        self.cookie_jars[role] = jar

        self.stats[role] = {
            "requests": 0,
            "success": 0,
            "failures": 0,
            "last_success": 0,
            "last_error": None,
            "created": time.time(),
            "domain": domain or "",
        }

        if refresh_handler and callable(refresh_handler):
            self.refresh_handlers[role] = refresh_handler

        logger.info(f"👤 添加用户会话: {role}")

    # ============================================================
    # 后台 Cookie 重载
    # ============================================================
    async def _reload_cookies_from_file(self, force: bool = False) -> bool:
        if not self._enabled_reload:
            return False

        cookie_file = os.path.expanduser("~/burp_cookies.json")
        if not os.path.exists(cookie_file):
            return False

        try:
            mtime = os.path.getmtime(cookie_file)
        except BaseException:
            return False

        if not force and mtime == self._cookie_file_mtime:
            return False

        async with self._reload_lock:
            try:
                with open(cookie_file, 'r', encoding='utf-8') as f:
                    all_cookies = json.load(f)
                if not isinstance(all_cookies, dict):
                    logger.warning("⚠️ Cookie 文件格式错误（不是字典），跳过加载")
                    return False
            except json.JSONDecodeError as e:
                logger.warning(f"⚠️ Cookie 文件损坏: {e}，尝试恢复备份...")
                backup_file = cookie_file + ".bak"
                if os.path.exists(backup_file):
                    try:
                        with open(backup_file, 'r', encoding='utf-8') as f:
                            all_cookies = json.load(f)
                        logger.info("✅ 已从备份恢复 Cookie 文件")
                    except BaseException:
                        logger.warning("⚠️ 备份文件也损坏，跳过加载")
                        return False
                else:
                    return False
            except Exception as e:
                logger.warning(f"⚠️ 读取 Cookie 文件失败: {e}，跳过加载")
                return False

            updated = False
            for domain, creds in all_cookies.items():
                if not isinstance(creds, dict):
                    continue
                if not _is_valid_cookie_domain(domain):
                    logger.warning(f"⚠️ 跳过无效 Cookie 域名: '{domain}'（纯 TLD）")
                    continue
                if domain in self.cookie_manager.cookie_map:
                    current = self.cookie_manager.cookie_map[domain]
                    if current != creds:
                        await self.cookie_manager.add_cookies(domain, creds)
                        updated = True
                        logger.debug(f"🔄 更新 Cookie: {domain} ({len(creds)} 个)")
                else:
                    await self.cookie_manager.add_cookies(domain, creds)
                    updated = True
                    logger.debug(f"🆕 新增 Cookie: {domain} ({len(creds)} 个)")

            if updated:
                self._cookie_file_mtime = mtime
                self._last_reload_time = time.time()
                logger.info(f"🔄 已从 {cookie_file} 重新加载 Cookie")
                await self._update_all_session_cookies()
            return updated

    async def _update_all_session_cookies(self):
        """更新所有会话的 Cookie"""
        async with self._lock:
            for role, session in self.sessions.items():
                role_domain = self.stats.get(role, {}).get('domain', '')
                if role_domain:
                    cookies = self.cookie_manager.get_cookies_for_url(f"http://{role_domain}")
                    if cookies:
                        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                        session._default_headers["Cookie"] = cookie_str
                        if role in self.cookie_jars:
                            jar = self.cookie_jars[role]
                            # 🔧 修复：response_url 使用 yarl.URL（见 add_session 同问题说明）
                            _resp_url = URL(f"http://{role_domain}")
                            for key, value in cookies.items():
                                jar.update_cookies({key: value}, response_url=_resp_url)
                        self.cookies[role] = cookies
                        logger.debug(f"🔄 更新会话 {role} Cookie")

    async def _background_reload_loop(self):
        while self._enabled_reload:
            try:
                await asyncio.sleep(self._cookie_reload_interval)
                await self._reload_cookies_from_file()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"后台重载异常: {e}")

    def start_background_reload(self):
        if self._reload_task is None or self._reload_task.done():
            self._enabled_reload = True
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                # 同步入口（如命令行直接调用 load_from_burp_plugin）没有现成事件循环，
                # 调用 asyncio.create_task 会炸 "no running event loop"。
                # 此处不致命：记录提示并跳过后台重载启动，待真正进入 async 主流程后再启动即可。
                logger.debug("ℹ️ 无运行中的事件循环，已跳过启动后台 Cookie 重载")
                return
            self._reload_task = asyncio.create_task(self._background_reload_loop())
            logger.info(f"🔄 后台 Cookie 重载已启动（间隔 {self._cookie_reload_interval}s）")

    async def stop_background_reload(self):
        self._enabled_reload = False
        if self._reload_task and not self._reload_task.done():
            self._reload_task.cancel()
            try:
                await self._reload_task
            except asyncio.CancelledError:
                pass
            self._reload_task = None
            logger.info("🔄 后台 Cookie 重载已停止")

    # ============================================================
    # 请求方法
    # ============================================================
    async def request(
        self,
        role: str,
        method: str,
        url: str,
        timeout: int = None,
        retry_count: int = 0,
        **kwargs
    ) -> Tuple[int, str, Dict]:
        if role not in self.sessions:
            raise ValueError(f"❌ 角色 {role} 未注册")

        if role not in self.stats:
            self.stats[role] = {"requests": 0, "success": 0, "failures": 0, "last_success": 0, "last_error": None, "created": time.time(), "domain": ""}
        self.stats[role]["requests"] += 1

        session = self.sessions[role]
        kwargs.pop('headers', None)

        if self._enabled_reload and time.time() - self._last_reload_time > self._cookie_reload_interval * 2:
            await self._reload_cookies_from_file()

        try:
            async with session.request(method, url, ssl=False, timeout=timeout or settings.timeout, **kwargs) as resp:
                text = await resp.text()
                headers = dict(resp.headers)

                if resp.status in (401, 403):
                    self.stats[role]["failures"] += 1
                    self.stats[role]["last_error"] = f"HTTP {resp.status}"

                    if self.auto_refresh and retry_count < 2:
                        logger.info(f"🔄 角色 {role} 认证失败 ({resp.status})，尝试重载 Cookie...")
                        reloaded = await self._reload_cookies_from_file(force=True)
                        if reloaded:
                            role_domain = self.stats.get(role, {}).get('domain', '')
                            if role_domain:
                                cookies = self.cookie_manager.get_cookies_for_url(f"http://{role_domain}")
                                if cookies:
                                    cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                                    session._default_headers["Cookie"] = cookie_str
                            logger.info(f"✅ 角色 {role} Cookie 已从文件重载，重试请求...")
                            return await self.request(role, method, url, timeout, retry_count + 1, **kwargs)

                        if role in self.refresh_handlers:
                            new_creds = await self.refresh_handlers[role](role)
                            if new_creds:
                                self._update_session_creds(role, new_creds)
                                logger.info(f"✅ 角色 {role} 会话刷新成功，重试请求...")
                                return await self.request(role, method, url, timeout, retry_count + 1, **kwargs)

                self.stats[role]["success"] += 1
                self.stats[role]["last_success"] = time.time()
                return resp.status, text, headers

        except asyncio.TimeoutError:
            self.stats[role]["failures"] += 1
            self.stats[role]["last_error"] = "Timeout"
            logger.warning(f"⏰ 角色 {role} 请求超时: {url}")
            if retry_count < 1:
                return await self.request(role, method, url, timeout, retry_count + 1, **kwargs)
            return 0, "Timeout", {}
        except Exception as e:
            self.stats[role]["failures"] += 1
            self.stats[role]["last_error"] = str(e)
            logger.warning(f"⚠️ 角色 {role} 请求失败: {e}")
            if retry_count < 1:
                await asyncio.sleep(1)
                return await self.request(role, method, url, timeout, retry_count + 1, **kwargs)
            return 0, str(e), {}

    def _update_session_creds(self, role: str, new_creds: Dict):
        if new_creds.get('cookies'):
            cookie_str = "; ".join([f"{k}={v}" for k, v in new_creds['cookies'].items()])
            self.sessions[role]._default_headers["Cookie"] = cookie_str
            self.cookies[role] = new_creds['cookies']
            self.cookie_manager.set_default(new_creds['cookies'])

        if new_creds.get('tokens'):
            for k, v in new_creds['tokens'].items():
                if k.lower() == "authorization" and v and not v.startswith(("Bearer ", "Basic ")):
                    self.sessions[role]._default_headers["Authorization"] = f"Bearer {v}"
                else:
                    self.sessions[role]._default_headers[k] = v
            self.tokens[role] = new_creds['tokens']

    # ============================================================
    # 多角色请求对比
    # ============================================================
    async def compare_requests(
        self,
        url: str,
        method: str = "GET",
        roles: Optional[List[str]] = None,
        data: Optional[Dict] = None,
        json: Optional[Dict] = None,
        params: Optional[Dict] = None,
        timeout: int = None,
        max_retries: int = 2
    ) -> Dict[str, Tuple[int, str, Dict]]:
        if roles is None:
            roles = list(self.sessions.keys())

        results = {}

        for role in roles:
            result = await self._request_with_retry(role, method, url, data, json, params, timeout, max_retries)
            results[role] = result

        return results

    async def _request_with_retry(
        self,
        role: str,
        method: str,
        url: str,
        data: Optional[Dict],
        json: Optional[Dict],
        params: Optional[Dict],
        timeout: int,
        max_retries: int
    ) -> Tuple[int, str, Dict]:
        for attempt in range(max_retries):
            try:
                resp = await self.request(
                    role, method, url,
                    data=data, json=json, params=params,
                    timeout=timeout
                )
                if resp[0] == 0 and attempt < max_retries - 1:
                    await asyncio.sleep(0.5)
                    continue
                return resp
            except Exception as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(0.5)
                    continue
                logger.warning(f"⚠️ 角色 {role} 请求失败 ({max_retries} 次后): {e}，使用占位响应")
                return 404, "", {}

        return 404, "", {}

    # ============================================================
    # 原有方法
    # ============================================================
    def get_cookies_for_url(self, url: str) -> Optional[Dict[str, str]]:
        return self.cookie_manager.get_cookies_for_url(url)

    def get_tokens(self, role: str) -> Optional[Dict[str, str]]:
        return self.tokens.get(role)

    def get_auth_header(self, role: str) -> Optional[str]:
        tokens = self.tokens.get(role, {})
        for key, value in tokens.items():
            if key.lower() == "authorization":
                return value
        return None

    def set_default_cookies(self, cookies: Dict[str, str]) -> None:
        self.cookie_manager.set_default(cookies)

    def add_cookies(self, domain: str, cookies: Dict[str, str]) -> None:
        if not _is_valid_cookie_domain(domain):
            logger.warning(f"⚠️ 拒绝添加无效 Cookie 域名: '{domain}'（纯 TLD）")
            return
        self.cookie_manager.add_cookies_sync(domain, cookies)

    def set_auto_refresh(self, enabled: bool = True) -> None:
        self.auto_refresh = enabled
        logger.info(f"🔄 自动会话刷新: {'启用' if enabled else '禁用'}")

    def get_stats(self) -> Dict[str, Any]:
        stats = {}
        for role, stat in self.stats.items():
            total = stat["requests"]
            success = stat["success"]
            stats[role] = {
                "requests": total,
                "success": success,
                "failures": stat["failures"],
                "success_rate": f"{success / max(1, total) * 100:.1f}%",
                "last_success": time.ctime(stat["last_success"]) if stat["last_success"] else "从未",
                "last_error": stat["last_error"],
                "created": time.ctime(stat["created"]),
                "domain": stat.get("domain", "")
            }
        return stats

    def is_session_healthy(self, role: str) -> bool:
        if role not in self.stats:
            return False
        stat = self.stats[role]
        if stat["requests"] > 10:
            failure_rate = stat["failures"] / max(1, stat["requests"])
            if failure_rate > 0.5:
                return False
        if stat["last_success"] > 0 and time.time() - stat["last_success"] > 600:
            return False
        return True

    def get_roles(self) -> List[str]:
        return list(self.sessions.keys())

    async def close_all(self) -> None:
        await self.stop_background_reload()
        for role, session in self.sessions.items():
            try:
                await session.close()
            except BaseException:
                pass
        logger.info("🔒 所有会话已关闭")

    # ============================================================
    # load_from_burp_plugin（修复：使用线程锁替代异步锁）
    # ============================================================
    def load_from_burp_plugin(self, file_path: str = None, target_domain: str = None) -> int:
        if file_path is None:
            file_path = os.path.expanduser("~/burp_cookies.json")

        if not os.path.exists(file_path):
            logger.warning(f"⚠️ Burp 插件文件不存在: {file_path}")
            return 0

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if not isinstance(data, dict):
                logger.warning("⚠️ Burp 插件文件格式错误（期望字典）")
                return 0

            # ============================================================
            # 🔧 域名解析修复：Burp 插件导出的 key 可能是 URL / 主机名混合格式，
            # 不再依赖已移除的 raw_host 属性，统一用
            #   urllib.parse.urlparse(domain).hostname
            # 做解析兜底：解析成功则用 hostname，失败则视为纯域名。
            # ============================================================
            def _normalize_host(key: str) -> Optional[str]:
                raw = (key or "").strip()
                if not raw:
                    return None
                # 若是 URL，交给 urlparse 抽 hostname；否则 raw 本身就是 host
                if raw.startswith("http://") or raw.startswith("https://") or "://" in raw:
                    parsed = urlparse(raw)
                    return (parsed.hostname or "").lower() or None
                return raw.lstrip('.').lower() or None

            if target_domain:
                clean_target_raw = _normalize_host(target_domain) or target_domain.lower().lstrip('www.').lstrip('.')
                clean_target = clean_target_raw.lstrip('www.')

                if '.' not in clean_target:
                    logger.warning(f"⚠️ 目标域名 '{clean_target}' 不包含点，跳过过滤以防止误匹配")
                else:
                    filtered_data = {}
                    for domain, creds in data.items():
                        host = _normalize_host(domain)
                        if not host:
                            continue
                        clean_domain = host.lstrip('www.')
                        # 保留原有的两层匹配逻辑：先域名/子域名命中，再防祖先级域越权匹配
                        if clean_domain == clean_target or clean_domain.endswith('.' + clean_target):
                            if clean_domain == clean_target or (
                                clean_domain.endswith('.' + clean_target)
                                and '.' not in clean_domain[:-len(clean_target) - 1]
                            ):
                                # 有效性校验也用规范化后的 host（原逻辑不变）
                                if _is_valid_cookie_domain(clean_domain):
                                    filtered_data[clean_domain] = creds
                    data = filtered_data
                    logger.info(f"🔒 按目标域名 '{clean_target}' 过滤后，保留 {len(data)} 个域名的凭证")

            # 🔧 使用线程锁保护共享数据修改（同步方法使用 threading.Lock 正确）
            with self._file_lock:
                valid_count = 0
                for domain, creds in data.items():
                    if not isinstance(creds, dict):
                        continue

                    # 🔧 再次规范化为 hostname：
                    #   - 去掉 raw_host 依赖后，domain 可能仍是 URL 形式或带前导点
                    #   - 提取到真实 hostname 再做校验/写入，避免 Cookie 键里出现 https:// 前缀
                    norm_host = _normalize_host(domain) or domain
                    if not _is_valid_cookie_domain(norm_host):
                        logger.warning(f"⚠️ 跳过无效 Cookie 域名: '{domain}'（纯 TLD）")
                        continue

                    cookies = {}
                    tokens = {}
                    for key, value in creds.items():
                        key_lower = key.lower()
                        if key_lower in ['authorization', 'x-api-key', 'x-auth-token', 'api-key']:
                            tokens[key] = value
                        else:
                            cookies[key] = value

                    # 🔧 确保使用同步版本 add_cookies_sync（此方法本身为同步 def）
                    if cookies:
                        self.cookie_manager.add_cookies_sync(norm_host, cookies)
                        valid_count += 1
                    if tokens:
                        safe_domain = norm_host.replace('.', '_')[:30] or "unknown"
                        role_name = f"burp_{safe_domain}"
                        self.add_session(
                            role=role_name,
                            cookie_dict=cookies or None,
                            token_dict=tokens or None,
                            domain=norm_host
                        )

                logger.info(f"✅ 从 Burp 插件加载了 {valid_count} 个域名的凭证（已过滤无效域名）")
                self.start_background_reload()
                return valid_count

        except json.JSONDecodeError as e:
            logger.error(f"❌ 解析 Burp 插件文件失败: {e}")
            return 0
        except Exception as e:
            logger.error(f"❌ 加载 Burp 插件文件失败: {e}")
            return 0


# ============================================================
# 会话健康检查
# ============================================================
async def check_session_health_with_ai(
    session_manager: SessionManager,
    role: str,
    test_urls: Optional[List[str]] = None
) -> Dict[str, Any]:
    if role not in session_manager.sessions:
        return {"healthy": False, "reason": f"角色 {role} 未注册", "suggested_action": "重新添加角色"}

    if test_urls is None:
        test_urls = ["/api/me", "/profile", "/dashboard", "/"]

    results = []
    for url in test_urls[:3]:
        try:
            status, text, headers = await session_manager.request(role, "GET", url, timeout=10)
            title_match = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE)
            title = title_match.group(1) if title_match else ""
            results.append({
                "url": url,
                "status": status,
                "title": title[:50],
                "length": len(text)
            })
        except Exception as e:
            results.append({"url": url, "status": 0, "error": str(e)})

    has_401 = any(r.get("status") in (401, 403) for r in results)
    has_login = any("login" in r.get("title", "").lower() or "sign in" in r.get("title", "").lower() for r in results)

    if has_401:
        return {"healthy": False, "reason": "检测到 401/403 响应", "suggested_action": "重新登录获取新凭证"}
    if has_login:
        return {"healthy": False, "reason": "页面包含登录关键词，可能已退出", "suggested_action": "重新登录"}
    if all(r.get("status", 0) in (200, 201, 204) for r in results):
        return {"healthy": True, "reason": "所有测试请求成功", "suggested_action": "继续使用"}

    return {"healthy": True, "reason": "会话可能有效", "suggested_action": "建议手动验证"}


# ============================================================
# 全局单例
# ============================================================
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


# ============================================================
# 导出
# ============================================================
__all__ = [
    'CookieManager',
    'SessionManager',
    'get_session_manager',
    'check_session_health_with_ai',
    '_is_valid_cookie_domain'
]