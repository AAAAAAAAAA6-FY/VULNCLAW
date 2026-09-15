# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/render_session.py
"""
可复用渲染会话（借鉴 Scrapling 的 Fetcher 设计）

本模块存在的原因（旧实现的两个真实缺陷）：
  1) **每个 URL 冷启动一次浏览器**。旧 `crawl_same_origin._fetch_html` 在每次
     fetch 内 `async with async_playwright()` + `chromium.launch()`，即渲染 80 个
     URL = 80 次 chromium 冷启动；单次冷启动 0.5~2s，纯启动开销就吃掉渲染爬取的
     主要时间预算。
  2) **每次全新 profile 的指纹高度雷同**。webdriver 标志、无历史、无插件、
     固定视口，逐次重建反而更容易被判为机器人——这恰好与"绕过反爬"的目标相反。

借鉴 Scrapling（BSD-3）的两条长处：
  · **会话复用**：浏览器只起一次，page 池化跨 URL 复用（本模块）
  · **隐身后端优先**：优先 `patchright`（Playwright 的隐身 fork，消除
    navigator.webdriver 等自动化特征），缺失时回退标准 Playwright。
    Scrapling 的 StealthyFetcher 亦基于 patchright，此处同构采用其思路而非引其源码。

可选依赖策略：两后端都缺失 → `open_render_session()` 返回 None，调用方回退纯
HTTP 爬取（与旧行为完全一致，零回归）。任何异常一律返回 None / 关闭会话，
绝不影响主流程。

纪律：无 emoji、轻量、异常优雅降级、并发安全。
"""
import asyncio
import importlib
import logging
from contextlib import asynccontextmanager
from typing import Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 后端优先级：patchright（隐身，借鉴 Scrapling 的选型）> playwright（标准）
_BACKEND_CANDIDATES = (
    ("patchright.async_api", "patchright"),
    ("playwright.async_api", "playwright"),
)

# 渲染页 UA：与 curl_cffi 默认 chrome 指纹保持同一代次，避免 TLS 层与 JS 层自相矛盾。
_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

_MAX_POOL_PAGES = 4


def _load_backend() -> Tuple[Optional[Any], Optional[str]]:
    """按优先级加载渲染后端，返回 (模块, 后端名)；都不可用返回 (None, None)。"""
    for module_path, name in _BACKEND_CANDIDATES:
        try:
            return importlib.import_module(module_path), name
        except Exception:  # noqa: BLE001 - 可选依赖缺失视为不可用
            continue
    return None, None


def render_backend_name() -> Optional[str]:
    """当前可用的渲染后端名（patchright / playwright），都不可用返回 None。"""
    return _load_backend()[1]


def render_available() -> bool:
    """是否存在可用的渲染后端。"""
    return _load_backend()[1] is not None


class RenderSession:
    """一次性启动、跨 URL 复用的渲染会话。

    用法（异步上下文管理器）::

        async with RenderSession() as rs:
            if rs is not None:
                got = await rs.fetch("https://target/")

    `__aenter__` 在启动失败时返回 None，调用方据此回退 HTTP。
    """

    def __init__(self, headless: bool = True, max_pages: int = _MAX_POOL_PAGES,
                 user_agent: str = _DEFAULT_UA, timeout_ms: int = 15000):
        self.headless = headless
        self.max_pages = max(1, int(max_pages))
        self.user_agent = user_agent
        self.timeout_ms = timeout_ms
        self.backend: str = ""
        self._pw_ctx: Optional[Any] = None
        self._browser: Optional[Any] = None
        self._pool: List[Any] = []
        self._sem: Optional[asyncio.Semaphore] = None

    # ---- 生命周期 ----
    async def __aenter__(self) -> Optional["RenderSession"]:
        return self if await self.start() else None

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    async def start(self) -> bool:
        """启动浏览器。成功返回 True；后端缺失/启动失败返回 False（调用方回退 HTTP）。"""
        module, name = _load_backend()
        if module is None:
            return False
        try:
            self._pw_ctx = module.async_playwright()
            pw = await self._pw_ctx.__aenter__()
            self._browser = await pw.chromium.launch(
                headless=self.headless,
                args=["--disable-blink-features=AutomationControlled"],
            )
            self.backend = name or ""
            self._sem = asyncio.Semaphore(self.max_pages)
            logger.debug(f"渲染会话已启动（后端={self.backend}, 页池={self.max_pages}）")
            return True
        except Exception as exc:  # noqa: BLE001 - 启动失败一律降级
            logger.debug(f"渲染会话启动失败（回退 HTTP 爬取）: {exc}")
            await self.close()
            return False

    async def close(self) -> None:
        """关闭所有 page / browser / playwright 上下文；重复调用安全。"""
        for page in self._pool:
            try:
                if not page.is_closed():
                    await page.close()
            except Exception:  # noqa: BLE001
                pass
        self._pool = []
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:  # noqa: BLE001
                pass
            self._browser = None
        if self._pw_ctx is not None:
            try:
                await self._pw_ctx.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
            self._pw_ctx = None

    # ---- 页池 ----
    @asynccontextmanager
    async def _page(self):
        """从池中取一个 page（池空则新建），用完归还。

        Semaphore 把并发页数限制在 max_pages：单个 page 不能被并发导航，
        无限新建又会退化成"每 URL 一个页面"的老问题。
        """
        if self._browser is None or self._sem is None:
            raise RuntimeError("render session not started")
        await self._sem.acquire()
        page = None
        try:
            while self._pool:
                cand = self._pool.pop()
                if not cand.is_closed():
                    page = cand
                    break
            if page is None:
                page = await self._browser.new_page(user_agent=self.user_agent)
                # P3-10：JS 运行时监控 hook（每个新 page 注入一次；池复用不重复）。
                # 失败静默 —— hook 是增强项，绝不影响渲染主流程。
                try:
                    from vulnclaw.core.js_hooks import JS_HOOK
                    await page.add_init_script(JS_HOOK)
                except Exception:  # noqa: BLE001
                    pass
            yield page
        finally:
            if page is not None:
                try:
                    if not page.is_closed():
                        self._pool.append(page)
                except Exception:  # noqa: BLE001
                    pass
            self._sem.release()

    # ---- 取数 ----
    async def fetch(self, url: str, wait_until: str = "networkidle",
                    timeout_ms: Optional[int] = None) -> Optional[Tuple[int, str]]:
        """渲染 URL，返回 (状态码, HTML)；失败返回 None（调用方回退 HTTP）。"""
        if self._browser is None:
            return None
        timeout = int(timeout_ms or self.timeout_ms)
        try:
            async with self._page() as page:
                resp = await page.goto(url, timeout=timeout, wait_until=wait_until)
                status = resp.status if resp is not None else 200
                html = await page.content()
                return int(status), (html or "")
        except Exception as exc:  # noqa: BLE001 - 单页失败不影响会话/其他页
            logger.debug(f"渲染失败 {url}: {exc}")
            return None

    async def render_for_dialog(self, url: str, wait_ms: int = 1500,
                                timeout_ms: Optional[int] = None) -> Optional[bool]:
        """（兼容包装）见 render_for_dialog_ex——只返回 dialog 命中布尔。"""
        res = await self.render_for_dialog_ex(url, wait_ms=wait_ms, timeout_ms=timeout_ms)
        return None if res is None else res[0]

    async def render_for_dialog_ex(self, url: str, wait_ms: int = 1500,
                                   timeout_ms: Optional[int] = None
                                   ) -> Optional[Tuple[bool, list]]:
        """渲染 URL：dialog 监听 + JS 运行时监控读回（P3-10）。

        用途：DOM 型 XSS 的**执行级**判定——
        ① dialog 命中（alert/confirm/prompt 弹窗）；
        ② JS hook 命中（静默 DOM XSS：innerHTML/eval/document.write/cookie 读取等
           sink 被调用但无弹窗）。

        返回 (dialog_hit, runtime_hits)；None=渲染不可用/失败（调用方按"未确认"
        处理，**不得当作命中**，避免把渲染故障伪装成漏洞）。
        runtime_hits 读回失败 → 空列表（**读回失败不得当作命中**）。"""
        if self._browser is None:
            return None
        timeout = int(timeout_ms or self.timeout_ms)
        try:
            async with self._page() as page:
                fired = {"hit": False}

                async def _on_dialog(dialog):
                    fired["hit"] = True
                    try:
                        await dialog.dismiss()
                    except Exception:  # noqa: BLE001
                        pass

                page.on("dialog", _on_dialog)
                try:
                    await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
                except Exception:  # noqa: BLE001 - 导航异常不阻断判定
                    pass
                try:
                    await page.wait_for_timeout(wait_ms)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    page.remove_listener("dialog", _on_dialog)  # 归还页池前摘监听
                except Exception:  # noqa: BLE001
                    pass
                # P3-10：读回 JS 运行时命中（hook 注入见 _page）；失败=空列表
                hits = []
                try:
                    hits = await page.evaluate("window.__vulnclaw_hits || []") or []
                except Exception:  # noqa: BLE001
                    hits = []
                return bool(fired["hit"]), list(hits)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"dialog 渲染失败 {url}: {exc}")
            return None


    async def evaluate_on_render(self, url: str, expr: str, wait_ms: int = 1500,
                                 timeout_ms: Optional[int] = None) -> Optional[str]:
        """渲染 URL 后执行 JS 表达式并返回其值（exploit_verify 的执行级实锤）。

        与 render_for_dialog_ex 同一页池纪律：浏览器启一次、page 复用，
        **禁止**调用方自行 async_playwright()+launch() 冷启动。
        返回 None=渲染不可用/失败（调用方按"未确认"处理）；表达式求值异常 → ""。
        """
        if self._browser is None:
            return None
        timeout = int(timeout_ms or self.timeout_ms)
        try:
            async with self._page() as page:
                try:
                    await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
                except Exception:  # noqa: BLE001 - 导航异常不阻断求值
                    pass
                try:
                    await page.wait_for_timeout(wait_ms)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    return await page.evaluate(expr)
                except Exception:  # noqa: BLE001 - 求值失败≠渲染故障
                    return ""
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"evaluate 渲染失败 {url}: {exc}")
            return None


async def open_render_session(headless: bool = True,
                              max_pages: int = _MAX_POOL_PAGES) -> Optional[RenderSession]:
    """便捷入口：启动并返回渲染会话；不可用时返回 None。"""
    session = RenderSession(headless=headless, max_pages=max_pages)
    if await session.start():
        return session
    return None


__all__ = [
    "RenderSession",
    "open_render_session",
    "render_available",
    "render_backend_name",
]
