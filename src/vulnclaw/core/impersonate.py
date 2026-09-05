# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

# core/impersonate.py
"""
SP16.2/SP17.3 TLS 指纹伪装通道（curl_cffi 可选后端，默认关）

SP16.2：aiohttp/httpx 默认 TLS（JA3/JA4）指纹是 Python 语境实现，商业 WAF
（Akamai/Cloudflare 级别）可一眼识别并拦截；红队工具主流做法是动态模拟真实
浏览器传输指纹（curl_cffi impersonate 会同时适配 JA3 指纹、HTTP/2 指纹与请求头顺序）。

SP17.3：在"单指纹"基础上升级为"指纹链"——
- 多浏览器轮换池 ImpersonatePool：按 settings.http_impersonate_pool 预建各 browser
  会话（懒加载，缺依赖跳过），next() 按 round-robin 返回下一个 browser 名 + 会话引用，
  带 hit/miss 计数实现"命中保持"（连续成功 hit_streak_keep 次沿用当前，失败切换）。
- HTTP2 指纹编排：http2_fingerprint() 返回当前（或指定）浏览器的 HTTP2 指纹概要
  （alpn_protocols / settings 顺序等说明性元数据）。curl_cffi 已内置浏览器指纹（JA3 /
  HTTP2 SETTINGS / HEADER ORDER），此处不手写 SETTINGS 帧，只把"显式编排"做成可配置、可查阅的输出。

- 开关：settings.http_impersonate（默认 False）+ http_impersonate_browser（默认 chrome）
           + http_impersonate_pool / http_impersonate_rotate / http_impersonate_http2（默认关/空池）
- 可用性：curl_cffi 可导入 且 开关打开，否则 impersonate_enabled() False（零行为回归）
- 接口：(status, text, headers) | None，与 core.utils.async_get / http_client.http2_get 兼容；
  调用方 scanner.py 不变（impersonate_get / impersonate_post 透出，池语义留在本模块内部）。
- 任一异常一律返回 None，由调用方回退既有通道（graceful degrade）
- 未安装 curl_cffi 不抛错、不提示噪音（同 http2 模块的 optional 模式）

纪律：无 emoji、轻量、异常优雅降级、线程安全。
"""
import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)

try:
    from curl_cffi.requests import AsyncSession
    CURL_CFFI_AVAILABLE = True
except Exception:  # noqa: BLE001 - 可选依赖缺失视为不可用
    AsyncSession = None  # type: ignore
    CURL_CFFI_AVAILABLE = False


def impersonate_enabled() -> bool:
    """TLS 伪装是否启用：curl_cffi 可用 且 settings.http_impersonate=True。"""
    if not CURL_CFFI_AVAILABLE:
        return False
    try:
        from vulnclaw.core.settings import settings
        return bool(getattr(settings, "http_impersonate", False))
    except Exception:  # noqa: BLE001
        return False


def _browser() -> str:
    try:
        from vulnclaw.core.settings import settings
        return str(getattr(settings, "http_impersonate_browser", "chrome") or "chrome")
    except Exception:  # noqa: BLE001
        return "chrome"


_impersonate_session: Any | None = None


async def _session() -> Any | None:
    """全局伪装会话单例（复用连接池；curl_cffi 内部管 TLS/代理）。"""
    global _impersonate_session
    if not CURL_CFFI_AVAILABLE or AsyncSession is None:
        return None
    current = _impersonate_session
    if current is not None and not getattr(current, "closed", True):
        return current
    try:
        sess = AsyncSession(impersonate=_browser())
        _impersonate_session = sess
        return sess
    except Exception:  # noqa: BLE001
        return None


def _make_async_session(browser: str) -> Any | None:
    """按浏览器名创建 curl_cffi 会话（缺依赖/异常返回 None，由池跳过）。"""
    if not CURL_CFFI_AVAILABLE or AsyncSession is None:
        return None
    try:
        return AsyncSession(impersonate=browser)
    except Exception:  # noqa: BLE001
        logger.debug("impersonate session build failed for %s", browser)
        return None


class ImpersonatePool:
    """多浏览器指纹轮换池（线程安全；懒加载会话，缺依赖跳过）。

    - next(): 按 round-robin 返回 (browser, session)；"命中保持"命中（连续成功
      hit_streak_keep 次）后沿用当前，失败（report(miss=True)）则切换。
    - report(miss): 请求结束回报命中/失败，驱动"命中保持"状态。
    - len==0：curl_cffi 缺失或池内浏览器全部构建失败时为空池（优雅降级不抛错）。
    """

    def __init__(
        self,
        browsers: list[str] | None = None,
        session_factory: Any | None = None,
        hit_streak_keep: int = 3,
    ):
        self._lock = threading.RLock()
        self._browsers = list(browsers or [])
        self._session_factory = session_factory or _make_async_session
        self._hit_streak_keep = max(1, int(hit_streak_keep))
        self._sessions: dict[str, Any] = {}
        self._order: list[str] = []
        self._index = -1
        self._current: str | None = None
        self._hits = 0
        self._misses = 0
        self._consecutive_hits = 0
        self._ready = False

    def _prebuild(self) -> None:
        if self._ready:
            return
        for b in self._browsers:
            try:
                sess = self._session_factory(b)
            except Exception:  # noqa: BLE001
                sess = None
            if sess is not None:
                self._sessions[b] = sess
                self._order.append(b)
        self._ready = True

    def _advance(self) -> None:
        if not self._order:
            self._current = None
            return
        self._index = (self._index + 1) % len(self._order)
        self._current = self._order[self._index]

    def next(self) -> tuple[str | None, Any | None]:
        """round-robin 返回 (browser, session)；命中保持时沿用当前。"""
        with self._lock:
            self._prebuild()
            if not self._order:
                return None, None
            if self._current is None or self._consecutive_hits < self._hit_streak_keep:
                self._advance()
            return self._current, self._sessions.get(self._current)

    def report(self, miss: bool = False) -> None:
        """请求结束回报：miss=True 记为失败（下次切换），否则累计连续命中。"""
        with self._lock:
            if miss:
                self._misses += 1
                self._consecutive_hits = 0
            else:
                self._hits += 1
                self._consecutive_hits += 1

    def add(self, browser: str, session: Any) -> None:
        """外部注入会话（供测试/运维预建）。"""
        with self._lock:
            if session is None:
                return
            self._sessions[browser] = session
            if browser not in self._order:
                self._browsers.append(browser)
                self._order.append(browser)

    def __len__(self) -> int:
        with self._lock:
            self._prebuild()
            return len(self._order)

    @property
    def hits(self) -> int:
        with self._lock:
            return self._hits

    @property
    def misses(self) -> int:
        with self._lock:
            return self._misses

    @property
    def current(self) -> str | None:
        with self._lock:
            return self._current


_pool_lock = threading.Lock()
_pool: ImpersonatePool | None = None


def get_impersonate_pool(force_new: bool = False) -> ImpersonatePool:
    """模块级指纹轮换池单例（懒加载；curl_cffi 缺失时空池 len==0）。"""
    global _pool
    with _pool_lock:
        if _pool is None or force_new:
            try:
                from vulnclaw.core.settings import settings
                browsers = list(getattr(settings, "http_impersonate_pool", None) or [])
            except Exception:  # noqa: BLE001
                browsers = ["chrome", "firefox", "safari"]
            _pool = ImpersonatePool(browsers=browsers)
        return _pool


async def _pick_session() -> tuple[Any | None, ImpersonatePool | None]:
    """按开关选取会话：rotate 开 → 池；否则单例会话（兼容 SP16.2 行为）。"""
    try:
        from vulnclaw.core.settings import settings
        rotating = bool(getattr(settings, "http_impersonate_rotate", False))
    except Exception:  # noqa: BLE001
        rotating = False
    if rotating:
        pool = get_impersonate_pool()
        _browser_name, sess = pool.next()
        return sess, pool
    sess = await _session()
    return sess, None


async def impersonate_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    params=None,
    data=None,
    json=None,
    cookies=None,
    timeout: float | None = None,
) -> tuple[int, str, dict[str, str]] | None:
    """伪装通道请求。返回 (status, text, headers) 或 None（不可用/异常→调用方降级）。"""
    sess, pool = await _pick_session()
    if sess is None:
        return None
    kwargs: dict[str, Any] = {"timeout": float(timeout) if timeout else 15.0}
    if params is not None:
        kwargs["params"] = params
    if headers is not None:
        kwargs["headers"] = headers
    if data is not None:
        kwargs["data"] = data
    if json is not None:
        kwargs["json"] = json
    if cookies is not None:
        kwargs["cookies"] = cookies
    try:
        resp = await sess.request(method, url, **kwargs)
        if pool is not None:
            pool.report(miss=False)
        return int(resp.status_code), str(resp.text), dict(resp.headers)
    except Exception:  # noqa: BLE001
        if pool is not None:
            pool.report(miss=True)
        return None


async def impersonate_get(
    url: str,
    session=None,
    headers: dict[str, str] | None = None,
    timeout: float | None = None,
    no_retry: bool = False,
    **kwargs: Any,
) -> tuple[int, str, dict[str, str]] | None:
    """伪装 GET，接口与 core.utils.async_get / http_client.http2_get 兼容。"""
    params = kwargs.pop("params", None)
    cookies = kwargs.pop("cookies", None)
    return await impersonate_request(
        "GET", url, headers=headers, params=params, cookies=cookies, timeout=timeout
    )


async def impersonate_post(
    url: str,
    data=None,
    json=None,
    session=None,
    headers: dict[str, str] | None = None,
    timeout: float | None = None,
    no_retry: bool = False,
    **kwargs: Any,
) -> tuple[int, str, dict[str, str]] | None:
    """伪装 POST，接口兼兼容 core.utils.async_post / http_client.http2_post。"""
    params = kwargs.pop("params", None)
    cookies = kwargs.pop("cookies", None)
    return await impersonate_request(
        "POST", url, headers=headers, params=params, data=data, json=json, cookies=cookies,
        timeout=timeout,
    )


def http2_fingerprint(browser: str | None = None) -> dict:
    """当前（或指定池内某浏览器）的 HTTP2 指纹概要（说明性元数据）。

    返回 dict；若 curl_cffi 不可用返回空 dict（优雅降级）。curl_cffi 已内置浏览器
    JA3 / HTTP2 SETTINGS / HEADER ORDER 指纹，此处不手写 SETTINGS 帧，仅提供
    "显式编排"层的可查阅输出。
    """
    if not CURL_CFFI_AVAILABLE or AsyncSession is None:
        logger.debug("http2_fingerprint: curl_cffi unavailable, return {}")
        return {}
    b = browser or _browser()
    return {
        "browser": b,
        "impersonate": b,
        "http2": True,
        "alpn_protocols": ["h2", "http/1.1"],
        "settings_note": (
            "HTTP2 SETTINGS / header order / pseudo-header order inherited from "
            "curl_cffi impersonation of {0}; explicit orchestration layer only, "
            "no hand-written SETTINGS frame".format(b)
        ),
    }


__all__ = [
    "CURL_CFFI_AVAILABLE",
    "ImpersonatePool",
    "get_impersonate_pool",
    "http2_fingerprint",
    "impersonate_enabled",
    "impersonate_get",
    "impersonate_post",
    "impersonate_request",
]
