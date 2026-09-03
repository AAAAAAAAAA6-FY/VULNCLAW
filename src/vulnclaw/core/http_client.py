# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/http_client.py
"""
HTTP 客户端单例管理 - 支持 HTTP/2（P0-1）

设计：
  - _SessionManager 单例：锁内双检，保证全局只有一个 httpx.AsyncClient（连接池复用）
  - httpx 可选后端：HTTP/2 优先；httpx 或 h2 未安装时 http2_enabled() 返回 False，调用方降级 aiohttp
  - 接口与 core.utils.async_get/async_post 兼容：(status, text, headers) 或 None

渐进式接入：
  - 默认关闭（settings.http2=False），仅 --http2 / env HTTP2=true 且依赖可用时启用
  - TLS 指纹与 aiohttp 不同，可能触发 WAF；故保持默认关闭，由用户显式开启
"""
import asyncio
from typing import Any, Dict, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings

try:
    import httpx
    import h2  # noqa: F401  （HTTP/2 协议库，httpx http2=True 依赖它）
    HTTPX_AVAILABLE = True
except ImportError:  # pragma: no cover
    httpx = None
    HTTPX_AVAILABLE = False
    logger.info("ℹ️  httpx[http2] 未安装，HTTP/2 不可用（pip install httpx[http2] 可启用）")


class ScopeGuardError(Exception):
    """E5.1: 请求超出 allowed_scope 白名单，被 HTTP 客户端层硬拦截。"""


def parse_scope() -> list:
    """解析 allowed_scope（逗号分隔条目：域名 / *.通配域 / CIDR / 精确 IP）。"""
    raw = str(getattr(settings, "allowed_scope", "") or "")
    return [s.strip() for s in raw.split(",") if s.strip()]


def url_in_scope(url: str, scope_entries=None) -> bool:
    """越界判断：scope 未配置时放行（兼容旧行为）；配置后仅白名单命中才放行。

    域名规则：entry 命中自身与其所有子域（evil-example.com 不会被 example.com 命中；
    *.example.com 与 example.com 行为一致，.*为显式通配写法）。
    """
    if scope_entries is None:
        scope_entries = parse_scope()
    if not scope_entries:
        return True
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
    except Exception:  # noqa: BLE001
        return True
    if not host:
        return True
    import ipaddress as _ia
    for entry in scope_entries:
        if not entry:
            continue
        if "/" in entry and _looks_like_cidr(entry, host):
            try:
                return _ia.ip_address(host) in _ia.ip_network(entry, strict=False)
            except ValueError:
                continue
        base = entry[2:] if entry.startswith("*.") else entry
        if host == base or host.endswith("." + base):
            return True
    return False


def _looks_like_cidr(entry: str, host: str) -> bool:
    """entry 形如 10.0.0.0/8 时按 CIDR 处理；若是域+斜杠路径则按域匹配。"""
    try:
        import ipaddress as _ia
        _ia.ip_address(host)
    except ValueError:
        return False
    return True


async def _scope_guard(request) -> None:
    """httpx event_hooks.request 守卫：白名单外的请求直接 raise 拦截（不可被 LLM 绕过）。"""
    if not getattr(settings, "allowed_scope", ""):
        return
    url = str(request.url)
    if not url.startswith(("http://", "https://")):
        return
    if not url_in_scope(url):
        raise ScopeGuardError(f"E5 越界请求被 HTTP 客户端层拦截（超出 allowed_scope）: {url}")


class _SessionManager:
    """httpx.AsyncClient 单例：锁内双检，避免并发重建连接。"""

    def __init__(self) -> None:
        self._client: Optional[Any] = None
        self._lock = asyncio.Lock()
        self._last_target: Optional[str] = None

    async def get_client(self, target: Optional[str] = None) -> Any:
        # fast path：已就绪则无锁直返
        if self._client is not None and not self._client.is_closed:
            return self._client
        async with self._lock:
            if self._client is None or self._client.is_closed:
                headers = {"User-Agent": settings.user_agent}
                limits = httpx.Limits(
                    max_connections=200,
                    max_keepalive_connections=40,
                )
                timeout = httpx.Timeout(
                    connect=15,
                    read=settings.timeout,
                    write=30,
                    pool=30,
                )
                self._client = httpx.AsyncClient(
                    http2=True,
                    verify=False,  # 与 aiohttp ssl=False 保持一致
                    headers=headers,
                    limits=limits,
                    timeout=timeout,
                    event_hooks=({"request": [_scope_guard]},),
                )
                self._last_target = target
                logger.info("🚀 HTTP/2 客户端已初始化（httpx + 连接池）")
            return self._client

    async def close(self) -> None:
        async with self._lock:
            if self._client is not None and not self._client.is_closed:
                await self._client.aclose()
            self._client = None
            logger.info("🛑 HTTP/2 客户端已关闭")


_session_manager = _SessionManager()


def http2_enabled() -> bool:
    """HTTP/2 是否启用：需要 httpx+h2 可用 且 settings.http2=True。"""
    return bool(HTTPX_AVAILABLE and getattr(settings, "http2", False))


def get_http2_manager() -> _SessionManager:
    """获取 HTTP/2 会话管理器单例。"""
    return _session_manager


async def http2_get(
    url: str,
    session=None,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    no_retry: bool = False,
    **kwargs: Any,
) -> Optional[Tuple[int, str, Dict[str, str]]]:
    """httpx GET，返回 (status, text, headers)，与 core.utils.async_get 兼容。"""
    return await _http2_request("GET", url, headers=headers, timeout=timeout, **kwargs)


async def http2_post(
    url: str,
    data=None,
    json=None,
    session=None,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    no_retry: bool = False,
    **kwargs: Any,
) -> Optional[Tuple[int, str, Dict[str, str]]]:
    """httpx POST，返回 (status, text, headers)，与 core.utils.async_post 兼容。"""
    return await _http2_request("POST", url, data=data, json=json, headers=headers, timeout=timeout, **kwargs)


async def _http2_request(
    method: str,
    url: str,
    data=None,
    json=None,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    **kwargs: Any,
) -> Optional[Tuple[int, str, Dict[str, str]]]:
    if not HTTPX_AVAILABLE:
        return None
    client = await _session_manager.get_client(url)
    # aiohttp -> httpx 参数映射
    redirect = bool(kwargs.pop("allow_redirects", True))
    req_kwargs: Dict[str, Any] = {"headers": headers or None}
    if data is not None:
        req_kwargs["data"] = data
    if json is not None:
        req_kwargs["json"] = json
    if "params" in kwargs:
        req_kwargs["params"] = kwargs.pop("params")
    if "cookies" in kwargs:
        req_kwargs["cookies"] = kwargs.pop("cookies")
    if "auth" in kwargs:
        req_kwargs["auth"] = kwargs.pop("auth")
    try:
        resp = await client.request(method, url, follow_redirects=redirect, **req_kwargs)
        return resp.status_code, resp.text, dict(resp.headers)
    except (httpx.TimeoutException, httpx.HTTPError) as exc:
        logger.debug(f"HTTP/2 {method} 请求错误 {url}: {exc}")
        return None
    except Exception as exc:  # 兜底：任何异常都返回 None，由调用方回退 aiohttp
        logger.debug(f"HTTP/2 {method} 请求异常 {url}: {exc}")
        return None


__all__ = [
    "HTTPX_AVAILABLE",
    "http2_enabled",
    "http2_get",
    "http2_post",
    "get_http2_manager",
]
