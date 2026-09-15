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
import fnmatch
import ipaddress
import os
import socket
import threading
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

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


# ============================================================
# 出站白名单 + 平台级 SSRF/DNS-rebinding 防护（工作流8）
#   三类防护默认均为 off，绝不改变现有扫描行为。
# ============================================================

# 压缩炸弹阈值（模块级，可用环境变量覆盖）
MAX_RESPONSE_BYTES = int(os.environ.get("MAX_RESPONSE_BYTES", str(64 * 1024 * 1024)))
MAX_COMPRESSION_RATIO = int(os.environ.get("MAX_COMPRESSION_RATIO", "1000"))


class EgressBlockError(Exception):
    """出站 host 不在 EGRESS_ALLOWLIST 白名单内，被 HTTP 客户端层拦截。"""


class SSRFGuardError(Exception):
    """平台级 SSRF / DNS-rebinding 防护拦截。"""


# DNS-rebinding 记录：host -> 首次解析的 IP 元组
_resolve_lock = threading.Lock()
_first_resolved: Dict[str, Tuple[str, ...]] = {}


def _parse_host(url: str) -> str:
    try:
        host = (urlparse(url).hostname or "").strip().lower()
        return host.lstrip("[").rstrip("]") if host else ""
    except Exception:  # noqa: BLE001
        return ""


def check_egress(url: str) -> None:
    """出站白名单：EGRESS_ALLOWLIST 非空且 host 不匹配 → 拒绝（记 warning）。

    默认（配置为空）放行一切，保持现有扫描行为。
    """
    raw = str(getattr(settings, "egress_allowlist", "") or "").strip()
    entries = [e.strip() for e in raw.split(",") if e.strip()]
    if not entries:
        return  # 默认放开
    if not url.lower().startswith(("http://", "https://")):
        return
    host = _parse_host(url)
    if not host:
        return
    for entry in entries:
        if fnmatch.fnmatch(host, entry):
            return
    logger.warning(f"🛡️ 出站白名单拦截（EGRESS_ALLOWLIST）: {url}")
    raise EgressBlockError(f"出站 host 不在 EGRESS_ALLOWLIST 内: {host}")


def _parse_allow_networks(allow_raw: str) -> list:
    nets = []
    for a in [x.strip() for x in allow_raw.split(",") if x.strip()]:
        try:
            nets.append(ipaddress.ip_network(a, strict=False))
        except ValueError:
            try:
                nets.append(ipaddress.ip_network(a))
            except ValueError:
                continue
    return nets


def _is_restricted_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local


def check_ssrf(url: str) -> None:
    """平台级 SSRF/DNS-rebinding 防护：SSRF_GUARD=1 时启用。

    - 解析 host → 对每个解析 IP 判定 loopback/private/link-local，不在 SSRF_ALLOW_PRIVATE 内即拒绝。
    - DNS-rebinding：记录首次解析 IP，重解析不一致 → 拒绝。
    默认（SSRF_GUARD != "1"）关闭，保持现有行为。
    """
    if str(getattr(settings, "ssrf_guard", "0") or "") != "1":
        return  # 默认关闭
    if not url.lower().startswith(("http://", "https://")):
        return
    host = _parse_host(url)
    if not host:
        return
    allow_nets = _parse_allow_networks(str(getattr(settings, "ssrf_allow_private", "") or ""))
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return  # 解析失败放行，交由连接层处理
    ips: list = []
    for res in infos:
        addr = str(res[4][0])
        if addr not in ips:
            ips.append(addr)
    # DNS-rebinding 一致性
    cur = tuple(ips)
    with _resolve_lock:
        prev = _first_resolved.get(host)
        if prev is None:
            _first_resolved[host] = cur
        elif cur != prev:
            logger.warning(f"🛡️ DNS-rebinding 检测（{host} 解析结果变化），已拒绝: {url}")
            raise SSRFGuardError(f"DNS-rebinding: {host} 解析结果不一致")
    # 私网判定
    for ip in ips:
        if _is_restricted_ip(ip) and not any(
            ipaddress.ip_address(ip) in n for n in allow_nets
        ):
            logger.warning(f"🛡️ SSRF 防护拦截私网地址 {ip}（不在 SSRF_ALLOW_PRIVATE 内）: {url}")
            raise SSRFGuardError(f"SSRF: {host} 解析到受保护地址 {ip}")


def _read_response_body(resp) -> bytes:
    """读取响应体并施加压缩炸弹/超大响应防护（单一执行点收口）。

    规则：
      1. Content-Length 头超上限 → 直接拒绝（记 warning，返回空）。
      2. 压缩类 content-encoding（gzip/deflate/br）解压后校验最终字节数上限，
         并以 Content-Length（压缩尺寸代理）计算压缩比：超限 → 截断到上限 + warning。
      3. 阈值内与原 resp.text 行为一致（不影响正常响应）。
    """
    headers = getattr(resp, "headers", None) or {}
    content_length = None
    if hasattr(headers, "get"):
        try:
            cl = headers.get("Content-Length")
            if cl:
                content_length = int(str(cl))
        except (TypeError, ValueError):
            content_length = None
    # 规则 1：Content-Length 已超上限 → 拒绝读取
    if content_length is not None and content_length > MAX_RESPONSE_BYTES:
        logger.warning(
            f"⚠️ 响应 Content-Length={content_length} 超过上限 {MAX_RESPONSE_BYTES} 字节，已拒绝读取"
        )
        return b""
    body = resp.content  # httpx 已自动解压 gzip/deflate/br
    if not isinstance(body, bytes):
        body = bytes(body or b"")
    if len(body) > MAX_RESPONSE_BYTES:
        logger.warning(f"⚠️ 响应体 {len(body)} 字节超过上限 {MAX_RESPONSE_BYTES}，已截断")
        return body[:MAX_RESPONSE_BYTES]
    # 规则 2：压缩类编码解压后校验压缩比
    enc = (headers.get("Content-Encoding") or "").lower() if hasattr(headers, "get") else ""
    if enc in ("gzip", "deflate", "br") and content_length:
        ratio = len(body) / max(content_length, 1)
        if ratio > MAX_COMPRESSION_RATIO:
            logger.warning(
                f"⚠️ 响应压缩比 {ratio:.0f}x 超过上限 {MAX_COMPRESSION_RATIO}x，已截断到 "
                f"{MAX_RESPONSE_BYTES} 字节"
            )
            return body[:MAX_RESPONSE_BYTES]
    return body


def _decode_body(body: bytes) -> str:
    try:
        return body.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return str(body)


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
                    event_hooks={"request": [_scope_guard]},
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
        check_egress(url)  # 出站白名单（EGRESS_ALLOWLIST 非空才启用）
        check_ssrf(url)  # 平台级 SSRF/DNS-rebinding（SSRF_GUARD=1 才启用）
        resp = await client.request(method, url, follow_redirects=redirect, **req_kwargs)
        raw_body = _read_response_body(resp)  # 压缩炸弹/超大响应防护
        return resp.status_code, _decode_body(raw_body), dict(resp.headers)
    except (EgressBlockError, SSRFGuardError) as exc:
        logger.warning(f"出站安全防护拦截请求 {url}: {exc}")
        return None
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
    "check_egress",
    "check_ssrf",
    "EgressBlockError",
    "SSRFGuardError",
    "MAX_RESPONSE_BYTES",
    "MAX_COMPRESSION_RATIO",
]
