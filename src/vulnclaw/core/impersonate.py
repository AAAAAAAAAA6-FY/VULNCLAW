# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

# core/impersonate.py
"""
SP16.2 TLS 指纹伪装通道（curl_cffi 可选后端，默认关）

痛点对照：aiohttp/httpx 默认 TLS（JA3/JA4）指纹是 Python 语境实现，
商业 WAF（Akamai/Cloudflare 级别）可一眼识别并拦截；红队工具主流做法是
动态模拟真实浏览器传输指纹（curl_cffi impersonate 会同时适配 JA3 指纹、
HTTP/2 指纹与请求头顺序）。

- 开关：settings.http_impersonate（默认 False）+ http_impersonate_browser（默认 chrome）
- 可用性：curl_cffi 可导入 且 开关打开，否则 impersonate_enabled() False（零行为回归）
- 接口：(status, text, headers) | None，与 core.utils.async_get / http_client.http2_get 兼容
- 任一异常一律返回 None，由调用方回退既有通道（graceful degrade）
- 未安装 curl_cffi 不抛错、不提示噪音（同 http2 模块的 optional 模式）

纪律：无 emoji、轻量、异常优雅降级。
"""
from typing import Any

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
    sess = await _session()
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
        return int(resp.status_code), str(resp.text), dict(resp.headers)
    except Exception:  # noqa: BLE001
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


__all__ = [
    "CURL_CFFI_AVAILABLE",
    "impersonate_enabled",
    "impersonate_get",
    "impersonate_post",
    "impersonate_request",
]