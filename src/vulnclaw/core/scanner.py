# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/scanner.py
"""
扫描器核心工具模块 - 精简版
包含：引擎加载、safe_request（含状态码重试）、工具函数、错误收集器
"""
import asyncio
import importlib
import inspect
import json
import threading
import time
import aiohttp
import traceback
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.settings import settings
from vulnclaw.core.logger import logger
from vulnclaw.core_modules.cache import cache
from vulnclaw.core_modules.metrics import get_metrics
from vulnclaw.core.utils import (
    async_get, async_post
)

from vulnclaw.engines.auxiliary_engines import AntiScanDetector


# ============================================================
# 高危险路径列表（用于 info_leak 假阳性过滤）
# ============================================================
HIGH_RISK_PATHS = [
    '/.git/config', '/.git/HEAD', '/.git/index',
    '/.env', '/.env.local', '/.env.production', '/.env.development',
    '/wp-config.php', '/config.php', '/settings.inc.php',
    '/.aws/credentials', '/.aws/config',
    '/backup.sql', '/db_backup.sql', '/dump.sql',
    '/.ssh/id_rsa', '/.ssh/authorized_keys',
    '/etc/passwd', '/etc/shadow', '/etc/hosts',
    '/proc/self/environ', '/proc/self/cmdline',
    '/web.config', '/web.xml', '/appsettings.json',
    '/secrets.yml', '/secrets.yaml', '/credentials.json',
    '/composer.json', '/composer.lock', '/package.json',
    '/.htaccess', '/.htpasswd'
]


# ============================================================
# 引擎加载（单例，包含所有增强引擎）
# ============================================================
_ENGINES = None
_ENGINE_MAP = None
_ENGINES_LOCK = asyncio.Lock()        # P3-2: asyncio 环境并发安全
_ENGINES_THREAD_LOCK = threading.Lock()  # P3-2: 同步/线程池环境并发安全


def _do_load_engines():
    """实际扫描并加载 engines 目录下的引擎插件（调用方须持有锁）。"""
    global _ENGINES, _ENGINE_MAP
    from vulnclaw.engines.base import BaseEngine
    engines_dir = Path(__file__).parent.parent / "engines"
    engines = []

    for module_path in sorted(engines_dir.glob("*.py")):
        if module_path.name in {"__init__.py", "base.py"}:
            continue

        module_name = f"vulnclaw.engines.{module_path.stem}"
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:
            logger.warning(f"⚠️ 引擎模块加载失败 {module_path.name}: {exc}")
            continue

        for _, engine_class in inspect.getmembers(module, inspect.isclass):
            if engine_class is BaseEngine:
                continue
            if engine_class.__module__ != module.__name__:
                continue
            try:
                if not issubclass(engine_class, BaseEngine):
                    continue
            except TypeError:
                continue
            if not hasattr(engine_class, "name"):
                continue

            try:
                engine = engine_class()
            except Exception as exc:
                logger.warning(f"⚠️ 引擎实例化失败 {engine_class.__name__}: {exc}")
                continue
            if getattr(engine, "enabled", True) is False:
                continue

            on_load = getattr(engine, "on_load", None)
            if callable(on_load):
                on_load()

            engines.append(engine)
            logger.info(f"✅ 自动发现引擎: {engine.name}")

    _ENGINES = engines
    _ENGINE_MAP = {e.name: e for e in engines}
    logger.info(f"✅ 加载 {len(engines)} 个漏洞检测引擎")


def _load_engines():
    """同步版引擎加载（线程安全，可在事件循环线程中被同步调用）。"""
    if _ENGINES is not None:
        return _ENGINES, _ENGINE_MAP
    with _ENGINES_THREAD_LOCK:
        if _ENGINES is not None:
            return _ENGINES, _ENGINE_MAP
        _do_load_engines()
        return _ENGINES, _ENGINE_MAP


async def _load_engines_async():
    """P3-2: 异步版引擎加载（协程安全，asyncio.Lock 双检锁）。"""
    if _ENGINES is not None:
        return _ENGINES, _ENGINE_MAP
    async with _ENGINES_LOCK:
        if _ENGINES is not None:
            return _ENGINES, _ENGINE_MAP
        _do_load_engines()
        return _ENGINES, _ENGINE_MAP


def _build_cache_key(url: str, method: str, **kwargs) -> str:
    """为相同请求生成稳定的缓存 key，避免 session 等对象参与序列化。"""
    normalized = {"url": url, "method": method.upper()}
    for key, value in sorted(kwargs.items()):
        if key in {"session", "timeout", "allow_redirects", "no_retry"}:
            continue
        try:
            json.dumps(value)
            normalized[key] = value
        except (TypeError, ValueError):
            normalized[key] = repr(value)
    return json.dumps(normalized, sort_keys=True, ensure_ascii=False)


def get_engine_by_name(name: str):
    """根据名称获取单个引擎"""
    _, engine_map = _load_engines()
    return engine_map.get(name)


def get_all_engines():
    """获取所有引擎列表"""
    engines, _ = _load_engines()
    return engines


# ============================================================
# 错误收集器
# ============================================================
class ErrorCollector:
    def __init__(self):
        self.errors = []
        self.lock = asyncio.Lock()

    async def add(self, source: str, error: Exception, context: str = ""):
        async with self.lock:
            entry = {
                "source": source,
                "error": str(error),
                "traceback": traceback.format_exc(),
                "context": context,
                "timestamp": datetime.now().isoformat()
            }
            self.errors.append(entry)
            if "404" not in str(error) and "403" not in str(error):
                logger.error(f"❌ [{source}] {error}")
            if len(self.errors) > 100:
                self.errors.pop(0)

    def get_all(self) -> List[Dict]:
        return self.errors.copy()


_error_collector = ErrorCollector()


def get_error_collector() -> ErrorCollector:
    return _error_collector


# ============================================================
# safe_request（修复：状态码500重试）
# ============================================================
def _http2_available() -> bool:
    """HTTP/2 是否启用（httpx 可用 + settings.http2=True）。"""
    try:
        from vulnclaw.core.http_client import http2_enabled
        return http2_enabled()
    except Exception:
        return False


def _http2_request_api():
    """惰性导入 HTTP/2 请求函数；不可用时返回 (None, None)。"""
    try:
        from vulnclaw.core.http_client import http2_get, http2_post
        return http2_get, http2_post
    except Exception:
        return None, None


def _get_anti_adapter():
    """惰性获取 WAF 反检测策略适配器；不可用时返回 None。"""
    try:
        from vulnclaw.core.anti_detection import get_anti_detection
        return get_anti_detection()
    except Exception:
        return None


async def safe_request(
    url: str,
    session,
    method: str = "GET",
    timeout: int = None,
    **kwargs
) -> Optional[Tuple[int, str, Dict]]:
    """
    安全的 HTTP 请求
    修复：对 500+ 状态码进行重试，并在稳定响应上启用缓存
    返回: (status, text, headers) 或 None（严重错误时）
    """
    if timeout is None:
        timeout = settings.timeout

    cache_key = _build_cache_key(url, method, **kwargs)
    cached = cache.get(cache_key)
    if cached is not None:
        logger.debug(f"📦 safe_request cache hit: {url}")
        return tuple(cached)

    start_ts = time.monotonic()
    retry_count = 0
    max_retries = 3

    while retry_count <= max_retries:
        try:
            # P0-3：应用反检测策略（延迟 + 注入头）
            try:
                _adapter = _get_anti_adapter()
                if _adapter is not None:
                    _delay = _adapter.get_delay(url)
                    if _delay:
                        await asyncio.sleep(_delay)
                    _inject = _adapter.get_headers(url)
                    if _inject:
                        _hdrs = dict(kwargs.get("headers") or {})
                        _hdrs.update(_inject)
                        kwargs["headers"] = _hdrs
            except Exception:
                logger.debug("suppressed exception (core audit)")
            if method.upper() == "GET":
                if _http2_available():
                    _http2_get, _ = _http2_request_api()
                    resp = await _http2_get(url, session=session, timeout=timeout, **kwargs, allow_redirects=False)
                else:
                    resp = await async_get(url, session=session, timeout=timeout, no_retry=True, **kwargs, allow_redirects=False)
            elif method.upper() == "POST":
                if _http2_available():
                    _, _http2_post = _http2_request_api()
                    resp = await _http2_post(url, session=session, timeout=timeout, **kwargs)
                else:
                    resp = await async_post(url, session=session, timeout=timeout, no_retry=True, **kwargs)
            else:
                return None

            if isinstance(resp, tuple) and len(resp) >= 3:
                status, text, headers = resp[0], resp[1], resp[2]
            elif isinstance(resp, tuple) and len(resp) >= 2:
                status, text = resp[0], resp[1]
                headers = {}
            else:
                status = getattr(resp, 'status', 0)
                text = await resp.text() if hasattr(resp, 'text') else ""
                headers = dict(getattr(resp, 'headers', {}))

            # ===== Metrics 埋点：请求计数 + 响应时间 =====
            try:
                get_metrics().inc_request(method.upper(), int(status) if status is not None else 0)
                get_metrics().observe_response_time(time.monotonic() - start_ts)
            except Exception:
                logger.debug("suppressed exception (core audit)")

            # ===== 反制检测（警告模式） =====
            anti_result = AntiScanDetector.analyze_response(text, status, headers)

            if anti_result["is_honeypot"]:
                logger.warning(f"⚠️ [反制-警告] 疑似蜜罐: {url} - {anti_result['issues']}（继续扫描）")

            if anti_result["is_fake_404"]:
                logger.warning(f"⚠️ [反制-警告] 疑似假404: {url} - {anti_result['issues']}（继续扫描）")

            if anti_result["is_rate_limited"] or anti_result["is_ip_blocked"]:
                logger.warning(f"⚠️ [反制] 触发限流/封禁: {url} - {anti_result['issues']}")
                if retry_count < max_retries:
                    # P0-3：WAF 自适应策略链升级 + GET / 探测（200 即锁定）
                    _level_name = "none"
                    try:
                        _adapter = _get_anti_adapter()
                        if _adapter is not None:
                            _level_name = await _adapter.record_block(url)
                            await _adapter.probe(url, session)
                    except Exception:
                        logger.debug("suppressed exception (core audit)")
                    wait = min(2 ** retry_count * 3, 30)
                    logger.info(f"⏳ 反制等待 {wait}s 后重试（策略: {_level_name}，{retry_count + 1}/{max_retries}）")
                    await asyncio.sleep(wait)
                    retry_count += 1
                    continue
                else:
                    logger.warning(f"⚠️ 限流/封禁重试 {max_retries} 次失败，放弃请求")
                    return None

            # ===== 修复：状态码 500+ 重试 =====
            if status >= 500 and retry_count < max_retries:
                wait = min(2 ** retry_count * 2, 16)
                logger.info(f"⏳ 服务端错误 {status}，等待 {wait}s 后重试 ({retry_count + 1}/{max_retries})")
                await asyncio.sleep(wait)
                retry_count += 1
                continue

            if status < 500 and status not in (429, 408):
                # P0-3：成功响应 → 记录并锁定当前策略
                try:
                    _adapter = _get_anti_adapter()
                    if _adapter is not None:
                        await _adapter.record_success(url)
                except Exception:
                    logger.debug("suppressed exception (core audit)")
                try:
                    cache.set(cache_key, (status, text, headers), ttl=300)
                except Exception:
                    logger.debug("suppressed exception (core audit)")

            # 成功返回
            return status, text, headers

        except asyncio.TimeoutError:
            logger.debug(f"安全请求超时 {url} (尝试 {retry_count + 1}/{max_retries + 1})")
            if retry_count < max_retries:
                wait = min(2 ** retry_count * 2, 16)
                await asyncio.sleep(wait)
                retry_count += 1
                continue
            try:
                get_metrics().inc_engine_failure("http")
            except Exception:
                logger.debug("suppressed exception (core audit)")
            return None
        except aiohttp.ClientError as e:
            logger.debug(f"安全请求客户端错误 {url}: {e} (尝试 {retry_count + 1}/{max_retries + 1})")
            if retry_count < max_retries:
                await asyncio.sleep(1)
                retry_count += 1
                continue
            try:
                get_metrics().inc_engine_failure("http")
            except Exception:
                logger.debug("suppressed exception (core audit)")
            return None
        except Exception as e:
            logger.debug(f"安全请求失败 {url}: {e}")
            if retry_count < max_retries:
                await asyncio.sleep(1)
                retry_count += 1
                continue
            try:
                get_metrics().inc_engine_failure("http")
            except Exception:
                logger.debug("suppressed exception (core audit)")
            return None

    return None


# ============================================================
# 引擎辅助函数
# ============================================================
def get_engine_by_vuln_type(vuln_type: str):
    mapping = {
        "sqli": "sqli",
        "xss": "xss",
        "lfi": "lfi",
        "cmdi": "cmdi",
        "nosql": "nosql",
        "ssti": "ssti",
        "ssrf": "ssrf",
        "xxe": "xxe",
        "idor": "idor",
        "jwt": "jwt",
        "oauth": "oauth",
        "graphql": "graphql",
        "file_upload": "file_upload",
        "el_injection": "el_injection",
        "cors": "cors",
        "security_headers": "security_headers",
        "race_condition": "race_condition",
        "open_redirect": "open_redirect",
        "crlf": "crlf",
        "ldap": "ldap",
        "host_header": "host_header",
        "info_leak": "info_leak",
        "business_logic": "business_logic",
        "cache_poison": "cache_poison",
        "session": "session",
        "api_version_diff": "api_version_diff",
        "request_smuggling": "request_smuggling",
        "http2_ws": "http2_ws",
        "rfi": "rfi",
        "hpp": "hpp",
        "deserialization": "deserialization",
        "dotnet_deserialization": "dotnet_deserialization",
        "container_security": "container_security",
        "websocket_security": "websocket_security",
        "api_security": "api_security",
        "api_version": "api_version",
    }
    engine_name = mapping.get(vuln_type.lower())
    if engine_name:
        return get_engine_by_name(engine_name)
    return None


def get_engine_payloads(engine_name: str, param: str = None, max_count: int = 10) -> List:
    engine = get_engine_by_name(engine_name)
    if not engine:
        return []
    if hasattr(engine, 'get_payloads'):
        return engine.get_payloads(param, max_count)
    if hasattr(engine, 'payloads'):
        return engine.payloads[:max_count]
    return []


# ============================================================
# 资产价值评分（增强版）
# ============================================================
def score_asset_enhanced(
    url: str,
    status: int,
    content_type: str,
    content_length: int,
    tech_stack: List[str],
    headers: Dict,
    has_auth: bool = False,
    params: List[str] = None
) -> int:
    score = 0
    params = params or []

    if 200 <= status < 300:
        score += 15
    elif status in (401, 403):
        score += 20
    elif status == 404:
        score += 5
    else:
        score += 10

    tech_weights = {
        "spring": 30, "django": 25, "rails": 25,
        "wordpress": 20, "react": 15, "vue": 15,
        "cloudflare": 5, "aws": 20, "azure": 15,
        "php": 20, "java": 25, "nodejs": 20,
        "python": 20, "go": 15, "dotnet": 20
    }
    for tech in tech_stack:
        for key, weight in tech_weights.items():
            if key in tech.lower():
                score += weight
                break

    path_keywords = {
        "/api/": 30, "/admin/": 25, "/graphql": 30,
        "/login": 15, "/upload": 25, "/payment": 35,
        "/v1/": 20, "/v2/": 20, "/internal": 30,
        "/oauth": 25, "/auth": 20, "/callback": 20
    }
    url_lower = url.lower()
    for keyword, weight in path_keywords.items():
        if keyword in url_lower:
            score += weight

    score += min(len(params) * 3, 20)
    if has_auth:
        score += 25
    if "json" in content_type.lower():
        score += 15
    if "xml" in content_type.lower():
        score += 10
    if 1000 < content_length < 100000:
        score += 10

    return min(100, score)


# ============================================================
# 导出
# ============================================================
__all__ = [
    'get_engine_by_name',
    'get_all_engines',
    'get_engine_by_vuln_type',
    'get_engine_payloads',
    'get_error_collector',
    'score_asset_enhanced',
    'HIGH_RISK_PATHS',
    '_load_engines',
    'safe_request',
]
