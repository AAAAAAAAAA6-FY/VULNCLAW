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


def engine_capability(engine) -> tuple:
    """P0-1: 判定引擎暴露的能力入口。

    返回 (has_scan, has_check)：
      - has_scan  : 重写了目标级 `scan(target, session, **kwargs)`
      - has_check : 重写了参数级 `check(url, param, normal_resp, parsed_query, session, **kwargs)`
    """
    from vulnclaw.engines.base import BaseEngine
    return (
        type(engine).scan is not BaseEngine.scan,
        type(engine).check is not BaseEngine.check,
    )


# ============================================================
# SP7: 逐引擎参数 schema（OpenAPI 式输入定义，签名自动同步）
# ============================================================
_ENGINE_PARAM_PINNED = {
    "self", "url", "param", "normal_resp", "parsed_query", "session", "target",
}


def engine_param_schema(engine) -> Dict:
    """SP7: 从引擎能力与签名自动推导 OpenAPI 式入参 schema。

    - scan 能力 → 必填 target；check 能力 → 必填 url+param；
    - 引擎在具体 scan()/check() 上显式声明的额外具名参数自动爬入
      （带默认值 → optional；无默认 → required，MCP 调用方缺它会报错）；
    - 每次调用实时取自签名 —— 引擎签名变更即自动同步，无需人工维护。
    """
    has_scan, has_check = engine_capability(engine)
    params: Dict[str, Dict] = {}
    if has_scan:
        params["target"] = {
            "type": "string", "description": "目标地址（域名/IP/URL）。", "required": True,
            "default": None,
        }
    if has_check:
        params["url"] = {
            "type": "string", "description": "完整测试 URL（含 query 串）。", "required": True,
            "default": None,
        }
        params["param"] = {
            "type": "string", "description": "被测查询参数名。", "required": True,
            "default": None,
        }
    if not has_scan:
        params.setdefault("target", {
            "type": "string", "description": "目标域名（check 链路 OOB/上下文用）。",
            "required": False, "default": None,
        })
    for attr, enabled in (("scan", has_scan), ("check", has_check)):
        if not enabled:
            continue
        try:
            sig = inspect.signature(getattr(type(engine), attr))
        except (TypeError, ValueError):
            continue
        for pname, pp in sig.parameters.items():
            if pname in _ENGINE_PARAM_PINNED:
                continue
            if pp.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                continue
            if pname in params:
                continue
            params[pname] = {
                "type": "string",
                "description": f"{attr}() 具名参数（签名自动同步）。",
                "required": pp.default is inspect.Parameter.empty,
                "default": None if pp.default is inspect.Parameter.empty else pp.default,
            }
    required = [n for n, v in params.items() if v.get("required")]
    return {
        "type": "object",
        "properties": params,
        "required": required,
    }


# ============================================================



async def run_engine(engine_name, target=None, url=None, param=None, session=None, **kwargs):
    """P0-1: 统一引擎调用适配层（供 MCP / 多智能体调度复用）。

    自动按引擎能力选择 scan（目标级）或 check（参数级）入口：
      - 有 scan 覆盖 → engine.scan(target, session, **kwargs)
      - 仅 check   → 拉取基线后 engine.check(url, param, normal_resp, parsed_query, session, **kwargs)
    返回 findings 列表（可能为空）。session 由调用方传入时复用，否则内部创建并关闭。
    """
    engine = get_engine_by_name(engine_name)
    if engine is None:
        raise ValueError(f"引擎不存在: {engine_name}")

    if not target and url:
        target = url
    if not target:
        raise ValueError("run_engine 需要 target 或 url")
    if not str(target).startswith(("http://", "https://")):
        target = "https://" + str(target)

    has_scan, has_check = engine_capability(engine)
    own_session = session is None
    if own_session:
        from vulnclaw.core.utils import get_shared_session, close_shared_session
        session = await get_shared_session(target=target)
    # P4-2: 机器事实覆盖账本（旁路记账，异常零传播——绝不影响引擎执行语义）
    try:
        from vulnclaw.core.coverage import get_coverage_ledger
        _ledger = get_coverage_ledger(target=str(target))
    except Exception:
        _ledger = None
    _asset = str(url or target)
    try:
        if has_scan:
            _out = (await engine.scan(target, session, **kwargs)) or []
        elif has_check and param:
            from urllib.parse import urlparse
            normal_resp = await engine._get_normal_response(url or target, session)
            parsed_query = urlparse(url or target).query
            _result = await engine.check(url or target, param, normal_resp, parsed_query, session, **kwargs)
            _out = [_result] if _result else []
        else:
            if _ledger is not None:
                try:
                    _ledger.record_skipped(_asset, engine_name,
                                           f"no_entry(scan={has_scan},check={has_check},param={bool(param)})")
                except Exception:
                    pass
            raise ValueError(
                f"引擎 {engine_name} 无可用入口（scan={has_scan}, check={has_check}, param={bool(param)}）"
            )
        if _ledger is not None:
            try:
                _ledger.record_run(_asset, engine_name,
                                   findings=len(_out) if isinstance(_out, list) else 0)
            except Exception:
                pass
        return _out
    except Exception as e:
        if _ledger is not None and not isinstance(e, ValueError):
            try:
                _ledger.record_failed(_asset, engine_name, str(e)[:200])
            except Exception:
                pass
        raise
    finally:
        if own_session:
            from vulnclaw.core.utils import close_shared_session
            await close_shared_session()


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

            # ===== N2 修复：5xx 直接返回，不再退避重试 =====
            # 对安全扫描器而言 5xx 是**判定信号**而非瞬时故障：报错型注入（error-based）
            # 本就以 500 + 数据库错误页呈现，调用方（如 web_engines SQLi 攻击响应处理）
            # 恰恰需要这个 500 响应体去匹配 SQL 报错短语。
            # 旧逻辑对每个 500 退避重试 3 轮（2s/4s/8s ≈ 14s 每请求），而
            # probe_param / ab_verify 等引擎链路全部走 safe_request，导致 SQLi 全量
            # 检测累计耗时 74~114s，撞上编排层 asyncio.wait_for(timeout=120) 预算被杀
            # → 静默 return None（N2：SQLi 生产链路漏报根因）。
            # 附带收益：不再把同一攻击载荷重复发送给目标最多 4 次。
            if status >= 500:
                logger.debug(f"5xx 响应直接返回（不重试）: HTTP {status} {url}")

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
