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
from urllib.parse import urlparse

from vulnclaw.core.settings import settings
from vulnclaw.core.logger import logger, audit_suppressed
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
_ENGINE_INVENTORY = None
_ENGINES_LOCK = asyncio.Lock()        # P3-2: asyncio 环境并发安全
_ENGINES_THREAD_LOCK = threading.Lock()  # P3-2: 同步/线程池环境并发安全


def _do_load_engines():
    """实际扫描并加载 engines 目录下的引擎插件（调用方须持有锁）。"""
    global _ENGINES, _ENGINE_MAP, _ENGINE_INVENTORY
    from vulnclaw.engines.base import BaseEngine
    engines_dir = Path(__file__).parent.parent / "engines"
    engines = []
    discovered = []
    failed = []
    abstract = []

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
            name = str(getattr(engine_class, "name", engine_class.__name__))
            discovered.append(name)
            if inspect.isabstract(engine_class):
                abstract.append({"name": name, "class": engine_class.__name__})
                continue

            try:
                engine = engine_class()
            except Exception as exc:
                logger.warning(f"⚠️ 引擎实例化失败 {engine_class.__name__}: {exc}")
                failed.append({"name": name, "class": engine_class.__name__, "error": str(exc)})
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
    _ENGINE_INVENTORY = {
        "discovered": len(discovered),
        "instantiated": len(engines),
        "enabled": len(engines),
        "failed": failed,
        "abstract": abstract,
        "names": sorted(str(e.name) for e in engines),
    }
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


def get_engine_inventory() -> Dict:
    """返回单一事实源的引擎发现/实例化统计，供 health、报告和 CI 使用。"""
    _load_engines()
    return dict(_ENGINE_INVENTORY or {})


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
        # 自动成长-读取端（2026-09-15）：账本强误报指纹过滤（默认关零影响）。
        # 命中 (vuln_type, 归一化参数) 强误报签名的 finding 不进主链路；
        # 过滤失败静默放行，绝不因账本问题丢/改引擎原始检出。
        try:
            from vulnclaw.growth.bridges import suppress_findings
            _kept, _suppressed = suppress_findings(_out)
            if _suppressed:
                logger.info(f"growth: 抑制 {len(_suppressed)} 条强误报指纹 (engine={engine_name})")
                _out = _kept
        except Exception:  # noqa: BLE001
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


def _impersonate_available() -> bool:
    """TLS 伪装是否可用（curl_cffi 可用 + settings.http_impersonate=True）。"""
    try:
        from vulnclaw.core.impersonate import impersonate_enabled
        return impersonate_enabled()
    except Exception:  # noqa: BLE001
        return False


def _impersonate_request_api():
    """惰性导入伪装请求函数；不可用时返回 (None, None)。"""
    try:
        from vulnclaw.core.impersonate import impersonate_get, impersonate_post
        return impersonate_get, impersonate_post
    except Exception:  # noqa: BLE001
        return None, None


# 蜜罐消极区（2026-09-07）：同一主机连续命中 N 条蜜罐/假404 路径 => 该主机提前放弃
# 后续退避重试（Audible 类 SPA 大站字典路径全 200=蜜罐，逐条 3 次退避纯属空耗）。
# 任何非蜜罐响应都会重置计数，正常站不受影响。
_HONEYPOT_SLUMP: Dict[str, int] = {}


def _is_local_target(url: str) -> bool:
    """Keep local test/lab targets on the native aiohttp path.

    HTTP/2 and TLS impersonation clients are useful for remote targets, but
    they can route localhost requests through an incompatible transport or
    proxy. Local targets must remain deterministic for tests and local labs.
    """
    try:
        hostname = (urlparse(str(url)).hostname or "").lower()
    except ValueError:
        return False
    return hostname in {"localhost", "127.0.0.1", "::1"}


async def safe_request(
    url: str,
    session,
    method: str = "GET",
    timeout: int = None,
    js_crypto_context: Optional[dict] = None,
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
    local_target = _is_local_target(url)

    while retry_count <= max_retries:
        try:
            if method.upper() == "GET":
                if not local_target and _impersonate_available():
                    _imp_get, _ = _impersonate_request_api()
                    resp = await _imp_get(url, session=session, timeout=timeout, **kwargs, allow_redirects=False)
                elif not local_target and _http2_available():
                    _http2_get, _ = _http2_request_api()
                    resp = await _http2_get(url, session=session, timeout=timeout, **kwargs, allow_redirects=False)
                else:
                    resp = await async_get(url, session=session, timeout=timeout, no_retry=True, **kwargs, allow_redirects=False)
            elif method.upper() == "POST":
                if not local_target and _impersonate_available():
                    _, _imp_post = _impersonate_request_api()
                    resp = await _imp_post(url, session=session, timeout=timeout, **kwargs)
                elif not local_target and _http2_available():
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

            # ===== K.4 JS 加密参数还原（默认关闭；需显式传 js_crypto_context 才启用） =====
            if js_crypto_context is not None and text:
                try:
                    from vulnclaw.modules.js_crypto_restore import JSCryptoRestorer
                    js_crypto_context["crypto_points"] = JSCryptoRestorer().analyze(text)
                except Exception:
                    logger.debug("suppressed exception (js_crypto_restore)")

            # ===== Metrics 埋点：请求计数 + 响应时间 =====
            try:
                get_metrics().inc_request(method.upper(), int(status) if status is not None else 0)
                get_metrics().observe_response_time(time.monotonic() - start_ts)
            except Exception:
                audit_suppressed()

            # ===== 反制检测（警告模式） =====
            anti_result = AntiScanDetector.analyze_response(text, status, headers)

            if anti_result["is_honeypot"]:
                logger.warning(f"⚠️ [反制-警告] 疑似蜜罐: {url} - {anti_result['issues']}（继续扫描）")

            if anti_result["is_fake_404"]:
                logger.warning(f"⚠️ [反制-警告] 疑似假404: {url} - {anti_result['issues']}（继续扫描）")

            # 蜜罐消极计数（2026-09-07）：连续蜜罐/假404 => 该主机进入消极区
            if anti_result["is_honeypot"] or anti_result["is_fake_404"]:
                from urllib.parse import urlparse as _urp
                _hst = _urp(url).netloc or url
                # 自适应（2026-09-07）：强蜜罐特征（动态UUID/随机占位符）2 条即消极，
                # 弱特征用配置值（默认 3）；配置中更大值也封顶 3，防无限拖延。
                if any(("UUID" in _i or "占位符" in _i) for _i in (anti_result.get("issues") or [])):
                    _slump_th_ = min(int(getattr(settings, "anti_scan_honeypot_consecutive", 3) or 3), 2)
                else:
                    _slump_th_ = int(getattr(settings, "anti_scan_honeypot_consecutive", 3) or 3)
                _cnt = _HONEYPOT_SLUMP.get(_hst, 0) + 1
                _HONEYPOT_SLUMP[_hst] = _cnt
                if _cnt == _slump_th_:
                    logger.warning(f"🛑 蜜罐消极区: {_hst} 连续 {_cnt} 条蜜罐路径——后续对该主机直接放弃请求（大站防拖死）")
            else:
                from urllib.parse import urlparse as _urp2
                _HONEYPOT_SLUMP.pop(_urp2(url).netloc or url, None)

            if anti_result["is_rate_limited"] or anti_result["is_ip_blocked"]:
                logger.warning(f"⚠️ [反制] 触发限流/封禁: {url} - {anti_result['issues']}")
                from urllib.parse import urlparse as _urp3
                _hst3 = _urp3(url).netloc or url
                if _HONEYPOT_SLUMP.get(_hst3, 0) >= _slump_th_:
                    logger.info(f"🛑 蜜罐消极区生效: {url} 直接放弃（不再退避重试）")
                    return None
                if retry_count < max_retries:
                    from vulnclaw.config.settings import settings as _ast
                    wait = min(
                        float(getattr(_ast, "anti_scan_backoff_base", 3.0)) * (2 ** retry_count),
                        float(getattr(_ast, "anti_scan_backoff_max", 30.0)),
                    )
                    logger.info(f"⏳ 反制等待 {wait}s 后重试（{retry_count + 1}/{max_retries}）")
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
                try:
                    cache.set(cache_key, (status, text, headers), ttl=300)
                except Exception:
                    audit_suppressed()

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
                audit_suppressed()
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
                audit_suppressed()
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
                audit_suppressed()
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
    'get_engine_inventory',
    'get_engine_by_vuln_type',
    'get_engine_payloads',
    'get_error_collector',
    'score_asset_enhanced',
    'HIGH_RISK_PATHS',
    '_load_engines',
    'safe_request',
]
