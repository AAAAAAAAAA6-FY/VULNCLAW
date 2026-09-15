# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/utils.py
"""
统一工具函数模块 - 精简版
"""
import os
import sys
import json
import random
import asyncio
import aiohttp
import shutil
import socket
import re
import platform
import urllib.parse
from pathlib import Path
from functools import lru_cache
from yarl import URL

from vulnclaw.core.settings import settings, PROJECT_CACHE_DIR  # 修改：导入 PROJECT_CACHE_DIR
from vulnclaw.core.logger import logger
from typing import Dict, List, Optional, Tuple, Union

MAX_RESPONSE_SIZE = settings.max_response_size_mb * 1024 * 1024

# 响应体分块读取的单块大小（见 _read_capped：aiohttp read(n) 不保证读满 n）
_READ_CHUNK = 65536

_SHARED_SESSION: Optional[aiohttp.ClientSession] = None
_SHARED_SESSION_LOCK = asyncio.Lock()
_LAST_TARGET: Optional[str] = None

# 漏洞大类映射：早停机制按“大类”而非整参数生效，
# 避免同参数上 XSS 被确认后把 SQLi/SSTI/LFI/CMDi 等正交漏洞大类一并误杀。
_VULN_CATEGORY_RULES = (
    ('xss', 'xss'),
    ('sqli', 'sqli'), ('sql注入', 'sqli'),
    ('ssti', 'ssti'), ('模板', 'ssti'), ('el_injection', 'ssti'), ('ssi', 'ssti'),
    ('lfi', 'lfi'), ('path_traversal', 'lfi'), ('traversal', 'lfi'),
    ('文件包含', 'lfi'), ('file_include', 'lfi'),
    ('cmdi', 'cmdi'), ('command', 'cmdi'), ('rce', 'cmdi'), ('命令', 'cmdi'),
    ('nosql', 'nosql'),
    ('ldap', 'ldap'),
    ('ssrf', 'ssrf'),
    ('xxe', 'xxe'),
    ('deser', 'deser'), ('反序列化', 'deser'), ('fastjson', 'deser'), ('jackson', 'deser'),
    ('redirect', 'redirect'), ('开放重定向', 'redirect'),
    ('cors', 'cors'),
    ('leak', 'info'), ('泄露', 'info'), ('info', 'info'),
)


def vuln_category(name: str) -> str:
    """将引擎名/漏洞类型归到粗略大类，供早停时不跨类互相阻塞。"""
    n = (name or '').lower()
    for needle, cat in _VULN_CATEGORY_RULES:
        if needle in n:
            return cat
    return 'misc'


# ============================================================
# 文件锁（用于跨进程写入保护）
# ============================================================
try:
    import portalocker
    HAS_PORTALOCKER = True
except ImportError:
    HAS_PORTALOCKER = False
    logger.debug("⚠️ portalocker 未安装，文件写入无跨进程锁保护。安装: pip install portalocker")


# ============================================================
# Cookie 文件路径管理（修改：统一存于 _runtime_cache/cookies/）
# ============================================================
COOKIE_DIR = Path(PROJECT_CACHE_DIR) / "cookies"

def _get_cookie_file_path(domain: str) -> Path:
    """获取目标专属的 Cookie 文件路径"""
    COOKIE_DIR.mkdir(parents=True, exist_ok=True)
    return COOKIE_DIR / f"{domain}.json"


# ============================================================
# Cookie 静态加密（防磁盘明文泄露；Windows DPAPI，跨平台优雅降级）
# ============================================================
# 落盘的登录态是高价值目标：明文 cookie 文件一旦被同机进程/备份读取即等于
# 会话泄露。Windows 用 DPAPI（当前用户密钥，无需自管密钥）加密；非 Windows
# 或加密失败保持明文（兼容优先），由调用方日志提示。
_COOKIE_ENVELOPE_KEY = "__vulnclaw_encrypted__"


def _dpapi(data: bytes, protect: bool) -> Optional[bytes]:
    """Windows DPAPI 加/解密（当前用户范围）；非 Windows/失败返回 None。"""
    if platform.system() != "Windows":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class _BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD),
                        ("pbData", ctypes.POINTER(ctypes.c_char))]

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        _buf = ctypes.create_string_buffer(data, len(data))
        blob_in = _BLOB(len(data), ctypes.cast(_buf, ctypes.POINTER(ctypes.c_char)))
        blob_out = _BLOB()
        _fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
        if not _fn(ctypes.byref(blob_in), None, None, None, None, 0,
                   ctypes.byref(blob_out)):
            return None
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32.LocalFree(blob_out.pbData)
    except Exception:  # noqa: BLE001
        return None


def encode_cookie_store(data: Dict) -> Dict:
    """把 cookie 字典编码为落盘形态（Windows: DPAPI 密文信封；其余原样）。"""
    try:
        import base64
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        sealed = _dpapi(raw, protect=True)
        if sealed:
            return {_COOKIE_ENVELOPE_KEY: base64.b64encode(sealed).decode("ascii")}
    except Exception:  # noqa: BLE001
        logger.debug("suppressed exception (cookie encrypt)")
    return data


def decode_cookie_store(data) -> Dict:
    """解码落盘 cookie 形态：密文信封自动解密；明文（历史/非 Windows）原样返回。"""
    if not isinstance(data, dict):
        return {}
    sealed = data.get(_COOKIE_ENVELOPE_KEY)
    if not isinstance(sealed, str) or len(data) != 1:
        return data
    try:
        import base64
        raw = _dpapi(base64.b64decode(sealed), protect=False)
        if raw is None:
            logger.warning("⚠️ Cookie 密文解密失败（非本机/非当前用户？），忽略该文件")
            return {}
        parsed = json.loads(raw.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else {}
    except Exception as e:  # noqa: BLE001
        logger.warning(f"⚠️ Cookie 密文解析失败: {e}")
        return {}


def _atomic_write_json(file_path: Path, data: Dict) -> bool:
    """原子写入 JSON 文件：先写 .tmp，再 rename；自动创建备份。"""
    try:
        # 唯一 tmp 名（含 PID）：多进程并发写同一文件时不抢同一 tmp，
        # 避免 Windows 上 os.replace 前 tmp 被他人占用导致 WinError 32。
        tmp_path = file_path.with_name(f"{file_path.name}.{os.getpid()}.tmp")
        bak_path = file_path.with_suffix('.json.bak')
        # 先备份现有文件（如果存在）
        if file_path.exists():
            try:
                shutil.copy2(file_path, bak_path)
            except Exception:
                logger.debug("suppressed exception (core audit)")
        # 写入临时文件
        with open(tmp_path, 'w', encoding='utf-8') as f:
            if HAS_PORTALOCKER:
                try:
                    portalocker.lock(f, portalocker.LOCK_EX)
                    json.dump(data, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())
                    portalocker.unlock(f)
                except Exception:
                    # portalocker.unlock 异常时 flush+fsync 仍已完成，fallback 不丢失
                    try:
                        f.flush()
                        os.fsync(f.fileno())
                    except Exception:
                        logger.debug("suppressed exception (core audit)")
            else:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
        # 原子替换
        tmp_path.replace(file_path)
        return True
    except Exception as e:
        logger.error(f"原子写入失败: {e}")
        # 尝试从备份恢复
        try:
            bak_path = Path(str(file_path) + '.bak') if file_path.suffix != '.bak' else file_path.with_suffix('.json.bak')
            if bak_path.exists():
                shutil.copy2(bak_path, file_path)
        except Exception:
            logger.debug("suppressed exception (core audit)")
        return False


# ============================================================
# 共享会话管理
# ============================================================
async def get_shared_session(target: Optional[str] = None) -> aiohttp.ClientSession:
    """创建或返回共享的 aiohttp ClientSession，支持动态更新Cookie。

    性能优化（瓶颈2）：
      - 默认 fast-path：_SHARED_SESSION 已就绪且 target 未变化 -> 无锁直返，
        避免每条 HTTP 调用都串行排队在同一个 asyncio.Lock 上。
      - 懒初始化 / 切 target / 会话关闭：在 lock 保护内双检后再操作，
        保证并发下仍只生成一个 ClientSession。
      - connector 使用更大的 TCP 连接池 & keepalive 复用，避免每次握手。
    """
    global _SHARED_SESSION, _LAST_TARGET

    # reuse_shared_session=False 时禁止会话复用：关闭并置空，强制每次新建
    if not settings.reuse_shared_session and _SHARED_SESSION is not None:
        if not _SHARED_SESSION.closed:
            await _SHARED_SESSION.close()
        _SHARED_SESSION = None
        _LAST_TARGET = None

    # --- fast path: 绝大多数请求走这里，零锁等待 ---
    if (
        target is None
        and _SHARED_SESSION is not None
        and not _SHARED_SESSION.closed
    ):
        return _SHARED_SESSION

    # --- slow path: 初始化 / 切 target / 重启 closed session ---
    async with _SHARED_SESSION_LOCK:
        # 双检：避免多个并发任务同时穿过 fast path 后重复新建 session
        if target and target != _LAST_TARGET and _SHARED_SESSION is not None:
            if not _SHARED_SESSION.closed:
                await _SHARED_SESSION.close()
            _SHARED_SESSION = None
            _LAST_TARGET = None

        if _SHARED_SESSION is None or _SHARED_SESSION.closed:
            # 连接池：瓶颈2 关键调参
            #   limit=200          全局并发连接（默认100太小，扫描场景明显不够）
            #   limit_per_host=40  单主机并发（之前 30，调大以配合 semaphore 并发）
            #   ttl_dns_cache=300  DNS 缓存 5 分钟（减少 getaddrinfo 调用）
            #   force_close=False  keepalive 复用（默认 false）
            connector = aiohttp.TCPConnector(
                ssl=False,
                limit=200,
                limit_per_host=40,
                ttl_dns_cache=300,          # 优化4：DNS 缓存 300s（已实现，保留）
                force_close=False,          # 优化6：keepalive 复用
                keepalive_timeout=60,       # 优化6：空闲连接保持 60s，避免反复三次握手
            )
            timeout = aiohttp.ClientTimeout(total=settings.timeout, connect=15)
            _SHARED_SESSION = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": settings.user_agent},
            )
            _LAST_TARGET = target
            await _load_and_filter_cookies(_SHARED_SESSION, target)
        elif target and target != _LAST_TARGET:
            _LAST_TARGET = target
            _SHARED_SESSION.cookie_jar.clear()
            await _load_and_filter_cookies(_SHARED_SESSION, target)

        return _SHARED_SESSION


async def _load_and_filter_cookies(session: aiohttp.ClientSession, target: Optional[str] = None):
    """加载并过滤 Cookie - 增强容错"""
    if not target:
        return

    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname
    if not host:
        return
    if host.startswith('www.'):
        host = host[4:]

    cookie_file = _get_cookie_file_path(host)

    # 目标专属文件不存在时，回退到父域名文件（如 app.box.com -> box.com）
    if not cookie_file.exists():
        fallback_parts = host.split(".")
        for i in range(1, len(fallback_parts)):
            parent = ".".join(fallback_parts[i:])
            parent_file = _get_cookie_file_path(parent)
            if parent_file.exists():
                cookie_file = parent_file
                logger.info(f"📂 目标 Cookie 文件不存在，回退到父域名文件: {parent}")
                break

    # 兼容旧文件 ~/burp_cookies.json
    old_file = resolve_burp_cookies_path()
    if not cookie_file.exists() and os.path.exists(old_file):
        try:
            with open(old_file, 'r', encoding='utf-8') as f:
                all_cookies = json.load(f)
            filtered = {}
            for domain, cookies in all_cookies.items():
                clean_domain = domain.lstrip('.')
                if clean_domain == host or clean_domain.endswith('.' + host):
                    filtered[domain] = cookies
            if filtered:
                _atomic_write_json(cookie_file, encode_cookie_store(filtered))
                logger.info(f"📂 从旧文件提取了 {len(filtered)} 个匹配 {host} 的凭证")
        except Exception as e:
            logger.warning(f"提取旧 Cookie 失败: {e}")

    if not cookie_file.exists():
        return

    try:
        with open(cookie_file, 'r', encoding='utf-8') as f:
            if HAS_PORTALOCKER:
                portalocker.lock(f, portalocker.LOCK_SH)
                data = json.load(f)
                portalocker.unlock(f)
            else:
                data = json.load(f)
        data = decode_cookie_store(data)  # 密文信封自动解密；明文原样返回
    except json.JSONDecodeError as e:
        logger.warning(f"⚠️ Cookie 文件损坏: {cookie_file} - {e}，尝试恢复备份...")
        backup_file = cookie_file.with_suffix('.json.bak')
        if backup_file.exists():
            try:
                with open(backup_file, 'r', encoding='utf-8') as f:
                    if HAS_PORTALOCKER:
                        portalocker.lock(f, portalocker.LOCK_SH)
                        data = json.load(f)
                        portalocker.unlock(f)
                    else:
                        data = json.load(f)
                data = decode_cookie_store(data)
                logger.info(f"✅ 从备份恢复 Cookie: {backup_file}")
                # 恢复主文件（统一加密落盘）
                _atomic_write_json(cookie_file, encode_cookie_store(data))
            except Exception as e2:
                logger.warning(f"⚠️ 备份恢复失败: {e2}")
                return
        else:
            return
    except Exception as e:
        logger.warning(f"⚠️ 读取 Cookie 文件失败: {e}，跳过")
        return

    injected_count = 0
    auth_candidates = {}  # domain -> Authorization 值（已规范化带 Bearer 前缀）
    for domain, cookies in data.items():
        url_obj = URL(f"http://{domain}")
        for key, value in cookies.items():
            session.cookie_jar.update_cookies({key: value}, response_url=url_obj)
            if key.lower() == "authorization" and isinstance(value, str) and value.strip():
                candidate = value.strip()
                if not candidate.startswith(("Bearer ", "Basic ")):
                    candidate = f"Bearer {candidate}"
                auth_candidates[domain] = candidate
        injected_count += 1

    logger.info(f"✅ 已注入 {injected_count} 个域的凭证")

    # 把 Authorization cookie 提升为 HTTP 请求头（Box 等 OAuth 站点用 Bearer 头认证）
    if auth_candidates:
        chosen = None
        if host in auth_candidates:
            chosen = auth_candidates[host]
        else:
            for d, val in auth_candidates.items():
                if d == host or d.endswith("." + host) or host.endswith("." + d):
                    chosen = val
                    break
        if chosen is None:
            chosen = next(iter(auth_candidates.values()))
        try:
            session._default_headers["Authorization"] = chosen
            logger.info("✅ 已将 Authorization 提升为请求头（Bearer 认证生效）")
        except Exception as e:
            logger.debug(f"设置 Authorization 头失败: {e}")


async def close_shared_session():
    global _SHARED_SESSION
    async with _SHARED_SESSION_LOCK:
        if _SHARED_SESSION and not _SHARED_SESSION.closed:
            await _SHARED_SESSION.close()
        _SHARED_SESSION = None


# ============================================================
# 限流器
# ============================================================
class _RateLimiter:
    """代理：统一使用 ai.v100.rate_limiter.AdaptiveRateLimiter 作为唯一实现。
    为避免 core/utils ↔ ai.v100.rate_limiter ↔ core.settings 的循环导入，
    将 impl 初始化放在首次 acquire() 时懒加载。"""
    def __init__(self, rate: float):
        self.rate = rate
        self._impl = None
        self._init_lock = None  # asyncio.Lock 也不要在模块 import 时创建？保留 None

    async def _ensure_impl(self):
        if self._impl is not None:
            return
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        async with self._init_lock:
            if self._impl is not None:
                return
            # ★ 懒加载：避免模块级循环导入 ★
            from vulnclaw.ai.v100.rate_limiter import AdaptiveRateLimiter
            self._impl = AdaptiveRateLimiter(max(int(self.rate), 1))

    async def acquire(self, tokens: int = 1):
        await self._ensure_impl()
        # AdaptiveRateLimiter.acquire 语义等价（单令牌获取），兜底兼容旧签名
        for _ in range(max(1, int(tokens))):
            await self._impl.acquire()

    async def set_qps(self, qps: float):
        """运行时动态调整全局 HTTP 限流 QPS（目标容量探测结果应用）。"""
        self.rate = qps
        await self._ensure_impl()
        await self._impl.set_qps(qps)


_global_rate_limit = _RateLimiter(settings.rps)


# ============================================================
# HTTP 请求核心（修复：状态码500重试）
# ============================================================
# 优化2: 超时分档 —— 静态资源等 5s 不响应就该放弃；API 类给 20s；其余沿用全局设置
_STATIC_TIMEOUT_EXTS = (
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf', '.map', '.webp', '.avif',
    '.mp4', '.webm', '.mp3', '.ogg', '.wav',
)
_API_PATH_KEYWORDS = ('/api/', '/graphql', '/rest/', '/v1/', '/v2/', '/v3/')


def _timeout_for_url(url: str, default: int) -> int:
    """按 URL 类型分档超时（静态 5s / API 20s / 其他 default）。"""
    try:
        path = urllib.parse.urlparse(url or "").path.lower()
    except Exception:  # noqa: BLE001
        return default
    if any(path.endswith(ext) for ext in _STATIC_TIMEOUT_EXTS):
        return min(5, default)
    if any(kw in path for kw in _API_PATH_KEYWORDS):
        return min(20, default)
    return default


_UNSET = object()  # 哨兵：区分"未传 proxy"（沿用配置）与"显式 proxy=None"（明确直连）


def _egress_ssrf_block_reason(url: str) -> Optional[str]:
    """工作流8：出站白名单 + 平台级 SSRF/DNS-rebinding 统一检查（同步）。

    供 aiohttp 主链路（_http_request）与 requests 兼容链路（sync_get/sync_post）复用，
    与 httpx 路径（http_client._http2_request）同源 —— 默认
    （EGRESS_ALLOWLIST 为空 且 SSRF_GUARD != "1"）零 import、零开销返回 None，
    行为与旧版完全一致；命中返回拦截原因字符串，调用方据此返回 (0, 原因, {})。
    """
    if not (
        getattr(settings, "egress_allowlist", "")
        or str(getattr(settings, "ssrf_guard", "0")) == "1"
    ):
        return None
    from vulnclaw.core.http_client import (
        check_egress, check_ssrf, EgressBlockError, SSRFGuardError,
    )
    try:
        check_egress(url)
        check_ssrf(url)
    except (EgressBlockError, SSRFGuardError) as exc:
        logger.warning(f"🛡️ 出站安全防护拦截请求 {url}: {exc}")
        return str(exc)
    return None


async def _http_request(
    method: str,
    url: str,
    session: Optional[aiohttp.ClientSession] = None,
    headers: Optional[Dict] = None,
    timeout: Optional[int] = None,
    max_retries: int = 3,
    use_shared: bool = True,
    no_retry: bool = False,
    **kwargs
) -> Tuple[int, str, Dict]:
    # E5.1 越界硬拦截：默认（allowed_scope 为空）放行，兼容旧行为；
    # 配置后仅白名单内主机可出网，越界请求直接抛 ScopeGuardError（不可被 LLM 绕过）。
    if getattr(settings, "allowed_scope", ""):
        from vulnclaw.core.http_client import url_in_scope, ScopeGuardError
        if not url_in_scope(url):
            raise ScopeGuardError(
                f"E5 越界请求被 HTTP 客户端层拦截（超出 allowed_scope）: {url}"
            )
    # 工作流8：出站白名单 + 平台级 SSRF/DNS-rebinding 防护。
    # 与 httpx 路径（http_client._http2_request）同源检查——httpx 默认关闭，
    # 若不在此处接线，主链路（aiohttp）默认配置下防护等于不存在。
    # 命中拦截返回 (0, 原因, {})，与超时/网络错误同一约定；默认 off 时零开销。
    _blocked = _egress_ssrf_block_reason(url)
    if _blocked:
        return 0, f"Blocked by egress/SSRF guard: {_blocked}", {}
    # 优化2：按 URL 类型分档超时（调用方显式传值时尊重调用方）
    if timeout is None:
        timeout = _timeout_for_url(url, settings.timeout)
    elif timeout == settings.timeout:
        timeout = _timeout_for_url(url, settings.timeout)

    await _global_rate_limit.acquire()

    # 合规：任何请求路径都必须带配置的 User-Agent（政策强制，如 HackerOne 的
    # audibleresearcher_<h1name>），调用方未显式指定时兜底注入。
    headers = dict(headers or {})
    headers.setdefault('User-Agent', settings.user_agent)

    # 代理解析：必须区分"**没传** proxy"与"**显式传 None**（明确要直连）"。
    # 踩过的坑（2026-09-12）：旧写法 `proxy or settings.proxy or 池` 会让
    # `async_get(url, proxy=None)` 依旧走配置代理——于是"直连重试"（phases_recon 的
    # 兜底）实际还在用同一个坏代理重试，等于没兜底。真实目标上表现为静默零结果。
    _sentinel = kwargs.pop('proxy', _UNSET)
    if _sentinel is _UNSET:
        proxy = settings.proxy or _pool_active_proxy()
    else:
        proxy = _sentinel or None  # 显式 None / "" → 直连
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname in ['127.0.0.1', 'localhost']:
        proxy = None
    if proxy:
        kwargs['proxy'] = proxy

    if session is None and use_shared:
        session = await get_shared_session()

    effective_retries = 0 if no_retry else max_retries

    for attempt in range(effective_retries + 1):
        try:
            current_timeout = timeout * (1 + 0.5 * attempt) if not no_retry else timeout
            if session is not None:
                async with session.request(
                    method, url,
                    headers=headers or {},
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=current_timeout, connect=15),
                    **kwargs
                ) as resp:
                    return await _read_response(resp)
            else:
                async with aiohttp.ClientSession() as temp_session:
                    async with temp_session.request(
                        method, url,
                        headers=headers or {},
                        ssl=False,
                        timeout=aiohttp.ClientTimeout(total=current_timeout, connect=15),
                        **kwargs
                    ) as resp:
                        return await _read_response(resp)

        except asyncio.TimeoutError as e:
            if no_retry:
                return 0, f"Timeout after {timeout}s", {}
            if attempt < effective_retries:
                await asyncio.sleep(2 ** attempt + random.uniform(0, 2))
                continue
            return 0, str(e), {}

        except Exception as e:
            if no_retry:
                return 0, f"Network error: {str(e)[:50]}", {}
            if attempt < effective_retries:
                await asyncio.sleep(2 ** attempt + random.uniform(0, 2))
                continue
            return 0, str(e), {}

    return 0, "Max retries exceeded", {}


async def _read_capped(resp: aiohttp.ClientResponse, limit: int) -> Tuple[bytes, bool]:
    """读满响应体（上限 limit 字节），返回 (原始字节, 是否截断)。

    ⚠️ 踩过的坑（2026-09-15）：aiohttp 的 ``StreamReader.read(n)`` **只要缓冲里有
    数据就返回**，并不保证读满 n 字节——旧写法 ``read(MAX_RESPONSE_SIZE + 1)`` 因此
    把 1MB 响应静默截断成首个 chunk（实测 130915 字节），表现为：
      · 大页面证据/分析不完整；
      · 基线走完整文本、攻击响应被截断 → 长度差被误判为"响应长度异常变化"（误报）。
    这里改为循环读到 EOF 或达到上限，内存占用上限 = limit + 一个 chunk。
    """
    chunks: List[bytes] = []
    total = 0
    truncated = False
    while True:
        chunk = await resp.content.read(_READ_CHUNK)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            truncated = True
            break
    return b"".join(chunks), truncated


async def _read_response(resp: aiohttp.ClientResponse) -> Tuple[int, str, Dict]:
    content_length = resp.headers.get('Content-Length')
    if content_length:
        try:
            cl = int(content_length)
            if cl > MAX_RESPONSE_SIZE:
                raw, _ = await _read_capped(resp, MAX_RESPONSE_SIZE)
                text = raw.decode('utf-8', errors='ignore')
                text += "\n... [截断: 响应体过大]"
                return resp.status, text, dict(resp.headers)
        except BaseException:
            logger.debug("suppressed exception (core audit)")

    try:
        raw, truncated = await _read_capped(resp, MAX_RESPONSE_SIZE + 1)
        if truncated or len(raw) > MAX_RESPONSE_SIZE:
            raw = raw[:MAX_RESPONSE_SIZE]
            text = raw.decode('utf-8', errors='ignore')
            text += "\n... [截断]"
        else:
            text = raw.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        text = raw.decode('latin-1', errors='ignore')
    except BaseException:
        text = await resp.text(errors='ignore')

    return resp.status, text, dict(resp.headers)


# ============================================================
# HTTP 快捷方法
# ============================================================
def _pool_active_proxy() -> Optional[str]:
    """P3-4: settings.proxy 为空时从代理池取最优可用代理（失败静默返回 None）。"""
    try:
        from vulnclaw.core.proxy_pool import get_active_proxy
        return get_active_proxy()
    except Exception:
        return None


async def async_get(url: str, session=None, headers=None, timeout=None, no_retry: bool = False, **kwargs) -> Tuple[int, str, Dict]:
    return await _http_request('GET', url, session, headers, timeout, no_retry=no_retry, **kwargs)


async def async_post(url: str, data=None, json=None, session=None, headers=None, timeout=None, no_retry: bool = False, **kwargs) -> Tuple[int, str, Dict]:
    kwargs['data'] = data
    kwargs['json'] = json
    return await _http_request('POST', url, session, headers, timeout, no_retry=no_retry, **kwargs)


async def async_put(url: str, data=None, json=None, session=None, headers=None, timeout=None, no_retry: bool = False, **kwargs) -> Tuple[int, str, Dict]:
    kwargs['data'] = data
    kwargs['json'] = json
    return await _http_request('PUT', url, session, headers, timeout, no_retry=no_retry, **kwargs)


async def async_delete(url: str, session=None, headers=None, timeout=None, no_retry: bool = False, **kwargs) -> Tuple[int, str, Dict]:
    return await _http_request('DELETE', url, session, headers, timeout, no_retry=no_retry, **kwargs)


async def async_options(url: str, session=None, headers=None, timeout=None, no_retry: bool = False, **kwargs) -> Tuple[int, str, Dict]:
    return await _http_request('OPTIONS', url, session, headers, timeout, no_retry=no_retry, **kwargs)


# ============================================================
# 同步 HTTP（兼容旧代码）
# ============================================================
def sync_get(url: str, **kwargs) -> Tuple[int, str, Dict]:
    try:
        import requests
    except ImportError:
        return 0, "requests 未安装", {}

    kwargs.setdefault('timeout', settings.timeout)
    kwargs.setdefault('headers', {'User-Agent': settings.user_agent})
    kwargs.setdefault('verify', False)

    _proxy = settings.proxy or _pool_active_proxy()
    if _proxy:
        kwargs.setdefault('proxies', {'http': _proxy, 'https': _proxy})

    _blocked = _egress_ssrf_block_reason(url)
    if _blocked:
        return 0, f"Blocked by egress/SSRF guard: {_blocked}", {}

    try:
        resp = requests.get(url, **kwargs)
        return resp.status_code, resp.text, dict(resp.headers)
    except Exception as e:
        return 0, str(e), {}


def sync_post(url: str, **kwargs) -> Tuple[int, str, Dict]:
    try:
        import requests
    except ImportError:
        return 0, "requests 未安装", {}

    kwargs.setdefault('timeout', settings.timeout)
    kwargs.setdefault('headers', {'User-Agent': settings.user_agent})
    kwargs.setdefault('verify', False)

    _proxy = settings.proxy or _pool_active_proxy()
    if _proxy:
        kwargs.setdefault('proxies', {'http': _proxy, 'https': _proxy})

    _blocked = _egress_ssrf_block_reason(url)
    if _blocked:
        return 0, f"Blocked by egress/SSRF guard: {_blocked}", {}

    try:
        resp = requests.post(url, **kwargs)
        return resp.status_code, resp.text, dict(resp.headers)
    except Exception as e:
        return 0, str(e), {}


# ============================================================
# 协程安全执行（P3-12：收敛 asyncio.run 混用）
# ============================================================
def run_sync(coro):
    """在同步上下文安全运行协程（P3-12，2026-09-15）。

    为什么需要：`asyncio.run()` 在"已有运行中事件循环"的线程里会直接抛
    RuntimeError（例如 async 上下文中被同步工具函数调用），是潜在崩溃点。
    本函数统一处理两种情况：
      · 当前线程无运行循环 → 直接 asyncio.run（等价原行为，绝大多数入口路径）；
      · 当前线程有运行循环 → 新线程 + 独立事件循环执行并等待结果。

    注意：协程若持有绑定当前 loop 的资源（如当前 loop 的 aiohttp session），
    不可跨线程复用 —— 此类调用点（引擎内 `resp.text()`）保持原生 asyncio.run
    并附注释说明，不在此 helper 覆盖范围。
    """
    import asyncio as _asyncio
    try:
        _asyncio.get_running_loop()
    except RuntimeError:
        return _asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: _asyncio.run(coro)).result()


def sync_resp_text(resp) -> str:
    """同步取响应文本（**不启动事件循环**；P3-12 收敛引擎内 asyncio.run）。

    背景：引擎的同步解析函数曾用 `asyncio.run(resp.text())` —— 在事件循环内
    调用会直接抛 RuntimeError；且 aiohttp response 绑定创建它的 loop，
    也不能换线程跑（run_sync 不适用）。规则：
      ① tuple（引擎惯用 (status, text, headers)）→ 取 text；
      ② aiohttp response 且 body 已读（_body 非 None）→ 直接解码；
      ③ 其余（body 未读/未知对象）→ 空串（宁可空串，绝不炸/阻塞）。
    """
    try:
        if isinstance(resp, tuple):
            return resp[1] if len(resp) > 1 and resp[1] else ""
        body = getattr(resp, "_body", None)
        if body is None:
            return ""
        if isinstance(body, bytes):
            return body.decode("utf-8", errors="replace")
        return str(body)
    except Exception:  # noqa: BLE001
        return ""


# ============================================================
# 安全命令执行（列表传参）
# ============================================================
async def run_cmd_async(cmd: List[str], timeout: int = 120) -> Tuple[int, str, str]:
    if not isinstance(cmd, list):
        raise ValueError("cmd 必须为列表")
    if not cmd:
        raise ValueError("cmd 列表不能为空")

    logger.debug(f"执行命令: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode, stdout.decode(errors='ignore'), stderr.decode(errors='ignore')
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return -1, "", f"Timeout after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"FileNotFound: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


# ============================================================
# 工具路径
# ============================================================
_TOOL_CACHE = {}
# 已提示过的缺失工具，避免刷屏
_TOLD_MISSING = set()
THIRDPARTY_SETUP_HINT = "运行  python scan.py setup --download-thirdparty  自动下载补齐"


# =====================================================================
# 第三方工具清单：从各自官方 GitHub Release 下载（稳定版 URL）
#   - url_fmt 里占位符 {ver} {ext}
#   - Windows ext = zip（绝大多数）；Linux/macOS 用 tar.gz
#   - bin_map：压缩包里的可执行文件相对路径 -> thirdparty/ 下最终目标文件名
# =====================================================================
THIRDPARTY_TOOLS = [
    {
        "name": "nuclei",
        "ver": "3.3.8",
        "owner": "projectdiscovery",
        "repo": "nuclei",
        "bin": {
            "win": "nuclei.exe",
            "linux": "nuclei",
            "darwin": "nuclei",
        },
        "post_update_templates": True,
    },
    {
        "name": "subfinder",
        "ver": "2.6.6",
        "owner": "projectdiscovery",
        "repo": "subfinder",
        "bin": {
            "win": "subfinder.exe",
            "linux": "subfinder",
            "darwin": "subfinder",
        },
    },
    {
        "name": "httpx",
        "ver": "1.6.9",
        "owner": "projectdiscovery",
        "repo": "httpx",
        "bin": {
            "win": "httpx.exe",
            "linux": "httpx",
            "darwin": "httpx",
        },
    },
    {
        "name": "interactsh-client",
        "ver": "1.1.10",
        "owner": "projectdiscovery",
        "repo": "interactsh",
        "bin": {
            "win": "interactsh-client.exe",
            "linux": "interactsh-client",
            "darwin": "interactsh-client",
        },
    },
    {
        "name": "ffuf",
        "ver": "2.1.0",
        "owner": "ffuf",
        "repo": "ffuf",
        "bin": {
            "win": "ffuf.exe",
            "linux": "ffuf",
            "darwin": "ffuf",
        },
    },
    {
        "name": "assetfinder",
        "ver": "0.1.0",
        "owner": "tomnomnom",
        "repo": "assetfinder",
        "bin": {
            "win": "assetfinder.exe",
            "linux": "assetfinder",
            "darwin": "assetfinder",
        },
    },
    {
        "name": "trivy",
        "ver": "0.59.1",
        "owner": "aquasecurity",
        "repo": "trivy",
        "bin": {
            "win": "trivy.exe",
            "linux": "trivy",
            "darwin": "trivy",
        },
    },
    # -------- 爬虫/历史数据工具（方案②：补全真扫缺件；下载失败自动降级，不阻塞） --------
    {
        "name": "waybackurls",
        "ver": "0.1.0",
        "owner": "tomnomnom",
        "repo": "waybackurls",
        "bin": {
            "win": "waybackurls.exe",
            "linux": "waybackurls",
            "darwin": "waybackurls",
        },
    },
    {
        "name": "gau",
        "ver": "2.0.9",
        "owner": "lc",
        "repo": "gau",
        "bin": {
            "win": "gau.exe",
            "linux": "gau",
            "darwin": "gau",
        },
    },
    {
        "name": "gospider",
        "ver": "1.1.6",
        "owner": "jaeles-project",
        "repo": "gospider",
        "bin": {
            "win": "gospider.exe",
            "linux": "gospider",
            "darwin": "gospider",
        },
    },
    {
        "name": "katana",
        "ver": "1.1.3",
        "owner": "projectdiscovery",
        "repo": "katana",
        "bin": {
            "win": "katana.exe",
            "linux": "katana",
            "darwin": "katana",
        },
    },
]


def _tp_os_key() -> str:
    if os.name == "nt":
        return "win"
    if sys.platform == "darwin":
        return "darwin"
    return "linux"


def _tp_arch_suffix() -> str:
    """返回 Release 文件名里常见的 arch 后缀段（不含平台）"""
    import struct
    bits = struct.calcsize("P") * 8
    machine = (os.environ.get("PROCESSOR_ARCHITECTURE") or platform.machine() or "").lower()
    if bits == 32 or machine in ("x86", "i386", "386"):
        return "386"
    # arm64 分支
    if "arm" in machine or "aarch" in machine:
        return "arm64"
    return "amd64"


_TP_UA = "VULNCLAW-setup/0.2"
# 本进程内判死的下载源（连接级失败标记，避免同一批里后续工具反复撞墙）
_TP_DEAD_CANDIDATES: set = set()


def _tp_mirrors() -> list:
    """镜像前缀列表（TOOL_DOWNLOAD_MIRRORS，逗号分隔；镜像 URL=前缀+原始完整 GitHub URL）。"""
    from vulnclaw.config.settings import settings as _st
    raw = str(getattr(_st, "tool_download_mirrors", "") or "")
    return [m.strip().rstrip("/") for m in raw.split(",") if m.strip()]


def _tp_candidate_urls(url: str) -> list:
    """候选下载源：直连在前，镜像按配置顺序追加。"""
    urls = [url]
    for m in _tp_mirrors():
        cand = m + "/" + url
        if cand not in urls:
            urls.append(cand)
    return urls


def _tp_is_connect_error(e: Exception) -> bool:
    """连接级失败（超时/重置/拒连/DNS）判定——这类失败按"源"标记跳过；HTTP 4xx/5xx 是 URL 级问题不标记。"""
    import urllib.error as _uerr
    if isinstance(e, _uerr.HTTPError):
        return False
    if isinstance(e, (TimeoutError, ConnectionError, socket.timeout)):
        return True
    reason = getattr(e, "reason", None)
    if isinstance(reason, (TimeoutError, ConnectionError, OSError)):
        return True
    text = str(e).lower()
    return any(k in text for k in (
        "timed out", "timeout", "connection reset", "connection refused",
        "unreachable", "getaddrinfo failed", "temporary failure",
        "10054", "10060", "10013",
    ))


def _tp_fetch_text(url: str, timeout: int = 30) -> Optional[str]:
    """拉取小文本（checksums 等）：走候选源（直连+镜像），全部失败返回 None（软失败）。"""
    import urllib.request
    for cand in _tp_candidate_urls(url):
        try:
            req = urllib.request.Request(cand, headers={"User-Agent": _TP_UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception:
            continue
    return None


# 只对确认发布 <repo>_<ver>_checksums.txt 的官方源做硬校验
# （2026-09-05 实测：PD/ffuf 命名正确；trivy 该命名 404，tomnomnom/gau/gospider 不发布 → 均不硬校验）
_TP_CHECKSUM_OWNERS = {"projectdiscovery", "ffuf"}


def _tp_checksum_url(tool: dict) -> Optional[str]:
    owner = tool.get("owner", "")
    if owner not in _TP_CHECKSUM_OWNERS:
        return None
    repo, ver = tool["repo"], tool["ver"]
    return (
        f"https://github.com/{owner}/{repo}/releases/download/"
        f"v{ver}/{repo}_{ver}_checksums.txt"
    )


def _tp_verify_archive_checksum(archive: Path, tool: dict, asset_name: str) -> str:
    """官方 checksums 硬校验。

    返回 ""（校验通过）或软告警文案（官方无 checksums/拉取失败/无条目 → 放行并提示）；
    哈希不匹配 → raise ValueError（硬拒装，防投毒/损坏）。
    """
    csum_url = _tp_checksum_url(tool)
    if not csum_url:
        return "该工具官方未发布 checksums，改用本地 manifest 比对"
    text = _tp_fetch_text(csum_url)
    if not text:
        return "官方 checksums 拉取失败，跳过本轮硬校验（仍记入本地 manifest 比对）"
    want = None
    aname = (asset_name or archive.name).lower()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].lstrip("*").lower() == aname:
            want = parts[0].lower()
            break
    if not want:
        return f"官方 checksums 中无 {aname} 条目，跳过硬校验"
    import hashlib
    h = hashlib.sha256()
    with open(archive, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    got = h.hexdigest()
    if got != want:
        raise ValueError(
            f"SHA256 与官方不符，已拒装（可能被篡改/损坏）：官方 {want[:16]}… / 实际 {got[:16]}…"
        )
    return ""


def _tp_api_assets(owner: str, repo: str, ver: str) -> list:
    """GitHub API 拉取 release assets（仅直连 api.github.com，尽力而为）。"""
    import urllib.request
    api = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/v{ver}"
    req = urllib.request.Request(
        api, headers={"User-Agent": _TP_UA, "Accept": "application/vnd.github+json"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return (json.loads(resp.read().decode("utf-8")) or {}).get("assets", []) or []


def _tp_api_asset_url(tool: dict) -> Optional[str]:
    """固定 URL 失败的兜底：按当前平台提示词从 API assets 里挑匹配资产（防上游改 Release 命名结构）。"""
    try:
        assets = _tp_api_assets(tool["owner"], tool["repo"], tool["ver"])
    except Exception:
        return None
    os_key = _tp_os_key()
    arch = _tp_arch_suffix()
    os_hints = {"win": ("windows",), "linux": ("linux",),
                "darwin": ("macos", "darwin", "mac")}[os_key]
    arch_hints = {"amd64": ("amd64", "x86_64", "64bit"), "arm64": ("arm64", "aarch64"),
                  "386": ("386", "i386")}[arch]
    best, best_score = None, -1
    for a in assets:
        n = str(a.get("name") or "").lower()
        if not n.endswith((".zip", ".tar.gz", ".tgz")):
            continue
        if "checksums" in n or ".sbom" in n or n.endswith(".json"):
            continue
        if not any(h in n for h in os_hints):
            continue
        if not any(h in n for h in arch_hints):
            continue
        score = sum(1 for h in os_hints if h in n) + sum(1 for h in arch_hints if h in n)
        if score > best_score:
            best, best_score = a.get("browser_download_url"), score
    return best


def _tp_release_url(tool: dict) -> tuple[str, str]:
    """返回 (download_url, archive_ext)。ext 不带点，如 'zip' / 'tar.gz'。"""
    owner = tool["owner"]
    repo = tool["repo"]
    ver = tool["ver"]
    os_key = _tp_os_key()
    arch = _tp_arch_suffix()

    # -------- projectdiscovery 统一命名 --------
    if owner == "projectdiscovery":
        # 例: https://github.com/projectdiscovery/nuclei/releases/download/v3.3.8/nuclei_3.3.8_windows_amd64.zip
        os_name = {"win": "windows", "linux": "linux", "darwin": "macOS"}[os_key]
        ext = "zip" if os_key == "win" else "zip"  # PD 全平台 zip
        url = (
            f"https://github.com/{owner}/{repo}/releases/download/"
            f"v{ver}/{repo}_{ver}_{os_name}_{arch}.{ext}"
        )
        return url, ext

    # -------- ffuf --------
    if owner == "ffuf":
        # 例: https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_windows_amd64.zip
        os_name = {"win": "windows", "linux": "linux", "darwin": "darwin"}[os_key]
        ext = "zip" if os_key in ("win", "darwin") else "tar.gz"
        if os_key == "darwin":
            # ffuf 把 darwin 两类拆开
            url = (
                f"https://github.com/{owner}/{repo}/releases/download/"
                f"v{ver}/{repo}_{ver}_{os_name}_{arch}.zip"
            )
        else:
            url = (
                f"https://github.com/{owner}/{repo}/releases/download/"
                f"v{ver}/{repo}_{ver}_{os_name}_{arch}.{ext}"
            )
        return url, ext

    # -------- assetfinder (tomnomnom) --------
    if owner == "tomnomnom":
        # 例: https://github.com/tomnomnom/assetfinder/releases/download/v0.1.0/assetfinder-windows-386-0.1.0.tgz
        os_name = {"win": "windows", "linux": "linux", "darwin": "darwin"}[os_key]
        url = (
            f"https://github.com/{owner}/{repo}/releases/download/"
            f"v{ver}/{repo}-{os_name}-{arch}-{ver}.tgz"
        )
        return url, "tar.gz"

    # -------- trivy --------
    if owner == "aquasecurity":
        # 例: https://github.com/aquasecurity/trivy/releases/download/v0.59.1/trivy_0.59.1_windows-64bit.zip
        if os_key == "win":
            bits_suffix = "64bit" if arch == "amd64" else arch
            url = (
                f"https://github.com/{owner}/{repo}/releases/download/"
                f"v{ver}/{repo}_{ver}_windows-{bits_suffix}.zip"
            )
            return url, "zip"
        if os_key == "darwin":
            mac_arch = "ARM64" if arch == "arm64" else "64bit"
            url = (
                f"https://github.com/{owner}/{repo}/releases/download/"
                f"v{ver}/{repo}_{ver}_macOS-{mac_arch}.tar.gz"
            )
            return url, "tar.gz"
        bits_suffix = "64bit" if arch == "amd64" else arch
        url = (
            f"https://github.com/{owner}/{repo}/releases/download/"
            f"v{ver}/{repo}_{ver}_Linux-{bits_suffix}.tar.gz"
        )
        return url, "tar.gz"

    # -------- lc/gau --------
    if owner == "lc":
        # 例: https://github.com/lc/gau/releases/download/v2.0.9/gau_2.0.9_windows_amd64.zip
        os_name = {"win": "windows", "linux": "linux", "darwin": "macOS"}[os_key]
        ext = "zip" if os_key == "win" else "tar.gz"
        url = (
            f"https://github.com/{owner}/{repo}/releases/download/"
            f"v{ver}/{repo}_{ver}_{os_name}_{arch}.{ext}"
        )
        return url, ext

    # -------- jaeles-project/gospider --------
    if owner == "jaeles-project":
        # 实际资产命名: <repo>_v<ver>_<os>_<arch>.zip（os=windows, arch=x86_64/386/arm64）
        os_name = "windows" if os_key == "win" else ("linux" if os_key == "linux" else "macos")
        arch_name = ("x86_64" if arch == "amd64" else arch)
        ext = "zip"
        url = (
            f"https://github.com/{owner}/{repo}/releases/download/"
            f"v{ver}/{repo}_v{ver}_{os_name}_{arch_name}.{ext}"
        )
        return url, ext

    raise ValueError(f"未实现 {tool['name']} 的下载 URL 规则")


def _tp_progress(rep: str, downloaded: int, total: int | None) -> None:
    if total:
        pct = downloaded * 100 // total
        bar = "#" * (pct // 4) + "-" * (25 - pct // 4)
        mb = f"{downloaded / 1024 / 1024:5.1f}MB / {total / 1024 / 1024:5.1f}MB"
        sys.stdout.write(f"\r  [{bar}] {pct:3d}%  {mb}  {rep}")
    else:
        mb = f"{downloaded / 1024 / 1024:5.1f}MB"
        sys.stdout.write(f"\r  {mb}  {rep}")
    sys.stdout.flush()


def _tp_fetch(url: str, dest: Path, timeout: int) -> None:
    """单次下载尝试（成功写满 dest；失败可能留下半截文件，由调用方清理）。"""
    import urllib.request
    # 加 UA，否则一些 GitHub asset CDN 会 403
    req = urllib.request.Request(url, headers={"User-Agent": _TP_UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        total = resp.headers.get("Content-Length")
        total_i = int(total) if total and total.isdigit() else None
        done = 0
        chunk = 64 * 1024
        with open(dest, "wb") as f:
            while True:
                buf = resp.read(chunk)
                if not buf:
                    break
                f.write(buf)
                done += len(buf)
                _tp_progress(url.rsplit("/", 1)[-1][:28], done, total_i)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _tp_download(url: str, dest: Path, tool_label: str, timeout: int = 60) -> str:
    """多候选（直连+镜像）+ 有限轮退避重试的下载入口。

    - 每轮遍历全部候选源，连接级失败的源本进程内标死（后续工具不再撞墙）；
    - 每次失败清理半截文件；
    - 返回实际下载成功的 URL；全部失败 raise RuntimeError。
    """
    from vulnclaw.config.settings import settings as _st
    import time as _time
    attempts = max(1, int(getattr(_st, "tool_download_retries", 3) or 3))
    total_cands = len(_tp_candidate_urls(url))
    last_err: Exception | None = None
    for attempt in range(attempts):
        cands = [c for c in _tp_candidate_urls(url) if c not in _TP_DEAD_CANDIDATES]
        if not cands:
            break
        for cand in cands:
            try:
                _tp_fetch(cand, dest, timeout)
                return cand
            except Exception as e:  # noqa: BLE001
                last_err = e
                if _tp_is_connect_error(e):
                    _TP_DEAD_CANDIDATES.add(cand)
                try:
                    dest.unlink()
                except OSError:
                    pass
                sys.stdout.write("\n")
                sys.stdout.flush()
        if attempt < attempts - 1:
            _time.sleep(0.5 * (attempt + 1))
    raise RuntimeError(
        f"{tool_label}: {attempts} 轮 × {total_cands} 个下载源全部失败: {last_err}"
    )


def _tp_extract(archive: Path, dest_dir: Path, bin_src_name: str, bin_dest: Path) -> None:
    """从压缩包里只挑出可执行文件 -> bin_dest。"""
    name = archive.name.lower()
    import tarfile
    import zipfile

    matched: Path | None = None
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive, "r") as zf:
            for info in zf.infolist():
                leaf = os.path.basename(info.filename.replace("\\", "/"))
                if leaf == bin_src_name:
                    with zf.open(info) as src, open(bin_dest, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    matched = bin_dest
                    break
    else:
        # tar.gz / .tgz
        mode = "r:gz"
        with tarfile.open(archive, mode) as tf:
            for member in tf.getmembers():
                leaf = os.path.basename(member.name.replace("\\", "/"))
                if leaf == bin_src_name and member.isfile():
                    src_obj = tf.extractfile(member)
                    if src_obj is None:
                        continue
                    with open(bin_dest, "wb") as dst:
                        shutil.copyfileobj(src_obj, dst)
                    matched = bin_dest
                    break

    if matched is None:
        raise FileNotFoundError(
            f"压缩包里没找到 {bin_src_name}，请检查该版本 Release 结构是否变化: {archive}"
        )
    try:
        if os.name != "nt":
            os.chmod(bin_dest, 0o755)
    except Exception:
        logger.debug("suppressed exception (core audit)")




def _sha256_file(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_tool_manifest(third_dir: Path) -> dict:
    mf = third_dir / "tool_manifest.json"
    if not mf.exists():
        return {}
    try:
        import json as _json
        return _json.loads(mf.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _record_tool_manifest(third_dir: Path, name: str, ver: str, dest_file: Path) -> None:
    """记录已装工具 SHA256 到 manifest；同版本 hash 变化时告警（防替换/防损坏）。"""
    import json as _json
    try:
        cur = _sha256_file(dest_file)
    except OSError:
        return
    mf = third_dir / "tool_manifest.json"
    data = _load_tool_manifest(third_dir)
    prev = data.get(name)
    if prev and prev.get("ver") == ver and prev.get("sha256") and prev["sha256"] != cur:
        logger.warning(
            f"⚠️ [工具校验] {name} v{ver} 与上次安装的 SHA256 不一致（文件可能被替换/损坏）；"
            f"上次 {prev['sha256'][:16]}… / 本次 {cur[:16]}…"
        )
    data[name] = {"ver": ver, "sha256": cur}
    try:
        mf.write_text(_json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError:
        logger.debug("suppressed exception (core audit)")




def plan_tool_install() -> list:
    """工具体检（只检查不下载）：返回 thirdparty/ 下缺失的工具清单。

    判定缺失：目标二进制不存在，或存在但 < 100KB（残留/损坏文件）。
    """
    from vulnclaw.config.settings import settings as _st

    third_dir = Path(_st.thirdparty_dir)
    os_key = _tp_os_key()
    missing = []
    for tool in THIRDPARTY_TOOLS:
        bin_name = tool["bin"][os_key]
        dest = third_dir / bin_name
        if not dest.exists() or dest.stat().st_size < 100 * 1024:
            missing.append(tool)
    return missing


def _github_reachable(timeout: int = 5) -> bool:
    """快速连通性预检：GitHub 不通时跳过自动安装（避免每次扫描空等超时）。"""
    import urllib.request
    try:
        req = urllib.request.Request(
            "https://github.com", method="HEAD",
            headers={"User-Agent": "VULNCLAW-tool-health/0.1"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status < 500
    except Exception:
        return False


def _mirror_reachable(timeout: int = 3) -> bool:
    """镜像前缀连通性预检：GitHub 直连不可达但镜像可用时，仍尝试自动安装（经镜像下载）。"""
    mirrors = _tp_mirrors()
    if not mirrors:
        return False
    import urllib.request
    for m in mirrors[:3]:
        try:
            req = urllib.request.Request(m, method="HEAD", headers={"User-Agent": _TP_UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status < 500:
                    return True
        except Exception:
            continue
    return False


def ensure_thirdparty_tools(auto_install: bool | None = None) -> tuple:
    """扫描/启动前的工具体检入口。

    语义（尽力而为）：
      - 无缺失 → (0, 0)，零开销返回
      - 有缺失且 auto_install（默认取 settings.tool_auto_install）→ 尝试自动下载；
        GitHub 不可达 / 下载失败 → 打警告继续，绝不阻塞扫描
      - auto_install=False → 只提示手动 setup --download-thirdparty

    返回: (ok_count, fail_count)
    """
    from vulnclaw.config.settings import settings as _st

    auto = _st.tool_auto_install if auto_install is None else auto_install
    missing = plan_tool_install()
    if not missing:
        return 0, 0
    names = ", ".join(t["name"] for t in missing)
    logger.info(f"🛠️ [工具体检] 缺失 {len(missing)} 个第三方工具: {names}")
    if not auto:
        logger.info(
            f"🛠️ [工具体检] TOOL_AUTO_INSTALL=false，跳过自动安装；可手动: "
            f"python scan.py setup --download-thirdparty"
        )
        return 0, len(missing)
    if not _github_reachable() and not _mirror_reachable():
        logger.warning(
            "🛠️ [工具体检] GitHub 直连与镜像均不可达，跳过自动安装（扫描继续，可稍后手动补齐）"
        )
        return 0, len(missing)
    try:
        ok, fail = download_thirdparty_tools(only_missing=True, update_nuclei_templates=False)
        logger.info(f"🛠️ [工具体检] 自动安装完成: 成功 {ok} / 失败 {fail}（失败项自动降级）")
        return ok, fail
    except Exception as e:  # noqa: BLE001
        logger.warning(f"🛠️ [工具体检] 自动安装异常（忽略，继续扫描）: {e}")
        return 0, len(missing)


def download_thirdparty_tools(
    only_missing: bool = True,
    update_nuclei_templates: bool = True,
) -> tuple[int, int]:
    """
    下载/补齐 thirdparty/ 下的二进制工具。

    参数:
        only_missing: True = 只下缺失的；False = 强制重下（升级版本用）
        update_nuclei_templates: 下完 nuclei 后是否跑 `nuclei -update-templates`

    返回: (ok_count, fail_count)
    """
    import subprocess
    import tempfile

    third_dir = Path(settings.thirdparty_dir)
    third_dir.mkdir(parents=True, exist_ok=True)
    os_key = _tp_os_key()

    ok = 0
    fail = 0

    print("=" * 68)
    print(f"📦 VULNCLAW 第三方工具自动下载（平台={os_key}/{_tp_arch_suffix()}）")
    print(f"   目标目录: {third_dir}")
    print(f"   模式: {'只补齐缺失项' if only_missing else '全部重新下载（版本强制对齐）'}")
    print("=" * 68)

    with tempfile.TemporaryDirectory(prefix="vulnclaw_setup_") as tmp:
        tmpdir = Path(tmp)
        for tool in THIRDPARTY_TOOLS:
            name = tool["name"]
            bin_name = tool["bin"][os_key]
            dest_file = third_dir / bin_name
            if only_missing and dest_file.exists() and dest_file.stat().st_size > 100 * 1024:
                print(f"\n✅ {name:<20s} 已存在，跳过（{dest_file}）")
                ok += 1
                continue

            try:
                url, ext = _tp_release_url(tool)
            except Exception as e:
                fail += 1
                print(f"\n❌ {name:<20s} URL 生成失败: {e}")
                continue

            archive_path = tmpdir / f"{name}-{tool['ver']}.{ext}"
            asset_name = url.rsplit("/", 1)[-1]
            print(f"\n⬇️  {name:<20s} v{tool['ver']}  {url}")
            try:
                _tp_download(url, archive_path, f"{name} v{tool['ver']}")
            except Exception as e:
                # 兜底①：GitHub API 按资产名挑匹配平台的文件（防上游改 Release 命名结构）
                alt = _tp_api_asset_url(tool)
                if not alt:
                    fail += 1
                    print(f"   ❌ 失败: {e}")
                    continue
                alt_ext = "zip" if alt.lower().endswith(".zip") else "tar.gz"
                archive_path = tmpdir / f"{name}-{tool['ver']}.{alt_ext}"
                asset_name = alt.rsplit("/", 1)[-1]
                print(f"   ↻ 固定链接失败（{e}），API 兜底: {asset_name}")
                try:
                    _tp_download(alt, archive_path, f"{name} v{tool['ver']}")
                except Exception as e2:
                    fail += 1
                    print(f"   ❌ 失败: {e2}")
                    continue
            # 兜底②：官方 checksums 硬校验（拉不到→软告警放行；不匹配→拒装防投毒）
            try:
                cnote = _tp_verify_archive_checksum(archive_path, tool, asset_name=asset_name)
                if cnote:
                    print(f"   ⚠️  {cnote}")
            except ValueError as e:
                fail += 1
                print(f"   ❌ {e}")
                if archive_path.exists():
                    try:
                        archive_path.unlink()
                    except Exception:
                        logger.debug("suppressed exception (core audit)")
                continue
            try:
                print(f"   ✔ 下载完成 ({archive_path.stat().st_size / 1024 / 1024:.2f} MB)")
                print(f"   🗜  提取 {bin_name} -> {dest_file}")
                _tp_extract(archive_path, tmpdir, bin_name, dest_file)
                ok += 1
                # 方案②：SHA256 记录到 manifest（同版本重下时 hash 变化会告警）
                _record_tool_manifest(third_dir, name, tool["ver"], dest_file)
                # 清缓存，避免后续 get_tool_path 还认为它不存在
                _TOOL_CACHE.pop(name, None)
            except Exception as e:
                fail += 1
                print(f"   ❌ 失败: {e}")
                if archive_path.exists():
                    try:
                        archive_path.unlink()
                    except Exception:
                        logger.debug("suppressed exception (core audit)")
                continue

    # -------- nuclei -update-templates（可选，默认开） --------
    nuclei_bin = third_dir / "nuclei.exe" if os_key == "win" else third_dir / "nuclei"
    if update_nuclei_templates and nuclei_bin.exists():
        print("\n🧬 调用 nuclei -update-templates 拉取最新官方模板（1~3 分钟）…")
        try:
            cp = subprocess.run(
                [str(nuclei_bin), "-update-templates"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=600,
            )
            tail = "\n".join(cp.stdout.splitlines()[-6:]) if cp.stdout else ""
            if cp.returncode == 0:
                print(f"   ✅ nuclei 模板更新成功\n{tail}")
            else:
                print(f"   ⚠️  nuclei 模板更新非 0 退出（exit={cp.returncode}），可之后手动再跑：\n"
                      f"      {nuclei_bin} -update-templates\n{tail}")
        except Exception as e:
            print(f"   ⚠️  nuclei -update-templates 调用失败（{e}）；请之后手动执行。")

    print("=" * 68)
    print(f"📊 下载完成：成功 {ok} / 失败 {fail}")
    if fail == 0:
        print(f"✅ 全部就绪。现在可以直接： python scan.py scan -t https://example.com")
    else:
        print(f"ℹ️  失败项会自动降级；可重跑 setup --download-thirdparty（会只补缺失的，很快）。")
        if not _tp_mirrors():
            print("   国内网络可在 .env 设 TOOL_DOWNLOAD_MIRRORS=https://gh-proxy.com/,https://ghproxy.net/ 启用镜像加速（逗号分隔多个）。")
    print("=" * 68)
    return ok, fail


def get_tool_path(tool_name: str) -> Optional[str]:
    if tool_name in _TOOL_CACHE:
        return _TOOL_CACHE[tool_name]

    path = shutil.which(tool_name)
    if path:
        _TOOL_CACHE[tool_name] = path
        return path

    # 工具名别名（2026-09-07）：Windows 下 sqlmap 是 Python 包，无 sqlmapapi 可执行文件，
    # 真实入口为 thirdparty/sqlmap/sqlmapapi.py；别名命中后 _invoke 会自动前置 python。
    _tool_aliases = {
        "sqlmapapi": os.path.join("sqlmap", "sqlmapapi.py"),
    }
    _alias_path = _tool_aliases.get(tool_name)
    if _alias_path:
        _ap = os.path.join(settings.thirdparty_dir, _alias_path)
        if os.path.exists(_ap):
            _TOOL_CACHE[tool_name] = _ap
            return _ap

    third = os.path.join(settings.thirdparty_dir, tool_name)
    if os.path.isdir(third):
        # 目录型分发（如 thirdparty/sqlmap/sqlmap.py）：定位内部可执行/脚本
        for cand in (
            os.path.join(third, tool_name + ".py"),
            os.path.join(third, tool_name + ".exe"),
            os.path.join(third, tool_name),
        ):
            if os.path.exists(cand):
                _TOOL_CACHE[tool_name] = cand
                return cand
    elif os.path.exists(third):
        _TOOL_CACHE[tool_name] = third
        return third

    if os.name == 'nt':
        third_exe = third + '.exe'
        if os.path.exists(third_exe):
            _TOOL_CACHE[tool_name] = third_exe
            return third_exe

    _TOOL_CACHE[tool_name] = None
    # 缺失时只提示一次，避免日志刷屏
    if tool_name not in _TOLD_MISSING:
        _TOLD_MISSING.add(tool_name)
        logger.info(
            f"💡 工具 '{tool_name}' 未在系统 PATH 或 thirdparty/ 中找到。"
            f"如需补齐，运行：{THIRDPARTY_SETUP_HINT}"
        )
    return None


def tool_exists(name: str) -> bool:
    return get_tool_path(name) is not None


# ============================================================
# 其他工具函数
# ============================================================
def resolve_hostnames(domains: List[str]) -> Dict[str, List[str]]:
    result = {}
    for domain in domains:
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            result[domain] = ips
        except socket.gaierror:
            result[domain] = []
        except Exception as e:
            logger.debug(f"解析 {domain} 失败: {e}")
            result[domain] = []
    return result


def detect_waf(headers: Dict, body: str) -> Optional[str]:
    combined = str(headers) + body
    waf_signatures = {
        "cloudflare": ["cf-ray", "__cfduid", "cf_clearance", "Cloudflare"],
        "aws_waf": ["x-amzn-RequestId", "AWS WAF", "Request blocked"],
        "modsecurity": ["ModSecurity", "www.modsecurity.org"],
        "akamai": ["X-Akamai-Transformed", "Akamai", "Access Denied"],
        "f5_bigip": ["X-Cnection", "X-F5-Client-IP", "BigIP", "F5"],
        "imperva": ["X-Iinfo", "Imperva", "Incapsula"],
        "sucuri": ["X-Sucuri-ID", "Sucuri"],
        "wordfence": ["Wordfence", "Generated by Wordfence"],
        "barracuda": ["X-Barracuda", "Barracuda"],
        "fortinet": ["X-Fortinet", "Fortinet"],
        "paloalto": ["X-Pan", "Palo Alto"],
        "radware": ["X-Radware", "Radware"],
        "citrix": ["X-Citrix", "Citrix"],
        "ddos_guard": ["X-DDOS-Guard", "DDOS-Guard"],
        "stackpath": ["X-StackPath", "StackPath"],
        "fastly": ["X-Served-By", "X-Cache", "Fastly"],
        "azure_waf": ["X-Msedge-Ref", "Azure"],
        "gcp_waf": ["X-GCP", "Google Cloud"],
        "aliyun_waf": ["X-Aliyun", "Aliyun"],
        "tencent_waf": ["X-Tencent", "Tencent"],
        "aws_cloudfront": ["X-Amz-Cf-Id", "CloudFront"],
    }
    combined_lower = combined.lower()
    for waf_name, signatures in waf_signatures.items():
        for sig in signatures:
            if sig.lower() in combined_lower:
                return waf_name
    return None


def generate_mutated_requests(
    original_data: Union[str, Dict, List],
    mutation_type: str = "all",
    max_mutations: int = 10
) -> List[Union[str, Dict, List]]:
    if not original_data:
        return []

    mutations = []

    if isinstance(original_data, str):
        if mutation_type in ("all", "case"):
            mutated = original_data.swapcase()
            if mutated != original_data:
                mutations.append(mutated)

        if mutation_type in ("all", "encoding"):
            encoded = urllib.parse.quote(original_data, safe='')
            if encoded != original_data:
                mutations.append(encoded)
            double_encoded = urllib.parse.quote(encoded, safe='')
            if double_encoded != encoded:
                mutations.append(double_encoded)
            sql_keywords = ["SELECT", "UNION", "OR", "AND", "FROM", "WHERE", "ORDER", "GROUP", "BY", "HAVING"]
            for kw in sql_keywords:
                if kw in original_data.upper():
                    mutated = original_data.replace(kw, kw + kw)
                    if mutated != original_data:
                        mutations.append(mutated)
                    mixed = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(kw))
                    if mixed != kw:
                        mutated = original_data.replace(kw, mixed)
                        mutations.append(mutated)

    elif isinstance(original_data, dict):
        if mutation_type in ("all", "encoding"):
            mutated = original_data.copy()
            mutated["_test"] = "1"
            mutations.append(mutated)

        for key, value in original_data.items():
            if isinstance(value, str):
                for mutated_value in generate_mutated_requests(value, mutation_type, 3)[:3]:
                    mutated = original_data.copy()
                    mutated[key] = mutated_value
                    mutations.append(mutated)

    elif isinstance(original_data, list):
        for i, item in enumerate(original_data):
            if isinstance(item, (str, dict)):
                for mutated_item in generate_mutated_requests(item, mutation_type, 3)[:3]:
                    mutated = list(original_data)
                    mutated[i] = mutated_item
                    mutations.append(mutated)

    unique_mutations = []
    seen = set()
    for m in mutations:
        m_str = str(m)
        if m_str not in seen:
            seen.add(m_str)
            unique_mutations.append(m)
            if len(unique_mutations) >= max_mutations:
                break

    if not unique_mutations:
        return [original_data]

    return unique_mutations


def ensure_scheme(url: str, default_scheme: str = "https") -> str:
    """给缺 scheme 的 URL 补默认 scheme（audible.com -> https://audible.com）。
    已带 scheme 的原样返回。修复无协议 URL 导致请求/复现命令失败的问题。
    """
    if not url:
        return url
    if "://" in url:
        return url
    return f"{default_scheme}://{url.lstrip('/')}"


def build_attack_url(base_url: str, param: str, payload: str, original_query: str = '') -> str:
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    base_url = ensure_scheme(base_url, "https")  # 补全 scheme，避免无协议 URL 使请求失败
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query) if parsed.query else {}
    if original_query and not qs:
        qs = parse_qs(original_query)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def resolve_burp_cookies_path() -> str:
    """双路回退：返回 burp_cookies.json 的实际可读路径。

    scan_main.py 为防 nuclei/uncover 往 HOME 写垃圾，会把 HOME/USERPROFILE
    重定向到 _runtime_cache/tools，导致 expanduser("~/burp_cookies.json")
    解析到不存在的位置（真实文件仍在用户目录）。这里按存在性双路回退：
      1) 当前 HOME 解析结果（若被重定向，即 _runtime_cache/tools/）；
      2) 真实用户目录（以系统盘 + 用户名重建，不受重定向影响）。
    任一存在即返回，均不存在时返回第 1 个候选（保持调用方报错路径可读）。
    """
    candidates = [os.path.expanduser("~/burp_cookies.json")]
    drive = os.environ.get("SystemDrive") or "C:"
    username = os.environ.get("USERNAME")
    if username:
        candidates.append(os.path.join(drive + os.sep, "Users", username, "burp_cookies.json"))
    for cand in candidates:
        try:
            if os.path.isfile(cand):
                return cand
        except OSError:
            continue
    return candidates[0]


def urlencode_payload(payload: str) -> str:
    return urllib.parse.quote(payload, safe='')


# ============================================================
# 平台自保护：凭据脱敏（安全审计——日志/导出中不得出现明文凭据）
# ============================================================
REDACT_MASK = "***REDACTED***"

_REDACT_RULES: Tuple[Tuple[re.Pattern, str], ...] = (
    # Authorization: Bearer/Basic <cred>
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*)(?:bearer|basic)\s+[A-Za-z0-9\-._~+/=]{4,}"),
     r"\1" + REDACT_MASK),
    # Set-Cookie / Cookie 头值
    (re.compile(r"(?i)\b(set-?cookie\s*:\s*)([^\r\n]+)"), r"\1" + REDACT_MASK),
    # key=value 形态凭据（api_key / token / password / client_secret ...）
    (re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
                r"secret[_-]?key|client[_-]?secret|password|passwd|pwd)(\s*[:=]\s*)"
                r"[\"']?([^\s\"'&,;]{4,})"), r"\1\2" + REDACT_MASK),
    # PEM 私钥块
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     REDACT_MASK),
)


def redact_secrets(text, mask: str = REDACT_MASK) -> str:
    """把文本中的明文凭据替换为掩码（日志/导出前调用）。

    覆盖：Authorization(Bearer/Basic)、Set-Cookie、api_key/secret/password/token
    等 key=value 形态、PEM 私钥块。
    **fail-open**：非字符串按 str() 处理、异常返回原文——脱敏失败绝不能吞掉日志内容。
    """
    try:
        if not isinstance(text, str):
            return "" if text is None else str(text)
        if not text:
            return text
        out = text
        for pat, repl in _REDACT_RULES:
            out = pat.sub(repl, out)
        return out
    except Exception:  # noqa: BLE001 - 脱敏失败必须原样放行
        return text if isinstance(text, str) else ""


def limit_response_size(text: str, max_len: int = 2000) -> str:
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    half = max_len // 2
    return text[:half] + "\n...[响应已截断]...\n" + text[-half:]


def cap(seq, limit: int):
    """按上限截断序列；limit<=0 表示不限制（最强模式默认）。"""
    _lst = list(seq)
    if not limit or limit <= 0:
        return _lst
    return _lst[:limit]


# ============================================================
# P1-5：云厂商实例元数据（IMDS）端点 —— 统一权威清单
# ============================================================
# 收敛背景：SSRF 引擎 / 云容器暴露引擎 / 业务逻辑引擎三处各自硬编码了 169.254.169.254
# 等云元数据端点，且厂商与路径互不一致（有的缺腾讯云/OpenStack，有的多写重复 AWS 路径）。
# 这里集中维护一份全厂商清单，供三处引用，保证覆盖范围一致、单点维护。
CLOUD_METADATA_ENDPOINTS = (
    # AWS EC2 IMDSv1（含常见敏感路径）
    ("http://169.254.169.254/latest/meta-data/", "AWS EC2 元数据"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM 凭证"),
    ("http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/", "AWS EC2 凭证"),
    ("http://169.254.169.254/latest/meta-data/user-data/", "AWS 用户数据"),
    ("http://169.254.169.254/latest/meta-data/local-ipv4", "AWS 本地 IP"),
    ("http://169.254.169.254/latest/meta-data/public-ipv4", "AWS 公网 IP"),
    ("http://169.254.169.254/latest/meta-data/hostname", "AWS 主机名"),
    ("http://169.254.169.254/latest/dynamic/instance-identity/", "AWS 实例身份"),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP 元数据"),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", "GCP 服务账号"),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2017-08-01", "Azure 元数据"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure 元数据(v2021)"),
    # 阿里云
    ("http://100.100.100.200/latest/meta-data/", "阿里云 ECS 元数据"),
    ("http://100.100.100.200/latest/meta-data/ram/security-credentials/", "阿里云 RAM 凭证"),
    # 腾讯云 / 通用（metadata/ 路径厂商区分度低，统一标注）
    ("http://169.254.169.254/metadata/", "云元数据(通用)"),
    ("http://169.254.169.254/metadata/v1/", "腾讯云/通用元数据"),
    # OpenStack
    ("http://169.254.169.254/openstack/latest/meta_data.json", "OpenStack 元数据"),
)


def compress_http_response(response_text: str, max_len: int = 1500) -> str:
    if not response_text:
        return ""
    if len(response_text) <= max_len:
        return response_text
    half = max_len // 2
    return response_text[:half] + "\n...[截断]...\n" + response_text[-half:]


def clean_ai_json(text: str) -> str:
    """从 AI 返回文本中提取 JSON - 修复：支持多对象解析"""
    if not text:
        return "{}"

    text = re.sub(r'```json\s*|\s*```', '', text)
    text = re.sub(r'```\s*|\s*```', '', text)

    # 先尝试直接解析
    # 解析崩溃修复：深层嵌套 JSON（如 "["*5000）会让 json.loads 抛 RecursionError，
    # 它继承自 RuntimeError 而非 JSONDecodeError，原实现只捕获后者 → 异常直接冒泡到
    # 调用方（AI 结构化输出清洗链路）导致整条链路崩溃。这里一并兜住。
    try:
        json.loads(text)
        return text
    except (json.JSONDecodeError, RecursionError):
        logger.debug("suppressed exception (core audit)")

    # 尝试修复尾部逗号等常见问题
    fixed = re.sub(r"'([^']+)':", r'"\1":', text)
    fixed = re.sub(r',\s*}', '}', fixed)
    fixed = re.sub(r',\s*]', ']', fixed)
    fixed = fixed.strip().lstrip('\ufeff')

    # 寻找第一个 JSON 对象或数组的开始位置
    start_idx = -1
    for i, ch in enumerate(fixed):
        if ch in '{[':
            start_idx = i
            break

    if start_idx == -1:
        return "{}"

    subset = fixed[start_idx:].strip()

    # 方法1：使用 JSONDecoder 尝试解析第一个完整对象
    decoder = json.JSONDecoder()
    try:
        obj, end_idx = decoder.raw_decode(subset)
        # 成功解析第一个对象，直接返回它
        return json.dumps(obj, ensure_ascii=False)
    except BaseException:
        logger.debug("suppressed exception (core audit)")

    # 方法2：贪婪匹配单个顶层对象（兼容旧逻辑）
    match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', subset, re.DOTALL)
    if match:
        try:
            obj = json.loads(match.group())
            return json.dumps(obj, ensure_ascii=False)
        except BaseException:
            logger.debug("suppressed exception (core audit)")

    # 方法3：贪婪匹配数组
    match = re.search(r'\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\]', subset, re.DOTALL)
    if match:
        try:
            obj = json.loads(match.group())
            return json.dumps(obj, ensure_ascii=False)
        except BaseException:
            logger.debug("suppressed exception (core audit)")

    return "{}"


def obfuscate_payload(payload: str, level: int = 1) -> str:
    if not payload or len(payload) < 3:
        return payload

    result = payload
    rand = random.random

    # 重要：本函数必须输出“原始字符”，不得做任何百分号预编码。
    # payload 最终会经 build_attack_url() 的 urlencode 统一编码一次；若此处预先把
    # '|' 编成 '%7c'、空格编成 '%0a'，urlencode 会把 '%' 再编成 '%25' → 双重编码
    # （'%257c'），服务端收到的是字面量 '%7c' 而非 '|'，注入直接失效。
    # 实测：混淆 payload 被服务端原样回显、返回正常行数；未混淆的 "'" 才正常触发
    # 500 + SQLite 报错。故此处只做“语义级”混淆，编码交给传输层做且只做一次。
    if rand() > 0.2:
        choices = ['/**/', '\n', '\r', '\t', '/*!*/', '/*!50000*/']
        result = result.replace(' ', random.choice(choices))

    if rand() > 0.3:
        chars = []
        for c in result:
            if c.isalpha() and rand() > 0.4:
                chars.append(c.upper() if rand() > 0.5 else c.lower())
            else:
                chars.append(c)
        result = ''.join(chars)

    if rand() > 0.5:
        result = result.replace('OR', '||')
        result = result.replace('AND', '&&')
        result = result.replace('<script>', '<scr<script>ipt>')

    return result


def load_cookie_file(cookie_path: str) -> Dict[str, str]:
    cookies = {}
    try:
        with open(cookie_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if '=' in line:
                    k, v = line.split('=', 1)
                    cookies[k.strip()] = v.strip()
    except BaseException:
        logger.debug("suppressed exception (core audit)")
    return cookies


def classify_severity(vuln_type: str, evidence: str = "", payload: str = "") -> str:
    vuln_lower = vuln_type.lower()
    evidence_lower = evidence.lower()

    critical_keywords = ['rce', '命令执行', '代码执行', '命令注入', 'cmdi', 'sql注入', 'sqli', '认证绕过', 'auth bypass', 'log4shell', 'jndi', '反序列化', 'deserialization', '权限提升', '越权', '越权访问', '权限绕过']
    if any(kw in vuln_lower or kw in evidence_lower for kw in critical_keywords):
        return "Critical"

    high_keywords = ['xss', '跨站脚本', 'ssrf', '敏感文件', 'file read', 'idor', '目录遍历', 'path traversal', '文件读取', 'git配置泄露', 'phpinfo', 'nginx状态']
    if any(kw in vuln_lower or kw in evidence_lower for kw in high_keywords):
        return "High"

    medium_keywords = ['csrf', 'open redirect', '开放重定向', '信息泄露', 'info leak', '缓存', 'csp', '安全头', 'security header', 'nosql', 'graphql注入', '参数污染', 'parameter pollution', '默认凭证', '文件上传', 'upload', 'cors']
    if any(kw in vuln_lower or kw in evidence_lower for kw in medium_keywords):
        return "Medium"

    info_keywords = ['graphql endpoint', 'graphiql', 'playground', 'jwt parse', '信息', 'info', 'endpoint', 'swagger', 'openapi', 'api-docs', 'graphql']
    if any(kw in vuln_lower or kw in evidence_lower for kw in info_keywords):
        return "Info"

    return "Low"


@lru_cache(maxsize=1000)
def score_asset_value_cached(
    url: str,
    status: int,
    content_type: str,
    content_length: int,
    tech_tuple: tuple = (),
    headers_tuple: tuple = ()
) -> int:
    score = 0

    if 200 <= status < 300:
        score += 20
    elif status in (401, 403):
        score += 15
    elif status == 404:
        score += 5
    else:
        score += 10

    if headers_tuple:
        headers = dict(headers_tuple)
        if headers.get('X-Powered-By') or headers.get('Server'):
            score += 8
        if headers.get('Set-Cookie'):
            score += 7

    keywords = ['api', 'admin', 'login', 'upload', 'dashboard', 'console',
                'config', 'system', 'gateway', 'portal', 'docs', 'swagger',
                'graphql', 'wp-admin', 'manage', 'panel', 'cpanel', 'git',
                'jenkins', 'grafana', 'prometheus', 'metrics', 'actuator']
    url_lower = url.lower()
    keyword_score = sum(15 if kw in url_lower else 0 for kw in keywords)
    score += min(25, keyword_score)

    if tech_tuple:
        score += min(15, len(tech_tuple) * 3)

    if '?' in url and '=' in url:
        score += 10
    if url.count('/') >= 4:
        score += 5

    if 2000 <= content_length <= 50000:
        score += 10
    elif 500 < content_length < 2000:
        score += 6
    elif content_length > 50000:
        score += 4
    elif content_length < 200:
        score += 2

    return min(100, score)


def score_asset_value(url, status=200, content_type='', content_length=0, tech_stack=None, headers=None):
    tech_tuple = tuple(tech_stack) if tech_stack else ()
    headers_tuple = tuple(sorted(headers.items())) if headers else ()
    return score_asset_value_cached(url, status, content_type, content_length, tech_tuple, headers_tuple)


# ============================================================
# 导出
# ============================================================
__all__ = [
    'async_get', 'async_post', 'async_put', 'async_delete', 'async_options',
    'sync_get', 'sync_post',
    'run_cmd_async',
    'get_tool_path', 'tool_exists',
    'resolve_hostnames',
    'detect_waf',
    'generate_mutated_requests',
    'build_attack_url', 'urlencode_payload',
    'limit_response_size', 'compress_http_response', 'clean_ai_json',
    'redact_secrets', 'REDACT_MASK',
    'obfuscate_payload', 'load_cookie_file',
    'classify_severity',
    'score_asset_value',
    'get_shared_session', 'close_shared_session'
]