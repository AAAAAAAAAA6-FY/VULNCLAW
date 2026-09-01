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

_SHARED_SESSION: Optional[aiohttp.ClientSession] = None
_SHARED_SESSION_LOCK = asyncio.Lock()
_LAST_TARGET: Optional[str] = None

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


def _atomic_write_json(file_path: Path, data: Dict) -> bool:
    """原子写入 JSON 文件：先写 .tmp，再 rename；自动创建备份。"""
    try:
        tmp_path = file_path.with_suffix('.tmp')
        bak_path = file_path.with_suffix('.json.bak')
        # 先备份现有文件（如果存在）
        if file_path.exists():
            try:
                shutil.copy2(file_path, bak_path)
            except Exception:
                pass
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
                        pass
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
            pass
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
    old_file = os.path.expanduser("~/burp_cookies.json")
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
                _atomic_write_json(cookie_file, filtered)
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
                logger.info(f"✅ 从备份恢复 Cookie: {backup_file}")
                # 恢复主文件
                _atomic_write_json(cookie_file, data)
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
    # 优化2：按 URL 类型分档超时（调用方显式传值时尊重调用方）
    if timeout is None:
        timeout = _timeout_for_url(url, settings.timeout)
    elif timeout == settings.timeout:
        timeout = _timeout_for_url(url, settings.timeout)

    await _global_rate_limit.acquire()

    proxy = kwargs.pop('proxy', None) or settings.proxy or _pool_active_proxy()
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


async def _read_response(resp: aiohttp.ClientResponse) -> Tuple[int, str, Dict]:
    content_length = resp.headers.get('Content-Length')
    if content_length:
        try:
            cl = int(content_length)
            if cl > MAX_RESPONSE_SIZE:
                raw = await resp.content.read(MAX_RESPONSE_SIZE)
                text = raw.decode('utf-8', errors='ignore')
                text += "\n... [截断: 响应体过大]"
                return resp.status, text, dict(resp.headers)
        except BaseException:
            pass

    try:
        raw = await resp.content.read(MAX_RESPONSE_SIZE + 1)
        if len(raw) > MAX_RESPONSE_SIZE:
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

    try:
        resp = requests.post(url, **kwargs)
        return resp.status_code, resp.text, dict(resp.headers)
    except Exception as e:
        return 0, str(e), {}


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


def _tp_download(url: str, dest: Path, tool_label: str) -> None:
    import urllib.request
    # 加 UA，否则一些 GitHub asset CDN 会 403
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "VULNCLAW-setup/0.1 (+https://github.com/AAAAAAAAAA6-FY/VULNCLAW)"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
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
                _tp_progress(tool_label, done, total_i)
    sys.stdout.write("\n")
    sys.stdout.flush()


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
        pass


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
            print(f"\n⬇️  {name:<20s} v{tool['ver']}  {url}")
            try:
                _tp_download(url, archive_path, f"{name} v{tool['ver']}")
                print(f"   ✔ 下载完成 ({archive_path.stat().st_size / 1024 / 1024:.2f} MB)")
                print(f"   🗜  提取 {bin_name} -> {dest_file}")
                _tp_extract(archive_path, tmpdir, bin_name, dest_file)
                ok += 1
                # 清缓存，避免后续 get_tool_path 还认为它不存在
                _TOOL_CACHE.pop(name, None)
            except Exception as e:
                fail += 1
                print(f"   ❌ 失败: {e}")
                if archive_path.exists():
                    try:
                        archive_path.unlink()
                    except Exception:
                        pass
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
    print("=" * 68)
    return ok, fail


def get_tool_path(tool_name: str) -> Optional[str]:
    if tool_name in _TOOL_CACHE:
        return _TOOL_CACHE[tool_name]

    path = shutil.which(tool_name)
    if path:
        _TOOL_CACHE[tool_name] = path
        return path

    third = os.path.join(settings.thirdparty_dir, tool_name)
    if os.path.exists(third):
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


def build_attack_url(base_url: str, param: str, payload: str, original_query: str = '') -> str:
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query) if parsed.query else {}
    if original_query and not qs:
        qs = parse_qs(original_query)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def urlencode_payload(payload: str) -> str:
    return urllib.parse.quote(payload, safe='')


def get_random_ua() -> str:
    if settings.user_agent and settings.user_agent != "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36":
        return settings.user_agent

    ua_list = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/122.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    ]
    return random.choice(ua_list)


def get_delay() -> float:
    return random.uniform(0.3, 1.0)


def limit_response_size(text: str, max_len: int = 2000) -> str:
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    half = max_len // 2
    return text[:half] + "\n...[响应已截断]...\n" + text[-half:]


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
    try:
        json.loads(text)
        return text
    except json.JSONDecodeError:
        pass

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
        pass

    # 方法2：贪婪匹配单个顶层对象（兼容旧逻辑）
    match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', subset, re.DOTALL)
    if match:
        try:
            obj = json.loads(match.group())
            return json.dumps(obj, ensure_ascii=False)
        except BaseException:
            pass

    # 方法3：贪婪匹配数组
    match = re.search(r'\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\]', subset, re.DOTALL)
    if match:
        try:
            obj = json.loads(match.group())
            return json.dumps(obj, ensure_ascii=False)
        except BaseException:
            pass

    return "{}"


def obfuscate_payload(payload: str, level: int = 1) -> str:
    if not payload or len(payload) < 3:
        return payload

    result = payload
    rand = random.random

    if rand() > 0.2:
        choices = ['/**/', '%0a', '%0d', '%09', '/*!*/', '/*!50000*/']
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
        result = result.replace('alert(', 'alert%28')
        result = result.replace(';', '%3b')
        result = result.replace('|', '%7c')

    if rand() > 0.6:
        encoded = ''
        for c in result:
            if c.isalnum() or c in ['/', '.', '-', '_']:
                encoded += c
            else:
                encoded += urllib.parse.quote(c)
        result = encoded

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
        pass
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
    'get_random_ua', 'get_delay',
    'limit_response_size', 'compress_http_response', 'clean_ai_json',
    'obfuscate_payload', 'load_cookie_file',
    'classify_severity',
    'score_asset_value',
    'get_shared_session', 'close_shared_session'
]