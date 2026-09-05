# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ============================================================
# 合并自: modules/alive.py
# ============================================================

# modules/alive.py
"""
存活探测模块 - 修复版 v2.3
修复：
1. 修正变量作用域错误（subs 未定义）
2. 增强空列表处理，避免无效操作
3. 优化超时控制，增加重试逻辑
4. 统一使用 settings.TMP_DIR
5. 修复末尾 try 缺少 except 的语法错误
"""

import os
import json
import socket
import time
import subprocess
import shutil
import requests
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings, TMP_DIR
from vulnclaw.core.tool_registry import run_tool

MAX_THREADS = settings.max_concurrent
COMPLIANT_THREADS = max(10, settings.max_concurrent // 4)
COMPLIANT_DELAY = 0.5 if settings.compliant else 0
TIMEOUT = settings.timeout
HTTPX_TIMEOUT = 15

HEADERS = {
    "User-Agent": settings.user_agent,
    "X-Bug-Bounty": "lyk20080208"
}

FINGERPRINTS = {
    'PHP': ['X-Powered-By: PHP', 'PHPSESSID'],
    'ASP.NET': ['X-AspNet-Version', '__VIEWSTATE'],
    'nginx': ['Server: nginx'],
    'Apache': ['Server: Apache'],
    'WordPress': ['wp-content', 'wp-json'],
    'Java': ['JSESSIONID', 'Servlet'],
}

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    80: "HTTP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 3389: "RDP", 5900: "VNC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 3000: "Node.js",
    5000: "Python/Flask", 7000: "Custom", 8000: "HTTP-Alt",
    9000: "PHP-FPM", 9200: "Elasticsearch"
}


def clean_subdomain(sub: str) -> str:
    if '://' in sub:
        sub = sub.split('://')[-1]
    if ':' in sub:
        sub = sub.split(':')[0]
    if '/' in sub:
        sub = sub.split('/')[0]
    return sub


def _run_cmd_safe(cmd: list, timeout: int = 300) -> tuple:
    if not isinstance(cmd, list):
        raise ValueError(f"cmd 必须为列表，收到: {type(cmd)}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8',
            errors='ignore'
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1
    except Exception as e:
        return "", str(e), -1


def _run_tool_sync(name: str, args: list, timeout: int = None) -> tuple:
    result = asyncio.run(run_tool(name, args=args, timeout=timeout))
    return (
        result.get("stdout", ""),
        result.get("stderr", result.get("error", "")),
        result.get("returncode", -1),
    )


def alive_scan(subdomains: list, compliant: bool = False) -> list:
    if not subdomains:
        logger.warning("子域名列表为空，跳过存活探测")
        return []

    cleaned_subs = []
    for sub in subdomains:
        cleaned = clean_subdomain(sub)
        if cleaned and cleaned not in cleaned_subs:
            cleaned_subs.append(cleaned)

    if not cleaned_subs:
        logger.warning("清洗后无有效子域名，跳过存活探测")
        return []

    total_count = len(cleaned_subs)
    logger.info(f"开始存活探测（共 {total_count} 个子域名）")

    max_workers = COMPLIANT_THREADS if compliant else MAX_THREADS
    delay = COMPLIANT_DELAY if compliant else 0
    alive = []  # 确保 alive 始终定义

    # 1. httpx
    if shutil.which("httpx"):
        logger.info("  [~] 使用 httpx 探测...")
        temp_subs = os.path.join(TMP_DIR, "_temp_subs.txt")
        try:
            with open(temp_subs, "w", encoding="utf-8") as f:
                for s in cleaned_subs:
                    f.write(s + "\n")

            stdout, stderr, code = _run_tool_sync(
                "httpx",
                ["-l", temp_subs],
                timeout=None,
            )

            if code == 0 and stdout:
                for line in stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        url = data.get("url", "")
                        status = data.get("status_code", 0)

                        if 200 <= status < 400 and status != 308:
                            tech = data.get("tech")
                            if tech is None:
                                tech = []
                            elif not isinstance(tech, list):
                                tech = [str(tech)] if tech else []

                            server = data.get("webserver", "") or data.get("server", "")
                            content_type = data.get("content_type", "") or ""

                            alive.append({
                                "url": url,
                                "status": status,
                                "title": data.get("title", "N/A") or "N/A",
                                "technologies": tech,
                                "server": server,
                                "content_type": content_type,
                                "content_length": data.get("content_length", 0) or 0
                            })
                    except BaseException:
                        continue

                if alive:
                    logger.info(f"  [+] httpx 发现 {len(alive)}/{total_count} 个存活")
                    return alive
        except Exception as e:
            logger.warning(f"  ⚠️ httpx 探测异常: {e}")
        finally:
            if os.path.exists(temp_subs):
                try:
                    os.remove(temp_subs)
                except BaseException:
                    logger.debug("suppressed exception (core audit)")

    # 2. httprobe
    if shutil.which("httprobe"):
        logger.info("  [~] 使用 httprobe 探测...")
        temp_subs = os.path.join(TMP_DIR, "_temp_subs_httprobe.txt")
        try:
            with open(temp_subs, "w", encoding="utf-8") as f:
                for s in cleaned_subs:
                    f.write(s + "\n")

            with open(temp_subs, 'r', encoding="utf-8") as stdin_file:
                stdin_data = stdin_file.read()

            result = asyncio.run(
                run_tool(
                    "httprobe",
                    args=["-c", "50", "-t", str(HTTPX_TIMEOUT * 1000)],
                    stdin_text=stdin_data,
                    timeout=120,
                )
            )
            success = result.get("success", False)
            stdout = result.get("output", "") or ""

            if success and stdout:
                for line in stdout.splitlines():
                    url = line.strip()
                    if url.startswith(('http://', 'https://')):
                        alive.append({
                            "url": url,
                            "status": 200,
                            "title": "N/A",
                            "technologies": [],
                            "server": "",
                            "content_type": "",
                            "content_length": 0
                        })

                if alive:
                    logger.info(f"  [+] httprobe 发现 {len(alive)}/{total_count} 个存活")
                    return alive
        except Exception as e:
            logger.warning(f"  ⚠️ httprobe 探测异常: {e}")
        finally:
            if os.path.exists(temp_subs):
                try:
                    os.remove(temp_subs)
                except BaseException:
                    logger.debug("suppressed exception (core audit)")

    # 3. 内置探测（慢速）
    logger.info("  [~] 使用内置探测（慢速）...")
    subs_to_probe = cleaned_subs
    logger.info(f"      内置探测将处理全部 {len(subs_to_probe)} 个子域名")

    if len(subs_to_probe) > 500:
        logger.info(f"      ⚠️ 子域名数量较多（{len(subs_to_probe)} 个），内置探测可能较慢")

    def check_one(sub):
        for scheme in ['https', 'http']:
            url = f"{scheme}://{sub}"
            if delay > 0:
                time.sleep(delay)
            try:
                r = requests.get(
                    url,
                    headers=HEADERS,
                    timeout=TIMEOUT,
                    verify=False,
                    allow_redirects=False
                )
                title = 'N/A'
                if '<title>' in r.text:
                    start = r.text.find('<title>') + 7
                    end = r.text.find('</title>', start)
                    title = r.text[start:end].strip() if end != -1 else 'N/A'

                combined = '\n'.join([f"{k}: {v}" for k, v in r.headers.items()]) + r.text[:2000]
                techs = []
                for tech, patterns in FINGERPRINTS.items():
                    for p in patterns:
                        if p in combined:
                            techs.append(tech)
                            break

                return {
                    "url": url,
                    "status": r.status_code,
                    "title": title,
                    "technologies": techs,
                    "server": r.headers.get('Server', ''),
                    "content_type": r.headers.get('Content-Type', ''),
                    "content_length": len(r.text)
                }
            except BaseException:
                logger.debug("suppressed exception (core audit)")
        return None

    with tqdm(total=len(subs_to_probe), desc="探测存活") as pbar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_one, sub): sub for sub in subs_to_probe}
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res:
                        alive.append(res)
                except Exception as e:
                    logger.debug(f"内置探测异常: {e}")
                pbar.update(1)

    logger.info(f"[+] 存活 Web 资产: {len(alive)} 个")
    return alive


__all__ = ['alive_scan', 'port_scan']

# ============================================================
# 合并自: modules/subdomain.py
# ============================================================

# modules/subdomain.py
"""
子域名收集模块 - 修复版 v2.2
修复：
1. 增加超时时间（60s → 120s），减少超时概率
2. 改进错误处理，避免因超时导致变量未定义
3. 增加空列表保护
4. 优化工具调用异常捕获
"""

import os
import time
import dns.resolver
import concurrent.futures
import random
import json
import aiohttp
import asyncio
import subprocess
import requests
import uuid
from concurrent.futures import ThreadPoolExecutor
from vulnclaw.core.utils import get_tool_path
from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings, TMP_DIR

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MAX_THREADS = settings.max_concurrent
COMPLIANT_THREADS = max(10, settings.max_concurrent // 4)
COMPLIANT_DELAY = 0.5 if settings.compliant else 0
DNS_TIMEOUT = 5
SUB_TIMEOUT = 120  # 从 60 提高到 120
ASSET_TIMEOUT = 120
DNS_SLEEP_MIN = 0.3
DNS_SLEEP_MAX = 0.8
BRUTE_LIMIT = 500

SUBfinder_PATH = get_tool_path("subfinder") or os.path.join(BASE_DIR, "thirdparty", "subfinder")
ASSETFINDER_PATH = get_tool_path("assetfinder") or os.path.join(BASE_DIR, "thirdparty", "assetfinder")

API_SUBDOMAINS = [
    "api", "graphql", "auth", "oauth", "login", "signin", "signup",
    "cdn", "static", "assets", "media", "files", "uploads",
    "dev", "test", "staging", "qa", "uat", "preprod", "sandbox",
    "console", "dashboard", "portal", "gateway", "proxy",
    "v1", "v2", "v3", "v4", "v5", "v6",
    "admin", "manage", "control", "system", "ops",
    "monitor", "metrics", "logs", "trace", "debug",
    "docs", "swagger", "redoc", "openapi", "graphiql",
]


def _is_internal_domain(domain: str) -> bool:
    """快速判断"该目标没必要调公网 OTX/crt/urlscan"。
    判断为 True 时，公网 API 阶段直接短路返回空，避免 5×指数退避浪费 2~5 分钟。
    命中条件（任一）：
      - 纯 IP 且是 127.0.0.0/8 / 10.0.0.0/8 / 172.16.0.0/12 / 192.168.0.0/16 / ::1 / fc00::/7
      - 主机名不含 '.' （纯内网 hostname）
      - 结尾是 .local / .localhost / .internal / .corp / .lan / .intranet（常见内网 TLD）
    """
    if not domain:
        return True
    d = domain.strip().lower()
    if '.' not in d:
        return True
    for pseudo_tld in ('.local', '.localhost', '.internal', '.corp', '.lan', '.intranet'):
        if d.endswith(pseudo_tld):
            return True
    # IP 判定（v4 / v6）
    try:
        import ipaddress as _ip
        ip = _ip.ip_address(d.rstrip('.'))
        return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified
    except (ValueError, TypeError):
        logger.debug("suppressed exception (core audit)")
    return False


def get_otx_with_retry(domain: str, max_retries: int = 5) -> dict:
    """查询 AlienVault OTX API，带指数退避重试。内网目标短路返回 None。"""
    if _is_internal_domain(domain):
        logger.info(f"  OTX 跳过（内网目标: {domain}）")
        return None
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    for attempt in range(max_retries):
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 429:
                wait = min(5 ** attempt, 60)
                logger.warning(f"  OTX API 限流 (429)，等待 {wait}s (尝试 {attempt + 1}/{max_retries})")
                time.sleep(wait)
                continue
            else:
                return None
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            return None
        except Exception as e:
            logger.warning(f"  OTX API 异常: {e}")
            return None
    return None


async def _fetch_ct_subdomains(domain: str) -> list:
    """从 crt.sh 获取历史证书中的子域名。内网目标短路空。"""
    if _is_internal_domain(domain):
        logger.info(f"  crt.sh 跳过（内网目标: {domain}）")
        return []
    subdomains = set()
    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get('name_value')
                        if name and not name.startswith('*'):
                            for sub in name.split('\n'):
                                sub = sub.strip()
                                if sub.endswith(f".{domain}") and sub != domain:
                                    subdomains.add(sub)
    except Exception as e:
        logger.warning(f"CT 子域名查询失败: {e}")
    return list(subdomains)


async def run_subfinder_async(domain: str, timeout: int = SUB_TIMEOUT) -> list:
    """异步执行 subfinder，使用列表传参，临时文件用 uuid"""
    if not SUBfinder_PATH or not os.path.exists(SUBfinder_PATH):
        logger.debug("subfinder 未找到或不可用")
        return []

    output_file = os.path.join(TMP_DIR, f"subfinder_{uuid.uuid4().hex[:8]}.txt")
    try:
        result = await run_tool(
            "subfinder",
            args=[
                "-d", domain,
                "-timeout", str(timeout),
                "-o", output_file,
            ],
            timeout=timeout + 10,
        )
        code = result.get("returncode", -1)
        result.get("stdout", "")
        result.get("stderr", result.get("error", ""))
        subs = []
        if os.path.exists(output_file):
            with open(output_file, 'r', encoding='utf-8') as f:
                subs = [line.strip() for line in f if line.strip()]
            os.remove(output_file)
        if code != 0 and code != -1:
            logger.warning(f"Subfinder 执行失败，返回码 {code}")
        return subs
    except Exception as e:
        logger.warning(f"Subfinder 执行异常: {e}")
        return []


async def run_assetfinder_async(domain: str, timeout: int = ASSET_TIMEOUT) -> list:
    """异步执行 assetfinder - 统一走 core.tool_registry.run_tool"""
    if not ASSETFINDER_PATH or not os.path.exists(ASSETFINDER_PATH):
        logger.debug("assetfinder 未找到或不可用")
        return []

    try:
        result = await run_tool(
            "assetfinder",
            args=["-subs-only", domain],
            timeout=timeout + 10,
        )
        if result.get("returncode") == 0:
            out = result.get("output", "") or ""
            subs = [line.strip() for line in out.splitlines() if line.strip()]
            return subs
    except Exception as e:
        logger.warning(f"Assetfinder 执行失败: {e}")
    return []


def _resolve_wordlist_path(wordlist: str) -> str:
    """Resolve reorganized and legacy dictionary locations in priority order."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    filename = os.path.basename(wordlist)
    if filename == "subdomains_top5000.txt" and not os.path.isabs(wordlist):
        candidates = [
            os.path.join(project_root, "core", "data", filename),
            os.path.join(project_root, "thirdparty", filename),
            wordlist,
        ]
    else:
        candidates = [wordlist]
        if not os.path.isabs(wordlist):
            candidates.extend([
                os.path.join(project_root, wordlist),
                os.path.join(project_root, "core", "data", wordlist),
                os.path.join(project_root, "thirdparty", wordlist),
            ])

    for candidate in dict.fromkeys(candidates):
        if os.path.isfile(candidate):
            return candidate
    return wordlist


def brute_force_subdomains(domain: str, wordlist: str = "subdomains_top5000.txt", limit: int = BRUTE_LIMIT) -> list:
    """
    DNS 暴力枚举（同步版本，使用线程池）
    修复：增加超时控制
    """
    found = []
    wordlist = _resolve_wordlist_path(wordlist)

    if not os.path.exists(wordlist):
        common_subs = list(settings.common_dirs) if settings.common_dirs else []
        common_subs.extend(API_SUBDOMAINS)
        common_subs = list(dict.fromkeys(common_subs))
        priority_keywords = ['api', 'graphql', 'auth', 'oauth', 'login', 'cdn', 'static']
        common_subs.sort(key=lambda x: (0 if x in priority_keywords else 1, x))
        subs = common_subs[:limit]
        logger.info(f"✅ 使用增强字典（{len(subs)} 个条目，含 API 子域）")
    else:
        with open(wordlist, 'r', encoding='utf-8') as f:
            all_subs = [line.strip() for line in f if line.strip()]
        subs = list(dict.fromkeys(all_subs))[:limit]
        logger.info(f"✅ 使用字典文件 {wordlist}（{len(subs)} 个条目）")

    logger.info(f"加载 {len(subs)} 个高频子域名，开始慢速爆破...")
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    def check(sub):
        full = f"{sub}.{domain}"
        time.sleep(random.uniform(DNS_SLEEP_MIN, DNS_SLEEP_MAX))
        try:
            answers = resolver.resolve(full, 'A')
            if answers:
                return full
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            logger.debug("suppressed exception (core audit)")
        except Exception:
            logger.debug("suppressed exception (core audit)")
        return None

    max_workers = min(MAX_THREADS // 2, 10)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check, sub) for sub in subs]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                found.append(res)

    logger.info(f"DNS 爆破完成，命中 {len(found)} 个")
    return found


async def get_subdomains_async(domain: str, compliant: bool = True, skip_subfinder: bool = False) -> list:
    """异步主流程：工具扫描 + DNS爆破 + CT + 公开API"""
    logger.info(f"🔍 开始收集子域名: {domain}")
    final_subs = set()

    # 0. 取当前 loop，之后统一用 loop.run_in_executor 替代 asyncio.to_thread
    try:
        _loop = asyncio.get_running_loop()
    except RuntimeError:
        _loop = None

    def _offload(fn, *args, **kwargs):
        """兼容版：有 loop → run_in_executor；没 loop → 同步跑（容错）"""
        if _loop is not None:
            return _loop.run_in_executor(None, lambda: fn(*args, **kwargs))
        # 降级：同步执行（仅在意外情况下）
        future = asyncio.Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except Exception as e:
            future.set_exception(e)
        return future

    # 1. 工具扫描（内网目标跳过：subfinder/assetfinder 无法发现回环/私网伪域）
    # 无损加速：subfinder/assetfinder 不再单独成阶段，与 DNS 爆破/CT/API 一起并发。
    async def _collect_subfinder() -> list:
        if skip_subfinder or _is_internal_domain(domain):
            return []
        try:
            result = await asyncio.wait_for(run_subfinder_async(domain, SUB_TIMEOUT), timeout=100.0)
            return result if isinstance(result, list) else []
        except asyncio.TimeoutError:
            logger.warning("  Subfinder 超时 (100s)，跳过该数据源")
            return []
        except Exception as e:
            logger.warning(f"  Subfinder 协程异常: {e}")
            return []

    async def _collect_assetfinder() -> list:
        if _is_internal_domain(domain):
            return []
        try:
            result = await asyncio.wait_for(run_assetfinder_async(domain, ASSET_TIMEOUT), timeout=100.0)
            return result if isinstance(result, list) else []
        except asyncio.TimeoutError:
            logger.warning("  Assetfinder 超时 (100s)，跳过该数据源")
            return []
        except Exception as e:
            logger.warning(f"  Assetfinder 协程异常: {e}")
            return []

    # 无损加速：DNS 爆破 / crt.sh / OTX+Urlscan 独立数据源并发执行，
    # 墙钟时间从 sum(t) 降为 max(t)；各源独立硬超时，单源超时不拖垮整体。
    async def _collect_brute() -> list:
        if _is_internal_domain(domain):
            logger.info(f"  DNS 暴力枚举跳过（内网目标: {domain}）")
            return []
        try:
            brute = await asyncio.wait_for(
                _offload(brute_force_subdomains, domain, "subdomains_top5000.txt", BRUTE_LIMIT),
                timeout=100.0,
            )
            return list(brute or [])
        except asyncio.TimeoutError:
            logger.warning("  DNS 爆破总超时 (100s)，跳过该数据源")
            return []
        except Exception as e:
            logger.warning(f"  DNS 爆破失败: {e}")
            return []

    async def _collect_ct() -> list:
        try:
            # crt.sh 高峰期可能挂起，45s 硬超时（该源为补充源，超时无伤）
            return await asyncio.wait_for(_fetch_ct_subdomains(domain), timeout=45.0)
        except asyncio.TimeoutError:
            logger.warning("  CT 查询超时 (45s)，跳过该数据源")
            return []
        except Exception as e:
            logger.warning(f"CT 查询失败: {e}")
            return []

    async def _collect_apis() -> set:
        api_subs: set = set()
        if _is_internal_domain(domain):
            logger.info(f"  目标 {domain} 判定为内网/回环/私网，跳过 OTX + Urlscan 公网 API 查询")
            return api_subs
        try:
            # 修复：OTX 429 指数退避最坏可累计 ~235s，整体包 60s 硬超时，超时即放弃该数据源
            otx_data = await asyncio.wait_for(
                _offload(get_otx_with_retry, domain, 2), timeout=60.0
            )
            if otx_data:
                for record in otx_data.get('passive_dns', []):
                    if 'hostname' in record:
                        api_subs.add(record['hostname'])
                logger.info(f"  OTX 新增 {len(otx_data.get('passive_dns', []))} 条记录")
        except asyncio.TimeoutError:
            logger.warning("  OTX API 总超时 (60s)，跳过该数据源")
        except Exception as e:
            logger.warning(f"  OTX API 失败: {e}")
        return api_subs

    def _query_urlscan(domain_target: str):
        if _is_internal_domain(domain_target):
            return None, set()
        try:
            resp = requests.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain_target}",
                timeout=15
            )
            if resp.status_code == 200:
                payload = resp.json()
                found = set()
                for res in payload.get('results', []):
                    if 'page' in res and 'domain' in res['page']:
                        found.add(res['page']['domain'])
                return None, found
            return resp.status_code, set()
        except Exception as e:
            return str(e), set()

    async def _collect_urlscan() -> set:
        if _is_internal_domain(domain):
            return set()
        try:
            urlscan_status, us_subs = await asyncio.wait_for(
                _offload(_query_urlscan, domain), timeout=20.0
            )
            if isinstance(urlscan_status, int) and urlscan_status != 200:
                logger.warning(f"  Urlscan API 返回 {urlscan_status}")
            elif isinstance(urlscan_status, str):
                logger.warning(f"  Urlscan API 失败: {urlscan_status}")
            else:
                return set(us_subs)
        except asyncio.TimeoutError:
            logger.warning("  Urlscan API 超时 (20s)，跳过该数据源")
        except Exception as e:
            logger.warning(f"  Urlscan API offload 失败: {e}")
        return set()

    # 2. 全部 6 个数据源（Subfinder/Assetfinder/DNS爆破/crt.sh/OTX/Urlscan）单阶段并发，
    # 墙钟 = max(各源) ≈ 100s，且远低于上层 120s 硬超时——修复了旧版两阶段串行
    # （subfinder 120s + 其余 100s）导致的超时丢数据问题。
    logger.info("  [并发] Subfinder + Assetfinder + DNS爆破 + crt.sh + OTX + Urlscan 全源并发...")
    sub_result, ass_result, brute_result, ct_subs, api_subs, us_subs = await asyncio.gather(
        _collect_subfinder(),
        _collect_assetfinder(),
        _collect_brute(),
        _collect_ct(),
        _collect_apis(),
        _collect_urlscan(),
    )
    final_subs.update(sub_result)
    final_subs.update(ass_result)
    logger.info(f"  工具扫描发现: {len(sub_result)} + {len(ass_result)} 个")
    final_subs.update(brute_result)
    final_subs.update(ct_subs)
    final_subs.update(api_subs)
    final_subs.update(us_subs)
    logger.info(f"  DNS 爆破新增: {len(brute_result)} 个")
    logger.info(f"  CT 日志新增: {len(ct_subs)} 个")
    logger.info(f"  公开 API 新增: {len(api_subs) + len(us_subs)} 个")

    final_list = list(final_subs)
    logger.info(f"✅ 共收集到 {len(final_list)} 个去重子域名")
    return final_list


async def get_subdomains_batch_async(domains: List[str], compliant: bool = True,
                                     max_api_concurrent: int = 5) -> Dict[str, list]:
    """批量子域名收集（P0-4）：
    - subfinder 用 -dL 单进程批量扫描全部目标（减少进程启动与连接开销）
    - 其余数据源（assetfinder/DNS爆破/crt.sh/OTX/urlscan）按目标限并发
    - 返回 {domain: [subdomains]}（已去重合并）
    """
    if not domains:
        return {}
    logger.info(f"🔍 [BATCH-SUB] 批量子域名收集: {len(domains)} 个目标")
    subfinder_subs = await _run_subfinder_batch_async(domains)
    sem = asyncio.Semaphore(max_api_concurrent)

    async def _one(domain: str):
        async with sem:
            subs = await get_subdomains_async(domain, compliant, skip_subfinder=True)
            return domain, subs

    results: Dict[str, list] = {d: [] for d in domains}
    gathered = await asyncio.gather(*[_one(d) for d in domains], return_exceptions=True)
    for r in gathered:
        if isinstance(r, tuple):
            d, subs = r
            merged = list(set(list(subfinder_subs.get(d, [])) + list(subs or [])))
            results[d] = merged
            logger.info(f"✅ [BATCH-SUB] {d}: {len(merged)} 个子域名")
    return results


async def _run_subfinder_batch_async(domains: List[str]) -> Dict[str, list]:
    """subfinder -dL 批量模式：单进程扫描全部目标，按根域后缀归类返回。"""
    result: Dict[str, list] = {d: [] for d in domains}
    public = [d for d in domains if not _is_internal_domain(d)]
    if not public or not SUBfinder_PATH or not os.path.exists(SUBfinder_PATH):
        return result
    tmp_file = ""
    output_file = os.path.join(TMP_DIR, f"subfinder_batch_{uuid.uuid4().hex[:8]}.txt")
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("\n".join(public))
            tmp_file = f.name
        await asyncio.wait_for(
            run_tool(
                "subfinder",
                args=["-dL", tmp_file, "-timeout", str(SUB_TIMEOUT), "-o", output_file],
                timeout=SUB_TIMEOUT + 15,
            ),
            timeout=SUB_TIMEOUT + 15,
        )
        raw: List[str] = []
        if os.path.exists(output_file):
            with open(output_file, 'r', encoding='utf-8') as f:
                raw = [line.strip() for line in f if line.strip()]
            try:
                os.remove(output_file)
            except Exception:
                logger.debug("suppressed exception (core audit)")
        for sub in raw:
            for d in public:
                if sub == d or sub.endswith("." + d):
                    result.setdefault(d, []).append(sub)
                    break
        logger.info(f"  [BATCH-SUB] subfinder -dL 发现 {len(raw)} 个子域名")
    except asyncio.TimeoutError:
        logger.warning("  [BATCH-SUB] subfinder 批量超时，回退逐域收集")
    except Exception as e:
        logger.warning(f"  [BATCH-SUB] subfinder 批量失败: {e}")
    finally:
        if tmp_file:
            try:
                os.unlink(tmp_file)
            except Exception:
                logger.debug("suppressed exception (core audit)")
    return result


def get_subdomains(domain: str, compliant: bool = True) -> list:
    """同步入口：不依赖调用方 loop，自己独立 loop 跑。"""
    def _run():
        try:
            import uvloop  # type: ignore
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        except ImportError:
            logger.debug("suppressed exception (core audit)")
        return asyncio.run(get_subdomains_async(domain, compliant))

    # 如果当前线程已在运行 loop（比如被 to_thread/run_in_executor 丢进来的 worker 线程）：
    # 直接 asyncio.run 会更简单、更稳定（每个 run() 创建全新独立 loop）
    try:
        asyncio.get_running_loop()
        # 有运行中的 loop — 另起一个全新线程执行 asyncio.run，彻底隔离
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(_run).result(timeout=max(SUB_TIMEOUT * 2 + 60, 300))
    except RuntimeError:
        return _run()


__all__ = ['get_subdomains', 'get_subdomains_async']

# ============================================================
# 合并自: modules/port_scan.py
# ============================================================

# modules/port_scan.py
"""
端口扫描模块 - 修复版 v2.2
修复：
1. 🔥 移除 run_command（shell=True），改用 run_cmd_async（列表传参）
2. 增强 nmap 输出解析，处理 filtered/closed 状态
3. 内置扫描改用异步 socket（asyncio.open_connection）
4. 增加超时控制
"""
import shutil
import asyncio
import tempfile
import os
import re
from typing import Any, Dict, List, Optional, Set

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings


class PortScanner:
    def __init__(self):
        self.tool = getattr(settings, 'port_scan_tool', 'nmap')
        self.ports = getattr(settings, 'port_scan_ports', "80,443,8080,8443,3000,5000,7000,8000,9000,3306,5432,6379,9200,27017")
        self.rate = getattr(settings, 'port_scan_rate', 1000)

    async def _scan_with_nmap(self, hosts: List[str]) -> Set[int]:
        """使用 nmap 扫描（异步安全）"""
        if not shutil.which("nmap"):
            return set()

        # 使用临时文件存储主机列表
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as f:
            for h in hosts:
                f.write(h + "\n")
            tmpfile = f.name

        try:
            result = await run_tool(
                "nmap",
                args=[
                    "-p", self.ports, "-sS", "-T5",
                    "--min-rate", str(self.rate), "-iL", tmpfile,
                    "-oG", "-", "--host-timeout", "30",
                ],
            )
            code = result.get("returncode", -1)
            stdout = result.get("stdout", "")
            result.get("stderr", result.get("error", ""))
            ports = set()
            if code == 0:
                for line in stdout.splitlines():
                    if "Ports:" in line:
                        ports_part = line.split("Ports:")[1].strip()
                        if not ports_part:
                            continue
                        for p in ports_part.split(","):
                            p = p.strip()
                            if not p:
                                continue
                            if "/" in p:
                                port_str = p.split("/")[0].strip()
                                if port_str and port_str.isdigit():
                                    ports.add(int(port_str))
                            elif p.isdigit():
                                ports.add(int(p))
            return ports
        except Exception as e:
            logger.warning(f"nmap 扫描异常: {e}")
            return set()
        finally:
            if os.path.exists(tmpfile):
                try:
                    os.unlink(tmpfile)
                except BaseException:
                    logger.debug("suppressed exception (core audit)")

    async def _scan_socket(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """异步 socket 连接测试"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except BaseException:
            return False

    async def scan(self, hosts: List[str]) -> Set[int]:
        if not hosts:
            return set()

        # 优先使用 nmap
        if self.tool == "nmap" and shutil.which("nmap"):
            return await self._scan_with_nmap(hosts)

        # ICMP 前置存活检查（尽力而为；ping 失败不阻断，回退全量 TCP 探测）
        alive_hosts = []
        for host in hosts:
            if await self._ping_host(host):
                alive_hosts.append(host)
        if alive_hosts:
            hosts = alive_hosts

        # 降级：异步 socket 扫描
        #   - asyncio.Semaphore(200) 限制并发，避免被防火墙判定为 DoS
        #   - 随机 jitter 0.1~0.5s 打散请求节奏
        logger.info("  [~] nmap 未安装或不可用，使用内置异步 socket 扫描...")
        ports_set = set()
        port_list = [int(p.strip()) for p in self.ports.split(",") if p.strip().isdigit()]
        if not port_list:
            return ports_set
        semaphore = asyncio.Semaphore(200)

        async def _probe(host: str, port: int) -> bool:
            async with semaphore:
                await asyncio.sleep(random.uniform(0.1, 0.5))
                return await self._scan_socket(host, port, timeout=1.0)

        results = await asyncio.gather(
            *(_probe(h, p) for h in hosts for p in port_list),
            return_exceptions=True,
        )
        for idx, result in enumerate(results):
            if result is True:
                ports_set.add(port_list[idx % len(port_list)])
        return ports_set

    @staticmethod
    async def _ping_host(host: str) -> bool:
        """ICMP 存活探测（尽力而为，失败返回 True 走 TCP 兜底）。"""
        try:
            loop = asyncio.get_running_loop()
            return await asyncio.wait_for(
                loop.run_in_executor(None, PortScanner._ping_sync, host),
                timeout=2.5,
            )
        except Exception:
            return True

    @staticmethod
    def _ping_sync(host: str) -> bool:
        try:
            import subprocess
            cmd = ["ping", "-n", "1", "-w", "500", host] if os.name == "nt" else ["ping", "-c", "1", "-W", "1", host]
            result = subprocess.run(cmd, capture_output=True, timeout=2)
            return result.returncode == 0
        except Exception:
            return True


# ===== 对外接口（同步包装，保持兼容） =====
def port_scan(ip: str, compliant: bool = True) -> List[int]:
    """
    端口扫描，返回开放端口列表（同步包装）。

    修复：
      - 严格区分"当前线程有没有在运行的事件循环"
      - 如果当前在 async 线程（被 run_in_executor/to_thread 从主协程池丢进来），
        直接在当前线程用 asyncio.run() 开一个新的独立事件循环；
        避免调用 asyncio.get_event_loop() 触发 Deprecation / 或拿到外层 loop
        导致 "There is no current event loop in thread 'asyncio_0'"。
    """
    def _run_async_scan(target: str) -> Set[int]:
        # 跑在新线程，自己创建一个独立 loop
        try:
            return asyncio.run(PortScanner().scan([target]))
        except Exception as e:
            logger.warning(f"  ⚠️ PortScanner.scan 内部异常: {e}")
            return set()

    try:
        # 先判断当前线程是否存在运行的 loop
        asyncio.get_running_loop()
        # 有正在运行的 loop：必须开一个新线程执行 asyncio.run
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_run_async_scan, ip)
            ports = future.result(timeout=300)
    except RuntimeError:
        # 没有运行中的 loop：直接 asyncio.run
        ports = _run_async_scan(ip)
    except Exception as e:
        logger.warning(f"  ⚠️ 端口扫描外层异常: {e}")
        ports = set()

    return sorted(list(ports or []))


def port_scan_detailed(ip: str, compliant: bool = True) -> List[Dict[str, Any]]:
    """端口扫描详细版（含 Banner）"""
    ports = port_scan(ip, compliant)
    details = []
    for port in ports:
        detail = banner_grab(ip, port)
        details.append(detail)
    return details


def banner_grab(ip: str, port: int, timeout: int = 3) -> Dict[str, Any]:
    """抓取 Banner（同步，保持原样）"""
    result = {"port": port, "service": "unknown", "banner": "", "version": ""}
    service_handlers = {
        21: ("FTP", b"220"),
        22: ("SSH", b""),
        23: ("Telnet", b""),
        25: ("SMTP", b"HELO\r\n"),
        80: ("HTTP", b"HEAD / HTTP/1.0\r\n\r\n"),
        443: ("HTTPS", b"HEAD / HTTP/1.0\r\n\r\n"),
        3306: ("MySQL", b"\x00\x00\x00\x0a\x0a\x00\x00\x00\x00\x00\x00\x00"),
        5432: ("PostgreSQL", b"\x00\x00\x00\x08\x04\xd2\x16\x2f"),
        6379: ("Redis", b"PING\r\n"),
        27017: ("MongoDB", b""),
        3389: ("RDP", b""),
        5900: ("VNC", b""),
    }
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port in service_handlers:
            send_data = service_handlers[port][1]
            if send_data:
                sock.send(send_data)
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        if banner:
            result["banner"] = banner
            if port in service_handlers:
                result["service"] = service_handlers[port][0]
            # 版本提取（简化）
            if "SSH" in banner:
                match = re.search(r'SSH-([\d.]+)', banner)
                if match:
                    result["version"] = match.group(1)
            elif "MySQL" in banner:
                match = re.search(r'(\d+\.\d+\.\d+)', banner)
                if match:
                    result["version"] = match.group(1)
    except Exception as e:
        result["banner"] = f"Error: {str(e)}"
    return result


__all__ = ['PortScanner', 'port_scan', 'port_scan_detailed', 'banner_grab']

# ============================================================
# 合并自: modules/endpoint_collector.py
# ============================================================

# modules/endpoint_collector.py
"""
端点自动收集器 - 整合子域名爬取、历史数据、JS端点，统一去重
修复：保留 .json/.xml 等标准 API 后缀
"""
import asyncio
import subprocess
import json
import re
import shutil
from urllib.parse import urljoin, urlparse, urlunparse

from vulnclaw.core.logger import logger
from vulnclaw.core.tool_registry import run_tool

# ============================================================
# E3.3: 纯 HTTP 兜底爬虫——零外部工具依赖（方案③）
# 外部工具（waybackurls/gau/gospider/katana 等）缺失或失效时，
# 仍能从主站 HTML 提取站内链接，保证端点收集不归零。
# ============================================================
_LINK_ATTR_RE = re.compile(r'(?:href|src|action|data-src)\s*=\s*["\']([^"\']+)["\']', re.I)
_SRCSET_RE = re.compile(r'srcset\s*=\s*["\']([^"\']+)["\']', re.I)


def _extract_links_from_html(html: str) -> list:
    """从 HTML 提取候选链接：href/src/action/data-src + srcset 逗号列表。

    纯正则、零依赖；供 _fallback_crawl 在外部工具全部不可用时兜底。
    """
    links = []
    for m in _LINK_ATTR_RE.finditer(html or ""):
        links.append(m.group(1))
    for m in _SRCSET_RE.finditer(html or ""):
        for part in m.group(1).split(","):
            cand = part.strip().split(" ")[0] if part.strip() else ""
            if cand:
                links.append(cand)
    return links


def _normalize_url(base: str, link: str) -> str:
    """相对链接解析为同协议绝对 URL；过滤伪协议与锚点，去 fragment，返回规范化 URL 或空串。"""
    link = (link or "").strip().strip('"').strip("'")
    if not link or link.startswith(("#", "mailto:", "tel:", "javascript:", "data:", "about:")):
        return ""
    if link.startswith("//"):
        link = f"{urlparse(base).scheme}:{link}"
    try:
        if not link.startswith(("http://", "https://")):
            link = urljoin(base, link)
        u = urlparse(link)
        if u.scheme not in ("http", "https"):
            return ""
        return urlunparse((u.scheme, u.netloc, u.path, u.params, u.query, ""))
    except ValueError:
        return ""



class EndpointCollector:
    def __init__(self, session=None, burp_client=None):
        self.session = session
        self.burp_client = burp_client
        self.cdn_info = None
        self._tool_stats = {
            "waybackurls": {"available": False, "found": 0},
            "gau": {"available": False, "found": 0},
            "katana": {"available": False, "found": 0},
            "waybackrobots": {"available": False, "found": 0},
            "gospider": {"available": False, "found": 0},
            "cdncheck": {"available": False, "found": 0},
            "unfurl": {"available": False, "found": 0},
            "fff": {"available": False, "found": 0},
            "anew": {"available": False, "found": 0},
        }

    def _check_tool(self, tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    async def collect(self, target_domain: str, subdomains: List[str],
                      js_endpoints: List[str], max_subdomains: int = 50) -> Set[str]:
        """
        收集所有端点，返回去重后的URL集合
        修复：不再丢弃 .json/.xml 等标准 API 后缀
        """
        all_endpoints = set()

        self.cdn_info = await self._detect_cdn(target_domain)

        for ep in js_endpoints:
            if self._is_valid_endpoint(ep):
                if ep.startswith(('http://', 'https://')):
                    all_endpoints.add(ep)
                elif ep.startswith('/'):
                    all_endpoints.add(f"https://{target_domain}{ep}")

        logger.info(f"   📊 初始 JS 端点: {len(all_endpoints)} 个")

        hist = await self._fetch_historical(target_domain)
        if hist:
            logger.info(f"      📜 历史数据新增: {len(hist)} 个")
            all_endpoints.update(hist)
        else:
            logger.warning("      ⚠️ 历史数据工具未返回结果，尝试备用爬虫...")
            fallback = await self._fallback_crawl(target_domain)
            if fallback:
                logger.info(f"      🔄 备用爬虫新增: {len(fallback)} 个")
                all_endpoints.update(fallback)

        robots = await self._fetch_robots_paths(target_domain)
        if robots:
            logger.info(f"      🤖 robots.txt 历史路径新增: {len(robots)} 个")
            all_endpoints.update(robots)

        subs_to_crawl = subdomains[:max_subdomains]
        if subs_to_crawl:
            crawled = await self._crawl_subdomains(subs_to_crawl)
            if crawled:
                logger.info(f"      🕷️ 子域名爬取新增: {len(crawled)} 个")
                all_endpoints.update(crawled)
            else:
                logger.warning("      ⚠️ 子域名爬取未返回结果，尝试备选方案...")
                fallback = await self._fallback_crawl_subdomains(subs_to_crawl[:10])
                if fallback:
                    logger.info(f"      🔄 备选爬取新增: {len(fallback)} 个")
                    all_endpoints.update(fallback)
        else:
            logger.info("      ℹ️ 无子域名可爬取")

        if subs_to_crawl:
            gs = await self._gospider_crawl(subs_to_crawl)
            if gs:
                logger.info(f"      🕸️ gospider 爬取新增: {len(gs)} 个")
                all_endpoints.update(gs)

        if len(all_endpoints) < 30:
            logger.info(f"      📄 端点数量较少（{len(all_endpoints)}），尝试从主站提取链接...")
            extra = await self._extract_from_main(target_domain)
            if extra:
                logger.info(f"      📄 主站链接新增: {len(extra)} 个")
                all_endpoints.update(extra)

            ff = await self._file_ffuzz(target_domain)
            if ff:
                logger.info(f"      🗂️ 文件模糊测试新增: {len(ff)} 个")
                all_endpoints.update(ff)

        # 修复：保留 .json/.xml/.yaml 等标准 API 后缀
        filtered = {ep for ep in all_endpoints if self._is_valid_endpoint(ep, strict=False)}

        filtered = await self._dedup_with_anew(filtered)

        unfurl_stats = await self._unfurl_stats(filtered)
        if unfurl_stats:
            logger.info(f"      🧩 unfurl 解析: {len(unfurl_stats)} 个唯一 host, {len(filtered)} 个端点")

        # SP14.1-B：参数挖掘钩子（默认关，开启后结果入池供任务生成消费）
        await self.mine_hidden_params(filtered)

        self._log_tool_stats()

        if filtered:
            logger.info(f"   ✅ 端点收集完成: 共 {len(filtered)} 个唯一端点（过滤后）")
        else:
            logger.warning("   ⚠️ 端点收集完成: 0 个有效端点（请检查外部工具是否可用）")

        return filtered

    def _is_valid_endpoint(self, ep: str, strict: bool = False) -> bool:
        """
        检查端点是否有效
        strict=True: 过滤静态资源扩展（默认）
        strict=False: 仅过滤明显无效的，保留 .json/.xml 等 API 后缀
        """
        if not ep or not isinstance(ep, str):
            return False

        ep_lower = ep.lower()

        # 核心静态资源（必须过滤）
        static_exts = {
            '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz',
            '.min.js', '.min.css'
        }

        # 如果是严格模式，过滤 .js 和 .json
        if strict:
            static_exts.add('.js')
            static_exts.add('.json')
            static_exts.add('.xml')
            static_exts.add('.yaml')
            static_exts.add('.yml')
            static_exts.add('.txt')

        for ext in static_exts:
            if ep_lower.endswith(ext):
                return False

        if len(ep) < 3:
            return False

        if ep.startswith(('http://', 'https://', '/')):
            return True

        return False

    def _log_tool_stats(self):
        available = sum(1 for s in self._tool_stats.values() if s["available"])
        total = len(self._tool_stats)
        if available < total:
            logger.warning(f"      ⚠️ 工具可用性: {available}/{total} 个工具可用")
            for name, stats in self._tool_stats.items():
                status = "✅" if stats["available"] else "❌"
                logger.warning(f"         {status} {name}: {'可用' if stats['available'] else '不可用'} (发现 {stats['found']} 个)")

    async def _fetch_historical(self, domain: str) -> Set[str]:
        urls = set()

        if self._check_tool("waybackurls"):
            self._tool_stats["waybackurls"]["available"] = True
            try:
                result = await run_tool(
                    "waybackurls",
                    args=[domain],
                )
                if result.get("success"):
                    count = 0
                    for line in result.get("stdout", "").splitlines():
                        if line.strip() and line.startswith('http'):
                            urls.add(line.strip())
                            count += 1
                    self._tool_stats["waybackurls"]["found"] = count
            except Exception as e:
                logger.debug(f"         waybackurls 失败: {e}")
        else:
            logger.debug("         waybackurls 未安装")

        if self._check_tool("gau"):
            self._tool_stats["gau"]["available"] = True
            try:
                result = await run_tool(
                    "gau",
                    args=[domain],
                )
                if result.get("success"):
                    count = 0
                    for line in result.get("stdout", "").splitlines():
                        if line.strip() and line.startswith('http'):
                            urls.add(line.strip())
                            count += 1
                    self._tool_stats["gau"]["found"] = count
            except Exception as e:
                logger.debug(f"         gau 失败: {e}")
        else:
            logger.debug("         gau 未安装")

        return urls

    async def _fallback_crawl(self, domain: str, max_depth: int = 2, max_urls: int = 30) -> Set[str]:
        """纯 HTTP 兜底爬虫：零外部工具依赖，从主站出发 BFS 提取站内链接。

        解析 href/src/action/data-src/srcset 四类属性 + 站内同域跟随，
        总量/深度受限，保证任何环境下端点收集不归零。
        """
        urls = set()
        try:
            import aiohttp
        except ImportError:
            return urls
        base = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
        base_host = urlparse(base).netloc.lower()
        try:
            async with aiohttp.ClientSession() as sess:
                seen = set()
                frontier = [base]
                for _depth in range(max_depth):
                    next_frontier = []
                    for page in frontier:
                        if len(urls) >= max_urls or page in seen:
                            continue
                        seen.add(page)
                        try:
                            async with sess.get(page, timeout=10, ssl=False) as resp:
                                if resp.status != 200:
                                    continue
                                html = await resp.text()
                                for link in _extract_links_from_html(html):
                                    norm = _normalize_url(page, link)
                                    if not norm or urlparse(norm).netloc.lower() != base_host:
                                        continue
                                    if self._is_valid_endpoint(norm, strict=False):
                                        if len(urls) >= max_urls:
                                            continue
                                        urls.add(norm)
                                        next_frontier.append(norm)
                        except BaseException:
                            continue
                    if not next_frontier:
                        break
                    frontier = next_frontier[:max_urls]
        except Exception as e:
            logger.debug(f"备用爬虫失败: {e}")
        return urls

    async def _crawl_subdomains(self, subdomains: List[str]) -> Set[str]:
        endpoints = set()

        if not self._check_tool("katana"):
            self._tool_stats["katana"]["available"] = False
            return endpoints

        self._tool_stats["katana"]["available"] = True
        count_total = 0

        for sub in subdomains[:30]:
            url = f"https://{sub}" if not sub.startswith('http') else sub
            try:
                result = await run_tool(
                    "katana",
                    args=["-u", url],
                )
                if result.get("success"):
                    count = 0
                    for line in result.get("stdout", "").splitlines():
                        if line.strip():
                            try:
                                data = json.loads(line)
                                ep = data.get("url")
                                if ep and self._is_valid_endpoint(ep, strict=False):
                                    endpoints.add(ep)
                                    count += 1
                            except BaseException:
                                logger.debug("suppressed exception (core audit)")
                    count_total += count
            except FileNotFoundError:
                self._tool_stats["katana"]["available"] = False
                break
            except Exception as e:
                logger.debug(f"         katana 失败: {e}")

        self._tool_stats["katana"]["found"] = count_total
        return endpoints

    async def _fallback_crawl_subdomains(self, subdomains: List[str]) -> Set[str]:
        endpoints = set()
        try:
            import aiohttp
            async with aiohttp.ClientSession() as sess:
                for sub in subdomains[:10]:
                    url = f"https://{sub}"
                    try:
                        async with sess.get(url, timeout=10, ssl=False) as resp:
                            if resp.status == 200:
                                html = await resp.text()
                                pattern = r'(?:href|src)=["\']([^"\']+)["\']'
                                for m in re.finditer(pattern, html, re.I):
                                    link = m.group(1)
                                    if link.startswith('/'):
                                        link = f"https://{sub}{link}"
                                    if link.startswith(('http://', 'https://')):
                                        if self._is_valid_endpoint(link, strict=False):
                                            endpoints.add(link)
                    except BaseException:
                        continue
        except Exception as e:
            logger.debug(f"备选子域名爬取失败: {e}")
        return endpoints

    async def _extract_from_main(self, domain: str) -> Set[str]:
        urls = set()
        try:
            import aiohttp
            async with aiohttp.ClientSession() as sess:
                for scheme in ['https', 'http']:
                    try:
                        async with sess.get(f"{scheme}://{domain}", timeout=10, ssl=False) as resp:
                            if resp.status == 200:
                                html = await resp.text()
                                pattern = r'(?:href|src)=["\']([^"\']+)["\']'
                                for m in re.finditer(pattern, html, re.I):
                                    link = m.group(1)
                                    if link.startswith('/'):
                                        link = f"{scheme}://{domain}{link}"
                                    if link.startswith(('http://', 'https://')):
                                        if self._is_valid_endpoint(link, strict=False):
                                            urls.add(link)
                                break
                    except BaseException:
                        continue
        except BaseException:
            logger.debug("suppressed exception (core audit)")
        return urls

    async def import_to_burp(self, endpoints: Set[str], limit: int = 300):
        if not self.burp_client:
            return
        valid = [ep for ep in endpoints if self._is_valid_endpoint(ep, strict=False)]
        for i, ep in enumerate(valid[:limit]):
            try:
                await self.burp_client.send_to_scanner(ep)
                if i % 10 == 0:
                    logger.debug(f"已导入 {i + 1}/{min(limit, len(valid))}")
            except Exception as e:
                logger.warning(f"导入{ep}失败: {e}")
        logger.info(f"✅ 已导入 {min(limit, len(valid))} 个端点到Burp")

    async def _detect_cdn(self, domain: str) -> Optional[str]:
        """cdncheck: 检测目标是否使用 CDN（不产出端点，记录结果到 self.cdn_info）"""
        if not self._check_tool("cdncheck"):
            logger.debug("         cdncheck 未安装")
            return None
        self._tool_stats["cdncheck"]["available"] = True
        try:
            result = await run_tool("cdncheck", args=["-i", domain])
            if result.get("success"):
                lines = [ln.strip() for ln in result.get("stdout", "").splitlines() if ln.strip()]
                if lines:
                    self._tool_stats["cdncheck"]["found"] = 1
                    info = lines[0]
                    logger.info(f"      🛡️ CDN 检测: {info}")
                    return info
        except Exception as e:
            logger.debug(f"         cdncheck 失败: {e}")
        return None

    async def _fetch_robots_paths(self, domain: str) -> Set[str]:
        """waybackrobots: 从 Wayback Machine 提取 robots.txt 中的路径并转为端点"""
        paths = set()
        if not self._check_tool("waybackrobots"):
            logger.debug("         waybackrobots 未安装")
            return paths
        self._tool_stats["waybackrobots"]["available"] = True
        try:
            result = await run_tool("waybackrobots", args=[domain])
            if result.get("success"):
                count = 0
                for line in result.get("stdout", "").splitlines():
                    p = line.strip()
                    if not p or p == "*" or p.startswith("#"):
                        continue
                    if p.startswith('/'):
                        paths.add(f"https://{domain}{p}")
                        count += 1
                self._tool_stats["waybackrobots"]["found"] = count
        except Exception as e:
            logger.debug(f"         waybackrobots 失败: {e}")
        return paths

    async def _gospider_crawl(self, subdomains: List[str]) -> Set[str]:
        """gospider: 轻量级爬虫，解析输出中的 URL"""
        endpoints = set()
        if not self._check_tool("gospider"):
            logger.debug("         gospider 未安装")
            return endpoints
        self._tool_stats["gospider"]["available"] = True
        count_total = 0
        for sub in subdomains[:15]:
            url = f"https://{sub}" if not sub.startswith('http') else sub
            try:
                result = await run_tool(
                    "gospider",
                    args=["-s", url, "-d", "2", "--quiet", "--no-redirect"],
                )
                if result.get("success"):
                    count = 0
                    for line in result.get("stdout", "").splitlines():
                        # 行格式如 "https://host/path [200]" 或 "[javascript] https://host/x.js"
                        m = re.search(r'https?://\S+', line)
                        if m:
                            ep = m.group(0).rstrip('.,;]')
                            if self._is_valid_endpoint(ep, strict=False):
                                endpoints.add(ep)
                                count += 1
                    count_total += count
            except FileNotFoundError:
                self._tool_stats["gospider"]["available"] = False
                break
            except Exception as e:
                logger.debug(f"         gospider 失败: {e}")
        self._tool_stats["gospider"]["found"] = count_total
        return endpoints

    async def _file_ffuzz(self, domain: str) -> Set[str]:
        """fff: 对主站做快速文件模糊测试（内置常见路径字典，仅输出匹配结果）"""
        endpoints = set()
        if not self._check_tool("fff"):
            logger.debug("         fff 未安装")
            return endpoints
        self._tool_stats["fff"]["available"] = True
        try:
            result = await run_tool(
                "fff",
                args=["-d", "1", "-S"],
                stdin_text=f"https://{domain}",
            )
            if result.get("success"):
                count = 0
                for line in result.get("stdout", "").splitlines():
                    m = re.search(r'https?://\S+', line)
                    if m:
                        ep = m.group(0).rstrip('.,;]')
                        if self._is_valid_endpoint(ep, strict=False):
                            endpoints.add(ep)
                            count += 1
                self._tool_stats["fff"]["found"] = count
        except Exception as e:
            logger.debug(f"         fff 失败: {e}")
        return endpoints

    async def _unfurl_stats(self, urls: Set[str]) -> Dict[str, int]:
        """unfurl: 解析 URL 各部分，统计唯一 host 分布（不产出新端点）"""
        stats: Dict[str, int] = {}
        if not urls or not self._check_tool("unfurl"):
            return stats
        self._tool_stats["unfurl"]["available"] = True
        try:
            result = await run_tool(
                "unfurl",
                args=["hosts"],
                stdin_text="\n".join(sorted(urls)),
            )
            if result.get("success"):
                for line in result.get("stdout", "").splitlines():
                    host = line.strip()
                    if host:
                        stats[host] = stats.get(host, 0) + 1
                self._tool_stats["unfurl"]["found"] = len(stats)
        except Exception as e:
            logger.debug(f"         unfurl 失败: {e}")
        return stats

    async def _dedup_with_anew(self, urls: Set[str]) -> Set[str]:
        """anew: 追加去重（防御性，保证输出集合无重复）"""
        if not urls or not self._check_tool("anew"):
            return urls
        self._tool_stats["anew"]["available"] = True
        try:
            result = await run_tool(
                "anew",
                args=["-q"],
                stdin_text="\n".join(sorted(urls)),
            )
            if result.get("success"):
                deduped = {ln.strip() for ln in result.get("stdout", "").splitlines() if ln.strip()}
                if deduped:
                    self._tool_stats["anew"]["found"] = len(deduped)
                    return deduped
        except Exception as e:
            logger.debug(f"         anew 失败: {e}")
        return urls

    async def mine_hidden_params(self, endpoints, max_endpoints: int = 10) -> List[Dict]:
        """SP14.1-B（D3.5 参数挖掘，默认关）：对收集到的端点做隐藏参数挖掘并入池。

        开关 settings.enable_param_mining（getattr 动态读，字段由 A 线在
        settings.py 定义）；关闭/失败时返回 []，零行为变更。
        """
        if not getattr(settings, "enable_param_mining", False):
            return []
        try:
            mined = await mine_params_for_endpoints(
                endpoints, session=self.session, max_endpoints=max_endpoints)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"参数挖掘异常（忽略）: {exc}")
            return []
        if mined:
            written = append_param_candidates(mined)
            logger.info(f"      🔎 参数挖掘: {len(mined)} 个候选（入池 {written}）")
        return mined


async def crawl_same_origin(target: str, session=None, max_depth: int = 2, max_urls: int = 80, render: bool = False, crawl_hash_routing: bool = False, crawl_websocket: bool = False, ws_endpoints=None) -> Dict[str, List[str]]:
    from vulnclaw.config.settings import settings as _st
    if render and not _st.crawl_render_spa:
        render = False

    """同源链接爬虫：从 target 出发 BFS 跟踪同源 <a href> 链接（深度 max_depth），
    返回 端点URL -> 候选注入参数 列表（参数来自该页 query / 表单 <input name> / 相对 ?x=1 链接）。
    目的：补 endpoint 覆盖率（如 DVWA /sqli /xss），让真实漏洞端点进入引擎扫描队列。
    安全措施：同源限制、静态后缀过滤、总数上限、单请求超时、去重、异常吞掉不影响主流程。
    render=True 时优先用 playwright 渲染 JS 后爬取（D1：发现 SPA 隐藏端点/参数），
    渲染不可用则回退纯 HTTP 爬取（安全降级，行为不变）。
    """
    from urllib.parse import urlparse, urljoin, parse_qs
    from vulnclaw.core.utils import async_get
    import re as _re
    base = urlparse(target)
    origin = f"{base.scheme}://{base.netloc}"
    results: Dict[str, set] = {}
    visited = set()
    queue: List[tuple] = [(target, 0)]
    _STATIC = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
               '.woff', '.woff2', '.ttf', '.pdf', '.zip', '.mp3', '.mp4')

    async def _fetch_html(url: str):
        """D1 渲染爬取：render=True 时优先 playwright 渲染 JS 取 DOM；失败回退 HTTP。"""
        if render:
            try:
                from playwright.async_api import async_playwright
                async with async_playwright() as p:
                    b = await p.chromium.launch(headless=True)
                    pg = await b.new_page()
                    resp = await pg.goto(url, timeout=15000, wait_until="networkidle")
                    status = resp.status if resp is not None else 200
                    html = await pg.content()
                    # R2-A S1: 浏览器渲染流 → LiveIntake 回注（开关关时零成本短路）
                    try:
                        from urllib.parse import urlparse as _up, parse_qs as _pq
                        from vulnclaw.modules.live_intake import feed_live
                        _q = _pq(_up(url).query, keep_blank_values=True)
                        feed_live(url, params={k: (v[0] if v else "") for k, v in _q.items()},
                                  source="render")
                    except BaseException:
                        logger.debug("suppressed exception (live intake render)")
                    await b.close()
                    return status, html
            except BaseException:
                logger.debug("suppressed exception (core audit)")
        try:
            resp = await async_get(url, session=session, timeout=10, no_retry=True)
        except BaseException:
            return None
        if not isinstance(resp, tuple) or len(resp) < 2:
            return None
        return resp[0], (resp[1] or "")

    async def _visit(url: str, depth: int):
        if url in visited or len(results) >= max_urls:
            return
        visited.add(url)
        fetched = await _fetch_html(url)
        if fetched is None:
            return
        status, text = fetched
        # D2: SPA hash 路由 + WebSocket 端点发现（按需启用，仅正则提取，零额外请求）
        if isinstance(text, str):
            if crawl_hash_routing:
                for hr in _re.findall(r'#/[A-Za-z0-9_./-]{1,120}', text):
                    hurl = target.split('#')[0] + hr
                    if hurl not in results:
                        results[hurl] = {k for k in parse_qs(urlparse(hr).query)}
            if crawl_websocket and ws_endpoints is not None:
                for w in _re.findall("wss?://[^\\s\"'<>()]+", text):
                    ws_endpoints.add(w)
        if status is None or status >= 400 or not isinstance(text, str):
            return
        params: set = set()
        for k in parse_qs(urlparse(url).query):
            params.add(k)
        for name in _re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', text, _re.I):
            if name:
                params.add(name)
        # 相对 ?x=1 链接 → 参数记到本页
        for h in _re.findall(r'href=["\']([^"\']+)["\']', text, _re.I):
            if h.startswith('?'):
                for k in parse_qs(urlparse(h).query):
                    params.add(k)
        if params:
            results[url] = params
        if depth >= max_depth:
            return
        for h in _re.findall(r'href=["\']([^"\']+)["\']', text, _re.I):
            if not h or h.startswith(('#', 'mailto:', 'javascript:', 'tel:')):
                continue
            if h.startswith('/'):
                full = urljoin(origin + '/', h)
            elif h.startswith('http'):
                if urlparse(h).netloc != base.netloc:
                    continue
                full = h
            else:
                continue
            if full in visited:
                continue
            if '?' in full:
                # 带 query 的链接：记录其参数但不再深入（避免爆炸）
                for k in parse_qs(urlparse(full).query):
                    results.setdefault(full, set()).add(k)
                continue
            if full.lower().endswith(_STATIC):
                continue
            queue.append((full, depth + 1))
            if len(queue) > max_urls * 3:
                return

    head = 0
    sem = asyncio.Semaphore(8)
    while head < len(queue):
        if len(results) >= max_urls:
            break
        url, depth = queue[head]
        head += 1
        async with sem:
            await _visit(url, depth)
    return {u: sorted(p) for u, p in results.items()}


# ============================================================
# SP14.1-B / D3.5: 参数名挖掘器（词典 + 差异判定）
#
# 入池格式（SP14 接口约定，消费方 = A 线 request_feed / 参数池 / 任务生成）:
#   {"param": str, "url": str, "base_len": int, "signal": str}
#   signal: "reflected"(强，探针回显) / "diff_len"(响应长度差异) / "status_change"(状态码变化)
# 解耦：B 不 import A 的任何文件；结果写 JSONL 池文件，A 按需读取。
# 开关：getattr(settings, "enable_param_mining", False) —— 字段由 A 线在
#       settings.py 定义（热区归 A），未定义时本挖掘器保持关闭，零行为变更。
# ============================================================

# 高价值候选参数词典（可被调用方 wordlist 覆盖/扩展）
_PARAM_WORDLIST = (
    # 调试/运维（历史高危）
    "debug", "debug_mode", "test", "admin", "verbose", "trace", "trace_id",
    "log", "log_level", "show_errors", "error", "errors", "dump",
    # 身份/会话
    "user", "username", "uname", "userid", "uid", "account", "email",
    "login", "token", "secret", "key", "apikey", "api_key", "session",
    # 重定向/回跳（SSRF/开放重定向高发位）
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "returnTo", "next", "next_url", "goto", "continue", "callback", "cb",
    "jsonp", "url", "uri", "link", "dest", "destination", "target",
    # 文件/路径（LFI/RCE 高发位）
    "file", "filename", "filepath", "path", "dir", "folder", "doc",
    "download", "read", "cat", "load", "load_file", "include", "template",
    "tpl", "view", "render", "page", "page_id", "module", "component",
    "theme", "layout", "skin", "partial", "block", "action", "func",
    # 查询/列表
    "q", "query", "search", "keyword", "filter", "sort", "order", "by",
    "limit", "offset", "start", "end", "count", "size", "num", "page_size",
    "id", "name", "type", "category", "tag", "group", "lang", "locale",
    "format", "mode", "op", "method", "cmd", "exec", "code", "run", "eval",
    # 网络/代理（SSRF 高发位）
    "host", "site", "server", "proxy", "gateway", "forward", "referer",
    "ref", "source", "src", "origin", "remote", "fetch", "feed", "rss",
    # 业务/其他
    "api", "version", "v", "out", "output", "output_format", "export",
    "download_type", "attachment", "media", "image", "img", "photo",
    "attachment_id", "post", "post_id", "article", "news", "product",
    "item", "order_id", "invoice", "report", "chart", "data", "json",
    "xml", "preview", "edit", "update", "delete", "create", "status",
)

_PARAM_PROBE = "vulnclaw_p0"  # 固定探针值（反射判定基准）

# 池文件相对根的路径（_runtime_cache/recon/param_candidates.jsonl）
_PARAM_POOL_RELPATH = ("_runtime_cache", "recon", "param_candidates.jsonl")

# 进程内 (url, param) 去重（跨多次调用不重复落池）
_PARAM_POOL_SEEN: set = set()


def param_pool_path() -> str:
    """参数候选池文件绝对路径（项目根/_runtime_cache/recon/param_candidates.jsonl）。"""
    root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    return os.path.join(root, *_PARAM_POOL_RELPATH)


def append_param_candidates(candidates) -> int:
    """按入池格式追加写 JSONL 池（进程内去重；失败静默返回 0，绝不影响主流程）。"""
    path = param_pool_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        written = 0
        with open(path, "a", encoding="utf-8") as f:
            for c in candidates or []:
                try:
                    key = (str(c["url"]), str(c["param"]))
                except (KeyError, TypeError):
                    continue
                if key in _PARAM_POOL_SEEN:
                    continue
                _PARAM_POOL_SEEN.add(key)
                f.write(json.dumps(c, ensure_ascii=False) + "\n")
                written += 1
        return written
    except OSError as exc:
        logger.debug(f"参数候选池写入失败（忽略）: {exc}")
        return 0


async def mine_params(url: str, session=None, wordlist=None,
                      max_params: int = 120, concurrency: int = 5,
                      timeout: int = 8) -> List[Dict]:
    """对单个 URL 做隐藏参数挖掘（词典 + 差异判定），返回入池格式列表。

    判定规则（低误报，逐词一轮探测）：
      - reflected:      探针值出现在响应体（强信号，参数既存在又回显）
      - diff_len:       状态码与基线一致但响应长度差 >=64（参数改变了行为）
      - status_change:  状态码变化且非 404/5xx（404 页与 5xx 多为全参数噪声）
    """
    from vulnclaw.core.utils import async_get

    url = str(url or "").strip()
    if not url or not url.lower().startswith(("http://", "https://")):
        return []
    words = list(wordlist or _PARAM_WORDLIST)[:max_params]
    if not words:
        return []

    try:
        base = await async_get(url, session=session, timeout=timeout, no_retry=True)
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"参数挖掘基线请求失败（{url}）: {exc}")
        return []
    if not isinstance(base, tuple) or len(base) < 2:
        return []
    base_status, base_text = base[0], base[1] or ""
    base_len = len(base_text)
    if not base_len and base_status in (0, None):
        return []

    sep = "&" if "?" in url else "?"
    probe_url_tpl = f"{url}{sep}{{w}}={_PARAM_PROBE}"

    async def _probe(word: str) -> Optional[Dict]:
        try:
            resp = await async_get(
                probe_url_tpl.format(w=word), session=session,
                timeout=timeout, no_retry=True)
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(resp, tuple) or len(resp) < 2:
            return None
        status, text = resp[0], resp[1] or ""
        if status in (0, 429) or (isinstance(status, int) and status >= 500):
            return None  # 目标不稳定，不可判
        if _PARAM_PROBE in text:
            return {"param": word, "url": url, "base_len": base_len, "signal": "reflected"}
        if status != base_status and status != 404:
            return {"param": word, "url": url, "base_len": base_len, "signal": "status_change"}
        if status == base_status and abs(len(text) - base_len) >= 64:
            return {"param": word, "url": url, "base_len": base_len, "signal": "diff_len"}
        return None

    sem = asyncio.Semaphore(max(1, concurrency))
    out: List[Dict] = []

    async def _guarded(word: str) -> Optional[Dict]:
        async with sem:
            return await _probe(word)

    for r in await asyncio.gather(*(_guarded(w) for w in words)):
        if r:
            out.append(r)
    return out


async def mine_params_for_endpoints(endpoints, session=None, max_endpoints: int = 10,
                                    per_url_words: int = 120) -> List[Dict]:
    """对端点集合批量挖掘（collect 钩子入口）：挑前 max_endpoints 个 URL 逐个挖。

    自证（SP15-B）：静态资源后缀跳过、同 URL 去重（重复端点只挖一次）。
    """
    picked: List[str] = []
    seen: set = set()
    for ep in endpoints or []:
        ep = str(ep or "").strip()
        if not ep.lower().startswith(("http://", "https://")):
            continue
        if ep.lower().rsplit("?", 1)[0].rsplit(".", 1)[-1] in (
                "css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico",
                "woff", "woff2", "ttf", "pdf", "zip", "mp3", "mp4"):
            continue
        if ep in seen:
            continue  # 端点去重：同 URL 只挖一次
        seen.add(ep)
        picked.append(ep)
        if len(picked) >= max_endpoints:
            break
    out: List[Dict] = []
    for u in picked:
        out.extend(await mine_params(u, session=session, max_params=per_url_words))
    return out


# ============================================================
# SP15-B / B-SP15.4: recon_brief 回灌（字段与 A 侧消费完全一致）
#
# A 侧消费（phases_taskgen）对 brief["param_mining"] 的契约：
#   _item 为 dict，读 .get("url")/.get("param")/.get("signal")/.get("base_len")；
#   url 会剥 query 由 param 注入；param 过凭据过滤；条目数过 cap(max_param_mining)。
# 本模块保证：回灌条目恒为四字段齐全的 dict，signal 在三枚举内，url 为绝对 http(s)。
# ============================================================
_PARAM_SIGNALS = ("reflected", "diff_len", "status_change")
_SIGNAL_RANK = {"reflected": 0, "diff_len": 1, "status_change": 2}


def load_param_candidates(path: str = None) -> List[Dict]:
    """读参数候选池 JSONL → 归一化列表（只留四字段齐全且合法的条目）。

    脏行（缺字段/非法 signal/非法 URL/类型错）剔除——A 侧消费零防御成本。
    """
    path = path or param_pool_path()
    out: List[Dict] = []
    try:
        if not os.path.isfile(path):
            return out
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(item, dict):
                    continue
                url = str(item.get("url") or "").strip()
                param = str(item.get("param") or "").strip()
                signal = str(item.get("signal") or "").strip()
                if not url or not param or signal not in _PARAM_SIGNALS:
                    continue
                if not url.lower().startswith(("http://", "https://")):
                    continue
                try:
                    base_len = int(item.get("base_len") or 0)
                except (TypeError, ValueError):
                    base_len = 0
                out.append({"param": param, "url": url,
                            "base_len": base_len, "signal": signal})
    except OSError as exc:
        logger.debug(f"参数候选池读取失败（忽略）: {exc}")
    return out


def brief_param_mining(brief: Dict, items=None, max_items: int = 0) -> List[Dict]:
    """回灌入口：把挖掘结果写入 brief["param_mining"]（幂等，可重复调用）。

    - items 缺省时自动读池（load_param_candidates）；传入时同样过归一化校验。
    - 确定性排序：reflected > diff_len > status_change（同信号按 url,param），
      保证 A 侧 cap(max_param_mining) 截断时优先留强信号。
    - max_items<=0 时不在此截断（截断权在 A 侧 cap，与"0=不限制"语义一致）。
    - 幂等：按 (url, param) 合并去重，重复调用以先出现的条目为准。
    返回写入后的 brief["param_mining"] 列表。
    """
    brief = brief if isinstance(brief, dict) else {}
    candidates = list(items) if items is not None else load_param_candidates()
    # 归一化校验（与 load_param_candidates 同规则）
    valid: List[Dict] = []
    seen: set = set()
    for it in candidates:
        if not isinstance(it, dict):
            continue
        url = str(it.get("url") or "").strip()
        param = str(it.get("param") or "").strip()
        signal = str(it.get("signal") or "").strip()
        if not url or not param or signal not in _PARAM_SIGNALS:
            continue
        if not url.lower().startswith(("http://", "https://")):
            continue
        key = (url, param)
        if key in seen:
            continue
        seen.add(key)
        try:
            base_len = int(it.get("base_len") or 0)
        except (TypeError, ValueError):
            base_len = 0
        valid.append({"param": param, "url": url,
                      "base_len": base_len, "signal": signal})
    valid.sort(key=lambda d: (_SIGNAL_RANK[d["signal"]], d["url"], d["param"]))
    if max_items and max_items > 0:
        valid = valid[:max_items]
    # 幂等合并：与 brief 已有 param_mining 去重合并（已有条目优先）
    existing = brief.get("param_mining") or []
    exist_keys = set()
    for it in existing:
        if isinstance(it, dict):
            exist_keys.add((str(it.get("url") or ""), str(it.get("param") or "")))
    merged = list(existing) + [it for it in valid
                               if (it["url"], it["param"]) not in exist_keys]
    brief["param_mining"] = merged
    return merged


__all__ = ['EndpointCollector', 'mine_params', 'mine_params_for_endpoints',
           'append_param_candidates', 'param_pool_path', 'load_param_candidates',
           'brief_param_mining', '_PARAM_WORDLIST']
