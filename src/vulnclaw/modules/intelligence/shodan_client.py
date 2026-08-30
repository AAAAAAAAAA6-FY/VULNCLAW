# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# modules/intelligence/shodan_client.py
"""P4-1: Shodan / Censys 情报自动补全。

Recon 阶段对解析出的 IP 调用情报 API：
- Shodan：GET /shodan/host/{ip} → ports / vulns(CVE) / data[].product
- Censys：GET /api/v2/hosts/{ip}（Shodan 无结果或无 Key 时兜底）

结果注入 recon_brief["intel"]：
    {
      "ips": {ip: {...}},
      "ports": [...],
      "vulns": ["CVE-2021-41773", ...],
      "products": ["nginx", "OpenSSH", ...],
      "service_hints": ["nginx", "php", ...],   # 引擎优先尝试的服务类型
    }

安全/稳定性约束：
- 未配置 API Key → info 级提示后跳过，不阻塞扫描；
- 401 → 标记 Key 失效，本次扫描内不再重试；
- 单次请求受 settings.intel_timeout 限制，最多查询前 3 个 IP。
"""

import asyncio
import json
import socket
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings

SHODAN_HOST_API = "https://api.shodan.io/shodan/host/{ip}"
CENSYS_HOST_API = "https://search.censys.io/api/v2/hosts/{ip}"
MAX_INTEL_IPS = 3

# Shodan product / module → 引擎可用的服务类型提示（用于 payload 决策与 Nuclei tags）
_SERVICE_HINTS: Dict[str, List[str]] = {
    "nginx": ["nginx"],
    "apache": ["apache", "php"],
    "tomcat": ["tomcat", "java"],
    "spring": ["spring", "java"],
    "jboss": ["jboss", "java"],
    "weblogic": ["weblogic", "java"],
    "websphere": ["websphere", "java"],
    "iis": ["iis", "asp", "aspx"],
    "jenkins": ["jenkins", "java"],
    "wordpress": ["wordpress", "php"],
    "joomla": ["joomla", "php"],
    "drupal": ["drupal", "php"],
    "redis": ["redis"],
    "memcached": ["memcached"],
    "elasticsearch": ["elasticsearch", "java"],
    "kibana": ["kibana"],
    "grafana": ["grafana"],
    "mysql": ["mysql"],
    "postgresql": ["postgresql"],
    "mssql": ["mssql"],
    "mongodb": ["mongodb"],
    "oracle": ["oracle"],
    "ftp": ["ftp"],
    "ssh": ["ssh"],
    "smtp": ["smtp"],
    "smb": ["smb"],
    "rdp": ["rdp"],
    "vnc": ["vnc"],
}


def _hints_from_text(blob: str) -> List[str]:
    """从 product / module 文本中提取服务类型提示。"""
    hints: List[str] = []
    low = (blob or "").lower()
    for key, val in _SERVICE_HINTS.items():
        if key in low:
            for h in val:
                if h not in hints:
                    hints.append(h)
    return hints


class ShodanClient:
    """Shodan REST API 客户端（免费版配额足够单目标情报补全）。"""

    def __init__(self, api_key: Optional[str] = None, timeout: Optional[int] = None):
        self.api_key = api_key or settings.shodan_api_key
        self.timeout = timeout or settings.intel_timeout
        self._cache: Dict[str, Dict] = {}
        self._disabled = False

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and not self._disabled

    async def host_info(self, ip: str) -> Optional[Dict]:
        """查询 /shodan/host/{ip}，返回标准化情报；失败返回 None。"""
        if not self.enabled:
            return None
        if ip in self._cache:
            return self._cache[ip]

        from vulnclaw.core.utils import async_get

        url = SHODAN_HOST_API.format(ip=ip) + f"?key={self.api_key}"
        try:
            status, text, _ = await async_get(
                url, timeout=self.timeout, no_retry=True
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"🌐 [Shodan] 请求异常 {ip}: {exc}")
            return None

        if status != 200:
            if status == 404:
                logger.info(f"🌐 [Shodan] {ip} 无情报记录 (404)")
            elif status == 401:
                logger.warning("🌐 [Shodan] API Key 无效 (401)，本次扫描跳过情报补全")
                self._disabled = True
            elif status == 429:
                logger.warning("🌐 [Shodan] 配额耗尽 (429)，本次扫描跳过情报补全")
                self._disabled = True
            else:
                logger.debug(f"🌐 [Shodan] {ip} 返回 HTTP {status}")
            return None

        try:
            raw = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return None

        info = self._normalize(raw)
        self._cache[ip] = info
        return info

    @staticmethod
    def _normalize(raw: Dict) -> Dict:
        """提取 vulns / ports / product 字段并标准化。"""
        ports = sorted(
            {int(p) for p in (raw.get("ports") or []) if isinstance(p, (int, float))}
        )
        products: List[str] = []
        services: List[str] = []
        for item in raw.get("data") or []:
            if not isinstance(item, dict):
                continue
            prod = (item.get("product") or "").strip()
            if prod and prod not in products:
                products.append(prod)
            svc = (
                (item.get("_shodan") or {}).get("module")
                or item.get("transport")
                or ""
            ).strip()
            if svc and svc not in services:
                services.append(svc)

        blob = " ".join(products + services + [str(raw.get("tags") or "")])
        return {
            "provider": "shodan",
            "ip": raw.get("ip_str", ""),
            "ports": ports,
            "vulns": sorted(raw.get("vulns") or []),
            "products": products,
            "services": services,
            "hostnames": list(raw.get("hostnames") or []),
            "os": raw.get("os") or "",
            "isp": raw.get("isp") or "",
            "asn": raw.get("asn") or "",
            "last_update": raw.get("last_update") or "",
            "service_hints": _hints_from_text(blob),
        }


class CensysClient:
    """Censys v2 API 客户端（Shodan 无结果时兜底，Basic Auth）。"""

    def __init__(
        self,
        api_id: Optional[str] = None,
        api_secret: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self.api_id = api_id or settings.censys_api_id
        self.api_secret = api_secret or settings.censys_api_secret
        self.timeout = timeout or settings.intel_timeout
        self._cache: Dict[str, Dict] = {}
        self._disabled = False

    @property
    def enabled(self) -> bool:
        return bool(self.api_id and self.api_secret) and not self._disabled

    async def host_info(self, ip: str) -> Optional[Dict]:
        if not self.enabled:
            return None
        if ip in self._cache:
            return self._cache[ip]

        try:
            import aiohttp
            from vulnclaw.core.utils import get_shared_session

            session = await get_shared_session()
            auth = aiohttp.BasicAuth(self.api_id, self.api_secret)
            async with session.get(
                CENSYS_HOST_API.format(ip=ip),
                auth=auth,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status != 200:
                    if resp.status in (401, 403):
                        logger.warning("🌐 [Censys] 凭据无效，本次扫描跳过")
                        self._disabled = True
                    return None
                raw = await resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"🌐 [Censys] 请求异常 {ip}: {exc}")
            return None

        info = self._normalize(raw)
        self._cache[ip] = info
        return info

    @staticmethod
    def _normalize(raw: Dict) -> Dict:
        result = (raw or {}).get("result") or {}
        services = result.get("services") or []
        ports = sorted(
            {int(s.get("port")) for s in services if str(s.get("port", "")).isdigit()}
        )
        products = [
            (s.get("software_display_name") or s.get("product") or "").strip()
            for s in services
        ]
        products = [p for p in products if p]
        blob = " ".join(
            products
            + [(s.get("service_name") or "") for s in services]
            + [str(result.get("operating_system") or "")]
        )
        return {
            "provider": "censys",
            "ip": result.get("ip", ""),
            "ports": ports,
            "vulns": [],
            "products": products,
            "services": sorted({(s.get("service_name") or "") for s in services} - {""}),
            "hostnames": list(result.get("dns", {}).get("names") or []),
            "os": (result.get("operating_system") or {}).get("product", "")
            if isinstance(result.get("operating_system"), dict)
            else str(result.get("operating_system") or ""),
            "isp": "",
            "asn": "",
            "last_update": result.get("last_updated_at", ""),
            "service_hints": _hints_from_text(blob),
        }


async def resolve_ip(host: str) -> Optional[str]:
    """域名 → IP（线程池 DNS 解析，避免阻塞事件循环）。"""
    if not host:
        return None
    host = host.strip()
    # netloc 可能带端口（host:port）
    if host.count(":") == 1:
        host = host.split(":")[0]
    # 已是 IP 直接返回
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, socket.gethostbyname, host)
    except Exception:  # noqa: BLE001
        return None


async def lookup_ip(ip: str) -> Optional[Dict]:
    """情报查询：Shodan 优先，Censys 兜底。"""
    shodan = ShodanClient()
    if shodan.enabled:
        info = await shodan.host_info(ip)
        if info:
            return info
    censys = CensysClient()
    if censys.enabled:
        return await censys.host_info(ip)
    return None


async def enrich_brief_with_intel(
    brief: Dict,
    domain: Optional[str] = None,
    ips: Optional[List[str]] = None,
) -> Dict:
    """P4-1: 拉取情报并注入 recon_brief["intel"]。

    Args:
        brief: 侦察简报（原地修改）。
        domain: 目标域名（未提供 ips 时解析为 IP）。
        ips: 已知 IP 列表（可选）。

    Returns:
        注入 intel 后的 brief（未配置 Key 时原样返回）。
    """
    if not settings.intel_enabled:
        return brief

    target_ips: List[str] = [i for i in (ips or []) if i]
    if not target_ips and domain:
        ip = await resolve_ip(domain)
        if ip:
            target_ips.append(ip)

    if not target_ips:
        logger.info("🌐 [情报] 未解析到目标 IP，跳过情报补全")
        return brief

    if not ShodanClient().enabled and not CensysClient().enabled:
        logger.info("🌐 [情报] 未配置 SHODAN_API_KEY / CENSYS 凭据，跳过情报补全")
        return brief

    collected: Dict[str, Dict] = {}
    for ip in target_ips[:MAX_INTEL_IPS]:
        try:
            info = await lookup_ip(ip)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"🌐 [情报] {ip} 查询异常: {exc}")
            continue
        if not info:
            continue
        collected[ip] = info
        ports = info.get("ports") or []
        if ports:
            shown = ", ".join(str(p) for p in ports[:12])
            more = " ..." if len(ports) > 12 else ""
            logger.info(
                f"🌐 [Shodan] 发现 {len(ports)} 个开放端口: {shown}{more}"
            )
        if info.get("vulns"):
            logger.info(
                f"🌐 [Shodan] {ip} 历史漏洞 {len(info['vulns'])} 个: "
                f"{', '.join(info['vulns'][:5])}"
            )
        if info.get("products"):
            logger.info(
                f"🌐 [Shodan] {ip} 服务指纹: {', '.join(info['products'][:5])}"
            )

    if not collected:
        brief.setdefault("intel", {})
        return brief

    merged: Dict[str, Any] = {
        "ips": collected,
        "ports": sorted({p for i in collected.values() for p in (i.get("ports") or [])}),
        "vulns": sorted({v for i in collected.values() for v in (i.get("vulns") or [])}),
        "products": sorted(
            {p for i in collected.values() for p in (i.get("products") or [])}
        ),
        "service_hints": sorted(
            {h for i in collected.values() for h in (i.get("service_hints") or [])}
        ),
    }
    brief["intel"] = merged

    # 情报服务类型并入 tech_stack，供引擎与 Nuclei tags 复用
    for hint in merged["service_hints"]:
        stack = brief.setdefault("tech_stack", [])
        if hint not in stack:
            stack.append(hint)

    logger.info(
        f"🌐 [情报] 补全完成: 端口 {len(merged['ports'])} 个、"
        f"CVE {len(merged['vulns'])} 个、服务提示 {len(merged['service_hints'])} 项"
    )
    return brief


__all__ = [
    "ShodanClient",
    "CensysClient",
    "resolve_ip",
    "lookup_ip",
    "enrich_brief_with_intel",
]
