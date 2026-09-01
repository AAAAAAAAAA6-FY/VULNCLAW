# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/framework_zero_day_engines_2.py
"""
框架级 0day / 管理面暴露 引擎组（v105 新增，与 framework_zero_day_engines.py 独立）
ShiroRememberMeEngine / SpringCloudGatewayEngine / ContainerPlatformExposureEngine / AdminConsoleExposureEngine
设计原则：全部基于"字节级指纹 / 固定响应特征（如 Set-Cookie deleteMe、Docker-Distribution 头）"判定，
且特征只在攻击/探测响应出现、不在普通页面出现，未命中即返回 None —— 低误报、无 OOB 依赖。
"""
import re
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get
from vulnclaw.engines.base import BaseEngine


# ============================================================
# ShiroRememberMeEngine（CVE-2016-4437：Shiro 反序列化指纹）
# ============================================================
class ShiroRememberMeEngine(BaseEngine):
    """Apache Shiro rememberMe 指纹检测（CVE-2016-4437 反序列化前奏）

    指纹原理：Shiro 对无法解密的 rememberMe Cookie 会在响应中追加
    `rememberMe=deleteMe`；普通站点不会出现该 Cookie。据此做黑盒判定。
    """

    name = "shiro_rememberme"
    description = "Apache Shiro rememberMe 指纹检测（CVE-2016-4437 rememberMe 反序列化风险）"

    def _cookie(self, headers) -> str:
        raw = ""
        for k, v in (headers or {}).items():
            if k.lower() == "set-cookie":
                raw = f"{raw}; {v}" if raw else str(v)
        return raw or ""

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/") or "/"
        reported = False
        try:
            resp = await async_get(base, session=session, timeout=settings.timeout, no_retry=True)
            if resp:
                status = resp[0]
                sc = self._cookie(resp[2] if len(resp) > 2 else {})
                if "rememberme=" in sc.lower():
                    findings.append({
                        'url': base, 'parameter': 'rememberMe',
                        'payload': '(正常请求观察 Cookie)',
                        'type': 'Shiro框架-rememberMe指纹(正常响应)',
                        'severity': 'Medium', 'ai_verdict': '中', 'confidence': 'high',
                        'evidence': f'正常请求 {base} 的响应 Set-Cookie 含 rememberMe —— Apache Shiro 框架暴露，'
                                    '若使用默认密钥/弱密钥且存在可反序列化组件，可构造 rememberMe 链触发 RCE (CVE-2016-4437)',
                        'status_code': status,
                        'recommendation': '升级 Shiro 至 >=1.7.1，更换强随机 rememberMe 密钥，限制反序列化 Gadget 类',
                    })
                    reported = True

            # 注入垃圾 rememberMe：若服务端回 deleteMe，同样证明 Shiro 存在
            resp2 = await async_get(
                base, session=session, timeout=settings.timeout, no_retry=True,
                headers={"Cookie": "rememberMe=deadbeef"},
            )
            if resp2:
                status2 = resp2[0]
                sc2 = self._cookie(resp2[2] if len(resp2) > 2 else {})
                if not reported and "rememberme=deleteme" in sc2.lower():
                    findings.append({
                        'url': base, 'parameter': 'rememberMe',
                        'payload': 'rememberMe=deadbeef',
                        'type': 'Shiro框架-rememberMe指纹(deleteMe)',
                        'severity': 'Medium', 'ai_verdict': '中', 'confidence': 'high',
                        'evidence': f'注入无效 rememberMe Cookie 后，响应 Set-Cookie 回 `rememberMe=deleteMe` '
                                    '—— Apache Shiro 框架暴露，存在 CVE-2016-4437 反序列化风险面',
                        'status_code': status2,
                        'recommendation': '升级 Shiro 至安全版本并更换强随机密钥',
                    })
        except Exception as e:
            self.log_debug(f"Shiro 指纹扫描异常: {e}")
        return findings

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


# ============================================================
# SpringCloudGatewayEngine（CVE-2022-22947 SpEL RCE 探测，保守）
# ============================================================
class SpringCloudGatewayEngine(BaseEngine):
    """Spring Cloud Gateway actuator 路由端点探测（CVE-2022-22947 前置）

    仅上报"网关 Actuator 路由端点未授权可读"这一确凿事实，并提示 SpEL 注入 RCE 链路。
    """

    name = "spring_cloud_gateway"
    description = "Spring Cloud Gateway actuator 路由端点探测（CVE-2022-22947 SpEL RCE 前置）"

    PROBE_PATHS = [
        "/actuator/gateway/routes",
        "/actuator/gateway/globalfilters",
        "/actuator/routes",
    ]
    ROUTE_HINT_RE = re.compile(r'"route_id"|routeId|"predicates"|"uri"|"filters"', re.I)

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        for path in self.PROBE_PATHS:
            probe_url = base + path
            try:
                resp = await async_get(probe_url, session=session, timeout=settings.timeout, no_retry=True)
            except Exception:
                continue
            if not resp or resp[0] != 200:
                continue
            text = resp[1] or ""
            if not isinstance(text, str) or not text.lstrip().startswith(("[{", "{")):
                continue
            if self.ROUTE_HINT_RE.search(text):
                findings.append({
                    'url': probe_url, 'parameter': '',
                    'payload': path,
                    'type': 'Spring Cloud Gateway 路由端点暴露',
                    'severity': 'High', 'ai_verdict': '高', 'confidence': 'high',
                    'evidence': f'未授权访问 {probe_url} 返回网关路由/过滤器 JSON（{text[:80]}...）—— '
                                'CVE-2022-22947 可在 route filter 注入 SpEL 实现 RCE',
                    'recommendation': '未使用网关 Actuator 则禁用 management 暴露；升级 Spring Cloud Gateway 并限制 actuator/gateway 端点',
                })
                return findings
        return findings

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


# ============================================================
# ContainerPlatformExposureEngine（容器平台/Docker 未授权暴露）
# ============================================================
class ContainerPlatformExposureEngine(BaseEngine):
    """容器平台未授权暴露（Docker Registry v2 / Kubernetes API 指纹）"""

    name = "container_platform_exposure"
    description = "Docker Registry v2 / Kubernetes API 未授权暴露检测"

    K8S_VERSION_RE = re.compile(r'"gitVersion"|"major"\s*:.*"minor"|"platform"', re.I)

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(base)
        try:
            api_base = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            api_base = base

        # Docker Registry v2：/v2/ 返回 200 + Docker-Distribution-Api-Version 头
        try:
            resp = await async_get(api_base + "/v2/", session=session, timeout=settings.timeout, no_retry=True)
            if resp and resp[0] == 200:
                headers = resp[2] if len(resp) > 2 else {}
                drv = None
                for k, v in (headers or {}).items():
                    if k.lower() == "docker-distribution-api-version":
                        drv = v
                        break
                if drv:
                    findings.append({
                        'url': api_base + "/v2/", 'parameter': '',
                        'payload': "/v2/",
                        'type': 'Docker Registry v2 未授权暴露',
                        'severity': 'High', 'ai_verdict': '高', 'confidence': 'high',
                        'evidence': f'请求 {api_base}/v2/ 返回 200 且头 Docker-Distribution-Api-Version={drv} —— '
                                    'Docker 私有仓库未授权，可尝试 /v2/_catalog 枚举镜像',
                        'recommendation': '对 Registry 启用认证与 TLS，限制 Docker-Distribution-Api-Version 暴露',
                    })
                    return findings
        except Exception:
            pass

        # Kubernetes API Server：/version 返回 JSON 含 gitVersion
        try:
            resp = await async_get(api_base + "/version", session=session, timeout=settings.timeout, no_retry=True)
            if resp and resp[0] == 200:
                text = resp[1] or ""
                if self.K8S_VERSION_RE.search(text):
                    findings.append({
                        'url': api_base + "/version", 'parameter': '',
                        'payload': "/version",
                        'type': 'Kubernetes API Server 未授权暴露',
                        'severity': 'High', 'ai_verdict': '高', 'confidence': 'high',
                        'evidence': f'请求 {api_base}/version 返回 k8s 版本 JSON（{(text or "")[:80]}...）—— '
                                    '若未启用 RBAC 可进一步未授权读取集群数据',
                        'recommendation': '对 kube-apiserver 启用认证 + RBAC，并仅内网/受信网络访问',
                    })
                    return findings
        except Exception:
            pass
        return findings

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


# ============================================================
# AdminConsoleExposureEngine（WebLogic/Tomcat/JBoss 管理台暴露）
# ============================================================
class AdminConsoleExposureEngine(BaseEngine):
    """常见中间件管理控制台未授权暴露（WebLogic/Tomcat/JBoss/Jenkins）"""

    name = "admin_console_exposure"
    description = "WebLogic/Tomcat/JBoss/Jenkins 管理控制台暴露检测"

    # path -> (名称, 指纹正则, 严重度, 说明)
    PROBES = [
        ("/console", "WebLogic", re.compile(r"(?i)(webLogic|oracle weblogic|/console/console\.portal|UserToken)"), "High", "WebLogic 管理控制台"),
        ("/wls-wsat", "WebLogic-WSAT", re.compile(r"(?i)(wsat|wls-wsat)"), "High", "WebLogic WSAT（CVE-2017-10271 RCE 面）"),
        ("/manager/html", "Tomcat", re.compile(r"(?i)(manager|tomcat)"), "High", "Tomcat Manager"),
        ("/host-manager/html", "Tomcat", re.compile(r"(?i)(manager|host-manager)"), "Medium", "Tomcat Host Manager"),
        ("/jmx-console", "JBoss", re.compile(r"(?i)(jmx[ -]?console)"), "High", "JBoss JMX Console"),
        ("/admin-console", "JBoss", re.compile(r"(?i)(jboss( management)?)"), "High", "JBoss Admin Console"),
        ("/jenkins/login", "Jenkins", re.compile(r"(?i)(sign in \[jenkins\]|jenkins)"), "Medium", "Jenkins"),
    ]

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        for path, name, sig, severity, title in self.PROBES:
            probe_url = base + path
            try:
                resp = await async_get(probe_url, session=session, timeout=settings.timeout, no_retry=True)
            except Exception:
                continue
            if not resp:
                continue
            status = resp[0]
            text = resp[1] or ""
            if status not in (200, 401, 403):
                continue
            if sig.search(text or ""):
                findings.append({
                    'url': probe_url, 'parameter': '',
                    'payload': path,
                    'type': f'{title} 暴露',
                    'severity': severity, 'ai_verdict': '中', 'confidence': 'high',
                    'evidence': f'访问 {probe_url}（状态 {status}）命中 `{title}` 指纹 —— 管理面暴露，尝试默认口令/已知 CVE',
                    'status_code': status,
                    'recommendation': f'限制 {title} 访问（IP 白名单/内网），禁用默认口令，及时修补已知 CVE',
                })
        return findings

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


__all__ = [
    'ShiroRememberMeEngine',
    'SpringCloudGatewayEngine',
    'ContainerPlatformExposureEngine',
    'AdminConsoleExposureEngine',
]