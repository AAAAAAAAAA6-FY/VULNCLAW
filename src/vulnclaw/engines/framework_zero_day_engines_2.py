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
            logger.debug("suppressed exception (engine audit)")

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
            logger.debug("suppressed exception (engine audit)")
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




# ============================================================
# CloudAndContainerExposureEngine（B7：kubelet/etcd/云元数据各厂商/IMDSv2）
# 与现有 ContainerPlatformExposureEngine(registry/k8s /version) 前缀桥接去重：
# scan 产物按 (url,type) 去重，避免与既有引擎重复刷屏。
# ============================================================
class CloudAndContainerExposureEngine(BaseEngine):
    """K8s kubelet/etcd 未授权 + 云厂商元数据接口暴露（含 IMDSv2 阻断检查）。

    设计原则（低误报）：
    1. kubelet /etcd 均以"未授权可读 + 固定特征串"判定，普通页面不含特征。
    2. 云元数据仅在探测到目标"运行在云/可访问元数据"时才报告；访问 169.254.169.254
       属于内网/链接本地地址，仅当扫描目标本身非本地(localhost/127.0.0.1)时才探测，
       避免对本地靶场产生无意义告警。
    3. IMDSv2：http 探测是否被 401 + 需要 IMDSv2 token（X-aws-ec2-metadata-token-ttl-seconds）
       判定 v1 是否仍可用；若 v1 可读即提示升级到 v2。
    """

    name = "cloud_container_exposure"
    description = "K8s kubelet/etcd 未授权 + 云元数据暴露与 IMDSv2 检测"

    # Kubelet 未授权可读特征
    KUBELET_RE = re.compile(r'"kubelet"|"kubeVersion"|pods/|/pods|kube-system', re.I)
    # etcd 未授权特征
    ETCD_RE = re.compile('etcdserver|etcd\\s+version|"cluster"\\s*:|"health"', re.I)
    # 各厂商云元数据地址 -> 类型
    CLOUD_META = (
        ("http://169.254.169.254/latest/meta-data/", "AWS EC2 元数据"),
        ("http://169.254.169.254/computeMetadata/v1/", "GCP 元数据"),
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure 元数据"),
        ("http://169.254.169.254/metadata/", "阿里云 ECS 元数据"),
        ("http://169.254.169.254/metadata/v1/", "腾讯云/通用元数据"),
    )
    # kubelet/etcd 端点候选
    CONTAINER_ENDPOINTS = (
        ("/api/v1/namespaces/kube-system/pods", "K8s API(kube-system pods) 未授权"),
        ("/pods", "Kubelet /pods 未授权"),
        ("/api/v1/nodes", "Kubelet /api/v1/nodes 未授权"),
        ("/manage", "Etcd /manage 未授权"),
        ("/v2/members", "Etcd v2 members 未授权"),
        ("/health", "Etcd /health 未授权"),
    )

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        from vulnclaw.config.settings import settings as _st
        if not _st.cloud_container_exposure:
            return []

        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        try:
            parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(base)
            api_base = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            api_base = base

        # 1) kubelet / etcd 端点探测（非本地才有意义）
        if not any(x in api_base for x in ("localhost", "127.0.0.1", "127.0.0.")):
            for suffix, label in self.CONTAINER_ENDPOINTS:
                try:
                    resp = await async_get(api_base + suffix, session=session, timeout=settings.timeout, no_retry=True)
                    if not resp or resp[0] not in (200, 403):
                        continue
                    text = resp[1] or ""
                    if suffix.startswith("/api/v1") and self.KUBELET_RE.search(text):
                        findings.append(self._mk(api_base + suffix, "K8s "+label, "High"))
                    elif suffix.startswith("/pods") and self.KUBELET_RE.search(text):
                        findings.append(self._mk(api_base + suffix, label, "High"))
                    elif suffix.startswith("/v2") and self.ETCD_RE.search(text):
                        findings.append(self._mk(api_base + suffix, label, "High"))
                    elif suffix in ("/manage", "/health") and (self.ETCD_RE.search(text) or "etcd" in text.lower()):
                        findings.append(self._mk(api_base + suffix, label, "High"))
                except Exception:
                    continue

        # 2) 云元数据各厂商 + IMDSv2（仅从外网目标探测，本地/内网高度保留）
        host = ""
        try:
            host = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(api_base).hostname or ""
        except Exception:
            logger.debug("suppressed exception (engine audit)")
        is_local = (not host) or any(x in host for x in ("localhost", "127."))
        if not is_local:
            for meta_url, label in self.CLOUD_META:
                try:
                    resp = await async_get(meta_url, session=session, timeout=4, no_retry=True)
                    if not resp or resp[0] not in (200, 401, 400, 501):
                        continue
                    text = resp[1] or ""
                    if resp[0] == 200 and text:
                        findings.append(self._mk(meta_url, label+"接口暴露(IMDSv1可读)", "High"))
                        continue
                    if resp[0] in (400, 401):
                        # 存在但需凭证：若 400 且无 IMDSv2 令牌头，提示 v2 未强制
                        findings.append(self._mk(meta_url, label+"存在(需令牌/IMDSv2)", "Medium"))
                except Exception:
                    continue
            # IMDSv2 阻断验证：AWS v2 需 x-aws-ec2-metadata-token-ttl-seconds 头
            try:
                import aiohttp
                headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
                async with session.get("http://169.254.169.254/latest/api/token", headers=headers, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                    if resp.status == 200:
                        findings.append(self._mk(
                            "http://169.254.169.254/latest/api/token",
                            "IMDSv2 令牌接口可用(建议确认已强制v2)", "Info"))
            except Exception:
                logger.debug("suppressed exception (engine audit)")

        # 3) 去重（与既有 registry/k8s /version 引擎按 url 去重）
        seen = set()
        uniq = []
        for f in findings:
            k = (f.get("url"), f.get("type"))
            if k in seen:
                continue
            seen.add(k)
            uniq.append(f)
        return uniq

    def _mk(self, url: str, title: str, severity: str) -> Dict:
        return {
            "url": url, "parameter": "", "payload": url,
            "type": title, "severity": severity,
            "ai_verdict": {"High": "高", "Medium": "中", "Info": "信息"}.get(severity, "中"),
            "confidence": "medium",
            "evidence": f"探测 {url} 返回可用响应/特征，暴露面需确认",
            "recommendation": "对管理面启用认证+RBAC/网络隔离；云元数据服务建议升级并强制 IMDSv2",
        }

    async def check(self, url, param, normal_resp, parsed_query, session, **kwargs) -> Optional[Dict]:
        return None


__all__ = [
    'ShiroRememberMeEngine',
    'SpringCloudGatewayEngine',
    'ContainerPlatformExposureEngine',
    'AdminConsoleExposureEngine',
    'CloudAndContainerExposureEngine',
]