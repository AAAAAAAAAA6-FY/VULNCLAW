# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/logic_leak_engines_2.py
"""
复杂逻辑 + 敏感泄露 引擎组（v105 新增，与 leak_logic_engines.py 独立）
BackupFileLeakEngine / SwaggerApiDocEngine / GraphQLIntrospectionEngine /
RateLimitEngine / VerbTamperingEngine / PrometheusMetricsExposureEngine
设计原则：
  - 泄露类用"字节魔数 / 固定指纹"判定（低误报）；
  - 逻辑类（如爆破防护缺失）仅给差异证据并标注"需人工复核"，不做破坏性操作。
"""
import re
import random
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, async_post, async_options
from vulnclaw.engines.base import BaseEngine


# ============================================================
# BackupFileLeakEngine（备份 / 源文件 / .env / phpinfo 泄露）
# ============================================================
class BackupFileLeakEngine(BaseEngine):
    """敏感文件 / 备份 / 源码 / 环境变量泄露检测（字节魔数 + 固定指纹）"""

    name = "backup_file_leak"
    description = "备份/源码/.env/phpinfo/SQL 转储泄露检测"

    # path -> (指纹正则或 bytes 前缀, 说明, 严重度)
    PROBES = [
        # 环境变量 (.env 类)
        (".env", (r"(?im)^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S"), ".env 环境变量泄露", "High"),
        (".env.production", (r"(?im)^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S"), ".env.production 泄露", "High"),
        # PHP 配置 / 源码备份
        ("phpinfo.php", (r"(?i)(php\s*version|<title>phpinfo|phpinfo\(\))"), "phpinfo 配置泄露", "High"),
        ("info.php", (r"(?i)(php\s*version|<title>phpinfo|phpinfo\(\))"), "phpinfo 配置泄露", "High"),
        ("config.php.bak", (r"(?i)<\?php|define\s*\(|db_host|mysql"), "PHP 源码备份泄露", "High"),
        ("config.php~", (r"(?i)<\?php|define\s*\(|db_host|mysql"), "PHP 源码备份泄露", "High"),
        ("config.phps", (r"(?i)<\?php|class\s+config|db_"), "PHP 源码备份泄露", "Medium"),
        ("index.php.bak", (r"(?i)<\?php"), "PHP 源码备份泄露", "High"),
        ("index.php~", (r"(?i)<\?php"), "PHP 源码备份泄露", "High"),
        # 数据库转储
        ("database.sql", (r"(?i)create\s+table|insert\s+into|drop\s+table"), "SQL 转储泄露", "High"),
        ("dump.sql", (r"(?i)create\s+table|insert\s+into"), "SQL 转储泄露", "High"),
        ("backup.sql", (r"(?i)create\s+table|insert\s+into"), "SQL 转储泄露", "High"),
        # 压缩包（PGK 魔数在 utf-8 解码下保留前缀）
        ("backup.zip", ("PK\x03\x04",), "备份压缩包泄露", "High"),
        ("backup.rar", ("Rar!\x1a\x07",), "备份压缩包泄露", "High"),
        ("backup.tar.gz", ("\x1f\x8b\x08",), "备份压缩包泄露", "High"),
        # 其他元数据
        (".htaccess.bak", (r"(?i)rewriterule|order\s+deny|directoryindex"), ".htaccess 备份泄露", "Medium"),
        ("web.config.bak", (r"(?i)<configuration>|connectionstrings"), "Web.Config 备份泄露", "Medium"),
    ]

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        for path, sig, title, severity in self.PROBES:
            probe_url = f"{base}/{path}"
            try:
                resp = await async_get(probe_url, session=session, timeout=settings.timeout, no_retry=True)
            except Exception:
                continue
            if not resp or resp[0] != 200:
                continue
            text = resp[1] or ""
            if not isinstance(text, str) or not text:
                continue
            matched = False
            if sig.startswith(("PK\x03", "Rar!", "\x1f\x8b")):
                # 二进制魔数
                matched = text.startswith(sig)
            else:
                matched = re.search(sig, text) is not None
            if not matched:
                continue
            # 排除"默认 404/共用模板"虚拟匹配：env 类要求至少两个 key=value
            if "环境变量" in title and len(re.findall(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", text)) < 2:
                continue
            findings.append({
                'url': probe_url, 'parameter': '',
                'payload': path,
                'type': title,
                'severity': severity, 'ai_verdict': '高', 'confidence': 'high',
                'evidence': f'未授权访问 {probe_url}（状态 200）命中 `{title}` 指纹（{path}），内容可能暴露凭据/源码/配置',
                'recommendation': '生产环境删除备份文件/phpinfo/源码备份，Web 服务器与 WAF 拦截 (.) 开头的隐藏文件与备份扩展名',
            })
        return findings

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


# ============================================================
# SwaggerApiDocEngine（Swagger / OpenAPI 文档暴露）
# ============================================================
class SwaggerApiDocEngine(BaseEngine):
    """Swagger UI / OpenAPI / api-docs 文档暴露（API 面测绘）"""

    name = "swagger_api_doc"
    description = "Swagger / OpenAPI / api-docs 接口文档暴露检测"

    JSON_PROBES = ["/v3/api-docs", "/v2/api-docs", "/api-docs", "/swagger-resources", "/openapi.json"]
    HTML_PROBES = ["/swagger-ui/index.html", "/swagger-ui.html", "/swagger-ui/", "/docs", "/api-docs/"]
    OPENAPI_HINT_RE = re.compile(r'"openapi"\s*:|\bswagger\s*:|\"paths\"\s*:|\"info\"\s*:', re.I)
    SWAGGER_HTML_RE = re.compile(r'swagger-ui|swaggerUIBundle|<title>\s*Swagger', re.I)

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        for path in self.JSON_PROBES:
            probe_url = base + path
            try:
                resp = await async_get(probe_url, session=session, timeout=settings.timeout, no_retry=True)
            except Exception:
                continue
            if not resp or resp[0] != 200:
                continue
            text = resp[1] or ""
            if not isinstance(text, str) or not text.lstrip().startswith(("{", "[")):
                continue
            if self.OPENAPI_HINT_RE.search(text):
                findings.append({
                    'url': probe_url, 'parameter': '',
                    'payload': path,
                    'type': 'OpenAPI/Swagger 接口文档暴露',
                    'severity': 'Medium', 'ai_verdict': '高', 'confidence': 'high',
                    'evidence': f'未授权访问 {probe_url} 返回 OpenAPI/Swagger 定义，可据此批量测绘全部接口',
                    'recommendation': '生产环境关闭文档端点或做身份鉴权，防止接口结构被批量枚举',
                })
                return findings

        for path in self.HTML_PROBES:
            probe_url = base + path
            try:
                resp = await async_get(probe_url, session=session, timeout=settings.timeout, no_retry=True)
            except Exception:
                continue
            if not resp or resp[0] != 200:
                continue
            text = resp[1] or ""
            if self.SWAGGER_HTML_RE.search(text or ""):
                findings.append({
                    'url': probe_url, 'parameter': '',
                    'payload': path,
                    'type': 'Swagger UI 文档暴露',
                    'severity': 'Medium', 'ai_verdict': '中', 'confidence': 'high',
                    'evidence': f'未授权访问 {probe_url} 返回 Swagger UI 页面',
                    'recommendation': '生产关闭 Swagger UI 或加鉴权',
                })
                return findings
        return findings

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


# ============================================================
# GraphQLIntrospectionEngine（GraphQL introspection 是否开启）
# ============================================================
class GraphQLIntrospectionEngine(BaseEngine):
    """GraphQL introspection 探测（__schema 可查询 => 接口边界泄露）"""

    name = "graphql_introspection"
    description = "GraphQL introspection 探测（__schema 查询）"

    ENDPOINTS = ["/graphql", "/gql", "/api/graphql", "/v1/graphql", "/graphiql"]
    SCHEMA_QUERY = "{__schema{queryType{name}types{name}}}"

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        for path in self.ENDPOINTS:
            ep = base + path
            try:
                resp = await async_post(
                    ep, json={"query": self.SCHEMA_QUERY},
                    session=session, timeout=settings.timeout, no_retry=True,
                )
            except Exception:
                continue
            if not resp:
                continue
            text = resp[1] or ""
            if not isinstance(text, str):
                continue
            if "data" in text and "__schema" in text:
                findings.append({
                    'url': ep, 'parameter': '',
                    'payload': self.SCHEMA_QUERY,
                    'type': 'GraphQL introspection 开启',
                    'severity': 'Medium', 'ai_verdict': '高', 'confidence': 'high',
                    'evidence': 'POST 构造 __schema 查询可获取完整 Schema（类型/字段/注释）—— 接口边界与模型信息泄露，'
                                '可结合 query 探测未授权数据访问',
                    'status_code': resp[0],
                    'recommendation': '生产环境关闭 GraphQL introspection（graphql: { introspection: false }）或做鉴权',
                })
                return findings
        return findings

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


# ============================================================
# RateLimitEngine（爆破防护缺失，保守）
# ============================================================
class RateLimitEngine(BaseEngine):
    """登录接口爆破/速率限制缺失检测（非破坏性：仅用随机不存在的账号）"""

    name = "rate_limit"
    description = "登录接口爆破/速率限制缺失检测（需人工复核）"

    LOGIN_PATHS = ["/login", "/signin", "/api/login", "/user/login", "/auth/login", "/account/login"]
    MAX_ATTEMPTS = 5
    LOCKOUT_HINTS = re.compile(
        r"(?i)(rate\s*limit|too\s*many\s*attempts|account\s*locked|temporarily\s*lock|"
        r"brute\s*force|短信?发送过.{0,4}频繁|请求过.{0,4}频繁|captcha|验证码)",
    )

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        candidates = [base] + [base + p for p in self.LOGIN_PATHS]
        for login_url in candidates:
            try:
                resp = await async_get(login_url, session=session, timeout=settings.timeout, no_retry=True)
            except Exception:
                continue
            if not resp:
                continue
            body = resp[1] or ""
            if not isinstance(body, str) or ("password" not in body.lower() and resp[0] not in (200, 405)):
                continue
            ghost = "vlcrate" + "".join(random.sample("abcdefghijklmnopqrstuvwxyz", 8))
            no_protection = True
            for _ in range(self.MAX_ATTEMPTS):
                try:
                    r = await async_post(
                        login_url, data={"username": ghost, "password": "vlc_wrong_xyz"},
                        session=session, timeout=settings.timeout, no_retry=True,
                    )
                except Exception:
                    break
                if not r:
                    break
                body2 = r[1] or ""
                if r[0] == 429 or (isinstance(body2, str) and self.LOCKOUT_HINTS.search(body2)):
                    no_protection = False
                    break
            if no_protection:
                findings.append({
                    'url': login_url, 'parameter': 'username',
                    'payload': f'{self.MAX_ATTEMPTS} 次连续错误登录',
                    'type': '登录爆破防护缺失(速率限制)',
                    'severity': 'Low', 'ai_verdict': '中', 'confidence': 'low',
                    'evidence': f'对 {login_url} 使用随机账号连续 {self.MAX_ATTEMPTS} 次错误登录均未触发锁定/限流(429/提示)，'
                                '存在在线爆破面。黑盒判定，建议人工复核并确认业务是否需要加锁',
                    'recommendation': '登录接口加入速率限制/账户锁定/图形验证码，并统一错误提示',
                })
                return findings
        return findings

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


# ============================================================
# VerbTamperingEngine（TRACE 开启 / 方法篡改）
# ============================================================
class VerbTamperingEngine(BaseEngine):
    """HTTP 方法篡改 / TRACE 开启（XST）检测"""

    name = "verb_tampering"
    description = "TRACE 开启(XST) / HTTP 方法滥权检测"

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        try:
            resp = await async_options(base, session=session, timeout=settings.timeout)
        except Exception:
            return findings
        if not resp:
            return findings
        headers = resp[2] if len(resp) > 2 else {}
        allow = ""
        for k, v in (headers or {}).items():
            if k.lower() == "allow":
                allow = str(v)
                break
        if not allow or resp[0] not in (200, 204, 405):
            return findings
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        if "TRACE" in methods:
            findings.append({
                'url': base, 'parameter': '',
                'payload': 'OPTIONS -> Allow: ' + allow,
                'type': 'TRACE 开启(XSS via XST)',
                'severity': 'Medium', 'ai_verdict': '高', 'confidence': 'high',
                'evidence': f'OPTIONS 请求 {base} 返回 Allow 头含 TRACE —— 开启 TRACE 可能导致跨站跟踪(XST)，'
                            '配合已存储 XSS 可窃取 HttpOnly Cookie',
                'status_code': resp[0],
                'recommendation': '禁用 TRACE 方法（部署层默认 Deny TRACE）',
            })
        elif methods & {"PUT", "DELETE"}:
            findings.append({
                'url': base, 'parameter': '',
                'payload': 'OPTIONS -> Allow: ' + allow,
                'type': '危险HTTP方法可用(信息)',
                'severity': 'Low', 'ai_verdict': '中', 'confidence': 'medium',
                'evidence': f'OPTIONS 请求 {base} 的 Allow 头声明 PUT/DELETE 方法，可能存在上传/篡改面，请人工确认',
                'status_code': resp[0],
                'recommendation': '按需关闭不必要的 HTTP 方法，或对 PUT/DELETE 做鉴权',
            })
        return findings

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


# ============================================================
# PrometheusMetricsExposureEngine（监控指标未授权暴露）
# ============================================================
class PrometheusMetricsExposureEngine(BaseEngine):
    """Prometheus / 指标端点未授权暴露检测"""

    name = "prometheus_metrics"
    description = "Prometheus / 指标端点未授权暴露检测"

    PROBE_PATHS = ["/metrics", "/prometheus", "/metrics/prometheus", "/actuator/prometheus", "/api/metrics"]
    METRIC_LINE_RE = re.compile(r"(?m)^\s*(?:#\s*HELP|#\s*TYPE|[a-zA-Z_:][a-zA-Z0-9_:]*\s+\d)")

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
            if not isinstance(text, str) or len(text) < 200:
                continue
            matches = self.METRIC_LINE_RE.findall(text)
            if len(matches) >= 5:
                findings.append({
                    'url': probe_url, 'parameter': '',
                    'payload': path,
                    'type': 'Prometheus 监控指标泄露',
                    'severity': 'Medium', 'ai_verdict': '高', 'confidence': 'high',
                    'evidence': f'未授权访问 {probe_url} 返回 Prometheus 格式指标（`{text[:80]}...`），'
                                '可能泄露内部版本/路由/资源使用等敏感信息',
                    'status_code': resp[0],
                    'recommendation': '生产关闭指标端点或做内网/鉴权隔离',
                })
                return findings
        return findings

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


class JsLibraryCveEngine(BaseEngine):
    """前端 JS 依赖版本识别与已知漏洞匹配（CWE-1104 使用有漏洞组件）

    从首页 HTML / 脚本引用中提取前端库名与版本号，
    与内置已知漏洞版本区间比对，命中即报组件漏洞。
    """

    name = "js_library_cve"
    description = "前端 JS 库版本识别与已知 CVE 匹配（组件漏洞）"

    # (库名, 版本提取正则)
    LIBRARY_PATTERNS = (
        ("jQuery", r"jquery[.-](\d+\.\d+(?:\.\d+)?)"),
        ("jQuery UI", r"jquery[-.]ui[.-](\d+\.\d+(?:\.\d+)?)"),
        ("React", r"react(?:\.production|\.development)?[.-](\d+\.\d+(?:\.\d+)?)"),
        ("Vue", r"vue(?:\.runtime|\.min)?[.-](\d+\.\d+(?:\.\d+)?)"),
        ("AngularJS", r"angular(?:\.min)?[.-](\d+\.\d+(?:\.\d+)?)"),
        ("Bootstrap", r"bootstrap(?:\.min)?[.-](\d+\.\d+(?:\.\d+)?)"),
        ("lodash", r"lodash(?:\.min)?[.-](\d+\.\d+(?:\.\d+)?)"),
        ("moment", r"moment(?:\.min)?[.-](\d+\.\d+(?:\.\d+)?)"),
        ("Handlebars", r"handlebars(?:\.min)?[.-](\d+\.\d+(?:\.\d+)?)"),
        ("D3", r"d3(?:\.min)?[.-](\d+\.\d+(?:\.\d+)?)"),
    )

    # (库名, 受影响最低版本, 受影响最高版本, CVE, 严重度, 风险说明)
    KNOWN_VULNERABLE_RANGES = (
        ("jQuery", (1, 0, 0), (3, 5, 0), "CVE-2020-11022 / CVE-2020-11023", "Medium",
         "html() 等方法处理不可信 HTML 时可导致 XSS"),
        ("jQuery UI", (1, 10, 0), (1, 12, 1), "CVE-2021-41184", "Low",
         "对话框 title 选项未转义导致 XSS"),
        ("lodash", (0, 0, 0), (4, 17, 20), "CVE-2021-23337", "High",
         "template 处理不可信输入可导致命令注入"),
        ("moment", (0, 0, 0), (2, 29, 1), "CVE-2022-31129", "Medium",
         "路径遍历与 ReDoS 风险"),
        ("Handlebars", (0, 0, 0), (4, 7, 6), "CVE-2021-23369", "High",
         "模板编译过程可被利用执行任意代码（RCE）"),
        ("AngularJS", (1, 0, 0), (1, 8, 2), "CVE-2024-21490", "Medium",
         "$sanitize 正则绕过导致 XSS"),
        ("Bootstrap", (0, 0, 0), (4, 1, 2), "CVE-2019-8331", "Low",
         "tooltip/popover 的 data 属性可导致 XSS"),
    )

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        from vulnclaw.config.settings import settings as _st
        if not _st.component_cve_check:
            return []

        """扫描首页引用的前端 JS 库，匹配已知漏洞版本。"""
        findings: List[Dict] = []
        try:
            resp = await async_get(target, session=session, timeout=settings.timeout, no_retry=True)
            if isinstance(resp, tuple):
                status, text = resp[0], resp[1] or ""
            else:
                status, text = resp.status, (await resp.text()) or ""
        except Exception:
            return findings
        if status != 200 or not text:
            return findings

        # H.2 扩展：库识别 = N 条正则扫全文响应体，纯 CPU 挪线程池
        import asyncio

        def _detect_libraries() -> Dict[str, str]:
            d: Dict[str, str] = {}
            for lib_name, pattern in self.LIBRARY_PATTERNS:
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    d[lib_name] = m.group(1)
            return d

        detected = await asyncio.to_thread(_detect_libraries)

        if not detected:
            return findings

        logger.info(f"🔍 [JsLibCVE] 识别到前端库: {detected}")

        for lib_name, version in detected.items():
            parsed_version = self._parse_version(version)
            if not parsed_version:
                continue
            for (name, low, high, cve, severity, risk) in self.KNOWN_VULNERABLE_RANGES:
                if name != lib_name:
                    continue
                if low <= parsed_version <= high:
                    findings.append({
                        'url': target,
                        'parameter': '',
                        'type': f'前端组件漏洞：{lib_name} {version}',
                        'severity': severity,
                        'ai_verdict': '高',
                        'confidence': 'medium',
                        'evidence': (
                            f'页面引用 {lib_name} {version}，落在 {cve} 受影响版本区间 '
                            f'[{self._fmt(low)} - {self._fmt(high)}]，{risk}'
                        ),
                        'recommendation': f'将 {lib_name} 升级到 {self._fmt(high)} 之后的安全版本',
                        'remediation': f'升级 {lib_name} 至不受影响版本，并锁定依赖版本（SCA 持续监控）',
                        'method': 'GET',
                        'cvss': 7.5 if severity == 'High' else (5.4 if severity == 'Medium' else 3.7),
                    })
                    break

        logger.info(f"   ✅ JsLibCVE 完成，发现 {len(findings)} 个问题")
        return findings

    @staticmethod
    def _parse_version(version: str):
        try:
            parts = [int(p) for p in str(version).split(".")[:3]]
            while len(parts) < 3:
                parts.append(0)
            return tuple(parts[:3])
        except Exception:
            return None

    @staticmethod
    def _fmt(version) -> str:
        return ".".join(str(p) for p in version)




# ============================================================
# BackendComponentFingerprintEngine（B8：后端组件指纹 + 精简 CVE 匹配）
# 从响应头(Server/X-Powered-By)与 HTML 中的框架特征识别后端组件版本，
# 命中内置"过时/高危版本区间"表即报组件漏洞（不依赖 nuclei，闭环自足）。
# ============================================================
class BackendComponentFingerprintEngine(BaseEngine):
    """后端组件版本指纹与已知 CVE 匹配（CWE-1104 有漏洞组件）。

    数据来源：
    1. HTTP 响应头 Server / X-Powered-By / Via
    2. HTML 中的生成器 meta 标签（meta name=generator）
    3. 常见框架暴露的特征串（如 WordPress /wp-content、Express、Django 错误页）

    仅当解析出版本号且落在精简映射表内才报，未版本化不报（低误报）。
    """

    name = "backend_component_cve"
    description = "后端组件版本指纹与已知 CVE 匹配（CWE-1104）"

    # (组件名, 版本正则(作用于 headers/html), CVE, 受影响最低版本, 受影响最高版本, 严重度, 说明)
    BACKEND_RULES = (
        ("Apache", r"Apache/(\d+\.\d+(?:\.\d+)?)", "CVE-2021-41773 / CVE-2021-42013",
         (2, 4, 49), (2, 4, 50), "Critical", "Apache 2.4.49/50 路径穿越与 RCE"),
        ("Apache", r"Apache/(\d+\.\d+(?:\.\d+)?)", "CVE-2017-15715",
         (2, 4, 0), (2, 4, 34), "Medium", "换行解析差异导致文件上传绕过"),
        ("Nginx", r"nginx/(\d+\.\d+(?:\.\d+)?)", "CVE-2021-23017",
         (0, 6, 18), (1, 20, 0), "High", "DNS 响应处理内存损坏 RCE"),
        ("PHP", r"PHP/(\d+\.\d+(?:\.\d+)?)", "CVE-2019-11043",
         (7, 1, 0), (7, 1, 28), "High", "PHP-FPM + 特定配置远程代码执行"),
        ("ASP.NET", r"ASP\.NET/?(\d+\.\d+(?:\.\d+)?)?", "CVE-2022-21986",
         (4, 0, 0), (4, 8, 0), "Medium", "ASP.NET 凭据泄露相关加固问题"),
        ("OpenSSL", r"OpenSSL/(\d+\.\d+(?:\.\d+)?)", "CVE-2014-3566 / CVE-2016-6309",
         (1, 0, 1), (1, 0, 2), "High", "历史 SSL/TLS 已知漏洞"),
        ("Jetty", r"Jetty/(\d+\.\d+\.\d+)", "CVE-2021-28164",
         (9, 4, 0), (9, 4, 37), "High", "Jetty 路径信息泄露"),
    )
    # HTML generator/meta 特征补充（组件 -> 正则）
    HTML_GENERATOR_RE = re.compile(
        r'<meta[^>]+name=["'']generator["''][^>]+content=["'']([^"'']+)',
        re.I,
    )
    # 若无版本但组件过度暴露本身即问题（仅框架指纹，属于 Info 提示，非 CVE）
    FRAMEWORK_FINGERPRINTS = (
        ("WordPress", r"/wp-content/|wp-includes"),
        ("Express", r"express global|powered by express"),
        ("Django", r"django.core|csrftoken|django/"),
    )

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        from vulnclaw.config.settings import settings as _st
        if not _st.component_cve_check:
            return []

        findings: List[Dict] = []
        headers: Dict = {}
        body = ""
        try:
            resp = await async_get(target, session=session, timeout=settings.timeout, no_retry=True)
            if isinstance(resp, tuple):
                status, body, headers = resp[0], resp[1] or "", resp[2] or {}
            else:
                status, body = resp.status, (await resp.text()) or ""
                headers = dict(resp.headers)
        except Exception:
            return findings
        if status not in (200, 301, 302, 403, 500):
            return findings

        # 收集要匹配的文本（头 + 体）
        header_text = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
        haystack = header_text + "\n" + body

        # 1) 后端组件版本 CVE 匹配（头）
        for name, pat, cve, low, high, sev, risk in self.BACKEND_RULES:
            m = re.search(pat, haystack, re.I)
            if not m or len(m.groups()) < 1:
                continue
            ver = m.group(1)
            pv = self._parse_version(ver)
            if not pv:
                continue
            if low <= pv <= high:
                findings.append(self._mk(target, f"后端组件漏洞：{name} {ver}", sev, cve, risk, ver))
                break  # 每组件只报最严重一条，避免重复

        # 2) HTML generator meta（后端生成框架版本）
        gm = self.HTML_GENERATOR_RE.search(body or "")
        if gm:
            meta_val = gm.group(1).strip()
            # 尝试抽取其中的版本号
            vm = re.search(r"(\d+\.\d+(?:\.\d+)?)", meta_val)
            if vm:
                findings.append(self._mk(
                    target, f"后端框架指纹：{meta_val[:60]}", "Info",
                    "", "", meta_val[:100]))
            else:
                findings.append(self._mk(
                    target, f"生成器泄露：{meta_val[:80]}", "Info",
                    "", "", meta_val[:100]))

        # 3) 框架指纹（无版本，仅 Info 暴露提示）
        for fname, fpat in self.FRAMEWORK_FINGERPRINTS:
            if re.search(fpat, body or "", re.I):
                findings.append(self._mk(
                    target, f"后端框架指纹：{fname}", "Info", "", "", fname))
                break

        # 去重
        seen = set()
        uniq = []
        for f in findings:
            k = (f.get("type"), f.get("url"))
            if k in seen:
                continue
            seen.add(k)
            uniq.append(f)
        return uniq

    @staticmethod
    def _parse_version(version: str):
        try:
            parts = [int(p) for p in str(version).split(".")[:3]]
            while len(parts) < 3:
                parts.append(0)
            return tuple(parts[:3])
        except Exception:
            return None

    def _mk(self, url: str, title: str, sev: str, cve: str, risk: str, ver: str) -> Dict:
        return {
            "url": url, "parameter": "", "type": title,
            "severity": sev,
            "ai_verdict": {"Critical": "严重", "High": "高", "Medium": "中", "Info": "信息"}.get(sev, "中"),
            "confidence": "medium",
            "evidence": f"指纹 {ver!r} 命中{'已知漏洞 ' + cve + (' —— ' + risk) if cve else '暴露面（无版本，仅提示）'}",
            "recommendation": "升级受影响组件至安全版本，并移除/收紧 Server 与 generator 指纹暴露",
        }

    async def check(self, url, param, normal_resp, parsed_query, session, **kwargs) -> Optional[Dict]:
        return None


__all__ = [
    'BackupFileLeakEngine',
    'SwaggerApiDocEngine',
    'GraphQLIntrospectionEngine',
    'RateLimitEngine',
    'VerbTamperingEngine',
    'PrometheusMetricsExposureEngine',
    'JsLibraryCveEngine',
    'BackendComponentFingerprintEngine',
]