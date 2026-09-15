# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""发现富化：PoC 复现信息（reproduction_steps / curl_command）与引擎指标（拆出的 mixin）。

拆分原因：orchestrator.py 单文件过大（1661 行），按内聚性拆成 mixin；
方法体逐字迁移（未改一行逻辑），`V100Orchestrator` 多继承后行为不变。
"""
from typing import Dict

from vulnclaw.core.logger import logger, audit_suppressed
from vulnclaw.core.settings import settings


class FindingEvidenceMixin:
    """发现富化：PoC 复现信息（reproduction_steps / curl_command）与引擎指标（拆出的 mixin）。"""

    @staticmethod
    def _sh_quote(value: str) -> str:
        """shell 单引号安全转义（payload 常含引号，直接拼接会破坏命令）。"""
        return "'" + str(value).replace("'", "'\\''") + "'"


    def _expected_observation(self, finding: Dict) -> str:
        """2.1: 按漏洞类型给出"预期现象"描述。"""
        vtype = str(finding.get("type", "")).lower()
        for key, expect in self._REPRO_EXPECTATION.items():
            if key in vtype:
                return expect
        return "响应与正常基线出现显著差异（对比状态码 / 长度 / 内容）"


    def _build_repro_url(self, finding: Dict) -> str:
        """2.1: 构造复现 URL（GET 时把 payload 注入目标参数）。"""
        url = str(finding.get("url") or self.target or "").strip()
        param = finding.get("parameter") or finding.get("param") or ""
        payload = str(finding.get("payload") or "")
        method = str(finding.get("method") or "GET").upper()
        if not param or not payload or method != "GET":
            return url
        try:
            from vulnclaw.core.utils import build_attack_url

            base, _, query = url.partition("?")
            return build_attack_url(base, param, payload, query)
        except Exception:  # noqa: BLE001
            return url


    def _request_cookie_header(self) -> str:
        """2.1: 提取复现所需的 Cookie（会话 + Burp 抓取）。"""
        cookies: Dict[str, str] = {}
        try:
            burp_cookies = (self._recon_brief or {}).get("burp_cookies") or {}
            if isinstance(burp_cookies, dict):
                cookies.update({str(k): str(v) for k, v in burp_cookies.items()})
        except Exception:  # noqa: BLE001
            audit_suppressed()
        try:
            if self.session is not None and getattr(self.session, "cookies", None):
                for k, v in self.session.cookies.items():
                    cookies.setdefault(str(k), str(v))
        except Exception:  # noqa: BLE001
            audit_suppressed()
        return "; ".join(f"{k}={v}" for k, v in cookies.items())


    def _build_curl_command(self, finding: Dict, attack_url: str) -> str:
        """2.1: 生成可直接复制执行的 curl 复现命令。"""
        method = str(finding.get("method") or "GET").upper()
        if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            method = "GET"
        param = finding.get("parameter") or finding.get("param") or ""
        payload = str(finding.get("payload") or "")

        parts = [f"curl -i -s -k -X {method}", self._sh_quote(attack_url)]

        if method != "GET" and param and payload:
            parts.append(f"--data-urlencode {self._sh_quote(f'{param}={payload}')}")
        elif method != "GET":
            parts.append(f"--data {self._sh_quote(finding.get('data', '') or '')}")

        for header_key, header_val in (finding.get("headers") or {}).items():
            if str(header_key).lower() in ("cookie", "content-length", "host"):
                continue
            parts.append(f"-H {self._sh_quote(f'{header_key}: {header_val}')}")

        if getattr(settings, "report_include_cookie", True):
            cookie = self._request_cookie_header()
            if cookie:
                parts.append(f"-H {self._sh_quote(f'Cookie: {cookie}')}")

        return " ".join(p for p in parts if p)


    def _enrich_finding(self, finding: Dict) -> Dict:
        """轨道2 2.1/2.2: 为单条 finding 补齐复现信息与双源确认标记。"""
        attack_url = self._build_repro_url(finding)
        curl = self._build_curl_command(finding, attack_url)
        method = str(finding.get("method") or "GET").upper()
        param = finding.get("parameter") or finding.get("param") or ""
        payload = str(finding.get("payload") or "")
        expected = self._expected_observation(finding)

        finding.setdefault("curl_command", curl)
        finding.setdefault("reproduction", {
            "method": method,
            "url": attack_url,
            "parameter": param,
            "payload": payload,
            "expected": expected,
        })
        finding.setdefault("reproduction_steps", [
            f"1. 以 {method} 方法请求: {attack_url}"
            + (f"（参数 {param} 赋值为 payload）" if param and payload else ""),
            f"2. 注入 Payload: {payload[:300]}" if payload else "2. 无需额外 payload，直接请求目标 URL",
            f"3. 预期现象: {expected}",
            f"4. 复现命令（可直接复制执行）: {curl}",
        ])

        # G 组: 五档证据规范字段（rule_hit / response_evidence / verified /
        # reproduced / oob_success）。此处先按当前信号归一；verify 阶段落锤
        # 后报告路径（normalize_vulns）会基于最终状态重算，二者口径一致。
        try:
            from vulnclaw.core.models import apply_evidence_schema
            apply_evidence_schema(finding)
        except Exception:  # noqa: BLE001 - 规范层缺席不阻断 finding 落库
            audit_suppressed()

        # 轨道2 2.2: 双源确认（引擎命中 + Burp 独立确认）
        burp_ok = bool(finding.get("burp_confirmed") or finding.get("burp_verified"))
        if burp_ok:
            finding["cross_confirmed"] = True
            sources = [str(s) for s in (finding.get("confirmation_sources") or [])]
            if "burp" not in sources:
                sources.append("burp")
            primary = str(finding.get("engine") or finding.get("type") or "engine")
            if primary not in sources:
                sources.insert(0, primary)
            finding["confirmation_sources"] = sources
        else:
            finding.setdefault("cross_confirmed", False)
        return finding


    def _record_engine_metric(self, name: str, elapsed: float, hit: bool, timeout: bool = False, error: bool = False) -> None:
        m = self._engine_metrics.setdefault(
            name, {"calls": 0, "hits": 0, "timeouts": 0, "errors": 0, "total_time": 0.0}
        )
        m["calls"] += 1
        m["total_time"] += elapsed
        if hit:
            m["hits"] += 1
        if timeout:
            m["timeouts"] += 1
        if error:
            m["errors"] += 1
        # 工作流8：引擎耗时导出到 Prometheus（P95/P99 由 histogram_quantile 计算）
        try:
            from vulnclaw.core_modules.metrics import get_metrics
            get_metrics().observe_engine_duration(name, elapsed)
        except Exception:  # noqa: BLE001 - 指标是增强项，绝不影响引擎执行
            pass


    _REPRO_EXPECTATION = {
        "sqli": "响应出现数据库报错（如 You have an error in your SQL syntax）或布尔/延时差异",
        "nosql": "响应出现 NoSQL 报错，或条件恒真/恒假返回不同",
        "xss": "payload 原样回显且未转义（查看页面源码确认未被编码）",
        "cmdi": "响应中包含命令执行结果（如 uid=0(root) 或 whoami 输出）",
        "rce": "响应中包含命令执行结果（如 uid=0(root)）",
        "lfi": "响应中包含目标文件内容（如 /etc/passwd 的 root:x:0:0）",
        "rfi": "远程文件内容被包含并在服务端执行",
        "ssrf": "服务端发起对外请求（OOB/DNS 回调或内网响应回显）",
        "xxe": "外部实体内容被解析回显或产生 OOB 回调",
        "ssti": "模板表达式被求值（如 {{7*7}} → 49）",
        "el_injection": "EL/SpEL 表达式被求值（如 ${7*7} → 49）",
        "deserialization": "反序列化被触发（延时 / OOB 回调 / 命令执行迹象）",
        "open_redirect": "响应 301/302 且 Location 指向外部域名",
        "idor": "可访问或篡改其他用户对象的资源",
        "file_upload": "上传文件可被访问且在服务端被解析执行",
        "jwt": "伪造/篡改的 token 被服务端接受",
        "oauth": "redirect_uri / state 校验被绕过",
        "cors": "Access-Control-Allow-Origin 反射任意 Origin 且允许凭证",
        "crlf": "响应头被注入（Set-Cookie 或自定义头）",
        "host_header": "Host 头被反射进链接或缓存键",
        "cache_poison": "缓存被写入恶意内容，其他用户可命中",
        "graphql": "GraphQL 内省/注入查询返回预期数据",
        "info_leak": "响应中包含敏感信息（路径 / 堆栈 / 密钥）",
        "security_headers": "缺失关键安全响应头（CSP / HSTS / X-Frame-Options）",
        "race_condition": "并发请求导致状态不一致（超额 / 重复提交）",
        "business_logic": "业务逻辑校验被绕过（金额 / 数量 / 权限）",
        "ldap": "LDAP 查询被注入，返回非预期条目",
        "xpath": "XPath 表达式被注入，返回非预期节点",
        "hpp": "同名参数被拼接，服务端行为与预期不一致",
        "smuggling": "前后端解析不一致，请求被走私",
    }
