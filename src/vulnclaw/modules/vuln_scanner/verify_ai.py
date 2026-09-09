# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# modules/vuln_scanner.py
"""
漏洞扫描辅助工具模块 - 精简版
包含：AI验证、批量验证、Nuclei验证、参数提取
"""
import asyncio
import re
import json
import time
from urllib.parse import urljoin

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_post, limit_response_size
from vulnclaw.ai.core import get_llm_client, get_configured_ai_models, LLMClient
from typing import Dict, List, Optional


# ============================================================
# AI 验证限流器（统一走 ai.v100.rate_limiter.AdaptiveRateLimiter，懒加载避免循环导入）
# ============================================================
class VulnAIRateLimiter:
    def __init__(self, max_calls_per_second: float = 0.33):
        self.rate = max_calls_per_second
        self._impl = None
        self._init_lock = None

    async def _ensure_impl(self):
        if self._impl is not None:
            return
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        async with self._init_lock:
            if self._impl is not None:
                return
            # ★ 懒加载：避免 modules/vuln_scanner.verify_ai 早期 import 造成循环 ★
            from vulnclaw.ai.v100.rate_limiter import AdaptiveRateLimiter
            self._impl = AdaptiveRateLimiter(max(1, int(self.rate * 2) or 1))

    async def acquire(self):
        await self._ensure_impl()
        # 按原语义：极低频率 ≈ 每秒 0.33 次。若自适应 impl 速率过高，这里手动额外 sleep 兜底
        await self._impl.acquire()
        if self.rate and self.rate < 1.0:
            extra_sleep = (1.0 / self.rate) - 0.5
            if extra_sleep > 0:
                await asyncio.sleep(extra_sleep)


_vuln_limiter = VulnAIRateLimiter(max_calls_per_second=0.33)


# ============================================================
# AI 验证状态管理
# ============================================================
_AI_VERIFY_FAILED = False
_VULN_LLM_FAIL_COUNT = 0
_VULN_LLM_MAX_FAIL = 8
_vuln_llm_client = None
_last_fail_time = 0
_RECOVERY_SECONDS = 120

# 重试队列（修复：增加尝试次数计数器）
_pending_retry_verifications: List[Dict] = []
_pending_retry_lock = asyncio.Lock()
_RETRY_EXPIRE_SECONDS = 600
_MAX_RETRY_ATTEMPTS = 3


def get_vuln_llm_client():
    global _vuln_llm_client
    if _vuln_llm_client is None:
        model_names = get_configured_ai_models()
        model_names = [m for m in model_names if m not in LLMClient._blocked_models]
        if not model_names:
            logger.info("ℹ️ 未配置 AI 模型（纯引擎模式），跳过 AI 漏洞验证")
            return None
        _vuln_llm_client = get_llm_client(
            max_total_tokens=5000000,
            max_rounds=500,
            force_new=True
        )
        _vuln_llm_client.models = model_names
        logger.info(f"🧠 漏洞验证客户端已创建 (模型: {model_names})")
    return _vuln_llm_client


def safe_extract_json(text: str) -> Optional[Dict]:
    if not text:
        return None
    try:
        return json.loads(text)
    except BaseException:
        logger.debug("suppressed exception (core audit)")
    cleaned = re.sub(r'```json\s*|\s*```', '', text)
    cleaned = re.sub(r'```\s*|\s*```', '', cleaned)
    match = re.search(r'(\{.*\})', cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except BaseException:
            logger.debug("suppressed exception (core audit)")
    match = re.search(r'(\[.*\])', cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except BaseException:
            logger.debug("suppressed exception (core audit)")
    return None


def normalize_response(text: str) -> str:
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
    text = re.sub(r'\b_=[a-zA-Z0-9]{8,}', '', text)
    text = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '', text, flags=re.I)
    text = re.sub(r'\b[a-f0-9]{32,64}\b', '', text, flags=re.I)
    return text


# ============================================================
# 规则降级验证
# ============================================================
def _rule_based_verify(request: str, response: str) -> Dict:
    if not response:
        return {"vuln_type": "未知", "confidence": "低", "evidence": "无响应数据"}

    response_lower = response.lower()

    if 'nreum' in response_lower or 'newrelic' in response_lower:
        response_lower = response_lower.replace('nreum', '').replace('newrelic', '')

    sql_patterns = [
        'sql syntax', 'mysql', 'postgresql', 'ora-', 'sqlstate',
        'you have an error', 'unclosed quotation mark',
        'microsoft ole db', 'odbc', 'jdbc', 'db2', 'sqlite'
    ]
    for pat in sql_patterns:
        if pat in response_lower:
            return {
                "vuln_type": "SQL注入",
                "confidence": "中（规则降级）",
                "evidence": f"检测到 SQL 错误特征: {pat}"
            }

    xss_patterns = ['<script>', 'alert(', 'onerror=', 'onload=', 'javascript:']
    for pat in xss_patterns:
        if pat in response_lower:
            return {
                "vuln_type": "XSS",
                "confidence": "中（规则降级）",
                "evidence": f"检测到 XSS 特征: {pat}"
            }

    if 'root:x:0:0' in response or 'etc/passwd' in response_lower:
        return {
            "vuln_type": "路径遍历",
            "confidence": "中（规则降级）",
            "evidence": "检测到敏感文件内容"
        }

    return {
        "vuln_type": "可疑",
        "confidence": "低（规则降级）",
        "evidence": "AI 熔断期间使用规则判断，未发现明显特征"
    }


# ============================================================
# 清理过期重试项
# ============================================================
async def _clean_expired_retries():
    async with _pending_retry_lock:
        global _pending_retry_verifications
        now = time.time()
        valid_items = []
        for item in _pending_retry_verifications:
            if now - item.get('timestamp', 0) < _RETRY_EXPIRE_SECONDS:
                # 检查尝试次数
                if item.get('attempts', 0) < _MAX_RETRY_ATTEMPTS:
                    valid_items.append(item)
                else:
                    logger.debug(f"⏭️ 任务已重试 {_MAX_RETRY_ATTEMPTS} 次，丢弃: {item.get('request', '')[:50]}")
            else:
                logger.debug(f"⏭️ 任务已过期，丢弃: {item.get('request', '')[:50]}")
        _pending_retry_verifications = valid_items


# ============================================================
# verify_with_ai
# ============================================================
async def verify_with_ai(request: str, response: str) -> Dict:
    global _AI_VERIFY_FAILED, _VULN_LLM_FAIL_COUNT, _last_fail_time, _pending_retry_verifications
    global _AI_VERIFY_FAILED, _VULN_LLM_FAIL_COUNT, _last_fail_time, _pending_retry_verifications
    """
    AI 验证单个漏洞
    修复：熔断期间使用规则降级，并记录重试次数
    """
    global _AI_VERIFY_FAILED, _VULN_LLM_FAIL_COUNT, _last_fail_time

    if _AI_VERIFY_FAILED:
        if time.time() - _last_fail_time > _RECOVERY_SECONDS:
            _AI_VERIFY_FAILED = False
            _VULN_LLM_FAIL_COUNT = 0
            logger.info("♻️ AI 验证降级已自动恢复（冷切 120 秒到期）")
            async with _pending_retry_lock:
                await _clean_expired_retries()
                if _pending_retry_verifications:
                    logger.info(f"🔄 恢复后重试 {len(_pending_retry_verifications)} 个待验证项")
        else:
            remaining = int(_RECOVERY_SECONDS - (time.time() - _last_fail_time))
            rule_result = _rule_based_verify(request, response)
            rule_result['evidence'] = f"{rule_result['evidence']} (AI 熔断中，剩余冷切 {remaining}s)"
            async with _pending_retry_lock:
                await _clean_expired_retries()
                # 查找是否有已存在的相同任务
                exists = False
                for item in _pending_retry_verifications:
                    if item.get('request') == request and item.get('response') == response:
                        exists = True
                        break
                if not exists:
                    _pending_retry_verifications.append({
                        "request": request,
                        "response": response,
                        "timestamp": time.time(),
                        "attempts": 0
                    })
                if len(_pending_retry_verifications) > 1000:
                    _pending_retry_verifications = _pending_retry_verifications[-1000:]
            return rule_result

    await _vuln_limiter.acquire()
    client = get_vuln_llm_client()
    if client is None:
        rule_result = _rule_based_verify(request, response)
        rule_result['evidence'] = f"{rule_result['evidence']} (未配置 AI 模型，使用规则降级)"
        return rule_result

    compressed = limit_response_size(response, 1500)

    prompt = f"""
你是一位严格的安全漏洞验证专家。请分析以下HTTP交互是否存在安全漏洞。

【请求】: {request[:300]}
【响应片段】: {compressed}

判断标准：
1. 必须给出具体证据（引用响应中的异常字符、错误信息或特殊回显）
2. 如果 confidence 为"高"，必须有明确的攻击成功特征
3. 如果只是正常的业务响应（如 404、403），不认定为漏洞

输出JSON格式：
{{"vuln_type":"漏洞类型","confidence":"高/中/低","evidence":"具体判断依据（引用响应中的关键证据）"}}
"""
    models_to_try = client.models
    last_error = None

    for model in models_to_try:
        try:
            system = "你是一名安全专家，只输出JSON。必须包含 evidence 字段，内容为具体证据。"
            result = await client.ask(
                prompt,
                system=system,
                temperature=0.1,
                wrap_data=True,
                models=[model]
            )
            _VULN_LLM_FAIL_COUNT = 0
            data = safe_extract_json(result)
            if data is not None:
                if 'evidence' not in data or not data['evidence']:
                    data['evidence'] = 'AI 判定但未提供具体证据'
                return data
            else:
                rule_result = _rule_based_verify(request, response)
                rule_result['evidence'] = f"{rule_result['evidence']} (AI 返回格式异常，使用规则兜底)"
                return rule_result
        except Exception as e:
            logger.warning(f"⚠️ 模型 {model} 验证失败: {e}")
            last_error = e
            _VULN_LLM_FAIL_COUNT += 1
            continue

    if _VULN_LLM_FAIL_COUNT >= _VULN_LLM_MAX_FAIL:
        _AI_VERIFY_FAILED = True
        _last_fail_time = time.time()
        logger.warning(f"⚠️ AI 连续失败 {_VULN_LLM_FAIL_COUNT} 次，进入降级模式，120 秒后自动恢复")
        rule_result = _rule_based_verify(request, response)
        rule_result['evidence'] = f"{rule_result['evidence']} (AI 熔断触发，使用规则降级)"
        return rule_result

    return {"vuln_type": "可疑", "confidence": "中", "evidence": f"AI 异常后规则判定: {str(last_error)[:50]}"}


# ============================================================
# batch_verify_with_ai
# ============================================================
async def batch_verify_with_ai(suspects: List[Dict]) -> List[Dict]:
    """
    批量 AI 验证
    修复：熔断期间记录重试任务，恢复后自动重试，带尝试次数限制
    """
    global _AI_VERIFY_FAILED, _pending_retry_verifications

    if not suspects:
        return suspects

    if not _AI_VERIFY_FAILED:
        async with _pending_retry_lock:
            await _clean_expired_retries()
            if _pending_retry_verifications:
                logger.info(f"🔄 处理 {len(_pending_retry_verifications)} 个待重试验证项")
                retry_items = _pending_retry_verifications.copy()
                _pending_retry_verifications.clear()
                for item in retry_items:
                    suspects.append({
                        "request": item.get("request", ""),
                        "response": item.get("response", ""),
                        "_retry": True,
                        "_attempts": item.get("attempts", 0) + 1
                    })

    client = get_vuln_llm_client()
    if client is None:
        # 纯引擎模式：逐条用规则降级，不打 AI
        for s in suspects:
            rule_result = _rule_based_verify(s.get('request', ''), s.get('response', ''))
            rule_result['evidence'] = f"{rule_result['evidence']} (未配置 AI 模型，使用规则降级)"
            s['ai_result'] = rule_result
        return suspects

    batch_size = 8
    results = []

    for i in range(0, len(suspects), batch_size):
        batch = suspects[i:i + batch_size]

        if _AI_VERIFY_FAILED:
            for s in batch:
                attempts = s.get('_attempts', 0)
                if attempts >= _MAX_RETRY_ATTEMPTS:
                    rule_result = _rule_based_verify(
                        s.get('request', ''),
                        s.get('response', '')
                    )
                    rule_result['evidence'] = f"{rule_result['evidence']} (已达最大重试次数 {_MAX_RETRY_ATTEMPTS})"
                    s['ai_result'] = rule_result
                else:
                    rule_result = _rule_based_verify(
                        s.get('request', ''),
                        s.get('response', '')
                    )
                    rule_result['evidence'] = f"{rule_result['evidence']} (AI 熔断中)"
                    s['ai_result'] = rule_result
                    async with _pending_retry_lock:
                        await _clean_expired_retries()
                        exists = False
                        for item in _pending_retry_verifications:
                            if item.get('request') == s.get('request') and item.get('response') == s.get('response'):
                                exists = True
                                break
                        if not exists:
                            _pending_retry_verifications.append({
                                "request": s.get('request', ''),
                                "response": s.get('response', ''),
                                "timestamp": time.time(),
                                "attempts": attempts + 1
                            })
                        if len(_pending_retry_verifications) > 1000:
                            _pending_retry_verifications = _pending_retry_verifications[-1000:]
            results.extend(batch)
            continue

        parts = []
        for idx, s in enumerate(batch):
            req = s.get('request', '')[:250]
            resp = limit_response_size(s.get('response', ''), 600)
            parts.append(f"## 样本{idx + 1}\n请求: {req}\n响应片段: {resp}\n")

        prompt = f"""你是一个漏洞验证专家。请分析以下HTTP交互，对每个样本输出JSON对象，合并为JSON数组。
每个样本必须包含 evidence 字段。

{chr(10).join(parts)}

输出格式：[{{"vuln_type":"类型","confidence":"高/中/低","evidence":"具体证据"}}]
"""

        try:
            await _vuln_limiter.acquire()
            result = await client.ask(
                prompt,
                system="只输出JSON数组，每个元素必须有 evidence 字段。",
                temperature=0.1,
                wrap_data=True
            )
            data = safe_extract_json(result)
            if isinstance(data, list) and len(data) == len(batch):
                for j, item in enumerate(data):
                    if 'evidence' not in item or not item['evidence']:
                        item['evidence'] = 'AI 判定但未提供具体证据'
                    batch[j]['ai_result'] = item
                results.extend(batch)
                continue
            else:
                if isinstance(data, list):
                    logger.warning(f"⚠️ 批量验证长度不匹配: AI返回 {len(data)} 个，期望 {len(batch)} 个，尝试逐个匹配")
                    used_indices = set()
                    for item in data:
                        idx = item.get('index', -1)
                        if idx is None or idx == -1:
                            for k in range(len(batch)):
                                if k not in used_indices:
                                    used_indices.add(k)
                                    if 'evidence' not in item or not item['evidence']:
                                        item['evidence'] = 'AI 判定但未提供具体证据'
                                    batch[k]['ai_result'] = item
                                    break
                        elif 0 <= idx < len(batch):
                            used_indices.add(idx)
                            if 'evidence' not in item or not item['evidence']:
                                item['evidence'] = 'AI 判定但未提供具体证据'
                            batch[idx]['ai_result'] = item
                    for k in range(len(batch)):
                        if k not in used_indices:
                            rule_result = _rule_based_verify(
                                batch[k].get('request', ''),
                                batch[k].get('response', '')
                            )
                            rule_result['evidence'] = f"{rule_result['evidence']} (批量验证未匹配，使用规则兜底)"
                            batch[k]['ai_result'] = rule_result
                    results.extend(batch)
                    continue
                else:
                    raise ValueError("AI 返回不是有效的 JSON 数组")
        except Exception as e:
            logger.warning(f"批量验证失败: {e}")
            for s in batch:
                attempts = s.get('_attempts', 0)
                if attempts >= _MAX_RETRY_ATTEMPTS:
                    rule_result = _rule_based_verify(
                        s.get('request', ''),
                        s.get('response', '')
                    )
                    rule_result['evidence'] = f"{rule_result['evidence']} (已达最大重试次数 {_MAX_RETRY_ATTEMPTS})"
                    s['ai_result'] = rule_result
                else:
                    try:
                        result = await verify_with_ai(s.get('request', ''), s.get('response', ''))
                        s['ai_result'] = result
                    except BaseException:
                        s['ai_result'] = {"vuln_type": "可疑", "confidence": "低", "evidence": "批量验证降级"}
            results.extend(batch)

    return results


# ============================================================
# verify_nuclei_with_ai_async
# ============================================================
async def verify_nuclei_with_ai_async(
    nuclei_results: List[Dict], target_url: str, evidence: Optional[bool] = None
) -> List[Dict]:
    """C 方案：nuclei 结果 AI 验证（证据增强可选）。

    evidence=True 时每条发现附加 matched-at 原文与模板描述（对齐 A 方案
    证据型裁决）；None 时读 settings.nuclei_ai_evidence 回退。
    输出契约不变：仍返回带 ai_verdict/confidence/ai_reason 的结果列表。
    """
    if not nuclei_results:
        return []
    if evidence is None:
        try:
            evidence = bool(getattr(settings, "nuclei_ai_evidence", True))
        except Exception:  # noqa: BLE001 - settings 不可用时默认开启
            evidence = True

    global _AI_VERIFY_FAILED, _last_fail_time

    if _AI_VERIFY_FAILED:
        for r in nuclei_results:
            r['ai_verdict'] = '待复核（AI已降级）'
            r['confidence'] = '中'
            r['ai_reason'] = 'AI 验证已降级，请人工复核'
        return nuclei_results

    client = get_vuln_llm_client()
    if client is None:
        for r in nuclei_results:
            r['ai_verdict'] = '待复核（未配置AI）'
            r['confidence'] = '中'
            r['ai_reason'] = '未配置 AI 模型（纯引擎模式），请人工复核'
        return nuclei_results

    verified_results = []

    batch_size = 5
    for i in range(0, len(nuclei_results), batch_size):
        batch = nuclei_results[i:i + batch_size]
        findings_str = []
        for idx, item in enumerate(batch):
            matched_raw = (item.get('matched') or item.get('url') or '')
            desc = (item.get('info') or '')
            if evidence:
                # C 方案证据增强：附上匹配原文与描述（裁剪），对齐 A 方案证据型裁决
                findings_str.append(f"""
【发现 {idx + 1}】
- 模板: {item.get('template', '未知')}
- 严重性: {item.get('severity', '未知')}
- 描述: {str(desc)[:300]}
- 匹配位置: {str(matched_raw)[:300]}
""")
            else:
                findings_str.append(f"""
【发现 {idx + 1}】
- 模板: {item.get('template', '未知')}
- 严重性: {item.get('severity', '未知')}
- 描述: {item.get('info', '')}
- 匹配位置: {item.get('matched', '')}
""")

        prompt = f"""
你是一个安全漏洞验证专家。请分析以下 Nuclei 扫描发现，判断哪些是真实的漏洞，哪些是误报。

目标 URL: {target_url}

发现列表：
{chr(10).join(findings_str)}

判断标准（严格）：
1. 如果发现涉及已知 CVE 且目标技术栈匹配 → 真实漏洞（置信度高）
2. 如果发现只是扫描到文件存在但无实际利用价值 → 误报（置信度低）
3. 如果发现是通用规则匹配但缺乏上下文 → 可能是误报（置信度中）
4. 如果证据中有明确的敏感信息泄露（密码、密钥）→ 真实漏洞
5. 附带的匹配原文（matched 字段）是判断的关键证据：若命中位置是明显攻击存在/敏感信息/错误配置指纹，应判真实；若仅泛化文本命中而无利用价值，应判误报

请为每个发现输出 JSON 数组：
[
  {{"index": 0, "is_real": true/false, "confidence": "高/中/低", "reason": "判断理由"}},
  {{"index": 1, "is_real": true/false, "confidence": "高/中/低", "reason": "判断理由"}}
]
"""

        try:
            await _vuln_limiter.acquire()
            result = await client.ask(
                prompt,
                system="你是一个漏洞验证专家，只输出 JSON 数组。",
                temperature=0.1,
                wrap_data=True,
                max_tokens=800
            )
            data = safe_extract_json(result)

            if isinstance(data, list):
                used_indices = set()
                for item in data:
                    idx = item.get('index', -1)
                    if idx is None or idx == -1 or idx >= len(batch):
                        for k in range(len(batch)):
                            if k not in used_indices:
                                used_indices.add(k)
                                idx = k
                                break
                    if 0 <= idx < len(batch):
                        used_indices.add(idx)
                        is_real = item.get('is_real', False)
                        confidence = item.get('confidence', '中')
                        reason = item.get('reason', '')
                        if is_real:
                            if confidence == '高':
                                batch[idx]['ai_verdict'] = '真实漏洞'
                            elif confidence == '中':
                                batch[idx]['ai_verdict'] = '疑似漏洞（建议复核）'
                            else:
                                batch[idx]['ai_verdict'] = '可疑（低置信度）'
                        else:
                            if confidence == '高':
                                batch[idx]['ai_verdict'] = '疑似误报（高置信度）'
                            else:
                                batch[idx]['ai_verdict'] = '待复核（置信度不足）'
                        batch[idx]['confidence'] = confidence
                        batch[idx]['ai_reason'] = reason

                for k in range(len(batch)):
                    if k not in used_indices:
                        batch[k]['ai_verdict'] = '待复核（AI未返回结果）'
                        batch[k]['confidence'] = '中'
                        batch[k]['ai_reason'] = 'AI 返回结果中未包含此发现，使用默认值'

                verified_results.extend(batch)
            else:
                for item in batch:
                    item['ai_verdict'] = '待复核（AI格式异常）'
                    item['confidence'] = '中'
                    item['ai_reason'] = 'AI 分析未返回有效结果'
                verified_results.extend(batch)

        except Exception as e:
            logger.warning(f"Nuclei AI 验证失败: {e}")
            for item in batch:
                item['ai_verdict'] = '待复核（验证异常）'
                item['confidence'] = '低'
                item['ai_reason'] = f'AI 验证异常: {str(e)[:50]}'
            verified_results.extend(batch)

    return verified_results


# ============================================================
# 其他辅助函数
# ============================================================
async def is_waf_block(resp_text: str) -> bool:
    keywords = ['blocked', 'security', 'waf', 'access denied', 'forbidden',
                'request denied', 'illegal', 'malicious', 'suspicious',
                'captcha', 'cf-ray', '__cfduid']
    return any(kw in resp_text.lower() for kw in keywords)


async def extract_params_from_html(html: str, base_url: str) -> Dict[str, List]:
    result = {"url": [], "json_keys": [], "path_params": []}
    if not html:
        return result
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action:
                full_url = urljoin(base_url, action)
                for inp in form.find_all('input'):
                    name = inp.get('name')
                    if name:
                        result['url'].append({"url": full_url, "param": name})
        script_tags = soup.find_all('script')
        for script in script_tags:
            if script.string:
                content = script.string
                fetch_patterns = re.findall(
                    r'fetch\s*\(\s*["\']([^"\']+)["\']\s*,\s*{[^}]*body\s*:\s*JSON\.stringify\s*\(\s*({[^}]+})\s*\)',
                    content, re.DOTALL
                )
                for path, body in fetch_patterns:
                    if path.startswith('/'):
                        path = urljoin(base_url, path)
                    keys = re.findall(r'"([^"]+)"\s*:', body)
                    if keys:
                        result['json_keys'].append({"url": path, "params": keys})
                axios_patterns = re.findall(
                    r'axios\.(?:post|put|patch)\s*\(\s*["\']([^"\']+)["\']\s*,\s*({[^}]+})\s*\)',
                    content, re.DOTALL
                )
                for path, body in axios_patterns:
                    if path.startswith('/'):
                        path = urljoin(base_url, path)
                    keys = re.findall(r'"([^"]+)"\s*:', body)
                    if keys:
                        result['json_keys'].append({"url": path, "params": keys})
        return result
    except Exception as e:
        logger.debug(f"HTML 参数提取失败: {e}")
        return result


async def test_post_json(url: str, json_params: List[str], session, compliant: bool = False) -> List[Dict]:
    vulns = []
    if not json_params:
        return vulns
    logger.info(f"📨 测试 POST JSON 接口: {url}")
    base_json = {p: "test" for p in json_params[:5]}
    for param in json_params[:5]:
        for payload, desc in [("' OR '1'='1", "SQLi"), ("<script>alert(1)</script>", "XSS")]:
            test_json = base_json.copy()
            test_json[param] = payload
            try:
                if compliant:
                    await asyncio.sleep(0.3)
                resp = await async_post(url, json=test_json, session=session, timeout=settings.timeout)
                if isinstance(resp, tuple):
                    resp_text, resp_status = resp[1], resp[0]
                else:
                    resp_text, resp_status = await resp.text(), resp.status
                if len(resp_text) > 500 or resp_status != 200:
                    req = f"POST {url} JSON\nBody: {json.dumps(test_json)}"
                    ai_result = await verify_with_ai(req, resp_text)
                    vuln_type = ai_result.get('vuln_type', '未知')
                    if vuln_type != '未知':
                        vulns.append({
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': f'POST-JSON-{vuln_type}',
                            'ai_verdict': ai_result.get('confidence', '低'),
                            'evidence': ai_result.get('evidence', ''),
                            'raw': ai_result,
                            'diff_ratio': 0.5
                        })
                        break
            except Exception as e:
                logger.debug(f"POST JSON 测试失败 {param}: {e}")
    return vulns


def get_pending_retry_count() -> int:
    """获取待重试验证项数量"""
    return len(_pending_retry_verifications)


async def clear_pending_retry():
    """清空待重试验证项"""
    global _pending_retry_verifications
    async with _pending_retry_lock:
        _pending_retry_verifications.clear()
        logger.info("🧹 已清空待重试验证队列")


__all__ = [
    'verify_with_ai',
    'batch_verify_with_ai',
    'verify_nuclei_with_ai_async',
    'is_waf_block',
    'extract_params_from_html',
    'test_post_json',
    'get_vuln_llm_client',
    'safe_extract_json',
    'normalize_response',
    'get_pending_retry_count',
    'clear_pending_retry',
]


