# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Implementation functions for the v100 verify phase."""
import asyncio
from typing import Any, Dict, Optional
from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.ai.core import get_llm_client
from vulnclaw.modules.vuln_scanner import get_interactsh_poll
from vulnclaw.core.exploit_verify import SafeExploit, safe_verify_vulnerability
def _severity_verify_plan(severity: str) -> Dict[str, Any]:
    plans = {
        "Critical": {"n_models": 3, "do_http_verify": True, "do_exploit": True, "do_oob_poll": True},
        "High": {"n_models": 3, "do_http_verify": True, "do_exploit": True, "do_oob_poll": True},
        "Medium": {"n_models": 2, "do_http_verify": True, "do_exploit": False, "do_oob_poll": False},
        "Low": {"n_models": 1, "model": "glm-4-flash", "do_http_verify": False, "do_exploit": False, "do_oob_poll": False},
        "Info": {"n_models": 1, "do_http_verify": False, "do_exploit": False, "do_oob_poll": False},
    }
    return dict(plans.get(severity, plans["Low"]))
def _should_upgrade_low_info(vuln: Dict) -> bool:
    evidence = str(vuln.get("evidence", "")).lower()
    vuln_type = str(vuln.get("type", "")).lower()
    if "sql" in vuln_type:
        return any(keyword in evidence for keyword in ("sql", "syntax", "mysql", "postgres"))
    if "lfi" in vuln_type:
        return "root:" in evidence or "etc/passwd" in evidence
    if any(keyword in vuln_type for keyword in ("rce", "cmdi", "command")):
        return "uid=" in evidence or "whoami" in evidence
    return False
def _llm_degraded(self) -> bool:
    """判断 LLM 服务是否处于降级状态（QPS 被自适应限流器压低）。

    500 错误风暴会把 current_qps 从初始值压到 1.5~2.1；此时模型投票不可信
    （真实漏洞会被降级服务否决），verify 应切换到本地兜底路径：
    跳过 LLM 投票，改用技术验证（HTTP 状态/响应差异/回显）+ 本地规则。
    阈值可通过 settings.verify_fallback_qps_threshold 配置（默认 2.5）。
    """
    try:
        threshold = float(getattr(settings, "verify_fallback_qps_threshold", 2.5))
        rl = getattr(self, "rate_limiter", None)
        if rl is None:
            return False
        qps = float(getattr(rl, "current_qps", threshold + 1.0))
        return qps < threshold
    except Exception:
        return False
def _local_rule_verify(self, vuln: Dict) -> str:
    """LLM 降级时的本地规则验证（纯静态，0 成本）。

    优先消费引擎已产出的结构化判定标志（file_read / dir_listing /
    base64_encoded —— 这些本身就是引擎侧响应内容规则匹配的结果），
    其次按 evidence 关键词分类匹配。返回命中的规则名，未命中返回空串。
    """
    # 1) 引擎结构化标志：响应内容已在引擎侧被规则确认
    if vuln.get("dir_listing") or vuln.get("file_read") or vuln.get("base64_encoded"):
        return "engine_structured_flag"
    vuln_type = str(vuln.get("type", ""))
    vuln_type_l = vuln_type.lower()
    evidence = str(vuln.get("evidence", ""))
    ev = evidence.lower()
    # 2) evidence 关键词分类匹配
    if "sql" in vuln_type_l or "注入" in vuln_type:
        if any(k in ev for k in ("sql", "syntax", "mysql", "postgres", "oracle", "odbc")):
            return "sql_error_marker"
    if any(k in vuln_type for k in ("lfi", "路径遍历", "文件包含")) or "path" in vuln_type_l:
        if "root:" in ev or "etc/passwd" in ev:
            return "lfi_file_content"
        if "目录项" in evidence or "目录列表" in evidence or "index of" in ev:
            return "dir_listing_marker"
    if any(k in vuln_type for k in ("rce", "cmdi", "command", "命令")):
        if "uid=" in ev or "whoami" in ev:
            return "cmdi_output_marker"
    if "xss" in vuln_type_l:
        if "<script" in ev or "onerror" in ev:
            return "xss_echo_marker"
    return ""
async def _verify_cross_batch(self, group: list) -> Optional[Dict[int, Dict]]:
    """优化7: 同 (url, param) 的 findings 合并为一次 AI 调用批量判定。

    同一 URL+参数常被多个引擎同时命中（sqli / xss / cmdi…），逐条调用 AI 会产生
    上下文高度重复的多次请求。这里把整组打包进一次 prompt，要求模型逐条独立
    给出结论，从而把 N 次 AI 调用压缩为 1 次（Token 与耗时同步下降）。

    Returns:
        {组内下标: {"confirmed": bool, "confidence": str, ...}}；
        未启用 / 解析失败 / 异常 → None（调用方回退逐条验证，不降低准确率）。
    """
    if len(group) < 2 or not getattr(settings, "verify_batch_ai", True):
        return None

    lines = []
    for i, vuln in enumerate(group):
        lines.append(
            f"[{i}] type={vuln.get('type', '?')} | severity={vuln.get('severity', '?')} | "
            f"url={vuln.get('url', '')} | param={vuln.get('parameter') or vuln.get('param', '')} | "
            f"payload={str(vuln.get('payload', ''))[:120]} | "
            f"evidence={str(vuln.get('evidence', ''))[:300]}"
        )
    prompt = (
        "你是 Web 漏洞验证专家。以下是同一 URL 与参数上多个检测引擎给出的漏洞候选，"
        "请逐条独立判断其是否真实可利用（不要因同组其他条目而影响判断）。\n\n"
        + "\n".join(lines)
        + "\n\n只输出 JSON 数组，不要任何解释性文字，格式：\n"
        '[{"index": 0, "confirmed": true, "confidence": "high", "reason": "..."}]\n'
        "confidence 只能是 high / medium / low。"
    )
    try:
        raw = await self._ask_ai(
            prompt,
            system="只输出 JSON 数组，不要 Markdown 代码块。",
            temperature=0.1,
            max_tokens=1500,
            task_type="verify",
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"🤖 [批量AI] 调用失败，回退逐条验证: {exc}")
        return None

    data = None
    try:
        from vulnclaw.modules.vuln_scanner import safe_extract_json

        data = safe_extract_json(raw)
    except Exception:  # noqa: BLE001
        data = None
    if isinstance(data, dict):
        data = data.get("results") or data.get("data") or [data]
    if not isinstance(data, list):
        logger.debug("🤖 [批量AI] 结果解析失败，回退逐条验证")
        return None

    parsed: Dict[int, Dict] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            idx = int(item.get("index"))
        except (TypeError, ValueError):
            continue
        if 0 <= idx < len(group):
            parsed[idx] = {
                "confirmed": bool(item.get("confirmed")),
                "confidence": str(item.get("confidence", "low")).lower(),
                "votes": [],
                "verification_method": "ai_batch",
                "batch_reason": str(item.get("reason", ""))[:300],
            }
    return parsed or None


async def _verify_all_findings(self):
    # 流水线验证去重：stream-verify 已处理过的条目不再重复跑 cross-validation。
    touched_keys = getattr(self, "_stream_touched_keys", None)
    finding_key_fn = getattr(self, "_finding_verify_key", None)
    if not self._pending_verify:
        logger.info("❌ 无待验证漏洞")
        return
    original_total = len(self._pending_verify)
    pending_snapshot = list(self._pending_verify)
    if touched_keys and callable(finding_key_fn):
        pending_snapshot = [
            v for v in pending_snapshot if finding_key_fn(v) not in touched_keys
        ]
    skipped_stream_dupes = original_total - len(pending_snapshot)
    if skipped_stream_dupes:
        logger.info(
            "🧪 [StreamVerify] 收尾阶段跳过 %s 条已流式验证条目（touched=%s）",
            skipped_stream_dupes,
            len(touched_keys) if touched_keys is not None else 0,
        )
    # 限制待验证列表大小
    if len(pending_snapshot) > self._max_pending_verify:
        logger.warning(f"⚠️ 待验证列表超过限制：({self._max_pending_verify})，截断至 {self._max_pending_verify}")
        pending_snapshot = pending_snapshot[-self._max_pending_verify:]
    if not pending_snapshot:
        return
    logger.info(f"🧪[验证器] 开始交叉验证：{len(pending_snapshot)} 个疑似漏洞...")
    critical_high = []
    medium = []
    low_info = []
    for v in pending_snapshot:
        sev = v.get('severity', 'Low')
        if sev in ("Low", "Info") and self._should_upgrade_low_info(v):
            v["severity"] = "Medium"
            sev = "Medium"
            logger.info(f"   猬嗭笍 强证据升级验证档位： {v.get('type', '未知')} → Medium")
        if sev in ['Critical', 'High']:
            critical_high.append(v)
        elif sev == 'Medium':
            medium.append(v)
        else:
            low_info.append(v)
    pending_sorted = critical_high + medium + low_info
    MAX_AI_VERIFY = 80
    MAX_LOW_INFO_VERIFY = 30
    verified_count = 0
    total = len(pending_sorted)
    # Reserve the complete verification budget before starting any work.  This
    # keeps concurrent tasks from racing past either of the serial limits.
    verification_plan = []
    low_info_reserved = 0
    verification_reserved = 0
    low_info_budget = max(
        0,
        MAX_LOW_INFO_VERIFY - min(len(critical_high) + len(medium), MAX_LOW_INFO_VERIFY)
    )
    for vuln in pending_sorted:
        severity = vuln.get('severity', 'Low')
        if vuln.get("bundle_engine"):
            verification_plan.append(("bundle", vuln))
        elif severity in ['Low', 'Info'] and low_info_reserved >= low_info_budget:
            verification_plan.append(("skip_low", vuln))
        elif verification_reserved >= MAX_AI_VERIFY:
            verification_plan.append(("skip_budget", vuln))
        else:
            verification_plan.append(("verify", vuln))
            verification_reserved += 1
            if severity in ['Low', 'Info']:
                low_info_reserved += 1
    verify_items = [
        (idx, vuln) for idx, (action, vuln) in enumerate(verification_plan)
        if action == "verify"
    ]
    verification_semaphore = self._concurrency_semaphore
    async def verify_one(vuln, preset_ai_result=None):
        async with verification_semaphore:
            severity = vuln.get("severity", "Low")
            plan = self._severity_verify_plan(severity)
            logger.info(
                f"   [验证计划] 漏洞类型: {vuln.get('type', '未知')}，严重程度: {severity} → "
                f"{plan['n_models']}模型 + "
                f"{'HTTP' if plan['do_http_verify'] else '无HTTP'} + "
                f"{'Exploit' if plan['do_exploit'] else '无Exploit'}"
            )
            llm_degraded = self._llm_degraded()
            if preset_ai_result is not None:
                # 优化7: 复用同 (url, param) 组的批量 AI 判定，省去一次独立调用
                ai_result = dict(preset_ai_result)
                logger.info(
                    f"   🤖 [批量AI] 复用分组判定: {vuln.get('type', '未知')} "
                    f"(参数: {vuln.get('parameter', '')})"
                )
            elif llm_degraded:
                logger.warning(
                    f"   [本地兜底] LLM QPS 降级 ({self.rate_limiter.current_qps:.1f})，"
                    f"跳过模型投票，改用技术验证+本地规则: {vuln.get('type', '未知')}"
                )
                ai_result = {
                    "confirmed": False,
                    "confidence": "low",
                    "votes": [],
                    "verification_method": "local_fallback",
                }
            else:
                ai_result = await self._verify_cross(
                    vuln,
                    model_count=plan["n_models"],
                    preferred_model=plan.get("model"),
                )
            # 降级时无条件做技术验证（HTTP 状态/响应差异/回显检测不依赖 LLM），
            # 正常路径仍按 severity 计划决定。
            if plan["do_http_verify"] or llm_degraded:
                technical_result = await safe_verify_vulnerability(
                    vuln,
                    self.session,
                    interactsh_domain=self._collaborator_domain,
                )
                ai_result["technical_verification"] = technical_result
                if technical_result.get("exploitable"):
                    ai_result["confirmed"] = True
                    ai_result["verification_method"] = technical_result.get("method")
                elif plan["do_oob_poll"] and technical_result.get("method") in ("oob_dns", "oob_ssrf", "oob_http", "oob_no_callback", "oob_confirmed") and self._collaborator_domain:
                    # ⑦ 闭环：用 pending finding 携带的 oob_scan_id 精确配对 Interactsh 回调
                    scan_id = technical_result.get("oob_scan_id") or vuln.get("oob_scan_id")
                    callback = await self._poll_collaborator_callback(
                        expected_scan_id=scan_id,
                    )
                    ai_result["collaborator_callback"] = callback
                    if callback:
                        ai_result["confirmed"] = True
                        ai_result["verification_method"] = "oob_callback"
                    elif technical_result.get("oob_confirmed"):
                        ai_result["confirmed"] = True
                        ai_result["verification_method"] = "oob_engine_confirmed"
            # 技术验证未确认 → 本地规则兜底（引擎结构化标志 / evidence 关键词）
            if llm_degraded and not ai_result.get("confirmed"):
                rule_hit = self._local_rule_verify(vuln)
                if rule_hit:
                    ai_result["confirmed"] = True
                    ai_result["confidence"] = "medium"
                    ai_result["verification_method"] = f"local_rule:{rule_hit}"
                    logger.info(f"   [本地兜底] 规则命中 ({rule_hit}): {vuln.get('type', '未知')}")
            burp_verified = False
            if self.burp_available and severity in ("Critical", "High"):
                burp_result = await self._verify_with_burp_repeater(vuln)
                burp_verified = burp_result.get("confirmed", False)
            return ai_result, burp_verified
    for idx, vuln in verify_items:
        vuln_type = vuln.get('type', '未知')
        vuln_param = vuln.get('parameter', '')
        logger.info(f"   🔄 验证 {idx + 1}/{total}: {vuln_type} (参数: {vuln_param})")
    # 优化7: 同 (url, param) 的 findings 先做一次批量 AI 判定，其余条目复用结果
    preset_ai: Dict[int, Dict] = {}
    batch_groups = 0
    batch_items = 0
    if getattr(settings, "verify_batch_ai", True) and len(verify_items) > 1:
        groups: Dict[tuple, list] = {}
        for _, vuln in verify_items:
            gkey = (
                vuln.get('url', ''),
                vuln.get('parameter', '') or vuln.get('param', ''),
            )
            groups.setdefault(gkey, []).append(vuln)
        for members in groups.values():
            if len(members) < 2:
                continue
            try:
                batch = await self._verify_cross_batch(members)
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"🤖 [批量AI] 分组判定异常，回退逐条: {exc}")
                batch = None
            if not batch:
                continue
            batch_groups += 1
            for i, member in enumerate(members):
                if i in batch:
                    preset_ai[id(member)] = batch[i]
                    batch_items += 1
        if batch_groups:
            logger.info(
                f"🤖 [批量AI] {batch_groups} 组同 (url,param) findings 合并判定，"
                f"覆盖 {batch_items} 条，节省 {batch_items - batch_groups} 次 AI 调用"
            )

    verification_results = await asyncio.gather(
        *(verify_one(vuln, preset_ai.get(id(vuln))) for _, vuln in verify_items),
        return_exceptions=True
    )
    result_by_index = {
        idx: result for (idx, _), result in zip(verify_items, verification_results)
    }
    # Apply outcomes in priority order, rather than completion order.  Apart
    # from making reports reproducible, this preserves the old serial
    # verified_count/budget behavior while the expensive checks run together.
    for idx, (action, vuln) in enumerate(verification_plan):
        vuln_type = vuln.get('type', '未知')
        vuln_param = vuln.get('parameter', '')
        if action == "skip_low":
            vuln['ai_verdict'] = '低优先级，已跳过验证'
            vuln['confidence'] = 'low'
            self._add_finding(vuln)
            logger.info(f"   ⏭️ 跳过低优先级验证： {vuln_type} (参数： {vuln_param})")
            continue
        if action == "bundle":
            if vuln.get("ai_verdict") == "非漏洞":
                logger.debug(f"   ❌ Bundle 判定未确认： {vuln_type} (参数： {vuln_param})")
                continue
            vuln["confidence"] = "high" if vuln.get("ai_verdict") == "真实漏洞" else "medium (rule fallback)"
            self._add_finding(vuln)
            verified_count += 1
            logger.info(f"   ✅ Bundle 保留结果： {vuln_type} (参数： {vuln_param})")
            continue
        if action == "skip_budget":
            vuln['ai_verdict'] = '待人工复核（AI验证预算已满）'
            vuln['confidence'] = '中'
            self._add_finding(vuln)
            logger.info(f"   ⏭️ 跳过验证（预算已满）： {vuln_type} (参数： {vuln_param})")
            continue
        outcome = result_by_index[idx]
        try:
            if isinstance(outcome, BaseException):
                if isinstance(outcome, asyncio.CancelledError):
                    raise outcome
                raise outcome
            ai_result, burp_verified = outcome
            ai_confirmed = ai_result.get("confirmed", False)
            if ai_confirmed or burp_verified:
                # 安全验证（仅对比响应，不提取数据）
                try:
                    plan = self._severity_verify_plan(vuln.get("severity", "Low"))
                    if plan["do_exploit"]:
                        exploit_result = await SafeExploit.auto_exploit(vuln, self.session)
                        if exploit_result.get("exploitable"):
                            vuln["exploited"] = True
                            vuln["exploit_method"] = exploit_result.get("method")
                            vuln["exploit_evidence"] = exploit_result.get("evidence")
                            # P2-2: OOB 回调确认是强证据，confidence 置 100
                            if exploit_result.get("confidence") == 100:
                                vuln["confidence"] = 100
                except Exception as e:
                    logger.debug(f"安全验证异常: {e}")
                vuln["severity"] = ai_result.get("severity", "High") if ai_confirmed else "High"
                vuln["confidence"] = "高"
                vuln["votes"] = ai_result.get("votes", [])
                vuln["burp_verified"] = burp_verified
                self._add_finding(vuln)
                verified_count += 1
                logger.info(f"   ✅ 确认漏洞： {vuln_type} (参数： {vuln_param})")
            else:
                evidence = vuln.get('evidence', '')
                if 'SQL' in vuln_type and ('error' in evidence.lower() or 'syntax' in evidence.lower()):
                    vuln['confidence'] = 'medium (rule fallback)'
                    self._add_finding(vuln)
                    verified_count += 1
                    logger.warning(f"   ⚠️ AI判定非漏洞，但存在SQL错误特征，保留： {vuln_type}")
                else:
                    logger.info(f"   [未确认] {vuln_type} (参数: {vuln_param})")
                    # 本地兜底：降级模式下未确认 != 非漏洞（LLM 投票不可信），
                    # 保守保留待人工复核，避免真实漏洞被降级服务否决后丢失。
                    if ai_result.get("verification_method") == "local_fallback":
                        vuln["ai_verdict"] = "待人工复核（LLM降级，本地兜底未命中）"
                        vuln["confidence"] = "中（本地兜底保留）"
                        self._add_finding(vuln)
                        verified_count += 1
                        logger.warning(f"   LLM降级且本地规则未命中，保守保留待复核: {vuln_type}")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"   ❌ 验证异常： {e}")
            if vuln.get('ai_verdict') in ['高', '高（WAF绕过）']:
                vuln['confidence'] = '中（验证异常兜底）'
                self._add_finding(vuln)
                verified_count += 1
                logger.warning(f"   ⚠️ AI验证失败，但置信度高，保留： {vuln_type}")
    logger.info(f"   Cross verification complete: {verified_count}/{total} confirmed ({MAX_AI_VERIFY} AI quota)")
async def _verify_cross(
    self,
    vuln: Dict,
    model_count: int = 3,
    preferred_model: Optional[str] = None,
) -> Dict:
    try:
        prompt = f"""
你是一位漏洞验证专家。请验证以下疑似漏洞是否真实存在。
漏洞信息:
- 类型： {vuln.get('type', '未知')}
- URL: {vuln.get('url', '')}
- 参数: {vuln.get('parameter', '')}
- 证据: {vuln.get('evidence', '')[:200]}
请只回答“是”或“否”，并给出简要理由。
"""
        # P2-1: verify 复杂推理优先使用大模型（glm-4.7），提高判定质量
        available_models = []
        try:
            from vulnclaw.ai.core import get_model_router
            verify_models = get_model_router().get_models_for_task("verify", max_models=3)
        except Exception:
            verify_models = []
        for vm in verify_models:
            try:
                client = get_llm_client(force_new=False, models=[vm])
                available_models.append((vm, client))
            except Exception:
                continue
        for provider_key in self.balancer.get_all_providers():
            if any(key == provider_key for key, _ in available_models):
                continue
            try:
                # 增加超时保护，避免卡死：
                client, _, _ = await asyncio.wait_for(
                    self.balancer.get_client_by_provider(provider_key),
                    timeout=5.0
                )
                available_models.append((provider_key, client))
            except Exception:
                continue
        if preferred_model and not any(key == preferred_model for key, _ in available_models):
            try:
                preferred_client = get_llm_client(force_new=False, models=[preferred_model])
                available_models.insert(0, (preferred_model, preferred_client))
            except Exception:
                logger.debug("棣栭€夐獙璇佹ā鍨嬩笉鍙敤: %s", preferred_model)
        if len(available_models) < max(3, model_count):
            for model in self._model_pool:
                if len(available_models) >= max(3, model_count):
                    break
                if any(key == model for key, _ in available_models):
                    continue
                try:
                    client = get_llm_client(force_new=False, models=[model])
                    available_models.append((model, client))
                except Exception:
                    continue
        if len(available_models) < 1:
            logger.warning("⚠️ 无可用模型进行交叉验证，返回保守结果")
            return {"confirmed": False, "confidence": "low"}
        # --- 第一层并发：多模型投票并行化 ---
        # 串行版本会等待每个 provider 的 ask() 返回后再发起下一个，
        # 这里改为同时发起最多 3 路 ask()，再等全部完成后做 majority 统计。
        # 每路请求单独超时 20s，防止单路模型卡死拖慢整条流式验证。
        _VERIFY_CROSS_TIMEOUT = 20.0
        async def ask_model(provider_key, client):
            try:
                return await asyncio.wait_for(
                    client.ask(
                        prompt,
                        system="Answer only yes or no and provide a brief reason.",
                        temperature=0.1,
                        max_tokens=200,
                        wrap_data=True,  # 安全加固
                        use_cache=True   # P1-2: 语义缓存（1h TTL，重复验证命中直接返回）
                    ),
                    timeout=_VERIFY_CROSS_TIMEOUT,
                )
            except asyncio.TimeoutError as te:
                # gather 閲岀敤 return_exceptions=True锛岄€忎紶渚夸簬投票渚ф寜异常鍒?False
                return te
        # Keep provider order stable so votes and reports remain deterministic,
        # while allowing the three independent model calls to overlap.
        selected_models = available_models[:max(1, min(model_count, 3))]
        model_results = await asyncio.wait_for(
            asyncio.gather(
                *(ask_model(provider_key, client) for provider_key, client in selected_models),
                return_exceptions=True
            ),
            timeout=30
        )
        votes = []
        for (provider_key, _), result in zip(selected_models, model_results):
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, Exception):
                logger.debug(f"模型 {provider_key} 验证失败: {result}")
                votes.append(False)
                continue
            try:
                is_vuln = "是" in result or "true" in result.lower()
                votes.append(is_vuln)
                logger.debug(f"模型 {provider_key} 判定: {is_vuln}")
            except Exception as e:
                logger.debug(f"模型 {provider_key} 验证失败: {e}")
                votes.append(False)
        confirmed_count = sum(votes)
        required_votes = 2 if len(selected_models) > 1 else 1
        if confirmed_count >= required_votes:
            return {
                "confirmed": True,
                "severity": "High",
                "confidence": "高",
                "votes": [{"provider": selected_models[i][0], "is_vuln": v} for i, v in enumerate(votes)]
            }
        elif confirmed_count == 1:
            return {
                "confirmed": False,
                "severity": "Medium",
                "confidence": "medium",
                "reason": "鍗曟ā鍨嬬‘璁わ紝寤鸿浜哄伐澶嶆牳",
                "votes": [{"provider": selected_models[i][0], "is_vuln": v} for i, v in enumerate(votes)]
            }
        else:
            return {
                "confirmed": False,
                "confidence": "low",
                "votes": [{"provider": selected_models[i][0], "is_vuln": v} for i, v in enumerate(votes)]
            }
    except Exception as e:
        logger.warning(f"AI验证失败: {e}")
        return {"confirmed": False, "votes": [], "severity": "Low"}
async def _poll_collaborator_callback(self, expected_scan_id: Optional[str] = None):
    """Poll the configured OOB provider and return the matching interaction.

    若给定 expected_scan_id（SSRF-OOB pending finding 携带的 oob_scan_id），
    仅返回与该 scan_id 精确配对的交互，避免其他扫描/其他 finding 的
    OOB 回调造成误配对（⑦ 闭环：DNS/HTTP 命中确认才可升级 High）。
    """
    if not self._collaborator_domain:
        return False
    try:
        if self.burp_available:
            result = await self.burp.collaborator("check")
            if result and result.get("results"):
                return result.get("results")[0]
        interactions = await get_interactsh_poll(self._collaborator_domain, timeout=5)
        if not interactions:
            return False
        if expected_scan_id:
            for inter in interactions:
                if not isinstance(inter, dict):
                    continue
                raw = str(inter.get("raw-request", ""))
                detail = str(inter.get("q-type", "")) + " " + str(inter.get("protocol", ""))
                if expected_scan_id in raw or expected_scan_id in detail:
                    return inter
            return False
        return interactions[0] if interactions else False
    except Exception as e:
        logger.debug(f"Collaborator 鍥炶繛杞失败: {e}")
        return False
async def _verify_with_burp_repeater(self, vuln: Dict) -> Dict:
    # Burp Repeater 功能暂不可用，直接返回未确认
    logger.debug("Burp Repeater 未实现，跳过验证")
    return {"confirmed": False}
__all__ = ['_severity_verify_plan', '_should_upgrade_low_info', '_llm_degraded', '_local_rule_verify', '_verify_all_findings', '_verify_cross', '_poll_collaborator_callback', '_verify_with_burp_repeater']
