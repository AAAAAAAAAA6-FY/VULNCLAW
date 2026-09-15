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
from vulnclaw.ai.v100.evidence_pack import build_evidence_pack, _probe_summary
import time as _time
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
    # 1b) 引擎实锤标志：CMD 回显 / 时间盲注 A/B 复核 / 反序列化 gadget 确认
    if vuln.get("cmd_exec") or vuln.get("time_verified") or vuln.get("deser_confirmed"):
        return "engine_hard_flag"
    vuln_type = str(vuln.get("type", ""))
    vuln_type_l = vuln_type.lower()
    evidence = str(vuln.get("evidence", ""))
    ev = evidence.lower()
    # 2) evidence 关键词分类匹配
    if "ldap" in vuln_type_l:
        if any(k in ev for k in (
            "ldap", "ldapexception", "invalid search filter", "active directory",
            "directory service", "opendldap", "result code", "error code",
            "edirectory", "novell", "unexpected token",
        )):
            return "ldap_error_marker"
    if "反序列化" in vuln_type or "deser" in vuln_type_l:
        if any(k in ev for k in (
            "反序列化错误", "实锤", "gadget", "ysoserial", "readobject",
            "deserialize", "failed to deserialize", "unsupported pickle",
            "no module named", "not implemented for this type",
        )):
            return "deser_error_marker"
    _nosql_local = ("nosql" in vuln_type_l) or ("mongodb" in vuln_type_l) or ("非关系" in vuln_type)
    if _nosql_local:
        if any(k in ev for k in ("mongo", "bson", "objectid", "mongodb", "redis", "neo4j",
                                 "couchdb", "invalid", "exception", "unexpected")):
            return "nosql_error_marker"
    if "sql" in vuln_type_l or "注入" in vuln_type:
        if any(k in ev for k in ("sql", "syntax", "mysql", "postgres", "oracle", "odbc")):
            return "sql_error_marker"
    if any(k in vuln_type for k in ("lfi", "路径遍历", "文件包含")) or "path" in vuln_type_l:
        if "root:" in ev or "etc/passwd" in ev:
            return "lfi_file_content"
        if "目录项" in evidence or "目录列表" in evidence or "index of" in ev:
            return "dir_listing_marker"
    if any(k in vuln_type for k in ("rce", "cmdi", "command", "命令")):
        if any(k in ev for k in ("uid=", "whoami", "命令输出", "延时 payload", "sleep 0 对照", "a/b 复核通过", "复核通过")):
            return "cmdi_output_marker"
    if "xss" in vuln_type_l:
        if "<script" in ev or "onerror" in ev:
            return "xss_echo_marker"
    # SSTI：A4 二次复核（1337*2→2674）是强甄别特征；仅单次算式时用
    # "计算结果" 语境词兜底（避免裸 "49" 数字误伤页面天然含 49 的端点）。
    if "ssti" in vuln_type_l or "模板注入" in vuln_type:
        if "2674" in ev or "1337*2" in ev or "计算结果" in ev:
            return "ssti_calc_marker"
    return ""
def _technical_signal_present(vuln: Dict) -> bool:
    """判断 finding 是否携带引擎侧技术证据，避免被 LLM 一票否决后静默丢弃。

    命中任一即视为'有技术依据'，在 LLM 未确认时仍保留为待人工复核，
    而非直接丢弃。仅看结构化标志与 evidence 关键词，零网络成本。
    """
    if vuln.get("file_read") or vuln.get("dir_listing") or vuln.get("base64_encoded"):
        return True
    if vuln.get("has_response_diff") or vuln.get("echo_feature") is True:
        return True
    if vuln.get("technical_confirmed") or vuln.get("oob_confirmed"):
        return True
    # 引擎侧实锤标志：CMD 回显、时间盲注 A/B 复核通过、反序列化无害 gadget/OOB 确认
    if vuln.get("cmd_exec") or vuln.get("time_verified") or vuln.get("deser_confirmed"):
        return True
    vuln_type = str(vuln.get("type", "")).lower()
    evl = str(vuln.get("evidence", "")).lower()
    # LDAP 注入：引擎报错回显（LDAPException / invalid search filter 等）即强证据，
    # 必须是 LDAP 专用判定，避免误落入下方通用"注入"分支的 SQL 关键词失配。
    if "ldap" in vuln_type:
        if any(k in evl for k in (
            "ldap", "ldapexception", "invalid search filter", "active directory",
            "directory service", "opendldap", "ldap error", "result code",
            "error code", "edirectory", "novell", "unexpected token",
        )):
            return True
    if "反序列化" in str(vuln.get("type", "")) or "deser" in vuln_type:
        if any(k in evl for k in (
            "反序列化错误", "实锤", "gadget", "ysoserial", "readobject",
            "deserialize", "failed to deserialize", "invalid object character",
            "unsupported pickle", "no module named", "not implemented for this type",
        )):
            return True
    _nosql_type = "nosql" in vuln_type or "mongodb" in vuln_type or "非关系" in vuln_type
    if _nosql_type:
        # 注意：'NoSQL' 含子串 'sql'，必须优先于下方 sql 分支判定，避免落回 SQL 关键词失配
        if any(k in evl for k in (
            "mongo", "bson", "objectid", "mongodb", "redis", "neo4j", "couchdb",
            "invalid", "exception", "unexpected", "command failed",
        )):
            return True
    if "sql" in vuln_type or "注入" in vuln_type:
        if any(k in evl for k in ("sql", "syntax", "mysql", "postgres", "sqlite",
                                  "odbc", "ora-", "near \"", "sqlstate", "unclosed", "error")):
            return True
    if "xss" in vuln_type or "跨站" in vuln_type:
        if any(k in evl for k in ("<script", "onerror", "alert(", "<img", "<svg")):
            return True
    if "lfi" in vuln_type or "path" in vuln_type or "文件" in vuln_type:
        if any(k in evl for k in ("root:", "etc/passwd", "index of", "directory listing", "/bin/")):
            return True
    if any(k in vuln_type for k in ("cmdi", "command", "rce", "命令")):
        if any(k in evl for k in (
            "uid=", "whoami", "root:", "id=", "bin/bash",
            "延时 payload", "sleep 0 对照", "a/b 复核通过", "复核通过", "命令输出",
        )):
            return True
    if "ssti" in vuln_type:
        if any(k in evl for k in ("49", "777", "jinja", "{{", "freemarker", "gotcha")):
            return True
    if "ssrf" in vuln_type:
        if any(k in evl for k in ("127.0.0.1", "localhost", "169.254", "metadata", "internal")):
            return True
    return False


async def _probe_before_ai(self, vuln: Dict) -> Dict:
    """A 方案步骤3: AI 投票前的断言前置探测（基线 vs 载荷），客观信号喂 AI。

    任何异常/参数不足 → {"ok": False}（fail-closed：绝不提升 confidence）。
    复用 verification_gateway._probe_one 的判定语义（reflect/status_shift），
    额外补充 len_diff（长度差比率）与 duration_diff（耗时差）。
    结果落回 vuln["probe"]，供 _verify_cross / _verify_cross_batch 消费。
    """
    import time as _probe_time

    result: Dict = {"ok": False}
    try:
        url = str(vuln.get("url", "") or "").strip()
        param = str(vuln.get("parameter") or vuln.get("param") or "").strip()
        payload = str(vuln.get("payload", "") or "").strip()
        if not (url and param and payload):
            result["reason"] = "insufficient"
            vuln["probe"] = result
            return vuln
        if not url.startswith(("http://", "https://")):
            result["reason"] = "bad_scheme"
            vuln["probe"] = result
            return vuln

        from vulnclaw.core.utils import async_get, build_attack_url

        _t0 = _probe_time.monotonic()
        b_status, b_text, _bh = await async_get(
            url, session=self.session, timeout=12, no_retry=True)
        _t1 = _probe_time.monotonic()
        a_url = build_attack_url(url, param, payload)
        a_status, a_text, _ah = await async_get(
            a_url, session=self.session, timeout=12, no_retry=True)
        _t2 = _probe_time.monotonic()

        low_p = payload.lower()
        low_b = str(b_text or "").lower()
        low_a = str(a_text or "").lower()
        result.update({
            "ok": True,
            "base_status": b_status,
            "attack_status": a_status,
            "reflect": bool(len(payload) >= 4 and low_p in low_a and low_p not in low_b),
            "status_shift": bool(
                (a_status and a_status >= 500 and b_status < 500) or (a_status != b_status)
            ),
            "len_diff": round(abs(len(low_a) - len(low_b)) / max(1, len(low_b)), 4),
            "duration_diff": round(_t2 - _t1 - (_t1 - _t0), 3),
        })
    except Exception as _pe:  # noqa: BLE001 - fail-closed：探测失败不升 confidence
        result["error"] = str(_pe)[:200]
    vuln["probe"] = result
    return vuln


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
        _pk = vuln.get("evidence_pack") or (
            f"type={vuln.get('type', '?')} | url={vuln.get('url', '')} | "
            f"evidence={str(vuln.get('evidence', ''))[:300]}"
        )
        _pr = _probe_summary(vuln.get("probe"))
        lines.append(
            f"[{i}] type={vuln.get('type', '?')} | severity={vuln.get('severity', '?')} | "
            f"url={vuln.get('url', '')} | param={vuln.get('parameter') or vuln.get('param', '')} | "
            f"payload={str(vuln.get('payload', ''))[:120]}\n"
            f"    证据包: {str(_pk)[:900]}\n"
            f"    观测: {_pr}"
        )
    # T12：prompt 收口到统一注册表（ai/prompt_registry），带版本号与样例回归集。
    # 模板文本与内嵌原字面量逐字一致，只换引用不换内容；注册表缺失时回退兜底，
    # 绝不因注册表问题打断验证链路。
    try:
        from vulnclaw.ai.prompt_registry import render as _render_prompt
        prompt = _render_prompt("verify.cross_batch", items="\n".join(lines))
    except Exception:  # noqa: BLE001 - 注册表不可用 → 回退内嵌原文
        prompt = ""
    if not prompt:
        prompt = (
            "你是 Web 漏洞证据型验证官。以下是同一 URL 与参数上多个检测引擎给出的漏洞候选，"
            "每候选附【证据包】与【probe 观测结果】。请逐条独立裁决，不受同组其他条目影响。\n"
            "\n"
            "【裁决规则】\n"
            "1. 反射/回显类漏洞：只有载荷回显（reflect=true）或明确响应差分才可 confirm；\n"
            "2. 无客观证据或 probe 缺失/失败（ok=false）：必须判 confirmed=false 且 confidence=low"
            "（证据不足）；\n"
            "3. 绝不猜测，宁可证据不足。\n\n"
            + "\n".join(lines)
            + "\n\n只输出 JSON 数组，不要任何解释性文字，格式：\n"
            '[{"index": 0, "confirmed": true, "confidence": "high", "reason": "证据式理由"}]\n'
            "confidence 只能是 high / medium / low。"
        )
    try:
        raw = await self._ask_ai(
            prompt,
            system="只输出 JSON 数组，不要 Markdown 代码块。",
            temperature=0.1,
            max_tokens=1500,
            task_type="verify",
            usage_site="verify:batch",  # A4.4/SP8: 成本台账按调用点记账
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


def _downgrade_unconfirmed_verdict(vuln: Dict) -> Dict:
    """降误报：反射型 XSS / 报错型 SQLi 缺少真实回显/响应证据时不判"真实漏洞"。

    当 finding 的 ai_verdict 为"真实漏洞"，但 chain_info 显示
    http_status 为空（未捕获到 HTTP 响应）或 echo_feature 为 False（payload 未回显）时，
    引擎的"真实漏洞"判定缺乏技术证据，降级为待人工复核，避免启发式猜测被当作
    已确认漏洞输出。仅作用于反射/报错类（盲注/时间盲注本就无回显，不降级）。
    """
    vt = str(vuln.get("type", "")).lower()
    if not any(k in vt for k in ("xss", "反射", "跨站", "报错", "error", "回显")):
        return vuln
    verdict = str(vuln.get("ai_verdict", ""))
    if "真实漏洞" not in verdict:
        return vuln
    ci = vuln.get("chain_info") or {}
    if not isinstance(ci, dict):
        return vuln
    http_status = vuln.get("http_status", ci.get("http_status"))
    echo = ci.get("echo_feature")
    no_evidence = (http_status in (None, "", 0)) or (echo is False)
    if no_evidence:
        vuln["ai_verdict_original"] = verdict
        vuln["ai_verdict"] = "待人工复核（无回显/无响应证据）"
        vuln["confidence"] = "中（无回显证据，待人工复核）"
        logger.info(
            f"   ⬇️ 降级误报候选: {vuln.get('type', '?')} (参数: {vuln.get('parameter', '')}) "
            f"— http_status={http_status}, echo_feature={echo}"
        )
    return vuln


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
            logger.info(f"   ⬆️ 强证据升级验证档位： {v.get('type', '未知')} → Medium")
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
    # A4.4: 成本分层路由——便宜 filter 模型先批量粗筛，verify 大模型只验证放行候选；
    # 同时挂 verify 档调用次数预算门，超门后剩余候选全部走本地规则/技术验证（0 LLM 成本）。
    gate = None
    prescreen_local: list = []
    prescreen_total = len(verify_items)
    if getattr(settings, "filter_first_verify", True) and verify_items:
        try:
            from vulnclaw.ai.cost_router import VerifyBudgetGate, pre_screen_candidates

            gate = VerifyBudgetGate(int(getattr(settings, "verify_llm_call_budget", 120)))
            self._a44_gate = gate
            fp_ids, _ps_calls = await pre_screen_candidates(self, [v for _, v in verify_items])
            if fp_ids:
                _kept = []
                for _iv in verify_items:
                    if id(_iv[1]) in fp_ids:
                        prescreen_local.append(_iv[1])
                    else:
                        _kept.append(_iv)
                verify_items = _kept
                logger.info(
                    f"   [A4.4] 粗筛拦截 {len(prescreen_local)}/{prescreen_total} 候选"
                    f"（转入本地规则复核，省约 {len(prescreen_local)} 次大模型投票）"
                )
        except Exception as _a44_exc:  # noqa: BLE001
            logger.debug(f"[A4.4] 粗筛不可用，候选全量进 verify: {_a44_exc}")
    # ===== E 方案: 交叉验证层（开源工具对照）=====
    if getattr(settings, "cross_check_enabled", True) and verify_items:
        try:
            from vulnclaw.modules.vuln_scanner.cross_verify import cross_check_findings
            _checked = await cross_check_findings([v for _, v in verify_items])
            if _checked:
                logger.info(f"🧬[交叉验证层] 完成 {_checked} 条开源工具对照")
        except BaseException as _cross_exc:  # 对照失败绝不影响主流程
            logger.debug(f"[E 交叉验证层] 异常（忽略）: {_cross_exc}")
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
            budget_exhausted = False  # A4.4: verify 档预算门状态（仅预算分支置 True）
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
            elif gate is not None and not gate.consume():
                # A4.4: verify 档调用次数超预算 → 本地规则/技术验证兜底（0 LLM 成本）
                budget_exhausted = True
                logger.warning(
                    f"   [A4.4] verify 预算已满（{gate.max_calls} 次调用），"
                    f"转本地规则/技术验证: {vuln.get('type', '未知')}"
                )
                ai_result = {
                    "confirmed": False,
                    "confidence": "low",
                    "votes": [],
                    "verification_method": "budget_fallback",
                }
            else:
                ai_result = await self._verify_cross(
                    vuln,
                    model_count=plan["n_models"],
                    preferred_model=plan.get("model"),
                )
            # 降级时无条件做技术验证（HTTP 状态/响应差异/回显检测不依赖 LLM），
            # 正常路径仍按 severity 计划决定。
            if plan["do_http_verify"] or llm_degraded or budget_exhausted:
                # 自动成长-供给端消费（2026-09-15）：finding 无 payload 时，
                # 用账本推荐的历史有效载荷补位再技术验证（默认关零影响，失败静默）。
                # 仅补复制出的验证用 payload，不改 finding 原始字段。
                _verify_vuln = vuln
                if not str(vuln.get("payload", "") or "").strip():
                    try:
                        from vulnclaw.growth.bridges import adaptive_payloads
                        _rec = adaptive_payloads(str(vuln.get("type", "") or ""), k=1)
                        if _rec:
                            _verify_vuln = dict(vuln)
                            _verify_vuln["payload"] = _rec[0]
                            _verify_vuln["growth_payload_source"] = "ledger_recommend"
                            logger.info(
                                f"   [Growth] 历史 payload 补位验证: "
                                f"{vuln.get('type', '?')}@{vuln.get('parameter', '')}"
                            )
                    except Exception:  # noqa: BLE001,S110
                        pass
                technical_result = await safe_verify_vulnerability(
                    _verify_vuln,
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
            if (llm_degraded or budget_exhausted) and not ai_result.get("confirmed"):
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
    # A 方案步骤2/3: 断言前置——组装证据包、并发 probe，客观信号落回 finding。
    # 必须在 batch 分组（下方 _verify_cross_batch 调用）之前执行，否则 batch prompt 吃不到。
    if getattr(settings, "verify_evidence_pack", True) or getattr(settings, "verify_probe_before_ai", True):
        for _pv in verify_items:
            _pv[1]["evidence_pack"] = build_evidence_pack(_pv[1], None)
        if getattr(settings, "verify_probe_before_ai", True) and not self._llm_degraded():
            await asyncio.gather(
                # 调度审计L：显式以模块函数形态调用并传入 self/vuln。
                # 经 bind_phase_methods 绑定后 self._probe_before_ai(v) 偶发把 v 当作
                # self（vuln 缺失）→ "missing 1 required positional argument: 'vuln'"
                # → 整批验证丢失（真扫实证：StreamVerify 批次 #19）。
                *(_probe_before_ai(self, v) for _, v in verify_items),
                return_exceptions=True,
            )
            for _pv in verify_items:
                _pv[1]["evidence_pack"] = build_evidence_pack(_pv[1], _pv[1].get("probe"))
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
            if gate is not None and not gate.allow():
                logger.info("   [A4.4] verify 预算已满，跳过剩余批量粗判（复用已有判定/逐条降级）")
                break
            try:
                batch = await self._verify_cross_batch(members)
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"🤖 [批量AI] 分组判定异常，回退逐条: {exc}")
                batch = None
            if not batch:
                continue
            if gate is not None:
                gate.consume()  # A4.4: 批量粗判消耗 1 次 verify 档调用额度
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
            self._add_finding(_downgrade_unconfirmed_verdict(vuln))
            logger.info(f"   ⏭️ 跳过低优先级验证： {vuln_type} (参数： {vuln_param})")
            continue
        if action == "bundle":
            if vuln.get("ai_verdict") == "非漏洞":
                logger.debug(f"   ❌ Bundle 判定未确认： {vuln_type} (参数： {vuln_param})")
                continue
            vuln["confidence"] = "high" if vuln.get("ai_verdict") == "真实漏洞" else "medium (rule fallback)"
            self._add_finding(_downgrade_unconfirmed_verdict(vuln))
            verified_count += 1
            logger.info(f"   ✅ Bundle 保留结果： {vuln_type} (参数： {vuln_param})")
            continue
        if action == "skip_budget":
            vuln['ai_verdict'] = '待人工复核（AI验证预算已满）'
            vuln['confidence'] = '中'
            self._add_finding(_downgrade_unconfirmed_verdict(vuln))
            logger.info(f"   ⏭️ 跳过验证（预算已满）： {vuln_type} (参数： {vuln_param})")
            continue
        # 修复（批次失败: 0 / SQLi 漏检根因）：A4.4 粗筛拦截后 verify_items 被删减，
        # 此循环基于完整 verification_plan 遍历，被拦截 idx 在 result_by_index 中缺失
        # -> KeyError(0) 击穿整批验证（日志: "批次 #N 失败: 0"），该批 finding 全部丢失。
        # 被拦截条目已在下方 prescreen_local 循环复核，这里跳过即可。
        if idx not in result_by_index:
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
                        _t0 = _time.perf_counter()
                        exploit_result = await SafeExploit.auto_exploit(vuln, self.session)
                        if exploit_result.get("exploitable"):
                            vuln["exploited"] = True
                            vuln["exploit_method"] = exploit_result.get("method")
                            vuln["exploit_evidence"] = exploit_result.get("evidence")
                            # G 组: 标准 reproduction/verification 字段落回（与
                            # apply_evidence_schema 五档同口径——exploited 信号已使
                            # reproduced/verified=True）。仅实锤时写入，绝不填假数据。
                            vuln["reproduced"] = True
                            vuln["repro_evidence"] = str(exploit_result.get("evidence") or "")
                            vuln["repro_command"] = str(vuln.get("curl_command") or "")
                            vuln["repro_result"] = str(exploit_result.get("method") or "")
                            vuln["verify_elapsed_ms"] = int((_time.perf_counter() - _t0) * 1000)
                            # P2-2: OOB 回调确认是强证据，confidence 置 100
                            if exploit_result.get("confidence") == 100:
                                vuln["confidence"] = 100
                except Exception as e:
                    logger.debug(f"安全验证异常: {e}")
                vuln["severity"] = ai_result.get("severity", "High") if ai_confirmed else "High"
                vuln["confidence"] = "高"
                vuln["votes"] = ai_result.get("votes", [])
                vuln["burp_verified"] = burp_verified
                self._add_finding(_downgrade_unconfirmed_verdict(vuln))
                verified_count += 1
                logger.info(f"   ✅ 确认漏洞： {vuln_type} (参数： {vuln_param})")
            else:
                evidence = vuln.get('evidence', '')
                if 'SQL' in vuln_type and ('error' in evidence.lower() or 'syntax' in evidence.lower()):
                    vuln['confidence'] = 'medium (rule fallback)'
                    self._add_finding(_downgrade_unconfirmed_verdict(vuln))
                    verified_count += 1
                    logger.warning(f"   ⚠️ AI判定非漏洞，但存在SQL错误特征，保留： {vuln_type}")
                elif _technical_signal_present(vuln):
                    # 防御性保留：引擎已产出结构化/响应证据（报错回显、响应差分、
                    # XSS 回显等），不应被 LLM 一票否决而静默丢弃。保留为待人工复核。
                    vuln["ai_verdict"] = "待人工复核（引擎证据充分，LLM未确认）"
                    vuln["confidence"] = "中（引擎证据，待人工复核）"
                    self._add_finding(_downgrade_unconfirmed_verdict(vuln))
                    verified_count += 1
                    logger.warning(f"   ⚠️ LLM未确认但引擎证据充分，保守保留待复核: {vuln_type}")
                else:
                    logger.info(f"   [未确认] {vuln_type} (参数: {vuln_param})")
                    # 本地兜底：降级模式下未确认 != 非漏洞（LLM 投票不可信），
                    # 保守保留待人工复核，避免真实漏洞被降级服务否决后丢失。
                    if ai_result.get("verification_method") == "local_fallback":
                        vuln["ai_verdict"] = "待人工复核（LLM降级，本地兜底未命中）"
                        vuln["confidence"] = "中（本地兜底保留）"
                        self._add_finding(_downgrade_unconfirmed_verdict(vuln))
                        verified_count += 1
                        logger.warning(f"   LLM降级且本地规则未命中，保守保留待复核: {vuln_type}")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"   ❌ 验证异常： {e}")
            if vuln.get('ai_verdict') in ['高', '高（WAF绕过）']:
                vuln['confidence'] = '中（验证异常兜底）'
                self._add_finding(_downgrade_unconfirmed_verdict(vuln))
                verified_count += 1
                logger.warning(f"   ⚠️ AI验证失败，但置信度高，保留： {vuln_type}")
    # A4.4: 粗筛否决候选 → 本地规则复核（与 LLM 降级路径同语义：命中即确认，未命中保守保留）
    for vuln in prescreen_local:
        try:
            rule_hit = self._local_rule_verify(vuln)
            if rule_hit:
                vuln["ai_verdict"] = "真实漏洞（本地规则确认）"
                vuln["confidence"] = "medium"
                # 审计K1: 规则兜底 = 本地规则单源证据（无 LLM 实调背书），标记供报告
                # 人工复核排序（AI 背书项优先），评分侧已按文本区分不重复计权。
                vuln["llm_backed"] = False
                vuln["verification_method"] = f"local_rule:{rule_hit}"
                self._add_finding(_downgrade_unconfirmed_verdict(vuln))
                verified_count += 1
                logger.info(
                    f"   ✅ [A4.4] 粗筛候选本地规则命中 ({rule_hit}): {vuln.get('type', '未知')}"
                )
            else:
                vuln["ai_verdict"] = "待人工复核（粗筛判误报，本地规则未命中）"
                vuln["confidence"] = "低（粗筛误报候选）"
                self._add_finding(_downgrade_unconfirmed_verdict(vuln))
        except Exception as _ps_exc:  # noqa: BLE001
            # 单项处理异常不得中断其余候选；失败候选取回 _pending_verify，
            # 交收尾/后续批次重试，避免静默丢失（SSTI-L1 / SSRF-OOB 教训）。
            logger.warning(
                f"   [A4.4] 候选处理异常，取回待验证队列: {vuln.get('type', '?')}: {_ps_exc}",
                exc_info=True,
            )
            try:
                _k = self._finding_verify_key(vuln)
                _existing = {self._finding_verify_key(x) for x in self._pending_verify}
                if _k not in _existing:
                    self._pending_verify.append(vuln)
            except Exception:  # noqa: BLE001
                logger.debug("suppressed (verify requeue audit)")
    # A4.4: 成本量化——UsageLedger site 维度对比（粗筛 vs 大模型投票），验收要求可量化
    if gate is not None or prescreen_local:
        try:
            from vulnclaw.core_modules.metrics import UsageLedger

            _sites = UsageLedger.breakdown(by=("site",))

            def _site_tokens(name: str) -> int:
                _a = _sites.get((name,), {}) or {}
                return int(_a.get("prompt_tokens", 0)) + int(_a.get("completion_tokens", 0))

            _gs = gate.stats() if gate is not None else {"used": 0, "max": 0}
            logger.info(
                f"   💰 [A4.4] 成本分层量化: 粗筛拦截 {len(prescreen_local)}/{prescreen_total}；"
                f"verify 预算已用 {_gs['used']}/{_gs['max']} 次；tokens "
                f"filter:prescreen={_site_tokens('filter:prescreen')} vs "
                f"verify:cross={_site_tokens('verify:cross')} vs "
                f"verify:batch={_site_tokens('verify:batch')}"
            )
        except Exception:  # noqa: BLE001
            logger.debug("suppressed exception (core audit)")
    logger.info(f"   Cross verification complete: {verified_count}/{total} confirmed ({MAX_AI_VERIFY} AI quota)")
async def _verify_cross(
    self,
    vuln: Dict,
    model_count: int = 3,
    preferred_model: Optional[str] = None,
) -> Dict:
    try:
        # A 方案: 证据型验证官——让模型基于【证据包】与【probe 观测】裁决，而非猜测。
        evidence_pack = str(vuln.get("evidence_pack") or "").strip()
        probe = vuln.get("probe")
        if not evidence_pack:
            evidence_pack = (
                f"type={vuln.get('type', '?')} | url={vuln.get('url', '')} | "
                f"parameter={vuln.get('parameter', '')} | evidence={str(vuln.get('evidence', ''))[:200]}"
            )
        # probe 缺失时保持 None：_probe_summary(None) 诚实输出「缺失/失败」（fail-closed），
        # 避免伪造 ok=True 让 AI 误以为「已探测且无信号」。
        # T12：prompt 收口到统一注册表（逐字一致，只换引用）；异常 → 回退内嵌原文。
        try:
            from vulnclaw.ai.prompt_registry import render as _render_prompt
            prompt = _render_prompt(
                "verify.single_evidence",
                evidence_pack=evidence_pack,
                probe_summary=_probe_summary(probe),
            )
        except Exception:  # noqa: BLE001
            prompt = ""
        if not prompt:
            prompt = (
                "你是 Web 漏洞证据型验证官。你的唯一职责：基于下方【证据包】与【probe 观测结果】做客观裁决。\n"
                "\n"
                "【裁决规则】\n"
                "1. 反射/XSS 回显类漏洞：只有观测到载荷回显（reflect=true）或明确的"
                "状态/长度/内容差分才允许 confirm；\n"
                "2. 无任何客观证据，或 probe 观测缺失/失败（ok=false）：一律判\"证据不足\"，不得 confirm；\n"
                "3. 绝不猜测、绝不脑补；宁可\"证据不足\"也不误判。\n"
                "\n"
                f"【证据包】\n{evidence_pack}\n"
                "\n"
                f"【probe 观测结果】\n{_probe_summary(probe)}\n"
                "\n"
                "请只回答问题并**仅输出一个 JSON 对象**（不要 markdown 代码块、不要额外文字）：\n"
                '{"confirmed": "是|否|证据不足", "confidence": "high|medium|low", '
                '"reason": "一条最有力的证据行", "evidence_ref": ["证据1", "证据2"], '
                '"curl_poc": "复现该判定的 curl 命令（单行可直接执行）"}\n'
                "规则：证据不足/无法构造 curl 时对应字段给空字符串或空数组，绝不编造。"
            )
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
                logger.debug("首选验证模型不可用: %s", preferred_model)
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
                        system=("Answer ONLY a single JSON object per the schema; "
                                "no markdown, no extra text."),
                        temperature=0.1,
                        max_tokens=400,
                        force_json=True,
                        wrap_data=True,  # 安全加固
                        use_cache=True,  # P1-2: 语义缓存（1h TTL，重复验证命中直接返回）
                        usage_site="verify:cross"  # SP8
                    ),
                    timeout=_VERIFY_CROSS_TIMEOUT,
                )
            except asyncio.TimeoutError as te:
                # gather 调用 return_exceptions=True，跨实例投票遇异常按 False
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
        # 结构化语义确认产物收集器（成立理由/证据引用/curl PoC，首个非空胜出）
        reasons: dict = {}
        try:
            from vulnclaw.modules.vuln_scanner import safe_extract_json
        except Exception:  # noqa: BLE001 - 解析器不可用则走兼容回退
            safe_extract_json = None
        for (provider_key, _), result in zip(selected_models, model_results):
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, Exception):
                logger.debug(f"模型 {provider_key} 验证失败: {result}")
                votes.append(False)
                continue
            try:
                data = (safe_extract_json(str(result))
                        if (safe_extract_json and isinstance(result, str)) else None)
                if isinstance(data, dict) and data.get("confirmed") is not None:
                    # 结构化输出优先：只看 confirmed 字段，避免 reason 文本中的
                    # "是"字造成误判（原实现全文关键词匹配的隐患）。
                    raw_v = data.get("confirmed")
                    is_vuln = (raw_v is True
                               or str(raw_v).strip().lower() in ("是", "true", "yes"))
                    if is_vuln:
                        if not reasons.get("reason") and data.get("reason"):
                            reasons["reason"] = str(data["reason"])[:300]
                        if not reasons.get("evidence_ref") and data.get("evidence_ref"):
                            ev = data["evidence_ref"]
                            reasons["evidence_ref"] = (
                                [str(x)[:200] for x in ev][:5]
                                if isinstance(ev, list) else [str(ev)[:200]])
                        if not reasons.get("curl_poc") and data.get("curl_poc"):
                            reasons["curl_poc"] = str(data["curl_poc"])[:600]
                else:
                    # 兼容回退：非 JSON 输出沿用原关键词判定（零行为回归）
                    is_vuln = "是" in result or "true" in result.lower()
                votes.append(is_vuln)
                logger.debug(f"模型 {provider_key} 判定: {is_vuln}")
            except Exception as e:
                logger.debug(f"模型 {provider_key} 验证失败: {e}")
                votes.append(False)
        confirmed_count = sum(votes)
        required_votes = 2 if len(selected_models) > 1 else 1
        if confirmed_count >= required_votes:
            out = {
                "confirmed": True,
                "severity": "High",
                "confidence": "高",
                "votes": [{"provider": selected_models[i][0], "is_vuln": v} for i, v in enumerate(votes)]
            }
            # 结构化语义确认产物（供报告/复现消费）：成立理由 + 证据引用 + curl PoC
            if reasons.get("reason"):
                out["ai_reason"] = reasons["reason"]
            if reasons.get("evidence_ref"):
                out["evidence_ref"] = reasons["evidence_ref"]
            if reasons.get("curl_poc"):
                out["curl_poc"] = reasons["curl_poc"]
            return out
        elif confirmed_count == 1:
            return {
                "confirmed": False,
                "severity": "Medium",
                "confidence": "medium",
                "reason": "单模型确认，建议人工复核",
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

    本地回环：私网目标的 pending finding 用本机监听器（hits 文件）闭环，
    命中即确认，无需远端 OOB 通道。
    """
    if expected_scan_id:
        try:
            from vulnclaw.core.oob_channel import wait_local_oob
            if await asyncio.wait_for(wait_local_oob(expected_scan_id, timeout=3), timeout=4):
                return {"local": True, "scan_id": expected_scan_id, "protocol": "http"}
        except Exception as e:  # noqa: BLE001
            logger.debug(f"本地 OOB 回连检查失败: {e}")
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
    """Burp 重放对比验证（Repeater 思路自动化）：基线 vs 载荷的响应差异判定。

    只作为 Critical/High finding 的**附加**确认（调用方把 burp_verified 当加分项，
    本函数返回 False 不会降低原有判定）。流程：
      1. 基线：优先取 Burp 历史里该 URL 的真实响应；历史没有 → 直连请求一次。
      2. 重放：用 build_attack_url 注入 finding 自带的 payload 发起攻击请求。
      3. 判定（任一命中即确认）：
         - 载荷回显：attack body 含 payload 而 baseline body 不含（payload>=4 字符）；
         - 状态突变：attack >=500 而 baseline <500（报错型注入特征）。
    任何异常都不上抛（绝不影响验证主流程）。
    """
    try:
        if not getattr(self, "burp_available", False):
            return {"confirmed": False, "reason": "burp_unavailable"}
        url = str(vuln.get("url", "") or "").strip()
        param = str(vuln.get("parameter") or vuln.get("param") or "").strip()
        payload = str(vuln.get("payload", "") or "").strip()
        if not url:
            return {"confirmed": False, "reason": "no_url"}
        if not param or not payload:
            return {"confirmed": False, "reason": "insufficient_param_payload"}

        from vulnclaw.core.utils import async_get, build_attack_url

        # 1) 基线：优先 Burp 历史（真实用户视角的响应）
        base_status = None
        base_body = ""
        client = getattr(self, "burp_client", None)
        if client is not None:
            try:
                history = await client.get_history_since(0, limit=50)
                url_root = url.split("?")[0]
                for ev in history or []:
                    if str(ev.get("url", "") or "").split("?")[0] == url_root:
                        base_status = ev.get("status")
                        base_body = str(ev.get("body", "") or "")[:20000]
                        break
            except Exception as _he:  # noqa: BLE001
                logger.debug(f"[BurpReplay] 历史基线获取失败，改用直连基线: {_he}")
        if base_status is None:
            try:
                s, text, _h = await async_get(url, session=self.session, timeout=15, no_retry=True)
                base_status, base_body = s, str(text or "")[:20000]
            except Exception as _be:  # noqa: BLE001
                logger.debug(f"[BurpReplay] 直连基线失败（基线未知）: {_be}")

        # 2) 重放攻击请求（no_retry：攻击请求不吃退避，复用 SQLi 快失败经验）
        attack_url = build_attack_url(url, param, payload)
        a_status, a_text, _ah = await async_get(
            attack_url, session=self.session, timeout=15, no_retry=True
        )
        a_body = str(a_text or "")[:20000]

        # 3) 差异判定
        confirmed = False
        signals = []
        low = payload.lower()
        if len(payload) >= 4 and (low in a_body.lower()) and (low not in base_body.lower()):
            confirmed = True
            signals.append("payload_reflected")
        if base_status is not None and a_status and a_status >= 500 and base_status < 500:
            confirmed = True
            signals.append("status_shift_5xx")

        result = {
            "confirmed": confirmed,
            "verification_method": "burp_replay_diff",
            "baseline_status": base_status,
            "attack_status": a_status,
            "signals": signals,
        }
        if confirmed:
            logger.info(
                f"   🔁 [BurpReplay] 重放确认: {vuln.get('type', '?')} "
                f"(signals={signals}, base={base_status}, attack={a_status})"
            )
        return result
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[BurpReplay] 重放验证异常（按未确认处理）: {exc}")
        return {"confirmed": False, "reason": f"error: {exc}"}
# ============================================================
# C9 / C10: AI 后处理 —— LLM-as-Judge 去重 + 幻觉抑制
# 这两个能力此前只有 settings 开关（llm_as_judge_dedup /
# hallucination_suppression），从未被消费。此处接入验证后、出报告前的
# 收尾链路（orchestrator 在 _verify_all_findings 之后调用）。
# ============================================================
_SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}


async def llm_judge_dedup(orch, findings: list) -> list:
    """C9: 同 type+url 且参数不同的多条 finding，用模型二次判定是否同一底层漏洞，
    合并降噪（保留最高档位，证据合并；不丢弃漏洞信息）。"""
    if not getattr(settings, "llm_as_judge_dedup", False):
        return findings
    if len(findings) < 2:
        return findings
    groups: dict = {}
    for i, f in enumerate(findings):
        groups.setdefault((f.get("type", ""), f.get("url", "")), []).append(i)
    result = list(findings)
    changed = False
    for (ftype, furl), idxs in groups.items():
        if len(idxs) < 2:
            continue
        if len({findings[i].get("parameter", "") for i in idxs}) < 2:
            continue  # 参数相同已被 _add_finding 去重，跳过
        try:
            from vulnclaw.core.utils import clean_ai_json
            summary = "\n".join(
                f"[{i}] param={findings[i].get('parameter', '')} sev={findings[i].get('severity', '')} "
                f"evidence={str(findings[i].get('evidence', ''))[:100]}"
                for i in idxs)
            # T12：prompt 收口到统一注册表（逐字一致，只换引用）；异常 → 回退内嵌原文。
            try:
                from vulnclaw.ai.prompt_registry import render as _render_prompt
                prompt = _render_prompt("verify.dedupe", summary=summary)
            except Exception:  # noqa: BLE001
                prompt = ""
            if not prompt:
                prompt = ("以下多条漏洞类型与 URL 相同、仅参数不同，请判断是否为同一个底层漏洞的重复报告。"
                          "若是，返回需保留的唯一条目下标 JSON 数组（如 [0]）；若不是同一漏洞返回 []。\n" + summary)
            resp = await orch._ask_ai(prompt, compress=True, task_type="verify")
            import json as _json
            try:
                keep = _json.loads(clean_ai_json(resp))
            except Exception:
                keep = []
            if isinstance(keep, list) and keep:
                keepset = {int(x) for x in keep if str(x).isdigit()}
                drop = [i for i in idxs if i not in keepset]
                if drop:
                    base = findings[keepset.pop()] if keepset else findings[idxs[0]]
                    base = dict(base)
                    extras = " | ".join(str(findings[i].get("evidence", ""))[:200] for i in drop)
                    if extras:
                        base["evidence"] = (str(base.get("evidence", "")) + " [合并自同URL同类型报告] " + extras)[:2000]
                    result[idxs[0]] = base
                    for i in drop:
                        result[i] = None
                    changed = True
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[C9] 去重判定失败，保留全部: {e}")
    if changed:
        result = [f for f in result if f is not None]
    return result


def hallucination_suppress(orch, findings: list) -> list:
    """C10: 幻觉抑制。丢弃被模型明确判定为'非漏洞/误报/幻觉'的 finding（清理 LLM
    误报产生的噪音），但 Critical/High 一律保留以免漏报。"""
    if not getattr(settings, "hallucination_suppression", False):
        return findings
    out = []
    dropped = 0
    for f in findings:
        sev = f.get("severity", "Low")
        verdict = str(f.get("ai_verdict", ""))
        # 仅精确命中模型裁决词才视为明确否定；复合 verdict（含上下文说明）绝不丢弃（C10 子串匹配误杀 8091 布尔盲注 fix）
        is_nonvuln = verdict in ("非漏洞", "误报", "幻觉")
        if is_nonvuln and sev not in ("Critical", "High"):
            dropped += 1
            continue
        out.append(f)
    if dropped:
        logger.info(f"🧹 [C10] 幻觉抑制丢弃 {dropped} 条非漏洞/误报 finding")
    return out


# ============================================================
# H 组: orchestrator 拆分 —— verify 阶段编排（自 orchestrator 迁入，
# 只搬不改：DAG / 重试 / 审计行为保持原样，依赖经 bind_phase_methods 绑定）
# ============================================================
async def _run_verify_block(self) -> None:
    """SH17.1：verify 阶段主体（流式停 + 全量验证 + C9/C10 后处理）。"""
    # 等所有流式 verify 把存量 pending 跑完；再收尾剩余未被流式 pick 的。
    await self._stop_stream_verify(wait_pending=True)
    _pt = _time.monotonic()
    await self._verify_all_findings()
    # C9/C10: AI 去重 + 幻觉抑制（配置默认开启；异常则保留原始结果，绝不阻断出报告）
    try:
        if getattr(settings, "llm_as_judge_dedup", False) or getattr(settings, "hallucination_suppression", False):
            from vulnclaw.ai.v100.phases.phases_verify import llm_judge_dedup, hallucination_suppress
            self.findings = await llm_judge_dedup(self, self.findings)
            self.findings = hallucination_suppress(self, self.findings)
            # 后处理可能重排/裁剪 findings，重建去重索引保持一致
            self._seen_ut = {(str(f.get("url", "")), str(f.get("type", ""))) for f in self.findings}
    except Exception as _ce:  # noqa: BLE001
        logger.warning(f"⚠️ C9/C10 后处理异常，保留原始 findings: {_ce}")
    self._phase_timings['verify'] = _time.monotonic() - _pt


def _apply_final_review_gate(self) -> None:
    """终稿收敛（负向裁决）：verify 层未背书或显式存疑的 finding，若缺任一实锤证据，
    降为 Info 并列入报告 pending_review 桶（保留 original_severity / type / evidence 可追溯）。
    规则可解释：doubted = ai_verdict 含存疑标记，或 verdict==suspicious 且 ai_verdict 非"真实漏洞"
    （即 verify 未背书，包括引擎裸模板/空值/预算跳过）。真漏洞经 verify 背书为"真实漏洞"或
    带实锤字段（cross_confirmed / burp_verified / exploited / oob_confirmed）一律不动。
    开关：settings.final_review_gate（默认 True）。幂等。
    """
    try:
        if not getattr(settings, "final_review_gate", True):
            return
        _doubt_markers = ("待人工复核", "低优先级", "非漏洞", "预算已满",
                          "未确认", "无回显/无响应证据", "响应异常", "LLM 降级", "LLM降级")
        _hard_proof = ("cross_confirmed", "cross_tool_confirmed",
                       "burp_verified", "burp_confirmed",
                       "exploited", "oob_confirmed", "oob_callback")
        downgraded = 0
        for f in self.findings:
            if f.get("verdict") == "pending_review":
                continue
            av = str(f.get("ai_verdict", ""))
            verdict = str(f.get("verdict", ""))
            doubted = any(m in av for m in _doubt_markers)
            if f.get("cross_tool_pending"):
                doubted = True  # E3: 业务逻辑单点且无差分证据 → 必须复核
            if not doubted and verdict == "suspicious" and "真实漏洞" not in av:
                doubted = True  # verify 未背书（裸模板/空/跳过），宁缺毋滥
            if not doubted:
                continue
            if any(f.get(k) for k in _hard_proof) or f.get("confirmation_sources"):
                continue
            sev = str(f.get("severity", "Low")).strip().capitalize()
            f["original_severity"] = sev
            f["severity"] = "Info"
            f["verdict"] = "pending_review"
            f["pending_review_reason"] = av or "验证未背书（engine 模板）"
            self._pending_review.append({
                k: f.get(k) for k in ("url", "type", "parameter", "ai_verdict",
                                      "original_severity", "payload", "evidence")
                if f.get(k) is not None
            })
            downgraded += 1
        if downgraded:
            logger.warning(
                f"⚠️ [终稿收敛] {downgraded} 条 AI/技术均未实锤的存疑发现已降级 Info "
                f"并列入报告 pending_review 桶（人工复核后再提升）"
            )
    except Exception as _ge:  # noqa: BLE001
        logger.warning(f"终稿收敛异常（跳过，保留原样）: {_ge}")


__all__ = ['_severity_verify_plan', '_should_upgrade_low_info', '_llm_degraded', '_local_rule_verify', '_verify_all_findings', '_verify_cross', '_poll_collaborator_callback', '_verify_with_burp_repeater', 'llm_judge_dedup', 'hallucination_suppress', '_run_verify_block', '_apply_final_review_gate']
