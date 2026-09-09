# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""验证网关（Verification Gateway）——任意扫描器输出的去伪存真层。

产品定位：VULNCLAW 的验证链作为独立服务，消费任何扫描器（Strix / Burp /
nuclei / xray / semgrep / 自研引擎…）的 SARIF 2.1 或 findings JSON 输出，
执行"去重 → 证据分诊 → 本地规则 → [可选] LLM 粗筛 → [可选] HTTP 重放探测"
的验证流水线，输出 verified SARIF + 防篡改审计凭证链。

默认全确定性、零外呼、零 API key——CI（PR 触发）安全；
--probe / --use-llm 为可选增强层，任何一层失败都自动跳过、绝不阻断。

入口：
    vulnclaw verify --input scanner-output.sarif [--probe] [--use-llm]
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from vulnclaw.core.audit_receipt import build_receipt_chain, verify_receipt_chain
from vulnclaw.core.logger import logger

GATEWAY_VERSION = "1.0.0"

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_LEVEL_MAP = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note",
}
_SEV_ALIASES = {
    "critical": "critical", "crit": "critical", "严重": "critical", "致命": "critical",
    "high": "high", "高危": "high", "高": "high", "error": "high",
    "medium": "medium", "med": "medium", "moderate": "medium", "warning": "medium",
    "warn": "medium", "中危": "medium", "中": "medium",
    "low": "low", "低危": "low", "低": "low", "note": "low", "minor": "low",
    "info": "info", "informational": "info", "提示": "info", "none": "info",
}


def normalize_severity(raw: Any) -> str:
    """任意来源的严重级说法 → 规范五档（未识别降为 info，宁保守）。"""
    s = str(raw or "").strip().lower()
    return _SEV_ALIASES.get(s, "info")


def _sev_rank(sev: Any) -> int:
    s = normalize_severity(sev)
    return _SEVERITY_ORDER.index(s) if s in _SEVERITY_ORDER else len(_SEVERITY_ORDER)


# ============================================================
# 归一化：SARIF 2.1 / findings JSON → 规范 finding
# ============================================================
def normalize_input(data: Any, source: str = "") -> tuple[list[dict], str]:
    """识别输入格式并归一化。返回 (findings, detected_format)。"""
    if isinstance(data, dict) and isinstance(data.get("runs"), list) and data.get("version"):
        return _normalize_sarif(data, source), "sarif"
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return _normalize_plain(data["findings"], source), "json_findings"
    if isinstance(data, list):
        return _normalize_plain(data, source), "json_list"
    return [], "unknown"


def _normalize_sarif(data: dict, source: str) -> list[dict]:
    out: list[dict] = []
    for run in data.get("runs") or []:
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool_name = str(driver.get("name") or source or "sarif")
        for res in run.get("results") or []:
            uri = ""
            for loc in res.get("locations") or []:
                phys = loc.get("physicalLocation") or {}
                uri = str((phys.get("artifactLocation") or {}).get("uri") or "")
                if uri:
                    break
            props = res.get("properties") or {}
            msg = str((res.get("message") or {}).get("text") or "")
            out.append({
                "type": str(res.get("ruleId") or props.get("type") or "unknown"),
                "url": uri,
                "parameter": str(props.get("parameter") or props.get("param") or ""),
                "payload": str(props.get("payload") or ""),
                "evidence": str(props.get("evidence") or msg or ""),
                "severity": normalize_severity(res.get("level") or props.get("severity")),
                "source": source or tool_name,
            })
    return out


def _normalize_plain(items: list[dict], source: str) -> list[dict]:
    out: list[dict] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        out.append({
            "type": str(it.get("type") or it.get("title") or it.get("rule") or "unknown"),
            "url": str(it.get("url") or it.get("host") or ""),
            "parameter": str(it.get("parameter") or it.get("param") or ""),
            "payload": str(it.get("payload") or ""),
            "evidence": str(it.get("evidence") or it.get("detail") or it.get("description") or ""),
            "severity": normalize_severity(it.get("severity") or it.get("level")),
            "source": source or str(it.get("source") or "json"),
        })
    return out


# ============================================================
# 去重 + 多源佐证
# ============================================================
def dedup_and_corroborate(findings: list[dict]) -> list[dict]:
    """(type, url, parameter) 相同的发现合并为一条，记录来源与佐证次数。"""
    merged: dict[tuple[str, str, str], dict] = {}
    order: list[tuple[str, str, str]] = []
    for f in findings:
        key = (str(f.get("type", "")).lower(), str(f.get("url", "")), str(f.get("parameter", "")))
        if key not in merged:
            g = dict(f)
            g["sources"] = [str(f.get("source") or "unknown")]
            g["corroboration"] = 1
            merged[key] = g
            order.append(key)
            continue
        g = merged[key]
        src = str(f.get("source") or "unknown")
        if src not in g["sources"]:
            g["sources"].append(src)
        g["corroboration"] = int(g.get("corroboration", 1)) + 1
        if _sev_rank(f.get("severity")) < _sev_rank(g.get("severity")):
            g["severity"] = normalize_severity(f.get("severity"))
        if not str(g.get("evidence", "")).strip() and str(f.get("evidence", "")).strip():
            g["evidence"] = f.get("evidence")
    return [merged[k] for k in order]


# ============================================================
# 证据分诊 + 本地规则 + 可选层
# ============================================================
# ============================================================
# P0-3: finding 证据三分类（RAPTOR 语义，与 confidence 形成二维可信度）
# ============================================================
# 证据类型：fact（可验证的具体信号）/ inference（有依据的推断）/
#           unproven_hypothesis（无证据的假设/推测）
_EVIDENCE_FACT_MARKERS = (
    "http", "https", "200", "302", "403", "500", "uid=", "root:", "error",
    "syntax", "alert(", "<script", "onerror", "mysql", "postgres", "sqlite",
    "callback", "oob", "dnslog", "接收", "命中", "回显", "响应头", "cookie",
)


def classify_evidence(f: dict) -> str:
    """对 finding 判定证据类型（fact / inference / unproven_hypothesis）。

    规则（宁保守分级，不误升实锤）：
    - 无 evidence 文本 → unproven_hypothesis（与无证据降档语义一致）；
    - evidence 含可验证的强信号（URL/状态码/错误特征/回显/回调）→ fact；
    - evidence 有内容但弱于实证 → inference。
    """
    ev = str(f.get("evidence") or "").strip()
    if not ev:
        return "unproven_hypothesis"
    low = ev.lower()
    hits = sum(1 for m in _EVIDENCE_FACT_MARKERS if m in low)
    # 至少两个独立可验证特征才认为构成"实证"，否则仅属推断
    if hits >= 2 or any(m in low for m in ("uid=", "root:", "onerror", "dnslog", "callback")):
        return "fact"
    return "inference"


def static_triage(f: dict) -> dict:
    """证据分诊：无 evidence → 严重级降一档并打标（幻觉抑制语义）。"""
    # P0-3: 证据三分类（fact/inference/unproven_hypothesis），二维可信度的横轴
    f["evidence_class"] = classify_evidence(f)
    has_ev = bool(str(f.get("evidence", "")).strip())
    f["evidence_present"] = has_ev
    sig = list(f.get("triage_signals") or [])
    if has_ev:
        sig.append("evidence_present")
    else:
        sig.append("no_evidence")
        idx = _sev_rank(f.get("severity"))
        downgraded = _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]
        if downgraded != normalize_severity(f.get("severity")):
            f["severity"] = downgraded
            sig.append("severity_downgraded_no_evidence")
        f["evidence_missing"] = True
    f["triage_signals"] = sig
    return f


def _rule_verify(f: dict) -> str:
    """复用主验证链的本地规则语义（phases_verify._local_rule_verify，self 未使用）。

    懒加载 + 失败兜底：任何导入/运行异常都返回 ""（规则层缺席不阻断网关）。
    """
    try:
        from vulnclaw.ai.v100.phases.phases_verify import _local_rule_verify

        return _local_rule_verify(None, f) or ""
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[Gateway] 本地规则层不可用（跳过）: {exc}")
        return ""


async def _llm_prescreen(batch: list[dict]) -> dict[int, dict] | None:
    """可选 LLM 粗筛（filter 档，A4.4 同源）。任何失败返回 None（整层跳过）。

    语义与 A4.4 一致：宁漏筛勿误杀——LLM 只打"高把握误报"标记，供降分，
    不直接丢弃 finding。
    """
    try:
        from vulnclaw.ai.core import get_llm_client

        client = get_llm_client()
        if client is None:
            return None
        lines = [
            f"[{i}] type={f.get('type', '?')} | severity={f.get('severity', '?')} | "
            f"url={f.get('url', '')} | param={f.get('parameter', '')} | "
            f"evidence={str(f.get('evidence', ''))[:200]}"
            for i, f in enumerate(batch)
        ]
        prompt = (
            "你是安全扫描结果粗筛器。以下为多来源合并后的疑似漏洞清单。"
            "只标记「把握非常高的明显误报」，宁漏勿误：不确定的不要标记。\n\n"
            + "\n".join(lines)
            + '\n\n只输出 JSON：{"verdicts": [{"index": 0, "likely_vuln": false, "confidence": "high"}]}'
            '\n（likely_vuln=false 且 confidence=high 表示判定为明显误报）'
        )
        raw = await client.ask(
            prompt, system="只输出 JSON，不要解释。", temperature=0.0,
            max_tokens=900, task_type="filter", usage_site="gateway:prescreen",
        )
        from vulnclaw.modules.vuln_scanner import safe_extract_json

        data = safe_extract_json(raw)
        if isinstance(data, dict):
            data = data.get("verdicts") or []
        out: dict[int, dict] = {}
        for item in data or []:
            if isinstance(item, dict):
                try:
                    out[int(item.get("index"))] = {
                        "likely_vuln": bool(item.get("likely_vuln")),
                        "confidence": str(item.get("confidence", "low")).lower(),
                    }
                except (TypeError, ValueError):
                    continue
        return out or None
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[Gateway] LLM 粗筛不可用（整层跳过）: {exc}")
        return None


async def _probe_one(f: dict, session) -> dict:
    """可选 HTTP 重放探测：基线 vs 载荷（复用砖 1 的 Repeater 判定语义）。"""
    try:
        from vulnclaw.core.utils import async_get, build_attack_url

        url = str(f.get("url", "")).strip()
        param = str(f.get("parameter", "")).strip()
        payload = str(f.get("payload", "")).strip()
        if not url or not url.startswith(("http://", "https://")):
            return f
        b_status, b_text, _h = await async_get(
            url, session=session, timeout=15, no_retry=True)
        f["probe_base_status"] = b_status
        confirmed = False
        if param and payload:
            attack_url = build_attack_url(url, param, payload)
            a_status, a_text, _h2 = await async_get(
                attack_url, session=session, timeout=15, no_retry=True)
            low = payload.lower()
            if len(payload) >= 4 and low in str(a_text or "").lower() and low not in str(b_text or "").lower():
                confirmed = True
                f.setdefault("signals", []).append("probe_reflected")
            if a_status and a_status >= 500 and b_status < 500:
                confirmed = True
                f.setdefault("signals", []).append("probe_status_shift")
            f["probe_attack_status"] = a_status
        f["probe_confirmed"] = confirmed
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[Gateway] probe 失败（跳过该条）: {exc}")
        f["probe_error"] = str(exc)
    return f


# ============================================================
# 盲复现验证闸门（Blind Reproduction Gate，L5 级压误报）
# ============================================================
"""盲复现闸门：验证者不接收发现者的推理与载荷，独立重打目标，打不中不进主台账。

对应业界两条最硬的压误报范式：
  - pwnkit 的"盲复现"：验证者不看原始推理链，只拿目标重打一遍；
  - defending-code 的"独立环境复现"：验证在 find 没碰过的干净环境执行，防环境污染造假阳性。

本闸门五条硬约束：
  1. 盲：只向验证器传 (url, parameter)，物理裁掉 evidence/payload/描述——
     不是"约定不看"，而是数据结构上没有这些字段（单测锁死）；
  2. 独立弹药：复用 SafeExploit 的独立复检器（自带唯一标记/标准载荷），
     绝不复用发现者那条 payload，避免"照抄答案"式自证；
  3. 干净上下文：session=None 每次新建会话，不复用主流程连接池/cookie；
     --blind-sandbox 时进一步把验证动作放进隔离进程（docker 优先、进程兜底）；
  4. 三态裁决：confirmed / refuted / inconclusive。refuted 降级 needs_review
     而非删除——凭证链要求记录不可删，等价于"不进 verified 台账"；
  5. 权限独立：走 danger_guard 的 blind_repro 探测级权限点；被拒 = inconclusive，
     不扣分、不阻断（与网关"任何一层失败自动跳过"语义一致）。
"""
BLIND_REPRO_VERSION = "1.0.0"

# 盲视图白名单：只有这三项能进入验证器
_BLIND_VIEW_KEYS = ("url", "parameter", "category")

# 大类 -> SafeExploit 验证器链（按顺序尝试，任一 exploitable 即 confirmed）
_BLIND_VERIFIER_CHAIN: dict[str, tuple[str, ...]] = {
    "sqli": ("verify_sqli", "verify_sqli_time_based"),
    "cmdi": ("verify_cmdi",),
    "ssti": ("verify_ssti",),
    "xss": ("verify_xss",),
    "lfi": ("verify_lfi",),
    "ssrf": ("verify_ssrf",),
    "idor": ("verify_idor",),
}

# vuln_category 未覆盖、仅凭原 type 字符串识别的补充路由
_BLIND_TYPE_EXTRA: tuple[tuple[str, str], ...] = (
    ("idor", "idor"), ("越权", "idor"),
)

# 沙箱内执行的验证脚本模板：与主流程同一套验证器，只换执行环境（不分叉判定逻辑）
_BLIND_SANDBOX_SNIPPET = r'''
import asyncio, json, sys
sys.path.insert(0, {src!r})
from vulnclaw.core.exploit_verify import SafeExploit
url, param, method = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    res = asyncio.run(getattr(SafeExploit, method)(url, param, None))
    print(json.dumps(res if isinstance(res, dict) else {{"exploitable": False}}, ensure_ascii=False))
except Exception as exc:
    print(json.dumps({{"exploitable": False, "error": str(exc)[:200]}}, ensure_ascii=False))
'''


def blind_category(f: dict) -> str:
    """盲复现用的漏洞大类：vuln_category 归一 + idor/xxe 等补充识别。"""
    try:
        from vulnclaw.core.utils import vuln_category

        cat = vuln_category(str(f.get("type", "") or ""))
    except Exception:  # noqa: BLE001
        cat = "misc"
    t = str(f.get("type", "") or "").lower()
    for needle, mapped in _BLIND_TYPE_EXTRA:
        if needle in t:
            return mapped
    return cat


def blind_view(f: dict) -> dict:
    """盲视图：只保留目标与参数，物理裁掉 evidence/payload/描述等一切"发现者的说法"。

    验证器签名只接受 (url, parameter)，类型层面就拿不到原始推理/载荷——
    这是"盲"的强保证，而非流程约定。
    """
    return {
        "url": str(f.get("url", "") or "").strip(),
        "parameter": str(f.get("parameter", "") or "").strip(),
        "category": blind_category(f),
    }


def blind_verifier_chain(f: dict) -> tuple[str, ...]:
    """盲视图类别 -> 验证器方法名链；无对应验证器返回空元组（inconclusive）。"""
    return _BLIND_VERIFIER_CHAIN.get(blind_category(f), ())


def _sandbox_snippet(method: str) -> str:
    """生成沙箱验证脚本（绝对路径注入 src，避免沙箱环境剥离 PYTHONPATH）。"""
    from vulnclaw.paths import PROJECT_ROOT as _ROOT

    src = str(_ROOT / "src")
    return _BLIND_SANDBOX_SNIPPET.format(src=src)


async def _blind_repro_one(
    f: dict, session, semaphore: asyncio.Semaphore, sandbox: bool = False
) -> dict:
    """单条 finding 的盲复现：盲视图 -> 独立验证器 -> 三态裁决。"""
    view = blind_view(f)
    f["blind_view"] = view
    f["blind_repro"] = "inconclusive"

    if not view["url"].startswith(("http://", "https://")):
        f["blind_repro"] = "inconclusive"
        f.setdefault("signals", []).append("blind_skip:no_url")
        return f
    if not view["parameter"]:
        f["blind_repro"] = "inconclusive"
        f.setdefault("signals", []).append("blind_skip:no_param")
        return f

    chain = blind_verifier_chain(f)
    if not chain:
        f.setdefault("signals", []).append(f"blind_skip:unsupported:{view['category']}")
        return f

    # 权限门：blind_repro 探测级独立权限点（被拒 = inconclusive，不惩罚）
    try:
        from vulnclaw.core.danger_guard import guard

        if not guard.require_approval("blind_repro", f"type={f.get('type')} url={view['url']}"):
            f.setdefault("signals", []).append("blind_skip:danger_denied")
            return f
    except Exception as exc:  # noqa: BLE001 - 门卫异常按 fail-closed 处理：宁可不复现，不可放行
        f.setdefault("signals", []).append("blind_skip:danger_unavailable")
        logger.debug(f"[BlindRepro] 权限门卫不可用（按拒绝处理）: {exc}")
        return f

    tried: list[str] = []
    async with semaphore:
        for method in chain:
            tried.append(method)
            try:
                res = await _run_verifier(method, view, session, sandbox)
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"[BlindRepro] {method} 异常（跳过）: {exc}")
                f["blind_error"] = str(exc)[:200]
                continue
            if isinstance(res, dict) and res.get("exploitable"):
                f["blind_repro"] = "confirmed"
                f["blind_method"] = str(res.get("method") or method)
                f["blind_evidence"] = str(res.get("evidence") or "")[:500]
                f.setdefault("signals", []).append(f"blind_confirmed:{res.get('method') or method}")
                f["blind_tried"] = tried
                return f
    f["blind_tried"] = tried
    if f.get("blind_error"):
        f.setdefault("signals", []).append("blind_skip:error")
    else:
        f["blind_repro"] = "refuted"
        f.setdefault("signals", []).append("blind_refuted")
    return f


async def _run_verifier(method: str, view: dict, session, sandbox: bool) -> dict:
    """执行单个验证器：沙箱模式走隔离进程，否则直接调用（session=None 保干净上下文）。"""
    if sandbox:
        return await _run_verifier_sandboxed(method, view)
    from vulnclaw.core.exploit_verify import SafeExploit

    verifier = getattr(SafeExploit, method, None)
    if verifier is None:
        return {"exploitable": False, "reason": f"no_verifier:{method}"}
    # session 传 None：每次独立会话，不复用主流程连接池/cookie（干净上下文）
    return await verifier(view["url"], view["parameter"], None)


async def _run_verifier_sandboxed(method: str, view: dict) -> dict:
    """在隔离进程/容器内跑同一验证器（docker 优先，不可用降级进程隔离并标记 degraded）。"""
    import sys

    from vulnclaw.core.exploit_verify import SafeExploit

    script = _sandbox_snippet(method)
    res = await SafeExploit.run_in_sandbox(
        [sys.executable, "-c", script, view["url"], view["parameter"], method],
        timeout=60,
    )
    out = str(res.get("stdout") or "").strip()
    parsed: dict = {}
    if out:
        import json as _json

        try:
            parsed = _json.loads(out.splitlines()[-1])
        except Exception:  # noqa: BLE001
            parsed = {}
    if isinstance(parsed, dict) and parsed:
        parsed["sandbox"] = res.get("sandbox", {})
        return parsed
    return {"exploitable": False, "reason": "sandbox_no_output",
            "sandbox": res.get("sandbox", {}), "stderr": str(res.get("stderr") or "")[:200]}


async def run_blind_repro_gate(
    findings: list[dict],
    session=None,
    sandbox: bool = False,
    max_targets: int = 40,
    concurrency: int = 8,
) -> dict[str, int]:
    """盲复现闸门批量入口。返回统计字典（confirmed/refuted/inconclusive/skipped）。"""
    stats = {"confirmed": 0, "refuted": 0, "inconclusive": 0, "skipped": 0}
    if not findings:
        return stats
    sem = asyncio.Semaphore(max(1, concurrency))
    targets = findings[: max(1, max_targets)]
    await asyncio.gather(*[_blind_repro_one(f, session, sem, sandbox) for f in targets])
    for f in findings[max(1, max_targets):]:
        f["blind_repro"] = "inconclusive"
        f.setdefault("signals", []).append("blind_skip:cap")
    for f in findings:
        key = str(f.get("blind_repro") or "inconclusive")
        if key in stats:
            stats[key] += 1
        if "blind_skip:cap" in (f.get("signals") or []):
            stats["skipped"] += 1
    logger.info(
        f"🧪 [BlindRepro] 盲复现闸门: 确认 {stats['confirmed']} / 打不中 {stats['refuted']} / "
        f"不适用 {stats['inconclusive']} / 超限跳过 {stats['skipped']}"
    )
    return stats


# ============================================================
# 评分 + SARIF 输出
# ============================================================
def score_confidence(f: dict) -> int:
    score = 40
    if f.get("evidence_present"):
        score += 25
    if f.get("rule_hit"):
        score += 40
    if int(f.get("corroboration") or 1) > 1:
        score += 10
    if f.get("probe_confirmed"):
        score += 20
    if f.get("llm_gate_reject"):
        score -= 15
    if f.get("evidence_missing"):
        score -= 25
    # 盲复现：独立重打是最强可信信号，确认加分、打不中重扣、不适用不罚
    blind = str(f.get("blind_repro") or "")
    if blind == "confirmed":
        score += 25
        if f.get("blind_method") == "browser_execution":
            score += 10  # 真实浏览器执行确认（最强实锤）
    elif blind == "refuted":
        score -= 30
    return max(0, min(100, int(score)))


def status_of(f: dict) -> str:
    # 盲复现打不中 → 不进 verified 台账（降级待复核，不删除：保护凭证链不可变）
    if str(f.get("blind_repro") or "") == "refuted":
        return "needs_review"
    if f.get("probe_confirmed") or f.get("rule_hit"):
        return "verified"
    score = int(f.get("confidence") or 0)
    if score >= 70:
        return "verified"
    if score >= 55:
        return "likely"
    return "unverified"


def build_verified_sarif(findings: list[dict], gateway_version: str = GATEWAY_VERSION) -> dict:
    """verified findings → SARIF 2.1.0（结果带 properties 审计字段）。"""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rid = str(f.get("type") or "unknown")
        rules.setdefault(rid, {"id": rid, "shortDescription": {"text": rid}})
        results.append({
            "ruleId": rid,
            "level": _LEVEL_MAP.get(normalize_severity(f.get("severity")), "note"),
            "message": {"text": f"[{f.get('status', 'unverified')}] {str(f.get('evidence', ''))[:300]}"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": str(f.get("url", ""))}},
            }],
            "properties": {
                "verified": f.get("status") == "verified",
                "status": f.get("status"),
                "confidence": f.get("confidence"),
                "signals": f.get("signals", []),
                "sources": f.get("sources", []),
                "corroboration": f.get("corroboration", 1),
                "severity": normalize_severity(f.get("severity")),
                # 盲复现闸门结论（不参与凭证链哈希：records 只取下方固定字段）
                "blind_repro": f.get("blind_repro", ""),
                "blind_method": f.get("blind_method", ""),
                "blind_evidence": f.get("blind_evidence", ""),
                # P0-3: 证据三分类（fact/inference/unproven_hypothesis），不参与凭证链哈希
                "evidence_class": f.get("evidence_class", ""),
                # 以下四项为凭证链出证字段的**全量原值**——审计反查
                # （verify_gateway_output）据此重建哈希输入，缺一即链式暴露
                "parameter": str(f.get("parameter", "")),
                "payload": str(f.get("payload", "")),
                "evidence": str(f.get("evidence", "")),
                "gateway_version": gateway_version,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "vulnclaw-verify",
                "version": gateway_version,
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


# ============================================================
# 主入口
# ============================================================
async def run_gateway(
    input_path: str,
    output_path: str = "",
    receipt_path: str = "",
    probe: bool = False,
    use_llm: bool = False,
    source: str = "",
    receipt_key: str = "",
    blind_repro: bool = False,
    blind_sandbox: bool = False,
    blind_max: int = 40,
) -> dict:
    """验证网关主流程。返回 summary dict（ok=False 时含 error）。

    blind_repro：启用盲复现闸门（调外呼，默认关，CI 安全）；
    blind_sandbox：盲复现在隔离进程/容器内执行（docker 优先、进程兜底）；
    blind_max：单轮盲复现目标上限（成本控制，超出标记 skipped 不惩罚）。
    """
    started = time.time()
    inp = Path(input_path)
    if not inp.is_file():
        return {"ok": False, "error": f"输入文件不存在: {input_path}"}
    try:
        data = json.loads(inp.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"输入 JSON 解析失败: {exc}"}

    findings, detected = normalize_input(data, source=source)
    if not findings:
        return {"ok": False, "error": "输入中没有可识别的 finding", "detected_format": detected}

    findings = dedup_and_corroborate(findings)
    findings = [static_triage(f) for f in findings]
    for f in findings:
        hit = _rule_verify(f)
        if hit:
            f["rule_hit"] = hit
            f.setdefault("signals", []).append(f"local_rule:{hit}")

    if use_llm:
        verdicts = await _llm_prescreen(findings)
        if verdicts:
            for i, f in enumerate(findings):
                v = verdicts.get(i)
                if v and v.get("likely_vuln") is False and str(v.get("confidence", "")).lower() == "high":
                    f["llm_gate_reject"] = True
                    f.setdefault("signals", []).append("llm_gate_reject")

    if probe:
        try:
            from vulnclaw.core.utils import get_shared_session

            session = get_shared_session()
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[Gateway] 共享会话不可用（逐条独立会话兜底）: {exc}")
            session = None
        findings = list(await asyncio.gather(*[_probe_one(f, session) for f in findings]))
        try:
            from vulnclaw.core.utils import close_shared_session

            await close_shared_session()
        except Exception as exc:  # noqa: BLE001 - 会话清理失败静默降级
            logger.debug(f"[Gateway] 共享会话关闭失败（忽略）: {exc}")

    blind_stats: dict[str, int] = {}
    if blind_repro:
        try:
            blind_stats = await run_blind_repro_gate(
                findings, None, sandbox=blind_sandbox, max_targets=blind_max)
        except Exception as exc:  # noqa: BLE001 - 闸门整体失败不阻断主流程
            logger.warning(f"🛡️ [Gateway] 盲复现闸门异常（跳过该层）: {exc}")

    for f in findings:
        f["confidence"] = score_confidence(f)
        f["status"] = status_of(f)

    out_path = Path(output_path) if output_path else inp.with_name(inp.stem + ".verified.sarif")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(build_verified_sarif(findings), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    rc_path = Path(receipt_path) if receipt_path else out_path.with_name(
        out_path.stem + ".receipt.json")
    records = [
        {k: f.get(k) for k in ("type", "url", "parameter", "payload", "evidence",
                               "severity", "status", "confidence", "sources",
                               "corroboration")}
        for f in findings
    ]
    receipt = build_receipt_chain(
        records,
        meta={"input": inp.name, "gateway_version": GATEWAY_VERSION,
              "probe": probe, "llm": use_llm,
              "blind_repro": bool(blind_repro), "blind_sandbox": bool(blind_sandbox),
              "blind_repro_version": BLIND_REPRO_VERSION if blind_repro else ""},
        secret=receipt_key or None,
    )
    rc_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")

    counts: dict[str, int] = {}
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    summary = {
        "ok": True,
        "input": str(inp),
        "detected_format": detected,
        "total": len(findings),
        "status_counts": counts,
        "corroborated": sum(1 for f in findings if int(f.get("corroboration") or 1) > 1),
        "blind_repro": blind_stats or None,
        "blind_repro_enabled": bool(blind_repro),
        "output": str(out_path),
        "receipt": str(rc_path),
        "chain_root": receipt["chain_root"],
        "elapsed_s": round(time.time() - started, 2),
    }
    logger.info(
        f"🛡️ [Gateway] 验证完成: {summary['total']} findings → "
        + ", ".join(f"{k}={v}" for k, v in counts.items())
        + f"；凭证链根 {receipt['chain_root'][:16]}…"
    )
    return summary


def verify_gateway_output(
    output_path: str, receipt_path: str = "", secret: str = ""
) -> dict:
    """审计校验入口：重算链并比对（供 CI/人工复核收据真伪）。"""
    out = Path(output_path)
    rc = Path(receipt_path) if receipt_path else out.with_name(out.stem + ".receipt.json")
    if not out.is_file() or not rc.is_file():
        return {"ok": False, "error": f"文件缺失: {out} / {rc}"}
    try:
        sarif = json.loads(out.read_text(encoding="utf-8"))
        receipt = json.loads(rc.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"JSON 解析失败: {exc}"}
    records = []
    for run in sarif.get("runs") or []:
        for res in run.get("results") or []:
            props = res.get("properties") or {}
            records.append({
                "type": res.get("ruleId"),
                "url": ((res.get("locations") or [{}])[0]
                        .get("physicalLocation", {}) or {})
                       .get("artifactLocation", {}).get("uri"),
                "parameter": props.get("parameter", ""),
                "payload": props.get("payload", ""),
                # evidence 必须取 properties 里的**原始全量值**（message 文本带
                # [status] 前缀且截断，与出证输入不一致会导致哈希不匹配）
                "evidence": props.get("evidence", ""),
                "severity": props.get("severity"),
                "status": props.get("status"),
                "confidence": props.get("confidence"),
                "sources": props.get("sources"),
                "corroboration": props.get("corroboration"),
            })
    ok, reason = verify_receipt_chain(receipt, records, secret=secret or "")
    return {"ok": ok, "reason": reason, "chain_root": receipt.get("chain_root", ""),
            "count": len(records)}


__all__ = [
    # 盲复现闸门
    "BLIND_REPRO_VERSION",
    # 网关主流程
    "GATEWAY_VERSION",
    "blind_category", "blind_verifier_chain", "blind_view",
    "build_verified_sarif", "dedup_and_corroborate", "normalize_input",
    "normalize_severity", "run_blind_repro_gate", "run_gateway",
    "score_confidence", "static_triage", "status_of", "verify_gateway_output",
]
