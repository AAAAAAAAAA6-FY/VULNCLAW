# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/finding_schema.py
"""B1: finding schema v1 —— 统一发现证据等级（附加视图，零破坏迁移）。

存在意义
--------
扫描链路上"这条 finding 到底是被规则命中了、还是被验证了、还是被复现了"
在多处各自解读（引擎布尔字段 / G 组五档 / verification_method 字符串 /
ai_verdict 中文串），口径漂移会让报告与评分把**规则命中**当成**验证结论**。
本模块把口径收敛为一处：五级证据等级 + 10 态状态机 + 稳定 finding_id。

五级语义铁律（各级独立赋值，禁止跨级推断）
----------------------------------------
  rule_match        规则命中：本地规则/引擎特征规则命中
  response_evidence 响应证据：响应侧存在可展示的证据文本
  verification      主动验证：验证层/外部工具对"确实可利用"的背书
  reproduction      独立复现：独立重打/重放确认可复现
  oob_confirmed     带外回调：OOB 通道收到目标侧回调实锤

``rule_match=True`` **绝不**自动推出 ``verification=True``；
``oob_confirmed=True`` **绝不**自动推出 ``reproduction=True``。
每一级只读取"属于自己那一级"的原生信号（``_SIGNAL_*`` 表），
不读取其它级派生出来的布尔，因此五级之间互不污染。

与 G 组 ``core.models.apply_evidence_schema`` 的关系（刻意分歧，见 docs/FINDING_SCHEMA.md）
----------------------------------------------------------------------------------------
G 组是**渲染口径**（HTML/MD/SARIF 徽标），其 ``verified = rule_hit or oob or ...``、
``reproduced = oob or exploit_*`` 存在跨级推断。本模块是**语义口径**，故：
  - 不采信 G 组派生字段 ``verified`` / ``reproduced``（已被 rule_hit / OOB 污染）；
  - ``exploited`` 归入 verification（而不是 G 组的 reproduction）；
  - 需要独立复现证据时只认 ``exploit_reproduced`` / ``revalidated`` /
    ``blind_repro=confirmed`` 这类**原生复现信号**。

兼容策略（只增不改）
------------------
``to_schema_v1`` 返回**新 dict**：既有键值一字不改，只新增 schema 键。
报告链路用 ``apply_schema_inplace``：就地补写附加键，保持 finding 对象身份不变，
从而保证 HTML/Markdown/SARIF/CSV 渲染字节不变（详见 ``SCHEMA_ADDITIVE_KEYS``）。
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

# ============================================================
# schema 版本
# ============================================================
SCHEMA_VERSION = 1

# ============================================================
# 五级证据等级（detection）
# ============================================================
DET_RULE_MATCH = "rule_match"
DET_RESPONSE_EVIDENCE = "response_evidence"
DET_VERIFICATION = "verification"
DET_REPRODUCTION = "reproduction"
DET_OOB_CONFIRMED = "oob_confirmed"

#: 从低到高（顺序即"证据强度"顺序，用于状态推导与置信度推导）
DETECTION_LEVELS: Tuple[str, ...] = (
    DET_RULE_MATCH,
    DET_RESPONSE_EVIDENCE,
    DET_VERIFICATION,
    DET_REPRODUCTION,
    DET_OOB_CONFIRMED,
)

DETECTION_KEY = "detection"

# ============================================================
# 10 态状态机
# ============================================================
STATUS_CANDIDATE = "candidate"
STATUS_SUSPECTED = "suspected"
STATUS_VERIFIED = "verified"
STATUS_REPRODUCED = "reproduced"
STATUS_OOB_CONFIRMED = "oob_confirmed"
STATUS_FALSE_POSITIVE = "false_positive"
STATUS_ACCEPTED = "accepted"
STATUS_FIXED = "fixed"
STATUS_REOPENED = "reopened"
STATUS_CLOSED = "closed"

#: 10 态枚举（全量，顺序即生命周期推进顺序）
STATUS_ORDER: Tuple[str, ...] = (
    STATUS_CANDIDATE,
    STATUS_SUSPECTED,
    STATUS_VERIFIED,
    STATUS_REPRODUCED,
    STATUS_OOB_CONFIRMED,
    STATUS_FALSE_POSITIVE,
    STATUS_ACCEPTED,
    STATUS_FIXED,
    STATUS_REOPENED,
    STATUS_CLOSED,
)
VALID_STATUSES = frozenset(STATUS_ORDER)

#: 检测等级 -> 由该等级直接推出的状态（单级映射，无跨级推断）
DETECTION_STATUS = {
    DET_OOB_CONFIRMED: STATUS_OOB_CONFIRMED,
    DET_REPRODUCTION: STATUS_REPRODUCED,
    DET_VERIFICATION: STATUS_VERIFIED,
    DET_RESPONSE_EVIDENCE: STATUS_SUSPECTED,
    DET_RULE_MATCH: STATUS_CANDIDATE,
}

#: 状态机允许的迁移（人工/治理状态只能按此推进；false_positive/closed 可 reopen）
STATUS_TRANSITIONS: Dict[str, frozenset] = {
    STATUS_CANDIDATE: frozenset({STATUS_SUSPECTED, STATUS_FALSE_POSITIVE, STATUS_CLOSED}),
    STATUS_SUSPECTED: frozenset({
        STATUS_CANDIDATE, STATUS_VERIFIED, STATUS_FALSE_POSITIVE, STATUS_CLOSED,
    }),
    STATUS_VERIFIED: frozenset({
        STATUS_SUSPECTED, STATUS_REPRODUCED, STATUS_ACCEPTED,
        STATUS_FALSE_POSITIVE, STATUS_CLOSED,
    }),
    STATUS_REPRODUCED: frozenset({
        STATUS_OOB_CONFIRMED, STATUS_ACCEPTED, STATUS_FIXED, STATUS_CLOSED,
    }),
    STATUS_OOB_CONFIRMED: frozenset({STATUS_ACCEPTED, STATUS_FIXED, STATUS_CLOSED}),
    STATUS_FALSE_POSITIVE: frozenset({STATUS_REOPENED, STATUS_CLOSED}),
    STATUS_ACCEPTED: frozenset({STATUS_FIXED, STATUS_REOPENED, STATUS_CLOSED}),
    STATUS_FIXED: frozenset({STATUS_REOPENED, STATUS_CLOSED}),
    STATUS_REOPENED: frozenset({
        STATUS_SUSPECTED, STATUS_VERIFIED, STATUS_REPRODUCED, STATUS_OOB_CONFIRMED,
        STATUS_FALSE_POSITIVE, STATUS_CLOSED,
    }),
    STATUS_CLOSED: frozenset({STATUS_REOPENED}),
}

#: 终态（无对外迁移，只能 reopen）
TERMINAL_STATUSES = frozenset({STATUS_CLOSED})

#: 治理/人工状态：一旦写入即为权威，不再由检测等级覆盖
GOVERNANCE_STATUSES = frozenset({
    STATUS_FALSE_POSITIVE, STATUS_ACCEPTED, STATUS_FIXED, STATUS_REOPENED, STATUS_CLOSED,
})

#: 检测等级可推导状态：可被检测等级单调推进（不降级）
DETECTION_DERIVED_STATUSES = frozenset(VALID_STATUSES - GOVERNANCE_STATUSES)

# ============================================================
# 各级原生信号表（互斥归属：一个信号只属于一级）
# ============================================================
# --- 1) rule_match：规则命中 ---
_RULE_MATCH_KEYS: Tuple[str, ...] = (
    "rule_hit", "rule_match", "rule_id", "rule_name", "matched_rule",
    "signature_id", "local_rule",
)
_RULE_MATCH_METHOD_TOKENS: Tuple[str, ...] = ("local_rule", "rule_engine", "signature")

# --- 2) response_evidence：响应侧证据文本 ---
_EVIDENCE_TEXT_KEYS: Tuple[str, ...] = (
    "evidence", "response_evidence", "response_preview", "proof",
    "evidence_chain", "detail", "response",
)

# --- 3) verification：验证层/外部工具背书 ---
_VERIFICATION_KEYS: Tuple[str, ...] = (
    "exploited", "exploit_verified", "burp_verified", "burp_confirmed",
    "cross_confirmed", "cross_tool_confirmed", "probe_confirmed",
    "technical_confirmed", "browser_verified", "sqlmap_confirmed",
)
_VERIFICATION_METHOD_TOKENS: Tuple[str, ...] = (
    "ai_batch", "burp", "cross_tool", "cross_confirm", "probe",
    "technical", "browser", "sqlmap", "verify",
)
_VERIFICATION_VERDICTS = ("confirm", "confirmed", "likely")
#: ai_verdict 中表示"验证通过"的标记（与 phases_verify 的裁决词一致）
_VERIFICATION_VERDICT_MARKER = "真实漏洞"

# --- 4) reproduction：独立复现 ---
_REPRODUCTION_KEYS: Tuple[str, ...] = (
    "reproduction_verified", "repro_confirmed", "repro_verified",
    "exploit_reproduced", "revalidated", "reproduction_success",
)
# 刻意**不**按 verification_method 文本判定复现：项目内 "burp_replay_diff" 同时
# 是验证信号，若按 "replay" 文本命中会让 verification 推出 reproduction（跨级推断）。


# --- 5) oob_confirmed：带外回调实锤 ---
_OOB_KEYS: Tuple[str, ...] = (
    "oob_success", "oob_confirmed", "oob_callback", "collaborator_callback",
    "oob_verified",
)
_OOB_METHOD_TOKENS: Tuple[str, ...] = ("oob", "collaborator", "dnslog")

# --- false positive（不是五级之一，而是终态判定）---
_FALSE_POSITIVE_FLAGS: Tuple[str, ...] = (
    "false_positive", "is_false_positive", "fp_confirmed",
)
_FALSE_POSITIVE_VERDICTS = ("refute", "refuted", "false_positive", "fp", "reject", "rejected")
#: ai_verdict 精确命中（不做子串匹配：避免 "待人工复核（粗筛判误报…）" 被误判为误报）
_FALSE_POSITIVE_AI_VERDICTS = ("非漏洞", "误报", "幻觉")

#: 人工/治理侧状态键（值命中即视为显式状态，不再由检测等级推导）
_LIFECYCLE_FIXED = "fixed"
_LIFECYCLE_DEPRECATED = "deprecated"

# ============================================================
# finding_id：确定性身份哈希
# ============================================================
ID_PREFIX = "f1-"
_ID_HEX_LEN = 16
_ID_SEP = "\x1f"  # 不可见于 URL/参数名的分隔符，避免拼接口径歧义

_WS_RE = re.compile(r"\s+")
_MULTI_PARAM_RE = re.compile(r"[&,;]+")

#: 报告链路就地补写的"纯新增"键（不含 confidence / evidence：两者是既有渲染字段）
SCHEMA_ADDITIVE_KEYS: Tuple[str, ...] = (
    "finding_id", "schema_version", DETECTION_KEY, "status",
    "verification", "reproduction", "oob", "evidence_items",
)


# ============================================================
# 基础工具
# ============================================================
def _as_dict(finding: Any) -> Dict[str, Any]:
    """fail-closed：非 dict 输入一律当空 finding 处理（→ candidate）。"""
    return finding if isinstance(finding, dict) else {}


def _truthy(value: Any) -> bool:
    """通用真值判定（None/空串/0/空容器 → False）。"""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, (list, tuple, set, frozenset, dict)):
        return len(value) > 0
    return bool(str(value).strip())


def _norm_text(value: Any) -> str:
    """文本归一化：折叠空白 + 小写（用于类型/方法等身份字段）。"""
    return _WS_RE.sub(" ", str(value or "")).strip().lower()


def _norm_param(value: Any) -> str:
    """参数归一化（顺序无关）：多参数拼接按字典序排序。

    与 ``core.dedupe._norm_param`` 的差异：本函数额外做**顺序无关**归一
    （``a,b`` 与 ``b,a`` 视为同一向量），因为 finding_id 要求"参数顺序无关"。
    """
    if value is None:
        return ""
    if isinstance(value, dict):
        tokens = [f"{k}={value[k]}" for k in sorted(value, key=lambda x: str(x))]
    elif isinstance(value, (list, tuple, set, frozenset)):
        tokens = [str(x) for x in value]
    else:
        text = str(value).strip()
        if not text:
            return ""
        tokens = _MULTI_PARAM_RE.split(text) if _MULTI_PARAM_RE.search(text) else [text]
    norm = sorted(_norm_text(t) for t in tokens if str(t).strip())
    return ",".join(norm)


def _norm_url(url: Any) -> str:
    """URL 身份归一化：保留 scheme，netloc 小写，去 query/fragment 与尾斜杠。

    与 ``core.dedupe._norm_url`` 同口径（query 不参与身份，参数由 ``parameter``
    字段单独承担），因此 URL query 顺序变化不会改变 finding_id。
    """
    raw = str(url or "").strip()
    if not raw:
        return ""
    try:
        p = urlsplit(raw)
    except ValueError:
        return _norm_text(raw)
    if p.scheme:
        return f"{p.scheme.lower()}://{(p.netloc or '').lower()}{p.path.rstrip('/')}"
    return _norm_text(raw)


def compute_finding_id(finding: Any) -> str:
    """稳定 finding_id：``(url, method, type, parameter)`` 确定性哈希。

    - 同输入 -> 同 ID（跨进程、跨扫描、与 dict 键序无关）；
    - 不同输入 -> 不同 ID（长度前缀 + 不可见分隔符拼接，无拼接歧义）；
    - 参数顺序 / URL query 顺序 / 尾斜杠 / 大小写差异 -> 同 ID；
    - 无任何身份字段（url/type/parameter 全空）或非 dict 输入 -> 空串（fail-closed）。
    """
    f = _as_dict(finding)
    url = _norm_url(f.get("url"))
    vtype = _norm_text(f.get("type"))
    param = _norm_param(f.get("parameter"))
    if not (url or vtype or param):
        return ""
    method = _norm_text(f.get("method")) or "get"
    payload = "|".join((
        f"{len(url)}:{url}",
        f"{len(method)}:{method}",
        f"{len(vtype)}:{vtype}",
        f"{len(param)}:{param}",
    ))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:_ID_HEX_LEN]
    return ID_PREFIX + digest


# ============================================================
# 五级检测语义（各级独立）
# ============================================================
def _method_text(finding: Dict[str, Any]) -> str:
    return str(finding.get("verification_method") or "").strip().lower()


def _evidence_text(finding: Dict[str, Any]) -> str:
    """取响应证据原文（多字段通配，返回首个非空文本）。"""
    for key in _EVIDENCE_TEXT_KEYS:
        value = finding.get(key)
        if isinstance(value, (list, tuple, set, frozenset, dict)):
            value = str(value)
        if str(value or "").strip():
            return str(value)
    return ""


def rule_match_signals(finding: Any) -> List[str]:
    """rule_match 级命中信号名（排序后，确定性）。"""
    f = _as_dict(finding)
    hits = sorted(k for k in _RULE_MATCH_KEYS if _truthy(f.get(k)))
    method = _method_text(f)
    if any(tok in method for tok in _RULE_MATCH_METHOD_TOKENS):
        hits.append("verification_method")
    return hits


def response_evidence_signals(finding: Any) -> List[str]:
    """response_evidence 级命中信号名。"""
    f = _as_dict(finding)
    hits: List[str] = []
    text = _evidence_text(f)
    if text:
        hits.append("evidence_text")
    if _truthy(f.get("response_proof")):
        hits.append("response_proof")
    return hits


def verification_signals(finding: Any) -> List[str]:
    """verification 级命中信号名（只认原生验证信号 + 裁决词）。"""
    f = _as_dict(finding)
    hits = sorted(k for k in _VERIFICATION_KEYS if _truthy(f.get(k)))
    method = _method_text(f)
    if any(tok in method for tok in _VERIFICATION_METHOD_TOKENS):
        hits.append("verification_method")
    verdict = _norm_text(f.get("verdict"))
    if verdict in _VERIFICATION_VERDICTS:
        hits.append("verdict")
    if _VERIFICATION_VERDICT_MARKER in str(f.get("ai_verdict") or ""):
        hits.append("ai_verdict")
    return hits


def reproduction_signals(finding: Any) -> List[str]:
    """reproduction 级命中信号名（只认原生复现信号，不采信 G 组 reproduced）。"""
    f = _as_dict(finding)
    hits = sorted(k for k in _REPRODUCTION_KEYS if _truthy(f.get(k)))
    if _norm_text(f.get("blind_repro")) == "confirmed":
        hits.append("blind_repro")
    return hits


def oob_signals(finding: Any) -> List[str]:
    """oob_confirmed 级命中信号名（只认带外通道回调证据）。"""
    f = _as_dict(finding)
    hits = sorted(k for k in _OOB_KEYS if _truthy(f.get(k)))
    method = _method_text(f)
    if any(tok in method for tok in _OOB_METHOD_TOKENS):
        hits.append("verification_method")
    oob_ev = f.get("oob_evidence")
    if isinstance(oob_ev, dict) and (
        str(oob_ev.get("ts") or "").strip() or str(oob_ev.get("detail") or "").strip()
    ):
        hits.append("oob_evidence")
    legacy_oob = f.get("oob")
    if isinstance(legacy_oob, dict) and _truthy(legacy_oob.get("confirmed")):
        hits.append("oob")
    return hits


def compute_detection(finding: Any) -> Dict[str, bool]:
    """计算五级检测等级（各级独立，禁止跨级推断）。"""
    return {
        DET_RULE_MATCH: bool(rule_match_signals(finding)),
        DET_RESPONSE_EVIDENCE: bool(response_evidence_signals(finding)),
        DET_VERIFICATION: bool(verification_signals(finding)),
        DET_REPRODUCTION: bool(reproduction_signals(finding)),
        DET_OOB_CONFIRMED: bool(oob_signals(finding)),
    }


def highest_detection_level(detection: Dict[str, bool]) -> str:
    """返回已达成的最高等级（全 False -> 空串）。"""
    for level in reversed(DETECTION_LEVELS):
        if (detection or {}).get(level):
            return level
    return ""


def is_false_positive(finding: Any) -> bool:
    """误报判定（只认显式否定信号；不做中文子串匹配以免误杀"待人工复核"）。"""
    f = _as_dict(finding)
    if any(_truthy(f.get(k)) for k in _FALSE_POSITIVE_FLAGS):
        return True
    if _norm_text(f.get("verdict")) in _FALSE_POSITIVE_VERDICTS:
        return True
    av = str(f.get("ai_verdict") or "").strip()
    if av in _FALSE_POSITIVE_AI_VERDICTS:
        return True
    # 只接受"非漏洞"作为整串前缀（"待人工复核（…误报…）" 不命中）
    return av.startswith("非漏洞")


# ============================================================
# 状态机
# ============================================================
def is_valid_status(status: Any) -> bool:
    return str(status or "") in VALID_STATUSES


def can_transition(current: Any, nxt: Any) -> bool:
    """状态迁移是否合法（未知状态 -> False）。"""
    src, dst = str(current or ""), str(nxt or "")
    if src not in VALID_STATUSES or dst not in VALID_STATUSES:
        return False
    return dst in STATUS_TRANSITIONS.get(src, frozenset())


def status_for_detection(detection: Dict[str, bool]) -> str:
    """检测等级 -> 状态（无任何等级 -> candidate）。"""
    level = highest_detection_level(detection)
    return DETECTION_STATUS.get(level, STATUS_CANDIDATE)


def advance_status(current: Any, detection: Dict[str, bool]) -> str:
    """按检测等级单调推进状态：只升不降，且必须满足状态机迁移。

    - 当前为"终态/人工态"（false_positive/accepted/fixed/closed）时保持不动；
    - 迁移非法（如 candidate -> reproduced）时退化为合法路径上的第一个中间态。
    """
    cur = str(current or "") or STATUS_CANDIDATE
    if cur not in VALID_STATUSES:
        cur = STATUS_CANDIDATE
    if cur in (STATUS_FALSE_POSITIVE, STATUS_ACCEPTED, STATUS_FIXED, STATUS_CLOSED):
        return cur
    target = status_for_detection(detection)
    if target == cur:
        return cur
    # 单调性优先：目标等级低于当前 -> 不降级。
    # can_transition 允许的"合法降级"（如 verified->suspected）只适用于人工迁移，
    # 不适用于检测等级的自动推进。
    order = [DETECTION_STATUS[lv] for lv in DETECTION_LEVELS]
    cur_rank = order.index(cur) if cur in order else 0
    tgt_rank = order.index(target) if target in order else cur_rank
    if tgt_rank <= cur_rank:
        return cur
    if can_transition(cur, target):
        return target
    # 非法直达：按 DETECTION_LEVELS 顺序逐级推进，取第一个合法落点
    for rank in range(cur_rank + 1, tgt_rank + 1):
        if can_transition(cur, order[rank]):
            cur = order[rank]
    return cur


def resolve_status(finding: Any, detection: Optional[Dict[str, bool]] = None) -> str:
    """解析 finding 的 schema 状态。

    优先级：治理状态（false_positive/accepted/fixed/reopened/closed，权威）
    > 显式误报信号 > 生命周期 fixed/deprecated > 由检测等级单调推进
    （candidate/suspected/verified/reproduced/oob_confirmed，只升不降）。
    """
    f = _as_dict(finding)
    explicit = str(f.get("status") or "")
    if explicit in GOVERNANCE_STATUSES:
        return explicit
    if is_false_positive(f):
        return STATUS_FALSE_POSITIVE
    lifecycle = _norm_text(f.get("lifecycle"))
    if lifecycle == _LIFECYCLE_FIXED:
        return STATUS_FIXED
    if lifecycle == _LIFECYCLE_DEPRECATED:
        return STATUS_CLOSED
    det = detection if detection is not None else compute_detection(f)
    if explicit in DETECTION_DERIVED_STATUSES:
        return advance_status(explicit, det)
    return status_for_detection(det)


# ============================================================
# confidence / evidence[] / verification{} / reproduction{} / oob{}
# ============================================================
#: 各检测等级对应的保守置信度（无任何证据 -> ""）
_DETECTION_CONFIDENCE = {
    DET_OOB_CONFIRMED: "high",
    DET_REPRODUCTION: "high",
    DET_VERIFICATION: "medium",
    DET_RESPONSE_EVIDENCE: "low",
    DET_RULE_MATCH: "low",
}


def compute_confidence(detection: Optional[Dict[str, bool]] = None) -> str:
    """由最高检测等级推导保守置信度；无任何等级 -> 空串（fail-closed）。"""
    level = highest_detection_level(detection if detection is not None else {})
    return _DETECTION_CONFIDENCE.get(level, "")


def build_evidence_items(finding: Any) -> List[Dict[str, str]]:
    """构造 schema v1 ``evidence[]``：结构化证据条目（确定性排序）。

    命名说明：schema 的 ``evidence[]`` 落盘键为 ``evidence_items``——
    既有 ``finding["evidence"]`` 是**字符串证据原文**且被 HTML/MD/SARIF/CSV
    消费，覆盖它会破坏渲染（违反"只增不改"），故以别名承载列表视图。
    """
    f = _as_dict(finding)
    items: List[Dict[str, str]] = []
    for key in _EVIDENCE_TEXT_KEYS:
        value = f.get(key)
        if isinstance(value, (list, tuple, set, frozenset, dict)):
            text = str(value)
        else:
            text = str(value or "")
        if text.strip():
            items.append({
                "kind": DET_RESPONSE_EVIDENCE,
                "source": key,
                "detail": text,
            })
    for key in _RULE_MATCH_KEYS:
        if _truthy(f.get(key)):
            items.append({
                "kind": DET_RULE_MATCH,
                "source": key,
                "detail": str(f.get(key)),
            })
    for level, keys in (
        (DET_VERIFICATION, _VERIFICATION_KEYS),
        (DET_REPRODUCTION, _REPRODUCTION_KEYS),
        (DET_OOB_CONFIRMED, _OOB_KEYS),
    ):
        for key in keys:
            if _truthy(f.get(key)):
                items.append({
                    "kind": level,
                    "source": key,
                    "detail": str(f.get(key)),
                })
    oob_ev = f.get("oob_evidence")
    if isinstance(oob_ev, dict):
        detail = str(oob_ev.get("detail") or oob_ev.get("ts") or "")
        if detail.strip():
            items.append({
                "kind": DET_OOB_CONFIRMED,
                "source": "oob_evidence",
                "detail": detail,
            })
    items.sort(key=lambda it: (DETECTION_LEVELS.index(it["kind"]) if it["kind"] in DETECTION_LEVELS else 99,
                               it["source"], it["detail"]))
    return items


def build_verification(finding: Any) -> Dict[str, Any]:
    """构造 ``verification{}``（验证层视图；既有同名字段不存在，纯新增）。"""
    f = _as_dict(finding)
    signals = verification_signals(f)
    return {
        "verified": bool(signals),
        "method": str(f.get("verification_method") or ""),
        "signals": signals,
        "evidence": str(f.get("confirm_evidence") or f.get("burp_evidence") or "")[:2000],
    }


def build_reproduction(finding: Any) -> Dict[str, Any]:
    """构造 ``reproduction{}``（就地视图，**保留**既有 reproduction 子键）。

    新增 ``reproduction_command``：当存在可重放要素（url + payload/parameter）
    时生成复现命令（默认 curl）。这是**复现能力**字段，不影响 ``reproduced``
    布尔 —— ``reproduced`` 仍只认原生复现信号（本机无真实授权靶场时保持 False，
    绝不填假数据）。
    """
    f = _as_dict(finding)
    legacy = f.get("reproduction")
    repro: Dict[str, Any] = dict(legacy) if isinstance(legacy, dict) else {}
    signals = reproduction_signals(f)
    repro["reproduced"] = bool(signals)
    repro["signals"] = signals
    payload = str(f.get("payload") or f.get("attack_payload") or "")
    param = str(f.get("parameter") or "")
    method = str(f.get("method") or "GET").upper()
    url = str(f.get("url") or "")
    repro.setdefault("payload", payload)
    repro.setdefault("parameter", param)
    steps = f.get("reproduction_steps")
    if isinstance(steps, (list, tuple)):
        repro["steps"] = [str(s) for s in steps]
    # 复现命令（仅当存在可重放要素时生成，避免空壳）
    if url and (payload or param):
        if param:
            target = f"{url}&{param}={payload}" if "?" in url else f"{url}?{param}={payload}"
        else:
            target = url
        repro["reproduction_command"] = f"curl -k -X {method} '{target}'"
    return repro


def build_oob(finding: Any) -> Dict[str, Any]:
    """构造 ``oob{}``（**保留**既有 oob 子键）。

    子键刻意使用 ``observed_at`` / ``raw`` 而非常见的 ``ts`` / ``detail``：
    ``engines/base.attach_oob_evidence`` 会把 finding["oob"] 当作 OOB 上下文并
    据此写出 ``oob_evidence``，用非同名键可避免 schema 视图被误当成回调实锤。
    """
    f = _as_dict(finding)
    legacy = f.get("oob")
    oob: Dict[str, Any] = dict(legacy) if isinstance(legacy, dict) else {}
    signals = oob_signals(f)
    ev = f.get("oob_evidence")
    ev = ev if isinstance(ev, dict) else {}
    legacy_channel = str(legacy.get("channel") or "") if isinstance(legacy, dict) else ""
    oob["confirmed"] = bool(signals)
    oob["signals"] = signals
    oob["channel"] = str(ev.get("channel") or legacy_channel or "")
    oob["token"] = str(ev.get("token") or f.get("oob_token") or "")
    oob["observed_at"] = str(ev.get("ts") or "")
    oob["raw"] = str(ev.get("detail") or "")
    return oob


# ============================================================
# 归一化入口
# ============================================================
def to_schema_v1(finding: Any) -> Dict[str, Any]:
    """把任意 finding 归一化为 schema v1 视图（返回**新 dict**，不改入参）。

    - 既有键值一字不改（浅拷贝保留）；
    - 五级检测各级独立计算，缺失信号一律保守 false；
    - ``confidence`` 仅在既有值为空时补写推导值（既有值原样保留）；
    - ``evidence`` 既有字符串原样保留，schema 列表视图写入 ``evidence_items``；
    - 非法/非 dict 输入 fail-closed 为 candidate；
    - 幂等：对已归一化结果重复调用输出不变。
    """
    f = _as_dict(finding)
    out: Dict[str, Any] = dict(f)

    detection = compute_detection(out)
    out["schema_version"] = SCHEMA_VERSION
    out["finding_id"] = compute_finding_id(out)
    out[DETECTION_KEY] = detection
    if not _truthy(out.get("confidence")):
        out["confidence"] = compute_confidence(detection)
    out["status"] = resolve_status(out, detection)
    out["evidence_items"] = build_evidence_items(out)
    out["verification"] = build_verification(out)
    out["reproduction"] = build_reproduction(out)
    out["oob"] = build_oob(out)
    return out


def to_schema_v1_many(findings: Iterable[Any]) -> List[Dict[str, Any]]:
    """批量归一化（输入非可迭代 -> 空列表）。"""
    if findings is None:
        return []
    try:
        items = list(findings)
    except TypeError:
        return []
    return [to_schema_v1(f) for f in items]


def apply_schema_inplace(finding: Any) -> Any:
    """报告链路专用：就地补写 schema v1 附加键，**不改任何既有键值**。

    只写 ``SCHEMA_ADDITIVE_KEYS``（不含 ``confidence`` / ``evidence`` 两个既有
    渲染字段），并保持 finding 对象身份不变，因此 HTML/Markdown/SARIF/CSV
    渲染结果与旧版逐字节一致。返回原对象（便于链式/单测）。
    """
    if not isinstance(finding, dict):
        return finding
    view = to_schema_v1(finding)
    for key in SCHEMA_ADDITIVE_KEYS:
        finding[key] = view[key]
    return finding


def is_schema_v1(finding: Any) -> bool:
    """是否已带 schema v1 视图（schema_version 命中）。"""
    f = _as_dict(finding)
    try:
        return int(f.get("schema_version") or 0) == SCHEMA_VERSION
    except (TypeError, ValueError):
        return False


def schema_gap_summary(findings: Sequence[Any]) -> Dict[str, int]:
    """现状差距量化：统计各级达成数量与"仅规则命中未验证"的条数。

    供报告/评测判读用（不改报告渲染）；空输入返回全 0。
    """
    stats = {level: 0 for level in DETECTION_LEVELS}
    stats["total"] = 0
    stats["rule_only_unverified"] = 0
    stats["false_positive"] = 0
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        det = compute_detection(f)
        stats["total"] += 1
        for level in DETECTION_LEVELS:
            if det[level]:
                stats[level] += 1
        if det[DET_RULE_MATCH] and not (det[DET_VERIFICATION] or det[DET_REPRODUCTION] or det[DET_OOB_CONFIRMED]):
            stats["rule_only_unverified"] += 1
        if is_false_positive(f):
            stats["false_positive"] += 1
    return stats


__all__ = [
    "SCHEMA_VERSION",
    "DETECTION_LEVELS", "DETECTION_KEY", "DETECTION_STATUS",
    "DET_RULE_MATCH", "DET_RESPONSE_EVIDENCE", "DET_VERIFICATION",
    "DET_REPRODUCTION", "DET_OOB_CONFIRMED",
    "STATUS_ORDER", "VALID_STATUSES", "STATUS_TRANSITIONS", "TERMINAL_STATUSES",
    "GOVERNANCE_STATUSES", "DETECTION_DERIVED_STATUSES",
    "STATUS_CANDIDATE", "STATUS_SUSPECTED", "STATUS_VERIFIED", "STATUS_REPRODUCED",
    "STATUS_OOB_CONFIRMED", "STATUS_FALSE_POSITIVE", "STATUS_ACCEPTED",
    "STATUS_FIXED", "STATUS_REOPENED", "STATUS_CLOSED",
    "ID_PREFIX", "SCHEMA_ADDITIVE_KEYS",
    "compute_finding_id",
    "rule_match_signals", "response_evidence_signals", "verification_signals",
    "reproduction_signals", "oob_signals",
    "compute_detection", "highest_detection_level", "is_false_positive",
    "compute_confidence", "build_evidence_items", "build_verification",
    "build_reproduction", "build_oob",
    "is_valid_status", "can_transition", "status_for_detection",
    "advance_status", "resolve_status",
    "to_schema_v1", "to_schema_v1_many", "apply_schema_inplace",
    "is_schema_v1", "schema_gap_summary",
]
