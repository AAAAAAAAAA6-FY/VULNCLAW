# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/models.py
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

try:
    from pydantic import BaseModel, HttpUrl  # noqa: F401  (可用性探测)
except ImportError:
    from pydantic import BaseModel


class WebAsset(BaseModel):
    url: str  # 改为 str 避免 URL 解析失败
    status: int = 0
    title: str = ""
    content_type: str = ""
    content_length: int = 0
    technologies: List[str] = []
    ip: Optional[str] = None


class VulnerabilityStrict(BaseModel):
    target: str
    type: str
    risk: str
    url: str
    detail: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0
    ai_analysis: str = ""
    cve_ids: List[str] = []
    cvss_score: float = 0.0


class ScanContextModel(BaseModel):
    domain: str
    subdomains: List[str] = []
    alive_assets: List[WebAsset] = []
    open_ports: List[int] = []
    tech_stack: Dict[str, List[str]] = {}
    has_cookie: bool = False
    scan_mode: str = "deep"


@dataclass
class Vulnerability:
    target: str
    type: str
    risk: str
    url: str
    detail: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0
    ai_analysis: str = ""
    ai_recommendation: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        result = {}
        for k, v in self.__dict__.items():
            if not k.startswith("_"):
                if isinstance(v, datetime):
                    result[k] = v.isoformat()
                elif isinstance(v, (list, dict)):
                    result[k] = v
                else:
                    result[k] = v
        return result


# ============================================================
# G 组: finding 证据五档规范（rule_hit / response_evidence /
#         verified / reproduced / oob_success）
# ============================================================
# 所有报告格式（HTML / Markdown / SARIF / 网关 SARIF）与统计
# （benchmark / dataset_metrics）统一消费这里产出的布尔语义，
# 避免各处各自解读 `exploit_verified` 等异构引擎字段导致口径漂移。
_EVIDENCE_TEXT_KEYS = (
    "evidence", "response_evidence", "response_preview",
    "proof", "evidence_chain", "detail",
)
# 验证/复现落锤信号（引擎与验证层异构字段的规范映射）
_VERIFY_SIGNAL_KEYS = (
    "exploited", "exploit_verified", "burp_verified", "burp_confirmed",
    "cross_confirmed", "cross_tool_confirmed", "probe_confirmed",
    "oob_confirmed", "oob_callback", "collaborator_callback",
    "technical_confirmed", "browser_verified",
)
_REPRO_SIGNAL_KEYS = (
    "exploited", "exploit_verified", "exploit_reproduced",
    "revalidated", "probe_confirmed",
)


def _evidence_text(f: dict) -> str:
    """取 finding 的响应证据原文（多个字段通配，返回首个非空文本）。"""
    for k in _EVIDENCE_TEXT_KEYS:
        v = f.get(k)
        if isinstance(v, (list, dict)):
            v = str(v)
        if str(v or "").strip():
            return str(v)
    return ""


def apply_evidence_schema(f: dict) -> dict:
    """把引擎/验证层的异构证据信号归一为五档规范布尔字段（就地改写）。

    字段语义（全报告格式共用，勿在别处自行重新定义）：
      rule_hit          规则命中：本地规则/引擎特征规则确认；
      response_evidence 响应证据：evidence/proof/response_preview 等存在非空文本；
      verified          验证成功：验证层背书（exploited/burp/cross/oob/probe/规则/
                                   verdict=confirm|likely/ai_verdict=真实漏洞）；
      reproduced        复现成功：独立重打或 OOB 回调实锤（exploited/exploit_*
                                   /revalidated/probe_confirmed/blind_repro=confirmed）；
      oob_success       带外回调成功：collaborator/OOB 通道实锤。
    """
    rule_hit = bool(f.get("rule_hit")) or "local_rule" in str(
        f.get("verification_method") or ""
    )
    oob_success = bool(
        f.get("oob_confirmed")
        or f.get("oob_callback")
        or f.get("collaborator_callback")
        or "oob" in str(f.get("verification_method") or "").lower()
    )
    _oe = f.get("oob_evidence")
    if isinstance(_oe, dict) and (str(_oe.get("ts") or "").strip() or str(_oe.get("detail") or "").strip()):
        oob_success = True
    verified = bool(
        oob_success
        or rule_hit
        or any(f.get(k) for k in _VERIFY_SIGNAL_KEYS)
        or str(f.get("blind_repro")) == "confirmed"
        or str(f.get("verdict")) in ("confirm", "likely")
        or "真实漏洞" in str(f.get("ai_verdict") or "")
    )
    reproduced = bool(
        oob_success
        or any(f.get(k) for k in _REPRO_SIGNAL_KEYS)
        or str(f.get("blind_repro")) == "confirmed"
    )
    f["response_evidence"] = bool(_evidence_text(f))
    # rule_hit 已是引擎/网关的字符串命中介质（如 local_rule:sql_error）时保原值，
    # 仅缺失时写入规范布尔——truthiness 语义一致且不丢可读信息。
    if not f.get("rule_hit"):
        f["rule_hit"] = rule_hit
    f["verified"] = bool(verified)
    f["reproduced"] = bool(reproduced)
    f["oob_success"] = bool(oob_success)
    return f


__all__ = [
    'WebAsset',
    'VulnerabilityStrict',
    'ScanContextModel',
    'Vulnerability',
    'apply_evidence_schema',
]
