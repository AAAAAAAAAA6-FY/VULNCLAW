# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""漏洞优先级排序器 - VULNCLAW v100

基于漏洞类型、严重性、可利用性、上下文，计算优先级分数 (0-100)。
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger

_SEVERITY_WEIGHT: Dict[str, int] = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
    "info": 5,
}

_SENSITIVE_KEYWORDS: List[str] = [
    "password", "secret", "token", "key", "api_key", "credential",
    "ssn", "cvv", "authorization", "aws_access", "aws_secret",
    "jwt_secret", "encryption_key", "private",
]

_CONFIDENCE_ADJUST: Dict[str, int] = {"high": 5, "medium": 0, "low": -5}


class VulnPrioritizer:
    """漏洞优先级排序器。

    使用方式::

        from vulnclaw.core.vuln_prioritizer import VulnPrioritizer
        vp = VulnPrioritizer()
        scored = vp.sort_by_priority(vulns)
        high = vp.get_high_priority(vulns, threshold=70)
    """

    def __init__(self, default_threshold: int = 70):
        self.default_threshold = default_threshold

    def calculate_score(self, vuln: Dict[str, Any]) -> int:
        """计算单个漏洞的优先级分数 (0-100)。"""
        score = 0

        severity = str(vuln.get("severity", "low")).lower()
        score += _SEVERITY_WEIGHT.get(severity, 10)

        has_poc = bool(vuln.get("has_poc", False))
        public_exp = bool(vuln.get("public_exp", False))
        exploitability = str(vuln.get("exploitability", "")).lower()
        if has_poc or exploitability in ("proven", "high"):
            score += 20
        elif public_exp or exploitability == "theoretical":
            score += 15

        sensitive = bool(vuln.get("sensitive", False))
        endpoint_type = str(vuln.get("endpoint_type", "")).lower()
        if sensitive:
            score += 15
        elif endpoint_type in ("admin", "internal"):
            score += 8
        elif endpoint_type == "public":
            score += 10

        if bool(vuln.get("has_cve", False)):
            score += 10
        if bool(vuln.get("has_cwe", False)):
            score += 5

        cvss = vuln.get("cvss")
        if cvss is not None and isinstance(cvss, (int, float)):
            score += min(20, int(float(cvss) * 2))

        confidence = str(vuln.get("confidence", "")).lower()
        score += _CONFIDENCE_ADJUST.get(confidence, 0)

        if not sensitive:
            blob = (
                str(vuln.get("evidence", ""))
                + " "
                + str(vuln.get("description", ""))
            )
            blob_lower = blob.lower()
            hits = sum(1 for kw in _SENSITIVE_KEYWORDS if kw in blob_lower)
            if hits >= 2:
                score += 10
            elif hits == 1:
                score += 5

        final = max(0, min(100, score))
        logger.debug("calculate_score: %d (%s)", final, severity)
        return final

    def sort_by_priority(
        self,
        vulns: List[Dict[str, Any]],
        add_score: bool = True,
    ) -> List[Dict[str, Any]]:
        """按优先级分数降序排序漏洞列表。"""
        scored: List[tuple] = []
        for v in vulns:
            v2 = dict(v)
            s = self.calculate_score(v2)
            if add_score:
                v2["_priority_score"] = s
            scored.append((s, v2))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored]

    def get_high_priority(
        self,
        vulns: List[Dict[str, Any]],
        threshold: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """筛选高于阈值的漏洞。"""
        if threshold is None:
            threshold = self.default_threshold
        sorted_vulns = self.sort_by_priority(vulns, add_score=True)
        return [v for v in sorted_vulns if v.get("_priority_score", 0) >= threshold]

    def summarize(
        self,
        vulns: List[Dict[str, Any]],
        top_n: int = 10,
    ) -> Dict[str, Any]:
        """生成漏洞优先级摘要报告。"""
        sorted_vulns = self.sort_by_priority(vulns, add_score=True)
        high = [v for v in sorted_vulns if v.get("_priority_score", 0) >= self.default_threshold]
        type_dist: Dict[str, int] = {}
        for v in vulns:
            t = str(v.get("type", "unknown")).lower()
            type_dist[t] = type_dist.get(t, 0) + 1
        avg = round(
            sum(v.get("_priority_score", 0) for v in sorted_vulns)
            / max(len(sorted_vulns), 1),
            1,
        )
        return {
            "total": len(vulns),
            "high_priority_count": len(high),
            "avg_score": avg,
            "top_vulns": sorted_vulns[:top_n],
            "type_distribution": type_dist,
            "generated_at": datetime.now().isoformat(),
        }


_DEFAULT_VP = VulnPrioritizer()


def calculate_score(vuln: Dict[str, Any]) -> int:
    return _DEFAULT_VP.calculate_score(vuln)


def sort_by_priority(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return _DEFAULT_VP.sort_by_priority(vulns)


def get_high_priority(
    vulns: List[Dict[str, Any]], threshold: int = 70
) -> List[Dict[str, Any]]:
    return _DEFAULT_VP.get_high_priority(vulns, threshold=threshold)