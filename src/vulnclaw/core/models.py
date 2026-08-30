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


__all__ = [
    'WebAsset',
    'VulnerabilityStrict',
    'ScanContextModel',
    'Vulnerability'
]
