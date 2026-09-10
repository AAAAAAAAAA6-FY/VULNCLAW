# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""声明式漏洞知识库：数据模型与校验。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


# oracle 类型
DETECT_REGEX = "regex"      # 响应文本命中正则
DETECT_REFLECT = "reflect"  # payload 被原样反射进响应
DETECT_TIME = "time"        # 相对基线出现显著延时
DETECT_DIFF = "diff"        # 与基线响应存在显著差异
DETECT_HEADER = "header"    # 检查**响应头**（CORS / 安全头缺失 / 重定向头等）

_DETECT_TYPES = (DETECT_REGEX, DETECT_REFLECT, DETECT_TIME, DETECT_DIFF, DETECT_HEADER)

# 默认适用的注入位置（与 attack_surface.PointLocation 对齐）
ALL_LOCATIONS = ("query", "path", "header", "cookie", "body_form", "body_json")


@dataclass(frozen=True)
class DetectRule:
    """判定规则（oracle）。"""

    type: str
    patterns: Tuple[str, ...] = ()
    negative: bool = False      # True：命中 patterns 表示**安全**（如"无权限"页）
    threshold: float = 0.0      # time: 秒；diff: 差异比
    header_name: str = ""       # header 型：要检查的响应头（空=检查全部头）
    header_absent: bool = False # header 型：True 表示该头**缺失**即命中（如安全头缺失）
    # 上下文约束：非空则要求响应 Content-Type 包含该串才判定。
    # 例：XSS 只在 HTML 响应中有意义——JSON 里回显 <script> 并不会执行，
    #     不加此约束会对"原样回显输入的搜索框/echo 接口"大量误报。
    require_content_type: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def compiled(self) -> List[re.Pattern]:
        out = []
        for p in self.patterns:
            try:
                out.append(re.compile(p, re.IGNORECASE))
            except re.error:
                continue
        return out


@dataclass(frozen=True)
class VulnSpec:
    """一条漏洞声明。"""

    id: str
    name: str
    category: str
    payloads: Tuple[str, ...]
    detect: DetectRule
    locations: Tuple[str, ...] = ALL_LOCATIONS
    param_hints: Tuple[str, ...] = ()   # 为空表示不限参数名
    severity: str = "medium"
    cvss: float = 5.0
    confidence: str = "medium"
    remediation: str = ""
    recommendation: str = ""
    max_payloads: int = 5
    enabled: bool = True
    # 发送请求时附加的请求头（如 CORS 探测需要带 Origin）
    request_headers: Tuple[Tuple[str, str], ...] = ()

    def applies_to(self, location: str, param_name: str) -> bool:
        if location not in self.locations:
            return False
        if not self.param_hints:
            return True
        low = str(param_name or "").lower()
        return any(h.lower() in low for h in self.param_hints)


def from_dict(d: Dict[str, Any]) -> VulnSpec:
    """从字典构造（便于未来接 YAML/JSON 声明文件）。"""
    det = d.get("detect") or {}
    rule = DetectRule(
        type=str(det.get("type") or DETECT_REGEX),
        patterns=tuple(det.get("patterns") or ()),
        negative=bool(det.get("negative", False)),
        threshold=float(det.get("threshold", 0.0) or 0.0),
        header_name=str(det.get("header_name") or ""),
        header_absent=bool(det.get("header_absent", False)),
        require_content_type=str(det.get("require_content_type") or ""),
        extra=dict(det.get("extra") or {}),
    )
    return VulnSpec(
        id=str(d.get("id") or ""),
        name=str(d.get("name") or d.get("id") or ""),
        category=str(d.get("category") or "generic"),
        payloads=tuple(d.get("payloads") or ()),
        detect=rule,
        locations=tuple(d.get("locations") or ALL_LOCATIONS),
        param_hints=tuple(d.get("param_hints") or ()),
        severity=str(d.get("severity") or "medium"),
        cvss=float(d.get("cvss", 5.0) or 5.0),
        confidence=str(d.get("confidence") or "medium"),
        remediation=str(d.get("remediation") or ""),
        recommendation=str(d.get("recommendation") or ""),
        max_payloads=int(d.get("max_payloads", 5) or 5),
        enabled=bool(d.get("enabled", True)),
        request_headers=tuple((str(k), str(v))
                              for k, v in (d.get("request_headers") or {}).items()),
    )


def validate(spec: VulnSpec) -> List[str]:
    """返回问题列表（空 = 合法）。声明质量保障的基础（后续可配靶场回归）。"""
    errs: List[str] = []
    if not spec.id:
        errs.append("缺少 id")
    if spec.detect.type not in _DETECT_TYPES:
        errs.append(f"未知 detect.type: {spec.detect.type}")
    if spec.detect.type in (DETECT_REGEX,) and not spec.detect.patterns:
        errs.append("regex 型 detect 必须提供 patterns")
    if spec.detect.type == DETECT_HEADER:
        if not spec.detect.patterns and not spec.detect.header_absent:
            errs.append("header 型 detect 需提供 patterns 或 header_absent=True")
    if spec.detect.type == DETECT_TIME and spec.detect.threshold <= 0:
        errs.append("time 型 detect 必须提供正的 threshold")
    if not spec.payloads:
        errs.append("缺少 payloads")
    for loc in spec.locations:
        if loc not in ALL_LOCATIONS:
            errs.append(f"未知 location: {loc}")
    return errs
