# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/dedupe.py
"""SP2 确定性去重前置：指纹去重 + 语义疑似分组。

对面在做"每条 finding 过 LLM 判重"（strix 思路）；本模块是它的前置确定性层：
  1. 指纹命中（同 host+path+type+method+param）-> 直接合并（零 LLM 成本）。
  2. 语义疑似组（同资产同类型、但描述/参数/证据不同）-> 进入 LLM 二次裁决列表。
配合使用：deterministic_dedupe(findings) -> (kept, ambiguous_groups)，
ambiguous_groups 作为 LLM 判重的输入，kept 无需再走 LLM。
"""
import re
from urllib.parse import urlparse, urlsplit
from typing import Any, Dict, List, Tuple

# severity 排序权重（越大越严重，合并时保留最强）
_SEVERITY_RANK = {"critical": 6, "high": 5, "medium": 3, "low": 2, "info": 1, "": 0}
# verdict 排序权重（confirm > likely > suspicious，保留更高判定）
_VERDICT_RANK = {"confirm": 3, "likely": 2, "suspicious": 1, "": 0}
# confidence 数值化（用于合并选优）
_CONFIDENCE_NUM = {"high": 0.95, "medium": 0.7, "low": 0.35, "": 0.5}

_FILLER_RE = re.compile(r"[\s_\-.]+")


def _norm_text(s: Any) -> str:
    return _FILLER_RE.sub(" ", str(s or "")).strip().lower()


def _norm_url(url: Any) -> str:
    """规范化 URL：去 query/fragment、去尾斜杠，统一大小写。param 单独参与指纹。"""
    try:
        p = urlparse(str(url or ""))
        return (p.scheme + "://" + p.netloc.lower() + p.path.rstrip("/")) if p.scheme else ""
    except Exception:  # noqa: BLE001
        return _norm_text(url)


def _conf_of(f: Dict[str, Any]) -> float:
    c = f.get("confidence")
    if isinstance(c, (int, float)):
        val = c
        if val >= 100:
            return 0.95
        if val >= 90:
            return 0.9
        if val >= 60:
            return 0.7
        return 0.35
    return _CONFIDENCE_NUM.get(_norm_text(c), 0.5)


def _strength(f: Dict[str, Any]) -> Tuple[int, int, float, int]:
    """合并优先级：(severity, verdict, confidence, 原序)。"""
    sev = _SEVERITY_RANK.get(_norm_text(f.get("severity")), 0)
    ver = _VERDICT_RANK.get(_norm_text(f.get("verdict")), 0)
    return (sev, ver, _conf_of(f), 0)


def findings_fingerprint(f: Dict[str, Any]) -> str:
    """确定性指纹：host|path|method|type|param。

    不含证据/描述文本——避免因措辞不同而误判为不同漏洞（保持与 strix 判同规则一致：
    同根因 + 同位置 + 同攻击向量 视为同一漏洞）。
    """
    url = _norm_url(f.get("url"))
    method = _norm_text(f.get("method")).lower() or "get"
    vtype = _norm_text(f.get("type"))
    param = _norm_text(f.get("parameter"))
    return "|".join((url, method, vtype, param))


def deterministic_dedupe(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """确定性去重前置。

    返回 (kept, ambiguous_groups)：
      - kept：按指纹合并后的保留列表（每指纹保留强度最高者，同强度保留先到）。
      - ambiguous_groups：语义疑似组——同 host+path+type（位置+类型相同）但
        指纹不同（param/证据不同）的 finding 簇，供 LLM 二次裁决边界情况；
        每组单条时不产生疑似（无需裁决）。
    """
    kept: List[Dict[str, Any]] = []
    best_by_key: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        key = findings_fingerprint(f)
        cur = best_by_key.get(key)
        if cur is None:
            best_by_key[key] = dict(f)
            kept.append(best_by_key[key])
        elif _strength(f) > _strength(cur):
            best_by_key[key].update(f)

    # 语义疑似组：同 host+path+type、不同指纹（param 或 method 不同）
    by_loc: Dict[str, List[Dict[str, Any]]] = {}
    url = ""
    for f in kept:
        purl = urlparse(str(f.get("url") or ""))
        loc = (purl.scheme + "://" + purl.netloc.lower() + purl.path.rstrip("/"),
               _norm_text(f.get("type")))
        if loc[0]:
            by_loc.setdefault(loc, []).append(f)
    ambiguous: List[Dict[str, Any]] = []
    for (loc, _t), items in by_loc.items():
        if len(items) > 1:
            params = {_norm_text(i.get("parameter")) for i in items} - {""}
            if len(params) > 1 or any(i.get("method") != items[0].get("method") for i in items):
                ambiguous.append({
                    "location": loc,
                    "type": _t,
                    "count": len(items),
                    "candidates": [
                        {"id": i.get("finding_id") or i.get("url"),
                         "url": i.get("url"), "method": i.get("method"),
                         "parameter": i.get("parameter"), "type": i.get("type"),
                         "evidence": str(i.get("evidence") or i.get("description") or "")[:200],
                         "severity": i.get("severity"), "verdict": i.get("verdict")}
                        for i in items
                    ],
                })
    return kept, ambiguous


def merge_llm_verdict(kept: List[Dict[str, Any]], ambiguous: List[Dict[str, Any]],
                      llm_decisions: Dict[str, bool]) -> List[Dict[str, Any]]:
    """LLM 裁决结果合并（is_duplicate 判定）。入口为 SP2 的 ambiguous_groups。

    llm_decisions: {location|param -> True(判为重复，舍弃)/False(保留)}。
    仅当某 key 显式判定为 True 才丢弃对应 finding；未裁决的疑似组全部保留
    （宁多报不漏报）。每个指纹组的保留对象由 kept 自带（去重时已留最强）。
    """
    if not llm_decisions:
        return list(kept)
    drop_keys = {k for k, v in llm_decisions.items() if v}
    out: List[Dict[str, Any]] = []
    for f in kept:
        purl = urlparse(str(f.get("url") or ""))
        loc = (purl.scheme + "://" + purl.netloc.lower() + purl.path.rstrip("/")) if purl.scheme else ""
        key = f"{loc}|{_norm_text(f.get('parameter'))}"
        if key not in drop_keys:
            out.append(f)
    return out


__all__ = ["findings_fingerprint", "deterministic_dedupe", "merge_llm_verdict"]