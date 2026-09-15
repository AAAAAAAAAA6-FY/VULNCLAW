# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/business_ir/observations.py
"""观测抽取 —— 把 recon brief / HTTP 轨迹归一化成"可建模的观测"。

只读、纯函数、确定性：不发任何请求（A2 不做主动探测，主动探测归引擎层）。
输入全部来自**已经采到的**数据：
  brief：alive_assets / crawled_endpoints / js_endpoints / apis / found_dirs /
         url_params / forms / tech_stack …
  traces：HTTP 轨迹（{method,url,status,headers,body}）—— 供回灌与联调用。

输出结构（IR 的前置事实，字段名稳定）：
    {"target", "endpoints": [{method,path,params:[{name,in}],status,auth_required,
                              response_sample}], "forms", "tech_stack", "sources"}
"""
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse

__all__ = ["collect_observations", "MAX_ENDPOINTS"]

MAX_ENDPOINTS = 300          # 端点上限（IR 不追求全量，追求可建模）
_SAMPLE_MAX = 400            # 响应样本截断


def _base_of(brief: Dict[str, Any], target: str = "") -> str:
    t = str(target or brief.get("target") or "")
    if t and not t.startswith(("http://", "https://")):
        t = "http://" + t
    return t.rstrip("/")


def _split(u: str, base: str) -> Optional[Tuple[str, str, List[Dict[str, Any]]]]:
    """URL → (method, path, params)。相对路径用 base 补全；畸形返回 None。

    **保留观测到的参数取值**（`samples`）——这是值域推断的唯一合法来源。
    没有样本时宁可不给值域（A1 会判 undecidable），也绝不凭参数名臆造。
    """
    if not isinstance(u, str) or not u.strip():
        return None
    raw = u.strip()
    if raw.startswith("//"):
        raw = "http:" + raw
    if not raw.startswith(("http://", "https://")):
        if not base:
            return None
        raw = base + (raw if raw.startswith("/") else "/" + raw)
    try:
        p = urlparse(raw)
    except ValueError:
        return None
    if not p.netloc:
        return None
    merged: Dict[str, List[str]] = {}
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        if k:
            merged.setdefault(k, []).append(v)
    return "GET", (p.path or "/"), [
        {"name": k, "in": "query", "samples": merged[k]} for k in sorted(merged)]


def _iter_urls(brief: Dict[str, Any], base: str) -> Iterable[Tuple[str, str]]:
    """产出 (url, source_key)。source_key 用于溯源。

    字段契约是**列表**：非法类型（如裸字符串）直接跳过——否则 `for c in "abc"`
    会把字符串逐字符当成 URL，造出 `/a` `/b` `/c` 这类幽灵端点污染 IR。
    """
    for key in ("crawled_endpoints", "js_endpoints", "apis", "found_dirs", "alive_assets"):
        lst = brief.get(key)
        if not isinstance(lst, (list, tuple)):
            continue
        for u in lst:
            if isinstance(u, dict):
                u = u.get("url") or u.get("endpoint") or ""
            if isinstance(u, str) and u:
                yield u, key
    params = brief.get("url_params")
    if isinstance(params, (list, tuple)):
        for p in params:
            if isinstance(p, dict) and p.get("url"):
                yield str(p["url"]), "url_params"


def collect_observations(brief: Optional[Dict[str, Any]] = None,
                         traces: Optional[Iterable[Dict[str, Any]]] = None,
                         target: str = "") -> Dict[str, Any]:
    """归一化观测。任何异常/畸形输入都被静默跳过（fail-closed，不抛）。"""
    brief = brief if isinstance(brief, dict) else {}
    base = _base_of(brief, target)

    endpoints: Dict[Tuple[str, str], Dict[str, Any]] = {}
    sources: set = set()

    def _add(method: str, path: str, params: List[Dict[str, str]],
             status: Optional[int] = None, sample: str = "",
             auth_required: Optional[bool] = None, src: str = "") -> None:
        method = str(method or "GET").upper()
        path = str(path or "/")
        key = (method, path)
        cur = endpoints.get(key)
        if cur is None:
            endpoints[key] = {"method": method, "path": path, "params": list(params),
                              "status": status, "auth_required": auth_required,
                              "response_sample": (sample or "")[:_SAMPLE_MAX]}
        else:
            names = {p["name"] for p in cur["params"]}
            for p in params:                      # 合并参数（不同来源可能各带一部分）
                if p["name"] not in names:
                    cur["params"].append(p)
                    names.add(p["name"])
                else:                             # 同名参数：合并观测样本（值域推断的原料）
                    tgt = next(x for x in cur["params"] if x["name"] == p["name"])
                    bucket = tgt.setdefault("samples", [])
                    for s in (p.get("samples") or []):
                        if len(bucket) < 20 and s not in bucket:
                            bucket.append(s)
            if cur.get("status") is None and status is not None:
                cur["status"] = status
            if not cur.get("response_sample") and sample:
                cur["response_sample"] = (sample or "")[:_SAMPLE_MAX]
            if cur.get("auth_required") is None and auth_required is not None:
                cur["auth_required"] = auth_required
        if src:
            sources.add(src)

    for u, src in _iter_urls(brief, base):
        got = _split(u, base)
        if got:
            _add(got[0], got[1], got[2], src=src)

    for tr in (traces or ()):
        if not isinstance(tr, dict):
            continue
        got = _split(str(tr.get("url") or ""), base)
        if not got:
            continue
        method = str(tr.get("method") or got[0]).upper()
        try:
            status = int(tr.get("status")) if tr.get("status") is not None else None
        except (TypeError, ValueError):
            status = None
        auth_required = True if status in (401, 403) else None
        _add(method, got[1], got[2], status=status,
             sample=str(tr.get("body") or tr.get("response_sample") or ""),
             auth_required=auth_required, src="http_trace")

    forms = []
    for f in (brief.get("forms") or []):
        if isinstance(f, dict) and f.get("action") is not None:
            forms.append({
                "action": str(f.get("action") or ""),
                "method": str(f.get("method") or "POST").upper(),
                "fields": sorted(str(x) for x in (f.get("fields") or f.get("inputs") or [])),
            })

    eps = sorted(endpoints.values(), key=lambda e: (e["path"], e["method"]))
    return {
        "target": base,
        "endpoints": eps[:MAX_ENDPOINTS],
        "forms": forms,
        "tech_stack": [str(t) for t in (brief.get("tech_stack") or [])],
        "sources": [{"kind": k, "ref": k} for k in sorted(sources)],
    }
