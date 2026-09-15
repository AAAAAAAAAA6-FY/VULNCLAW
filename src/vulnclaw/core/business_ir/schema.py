# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/business_ir/schema.py
"""BusinessIR 数据结构 / 校验 / 归一化（版本 `ir-1`）。

IR 是 A 池三件套的**中间表示**：A2 产出它，A1（符号执行）与 A3（链规划器）消费它。
因此本文件的字段名就是三方接口契约（见 docs/TASKLIST_BEYOND_STRIX.md §28.1），
**改字段名等于改接口**，必须同步三方。

纪律：
* `validate_ir` 只**返回错误列表**，绝不抛异常（调用方据此决定是否 fail-closed）。
* `normalize_ir` 保证**确定性**：排序稳定、无时间戳、无随机 → 同输入逐字节同输出
  （这是"IR 幂等"验收项的实现基础）。
"""
from typing import Any, Dict, List

__all__ = [
    "IR_VERSION",
    "PARAM_IN",
    "DOMAIN_KINDS",
    "AUTH_ROLES",
    "empty_ir",
    "validate_ir",
    "normalize_ir",
    "ir_summary",
]

IR_VERSION = "ir-1"
PARAM_IN = ("query", "body", "path", "header", "cookie")
DOMAIN_KINDS = ("int", "float", "enum", "str", "bool")
# 认证角色归一：未识别一律 None（不猜）
AUTH_ROLES = ("anonymous", "user", "admin", "owner")

_ENDPOINT_KEYS = ("id", "method", "path", "params", "auth", "effects", "idempotent")


def empty_ir(target: str = "") -> Dict[str, Any]:
    """空 IR 骨架（所有字段齐备 → 下游无需判 None）。"""
    return {
        "target": str(target or ""),
        "version": IR_VERSION,
        "entities": [],
        "endpoints": [],
        "transitions": [],
        "invariants": [],
        "goals": [],
        "confidence": 0.0,
        "sources": [],
    }


def _is_str(v: Any) -> bool:
    return isinstance(v, str) and bool(v.strip())


def validate_ir(ir: Any) -> List[str]:
    """校验 IR。返回错误信息列表；空列表 = 合法。**绝不抛异常**。"""
    errs: List[str] = []
    if not isinstance(ir, dict):
        return ["IR 不是字典"]
    if ir.get("version") != IR_VERSION:
        errs.append(f"版本不匹配: {ir.get('version')!r} != {IR_VERSION!r}")
    for key in ("entities", "endpoints", "transitions", "invariants", "goals"):
        if not isinstance(ir.get(key), list):
            errs.append(f"缺少或非列表字段: {key}")

    ep_ids = set()
    for i, ep in enumerate(ir.get("endpoints") or []):
        if not isinstance(ep, dict):
            errs.append(f"endpoints[{i}] 不是字典")
            continue
        eid = ep.get("id")
        if not _is_str(eid):
            errs.append(f"endpoints[{i}].id 非法")
        elif eid in ep_ids:
            errs.append(f"endpoints[{i}].id 重复: {eid}")
        else:
            ep_ids.add(eid)
        if not _is_str(ep.get("method")):
            errs.append(f"endpoints[{i}].method 非法")
        if not _is_str(ep.get("path")):
            errs.append(f"endpoints[{i}].path 非法")
        for j, p in enumerate(ep.get("params") or []):
            if not isinstance(p, dict) or not _is_str(p.get("name")):
                errs.append(f"endpoints[{i}].params[{j}] 非法")
                continue
            if p.get("in") is not None and p.get("in") not in PARAM_IN:
                errs.append(f"endpoints[{i}].params[{j}].in 非法: {p.get('in')!r}")
            dom = p.get("domain")
            if dom is not None:
                if not isinstance(dom, dict) or dom.get("kind") not in DOMAIN_KINDS:
                    errs.append(f"endpoints[{i}].params[{j}].domain 非法: {dom!r}")

    for i, tr in enumerate(ir.get("transitions") or []):
        if not isinstance(tr, dict):
            errs.append(f"transitions[{i}] 不是字典")
            continue
        via = tr.get("via_endpoint")
        if _is_str(via) and ep_ids and via not in ep_ids:
            errs.append(f"transitions[{i}].via_endpoint 引用不存在的端点: {via}")

    for i, inv in enumerate(ir.get("invariants") or []):
        if not isinstance(inv, dict) or not _is_str(inv.get("id")):
            errs.append(f"invariants[{i}] 缺少 id")
            continue
        expr = inv.get("expr")
        if not isinstance(expr, dict) or not isinstance(expr.get("coeffs"), dict):
            errs.append(f"invariants[{i}].expr 非法（需 {{coeffs:{{var:coef}}, const:int}}）")

    for i, g in enumerate(ir.get("goals") or []):
        if not isinstance(g, dict) or not _is_str(g.get("id")):
            errs.append(f"goals[{i}] 缺少 id")

    conf = ir.get("confidence")
    if conf is not None and not isinstance(conf, (int, float)):
        errs.append("confidence 非数值")
    return errs


def _norm_endpoint(ep: Dict[str, Any]) -> Dict[str, Any]:
    params = []
    seen = set()
    for p in (ep.get("params") or []):
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        params.append({
            "name": name,
            "in": p.get("in") if p.get("in") in PARAM_IN else "query",
            "required": bool(p.get("required", False)),
            "domain": p.get("domain") if isinstance(p.get("domain"), dict) else None,
        })
    params.sort(key=lambda x: x["name"])
    auth = ep.get("auth") if isinstance(ep.get("auth"), dict) else {}
    role = auth.get("role") if auth.get("role") in AUTH_ROLES else None
    return {
        "id": str(ep.get("id") or ""),
        "method": str(ep.get("method") or "GET").upper(),
        "path": str(ep.get("path") or ""),
        "params": params,
        "auth": {"required": bool(auth.get("required", False)), "role": role},
        "effects": [
            {"entity": str(e.get("entity")), "op": str(e.get("op") or "write")}
            for e in (ep.get("effects") or []) if isinstance(e, dict) and e.get("entity")
        ],
        "idempotent": bool(ep.get("idempotent", False)),
    }


def normalize_ir(ir: Dict[str, Any]) -> Dict[str, Any]:
    """归一化：补齐字段、排序去重、剔除非法项。**确定性**（同输入同输出）。"""
    if not isinstance(ir, dict):
        return empty_ir()
    out = empty_ir(ir.get("target", ""))

    eps = [_norm_endpoint(e) for e in (ir.get("endpoints") or []) if isinstance(e, dict)]
    eps = [e for e in eps if e["id"] and e["path"]]
    # 去重键：(method, path)；同键保留参数更全的那条
    best: Dict[Any, Dict[str, Any]] = {}
    for e in eps:
        key = (e["method"], e["path"])
        cur = best.get(key)
        if cur is None or len(e["params"]) > len(cur["params"]):
            best[key] = e
    out["endpoints"] = sorted(best.values(), key=lambda x: (x["path"], x["method"], x["id"]))

    ents: Dict[str, Dict[str, Any]] = {}
    for e in (ir.get("entities") or []):
        if isinstance(e, dict) and e.get("name"):
            ents[str(e["name"])] = {
                "name": str(e["name"]),
                "key": str(e.get("key") or "id"),
                "fields": sorted(
                    ({"name": str(f.get("name")), "type": str(f.get("type") or "str"),
                      "domain": f.get("domain") if isinstance(f.get("domain"), dict) else None}
                     for f in (e.get("fields") or []) if isinstance(f, dict) and f.get("name")),
                    key=lambda x: x["name"]),
            }
    out["entities"] = [ents[k] for k in sorted(ents)]

    ep_ids = {e["id"] for e in out["endpoints"]}
    trs = []
    for t in (ir.get("transitions") or []):
        if not isinstance(t, dict):
            continue
        if t.get("via_endpoint") and ep_ids and t["via_endpoint"] not in ep_ids:
            continue                                  # 悬空引用直接丢（fail-closed）
        trs.append({
            "from_state": str(t.get("from_state") or ""),
            "to_state": str(t.get("to_state") or ""),
            "via_endpoint": str(t.get("via_endpoint") or ""),
            "preconditions": [str(x) for x in (t.get("preconditions") or [])],
            "postconditions": [str(x) for x in (t.get("postconditions") or [])],
        })
    out["transitions"] = sorted(
        trs, key=lambda x: (x["via_endpoint"], x["from_state"], x["to_state"]))

    invs = []
    for inv in (ir.get("invariants") or []):
        if not isinstance(inv, dict) or not inv.get("id"):
            continue
        expr = inv.get("expr")
        if not isinstance(expr, dict) or not isinstance(expr.get("coeffs"), dict):
            continue
        try:
            coeffs = {str(k): int(v) for k, v in expr["coeffs"].items() if int(v) != 0}
            const = int(expr.get("const", 0))
        except (TypeError, ValueError):
            continue
        invs.append({
            "id": str(inv["id"]),
            "expr": {"coeffs": {k: coeffs[k] for k in sorted(coeffs)}, "const": const},
            "kind": str(inv.get("kind") or "arithmetic"),
            "confidence": float(inv.get("confidence", 0.5) or 0.0),
        })
    out["invariants"] = sorted(invs, key=lambda x: x["id"])

    goals = []
    for g in (ir.get("goals") or []):
        if isinstance(g, dict) and g.get("id"):
            goals.append({
                "id": str(g["id"]),
                "desc": str(g.get("desc") or ""),
                "requires_facts": sorted(str(x) for x in (g.get("requires_facts") or [])),
                "predicate": g.get("predicate") if isinstance(g.get("predicate"), dict) else None,
            })
    out["goals"] = sorted(goals, key=lambda x: x["id"])

    srcs = []
    for s in (ir.get("sources") or []):
        if isinstance(s, dict) and s.get("kind"):
            srcs.append({"kind": str(s["kind"]), "ref": str(s.get("ref") or "")})
    out["sources"] = sorted({(s["kind"], s["ref"]) for s in srcs})
    out["sources"] = [{"kind": k, "ref": r} for k, r in out["sources"]]

    try:
        out["confidence"] = round(float(ir.get("confidence", 0.0) or 0.0), 4)
    except (TypeError, ValueError):
        out["confidence"] = 0.0
    return out


def ir_summary(ir: Dict[str, Any]) -> Dict[str, Any]:
    """给日志/报告用的摘要（纯统计，无副作用）。"""
    if not isinstance(ir, dict):
        return {"ok": False, "reason": "非法 IR"}
    eps = ir.get("endpoints") or []
    return {
        "ok": not validate_ir(ir),
        "target": ir.get("target", ""),
        "version": ir.get("version", ""),
        "endpoints": len(eps),
        "params": sum(len(e.get("params") or []) for e in eps if isinstance(e, dict)),
        "entities": len(ir.get("entities") or []),
        "transitions": len(ir.get("transitions") or []),
        "invariants": len(ir.get("invariants") or []),
        "goals": len(ir.get("goals") or []),
        "confidence": ir.get("confidence", 0.0),
        "sources": len(ir.get("sources") or []),
    }
