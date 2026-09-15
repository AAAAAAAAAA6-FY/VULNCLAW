# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/business_ir/features.py
"""确定性特征推断 —— 不依赖 LLM 的 IR 骨架（LLM 只在其上做增强，见 llm_extractor）。

推断内容（全部纯函数、无随机、无时间依赖）：
  * 参数类型与值域：从样本值推 区间 / 枚举 / 字符串
  * 参数位置：query / body / path（按方法与名称启发）
  * 路径聚类：/order/123 与 /order/456 → /order/{id}（同一业务端点）
  * 写操作与实体：POST/PUT/PATCH/DELETE + 路径段 → effects/entities
  * 认证需求：观测到的 401/403 → auth.required=True（只认证据，不猜）
  * 流程顺序：step 类关键词端点 → transitions 的粗序（postconditions 由 LLM 补精确）

产出 confidence 固定偏低（0.3）：启发式骨架只是"待 LLM 增强的草稿"，
**不允许**把骨架当高置信结论用。
"""
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

__all__ = [
    "infer_domain",
    "classify_param_kind",
    "guess_param_in",
    "path_template",
    "cluster_paths",
    "build_ir_skeleton",
]

_NUM_RE = re.compile(r"^-?\d+$")
_FLOAT_RE = re.compile(r"^-?\d+\.\d+$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SEG_ID_RE = re.compile(r"^(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{16,})$")
_STEP_WORDS = ("step", "stage", "confirm", "pay", "checkout", "verify",
               "finalize", "commit", "complete", "activate", "submit", "approve")
_WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

_INT_NAME_HINTS = ("id", "uid", "count", "num", "qty", "quantity", "page", "size",
                   "limit", "offset", "code", "status", "role", "level", "type", "flag")
_FLOAT_NAME_HINTS = ("price", "amount", "total", "fee", "cost", "money", "balance",
                     "rate", "score", "weight", "discount")
_BOOL_NAME_HINTS = ("is_", "has_", "enable", "enabled", "active", "verified",
                    "approved", "paid", "locked", "remember")


def classify_param_kind(name: str) -> str:
    """按参数名猜类型（仅作**无样本时的兜底**；有样本时以样本为准）。"""
    if not isinstance(name, str) or not name:
        return "str"
    low = name.lower()
    if any(low.startswith(h) or h in low for h in _BOOL_NAME_HINTS):
        return "bool"
    if any(h in low for h in _FLOAT_NAME_HINTS):
        return "float"
    if any(h == low or low.endswith("_" + h) or low.startswith(h + "_") or h in low
           for h in _INT_NAME_HINTS):
        return "int"
    return "str"


def _coerce_value(s: Any) -> Any:
    """样本字符串 → 尽量还原类型（bool / int / float / str），供值域推断使用。"""
    if not isinstance(s, str):
        return s
    t = s.strip()
    low = t.lower()
    if low in ("true", "false"):
        return low == "true"
    if _NUM_RE.match(t):
        try:
            return int(t)
        except ValueError:
            return t
    if _FLOAT_RE.match(t):
        try:
            return float(t)
        except ValueError:
            return t
    return t


def _domain_for_kind(kind: str) -> Dict[str, Any]:
    """类型名 → 保守占位值域（无样本时用；有样本由 `infer_domain` 覆盖）。"""
    if kind == "bool":
        return {"kind": "enum", "values": [False, True]}
    if kind == "int":
        return {"kind": "int"}
    if kind == "float":
        return {"kind": "float"}
    return {"kind": "str"}


def infer_domain(values: Sequence[Any]) -> Dict[str, Any]:
    """从样本值推值域（IR 的 `domain` 字段形态）。

    优先级：全部布尔 → enum(bool) ｜ 全整数 → int 区间 ｜ 全数值 → float 区间 ｜
    少量不同值(<=10) → enum ｜ 其余 → str（带长度上限）。
    空样本 → 无信息，返回 str（**不虚构区间**，避免 A1 拿到假域产生误报）。
    """
    vals = [v for v in (values or []) if v is not None]
    if not vals:
        return {"kind": "str"}
    if all(isinstance(v, bool) for v in vals):
        uniq = sorted({bool(v) for v in vals})
        return {"kind": "enum", "values": uniq}
    nums = [v for v in vals if isinstance(v, int) and not isinstance(v, bool)]
    if len(nums) == len(vals):
        uniq = sorted(set(nums))
        if len(uniq) <= 10:
            return {"kind": "enum", "values": uniq}
        return {"kind": "int", "lo": uniq[0], "hi": uniq[-1]}
    floats = [v for v in vals if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if len(floats) == len(vals):
        uniq = sorted({float(v) for v in floats})
        if len(uniq) <= 10:
            return {"kind": "enum", "values": uniq}
        return {"kind": "float", "lo": uniq[0], "hi": uniq[-1]}
    strs = [str(v) for v in vals]
    uniq_s = sorted(set(strs))
    # 枚举只适用于"少且短"的取值（如 method=GET/POST、status=paid/pending）；
    # 长文本（40/50 字符那种）归 str + max_len，否则值域会被当成无意义的枚举集
    if len(uniq_s) <= 10 and all(0 < len(s) <= 24 for s in uniq_s):
        return {"kind": "enum", "values": uniq_s}
    return {"kind": "str", "max_len": max(len(s) for s in strs)}


def guess_param_in(name: str, method: str = "GET") -> str:
    """参数位置启发：GET → query；写方法 → body；路径段里的数字/UUID → path。"""
    if not isinstance(name, str):
        return "query"
    if _SEG_ID_RE.match(name):
        return "path"
    if str(method or "GET").upper() in _WRITE_METHODS:
        return "body"
    return "query"


def path_template(path: str) -> str:
    """路径模板化：/order/123 → /order/{id}（同类业务端点归一，便于聚类与去重）。"""
    if not isinstance(path, str) or not path:
        return "/"
    out = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg)
            continue
        if _NUM_RE.match(seg) or _UUID_RE.match(seg):
            out.append("{id}")
        elif len(seg) >= 16 and _SEG_ID_RE.match(seg):
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out)


def cluster_paths(endpoints: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """按路径模板聚类；同模板多端点合并参数（确定性排序）。"""
    groups: Dict[str, Dict[str, Any]] = {}
    for ep in (endpoints or ()):
        if not isinstance(ep, dict):
            continue
        tpl = path_template(str(ep.get("path") or "/"))
        g = groups.setdefault(tpl, {"path": tpl, "methods": set(), "params": {},
                                    "count": 0, "auth_required": None})
        g["methods"].add(str(ep.get("method") or "GET").upper())
        g["count"] += 1
        for p in (ep.get("params") or []):
            if isinstance(p, dict) and p.get("name"):
                g["params"].setdefault(str(p["name"]), p.get("in") or "query")
        if g["auth_required"] is None and ep.get("auth_required") is not None:
            g["auth_required"] = ep.get("auth_required")
    out = []
    for tpl in sorted(groups):
        g = groups[tpl]
        out.append({
            "path": tpl,
            "methods": sorted(g["methods"]),
            "params": [{"name": n, "in": g["params"][n]} for n in sorted(g["params"])],
            "count": g["count"],
            "auth_required": g["auth_required"],
        })
    return out


def _merge_form_fields(obs: Dict[str, Any], endpoints: List[Dict[str, Any]]) -> None:
    """把观测到的表单字段并入端点参数（原地修改）。

    表单是"参数"最可靠的观测来源（比 URL query 更全）。两种情形：
      * 已有同 (method, 路径模板) 端点 → 补字段
      * 没有（爬虫只见过 GET 页面，提交口其实是 POST）→ **按表单观测新建**该端点
        （表单本身是观测事实，不是幻觉）
    """
    forms = obs.get("forms") if isinstance(obs, dict) else None
    if not isinstance(forms, (list, tuple)) or not forms:
        return
    by_pm = {(e["method"], path_template(e["path"])): e for e in endpoints}
    by_id = {e["id"] for e in endpoints}

    def _fill(target: Dict[str, Any], fields: Sequence[Any]) -> None:
        have = {p["name"] for p in target["params"]}
        for fld in fields:
            name = str(fld or "")
            if not name or name in have:
                continue
            have.add(name)
            # 表单字段只有"名字"这一项观测（没有取值样本）→ 同样不给值域
            target["params"].append({"name": name, "in": "body", "required": True,
                                     "domain": None})
        target["params"].sort(key=lambda x: x["name"])

    for f in forms:
        if not isinstance(f, dict):
            continue
        action = str(f.get("action") or "")
        if not action:
            continue
        method = str(f.get("method") or "POST").upper()
        tpl = path_template(action)
        target = by_pm.get((method, tpl))
        if target is not None:
            _fill(target, f.get("fields") or [])
            continue
        new_id = f"{method.lower()}:{action}"
        if new_id in by_id:
            continue
        ent = _entity_of(action)
        created: Dict[str, Any] = {
            "id": new_id, "method": method, "path": action, "params": [],
            "auth": {"required": False, "role": None},
            "effects": [{"entity": ent, "op": "write"}] if ent else [],
            "idempotent": method in ("GET", "HEAD", "OPTIONS"),
        }
        _fill(created, f.get("fields") or [])
        endpoints.append(created)
        by_pm[(method, tpl)] = created
        by_id.add(new_id)


def _entity_of(path: str) -> str:
    """从路径推实体名：/api/orders/123/pay → orders。取第一个非 api/版本段的路径段。"""
    segs = [s for s in str(path or "").split("/") if s and not _SEG_ID_RE.match(s)]
    skip = {"api", "v1", "v2", "v3", "rest", "www"}
    for s in segs:
        if s.lower() not in skip:
            return s.lower()
    return ""


def build_ir_skeleton(obs: Dict[str, Any], target: str = "") -> Dict[str, Any]:
    """观测 → 确定性 IR 骨架（无 LLM）。产出可被 llm_extractor 增强，也可单独使用。"""
    from .schema import IR_VERSION, empty_ir

    obs = obs if isinstance(obs, dict) else {}
    ir = empty_ir(str(target or obs.get("target") or ""))
    ir["version"] = IR_VERSION
    ir["confidence"] = 0.3
    src_kinds = {str(s.get("kind")) for s in (obs.get("sources") or []) if isinstance(s, dict)}
    ir["sources"] = [{"kind": k, "ref": k} for k in sorted(src_kinds)] or \
                    [{"kind": "recon_brief", "ref": "alive_assets/crawled_endpoints"}]

    entities: Dict[str, Dict[str, Any]] = {}
    endpoints = []
    for ep in (obs.get("endpoints") or []):
        if not isinstance(ep, dict):
            continue
        path = str(ep.get("path") or "/")
        method = str(ep.get("method") or "GET").upper()
        params = []
        for p in (ep.get("params") or []):
            if not isinstance(p, dict) or not p.get("name"):
                continue
            name = str(p["name"])
            samples = p.get("samples")
            dom = infer_domain([_coerce_value(s) for s in samples]) \
                if isinstance(samples, (list, tuple)) and samples else None
            params.append({
                "name": name,
                "in": p.get("in") or guess_param_in(name, method),
                "required": False,
                # 无观测样本 → 不给值域（**绝不凭参数名臆造**）：A1 会据此判 undecidable，
                # 避免"role 是 int → 那 role=1 一定可行"这类空洞推断变成批量误报。
                "domain": dom,
            })
        params.sort(key=lambda x: x["name"])

        effects = []
        if method in _WRITE_METHODS:
            ent = _entity_of(path)
            if ent:
                effects.append({"entity": ent, "op": "write"})
                entities.setdefault(ent, {"name": ent, "key": "id", "fields": []})
                for p in params:
                    entities[ent]["fields"].append(
                        {"name": p["name"], "type": p["domain"]["kind"], "domain": p["domain"]})
        elif _entity_of(path):
            entities.setdefault(_entity_of(path), {"name": _entity_of(path),
                                                   "key": "id", "fields": []})

        auth_required = ep.get("auth_required")
        endpoints.append({
            "id": f"{method.lower()}:{path}",
            "method": method,
            "path": path,
            "params": params,
            "auth": {"required": bool(auth_required) if auth_required is not None else False,
                     "role": None},
            "effects": effects,
            "idempotent": method in ("GET", "HEAD", "OPTIONS"),
        })

    _merge_form_fields(obs, endpoints)
    ir["endpoints"] = endpoints
    ir["entities"] = [{"name": entities[k]["name"], "key": "id", "fields": entities[k]["fields"]}
                      for k in sorted(entities)]

    # transitions：仅用"步骤类关键词"的端点做粗序（精确 pre/post 交 LLM）
    steps = [(i, e) for i, e in enumerate(endpoints)
             if any(w in e["path"].lower() for w in _STEP_WORDS)]
    transitions = []
    for (i, a), (j, b) in zip(steps, steps[1:]):
        transitions.append({
            "from_state": path_template(a["path"]),
            "to_state": path_template(b["path"]),
            "via_endpoint": b["id"],
            "preconditions": [f"visited:{path_template(a['path'])}"],
            "postconditions": [f"visited:{path_template(b['path'])}"],
        })
    ir["transitions"] = transitions
    return ir
