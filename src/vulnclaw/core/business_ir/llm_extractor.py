# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/business_ir/llm_extractor.py
"""LLM 逆向增强 —— 在确定性骨架上补"只有语义理解才能得到"的部分。

LLM 只做四件事（其余一律不允许，防止幻觉污染 A1 的判定输入）：
  1. 给**已观测到**的参数补类型/值域与业务含义
  2. 补业务不变量（`expr: {coeffs, const}`，形如 `total - 100*qty == 0`）
  3. 补攻击目标谓词（goals）
  4. 补转移的前置/后置条件（transitions pre/postconditions）

**硬约束**：LLM 不得新增"没被观测到"的端点/参数（`merge_fragment` 会丢弃并计数）。
失败降级：LLM 不可用 / 超时 / 返回非法 JSON / 打了补丁仍不合法 → 原样返回骨架，
**绝不抛异常、绝不阻塞主流程**。
"""
import asyncio
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger

__all__ = [
    "IR_SYSTEM",
    "build_ir_prompt",
    "extract_json",
    "merge_fragment",
    "extract_ir_fragment",
    "refine_ir",
]

IR_SYSTEM = (
    "你是 Web 业务逻辑逆向分析器。输入是目标站点的观测（端点/参数/表单）与一份确定性骨架 IR。"
    "你的任务是**补充语义**，不是发明事实：\n"
    "1) 只允许对已给出的端点/参数做增强，禁止新增未观测到的端点或参数；\n"
    "2) 业务不变量用线性表达式表示：{\"coeffs\": {\"变量名\": 整数系数}, \"const\": 整数}，"
    "语义为 coeffs·vars + const == 0（例：total == 100*qty → {\"coeffs\":{\"total\":1,\"qty\":-100},\"const\":0}）；\n"
    "3) 只输出 JSON，不要解释文字、不要 markdown 代码块。"
)

_MAX_OBS_CHARS = 4000
_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def extract_json(text: Any) -> Optional[Dict[str, Any]]:
    """从模型输出里抠 JSON（容错：裸 JSON / ```json 包裹 / 前后有解释文字）。"""
    if isinstance(text, dict):
        return text
    if not isinstance(text, str) or not text.strip():
        return None
    raw = text.strip()
    try:
        got = json.loads(raw)
        return got if isinstance(got, dict) else None
    except (json.JSONDecodeError, ValueError):
        pass
    cleaned = re.sub(r"```(?:json)?", "", raw).replace("```", "")
    m = _JSON_RE.search(cleaned)
    if not m:
        return None
    try:
        got = json.loads(m.group(0))
        return got if isinstance(got, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def build_ir_prompt(obs: Dict[str, Any], skeleton: Dict[str, Any]) -> str:
    """构造提示：只喂端点/参数/表单摘要（控制 token），不喂整页 HTML。"""
    obs = obs if isinstance(obs, dict) else {}
    eps = []
    for e in (obs.get("endpoints") or [])[:60]:
        if not isinstance(e, dict):
            continue
        eps.append({
            "method": e.get("method"), "path": e.get("path"),
            "params": [p.get("name") for p in (e.get("params") or []) if isinstance(p, dict)],
            "status": e.get("status"),
            "auth_required": e.get("auth_required"),
        })
    forms = [{"action": f.get("action"), "method": f.get("method"), "fields": f.get("fields")}
             for f in (obs.get("forms") or [])[:10] if isinstance(f, dict)]
    payload = {
        "target": obs.get("target", ""),
        "tech_stack": (obs.get("tech_stack") or [])[:10],
        "endpoints": eps,
        "forms": forms,
        "skeleton_entities": [e.get("name") for e in (skeleton.get("entities") or [])
                              if isinstance(e, dict)][:20],
    }
    body = json.dumps(payload, ensure_ascii=False, indent=1)[:_MAX_OBS_CHARS]
    return (
        "以下是观测与骨架 IR。请输出 JSON，字段（都可选，缺省表示不改）：\n"
        "{\n"
        '  "endpoints": [{"id"|"path": "...", "auth_role": "user|admin|owner|null",\n'
        '                 "params": [{"name": "...", "kind": "int|float|enum|str|bool",\n'
        '                             "domain": {...}, "meaning": "业务含义"}]}],\n'
        '  "invariants": [{"id": "inv_x", "expr": {"coeffs": {"a": 1, "b": -100}, "const": 0},\n'
        '                  "kind": "arithmetic", "confidence": 0.6}],\n'
        '  "goals": [{"id": "g_admin", "desc": "...", "requires_facts": ["role=admin"]}],\n'
        '  "transitions": [{"via_endpoint": "端点id", "from_state": "...", "to_state": "...",\n'
        '                   "preconditions": [...], "postconditions": [...]}]\n'
        "}\n"
        "约束：不得新增未观测到的端点/参数；不变量只允许线性（系数为整数）。\n\n"
        f"观测与骨架：\n{body}"
    )


def _num(v: Any) -> Optional[int]:
    try:
        if isinstance(v, bool):
            return None
        return int(v)
    except (TypeError, ValueError):
        return None


def merge_fragment(skeleton: Dict[str, Any], frag: Optional[Dict[str, Any]]) -> Tuple[Dict[str, Any], int, int]:
    """把 LLM 片段并入骨架。返回 (ir, 采纳数, 丢弃数)。

    只增强已存在的端点/参数；`invariants`/`goals`/`transitions` 允许新增但必须合法。
    """
    if not isinstance(skeleton, dict) or not isinstance(frag, dict):
        return skeleton, 0, 0
    ir = json.loads(json.dumps(skeleton))       # 深拷贝，避免污染调用方
    _eps = [e for e in (ir.get("endpoints") or []) if isinstance(e, dict)]
    eps = {e.get("id"): e for e in _eps}
    by_pm = {(str(e.get("method") or "").upper(), e.get("path")): e for e in _eps}
    by_path: Dict[Any, Dict[str, Any]] = {}
    for e in _eps:                              # 同路径多方法时保留先到者（确定性）
        by_path.setdefault(e.get("path"), e)
    adopted = dropped = 0

    for f in (frag.get("endpoints") or []):
        if not isinstance(f, dict):
            continue
        # 匹配优先级：id → (method, path) → path（LLM 常只给 path，且同路径多方法时必须靠 method 区分）
        tgt = eps.get(str(f.get("id") or ""))
        if tgt is None and f.get("path"):
            fm = str(f.get("method") or "").upper()
            if fm:
                tgt = by_pm.get((fm, f.get("path")))
            tgt = tgt or by_path.get(f.get("path"))
        if tgt is None:
            dropped += 1                        # 幻觉端点：丢弃（不新增）
            continue
        adopted += 1
        role = f.get("auth_role")
        if role in ("anonymous", "user", "admin", "owner"):
            tgt.setdefault("auth", {})["role"] = role
            tgt["auth"]["required"] = role != "anonymous"
        known = {p.get("name"): p for p in (tgt.get("params") or []) if isinstance(p, dict)}
        for p in (f.get("params") or []):
            if not isinstance(p, dict):
                continue
            cur = known.get(str(p.get("name") or ""))
            if cur is None:
                dropped += 1                    # 未观测参数：丢弃
                continue
            dom = p.get("domain")
            if isinstance(dom, dict) and dom.get("kind") in ("int", "float", "enum", "str", "bool"):
                cur["domain"] = dom
            if p.get("meaning"):
                cur["meaning"] = str(p["meaning"])[:120]

    invs = [i for i in (ir.get("invariants") or []) if isinstance(i, dict)]
    have_inv = {str(i.get("id")) for i in invs}
    for i in (frag.get("invariants") or []):
        if not isinstance(i, dict) or not i.get("id"):
            continue
        expr = i.get("expr")
        if not isinstance(expr, dict) or not isinstance(expr.get("coeffs"), dict):
            dropped += 1
            continue
        coeffs = {}
        bad = False
        for k, v in expr["coeffs"].items():
            n = _num(v)
            if n is None:
                bad = True
                break
            if n:
                coeffs[str(k)] = n
        if bad or not coeffs:
            dropped += 1
            continue
        iid = str(i["id"])
        entry = {"id": iid, "expr": {"coeffs": coeffs, "const": _num(expr.get("const")) or 0},
                 "kind": str(i.get("kind") or "arithmetic"),
                 "confidence": float(i.get("confidence", 0.5) or 0.0)}
        if iid in have_inv:
            invs = [entry if str(x.get("id")) == iid else x for x in invs]
        else:
            invs.append(entry)
        adopted += 1
    ir["invariants"] = invs

    goals = [g for g in (ir.get("goals") or []) if isinstance(g, dict)]
    have_goal = {str(g.get("id")) for g in goals}
    for g in (frag.get("goals") or []):
        if not isinstance(g, dict) or not g.get("id"):
            continue
        gid = str(g["id"])
        entry = {"id": gid, "desc": str(g.get("desc") or ""),
                 "requires_facts": sorted(str(x) for x in (g.get("requires_facts") or [])),
                 "predicate": g.get("predicate") if isinstance(g.get("predicate"), dict) else None}
        if gid in have_goal:
            goals = [entry if str(x.get("id")) == gid else x for x in goals]
        else:
            goals.append(entry)
        adopted += 1
    ir["goals"] = goals

    trs = [t for t in (ir.get("transitions") or []) if isinstance(t, dict)]
    ep_ids = {str(e.get("id")) for e in (ir.get("endpoints") or []) if isinstance(e, dict)}
    for t in (frag.get("transitions") or []):
        if not isinstance(t, dict):
            continue
        via = str(t.get("via_endpoint") or "")
        if via and ep_ids and via not in ep_ids:
            dropped += 1                        # 悬空引用：丢弃
            continue
        trs.append({
            "from_state": str(t.get("from_state") or ""),
            "to_state": str(t.get("to_state") or ""),
            "via_endpoint": via,
            "preconditions": [str(x) for x in (t.get("preconditions") or [])],
            "postconditions": [str(x) for x in (t.get("postconditions") or [])],
        })
        adopted += 1
    ir["transitions"] = trs

    if adopted:
        try:
            ir["confidence"] = round(max(float(ir.get("confidence") or 0.0), 0.6), 4)
        except (TypeError, ValueError):
            ir["confidence"] = 0.6
        srcs = {(s.get("kind"), s.get("ref")) for s in (ir.get("sources") or [])
                if isinstance(s, dict)}
        srcs.add(("llm", "business_ir"))
        ir["sources"] = [{"kind": k, "ref": r} for k, r in sorted(srcs) if k]
    return ir, adopted, dropped


async def extract_ir_fragment(obs: Dict[str, Any], skeleton: Dict[str, Any],
                              *, client: Any = None, timeout: float = 60.0
                              ) -> Optional[Dict[str, Any]]:
    """调 LLM 拿片段；任何失败 → None（调用方据此保底用骨架）。"""
    try:
        if client is None:
            from vulnclaw.ai.core import get_llm_client

            client = get_llm_client()
        if client is None:
            return None
        prompt = build_ir_prompt(obs, skeleton)
        resp = await asyncio.wait_for(
            client.ask(
                prompt,
                system=IR_SYSTEM,
                temperature=0.1,
                max_tokens=1500,
                retries=1,
                force_json=True,
                usage_site="business_ir",
            ),
            timeout=max(1.0, float(timeout)),
        )
        return extract_json(resp)
    except asyncio.TimeoutError:
        logger.info("🧩 [IR] LLM 增强超时，降级为确定性骨架")
        return None
    except Exception as exc:  # noqa: BLE001 - LLM 失败绝不影响主流程
        logger.debug(f"🧩 [IR] LLM 增强失败（降级）: {exc}")
        return None


async def refine_ir(obs: Dict[str, Any], skeleton: Dict[str, Any],
                    *, client: Any = None, timeout: float = 60.0,
                    enabled: bool = True) -> Dict[str, Any]:
    """骨架 → LLM 增强 → 合并。**永不抛异常**；LLM 不可用时原样返回骨架。"""
    if not enabled:
        return skeleton
    frag = await extract_ir_fragment(obs, skeleton, client=client, timeout=timeout)
    if not frag:
        return skeleton
    ir, adopted, dropped = merge_fragment(skeleton, frag)
    logger.info(f"🧩 [IR] LLM 增强：采纳 {adopted} 项，丢弃 {dropped} 项（未观测/非法）")
    return ir
