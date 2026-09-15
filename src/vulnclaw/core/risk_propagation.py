# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/risk_propagation.py
"""风险传播模型（E1.5）：把攻击图上"已确认漏洞"沿利用/级联边扩散为资产风险评分。

存在意义
--------
攻击图（``core.attack_graph``）回答"怎么打进去"（路径），本模块回答"**打进去之后
影响面多大**"：从漏洞节点出发，按边概率与严重度做**衰减扩散**，产出

- 节点级风险分（**最强传播路径**，可回溯父链 → 可解释）
- 资产级风险分（该资产全部漏洞分**求和**，体现总暴露面）
- top-N 资产排行 + 每个高分的传播来源链

设计铁律
--------
1. **确定性**：零随机、零时间戳、按节点 id 排序遍历；同一图多次调用结果**逐字节一致**
   （可直接做 JSON 比对，禁用 set/dict 哈希序）。
2. **可解释**：不使用黑盒聚合——节点分保留 ``parent`` 指针，任何高分都能回溯到种子漏洞。
3. **只读**：只消费 ``AttackGraph``（``.graph()`` 取 ``nx.DiGraph``），不修改图、不联网、不调 AI。
4. **口径显式**：种子分 = severity 权重 × confidence 概率；跨边传播 = 上游分 × 边概率 × 衰减。
   ``confirmed_only`` 严格只取已确认漏洞（无则返回空并给出 note，**绝不**用可疑项冒充）。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

#: severity → 种子基分（与 attack_graph._SEVERITY_WEIGHT 同口径量级）
_SEVERITY_SCORE: Dict[str, float] = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 1.0,
}

#: 视为"已确认"的 verdict（与 finding_schema 状态机对齐；大小写不敏感）
_CONFIRMED_VERDICTS = {
    "verified", "confirmed", "true_positive", "tp", "oob_confirmed",
}

_MAX_SCORE = 100.0


def _severity_score(severity: Any) -> float:
    return _SEVERITY_SCORE.get(str(severity or "low").strip().lower(), 2.0)


def _seed_score(meta: Dict[str, Any]) -> float:
    """种子分 = severity 权重 × confidence 概率（概率缺省 0.5）。"""
    prob = meta.get("prob")
    try:
        prob = float(prob) if prob is not None else 0.5
    except (TypeError, ValueError):
        prob = 0.5
    prob = min(max(prob, 0.0), 1.0)
    return round(_severity_score(meta.get("severity")) * prob, 4)


def _is_confirmed(meta: Dict[str, Any]) -> bool:
    return str(meta.get("verdict", "")).strip().lower() in _CONFIRMED_VERDICTS


def propagate_risk(
    graph,
    *,
    decay: float = 0.6,
    max_depth: int = 6,
    confirmed_only: bool = False,
    top_k: int = 10,
) -> Dict[str, Any]:
    """在攻击图上做风险传播（确定性纯计算）。

    Args:
        graph: ``AttackGraph`` 实例（须实现 ``.graph() -> nx.DiGraph``）。
        decay: 每跳衰减系数（0-1，越小影响面收敛越快）。
        max_depth: 最大传播跳数。
        confirmed_only: True 时种子只取已确认漏洞（verdict 命中 ``_CONFIRMED_VERDICTS``）；
            无已确认漏洞则返回空结果 + note，绝不降级用可疑项顶替。
        top_k: top 资产/来源列表长度。

    Returns:
        ``{"params", "sources", "node_scores", "asset_scores", "top_assets", "note"}``
        全部浮点已 ``round(..., 4)``，可直接 JSON 序列化做字节级比对。
    """
    # 解析入参（顺序很关键）：nx.DiGraph **自带** ``.graph`` 属性（graph attribute dict），
    # 因此绝不能先 getattr("graph") 兜底——那会拿到空 dict 导致后续 AttributeError
    # （报告链路接线实测踩坑）。先按 networkx 图接口特征判定，再走 AttackGraph 的 property。
    if hasattr(graph, "is_directed"):  # networkx 图接口特征
        g = graph
    else:
        _raw = getattr(graph, "graph", graph)
        g = _raw() if callable(_raw) else _raw

    # ---------- 1. 种子：漏洞节点 ----------
    sources: List[Tuple[str, float]] = []
    for nid in sorted(g.nodes()):
        meta = g.nodes[nid]
        if meta.get("kind") != "vuln":
            continue
        if confirmed_only and not _is_confirmed(meta):
            continue
        s = _seed_score(meta)
        if s > 0:
            sources.append((nid, s))

    note = ""
    if not sources:
        note = (
            "图中无已确认漏洞节点（confirmed_only=True）"
            if confirmed_only
            else "图中无漏洞节点或全部种子分为 0"
        )
        return {
            "params": {"decay": decay, "max_depth": max_depth, "confirmed_only": confirmed_only},
            "sources": [], "node_scores": {}, "asset_scores": {}, "top_assets": [], "note": note,
        }

    # ---------- 2. 传播：取"最强路径"（可回溯），逐轮推进 ----------
    score: Dict[str, float] = {nid: s for nid, s in sources}
    parent: Dict[str, Optional[str]] = {nid: None for nid, _ in sources}
    depth: Dict[str, int] = {nid: 0 for nid, _ in sources}

    frontier = [nid for nid, _ in sources]
    for _ in range(max(0, int(max_depth))):
        nxt: List[str] = []
        for u in sorted(frontier):
            for v in sorted(g.successors(u)):
                if g.nodes[v].get("kind") == "asset":
                    continue  # 资产分在聚合阶段算，不做点对点传播
                edge = g.edges[u, v]
                try:
                    prob = float(edge.get("prob") if edge.get("prob") is not None else 0.5)
                except (TypeError, ValueError):
                    prob = 0.5
                cand = round(score[u] * min(max(prob, 0.0), 1.0) * decay, 4)
                if cand > score.get(v, 0.0) + 1e-9:
                    score[v] = cand
                    parent[v] = u
                    depth[v] = depth.get(u, 0) + 1
                    nxt.append(v)
        if not nxt:
            break
        frontier = nxt

    # ---------- 3. 资产聚合：资产分 = Σ(其后继 vuln 分) + 自身被传播分（上限 100） ----------
    asset_scores: Dict[str, float] = {}
    for nid in sorted(g.nodes()):
        if g.nodes[nid].get("kind") != "asset":
            continue
        total = 0.0
        for v in sorted(g.successors(nid)):
            if g.nodes[v].get("kind") == "vuln":
                total += score.get(v, 0.0)
        total += score.get(nid, 0.0)
        if total > 0:
            asset_scores[nid] = round(min(total, _MAX_SCORE), 4)

    # ---------- 4. top 资产 + 传播来源链（回溯 parent） ----------
    def _path_to(nid: str) -> List[str]:
        chain: List[str] = []
        cur: Optional[str] = nid
        seen = set()
        while cur is not None and cur not in seen:
            seen.add(cur)
            chain.append(cur)
            cur = parent.get(cur)
        return list(reversed(chain))

    top_assets: List[Dict[str, Any]] = []
    for asset in sorted(asset_scores, key=lambda a: (-asset_scores[a], a))[: max(0, int(top_k))]:
        best_vuln = ""
        best_score = -1.0
        for v in sorted(g.successors(asset)):
            if g.nodes[v].get("kind") == "vuln" and score.get(v, 0.0) > best_score:
                best_vuln, best_score = v, score.get(v, 0.0)
        meta = g.nodes.get(best_vuln, {}) if best_vuln else {}
        top_assets.append({
            "asset": asset,
            "score": asset_scores[asset],
            "top_vuln": best_vuln,
            "top_vuln_score": round(max(best_score, 0.0), 4),
            "severity": str(meta.get("severity", "")),
            "type": str(meta.get("type", "")),
            "path": _path_to(best_vuln) if best_vuln else [],
        })

    sources_out = [
        {
            "node": nid,
            "score": round(s, 4),
            "severity": str(g.nodes[nid].get("severity", "")),
            "type": str(g.nodes[nid].get("type", "")),
        }
        for nid, s in sorted(sources, key=lambda kv: kv[0])
    ]

    return {
        "params": {"decay": decay, "max_depth": max_depth, "confirmed_only": confirmed_only},
        "sources": sources_out[: max(0, int(top_k))],
        "node_scores": {k: round(v, 4) for k, v in sorted(score.items())},
        "asset_scores": {k: asset_scores[k] for k in sorted(asset_scores)},
        "top_assets": top_assets,
        "note": note,
    }


def propagate_from_report(report: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
    """便捷入口：从扫描报告 dict 直接构建攻击图并传播（离线、确定性）。"""
    from vulnclaw.core.attack_graph import AttackGraph

    graph = AttackGraph().build_from_report(report or {})
    return propagate_risk(graph, **kwargs)


__all__ = ["propagate_risk", "propagate_from_report"]
