# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/attack_graph.py
"""E1 攻击图与路径可视化：统一图模型 + 攻击路径计算。

- E1.1  资产-漏洞-利用链统一图模型（networkx 起步，可换 neo4j）
- E1.2  攻击路径计算：起点（外部面）-> 终点（RCE/数据）加权最短路径与概率
- E1.4  ExploitChain 复用同一图模型（from_chains / 构建接口）

节点类型：
  asset   资产（URL / 域名 / IP）
  vuln    漏洞（来自 scan findings）
  gate    前置条件门（利用前提，如"需认证" "需用户交互"）

边类型：
  asset -> vuln   expose  资产承载漏洞
  vuln  -> gate   requires 漏洞利用需先满足前置条件
  gate  -> vuln   enables  条件满足后可发动下一步利用
  vuln  -> vuln   cascade 级联利用（LFI -> 日志投毒 -> RCE）

边属性：weight（利用代价，severity 折算）、prob（成功率，来自 confidence）、label。
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

import networkx as nx
from networkx.readwrite import json_graph

from vulnclaw.core.logger import logger

# severity -> 边权重（代价）。权重越低路径成本越低，dijkstra 按此寻优。
_SEVERITY_WEIGHT: Dict[str, int] = {
    "critical": 25,
    "high": 18,
    "medium": 12,
    "low": 6,
    "info": 3,
}

# 终点（sink）漏洞关键词：RCE / 数据读取类。命中则视为可被攻击路径达到的目标。
_TARGET_KEYWORDS = (
    "rce", "remote code", "command injection", "sqli", "sql injection",
    "arbitrary file", "file read", "file download", "leak",
    "ssrf", "deserialization", "shell", "upload", "metadata", "idor",
)

# 级联利用规则：(源漏洞 type 包含, (目标漏洞 type 包含, ...))
_CASCADE_RULES = (
    ("lfi", ("rce", "remote code", "command", "shell")),
    ("file upload", ("rce", "shell")),
    ("sqli", ("data", "sql", "read", "leak")),
    ("ssrf", ("file read", "arbitrary file", "metadata", "rce")),
    ("deserialization", ("rce",)),
    ("auth bypass", ("rce", "admin", "data")),
    ("xss", ("csrf", "account takeover")),
    ("open redirect", ("xss", "csrf", "phishing")),
)

# confidence -> 成功概率（路径概率由边概率连乘）
def _confidence_prob(confidence: Any) -> float:
    """把各种 confidence 表示折算为成功概率。"""
    if confidence is None:
        return 0.5
    if isinstance(confidence, (int, float)):
        if confidence >= 100:
            return 0.95
        if confidence >= 90:
            return 0.9
        if confidence >= 60:
            return 0.7
        return 0.35
    s = str(confidence).split("（")[0].split(" (")[0].strip().lower()
    if s in ("高", "high"):
        return 0.95
    if s.startswith("中") or s == "medium":
        return 0.7
    if s in ("低", "low"):
        return 0.35
    return 0.5


# ---- 级联边概率校准（数据飞轮接线，2026-09-14）----
_LEDGER_TYPE_STAT: Optional[Dict[str, Dict[str, int]]] = None


def _cascade_observed_prob(src_kw: str, default: float = 0.5) -> float:
    """级联边概率校准：用经验账本里同源类型的观察命中率修正硬编码概率。

    依据：feedback_ledger 中 verdict=confirm 的经验 = "该类型 payload 真实打中过"；
    源类型命中率越高，其级联边成功概率越应上调（0.7*base + 0.3*observed）。
    样本不足（<10）或账本不可用 → 原样返回 default（零行为回归）。
    """
    global _LEDGER_TYPE_STAT
    try:
        if _LEDGER_TYPE_STAT is None:
            from vulnclaw.growth.feedback_ledger import get_feedback_ledger
            stat: Dict[str, Dict[str, int]] = {}
            for r in get_feedback_ledger().rows():
                if str(r.get("kind")) != "finding":
                    continue
                t = str(r.get("vuln_type") or "").lower()
                if not t:
                    continue
                d = stat.setdefault(t, {"n": 0, "c": 0})
                d["n"] += 1
                if str(r.get("verdict") or "").lower() in (
                        "confirm", "confirmed", "fixed", "reconfirmed"):
                    d["c"] += 1
            _LEDGER_TYPE_STAT = stat
        n = c = 0
        for t, d in _LEDGER_TYPE_STAT.items():
            if src_kw in t:
                n += d["n"]
                c += d["c"]
        if n >= 10:
            observed = c / n
            return round(min(0.95, max(0.05, 0.7 * default + 0.3 * observed)), 4)
    except Exception:  # noqa: BLE001 - 校准是增强项，绝不影响图构建
        logger.debug("suppressed exception (cascade calibration)")
    return default


def _severity_weight(severity: Any) -> int:
    sev = str(severity or "low").strip().lower()
    return _SEVERITY_WEIGHT.get(sev, 6)


def _is_target_vuln(vuln_type: str) -> bool:
    t = str(vuln_type or "").lower()
    return any(k in t for k in _TARGET_KEYWORDS)


def _host_of(url: str) -> str:
    """提取 URL 的 host 部分，用于资产归组。"""
    from urllib.parse import urlparse
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url



def _graphml_val(val: Any) -> str:
    """GraphML data 值序列化：float 收敛到 4 位小数，其余原样字符串化。"""
    if isinstance(val, float):
        return repr(round(val, 4))
    return str(val)


class AttackGraph:
    """资产-漏洞-利用链统一图模型（E1.1 / E1.4 双端消费）。"""

    def __init__(self) -> None:
        self._g: nx.DiGraph = nx.DiGraph()

    # ---------- 构建 API ----------
    def add_node(self, node_id: str, kind: str, **meta: Any) -> None:
        """追加/更新节点。kind: asset | vuln | gate；node_id 必须全局唯一。"""
        if kind not in ("asset", "vuln", "gate"):
            raise ValueError(f"未知节点类型: {kind}")
        if self._g.has_node(node_id):
            self._g.nodes[node_id]["kind"] = kind
            self._g.nodes[node_id].update(meta)
            return
        self._g.add_node(node_id, kind=kind, **meta)

    def add_edge(
        self,
        src: str,
        dst: str,
        label: str = "expose",
        weight: Optional[int] = None,
        prob: Optional[float] = None,
    ) -> None:
        """追加有向边。weight 缺省按 src 节点 severity 折算；prob 缺省 0.5。"""
        data = {"label": label, "weight": weight, "prob": prob}
        if weight is None:
            severity = self._g.nodes.get(dst, {}).get("severity")
            data["weight"] = _severity_weight(severity)
        if prob is None:
            data["prob"] = 0.5
        if self._g.has_edge(src, dst):
            self._g.edges[src, dst].update(data)
            return
        self._g.add_edge(src, dst, **data)

    def add_vuln(self, finding: Dict) -> str:
        """由单条 finding 追加 vuln 节点，返回节点 id。"""
        fid = finding.get("finding_id") or f"{finding.get('url', '')}|{finding.get('type', '')}|{finding.get('parameter', '')}"
        prob = _confidence_prob(finding.get("confidence"))
        self.add_node(
            fid,
            kind="vuln",
            url=finding.get("url", ""),
            type=str(finding.get("type", "")),
            severity=str(finding.get("severity", "low")),
            parameter=finding.get("parameter", ""),
            verdict=finding.get("verdict", "suspicious"),
            confidence=finding.get("confidence", ""),
            prob=prob,
        )
        prev_host = _host_of(finding.get("url", ""))
        self.add_node(prev_host, kind="asset", url=prev_host)
        self.add_edge(prev_host, fid, label="expose", prob=prob)
        return fid

    def link_cascades(self) -> None:
        """基于级联规则给同资产内 vuln->vuln 连边（E1.2 路径素材）。"""
        vulns = [n for n, d in self._g.nodes(data=True) if d.get("kind") == "vuln"]
        for i, node_a in enumerate(vulns):
            meta_a = self._g.nodes[node_a]
            type_a = str(meta_a.get("type", "")).lower()
            for node_b in vulns[i + 1:]:
                type_b = str(self._g.nodes[node_b].get("type", "")).lower()
                if _host_of(meta_a.get("url", "")) != _host_of(self._g.nodes[node_b].get("url", "")):
                    continue
                for src_kw, dst_kws in _CASCADE_RULES:
                    # 概率由经验账本校准（同源类型观察命中率），账本不可用时退回 0.5
                    _p = _cascade_observed_prob(src_kw)
                    if src_kw in type_a and any(k in type_b for k in dst_kws):
                        self.add_edge(node_a, node_b, label="cascade", prob=_p)
                    if src_kw in type_b and any(k in type_a for k in dst_kws):
                        self.add_edge(node_b, node_a, label="cascade", prob=_p)

    def build_from_report(self, report: Dict) -> "AttackGraph":
        """从扫描报告构建攻击图（E1.1 主入口）。"""
        for asset in report.get("alive_assets", []) or []:
            if isinstance(asset, str):
                self.add_node(asset, kind="asset", url=asset, source="alive")
        for sub in report.get("subdomains", []) or []:
            self.add_node(str(sub), kind="asset", url=str(sub), source="subdomain")
        for finding in report.get("vulnerabilities", []) or []:
            self.add_vuln(finding)
        self.link_cascades()
        return self

    # ---------- E1.2 攻击路径 ----------
    def top_attack_paths(
        self,
        top_k: int = 5,
        min_prob: float = 0.0,
        max_depth: int = 6,
        strategy: str = "dijkstra",
        use_llm: bool = False,
    ) -> List[Dict]:
        """计算 TOP 攻击路径：外部面资产 -> RCE/数据类终点。

        strategy:
          - "dijkstra"（默认）：加权最短路（权重=severity 代价），零行为变化；
          - "mcts"：在 dijkstra 结果之外，用图上 MCTS（UCB1 + 随机 rollout）
            再产出若干候选，合并去重后**用同一套排序键**统一排序 ——
            dijkstra 的"单条最短路"局限（每个起终点对只出一条）由此补齐。

        use_llm: 仅对 mcts 生效 —— LLM 启发式给探索顺序做先验（不可用自动回退）。

        路径概率 = 各边概率连乘（保守估计：链路需逐跳成功），
        排序键 (路径条数, 总权重, 概率) 两种策略一致。
        """
        if self._g.number_of_nodes() == 0:
            return []
        starts, termini = self._starts_termini(self._g)
        if not termini:
            return []
        results = self._paths_on_graph(
            self._g, starts, termini, min_prob=min_prob, max_depth=max_depth)

        if str(strategy).lower() == "mcts":
            try:
                results.extend(self._mcts_paths(
                    starts, termini, max_depth=max_depth, use_llm=use_llm))
            except Exception as _e:  # noqa: BLE001 - MCTS 为增强项，失败退回 dijkstra 结果
                logger.debug(f"[MCTS] 攻击路径搜索失败（忽略）: {_e}")

        # 去重（按路径元组）后统一排序 —— 保证 mcts 与 dijkstra 结果同口径竞争
        seen = set()
        uniq: List[Dict] = []
        for r in results:
            k = tuple(r["path"])
            if k in seen:
                continue
            seen.add(k)
            uniq.append(r)
        uniq.sort(key=lambda r: (len(r["path"]), r["total_weight"], -r["probability"]))
        return uniq[:top_k]

    def _mcts_paths(
        self,
        starts: List[str],
        termini: List[str],
        max_depth: int = 6,
        simulations: int = 300,
        seed: int = 1337,
        top_n: int = 8,
        use_llm: bool = False,
    ) -> List[Dict]:
        """图上 MCTS（P3-②）：节点=图节点、动作=出边，UCB1 选择 + 随机 rollout + 收益回传。

        收益 = 路径概率连乘 × 终点严重度权重 / (1 + 总代价)，与 dijkstra 的
        "代价越低、概率越高越好"语义对齐。

        环防护（必须）：link_cascades 双向加边会造环，故每轮 rollout 带
        visited 集合 + max_depth 截断；固定 seed 保证结果可复现。

        use_llm（P3-② LLM 融合）：多个"未访问边"之间的探索顺序由 LLM 启发式
        先验决定（而非取图顺序第一个）—— 同样仿真预算下更快收敛到高价值路径。
        LLM 不可用（无 key/事件循环内/调用失败）自动回退纯 UCB1，行为与不启用一致。
        """
        import math
        import random as _random

        rng = _random.Random(seed)
        termini_set = set(termini)
        if not starts or not termini_set:
            return []

        visits: Dict[tuple, int] = {}
        rewards: Dict[tuple, float] = {}
        found: Dict[tuple, float] = {}
        c_ucb = 1.4
        llm_budget = {"used": 0, "max": 3}

        for _ in range(max(1, int(simulations))):
            cur = rng.choice(starts)
            path = [cur]
            visited = {cur}
            for _d in range(max(1, int(max_depth))):
                nbrs = [n for n in self._g.successors(cur) if n not in visited]
                if not nbrs:
                    break
                untried = [n for n in nbrs if visits.get((cur, n), 0) == 0]
                if untried:
                    # 未访问边优先探索；多个候选时用 LLM 先验排序（可用时；
                    # 不可用则取图顺序第一个 = 与原行为一致）
                    llm_scores = None
                    if use_llm:
                        llm_scores = self._llm_edge_scores(cur, untried, llm_budget)
                    _scores = llm_scores or {}
                    if _scores:
                        best = max(untried, key=lambda n: float(_scores.get(n, 0.0)))
                    else:
                        best = untried[0]
                else:
                    best, best_ucb = None, -1.0
                    total = max(1, sum(visits.values()))
                    for n in nbrs:
                        key = (cur, n)
                        n_i = visits.get(key, 0)
                        ucb = rewards.get(key, 0.0) / n_i + c_ucb * math.sqrt(math.log(1 + total) / n_i)
                        if ucb > best_ucb:
                            best, best_ucb = n, ucb
                if best is None:
                    break
                cur = best
                path.append(cur)
                visited.add(cur)
                if cur in termini_set:
                    break
            if len(path) < 2 or path[-1] not in termini_set:
                continue
            prob, weight = 1.0, 0
            for i in range(len(path) - 1):
                e = self._g.edges[path[i], path[i + 1]]
                weight += int(e.get("weight") or 5)
                prob *= float(e.get("prob") or 0.5)
            sev_w = float(_SEVERITY_WEIGHT.get(
                str(self._g.nodes[path[-1]].get("severity", "")).title(), 5))
            reward = prob * sev_w / (1.0 + weight)
            found.setdefault(tuple(path), reward)
            for i in range(len(path) - 1):
                key = (path[i], path[i + 1])
                visits[key] = visits.get(key, 0) + 1
                rewards[key] = rewards.get(key, 0.0) + reward

        out: List[Dict] = []
        for path, _reward in sorted(found.items(), key=lambda kv: -kv[1])[:max(1, int(top_n))]:
            prob, total_weight = 1.0, 0
            for i in range(len(path) - 1):
                e = self._g.edges[path[i], path[i + 1]]
                total_weight += int(e.get("weight") or 5)
                prob *= float(e.get("prob") or 0.5)
            sink = path[-1]
            sink_meta = self._g.nodes[sink]
            out.append({
                "path": list(path),
                "nodes": [{"id": n, "kind": self._g.nodes[n].get("kind"), "label": self._label_of(n)} for n in path],
                "total_weight": total_weight,
                "probability": round(prob, 4),
                "severity": sink_meta.get("severity", ""),
                "end_type": sink_meta.get("type", ""),
                "end_url": sink_meta.get("url", ""),
                "source": "mcts",
            })
        return out

    def _label_of(self, node_id: str) -> str:
        d = self._g.nodes[node_id]
        if d.get("kind") == "asset":
            return node_id
        if d.get("kind") == "vuln":
            vtype = str(d.get("type", ""))
            return f"{vtype}" if d.get("url") else vtype
        return str(d.get("label", node_id))

    # ---------- 内部：起终点与图副本路径枚举（供反事实分析复用） ----------
    def _starts_termini(self, g) -> tuple:
        termini = [n for n, d in g.nodes(data=True)
                   if d.get("kind") == "vuln" and _is_target_vuln(str(d.get("type", "")))]
        starts = [n for n, d in g.nodes(data=True)
                  if d.get("kind") == "asset" and g.in_degree(n) == 0] or \
                 [n for n, d in g.nodes(data=True) if d.get("kind") == "asset"]
        return starts, termini

    def _label_of_g(self, g, node_id: str) -> str:
        d = g.nodes[node_id]
        if d.get("kind") == "asset":
            return node_id
        if d.get("kind") == "vuln":
            vtype = str(d.get("type", ""))
            return f"{vtype}" if d.get("url") else vtype
        return str(d.get("label", node_id))

    def _paths_on_graph(
        self, g, starts: List[str], termini: List[str],
        min_prob: float = 0.0, max_depth: int = 6,
    ) -> List[Dict]:
        """在给定图（可为副本）上枚举 dijkstra 攻击路径（top_attack_paths 主体）。"""
        results: List[Dict] = []
        for start in starts:
            for sink in termini:
                if start == sink:
                    continue
                try:
                    path = nx.shortest_path(g, start, sink, weight="weight")
                except (nx.NetworkXNoPath, nx.NetworkXNoCycle):
                    continue
                if len(path) - 1 > max_depth:
                    continue
                prob = 1.0
                total_weight = 0
                for i in range(len(path) - 1):
                    e = g.edges[path[i], path[i + 1]]
                    edge_w = (e.get("weight") or 0) if (i == 0 and g.nodes[path[i]]["kind"] == "asset") \
                        else (e.get("weight") or 5)
                    edge_p = e.get("prob") or 0.5
                    total_weight += int(edge_w)
                    prob *= float(edge_p)
                if prob < min_prob:
                    continue
                sink_meta = g.nodes[sink]
                results.append({
                    "path": path,
                    "nodes": [{"id": n, "kind": g.nodes[n].get("kind"),
                               "label": self._label_of_g(g, n)} for n in path],
                    "total_weight": total_weight,
                    "probability": round(prob, 4),
                    "severity": sink_meta.get("severity", ""),
                    "end_type": sink_meta.get("type", ""),
                    "end_url": sink_meta.get("url", ""),
                })
        return results

    # ---------- P3-③ 反事实分析 ----------
    def counterfactual_impact(self, node_id: str, max_depth: int = 6) -> Dict:
        """反事实分析：移除某节点后攻击面如何变化（"修掉 X 能断掉哪些链"）。

        对图做**副本**（不改原图）后重新枚举路径，对比修复前后：
        - removed_chains：修复前可达、修复后不可达的路径（含完整路径样例）
        - risk_reduction：概率加权的风险降幅（1 - after/before）
        - critical：剩余风险 < 50% 即视为"关键节点"（单点修复大幅收缩攻击面）

        纯图算法、确定性输出、零 LLM 依赖 —— 报告侧可直接给出"修补优先级"。
        """
        out: Dict[str, Any] = {
            "removed_node": node_id, "found": False,
            "before_chains": 0, "after_chains": 0,
            "before_total_prob": 0.0, "after_total_prob": 0.0,
            "removed_chains": [], "risk_reduction": 0.0, "critical": False,
        }
        if self._g.number_of_nodes() == 0 or not self._g.has_node(node_id):
            return out
        starts, termini = self._starts_termini(self._g)
        if not termini:
            return out
        before = self._paths_on_graph(self._g, starts, termini, max_depth=max_depth)
        g2 = self._g.copy()
        try:
            g2.remove_node(node_id)
        except Exception:  # noqa: BLE001
            return out
        starts2, termini2 = self._starts_termini(g2)
        after = self._paths_on_graph(g2, starts2, termini2, max_depth=max_depth) if termini2 else []

        after_keys = {tuple(r["path"]) for r in after}
        before_map = {tuple(r["path"]): r for r in before}
        removed = [r for k, r in before_map.items() if k not in after_keys]
        before_total = sum(float(r["probability"]) for r in before_map.values())
        after_total = sum(float(r["probability"]) for r in after)
        out.update({
            "found": True,
            "before_chains": len(before_map), "after_chains": len(after),
            "before_total_prob": round(before_total, 4),
            "after_total_prob": round(after_total, 4),
            "removed_chains": removed[:20],
            "risk_reduction": round(1.0 - (after_total / before_total), 4) if before_total > 0 else 0.0,
        })
        out["critical"] = bool(removed) and before_total > 0 and (after_total / before_total) < 0.5
        return out

    # ---------- P3-② LLM 启发式（MCTS 先验） ----------
    def _llm_edge_scores(self, node_id: str, candidates: List[str], budget: Dict) -> Optional[Dict[str, float]]:
        """LLM 给"从 node 出发的候选边"打 0-1 先验分（引导 MCTS 探索顺序）。

        安全边界（任一不满足即返回 None，调用方回退纯 UCB1）：
        ① 事件循环内不调用（防 asyncio 嵌套）；② 每次搜索调用上限 budget["max"]；
        ③ 结果按 node 缓存；④ 解析失败/无客户端 → None。**永不抛异常**。
        """
        cache = getattr(self, "_llm_edge_cache", None)
        if cache is None:
            cache = self._llm_edge_cache = {}
        if node_id in cache:
            return cache[node_id]
        if int(budget.get("used", 0)) >= int(budget.get("max", 3)):
            return None
        try:
            import asyncio as _aio
            try:
                _aio.get_running_loop()
                return None  # 事件循环中：跳过（防 asyncio 嵌套）
            except RuntimeError:
                pass
            from vulnclaw.ai.core import get_llm_client
            client = get_llm_client()
            if client is None or not hasattr(client, "ask"):
                return None
            lines = []
            for n in candidates[:8]:
                d = self._g.nodes[n]
                lines.append(
                    f"- {n}: kind={d.get('kind')} type={d.get('type', '')} "
                    f"severity={d.get('severity', '')} url={str(d.get('url', ''))[:60]}")
            prompt = (
                "以下是攻击图中的一个节点及其出边候选。请给每个候选打 0-1 分"
                "（越高 = 越可能通向 RCE/数据泄露等高危终点），"
                "只输出 JSON 对象 {节点id: 分数}。\n"
                f"当前节点: {node_id}\n" + "\n".join(lines)
            )
            budget["used"] = int(budget.get("used", 0)) + 1
            resp = client.ask(
                prompt, system="你是攻击路径评估助手，只输出 JSON。",
                temperature=0.1, max_tokens=128, retries=1,
                usage_site="mcts-heuristic",
            )
            if isinstance(resp, dict):
                resp = resp.get("text") or resp.get("content") or resp.get("answer") or ""
            m = re.search(r"\{.*\}", str(resp or ""), re.S)
            if not m:
                return None
            raw = json.loads(m.group(0))
            scores = {
                str(k): max(0.0, min(1.0, float(v)))
                for k, v in (raw or {}).items()
                if isinstance(v, (int, float))
            }
            if not scores:
                return None
            cache[node_id] = scores
            return scores
        except Exception:  # noqa: BLE001
            return None

    # ---------- E1.4 ExploitChain 双端消费 ----------
    @classmethod
    def from_chains(cls, chains: List[Dict], target: str = "") -> "AttackGraph":
        """从 ExploitChain 利用结果构建攻击图（E1.4 消费端）。

        同一资产的成功利用按执行顺序串联为 vuln->vuln 边，末端挂 asset。
        """
        g = cls()
        if target:
            g.add_node(target, kind="asset", url=target, source="chain")
        for chain in chains or []:
            fid = chain.get("finding_id") or "exit"
            strategy = str(chain.get("strategy", "poc"))
            success = bool(chain.get("success"))
            url = str(chain.get("url") or chain.get("target") or target or "")
            prev = ""
            for hop in chain.get("chain") or [{"node": fid, "strategy": strategy}]:
                node = str(hop.get("node") or fid)
                kind = "vuln" if not node.startswith("gate:") else "gate"
                g.add_node(node, kind=kind, url=url, strategy=str(hop.get("strategy", "")), success=success)
                if prev:
                    g.add_edge(prev, node, label="cascade", prob=0.5 if success else 0.2)
                prev = node
                host = _host_of(url)
            if url:
                g.add_node(host, kind="asset", url=host, source="chain")
                g.add_edge(host, prev, label="expose", prob=0.5 if success else 0.2)
        return g

    # ---------- 导出 ----------
    def to_json(self) -> Dict:
        """node_link_data + 统计（E1.3 报告 React flow / D3 直接消费）。"""
        data = json_graph.node_link_data(self._g)
        if "links" in data and "edges" not in data:
            data["edges"] = data.pop("links")  # 兼容 networkx <3.5 的边键
        stats = {
            "nodes": self._g.number_of_nodes(),
            "edges": self._g.number_of_edges(),
            "assets": sum(1 for _, d in self._g.nodes(data=True) if d.get("kind") == "asset"),
            "vulns": sum(1 for _, d in self._g.nodes(data=True) if d.get("kind") == "vuln"),
            "gates": sum(1 for _, d in self._g.nodes(data=True) if d.get("kind") == "gate"),
        }
        data["stats"] = stats
        return data

    def to_graphml(self) -> str:
        """GraphML 文本导出（neo4j 导入 / 工具链交换用）。

        用标准库手写 XML：不依赖 networkx 的 GraphML writer——其 lxml 后端会
        懒加载 numpy，在 numpy<2.0 + Python 3.14 环境存在导入段错误。
        """
        root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
        # key 声明（id 全局唯一；node/edge 的 prob 分开声明为 k_prob / e_prob）
        key_specs = [
            ("k_kind", "node", "kind", "string"),
            ("k_url", "node", "url", "string"),
            ("k_type", "node", "type", "string"),
            ("k_severity", "node", "severity", "string"),
            ("k_param", "node", "parameter", "string"),
            ("k_verdict", "node", "verdict", "string"),
            ("k_confidence", "node", "confidence", "string"),
            ("k_source", "node", "source", "string"),
            ("k_strategy", "node", "strategy", "string"),
            ("k_success", "node", "success", "string"),
            ("k_prob", "node", "prob", "double"),
            ("e_label", "edge", "label", "string"),
            ("e_weight", "edge", "weight", "int"),
            ("e_prob", "edge", "prob", "double"),
        ]
        for kid, scope, name, dtype in key_specs:
            ET.SubElement(
                root, "key",
                attrib={"id": kid, "for": scope, "attr.name": name, "attr.type": dtype},
            )
        graph_el = ET.SubElement(root, "graph", id="G", edgedefault="directed")
        node_key_ids = {
            "kind": "k_kind", "url": "k_url", "type": "k_type",
            "severity": "k_severity", "parameter": "k_param",
            "verdict": "k_verdict", "confidence": "k_confidence",
            "source": "k_source", "strategy": "k_strategy",
            "success": "k_success",
        }
        for nid in self._g.nodes:
            node_el = ET.SubElement(graph_el, "node", id=str(nid))
            meta = self._g.nodes[nid]
            for name, kid in node_key_ids.items():
                val = meta.get(name)
                if val is None or val == "":
                    continue
                ET.SubElement(node_el, "data", key=kid).text = _graphml_val(val)
            nprob = meta.get("prob")
            if nprob is not None:
                ET.SubElement(node_el, "data", key="k_prob").text = _graphml_val(nprob)
        for src, dst, meta in self._g.edges(data=True):
            edge_el = ET.SubElement(graph_el, "edge", source=str(src), target=str(dst))
            label = meta.get("label")
            if label:
                ET.SubElement(edge_el, "data", key="e_label").text = str(label)
            weight = meta.get("weight")
            if weight is not None:
                ET.SubElement(edge_el, "data", key="e_weight").text = str(int(weight))
            prob = meta.get("prob")
            if prob is not None:
                ET.SubElement(edge_el, "data", key="e_prob").text = _graphml_val(prob)
        ET.indent(root)  # 可读性；Python 3.9+
        body = ET.tostring(root, encoding="unicode")
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + body

    def dump(self) -> Dict:
        """调试/持久化用：纯 dict 结构。"""
        return self.to_json()

    @property
    def graph(self) -> nx.DiGraph:
        return self._g


__all__ = ["AttackGraph"]