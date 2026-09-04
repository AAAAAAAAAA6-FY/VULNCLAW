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
                    if src_kw in type_a and any(k in type_b for k in dst_kws):
                        self.add_edge(node_a, node_b, label="cascade", prob=0.5)
                    if src_kw in type_b and any(k in type_a for k in dst_kws):
                        self.add_edge(node_b, node_a, label="cascade", prob=0.5)

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
    ) -> List[Dict]:
        """计算 TOP 攻击路径：外部面资产 -> RCE/数据类终点。

        使用加权最短路（dijkstra，权重=severity 代价），路径概率 = 各边概率连乘
        （保守估计：链路需逐跳成功），按 (路径条数, 总权重, 概率) 排序截取 top_k。
        """
        if self._g.number_of_nodes() == 0:
            return []
        termini = [n for n, d in self._g.nodes(data=True) if d.get("kind") == "vuln" and _is_target_vuln(str(d.get("type", "")))]
        if not termini:
            return []
        starts = [n for n, d in self._g.nodes(data=True) if d.get("kind") == "asset" and self._g.in_degree(n) == 0] or \
                 [n for n, d in self._g.nodes(data=True) if d.get("kind") == "asset"]

        results: List[Dict] = []
        for start in starts:
            for sink in termini:
                if start == sink:
                    continue
                try:
                    path = nx.shortest_path(self._g, start, sink, weight="weight")
                except (nx.NetworkXNoPath, nx.NetworkXNoCycle):
                    continue
                if len(path) - 1 > max_depth:
                    continue
                prob = 1.0
                total_weight = 0
                for i in range(len(path) - 1):
                    if i == 0 and self._g.nodes[path[i]]["kind"] == "asset":
                        edge_w = self._g.edges[path[i], path[i + 1]].get("weight") or 0
                        edge_p = self._g.edges[path[i], path[i + 1]].get("prob") or 0.5
                    else:
                        edge_w = self._g.edges[path[i], path[i + 1]].get("weight") or 5
                        edge_p = self._g.edges[path[i], path[i + 1]].get("prob") or 0.5
                    total_weight += int(edge_w)
                    prob *= float(edge_p)
                if prob < min_prob:
                    continue
                sink_meta = self._g.nodes[sink]
                results.append({
                    "path": path,
                    "nodes": [{"id": n, "kind": self._g.nodes[n].get("kind"), "label": self._label_of(n)} for n in path],
                    "total_weight": total_weight,
                    "probability": round(prob, 4),
                    "severity": self._g.nodes[sink].get("severity", ""),
                    "end_type": sink_meta.get("type", ""),
                    "end_url": sink_meta.get("url", ""),
                })

        results.sort(key=lambda r: (len(r["path"]), r["total_weight"], -r["probability"]))
        return results[:top_k]

    def _label_of(self, node_id: str) -> str:
        d = self._g.nodes[node_id]
        if d.get("kind") == "asset":
            return node_id
        if d.get("kind") == "vuln":
            vtype = str(d.get("type", ""))
            return f"{vtype}" if d.get("url") else vtype
        return str(d.get("label", node_id))

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