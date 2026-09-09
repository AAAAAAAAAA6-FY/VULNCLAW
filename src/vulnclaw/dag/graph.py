# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# dag/graph.py
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class NodeStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"  # 调度审计C: 指数退避期间挂起态，防止重试节点被重复提交


class NodeType(Enum):
    RECON = "recon"
    RECON_SUB = "recon_sub"
    RECON_ALIVE = "recon_alive"
    RECON_NUCLEI = "recon_nuclei"
    RECON_JS = "recon_js"
    RECON_PORT = "recon_port"
    RECON_FFUF = "recon_ffuf"
    ATTACK = "attack"
    VERIFY = "verify"
    EXPLOIT = "exploit"
    REPORT = "report"
    SUBGRAPH = "subgraph"
    CODE_SCAN = "code_scan"  # Sprint 2: 代码扫描节点
    EXPLOIT_DEEP = "exploit_deep"  # Sprint 3: 深度利用节点
    DESERIALIZATION = "deserialization"  # Sprint 4: 反序列化节点


@dataclass
class DAGNode:
    node_id: str
    node_type: NodeType
    name: str
    target: str
    params: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    status: NodeStatus = NodeStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 2


@dataclass
class DAG:
    nodes: Dict[str, DAGNode] = field(default_factory=dict)
    edges: List[tuple] = field(default_factory=list)
    entry_nodes: List[str] = field(default_factory=list)
    exit_nodes: List[str] = field(default_factory=list)

    def add_node(self, node: DAGNode) -> None:
        self.nodes[node.node_id] = node
        if node.node_type == NodeType.SUBGRAPH and node.node_id not in self.entry_nodes:
            self.entry_nodes.append(node.node_id)

    def add_edge(self, from_node_id: str, to_node_id: str) -> None:
        """建立一条 from → to 的依赖边：to 需要等 from 完成才能执行。

        语义：to_node.depends_on 记录它的前置节点（from_node_id），
        与 scheduler.get_ready_nodes() 的判断方向保持一致（看"我自己等谁"）。
        """
        if (from_node_id, to_node_id) in self.edges:
            # 去重：同一条边反复添加不应污染 depends_on / in_degree
            return
        self.edges.append((from_node_id, to_node_id))
        if to_node_id in self.nodes:
            if from_node_id not in self.nodes[to_node_id].depends_on:
                self.nodes[to_node_id].depends_on.append(from_node_id)

    def get_entry_nodes(self) -> List[str]:
        if self.entry_nodes:
            return self.entry_nodes
        in_degree = {node_id: 0 for node_id in self.nodes}
        for _, to_node in self.edges:
            in_degree[to_node] += 1
        return [node_id for node_id, degree in in_degree.items() if degree == 0]

    def get_exit_nodes(self) -> List[str]:
        if self.exit_nodes:
            return self.exit_nodes
        out_degree = {node_id: 0 for node_id in self.nodes}
        for from_node, _ in self.edges:
            out_degree[from_node] += 1
        return [node_id for node_id, degree in out_degree.items() if degree == 0]

    def topological_sort(self) -> List[str]:
        in_degree = {node_id: 0 for node_id in self.nodes}
        adjacency = {node_id: [] for node_id in self.nodes}
        for from_node, to_node in self.edges:
            adjacency[from_node].append(to_node)
            in_degree[to_node] += 1

        queue = [node_id for node_id, degree in in_degree.items() if degree == 0]
        result = []

        while queue:
            node_id = queue.pop(0)
            result.append(node_id)
            for neighbor in adjacency[node_id]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if len(result) != len(self.nodes):
            raise ValueError("Cycle detected in DAG")
        return result

    def detect_cycle(self) -> Optional[List[str]]:
        visited = set()
        rec_stack = set()
        path = []

        def dfs(node_id: str) -> Optional[List[str]]:
            visited.add(node_id)
            rec_stack.add(node_id)
            path.append(node_id)

            for from_node, to_node in self.edges:
                if from_node == node_id:
                    if to_node not in visited:
                        cycle = dfs(to_node)
                        if cycle:
                            return cycle
                    elif to_node in rec_stack:
                        cycle_start = path.index(to_node)
                        return path[cycle_start:] + [to_node]

            path.pop()
            rec_stack.remove(node_id)
            return None

        for node_id in self.nodes:
            if node_id not in visited:
                cycle = dfs(node_id)
                if cycle:
                    return cycle
        return None