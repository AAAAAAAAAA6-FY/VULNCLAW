# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 4: 分布式部署模块包。

包含 Redis 后端上下文、Master/Worker 架构、任务队列和故障转移。

协议契约（P2-19 编排端口协议）
------------------------------
Master 与 Worker 之间此前只有**隐式约定**：键名与字段散落在两侧实现里，
任一侧改字段都只能靠"跑一遍集群才发现问题"。这里集中定义信封 schema +
协议版本，供双方 import 校验，把"口头协议"变成"可断言的契约"。

三类信封：
- ``task``     任务信封：Master → Worker（投递 DAG 节点任务）
- ``heartbeat`` 心跳信封：Worker → Master（存活 + 负载）
- ``result``   结果信封：Worker → Master（执行回执）

设计取舍（前向兼容优先）：
- **必填缺失 → 判错**（ok=False，调用方应拒绝/告警）
- **未知字段 → 只告警不判错**（新版加字段时，旧节点不应直接炸）
- 版本不匹配 → 判错并回报双方版本，由调用方决定降级还是拒连

本模块只做**纯校验**，不含 IO、不抛异常、不阻断流程——是否 reject 由调用方决定。
"""

from typing import Any, Dict, Tuple

# 协议版本。破坏性变更（删必填字段/改语义）必须 +1。
PROTOCOL_VERSION = "1.0"

# --- 信封 schema：kind → (必填字段, 可选字段) ---

TASK_REQUIRED = frozenset({"task_id", "type"})
TASK_OPTIONAL = frozenset({
    "params", "context", "ttl", "status",
    "submitted_at", "assigned_to", "assigned_at",
    "requeued_from", "requeued_at", "idempotency_key",
})

HEARTBEAT_REQUIRED = frozenset({"worker_id"})
HEARTBEAT_OPTIONAL = frozenset({
    "status", "last_heartbeat", "capabilities",
    "tasks_completed", "tasks_failed", "load",
})

RESULT_REQUIRED = frozenset({"task_id", "status"})
RESULT_OPTIONAL = frozenset({
    "result", "error", "retry_count", "completed_at", "worker_id",
})

_ENVELOPES: Dict[str, Tuple[frozenset, frozenset]] = {
    "task": (TASK_REQUIRED, TASK_OPTIONAL),
    "heartbeat": (HEARTBEAT_REQUIRED, HEARTBEAT_OPTIONAL),
    "result": (RESULT_REQUIRED, RESULT_OPTIONAL),
}

# 终态：进入后不再重试/重投递（故障转移时用于判定是否值得重入队）
TASK_TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled"})


def validate_envelope(
    kind: str,
    data: Any,
    version: str = PROTOCOL_VERSION,
) -> Tuple[bool, list]:
    """校验一个信封是否符合协议。

    纯函数：不抛异常、不做 IO、不修改入参。

    Args:
        kind: 信封类型，``task`` / ``heartbeat`` / ``result``。
        data: 待校验的信封（应为 dict）。
        version: 对端声明的协议版本，用于版本协商。

    Returns:
        ``(ok, errors)``：ok 为 True 表示必填齐备且版本一致；
        errors 为诊断信息列表，其中 ``missing:`` 前缀是致命错误，
        ``unknown:`` 前缀只是前向兼容告警（不计入 ok 判定）。
    """
    if version != PROTOCOL_VERSION:
        return (False, [f"version_mismatch: peer={version} local={PROTOCOL_VERSION}"])

    schema = _ENVELOPES.get(kind)
    if schema is None:
        return (False, [f"unknown_envelope_kind: {kind}"])

    if not isinstance(data, dict):
        return (False, [f"envelope_not_dict: {type(data).__name__}"])

    required, optional = schema
    errors = [f"missing:{f}" for f in sorted(required - set(data))]
    warnings = [f"unknown:{f}" for f in sorted(set(data) - required - optional)]
    return (not errors, errors + warnings)


def is_terminal(status: Any) -> bool:
    """任务状态是否为终态（终态不再重试/重投递）。"""
    return status in TASK_TERMINAL_STATUSES


def envelope_version_ok(version: str) -> bool:
    """对端协议版本是否与本端一致（用于建连时快速拒绝）。"""
    return version == PROTOCOL_VERSION


__all__ = [
    "PROTOCOL_VERSION",
    "TASK_REQUIRED",
    "TASK_OPTIONAL",
    "HEARTBEAT_REQUIRED",
    "HEARTBEAT_OPTIONAL",
    "RESULT_REQUIRED",
    "RESULT_OPTIONAL",
    "TASK_TERMINAL_STATUSES",
    "validate_envelope",
    "is_terminal",
    "envelope_version_ok",
]
