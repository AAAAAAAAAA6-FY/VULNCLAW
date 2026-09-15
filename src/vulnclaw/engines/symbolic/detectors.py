# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/symbolic/detectors.py
"""判定产物化 —— 把"可满足的目标"转成 finding，并做不变量差分复核。

与其它引擎的区别（为什么它天然低误报）
--------------------------------------
其它引擎靠"响应差异"猜漏洞；本模块的两条判据都是**推导出来的**：
  ① 目标可满足 = 在已知约束下存在一组输入让业务不变量破缺（solver 给出的证明 + 见证载荷）；
  ② 差分复核 = 拿见证载荷真打一次，比对业务不变量是否**确实**被破（服务端说了算）。
两条都过才落 finding；只有 ① 无 ② → 标记 `needs_verification=True`，交既有验证层
（`verify_nuclei_with_ai_async` / cross_verify）处置，绝不直接当真实漏洞入报告。

**零网络**：本模块全部是纯函数（差分复核的输入由调用方给），便于离线测试与审计。
"""
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .objectives import Objective, ObjectiveResult
from .values import LinExpr

__all__ = [
    "ENGINE_NAME",
    "witness_to_payload",
    "objective_to_finding",
    "invariant_holds",
    "differential_verdict",
    "findings_from_results",
]

ENGINE_NAME = "symbolic_logic"


def witness_to_payload(witness: Dict[str, Any]) -> str:
    """见证赋值 → 可复现的攻击载荷串（`qty=-1&total=-100`）。纯字符串拼接，无副作用。"""
    if not isinstance(witness, dict) or not witness:
        return ""
    parts: List[str] = []
    for k in sorted(witness.keys()):
        v = witness[k]
        if isinstance(v, bool):
            v = "true" if v else "false"
        elif v is None:
            v = ""
        parts.append(f"{k}={v}")
    return "&".join(parts)


def objective_to_finding(
    result: ObjectiveResult,
    *,
    url: str,
    method: str = "GET",
    parameter: Optional[str] = None,
    path: Optional[Sequence[str]] = None,
    ir_ref: Optional[Dict[str, Any]] = None,
    evidence: str = "",
    verified: bool = False,
) -> Optional[Dict[str, Any]]:
    """目标判定结果 → SymbolicFinding（§28.1 schema）。不可行/不可判 → None（不产出）。"""
    if not isinstance(result, ObjectiveResult) or not result.objective:
        return None
    if result.undecidable or not result.feasible:
        return None
    obj: Objective = result.objective
    payload = witness_to_payload(result.witness or {})
    return {
        "engine": ENGINE_NAME,
        "vuln_type": obj.vuln_type,
        "severity": obj.severity,
        "url": str(url or ""),
        "method": str(method or "GET").upper(),
        "parameter": parameter or (obj.params[0] if obj.params else ""),
        "payload": payload,
        "cwe": obj.cwe,
        "constraint_trace": [c.to_dict() for c in obj.goal],
        "path": list(path or []),
        "ir_ref": dict(ir_ref or {"objective": obj.id, "kind": obj.kind}),
        "evidence": evidence or (
            f"约束求解证明目标可满足：{obj.note}；见证 {payload}"),
        # 无差分复核 → 需验证层确认；已复核 → 置信度上调
        "confidence": "高" if verified else "中",
        "deterministic": True,
        "needs_verification": not verified,
        "source": "symbolic",
    }


def invariant_holds(values: Dict[str, Any], invariant: LinExpr) -> bool:
    """不变量（形如 expr == 0）在给定观测值下是否成立。非数值/异常 → 视为成立（fail-closed，
    避免因解析失败而误报业务不变量破缺）。"""
    if not isinstance(invariant, LinExpr) or not isinstance(values, dict):
        return True
    try:
        return invariant.eval(values) == 0
    except Exception:  # noqa: BLE001
        return True


def differential_verdict(
    baseline_values: Dict[str, Any],
    tampered_values: Dict[str, Any],
    invariants: Sequence[LinExpr] = (),
) -> Dict[str, Any]:
    """差分复核：见证载荷是否**真的**让业务不变量破缺。

    判据（保守）：至少一条不变量在 baseline 成立、在 tampered 破缺 → violated=True。
    baseline 本身就不成立的不变量不参与判定（说明建模/观测有问题，不据此报洞）。
    """
    broken: List[int] = []
    considered = 0
    invs = [i for i in (invariants or ()) if isinstance(i, LinExpr)]
    for idx, inv in enumerate(invs):
        if not invariant_holds(baseline_values or {}, inv):
            continue                      # baseline 不成立 → 不参与
        considered += 1
        if not invariant_holds(tampered_values or {}, inv):
            broken.append(idx)
    return {
        "violated": bool(broken),
        "broken_invariants": broken,
        "considered": considered,
        "reason": ("业务不变量被破缺" if broken else
                   ("不变量保持成立（无洞）" if considered else "无可判定不变量")),
    }


def findings_from_results(
    results: Sequence[ObjectiveResult],
    *,
    url: str,
    method: str = "GET",
    path: Optional[Sequence[str]] = None,
    ir_ref: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """批量转 finding（过滤不可行/不可判的，保持顺序确定）。"""
    out: List[Dict[str, Any]] = []
    for r in (results or ()):
        f = objective_to_finding(r, url=url, method=method, path=path, ir_ref=ir_ref)
        if f is not None:
            out.append(f)
    return out
