# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/planning/capabilities.py
"""动作能力模型 —— 攻击链规划的基本单元。

一个 `Capability` = 一个**原子动作**：满足 `requires` 后即可获得 `produces`。
规划器（planner.py）只在这层做前/后向搜索，不关心动作背后是 IR 端点还是引擎。

事实（Fact）约定（字符串，可哈希、可排序、可复现）：
    visited:<path_template>      已到达某业务阶段
    role=<role>                  已取得某角色（admin/user/owner/anonymous）
    token:<name>                 已取得某令牌/凭据
    written:<entity>             已对某实体产生写副作用
    finding:<type>               已确认某类漏洞（供链式利用的前置）
    access:<host>                已获得某主机访问权

来源三路（与 §28.4 一致）：① IR endpoints ② IR transitions ③ 已有 findings。
**只读优先**：写动作 `side_effect=True`，默认不进规划（需显式允许）。
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "Capability",
    "read_capabilities",
    "produce_index",
    "build_capabilities",
]

_WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")


@dataclass(frozen=True)
class Capability:
    """原子动作。字段全部可哈希 → 计划可比较、可复现。"""

    id: str
    kind: str = "ir_endpoint"           # ir_endpoint | ir_transition | finding
    requires: Tuple[str, ...] = ()
    produces: Tuple[str, ...] = ()
    cost: float = 1.0
    side_effect: bool = False
    method: str = "GET"
    path: str = ""
    source: str = ""
    note: str = ""

    def __post_init__(self):
        # 归一化为「去重 + 排序」的字符串元组 → 计划可比较、可复现
        for attr in ("requires", "produces"):
            v = getattr(self, attr)
            object.__setattr__(self, attr, tuple(sorted({str(x) for x in (v or ()) if x})))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind,
            "requires": list(self.requires), "produces": list(self.produces),
            "cost": self.cost, "side_effect": self.side_effect,
            "method": self.method, "path": self.path,
            "source": self.source, "note": self.note,
        }


def read_capabilities(caps: Iterable[Capability], *, allow_side_effect: bool = False) -> List[Capability]:
    """可用动作集（默认剔除写动作）。排序保证规划确定性。"""
    out = [c for c in (caps or ()) if isinstance(c, Capability)]
    if not allow_side_effect:
        out = [c for c in out if not c.side_effect]
    return sorted(out, key=lambda c: c.id)


def produce_index(caps: Iterable[Capability]) -> Dict[str, List[Capability]]:
    """事实 → 能产出它的动作（后向搜索用）。列表按 id 排序 → 选择顺序确定。"""
    idx: Dict[str, List[Capability]] = {}
    for c in caps or ():
        if not isinstance(c, Capability):
            continue
        for f in c.produces:
            idx.setdefault(f, []).append(c)
    for f in idx:
        idx[f].sort(key=lambda c: c.id)
    return idx


def _path_template(path: str) -> str:
    from vulnclaw.core.business_ir import path_template

    try:
        return path_template(path)
    except Exception:  # noqa: BLE001 - 兜底：模板化失败就用原路径
        return str(path or "/")


def build_capabilities(ir: Optional[Dict[str, Any]] = None,
                       findings: Optional[Sequence[Dict[str, Any]]] = None,
                       *,
                       extra: Optional[Sequence[Capability]] = None,
                       allow_side_effect: bool = True) -> List[Capability]:
    """从 IR + findings 构建动作集（确定性；任何异常 → 返回已构建部分，绝不抛）。

    allow_side_effect 只控制"是否把写动作纳入集合"；是否真的允许规划走写路径
    由 planner 的参数决定（双闸，避免误开）。
    """
    caps: List[Capability] = []
    ir = ir if isinstance(ir, dict) else {}

    # ① IR endpoints → 动作
    for ep in (ir.get("endpoints") or []):
        if not isinstance(ep, dict):
            continue
        eid = str(ep.get("id") or "")
        path = str(ep.get("path") or "")
        method = str(ep.get("method") or "GET").upper()
        if not eid or not path:
            continue
        auth = ep.get("auth") if isinstance(ep.get("auth"), dict) else {}
        requires: List[str] = []
        if auth.get("required") and auth.get("role"):
            requires.append(f"role={auth.get('role')}")
        produces = [f"visited:{_path_template(path)}"]
        for eff in (ep.get("effects") or []):
            if isinstance(eff, dict) and eff.get("entity"):
                produces.append(f"written:{eff['entity']}")
        se = method in _WRITE_METHODS
        if se and not allow_side_effect:
            continue
        caps.append(Capability(
            id=f"ep:{eid}", kind="ir_endpoint", requires=tuple(requires),
            produces=tuple(produces), side_effect=se, method=method, path=path,
            source=eid,
        ))

    # ② IR transitions → 动作（pre/post 直接映射，语义更精确）
    for i, tr in enumerate(ir.get("transitions") or []):
        if not isinstance(tr, dict):
            continue
        via = str(tr.get("via_endpoint") or "")
        if not via:
            continue
        pre = tuple(sorted({str(x) for x in (tr.get("preconditions") or [])}))
        post = tuple(sorted({str(x) for x in (tr.get("postconditions") or [])}))
        if not post:
            continue
        caps.append(Capability(
            id=f"tr:{via}", kind="ir_transition", requires=pre, produces=post,
            cost=1.0, side_effect=False, source=via, note=f"transition#{i}",
        ))

    # ③ 已确认 finding → 动作（把"已获得的洞"变成后续链的前置事实）
    for i, f in enumerate(findings or ()):
        if not isinstance(f, dict):
            continue
        ftype = str(f.get("type") or f.get("vuln_type") or "").strip()
        if not ftype:
            continue
        facts = [f"finding:{ftype}"]
        url = str(f.get("url") or "")
        if url:
            try:
                from urllib.parse import urlparse

                host = urlparse(url).netloc or ""
                if host:
                    facts.append(f"access:{host}")
            except Exception:  # noqa: BLE001
                pass
        caps.append(Capability(
            id=f"finding:{i}:{ftype}", kind="finding", requires=(),
            produces=tuple(facts), cost=0.0, side_effect=False, source=ftype,
        ))

    for c in (extra or ()):
        if isinstance(c, Capability):
            caps.append(c)

    # 去重（同 id 保留先到者）+ 确定性排序
    best: Dict[str, Capability] = {}
    for c in caps:
        best.setdefault(c.id, c)
    return sorted(best.values(), key=lambda c: c.id)
