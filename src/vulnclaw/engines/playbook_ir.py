# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/playbook_ir.py
"""B3 剧本 → BusinessIR（ir-1）桥：让 B3 剧本可被 A1 符号执行引擎消费。

分工（与 A2 的区别）
---------------------
A2 负责“LLM 逆向 → 符号化中间表示”（源码/JS 还原产物 → IR），面向白盒。
本模块是**黑盒路径**：把 B3 剧本生成器的动作 + 不变量类别 → IR 业务模型，
供 `SymbolicLogicEngine` 做确定性求解（六类逻辑洞：越权/金额/数量/流程/幂等/溢出）。

约束纪律
--------
1. **fail-closed**：任何异常返回最小合法 IR（空 endpoints），不报错、不阻断流水线；
2. **宁缺毋滥**：参数只在其语义类可确定性归类时才给值域（domain），否则不建模
   （A1 对无值域参数判 undecidable → 不产出，这比乱给域更安全）；
3. 本桥只做建模，**不负责验证**：A1 产出恒带 `needs_verification=True`，
   由既有验证层（verify / cross_verify / 差分）裁决后再入报告。
"""
from typing import Any

from vulnclaw.core.logger import logger

__all__ = [
    "PARAM_DOMAINS",
    "playbooks_to_ir",
    "symbolic_from_playbooks",
]

# 参数语义类 → 可能值域形态（A1 的 domain_from_dict 消费；保守取宽区间，
# 具体端点参数若受服务端校验则由不变量目标裁决，多解交给验证层过滤）
PARAM_DOMAINS: dict[str, dict[str, Any]] = {
    # 金额类：允许负值与大值（负价/大额篡改在建模域内必须可表达）
    "amount": {"kind": "int", "lo": -100000, "hi": 100000},
    # 数量类：允许越界（0 / 负值 / 超上限）
    "quantity": {"kind": "int", "lo": 0, "hi": 10000},
    # 角色类：高低权限双值（水平/垂直越权建模）
    "role": {"kind": "enum", "values": ["admin", "administrator", "1", "user", "0"]},
    # 流程类：前置/终态若干（状态跳跃建模；explore 路径日志用）
    "step": {"kind": "enum", "values": ["init", "pending", "paid", "done", "shipped"]},
    # 布尔开关类（is_admin / verified / paid）
    "flag": {"kind": "enum", "values": [True, False]},
    # 身份类：凑几档可对照值（水平 IDOR 目标用；具体值由差分层裁决）
    "identity": {"kind": "enum", "values": ["1", "2", "1001", "admin"]},
}


def _rel_path(url: Any) -> str:
    """完整 URL → 相对路径（IR 只存路径，请求拼接由引擎层负责）。"""
    try:
        from urllib.parse import urlparse

        return (urlparse(str(url or "")).path or "/")
    except Exception:  # noqa: BLE001
        return "/"


def _extract_unit_price(actions: list[Any]) -> int | None:
    """从剧本动作参数里提取“观测到的真实单价”（如 amount=1 → unit_price=1）。

    找不到正数值 → None（A1 将不对该端点生成 amount/overflow 目标，宁缺毋滥）。
    """
    for act in actions or []:
        params = getattr(act, "params", {}) or {}
        for k, v in params.items():
            low = str(k or "").strip().lower()
            if not any(w in low for w in ("amount", "price", "fee", "total", "money", "pay")):
                continue
            try:
                n = int(float(str(v)))
                if n > 0:
                    return n
            except (TypeError, ValueError):
                continue
    return None


def _classify(name: str) -> str | None:
    """参数名 → 语义类（复用 A1 的同源归类，保证枚举一致性）。"""
    try:
        from vulnclaw.engines.symbolic.objectives import classify_param

        return classify_param(str(name or ""))
    except Exception:  # noqa: BLE001 - 桥依赖异常不得阻断
        logger.debug(f"[PLAYBOOK-IR] classify_param 不可用: {name}")
        return None


def playbooks_to_ir(
    playbooks: list[Any],
    target: str = "",
    *,
    version: str = "ir-1",
    confidence: float = 0.6,
) -> dict[str, Any]:
    """B3 Playbook 列表 → BusinessIR(ir-1)。任何异常返回最小合法 IR（fail-closed）。

    IR 结构（A1 引擎消费约定）：
        endpoints[].id/method/path/params[{name, domain}]
        unit_price        （观测到的真实单价，可缺）
        invariants[]      （线性不变量；黑盒桥暂不做服务端硬校验假设 → 留空，
                            由 A1 目标谓词 + 验证层裁决，避免建模错误误挡/误放）
        goals[]           （路径探索目标：state 剧本 → 终态可达）
    """
    empty: dict[str, Any] = {
        "version": version, "source": "b3-playbook",
        "target": str(target or ""), "endpoints": [],
        "invariants": [], "goals": [],
    }
    try:
        if not playbooks:
            return empty
        ep_map: dict[str, dict[str, Any]] = {}   # key: (method, path)
        unit_price: int | None = None
        goals: dict[str, dict[str, Any]] = {}
        for book in playbooks:
            acts = getattr(book, "actions", []) or []
            if not acts:
                continue
            for act in acts:
                path = _rel_path(getattr(act, "url", ""))
                method = "GET"
                key = (method, path)
                ep = ep_map.get(key)
                if ep is None:
                    ep = {
                        "id": f"ep:{len(ep_map)}",
                        "method": method,
                        "path": path,
                        "params": [],
                        # 状态机建模：绑定后置写（auth.role 由抽取的参数注入）
                        "auth": {"required": True, "role": "user"},
                        "effects": [],
                    }
                    ep_map[key] = ep
                # 注入参数（语义类归类成功才给 domain；重复参数去重）
                for pname in (getattr(act, "params", {}) or {}):
                    if any(p.get("name") == pname for p in ep["params"]):
                        continue
                    kind = _classify(pname)
                    dom = PARAM_DOMAINS.get(kind or "") if kind else None
                    if dom is None:
                        continue
                    ep["params"].append({"name": str(pname), "domain": dict(dom)})
                if ep["params"] and not ep["effects"]:
                    # 动作端点默认“写”其业务实体（符号机需要可区分的转移）
                    ep["effects"] = [{"op": "write", "entity": path.strip("/").split("/")[-1] or "state"}]
            # unit_price：取首个可观测金额类参数值
            if unit_price is None:
                unit_price = _extract_unit_price(acts)
            # state 剧本 → 路径探索目标（requires_facts 给出其不变量期望）
            inv = getattr(book, "invariant", "")
            if inv == "state" and getattr(book, "id", ""):
                goals[f"goal:{book.id}"] = {
                    "id": f"goal:{book.id}",
                    "requires_facts": ["role=user"],
                }
        eps = list(ep_map.values())
        for idx, ep in enumerate(eps):
            if ep["params"]:
                ep["id"] = f"ep:{idx}"
        return {
            "version": version,
            "source": "b3-playbook",
            "target": str(target or ""),
            "endpoints": eps,
            "unit_price": unit_price,
            "invariants": [],
            "goals": list(goals.values()),
        }
    except Exception as exc:  # noqa: BLE001 - 桥失败绝不阻断上游
        logger.debug(f"[PLAYBOOK-IR] IR 生成失败（降级为空 IR）: {exc}")
        return empty


async def symbolic_from_playbooks(
    playbooks: list[Any],
    target: str = "",
    *,
    session=None,
) -> list[dict[str, Any]]:
    """剧本 → IR → A1 SymbolicLogicEngine 求解 → 归一化 findings。

    任何失败 → []（fail-closed）。产出恒 `needs_verification=True`，交验证层。
    """
    ir = playbooks_to_ir(playbooks, str(target or ""))
    if not ir.get("endpoints"):
        return []
    try:
        from vulnclaw.engines.symbolic_engine import SymbolicLogicEngine

        engine = SymbolicLogicEngine()
        return await engine.scan(str(target or ""), session=session, ir=ir)
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[PLAYBOOK-IR] A1 求解不可用（跳过该复核通道）: {exc}")
        return []
