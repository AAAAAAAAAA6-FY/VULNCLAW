# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/business_ir/validator.py
"""IR 交叉校验 —— 用**观测**去证伪模型（确定性，无 LLM）。

为什么必须有这一层
------------------
A1（符号执行）的判定强度完全取决于 IR 是否可信：IR 里多一个不存在的不变量
→ 漏报；少一个真实不变量 → **误报**。所以 LLM 产出的 IR 必须过一遍证据交叉校验：
  * error：结构性错误（schema）→ 不可用于判定
  * warning：与观测不符 / 无法证据支撑 → 保留但**降低置信度**，并交给 A1 侧
    的 `undecidable` 机制谨慎处理
"""
from typing import Any, Dict, List, Tuple

from .schema import normalize_ir, validate_ir

__all__ = ["cross_validate", "validate_and_fix"]


def cross_validate(ir: Any, obs: Any = None) -> Dict[str, Any]:
    """返回 {"ok", "errors", "warnings"}。**绝不抛异常**。"""
    errors = validate_ir(ir)
    warnings: List[str] = []
    if not isinstance(ir, dict):
        return {"ok": False, "errors": errors, "warnings": warnings}

    obs = obs if isinstance(obs, dict) else {}
    obs_paths = set()
    for e in (obs.get("endpoints") or []):
        if isinstance(e, dict) and e.get("path"):
            obs_paths.add(str(e["path"]))

    ep_paths = set()
    ep_param_names = set()
    for e in (ir.get("endpoints") or []):
        if not isinstance(e, dict):
            continue
        p = str(e.get("path") or "")
        ep_paths.add(p)
        for prm in (e.get("params") or []):
            if isinstance(prm, dict) and prm.get("name"):
                ep_param_names.add(str(prm["name"]))
        for prm in (e.get("params") or []):
            if isinstance(prm, dict) and prm.get("domain") is None:
                warnings.append(f"端点 {p} 的参数 {prm.get('name')} 缺值域（A1 将判 undecidable）")

    if obs_paths:
        for p in sorted(ep_paths - obs_paths):
            warnings.append(f"IR 端点未被观测到（可能幻觉）: {p}")
        for p in sorted(obs_paths - ep_paths):
            warnings.append(f"观测端点未进 IR（漏建模）: {p}")

    for inv in (ir.get("invariants") or []):
        if not isinstance(inv, dict):
            continue
        coeffs = ((inv.get("expr") or {}).get("coeffs") or {})
        unknown = sorted({str(k) for k in coeffs} - ep_param_names)
        if unknown:
            warnings.append(f"不变量 {inv.get('id')} 引用了未建模的参数: {','.join(unknown)}")

    return {"ok": not errors, "errors": errors, "warnings": warnings}


def validate_and_fix(ir: Any, obs: Any = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """归一化 + 交叉校验。返回 (clean_ir, report)。

    `clean_ir` 一定是一份**结构合法**的 IR（normalize 已剔除非法项）；report 里带上
    输入错误 / 警告与最终置信度，供上层决定是否落盘/使用。

    注意：normalize 会把非法输入"修"成合法骨架，所以**单看 clean 看不出输入是否损坏**。
    因此这里额外对**归一化前**的输入做一次校验并计入 `input_errors`——输入本身有问题
    时置信度直接归零（宁可不用，也不让 A1 拿坏模型去判定）。
    """
    input_errors = validate_ir(ir) if isinstance(ir, dict) else ["IR 不是字典"]
    clean = normalize_ir(ir if isinstance(ir, dict) else {})
    rep = cross_validate(clean, obs)
    rep["input_errors"] = input_errors
    if input_errors:
        rep["ok"] = False
    if not rep["ok"]:
        clean["confidence"] = 0.0
    elif rep["warnings"]:
        try:
            clean["confidence"] = round(float(clean.get("confidence") or 0.0) * 0.7, 4)
        except (TypeError, ValueError):
            clean["confidence"] = 0.0
    rep["confidence"] = clean.get("confidence", 0.0)
    return clean, rep
