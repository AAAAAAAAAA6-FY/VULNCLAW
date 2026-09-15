# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/business_ir/__init__.py
"""A2：LLM 逆向 → 业务 IR 还原链。

主入口：
    from vulnclaw.core.business_ir import build_business_ir
    ir = await build_business_ir(brief, target)      # → BusinessIR(ir-1) 或 {}（fail-closed）

流水线（每一步都可降级，绝不抛异常）：
    ① observations  观测归一（recon brief / HTTP 轨迹，零主动探测）
    ② features      确定性骨架 IR（域推断 / 路径聚类 / 写操作与实体 / 认证 / 粗流程）
    ③ llm_extractor 语义增强（只增强已观测项；LLM 不可用 → 保底骨架）
    ④ validator     归一化 + 观测交叉校验（幻觉端点/未建模端点 → warning + 降置信度）
    ⑤ store         幂等落盘 _runtime_cache/ir/<host>.json
"""
from typing import Any, Dict, Optional

from vulnclaw.core.logger import logger

from .features import build_ir_skeleton, cluster_paths, infer_domain, path_template
from .llm_extractor import extract_json, merge_fragment, refine_ir
from .observations import collect_observations
from .schema import (
    IR_VERSION,
    empty_ir,
    ir_summary,
    normalize_ir,
    validate_ir,
)
from .store import ir_path, load_ir, save_ir
from .validator import cross_validate, validate_and_fix

__all__ = [
    "IR_VERSION",
    "empty_ir",
    "validate_ir",
    "normalize_ir",
    "ir_summary",
    "collect_observations",
    "build_ir_skeleton",
    "infer_domain",
    "path_template",
    "cluster_paths",
    "refine_ir",
    "merge_fragment",
    "extract_json",
    "cross_validate",
    "validate_and_fix",
    "save_ir",
    "load_ir",
    "ir_path",
    "build_business_ir",
    "attach_ir_to_brief",
]


def business_ir_enabled() -> bool:
    """开关：`getattr` 读取（A2 不改 settings.py，避免与其他并行线争抢共享文件）。"""
    try:
        from vulnclaw.core.settings import settings

        return bool(getattr(settings, "business_ir_enabled", True))
    except Exception:  # noqa: BLE001 - 配置读取失败按开启（后续步骤各自 fail-closed）
        return True


async def build_business_ir(brief: Optional[Dict[str, Any]] = None,
                            target: str = "",
                            *,
                            traces: Any = None,
                            use_llm: bool = True,
                            client: Any = None,
                            persist: bool = True,
                            timeout: float = 60.0) -> Dict[str, Any]:
    """构建业务 IR。任何异常 → `{}`（fail-closed，绝不阻断扫描主流程）。"""
    try:
        if not business_ir_enabled():
            logger.debug("🧩 [IR] business_ir_enabled=False，跳过")
            return {}
        brief = brief if isinstance(brief, dict) else {}
        tgt = str(target or brief.get("target") or "")

        obs = collect_observations(brief, traces=traces, target=tgt)
        if not obs.get("endpoints"):
            logger.info("🧩 [IR] 无端点观测，跳过 IR 构建")
            return {}

        skeleton = build_ir_skeleton(obs, target=tgt)
        ir = await refine_ir(obs, skeleton, client=client, timeout=timeout, enabled=bool(use_llm))
        clean, rep = validate_and_fix(ir, obs)

        for w in rep["warnings"][:8]:
            logger.debug(f"🧩 [IR] 警告: {w}")
        if not rep["ok"]:
            logger.warning(f"🧩 [IR] 校验未通过（{len(rep['errors'])} 项），仍保留结构合法的部分")

        summary = ir_summary(clean)
        logger.info(
            f"🧩 [IR] 构建完成：端点 {summary['endpoints']} / 参数 {summary['params']} / "
            f"不变量 {summary['invariants']} / 目标 {summary['goals']} / "
            f"置信度 {summary['confidence']}"
        )
        if persist:
            path = save_ir(clean, tgt)
            if path:
                logger.debug(f"🧩 [IR] 已落盘 {path}")
        return clean
    except Exception as exc:  # noqa: BLE001 - IR 构建失败必须无副作用地退化
        logger.warning(f"🧩 [IR] 构建异常（fail-closed）: {exc}")
        return {}


def attach_ir_to_brief(brief: Optional[Dict[str, Any]], ir: Dict[str, Any]) -> Dict[str, Any]:
    """把 IR 挂到 brief 上（供 A1/A3 消费；空 IR 不挂，避免下游误判"有模型"）。"""
    if isinstance(brief, dict) and isinstance(ir, dict) and ir.get("endpoints"):
        brief["business_ir"] = ir
    return brief if isinstance(brief, dict) else {}
