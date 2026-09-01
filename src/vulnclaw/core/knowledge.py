# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

# core/knowledge.py
"""A3.3 通用漏洞模式库：按指纹（框架+版本）映射已知弱点速查，减少 LLM 重复推导。

模式库以 YAML 维护在 core/data/knowledge/，可被引擎/验证 prompt 引用，
让 Agent 针对识别到的技术栈直接获得"已知弱点清单"而非每次重新推理。
"""
import os
from typing import Dict, List

import yaml

from vulnclaw.core.logger import logger

_KNOWLEDGE_DIR = os.path.join(os.path.dirname(__file__), "data", "knowledge")


def load_vuln_knowledge() -> Dict:
    """加载所有漏洞模式库 YAML，合并为 {框架: {weaknesses: [...]}} 字典。"""
    data: Dict = {}
    try:
        if not os.path.isdir(_KNOWLEDGE_DIR):
            return data
        for fname in sorted(os.listdir(_KNOWLEDGE_DIR)):
            if not fname.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(_KNOWLEDGE_DIR, fname)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    parsed = yaml.safe_load(fh) or {}
                if isinstance(parsed, dict):
                    data.update(parsed)
            except (OSError, yaml.YAMLError) as exc:
                logger.warning(f"⚠️ 加载漏洞模式库 {fname} 失败: {exc}")
    except OSError as exc:
        logger.warning(f"⚠️ 读取漏洞模式库目录失败: {exc}")
    return data


def format_knowledge_for_prompt(tech_stack: List[str]) -> str:
    """返回与给定技术栈匹配的已知弱点速查文本（供 prompt 注入）。无匹配返回空串。"""
    kb = load_vuln_knowledge()
    if not tech_stack:
        return ""
    stack_lower = [s.lower() for s in tech_stack]
    hits: List[str] = []
    for framework, info in kb.items():
        if not any(framework.lower() in s or s in framework.lower() for s in stack_lower):
            continue
        if isinstance(info, dict):
            weaknesses = info.get("weaknesses", []) or []
            detail = "; ".join(str(w) for w in weaknesses) if weaknesses else ""
            hits.append(f"- {framework}: {detail}" if detail else f"- {framework}")
        else:
            hits.append(f"- {framework}")
    return "\n".join(hits)


__all__ = ["load_vuln_knowledge", "format_knowledge_for_prompt"]
