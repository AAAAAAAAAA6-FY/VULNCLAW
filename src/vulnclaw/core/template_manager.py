# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/template_manager.py
"""
社区模板仓库管理器（v105，任务 5）

提供社区模板仓库（community_templates/）的元数据索引访问，
支持社区贡献模板的注册、查询与测试状态跟踪。

索引文件: src/vulnclaw/community_templates/templates_index.yaml
"""

from pathlib import Path

import yaml

COMMUNITY_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "community_templates"
INDEX_FILE = COMMUNITY_TEMPLATES_DIR / "templates_index.yaml"

_DEFAULT_INDEX_VERSION = "0.1.0"


def _load_index() -> dict:
    """加载社区模板索引，文件缺失或损坏时返回空结构。"""
    empty = {"version": _DEFAULT_INDEX_VERSION, "templates": []}
    if not INDEX_FILE.exists():
        return empty
    try:
        with open(INDEX_FILE, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return empty
    if not isinstance(data, dict):
        return empty
    data.setdefault("version", _DEFAULT_INDEX_VERSION)
    data.setdefault("templates", [])
    return data


def list_community_templates() -> list:
    """返回社区模板元数据列表（name/author/cve/severity/tested 等）。"""
    return list(_load_index().get("templates", []))


def get_template_by_name(name: str) -> dict | None:
    """按模板名称查询元数据，未找到返回 None。"""
    for item in list_community_templates():
        if item.get("name") == name:
            return item
    return None


def count_community_templates() -> int:
    """返回社区模板总数。"""
    return len(list_community_templates())
