# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/business_ir/store.py
"""IR 持久化 —— 按目标落盘 `_runtime_cache/ir/<host>.json`。

**幂等**是硬要求（验收项）：`json.dumps(sort_keys=True)` + 正文不含时间戳/随机数
→ 同一 IR 反复保存得到**逐字节相同**的文件，便于 diff 与缓存命中。
"""
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from vulnclaw.core.logger import logger
from vulnclaw.paths import RUNTIME_DIR

__all__ = ["ir_dir", "ir_path", "save_ir", "load_ir", "host_of"]

IR_SUBDIR = "ir"
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def host_of(target: str) -> str:
    """target → 安全文件名（host[_port]）。畸形输入退化为 'unknown'。"""
    t = str(target or "").strip()
    if t and not t.startswith(("http://", "https://")):
        t = "http://" + t
    try:
        p = urlparse(t)
    except ValueError:
        return "unknown"
    host = p.hostname or ""
    if not host:
        return "unknown"
    name = host + (f"_{p.port}" if p.port else "")
    return _SAFE.sub("_", name)[:120] or "unknown"


def ir_dir() -> Path:
    d = Path(RUNTIME_DIR) / IR_SUBDIR
    try:
        os.makedirs(d, exist_ok=True)
    except OSError as exc:
        logger.debug(f"[IR] 建目录失败（忽略）: {exc}")
    return d


def ir_path(target: str) -> Path:
    return ir_dir() / f"{host_of(target)}.json"


def save_ir(ir: Dict[str, Any], target: str = "") -> Optional[str]:
    """保存 IR；返回落盘路径，失败返回 None（绝不抛）。"""
    if not isinstance(ir, dict) or not ir:
        return None
    tgt = str(target or ir.get("target") or "")
    try:
        p = ir_path(tgt)
        blob = json.dumps(ir, ensure_ascii=False, sort_keys=True, indent=1)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(blob)
        return str(p)
    except (OSError, TypeError, ValueError) as exc:
        logger.debug(f"[IR] 保存失败（忽略）: {exc}")
        return None


def load_ir(target: str) -> Dict[str, Any]:
    """读取 IR；不存在/损坏 → {}（fail-closed）。"""
    try:
        p = ir_path(target)
        if not p.exists():
            return {}
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        logger.debug(f"[IR] 读取失败（忽略）: {exc}")
        return {}
