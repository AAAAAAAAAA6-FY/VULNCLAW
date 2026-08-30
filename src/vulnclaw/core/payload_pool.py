# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/payload_pool.py
"""
统一 Payload 池 - 所有引擎的 Payload 集中管理（v102）。

数据源：core/data/payload_pool.yaml
引擎只需声明 payload_pool 名称（或子类别 key），即可从池加载 Payload；
新增/修改 Payload 只需编辑 YAML，无需改动引擎代码。

YAML 结构（两级嵌套，v100 已建立）：
    pool_name:
      subcategory:
        - payload: "xxx"        # dict 形式（带描述/元数据）
          description: "yyy"
        - "纯字符串"             # 简写形式（描述取子类别名）

API 一览：
    PayloadPool.get(name[, subcategory])          -> List[Any]          原始条目
    PayloadPool.get_raw(name)                     -> Dict                原始两级结构
    PayloadPool.load(name[, subcategory])         -> List[Tuple[str,str]] (payload, desc)
    PayloadPool.load_dicts(name[, subcategory])   -> List[Dict]          保留元数据的条目
    PayloadPool.reload()                          -> None                清缓存
"""
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from vulnclaw.core.logger import logger

_POOL_PATH = Path(__file__).parent / "data" / "payload_pool.yaml"

_lock = threading.Lock()
_cache: Dict[str, Any] = {}


class PayloadPool:
    """Payload 池加载器（进程内缓存 + 线程安全）。"""

    @classmethod
    def _load_raw(cls) -> Dict[str, Any]:
        global _cache
        with _lock:
            if _cache:
                return _cache
            data = {}
            try:
                with open(_POOL_PATH, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f) or {}
                data = loaded if isinstance(loaded, dict) else {}
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"⚠️ Payload 池加载失败 {_POOL_PATH.name}: {exc}")
            _cache = data
            return data

    @classmethod
    def reload(cls) -> None:
        """清空缓存，下次访问重新读取 YAML。"""
        global _cache
        with _lock:
            _cache = {}

    @classmethod
    def get_raw(cls, name: str) -> Dict[str, Any]:
        """返回某池的原始嵌套结构 {subcategory: [...]}，不存在返回 {}。"""
        raw = cls._load_raw().get(name)
        return raw if isinstance(raw, dict) else {}

    @classmethod
    def get(cls, name: str, subcategory: Optional[str] = None) -> List[Any]:
        """返回某池（或某子类别）的 payload 原始列表。

        - 指定 subcategory：仅返回该子类别条目
        - 未指定：返回该池全部子类别条目（扁平拼接）
        """
        raw = cls.get_raw(name)
        if not raw:
            return []
        if subcategory is not None:
            items = raw.get(subcategory)
            return items if isinstance(items, list) else []
        items: List[Any] = []
        for sub, lst in raw.items():
            if isinstance(lst, list):
                items.extend(lst)
        return items

    @classmethod
    def load(cls, name: str, subcategory: Optional[str] = None, with_desc: bool = True) -> List[Tuple[str, str]]:
        """返回 (payload, description) 二元组列表，供引擎的 payloads 属性使用。

        简写字符串 -> (str, 子类别名)；dict -> (payload, description)。
        """
        result: List[Tuple[str, str]] = []
        raw = cls.get_raw(name)
        if not raw:
            return result
        cats = [subcategory] if subcategory is not None else list(raw.keys())
        for sub in cats:
            for item in raw.get(sub, []) or []:
                if isinstance(item, dict):
                    payload = item.get("payload")
                    if payload is None:
                        payload = item.get("value", "")
                    desc = item.get("description") or item.get("desc") or str(sub)
                    result.append((str(payload), str(desc)))
                elif isinstance(item, str):
                    result.append((item, str(sub)))
                elif isinstance(item, (int, float)):
                    result.append((str(item), str(sub)))
        return result

    @classmethod
    def load_dicts(cls, name: str, subcategory: Optional[str] = None) -> List[Dict]:
        """返回 dict 形式的 payload 列表（保留全部元数据），供需要额外字段的引擎使用。"""
        result: List[Dict] = []
        raw = cls.get_raw(name)
        if not raw:
            return result
        cats = [subcategory] if subcategory is not None else list(raw.keys())
        for sub in cats:
            for item in raw.get(sub, []) or []:
                if isinstance(item, dict):
                    entry = dict(item)
                    entry.setdefault("_subcategory", sub)
                    result.append(entry)
                elif isinstance(item, str):
                    result.append({"payload": item, "description": str(sub), "_subcategory": sub})
                elif isinstance(item, (int, float)):
                    result.append({"payload": str(item), "description": str(sub), "_subcategory": sub})
        return result


__all__ = ["PayloadPool"]
