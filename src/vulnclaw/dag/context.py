# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# dag/context.py
import asyncio
from typing import Any, Dict


class DAGContext:
    """共享上下文（Blackboard）用于 DAG 节点间数据传递"""

    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._lock = asyncio.Lock()
        # P1-3: 节点重试计数（可观测 / 报告）
        self.node_retries: Dict[str, int] = {}

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            self._data[key] = value

    async def get(self, key: str, default: Any = None) -> Any:
        async with self._lock:
            return self._data.get(key, default)

    async def update(self, key: str, value: Any) -> None:
        async with self._lock:
            if key in self._data and isinstance(self._data[key], list) and isinstance(value, list):
                self._data[key].extend(value)
            elif key in self._data and isinstance(self._data[key], dict) and isinstance(value, dict):
                self._data[key].update(value)
            else:
                self._data[key] = value

    async def get_and_clear(self, key: str) -> Any:
        async with self._lock:
            return self._data.pop(key, None)

    async def get_all(self) -> Dict[str, Any]:
        async with self._lock:
            return dict(self._data)

    async def clear(self) -> None:
        async with self._lock:
            self._data.clear()

    async def has(self, key: str) -> bool:
        async with self._lock:
            return key in self._data

    async def record_node_retry(self, node_id: str) -> int:
        """P1-3: 记录节点一次重试，返回累计重试次数。"""
        async with self._lock:
            self.node_retries[node_id] = self.node_retries.get(node_id, 0) + 1
            return self.node_retries[node_id]

    async def get_node_retries(self, node_id: str) -> int:
        """P1-3: 读取节点累计重试次数。"""
        async with self._lock:
            return self.node_retries.get(node_id, 0)