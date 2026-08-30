# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# dag/resources.py
import asyncio
from contextlib import asynccontextmanager
from .graph import NodeType
from typing import Dict, Optional


_RESOURCE_DEFAULTS = {
    "llm": 7,
    "http": 300,
    "nuclei": 2,
    "ffuf": 4,
}

_NODE_TYPE_RESOURCE = {
    NodeType.RECON: "http",
    NodeType.RECON_SUB: "http",
    NodeType.RECON_ALIVE: "http",
    NodeType.RECON_NUCLEI: "nuclei",
    NodeType.RECON_JS: "http",
    NodeType.RECON_PORT: "http",
    NodeType.RECON_FFUF: "ffuf",
    NodeType.ATTACK: "llm",
    NodeType.VERIFY: "llm",
    NodeType.EXPLOIT: "http",
    NodeType.REPORT: "llm",
    NodeType.SUBGRAPH: "http",
}


class ResourceGovernor:
    """资源票池 - 按 node_type 分配不同资源令牌，防止同类重资源并发过载"""

    def __init__(self, limits: Optional[Dict[str, int]] = None):
        cfg = {**_RESOURCE_DEFAULTS, **(limits or {})}
        self._limits: Dict[str, int] = dict(cfg)
        self._semaphores: Dict[str, asyncio.Semaphore] = {
            name: asyncio.Semaphore(cap) for name, cap in self._limits.items()
        }
        self._acquired: Dict[str, int] = {name: 0 for name in self._limits}

    def resource_for(self, node_type: NodeType) -> str:
        return _NODE_TYPE_RESOURCE.get(node_type, "http")

    @asynccontextmanager
    async def acquire(self, node_type: NodeType):
        resource = self.resource_for(node_type)
        sem = self._semaphores.get(resource)
        if sem is None:
            yield
            return
        await sem.acquire()
        self._acquired[resource] += 1
        try:
            yield
        finally:
            self._acquired[resource] -= 1
            sem.release()

    async def run_with_acquire(self, node_type: NodeType, coro):
        async with self.acquire(node_type):
            return await coro

    def status(self) -> Dict[str, Dict[str, int]]:
        return {
            name: {
                "limit": self._limits[name],
                "acquired": self._acquired[name],
                "available": self._limits[name] - self._acquired[name],
            }
            for name in self._limits
        }