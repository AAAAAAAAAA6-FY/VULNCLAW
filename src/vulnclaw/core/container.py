# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/container.py
"""
轻量依赖注入容器（P3-2）。

用于替代"模块级全局单例直连"，提供：
- register / register_factory：注册实例或工厂；
- override：测试时注入 mock（优先级高于 register），使单元测试不再依赖真实 .env；
- get / resolve / has：取值；resolve 未注册时抛 KeyError 便于尽早发现缺失依赖。

不引入第三方库，线程安全（RLock）。
"""
import threading
from typing import Any, Callable, Dict, Optional


class Container:
    """线程安全的轻量 DI 容器。"""

    def __init__(self) -> None:
        self._registry: Dict[str, Any] = {}
        self._overrides: Dict[str, Any] = {}
        self._lock = threading.RLock()

    def register(self, name: str, instance: Any) -> None:
        """注册实例（override 存在时仍以 override 优先）。"""
        with self._lock:
            self._registry[name] = instance

    def register_factory(self, name: str, factory: Callable[[], Any]) -> None:
        """注册工厂并立即求值一次。"""
        with self._lock:
            self._registry[name] = factory()

    def get(self, name: str, default: Any = None) -> Any:
        """取值，未注册时返回 default。"""
        with self._lock:
            if name in self._overrides:
                return self._overrides[name]
            return self._registry.get(name, default)

    def resolve(self, name: str) -> Any:
        """取值，未注册时抛 KeyError。"""
        with self._lock:
            if name in self._overrides:
                return self._overrides[name]
            return self._registry[name]

    def override(self, name: str, mock: Any) -> None:
        """测试注入 mock：优先级高于 register，无需改动生产代码。"""
        with self._lock:
            self._overrides[name] = mock

    def clear_overrides(self) -> None:
        with self._lock:
            self._overrides.clear()

    def reset(self) -> None:
        with self._lock:
            self._registry.clear()
            self._overrides.clear()

    def has(self, name: str) -> bool:
        with self._lock:
            return name in self._registry or name in self._overrides


_container = Container()


def get_container() -> Container:
    """全局容器单例。"""
    return _container


__all__ = ["Container", "get_container"]
