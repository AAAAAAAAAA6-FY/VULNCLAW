# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/cache.py
"""R3 迁移兼容存根：实现已迁至 vulnclaw.core_modules.cache。"""

from vulnclaw.core_modules.cache import (  # noqa: F401
    CacheBackend,
    FileCache,
    MemoryCache,
    cache,
    get_cache,
)

__all__ = ['CacheBackend', 'MemoryCache', 'FileCache', 'get_cache', 'cache']
