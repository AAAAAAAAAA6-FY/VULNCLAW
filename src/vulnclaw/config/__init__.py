# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""配置模块"""
from .settings import settings, PROJECT_CACHE_DIR, TMP_DIR  # noqa: F401
__all__ = ["settings", "PROJECT_CACHE_DIR", "TMP_DIR"]