# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Compatibility wrapper for settings.

This module is retained for backward compatibility. The canonical configuration
source lives in ``vulnclaw.config.settings``. Importing from ``core.settings``
should resolve to the exact same singleton instance used elsewhere in the app.
"""

from vulnclaw.config.settings import PROJECT_CACHE_DIR, PROJECT_ROOT, Settings, TMP_DIR, settings

__all__ = ["Settings", "settings", "TMP_DIR", "PROJECT_CACHE_DIR", "PROJECT_ROOT"]
