# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Health runner facade（R2 拆分后指向 vulnclaw.runners.health_runner）。"""

from vulnclaw.runners.health_runner import run_health_check

__all__ = ["run_health_check"]
