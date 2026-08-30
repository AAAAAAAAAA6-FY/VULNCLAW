# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Code audit runner facade（R2 拆分后指向 vulnclaw.runners.code_audit_runner）。"""

from vulnclaw.runners.code_audit_runner import run_code_audit

__all__ = ["run_code_audit"]
