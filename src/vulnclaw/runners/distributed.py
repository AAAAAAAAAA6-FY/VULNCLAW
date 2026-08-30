# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Distributed runner facade（R2 拆分后指向 vulnclaw.runners.distributed_runner）。"""

from vulnclaw.runners.distributed_runner import (  # noqa: F401
    run_distributed_master,
    run_distributed_worker,
)

__all__ = ["run_distributed_master", "run_distributed_worker"]
