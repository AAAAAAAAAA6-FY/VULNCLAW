# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""分布式扫描入口适配模块。

R2 拆分后实现已迁移至 vulnclaw.runners.distributed_runner，此处保持旧调用方兼容。
"""

from vulnclaw.runners.distributed_runner import (  # noqa: F401
    run_distributed_master,
    run_distributed_worker,
)

__all__ = ["run_distributed_master", "run_distributed_worker"]
