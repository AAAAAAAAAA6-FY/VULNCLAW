# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Runner 包（R2 拆分完成）：稳定公共入口，实现见各 *_runner 子模块。

- scan_runner: main_async 扫描主流程 + Cookie 获取链路 + check_environment
- code_audit_runner: run_code_audit 代码审计
- distributed_runner: run_distributed_master / run_distributed_worker
- health_runner: run_health_check 健康检查
"""

from vulnclaw.runners.code_audit_runner import run_code_audit
from vulnclaw.runners.distributed_runner import (  # noqa: F401
    run_distributed_master,
    run_distributed_worker,
)
from vulnclaw.runners.health_runner import run_health_check
from vulnclaw.runners.scan_runner import main_async

# 兼容别名：统一扫描入口
run_scan = main_async

__all__ = [
    "main_async",
    "run_scan",
    "run_code_audit",
    "run_distributed_master",
    "run_distributed_worker",
    "run_health_check",
]
