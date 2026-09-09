# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""B 方案: 双会话差分业务逻辑 oracle（专治水平越权）。

- identity_matrix.IdentityMatrix: A/B 双身份矩阵（真实第2角色 → 第二账号文件 → 匿名兜底）
- diff_oracle.dual_session_probe / oracle_verdict: 并发双发差分 + 三态判定（fail-closed）
"""

from vulnclaw.core.biz_oracle.identity_matrix import IdentityMatrix
from vulnclaw.core.biz_oracle.diff_oracle import dual_session_probe, oracle_verdict

__all__ = ["IdentityMatrix", "dual_session_probe", "oracle_verdict"]
