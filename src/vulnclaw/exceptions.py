# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""
VULNCLAW 统一异常定义
"""

class VULNCLAWError(Exception):
    """所有项目异常的基类"""
    pass

class ConfigurationError(VULNCLAWError):
    """配置错误"""
    pass

class EngineError(VULNCLAWError):
    """引擎执行错误"""
    pass

class ToolError(VULNCLAWError):
    """工具调用错误"""
    pass

class ScanTimeoutError(VULNCLAWError):
    """扫描超时"""
    pass

class TargetUnreachableError(VULNCLAWError):
    """目标不可达"""
    pass