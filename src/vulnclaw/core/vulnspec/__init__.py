# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""声明式漏洞知识库（vulnspec）——"加数据不加代码"的承载层。

一个漏洞类型 = 一条**声明**（数据），而不是一个引擎（代码）：

    id / name / category
    payloads        -> 注入什么
    locations       -> 注入到哪些可控点（query/header/json/path…）
    param_hints     -> 只对匹配的参数名生效（可选，缩小面）
    detect          -> oracle：regex / reflect / time / diff
    severity / cvss / confidence / remediation

新增一种漏洞 = 加一条声明；引擎数量不再随漏洞类型增长。
"""
from .model import DetectRule, VulnSpec, from_dict, validate
from .builtin import BUILTIN_SPECS, get_spec, iter_specs
from .runner import SpecRunner


__all__ = [
    "VulnSpec",
    "DetectRule",
    "from_dict",
    "validate",
    "BUILTIN_SPECS",
    "get_spec",
    "iter_specs",
    "SpecRunner",
]
