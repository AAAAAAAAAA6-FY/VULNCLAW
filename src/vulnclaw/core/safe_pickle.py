# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"安全反序列化：限制 pickle 允许的全局名，结构上杜绝 __reduce__ RCE（allowlist 白名单）。"
"适用于 Redis / DAG 共享上下文的 pickle 兜底分支：JSON 能表达的值优先 JSON，"
"仅当值无法 JSON 序列化时才走 pickle，且加载时用白名单限制，即使缓存被不可信方写入也无法执行任意代码。"

import builtins
import collections
import datetime
import decimal
import fractions
import io
import pickle
from typing import Any

# 允许的全局名白名单：模块名 -> 允许的名称集合。
# 仅放行无 RCE 能力的纯数据类型模块（值对象恢复所需的最小集）。
_ALLOWED_MODULES = {
    "builtins": {
        "NoneType", "bool", "int", "float", "str", "bytes", "bytearray",
        "dict", "list", "tuple", "set", "frozenset", "complex", "range",
        "slice", "object",
    },
    "collections": {"OrderedDict", "defaultdict", "deque", "Counter"},
    "datetime": {"datetime", "date", "time", "timedelta", "timezone"},
    "decimal": {"Decimal"},
    "fractions": {"Fraction"},
}

# 显式黑名单兜底（即使误加白名单模块，也禁止这些危险名）
_BLOCKED_NAMES = {
    "eval", "exec", "compile", "globals", "locals", "vars", "getattr",
    "setattr", "delattr", "__import__", "open", "input", "breakpoint",
    "help", "exit", "quit", "memoryview",
}


def _check_globals(names):
    "逐项校验 (module, name)，任一不在白名单即拒绝。"
    for module_name, name in names:
        if name in _BLOCKED_NAMES:
            raise pickle.UnpicklingError(
                f"pickle 名称命中黑名单: {module_name}.{name}"
            )
        if name not in _ALLOWED_MODULES.get(module_name, {}):
            raise pickle.UnpicklingError(
                f"pickle 全局名不在白名单: {module_name}.{name}"
            )


class SafeUnpickler(pickle.Unpickler):
    "白名单限制版 Unpickler。"

    def find_class(self, module, name):
        _check_globals([(module, name)])
        return super().find_class(module, name)


def safe_pickle_loads(data: bytes, default: Any = None) -> Any:
    "安全反序列化；白名单外全局名 / 解析失败一律返回 default（拒绝污染）。"
    try:
        return SafeUnpickler(io.BytesIO(data)).load()
    except Exception:  # noqa: BLE001 - 恶意/损坏数据按 default 处理
        return default


def json_able(value: Any) -> bool:
    "判断顶层值是否可直接 JSON 序列化（str/int/float/bool/None/dict/list）。"
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, (dict, list)):
        return True
    return False
