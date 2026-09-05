# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP16.3（A 线）调用链上下文：轻量符号索引 + 入口可达性 单元测试。

覆盖（全部离线，零三方依赖）：
- symbol_index：正则索引提取 def 定义行 + 紧邻装饰器（tree-sitter 缺失自动降级）；
- entry_reachability：reachable / unreachable / unknown 三态判定；
- enrich_findings：副本语义（不改入参）与字段注入；
- 非 python / 空路径不崩溃。
"""
import os

from vulnclaw.code.graph import (
    TREE_SITTER_AVAILABLE,
    enrich_findings,
    entry_reachability,
    is_source_file,
    symbol_index,
)

_APP = """import os

@app.route("/login")
def login():
    return validate(req.data)

def validate(data):
    return _lookup(data)

def _lookup(data):
    return sql(data)      # sink line

def sql(q):
    return q
"""

_HELPER = """def helper():
    return 1
"""


def _write(tmp_path, name: str, text: str):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


# ---------- symbol_index ----------

def test_symbol_index_captures_defs_and_decorators(tmp_path):
    p = _write(tmp_path, "app.py", _APP)
    idx = symbol_index([p], use_tree_sitter=False)
    assert idx[p]["login"]["line"] == 4
    assert "route" in idx[p]["login"]["decorators"]
    assert idx[p]["sql"]["line"] == 13  # 定义行（按 _APP 逐行计数）


def test_symbol_index_directory_walk(tmp_path):
    _write(tmp_path, "a.py", _APP)
    _write(tmp_path, "b.txt", "no py")
    sub = tmp_path / "mod"
    sub.mkdir()
    _write(sub, "c.py", _HELPER)
    idx = symbol_index([str(tmp_path)], use_tree_sitter=False)
    names = {k for d in idx.values() for k in d}
    assert "login" in names and "helper" in names


def test_symbol_index_empty_paths():
    assert symbol_index([], use_tree_sitter=False) == {}


# ---------- entry_reachability ----------

def test_reachable_via_decorator_entry(tmp_path):
    p = _write(tmp_path, "app.py", _APP)
    idx = symbol_index([p], use_tree_sitter=False)
    finding = {"abs_path": p, "line": 13}  # sql(data) 调用点
    assert entry_reachability(finding, idx) == "reachable"


def test_unreachable_isolated_helper(tmp_path):
    p = _write(tmp_path, "helper.py", _HELPER)
    idx = symbol_index([p], use_tree_sitter=False)
    finding = {"abs_path": p, "line": 2}
    assert entry_reachability(finding, idx) == "unreachable"


def test_unknown_when_index_missing(tmp_path):
    finding = {"abs_path": str(tmp_path / "no.py"), "line": 1}
    assert entry_reachability(finding, {}) == "unknown"


def test_unknown_when_no_line():
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "x.py")
    assert entry_reachability({"abs_path": p, "line": 0}, {}) == "unknown"  # line=0 直接 unknown


# ---------- enrich_findings ----------

def test_enrich_findings_injects_reachability(tmp_path):
    p = _write(tmp_path, "app.py", _APP)
    findings = [
        {"title": "sink", "line": 13, "abs_path": p, "file": "app.py"},
        {"title": "noline", "abs_path": p, "file": "app.py"},
    ]
    out = enrich_findings(findings, [p], use_tree_sitter=False)
    assert out[0].get("reachability") == "reachable"
    assert "reachability" not in out[1]  # unknown 不写字段
    assert findings[0].get("reachability") is None  # 副本语义


def test_enrich_findings_empty_no_crash():
    assert enrich_findings([], ["dummy"]) == []
    assert enrich_findings([{"title": "x"}], []) == [{"title": "x"}]


def test_is_source_file():
    assert is_source_file("a/b.py") and not is_source_file("a/b.go")


# ---------- tree-sitter 可用性 ----------

def test_ts_flag_is_bool():
    assert isinstance(TREE_SITTER_AVAILABLE, bool)