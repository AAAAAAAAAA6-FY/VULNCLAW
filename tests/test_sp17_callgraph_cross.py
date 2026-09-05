# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP17.2（A 线）跨文件 import 调用图 单元测试。

覆盖（全部离线，零三方依赖）：
- import_index：绝对/相对导入解析（import X / import X as Y / from X import a /
  from . import a / from .mod import name）；
- build_cross_graph：产出 module.func 形态的跨文件调用；
- entry_reachability（cross=...）：跨文件 reachable / unreachable / unknown；
- enrich_findings(use_cross)：开/关行为差异（use_cross=False 保持旧版同文件行为，
  与 test_sp16_graph.py 一致性）；
- tree-sitter 缺失时（monkeypatch TREE_SITTER_AVAILABLE=False）正则模式仍工作。
"""
import pytest

from vulnclaw.code import graph
from vulnclaw.code.graph import (
    build_cross_graph,
    enrich_findings,
    entry_reachability,
    import_index,
    symbol_index,
)

_APP = """import helper

@app.route("/login")
def handler():
    return helper.func(req)
"""

_HELPER = """import sink


def func(data):
    return sink.dangerous_func(data)
"""

_SINK = """def dangerous_func(q):
    return q
"""

_ORPHAN = """def isolated_sink(x):
    return x
"""


def _write(tmp_path, name: str, text: str, sub: str | None = None):
    base = tmp_path / sub if sub else tmp_path
    p = base / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return str(p)


def _make_cross_project(tmp_path) -> dict:
    """构造 app -> helper -> sink 的跨文件调用小工程（含一个 import 链外孤儿）。"""
    paths = {
        "app": _write(tmp_path, "app.py", _APP),
        "helper": _write(tmp_path, "helper.py", _HELPER),
        "sink": _write(tmp_path, "sink.py", _SINK),
        "orphan": _write(tmp_path, "orphan.py", _ORPHAN),
    }
    return paths


@pytest.fixture(autouse=True)
def _no_ts(monkeypatch):
    # 保证运行确定：无论环境是否安装 tree-sitter，本套测试走正则路径校验。
    monkeypatch.setattr(graph, "TREE_SITTER_AVAILABLE", False)


# ---------- import_index ----------

def test_import_index_absolute(tmp_path):
    idx = _make_cross_project(tmp_path)
    imp = import_index([str(tmp_path)])
    assert imp["helper"] == idx["helper"]
    assert imp["sink"] == idx["sink"]


def test_import_index_alias(tmp_path):
    _write(tmp_path, "helper.py", _HELPER)
    _write(tmp_path, "main.py", "import helper as h\n\nh.func(1)\n")
    imp = import_index([str(tmp_path)])
    assert imp["helper"] == str(tmp_path / "helper.py")
    assert imp["h"] == str(tmp_path / "helper.py")


def test_import_index_from_import(tmp_path):
    _write(tmp_path, "helper.py", "def func(): return 1\n")
    _write(tmp_path, "main.py", "from helper import func\n\nfunc()\n")
    imp = import_index([str(tmp_path)])
    assert imp["helper"] == str(tmp_path / "helper.py")


def test_import_index_relative_pkg(tmp_path):
    pkg = tmp_path / "pkg"
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/a.py", "def top_a(): return 1\n")
    sub = pkg / "sub"
    _write(tmp_path, "pkg/sub/__init__.py", "")
    _write(tmp_path, "pkg/sub/c.py", "def c(): return 1\n")
    _write(tmp_path, "pkg/sub/b.py", "from . import c\nfrom .. import a\n")
    imp = import_index([str(tmp_path)])
    assert imp["pkg.sub.c"] == str(sub / "c.py")
    assert imp["pkg.a"] == str(pkg / "a.py")


def test_import_index_unresolvable_skipped(tmp_path):
    _write(tmp_path, "main.py", "import hypothetical_mod_zzz\nimport another_missing_xyz\n")
    imp = import_index([str(tmp_path)])
    assert imp == {}


# ---------- build_cross_graph ----------

def test_build_cross_graph_module_dot_func(tmp_path):
    idx = _make_cross_project(tmp_path)
    g = build_cross_graph([str(tmp_path)], use_tree_sitter=False)
    app_abs = idx["app"]
    helper_abs = idx["helper"]
    assert "helper.func" in g[app_abs]["handler"]
    assert "sink.dangerous_func" in g[helper_abs]["func"]
    # 裸函数名（同文件调用形态）与限定形态并存
    assert "func" in g[app_abs]["handler"]
    assert "dangerous_func" in g[helper_abs]["func"]


# ---------- entry_reachability (cross) ----------

def test_cross_reachable(tmp_path):
    idx = _make_cross_project(tmp_path)
    cg = build_cross_graph([str(tmp_path)], use_tree_sitter=False)
    finding = {"abs_path": idx["sink"], "line": 1}
    assert entry_reachability(finding, symbol_index([str(tmp_path)], use_tree_sitter=False), cross=cg) == "reachable"


def test_cross_unreachable_orphan(tmp_path):
    idx = _make_cross_project(tmp_path)
    cg = build_cross_graph([str(tmp_path)], use_tree_sitter=False)
    finding = {"abs_path": idx["orphan"], "line": 1}
    assert entry_reachability(finding, symbol_index([str(tmp_path)], use_tree_sitter=False), cross=cg) == "unreachable"


def test_cross_unknown_when_index_missing(tmp_path):
    _make_cross_project(tmp_path)
    cg = build_cross_graph([str(tmp_path)], use_tree_sitter=False)
    finding = {"abs_path": str(tmp_path / "nope.py"), "line": 1}
    assert entry_reachability(finding, symbol_index([str(tmp_path)], use_tree_sitter=False), cross=cg) == "unknown"


# ---------- enrich_findings use_cross 开关 ----------

def test_enrich_use_cross_off_keeps_legacy(tmp_path):
    idx = _make_cross_project(tmp_path)
    findings = [{"title": "sink", "line": 1, "abs_path": idx["sink"], "file": "sink.py"}]
    # 关闭跨文件：同文件模式找不到入口 -> unreachable（与 SP16 一致）
    out_off = enrich_findings(findings, [str(tmp_path)], use_tree_sitter=False)
    assert out_off[0].get("reachability") == "unreachable"
    # 开启跨文件：经 helper.func 链到 @app.route 入口 -> reachable
    out_on = enrich_findings(findings, [str(tmp_path)], use_tree_sitter=False, use_cross=True)
    assert out_on[0].get("reachability") == "reachable"
    # 副本语义：入参不被修改
    assert findings[0].get("reachability") is None


def test_enrich_use_cross_orphan_still_unreachable(tmp_path):
    idx = _make_cross_project(tmp_path)
    findings = [{"title": "orphan", "line": 1, "abs_path": idx["orphan"], "file": "orphan.py"}]
    out = enrich_findings(findings, [str(tmp_path)], use_tree_sitter=False, use_cross=True)
    assert out[0].get("reachability") == "unreachable"


# ---------- tree-sitter 缺失（monkeypatch）下正则全流程仍工作 ----------

def test_regex_full_flow_without_tree_sitter(tmp_path, monkeypatch):
    monkeypatch.setattr(graph, "TREE_SITTER_AVAILABLE", False)
    idx = _make_cross_project(tmp_path)
    imp = import_index([str(tmp_path)])
    assert imp["helper"] == idx["helper"]
    g = build_cross_graph([str(tmp_path)], use_tree_sitter=True)
    assert "helper.func" in g[idx["app"]]["handler"]
    finding = {"abs_path": idx["sink"], "line": 1}
    assert entry_reachability(finding, symbol_index([str(tmp_path)], use_tree_sitter=True), cross=g) == "reachable"
    out = enrich_findings([finding], [str(tmp_path)], use_tree_sitter=True, use_cross=True)
    assert out[0].get("reachability") == "reachable"


# ---------- 兼容性烟测：legacy 同文件入口在跨文件开关下不回归 ----------

def test_legacy_samefile_entry_still_reachable(tmp_path):
    _write(tmp_path, "app.py", _APP)
    idx = symbol_index([str(tmp_path)], use_tree_sitter=False)
    finding = {"abs_path": str(tmp_path / "app.py"), "line": 5}
    # 同文件链路（handler -> helper.func 的裸名 func）应 reachable，且不报错
    assert entry_reachability(finding, idx) == "reachable"
