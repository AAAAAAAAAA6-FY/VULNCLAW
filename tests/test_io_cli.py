# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
"""importers / exporters CLI 形式对接验收（薄封装 core.interop）。

设计意图：这两个 CLI **不得重复实现解析/渲染逻辑**——用例只验证"分派正确 + 退出码
契约 + 输入输出形状"，字段级语义由 tests/test_interop.py 负责（避免两处断言同一件事）。

覆盖：
  1) importers：nuclei_jsonl → 统一模型 JSON（imported/格式名/字段存在）
  2) importers：未知格式 → 退出码 1（显式失败，不静默降级）
  3) importers/exporters：--list-formats 输出注册表
  4) exporters：报告 JSON → SARIF / CSV（stdout）
  5) exporters：空报告 → 空清单且退出 0（不是错误）
  6) 真实 CLI 路径：`python -m scripts.importers.cli --list-formats` 可运行
"""
import importlib.util
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: 与 tests/test_interop.py 同源的 nuclei 最小样本（字段口径一致，避免自造样例漂移）
_NUCLEI_SAMPLE = json.dumps({
    "template-id": "CVE-2021-44228",
    "info": {"name": "Log4Shell", "severity": "critical",
             "description": "JNDI injection"},
    "type": "http",
    "host": "t.example",
    "matched-at": "http://t.example/api",
    "matcher-name": "word",
    "extracted-results": ["callback-ok"],
})

_REPORT = {
    "target": "http://t.example",
    "vulnerabilities": [
        {"url": "http://t.example/api?id=1", "type": "SQL Injection", "severity": "Critical",
         "parameter": "id", "evidence": "SQL syntax error near id", "confidence": "高",
         "method": "GET"},
    ],
}


def _load_cli(module_name: str, rel_path: str):
    """按文件路径加载 CLI 模块（不经 scripts 命名空间包，避免环境差异）。"""
    spec = importlib.util.spec_from_file_location(module_name, os.path.join(ROOT, rel_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def import_cli():
    return _load_cli("io_import_cli", os.path.join("scripts", "importers", "cli.py"))


@pytest.fixture(scope="module")
def export_cli():
    return _load_cli("io_export_cli", os.path.join("scripts", "exporters", "cli.py"))


# ============================================================
# importers
# ============================================================
def test_import_cli_nuclei_to_unified(tmp_path, import_cli):
    src = tmp_path / "nuclei.jsonl"
    src.write_text(_NUCLEI_SAMPLE + "\n", encoding="utf-8")
    out = tmp_path / "unified.json"
    rc = import_cli.main(["--format", "nuclei_jsonl", "--input", str(src), "--output", str(out)])
    assert rc == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["format"] == "nuclei_jsonl"
    assert payload["imported"] >= 1, f"nuclei 样本应至少导入 1 条: {payload}"
    f0 = payload["findings"][0]
    assert f0.get("type") or f0.get("url"), f"统一模型关键字段缺失: {f0}"


def test_import_cli_unknown_format_exit1(tmp_path, import_cli):
    src = tmp_path / "x.txt"
    src.write_text("whatever", encoding="utf-8")
    assert import_cli.main(["--format", "no_such_fmt", "--input", str(src)]) == 1


def test_import_cli_list_formats(import_cli, capsys):
    assert import_cli.main(["--list-formats"]) == 0
    out = capsys.readouterr().out
    for fmt in ("nuclei_jsonl", "burp_xml", "sarif", "raw_http", "vulnclaw_json"):
        assert fmt in out


# ============================================================
# exporters
# ============================================================
def test_export_cli_report_to_sarif(tmp_path, export_cli):
    src = tmp_path / "report.json"
    src.write_text(json.dumps(_REPORT, ensure_ascii=False), encoding="utf-8")
    out = tmp_path / "out.sarif"
    rc = export_cli.main(["--format", "sarif", "--input", str(src), "--output", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc.get("$schema") or doc.get("version") or doc.get("runs") is not None, (
        f"SARIF 结构异常: {list(doc)[:6]}"
    )


def test_export_cli_csv_stdout(tmp_path, export_cli, capsys):
    src = tmp_path / "report.json"
    src.write_text(json.dumps(_REPORT, ensure_ascii=False), encoding="utf-8")
    assert export_cli.main(["--format", "csv", "--input", str(src)]) == 0
    out = capsys.readouterr().out
    assert "sql" in out.lower(), f"CSV 未包含 finding 类型: {out[:200]}"


def test_export_cli_empty_report_is_empty_not_error(tmp_path, export_cli, capsys):
    src = tmp_path / "empty.json"
    src.write_text("{}", encoding="utf-8")
    assert export_cli.main(["--format", "jsonl", "--input", str(src)]) == 0
    assert capsys.readouterr().out.strip() == "", "空输入应输出空清单而非报错"


def test_export_cli_unknown_format_exit1(tmp_path, export_cli):
    src = tmp_path / "r.json"
    src.write_text(json.dumps(_REPORT), encoding="utf-8")
    assert export_cli.main(["--format", "no_such", "--input", str(src)]) == 1


def test_export_cli_list_formats(export_cli, capsys):
    assert export_cli.main(["--list-formats"]) == 0
    out = capsys.readouterr().out
    for fmt in ("sarif", "csv", "burp_xml", "markdown"):
        assert fmt in out


# ============================================================
# 真实 CLI 路径（-m 可运行性）
# ============================================================
def test_cli_runnable_via_dash_m(monkeypatch, capsys):
    """`python -m scripts.importers.cli` 等价路径验证。

    用 runpy（即 `-m` 的内部实现）而非 subprocess：Windows + pytest 下 subprocess 会
    偶发 WinError 6 句柄错误（环境问题，与 CLI 无关）。本用例同时锁死"父包 __init__
    必须先做 sys.path 处理"这一真实修复点。
    """
    import runpy

    monkeypatch.syspath_prepend(str(ROOT))
    monkeypatch.setattr(sys, "argv", ["scripts.importers.cli", "--list-formats"])
    with pytest.raises(SystemExit) as ei:
        runpy.run_module("scripts.importers.cli", run_name="__main__", alter_sys=False)
    assert ei.value.code in (0, None)
    assert "nuclei_jsonl" in capsys.readouterr().out
