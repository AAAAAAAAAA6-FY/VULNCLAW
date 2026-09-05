# -*- coding: utf-8 -*-  # noqa: UP009 - 平台统一文件头约定
# SPDX-License-Identifier: AGPL-3.0-or-later
"""test_autofix: 自动修复补丁链路（build_patch_plan / write_patch_files / apply_patches / main）。

覆盖：四类漏洞的 plan 生成与 tier/confidence、无 file 降级、补丁文件与 manifest、
dry-run 与真实 apply、坏 JSON / 空 vulnerabilities 不抛错。纯同步测试。
"""
import json
import os

from vulnclaw.core.autofix import apply_patches, build_patch_plan, main, write_patch_files

_PLAN_KEYS = {"finding_id", "type", "severity", "file", "line_hint", "patch", "confidence", "tier"}


def _make_report():
    return {
        "target": "http://example.test",
        "vulnerabilities": [
            {
                "finding_id": "v-001",
                "type": "SQL Injection",
                "severity": "critical",
                "url": "http://example.test/item?id=1",
                "parameter": "id",
                "method": "GET",
                "file": "app.py",
                "line": 10,
                "remediation": "使用参数化查询",
            },
            {
                "finding_id": "v-002",
                "type": "Reflected XSS",
                "severity": "high",
                "file": "templates/view.py",
                "remediation": "输出转义",
            },
            {
                "finding_id": "v-003",
                "type": "hardcoded secret",
                "severity": "high",
                "file": "config.py",
                "remediation": "改用环境变量",
            },
            {
                "finding_id": "v-004",
                "type": "Insecure Deserialization",
                "severity": "medium",
                "remediation": "升级依赖并校验反序列化数据源",
            },
        ],
    }


def test_plan_generation_four_types():
    plan = build_patch_plan(_make_report())
    assert len(plan) == 4
    for item in plan:
        assert _PLAN_KEYS.issubset(item.keys())
    by_type = {item["type"]: item for item in plan}
    assert set(by_type) == {"sql_injection", "xss", "hardcoded_secret", "unknown"}
    # tier / confidence 合理性
    assert by_type["sql_injection"]["tier"] == "critical"
    assert by_type["sql_injection"]["confidence"] == 0.9
    assert by_type["xss"]["tier"] == "high"
    assert by_type["xss"]["confidence"] == 0.85
    assert by_type["hardcoded_secret"]["tier"] == "critical"
    assert by_type["hardcoded_secret"]["confidence"] == 0.9
    assert by_type["unknown"]["tier"] == "low"
    assert by_type["unknown"]["confidence"] < 0.5
    # 已知类型含统一 diff 头
    for key in ("sql_injection", "xss", "hardcoded_secret"):
        patch = by_type[key]["patch"]
        assert patch.startswith("--- a/")
        assert "\n+++ b/" in patch
        assert "@@ " in patch
    # line_hint 进入 hunk 头
    assert "@@ -10 +10,2 @@" in by_type["sql_injection"]["patch"]
    # 未知类型引用 remediation 文本
    assert "反序列化数据源" in by_type["unknown"]["patch"]


def test_no_file_downgrades_to_suggestion():
    report = {"vulnerabilities": [{"type": "SQL Injection", "severity": "high", "remediation": "参数化"}]}
    item = build_patch_plan(report)[0]
    assert item["file"] == ""
    assert item["patch"].startswith("#")
    assert "--- a/" not in item["patch"]
    assert item["confidence"] < 0.5
    assert item["tier"] == "medium"
    assert item.get("suggestion_only") is True


def test_evidence_regex_extracts_file():
    report = {"vulnerabilities": [{"type": "XSS", "evidence": "in src/db.py:42 user_input rendered"}]}
    item = build_patch_plan(report)[0]
    assert item["file"] == "src/db.py"
    assert item["patch"].startswith("--- a/")
    assert item["confidence"] < 0.85
    assert item["tier"] == "medium"


def test_write_patch_files_and_manifest(tmp_path):
    plan = build_patch_plan(_make_report())
    paths = write_patch_files(plan, tmp_path)
    assert len(paths) == 4
    for p in paths:
        assert os.path.isfile(p)
        assert p.endswith(".patch")
    manifest_path = os.path.join(tmp_path, "autofix_manifest.json")
    assert os.path.isfile(manifest_path)
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    assert manifest["count"] == 4
    assert manifest["patch_count"] == 4
    assert len(manifest["patches"]) == 4
    assert len(manifest["plan"]) == 4
    assert manifest["skipped"] == []


def test_apply_patches_dry_run_and_real(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "app.py"
    target.write_text('cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n', encoding="utf-8")
    report = {
        "vulnerabilities": [
            {"type": "SQL Injection", "file": "app.py"},
            {"type": "XSS", "file": "missing_view.py"},
        ]
    }
    plan = build_patch_plan(report)
    # dry_run：只统计，不落盘
    res = apply_patches(plan, str(repo), dry_run=True)
    assert res["dry_run"] is True
    assert res["total"] == 2
    assert res["applicable"] == 1
    assert res["applied"] == 0
    assert len(res["skipped"]) == 1
    assert "file not found" in res["skipped"][0]["reason"]
    assert 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)' in target.read_text(encoding="utf-8")
    # 真实应用
    res2 = apply_patches(plan, str(repo), dry_run=False)
    assert res2["dry_run"] is False
    assert res2["applied"] == 1
    new_text = target.read_text(encoding="utf-8")
    assert "%s" in new_text
    assert "参数化查询" in new_text


def test_main_cli_with_apply_writes_file(tmp_path):
    repo = tmp_path / "repo2"
    repo.mkdir()
    target = repo / "config.py"
    target.write_text('API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxx"\n', encoding="utf-8")
    report = {"vulnerabilities": [{"type": "hardcoded secret", "file": "config.py"}]}
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    out_dir = tmp_path / "out"
    rc = main(["--report", str(report_path), "--out-dir", str(out_dir), "--repo", str(repo), "--apply"])
    assert rc == 0
    assert (out_dir / "autofix_manifest.json").is_file()
    assert "os.environ" in target.read_text(encoding="utf-8")


def test_bad_json_and_empty_vulnerabilities_no_raise(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    out_dir = tmp_path / "out_bad"
    rc = main(["--report", str(bad), "--out-dir", str(out_dir)])
    assert rc == 0
    assert (out_dir / "autofix_manifest.json").is_file()
    # 空 / 非 dict / 非列表输入一律不抛错
    assert build_patch_plan({}) == []
    assert build_patch_plan(None) == []
    assert build_patch_plan("nope") == []
    assert build_patch_plan({"vulnerabilities": []}) == []
    assert build_patch_plan({"vulnerabilities": "bad"}) == []
    # 缺 --report 返回用法码
    assert main([]) == 2
