# SPDX-License-Identifier: AGPL-3.0-or-later
"""SP18 商业化落地：扫描成果归档（A 线）。

- build_scan_archive：生成 out_dir/<scan_id>/ + ARCHIVE.md，携带 HTML/CSV 时一并归档，
  缺失格式跳过不报错
- zip_archive：归档目录整体打成 zip，可被 zipfile 读回且条目数 > 0
- batch_targets：多目标批量规划，含 serial/parallel 分组键，重复目标去重
"""
import os
import zipfile

import pytest

from vulnclaw.core.archive import batch_targets, build_scan_archive, zip_archive


def _finding(url, type_, severity, extra=None):
    f = {"url": url, "type": type_, "severity": severity}
    if extra:
        f.update(extra)
    return f


def _report(findings=None, extra=None):
    findings = findings if findings is not None else [
        _finding("http://a.example.com/p?q=1", "SQL注入", "Critical",
                 {"parameter": "q", "method": "GET"}),
        _finding("http://b.example.com/x", "XSS", "High",
                 {"method": "POST"}),
        _finding("http://c.example.com/y", "XSS", "Medium"),
    ]
    report = {
        "scan_id": "scan-sp18",
        "target": "http://t.example.com",
        "vulnerabilities": findings,
        "distribution": {
            "by_type": {"SQL注入": {"critical": 1}, "XSS": {"high": 1, "medium": 1}},
            "by_severity": {"critical": 1, "high": 1, "medium": 1},
            "ranked_targets": [{"host": "t.example.com", "count": 3}],
        },
    }
    if extra:
        report.update(extra)
    return report


class TestBuildScanArchive:
    def test_creates_archive_dir_with_files_and_manifest(self, tmp_path):
        html = tmp_path / "out" / "report.html"
        csv = tmp_path / "out" / "report.csv"
        html.parent.mkdir(parents=True, exist_ok=True)
        html.write_text("<html>demo</html>", encoding="utf-8")
        csv.write_text("type,severity\nXSS,High\n", encoding="utf-8")
        report = _report(extra={"html_file": str(html), "csv_file": str(csv)})

        archive_dir = build_scan_archive("scan-sp18", report, str(tmp_path / "archives"))

        assert archive_dir == os.path.join(str(tmp_path / "archives" / "scan-sp18"))
        assert os.path.isdir(archive_dir)
        for name in ("report.json", "report.html", "report.csv", "ARCHIVE.md"):
            assert os.path.isfile(os.path.join(archive_dir, name)), name
        md = open(os.path.join(archive_dir, "ARCHIVE.md"), encoding="utf-8").read()
        assert "scan-sp18" in md
        assert "http://t.example.com" in md
        assert "findings 数: 3" in md
        assert "critical: 1" in md  # distribution 摘要
        assert "SQL注入" in md

    def test_missing_report_files_skipped_without_error(self, tmp_path):
        report = _report()  # 无 html_file / csv_file
        archive_dir = build_scan_archive("scan-sp18b", report, str(tmp_path / "archives"))
        assert os.path.isdir(archive_dir)
        assert os.path.isfile(os.path.join(archive_dir, "report.json"))
        assert os.path.isfile(os.path.join(archive_dir, "ARCHIVE.md"))
        assert not os.path.exists(os.path.join(archive_dir, "report.html"))
        assert not os.path.exists(os.path.join(archive_dir, "report.csv"))

    def test_nonexistent_paths_ignored(self, tmp_path):
        report = _report(extra={"html_file": str(tmp_path / "nope.html")})
        archive_dir = build_scan_archive("scan-sp18c", report, str(tmp_path / "archives"))
        assert os.path.isfile(os.path.join(archive_dir, "report.json"))
        assert not os.path.exists(os.path.join(archive_dir, "report.html"))


class TestZipArchive:
    def test_zip_roundtrip_readable_with_entries(self, tmp_path):
        report = _report()
        archive_dir = build_scan_archive("scan-sp18", report, str(tmp_path / "archives"))
        zip_path = str(tmp_path / "scan-sp18.zip")

        result = zip_archive(archive_dir, zip_path)

        assert result == os.path.join(str(tmp_path / "scan-sp18.zip"))
        assert os.path.isfile(zip_path)
        assert os.path.getsize(zip_path) > 0
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            assert len(names) > 0
            assert any(n.endswith("ARCHIVE.md") for n in names)
            assert any(n.endswith("report.json") for n in names)


class TestBatchTargets:
    def test_group_keys_and_dedupe(self):
        targets = ["10.0.0.1", "10.0.0.1", "app.example.com:8443", "app.example.com:9443"]
        plan = batch_targets(targets, {"tier": "full", "ports": [8443, 9443]})

        assert len(plan) == 3  # 重复目标去重
        for item in plan:
            assert "group" in item
            assert "group_id" in item
            assert "cfg" in item
            assert item["cfg"]["tier"] == "full"
        by_target = {item["target"]: item for item in plan}
        assert by_target["10.0.0.1"]["group"] == "parallel"
        assert by_target["app.example.com:8443"]["group"] == "serial"
        assert by_target["app.example.com:9443"]["group"] == "serial"
        # 同一目标多端口共享串行组
        assert by_target["app.example.com:8443"]["group_id"] == by_target["app.example.com:9443"]["group_id"]

    def test_independent_targets_parallel(self):
        plan = batch_targets(["a.example.com", "b.example.com", "c.example.com"], {"tier": "light"})
        assert len(plan) == 3
        assert all(item["group"] == "parallel" for item in plan)
        assert len({item["group_id"] for item in plan}) == 3

    def test_empty_targets(self):
        assert batch_targets([], {"tier": "light"}) == []