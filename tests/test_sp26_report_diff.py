# SPDX-License-Identifier: AGPL-3.0-or-later
"""SP26: scan_diff 自动基线单元测试（report_diff.py）。"""
import json

from vulnclaw.config.settings import settings
from vulnclaw.core.report_diff import _diff_reports, _signature, maybe_diff_baseline


def _v(url, title):
    return {"url": url, "title": title}


def test_signature():
    assert _signature(_v("http://a/x?y=1", "SQLi")) == "http://a/x?y=1|SQLi"
    assert _signature({}) == "|"


def test_diff_reports():
    prev = [_v("http://a/p1", "XSS"), _v("http://a/p2", "SQLi")]
    cur = [_v("http://a/p1", "XSS"), _v("http://a/p3", "RCE")]
    d = _diff_reports(prev, cur)
    assert len(d["added"]) == 1 and d["added"][0]["title"] == "RCE"
    assert len(d["fixed"]) == 1 and d["fixed"][0]["title"] == "SQLi"


def test_maybe_diff_baseline_disabled(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "scan_diff", False)
    maybe_diff_baseline({"vulnerabilities": []}, "t", "t", tmp_path)
    assert not (tmp_path / "t.json").exists()


def test_maybe_diff_baseline_first_and_second(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(settings, "scan_diff", True)
    monkeypatch.setattr(settings, "scan_diff_baseline", "")
    monkeypatch.setattr("vulnclaw.core.report_diff._default_baseline_path",
                        lambda st: str(tmp_path / f"{st}.json"))
    report1 = {"target": "t", "vulnerabilities": [_v("http://a/p1", "XSS")]}
    maybe_diff_baseline(report1, "t", "t", None)
    assert (tmp_path / "t.json").exists()
    assert "建立基线" in capsys.readouterr().out

    report2 = {"target": "t", "vulnerabilities": [_v("http://a/p1", "XSS"), _v("http://a/p2", "SQLi")]}
    maybe_diff_baseline(report2, "t", "t", None)
    out = capsys.readouterr().out
    assert "新增 1" in out
    assert "已修复 0" in out


def test_explicit_baseline_readonly(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "scan_diff", True)
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"vulnerabilities": [_v("http://a/old", "OLD")]}), encoding="utf-8")
    monkeypatch.setattr(settings, "scan_diff_baseline", str(base))
    content_before = base.read_text(encoding="utf-8")
    maybe_diff_baseline({"target": "t", "vulnerabilities": [_v("http://a/new", "NEW")]}, "t", "t", None)
    assert base.read_text(encoding="utf-8") == content_before