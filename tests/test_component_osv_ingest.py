# -*- coding: utf-8 -*-
"""P2-③ 组件 CVE→声明流水线单元测试（growth.component_osv_ingest）。

依赖 OSV 离线 KB（thirdparty/osv/component_kb.json，本地生成物、已 gitignore），
KB 不在时整组 skip。
"""
import os
import re

import pytest

KB = os.path.join("thirdparty", "osv", "component_kb.json")

pytestmark = pytest.mark.skipif(
    not os.path.exists(KB), reason="OSV KB 未构建（thirdparty 已 gitignore）")

from vulnclaw.growth.component_osv_ingest import ComponentOsvIngest, _pkg_pattern  # noqa: E402


@pytest.fixture()
def ing(tmp_path):
    return ComponentOsvIngest(drafts_path=str(tmp_path / "d.jsonl"))


class TestPkgPattern:
    def test_requirements_txt_form(self):
        rx = re.compile(_pkg_pattern("lodash"), re.IGNORECASE)
        m = rx.search('lodash==4.17.20')
        assert m and m.group(1) == "4.17.20"

    def test_package_json_form(self):
        rx = re.compile(_pkg_pattern("lodash"))
        m = rx.search('"lodash": "^4.17.15"')
        assert m and m.group(1) == "4.17.15"


class TestIngest:
    def test_lodash_vulnerable_version_drafts(self, ing):
        """lodash 4.17.20（< 4.17.21，已知 CVE 区间）→ validated 草稿"""
        d = ing.ingest("npm", "lodash", "4.17.20")
        assert d is not None
        assert d["status"] == "validated"
        assert d["signatures"]
        assert all(s.get("cve", "").startswith("CVE") or s.get("cve") for s in d["signatures"])

    def test_fixed_version_no_draft(self, ing):
        """已修复版本（不在任何影响区间）→ None，不产草稿"""
        d = ing.ingest("npm", "lodash", "999.0.0")
        assert d is None

    def test_idempotent(self, ing):
        """同 rule_id 二次摄入 → skipped_existing，不重复落盘"""
        d1 = ing.ingest("npm", "lodash", "4.17.20")
        assert d1 is not None
        n_before = len(ing.drafts())
        d2 = ing.ingest("npm", "lodash", "4.17.20")
        assert d2 is not None and d2["status"] == "skipped_existing"
        assert len(ing.drafts()) == n_before

    def test_unknown_pkg_no_kb(self, ing):
        """KB 没有的包 → None（绝不产出无据草稿）"""
        assert ing.ingest("npm", "this-pkg-does-not-exist-xyz-9999") is None

    def test_patterns_compilable(self, ing):
        """所有草稿 pattern 可编译（validate 的核心保障）"""
        d = ing.ingest("npm", "lodash", "4.17.20")
        assert d is not None
        for s in d["signatures"]:
            re.compile(s["pattern"])

    def test_batch_stats(self, ing):
        stats = ing.ingest_batch([("npm", "lodash", "4.17.20"),
                                  ("npm", "this-pkg-does-not-exist-xyz-9999")])
        assert stats["total"] == 2
        assert stats["validated"] == 1
        assert stats["no_kb"] == 1


class TestPromote:
    """P1-6 闭环：validated 草稿 → 人审 promote → builtin 注入生效。"""

    def test_promote_validated_draft(self, tmp_path):
        ing = ComponentOsvIngest(
            drafts_path=str(tmp_path / "d.jsonl"),
            promoted_path=str(tmp_path / "p.json"))
        d = ing.ingest("npm", "lodash", "4.17.20")
        assert d and d["status"] == "validated"
        assert ing.promote(d["rule_id"], note="unit") is True
        promoted = ing.promoted()
        assert d["rule_id"] in promoted
        entry = promoted[d["rule_id"]]
        assert entry["lib"] == "npm:lodash"
        assert entry["cves"]
        for s in entry["signatures"]:
            assert set(s) == {"lib", "pattern", "vulnerable_below", "cve"}
            assert s["cve"] and s["pattern"] and s["vulnerable_below"]

    def test_promote_idempotent(self, tmp_path):
        ing = ComponentOsvIngest(
            drafts_path=str(tmp_path / "d.jsonl"),
            promoted_path=str(tmp_path / "p.json"))
        d = ing.ingest("npm", "lodash", "4.17.20")
        assert ing.promote(d["rule_id"]) is True
        assert ing.promote(d["rule_id"]) is False  # 同 rule_id 只晋升一次

    def test_promote_rejects_unvalidated(self, tmp_path):
        """drafted（未过 validate）不可晋升"""
        ing = ComponentOsvIngest(
            drafts_path=str(tmp_path / "d.jsonl"),
            promoted_path=str(tmp_path / "p.json"))
        d = ing.draft("npm", "lodash", "4.17.20")
        assert d and d["status"] == "drafted"
        ing._append(d)
        assert ing.promote(d["rule_id"]) is False
        assert ing.promoted() == {}

    def test_promote_unknown_rule(self, tmp_path):
        ing = ComponentOsvIngest(
            drafts_path=str(tmp_path / "d.jsonl"),
            promoted_path=str(tmp_path / "p.json"))
        assert ing.promote("no-such-rule") is False

    def test_builtin_injection(self, tmp_path, monkeypatch):
        """promoted 台账条目经 _inject_promoted_component_sigs 并入 builtin 声明"""
        import json as _json
        from vulnclaw.core.vulnspec import builtin as blt
        promoted = {"growth-comp-npm-lodash-cve-2020-8203": {
            "kind": "component_osv", "lib": "npm:lodash",
            "cves": ["CVE-2020-8203"],
            "signatures": [{"lib": "lodash-test-inject", "pattern": r"(?i)lodash-test-inject[ /.\-_]*v?(\d+\.\d+)",
                            "vulnerable_below": "4.17.21", "cve": "CVE-2020-8203"}],
        }}
        pf = tmp_path / "growth"
        pf.mkdir()
        (pf / "promoted_component_sigs.json").write_text(
            _json.dumps(promoted, ensure_ascii=False), encoding="utf-8")
        monkeypatch.setattr("vulnclaw.core.settings.PROJECT_CACHE_DIR", str(tmp_path))
        spec = next(s for s in blt._BUILTIN
                    if s.get("id") == "component_version_disclosure")
        before = list(spec["detect"]["signatures"])
        try:
            n = blt._inject_promoted_component_sigs()
            assert n == 1
            after = spec["detect"]["signatures"]
            assert len(after) == len(before) + 1
            assert after[-1]["lib"] == "lodash-test-inject"
        finally:
            spec["detect"]["signatures"] = before  # 还原全局，防污染其他用例

    def test_builtin_injection_missing_file(self, monkeypatch, tmp_path):
        from vulnclaw.core.vulnspec import builtin as blt
        monkeypatch.setattr("vulnclaw.core.settings.PROJECT_CACHE_DIR", str(tmp_path))
        assert blt._inject_promoted_component_sigs() == 0
