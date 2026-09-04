# -*- coding: utf-8 -*-
"""方向5 本地规则集市：导入校验/去重/排名/回灌/导出。"""
import json

from vulnclaw.growth import rule_bazaar as rb

VALID_YAML = """id: test-xss-001
info:
  name: Test XSS
  severity: medium
  tags: xss
http:
  - method: GET
    path:
      - "{{BaseURL}}/?q={{payload}}"
    payload: "<script>alert(1)</script>"
matchers:
  - type: word
    words:
      - "<script>"
"""

BAD_YAML = "just: [broken\n  yaml: : :"

MISSING_SEG_YAML = """id: empty-rule
info:
  name: Empty
  severity: low
http:
  - method: GET
"""

DMG_YAML = """id: impact-rule
info:
  name: Impact
  severity: nonsense-level
http:
  - method: GET
matchers:
  - type: word
    words: ["x"]
"""


def _write(path, content):
    path.write_text(content, encoding="utf-8")


class TestImport:
    def test_valid_imported(self, tmp_path):
        src = tmp_path / "rules"
        src.mkdir()
        _write(src / "a.yaml", VALID_YAML)
        bz = rb.RuleBazaar(str(tmp_path / "pool"))
        res = bz.import_rules(str(src / "*.yaml"), source="community")
        assert res["scanned"] == 1
        assert res["imported"] == 1
        assert res["skipped"] == 0

    def test_duplicate_skipped(self, tmp_path):
        src = tmp_path / "rules"
        src.mkdir()
        p1, p2 = src / "a.yaml", src / "b.yaml"
        _write(p1, VALID_YAML)
        _write(p2, VALID_YAML)
        bz = rb.RuleBazaar(str(tmp_path / "pool"))
        first = bz.import_rules(str(src / "*.yaml"))
        assert first["imported"] == 2
        res = bz.import_rules(str(src / "*.yaml"))
        assert res["imported"] == 0
        assert res["duplicates"] == 2

    def test_bad_and_invalid_skipped(self, tmp_path):
        src = tmp_path / "rules"
        src.mkdir()
        _write(src / "bad.yaml", BAD_YAML)
        _write(src / "seg.yaml", MISSING_SEG_YAML)
        _write(src / "dmg.yaml", DMG_YAML)
        _write(src / "ok.yaml", VALID_YAML)
        bz = rb.RuleBazaar(str(tmp_path / "pool"))
        res = bz.import_rules(str(src / "*.yaml"))
        assert res["scanned"] == 4
        assert res["imported"] == 1
        assert res["skipped"] == 3
        assert "缺必需段" in " | ".join(res["skip_reasons"])


class TestRank:
    def test_rank_orders_by_reputation_and_hits(self, tmp_path):
        src = tmp_path / "rules"
        src.mkdir()
        _write(src / "a.yaml", VALID_YAML)
        _write(src / "b.yaml", VALID_YAML.replace("test-xss-001", "test-xss-002"))
        bz = rb.RuleBazaar(str(tmp_path / "pool"))
        bz.import_rules(str(src / "*.yaml"))
        rows = bz.rows()
        rid = {r["rule_id"]: r for r in rows}
        fp_a = rid["test-xss-001"]["fingerprint"]
        bz.record_outcome(fp_a, "confirm")
        bz.record_outcome(fp_a, "confirm")
        ranked = bz.rank_rules(k=10)
        assert len(ranked) == 2
        # 命中多的排前面
        assert ranked[0]["rule_id"] == "test-xss-001"
        assert ranked[0]["score"] > ranked[1]["score"]

    def test_record_outcome_fp(self, tmp_path):
        src = tmp_path / "rules"
        src.mkdir()
        _write(src / "a.yaml", VALID_YAML)
        bz = rb.RuleBazaar(str(tmp_path / "pool"))
        bz.import_rules(str(src / "*.yaml"))
        fp = bz.rows()[0]["fingerprint"]
        assert bz.record_outcome(fp, "fp") is True
        assert bz.rows()[0]["fp_hits"] == 1
        assert bz.record_outcome("no-such-fp", "confirm") is False


class TestExport:
    def test_export_pool_writes_yaml(self, tmp_path):
        src = tmp_path / "rules"
        src.mkdir()
        _write(src / "a.yaml", VALID_YAML)
        bz = rb.RuleBazaar(str(tmp_path / "pool"))
        bz.import_rules(str(src / "*.yaml"))
        out_dir = tmp_path / "exported"
        res = bz.export_pool(str(out_dir), top_k=10)
        assert res["written"] == 1
        assert (out_dir / "test-xss-001.yaml").exists()


class TestCommunity:
    def test_community_publish_placeholder(self):
        res = rb.community_publish()
        assert res["supported"] is False

    def test_stats_shape(self, tmp_path):
        stats = rb.rule_bazaar_stats()
        assert "rules" in stats and "sources" in stats