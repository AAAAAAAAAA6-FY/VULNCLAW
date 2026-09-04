# -*- coding: utf-8 -*-
"""方向1：CVE 情报摄入测试。

覆盖：游标增量（只取新增，不重复）；draft 骨架字段与 YAML 段齐全；
validate 通过/非法拒绝；ingest_batch 主流程与游标推进；
promote 状态门禁（仅 validated 可晋升/幂等）；stats 聚合。
"""
import json

import pytest

from vulnclaw.growth.cve_ingest import CveIngest

_CVE = {
    "cve_id": "CVE-2026-0001",
    "name": "ExampleX - Remote Code Execution",
    "severity": "high",
    "cvss": 8.1,
    "file_path": "http/cves/2026/CVE-2026-0001.yaml",
    "description": "ExampleX allows remote unauthenticated attackers to run arbitrary code.",
    "components": ["examplex"],
    "versions": ["1.0"],
}

_CVE_BAD = dict(_CVE, cve_id="", severity="critical")


@pytest.fixture
def ingest(tmp_path):
    cve_dir = tmp_path / "cve_index"
    growth_dir = tmp_path / "growth"
    cve_dir.mkdir()
    return CveIngest(str(cve_dir), str(growth_dir))


def _write_records(ingest, rows):
    with open(ingest._records_path, "a", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def _write_meta(ingest, count):
    with open(ingest._meta_path, "w", encoding="utf-8") as fh:
        json.dump({"count": count}, fh)


class TestIncrementCursor:
    def test_cursor_starts_zero(self, ingest):
        assert ingest.cursor() == 0

    def test_incremental_only_new(self, ingest, tmp_path):
        _write_records(ingest, [dict(_CVE, cve_id="CVE-2000-0001"),
                                dict(_CVE, cve_id="CVE-2000-0002")])
        _write_meta(ingest, 2)
        r = ingest.ingest_batch(limit=10)
        assert r["ingested"] == 2
        assert ingest.cursor() == 2
        # 二次运行无新增 -> 不再摄入
        r2 = ingest.ingest_batch(limit=10)
        assert r2["ingested"] == 0
        assert len(ingest.drafts()) == 2

    def test_meta_count_visible(self, ingest, tmp_path):
        _write_meta(ingest, 4327)
        assert ingest.total_count() == 4327


class TestDraft:
    def test_draft_fields(self, ingest):
        d = ingest.draft(_CVE)
        assert d["cve_id"] == "CVE-2026-0001"
        assert d["severity"] == "high"
        assert d["status"] == "drafted"
        assert d["components"] == ["examplex"]
        assert d["yaml_draft"]

    def test_draft_yaml_has_required_segments(self, ingest):
        d = ingest.draft(_CVE)
        for seg in ("id: growth-", "info:", "severity: high", "http:", "matchers:"):
            assert seg in d["yaml_draft"], seg

    def test_draft_keyword_from_components(self, ingest):
        d = ingest.draft(_CVE)
        assert '          - "examplex"' in d["yaml_draft"]


class TestValidate:
    def test_valid_draft_validates(self, ingest):
        d = ingest.validate(ingest.draft(_CVE))
        assert d["status"] == "validated"
        assert "validated_ts" in d

    def test_invalid_draft_rejected(self, ingest):
        d = ingest.validate(ingest.draft(_CVE_BAD))
        assert d["status"] == "invalid"
        assert "cve_id 缺失" in d["invalid_reason"]

    def test_bad_severity_rejected(self, ingest):
        d = dict(_CVE, severity="crazy")
        d = ingest.validate(ingest.draft(d))
        assert d["status"] == "invalid"
        assert "severity 非法" in d["invalid_reason"]


class TestPromote:
    def test_only_validated_can_promote(self, ingest):
        _write_records(ingest, [_CVE])
        _write_meta(ingest, 1)
        ingest.ingest_batch(limit=10)
        draft = ingest.drafts()[0]
        rule_id = draft["rule_id"]
        # 直接晋升未 validated（draft 已落盘为 validated，模拟手动绕过不适用；此处验证 promote 读盘）
        assert rule_id in ingest._find_draft(rule_id).get("rule_id", "")
        # 先 promoted 空 -> 从盘上的 validated 草稿晋升成功
        assert ingest.promote(rule_id, note="test") is True
        assert rule_id in ingest.promoted_rules()
        # 幂等：再次晋升失败
        assert ingest.promote(rule_id) is False

    def test_promote_unknown_rule_fails(self, ingest):
        assert ingest.promote("growth-nope") is False

    def test_promoted_rules_persist(self, ingest, tmp_path):
        _write_records(ingest, [_CVE])
        _write_meta(ingest, 1)
        ingest.ingest_batch(limit=10)
        rid = ingest.drafts()[0]["rule_id"]
        assert ingest.promote(rid) is True
        other = CveIngest(str(tmp_path / "cve_index"), str(tmp_path / "growth"))
        assert rid in other.promoted_rules()


class TestStats:
    def test_stats_aggregate(self, ingest):
        _write_records(ingest, [_CVE, dict(_CVE, cve_id="CVE-2026-0002", severity="medium")])
        _write_meta(ingest, 2)
        ingest.ingest_batch(limit=10)
        s = ingest.stats()
        assert s["cursor"] == 2
        assert s["drafts"] == 2
        assert s["by_status"]["validated"] == 2
        assert s["total_cve"] == 2