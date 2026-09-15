# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""B1: finding schema v1 单元测试。

覆盖：
- 字段完整性 / 五级 detection 键集合 / 状态枚举合法性
- **五级语义独立性**（低级别证据不得自动升级高级别，含 G 组派生字段污染场景）
- finding_id 稳定性（同输入同 ID、不同输入不同 ID、参数与 query 顺序无关）
- 归一化幂等 / 旧 finding 兼容（只增不改）/ 非法输入 fail-closed
- 状态机迁移与单调推进
- 报告链路挂接零回归（enrich_report 只增键，渲染字段一字不改）
"""
import json

import pytest

from vulnclaw.core.finding_schema import (
    DETECTION_LEVELS,
    DET_OOB_CONFIRMED,
    DET_REPRODUCTION,
    DET_RESPONSE_EVIDENCE,
    DET_RULE_MATCH,
    DET_VERIFICATION,
    GOVERNANCE_STATUSES,
    SCHEMA_ADDITIVE_KEYS,
    SCHEMA_VERSION,
    STATUS_ACCEPTED,
    STATUS_CANDIDATE,
    STATUS_CLOSED,
    STATUS_FALSE_POSITIVE,
    STATUS_FIXED,
    STATUS_OOB_CONFIRMED,
    STATUS_ORDER,
    STATUS_REPRODUCED,
    STATUS_SUSPECTED,
    STATUS_VERIFIED,
    VALID_STATUSES,
    advance_status,
    apply_schema_inplace,
    build_evidence_items,
    can_transition,
    compute_detection,
    compute_finding_id,
    highest_detection_level,
    is_false_positive,
    is_schema_v1,
    resolve_status,
    schema_gap_summary,
    to_schema_v1,
    to_schema_v1_many,
)


def _finding(**extra):
    base = {
        "url": "http://t.example.com/a.php?id=1",
        "type": "SQL注入",
        "severity": "High",
        "parameter": "id",
        "method": "GET",
    }
    base.update(extra)
    return base


# ============================================================
# 1. 字段完整性 / 枚举合法性
# ============================================================
class TestSchemaShape:
    def test_all_schema_fields_present(self):
        out = to_schema_v1(_finding())
        for key in ("finding_id", "schema_version", "detection", "confidence", "status",
                    "evidence_items", "verification", "reproduction", "oob"):
            assert key in out, key
        assert out["schema_version"] == SCHEMA_VERSION == 1
        assert isinstance(out["evidence_items"], list)

    def test_detection_has_exactly_five_bool_levels(self):
        det = to_schema_v1(_finding())["detection"]
        assert set(det) == set(DETECTION_LEVELS)
        assert len(DETECTION_LEVELS) == 5
        for level, value in det.items():
            assert isinstance(value, bool), level

    def test_status_enum_has_ten_states(self):
        assert len(STATUS_ORDER) == 10
        assert len(VALID_STATUSES) == 10
        assert STATUS_ORDER == (
            STATUS_CANDIDATE, STATUS_SUSPECTED, STATUS_VERIFIED, STATUS_REPRODUCED,
            STATUS_OOB_CONFIRMED, STATUS_FALSE_POSITIVE, STATUS_ACCEPTED,
            STATUS_FIXED, "reopened", STATUS_CLOSED,
        )
        # 每个状态都必须在状态机里有出边定义
        from vulnclaw.core.finding_schema import STATUS_TRANSITIONS
        assert set(STATUS_TRANSITIONS) == set(VALID_STATUSES)

    def test_status_enum_accepts_governance_states(self):
        assert GOVERNANCE_STATUSES == {
            STATUS_FALSE_POSITIVE, STATUS_ACCEPTED, STATUS_FIXED, "reopened", STATUS_CLOSED,
        }
        for state in GOVERNANCE_STATUSES:
            assert to_schema_v1(_finding(status=state))["status"] == state

    def test_nested_views_are_json_serializable(self):
        out = to_schema_v1(_finding(evidence="proof", burp_verified=True,
                                    reproduction_steps=["1. do it"]))
        json.dumps(out, ensure_ascii=False)


# ============================================================
# 2. 五级语义独立性（核心铁律）
# ============================================================
class TestDetectionIndependence:
    @pytest.mark.parametrize("signal,level", [
        ({"rule_hit": "local_rule:sql_error"}, DET_RULE_MATCH),
        ({"evidence": "MySQL syntax error near '1''"}, DET_RESPONSE_EVIDENCE),
        ({"burp_verified": True}, DET_VERIFICATION),
        ({"exploit_reproduced": True}, DET_REPRODUCTION),
        ({"oob_confirmed": True}, DET_OOB_CONFIRMED),
    ])
    def test_single_signal_only_lights_its_own_level(self, signal, level):
        det = compute_detection(_finding(**signal))
        assert det[level] is True
        for other in DETECTION_LEVELS:
            if other != level:
                assert det[other] is False, (level, other)

    def test_rule_match_never_upgrades_to_verification(self):
        """铁律：规则命中不得自动置 verification/reproduction/oob_confirmed。"""
        out = to_schema_v1(_finding(rule_hit="local_rule:sql_error"))
        assert out["detection"][DET_RULE_MATCH] is True
        assert out["detection"][DET_VERIFICATION] is False
        assert out["detection"][DET_REPRODUCTION] is False
        assert out["detection"][DET_OOB_CONFIRMED] is False
        assert out["verification"]["verified"] is False
        assert out["reproduction"]["reproduced"] is False
        assert out["oob"]["confirmed"] is False
        assert out["status"] == STATUS_CANDIDATE

    def test_oob_never_upgrades_to_verification_or_reproduction(self):
        """铁律：OOB 回调是独立档，不得反推 verification/reproduction。"""
        out = to_schema_v1(_finding(oob_confirmed=True))
        assert out["detection"][DET_OOB_CONFIRMED] is True
        assert out["detection"][DET_VERIFICATION] is False
        assert out["detection"][DET_REPRODUCTION] is False
        assert out["status"] == STATUS_OOB_CONFIRMED

    def test_verification_never_upgrades_to_reproduction(self):
        out = to_schema_v1(_finding(exploited=True, burp_verified=True,
                                    verdict="confirm", cross_confirmed=True))
        assert out["detection"][DET_VERIFICATION] is True
        assert out["detection"][DET_REPRODUCTION] is False

    def test_response_evidence_never_upgrades(self):
        out = to_schema_v1(_finding(evidence="some response body"))
        assert out["detection"] == {
            DET_RULE_MATCH: False,
            DET_RESPONSE_EVIDENCE: True,
            DET_VERIFICATION: False,
            DET_REPRODUCTION: False,
            DET_OOB_CONFIRMED: False,
        }
        assert out["status"] == STATUS_SUSPECTED

    def test_lower_levels_never_upgrade_higher_levels_exhaustive(self):
        """遍历所有单信号组合：任一级为真都不得点亮"更高"的级，除非自身有信号。"""
        signals = [
            {DET_RULE_MATCH: {"rule_hit": "local_rule:x"}},
            {DET_RESPONSE_EVIDENCE: {"evidence": "body"}},
            {DET_VERIFICATION: {"burp_verified": True}},
            {DET_REPRODUCTION: {"exploit_reproduced": True}},
            {DET_OOB_CONFIRMED: {"oob_confirmed": True}},
        ]
        for single in signals:
            det = compute_detection(_finding(**list(single.values())[0]))
            fired = {level for level, on in det.items() if on}
            assert fired == set(single)

    def test_g_schema_derived_verified_is_not_trusted(self):
        """G 组 apply_evidence_schema 把 rule_hit 并入 verified；本 schema 不采信该派生字段。"""
        from vulnclaw.core.models import apply_evidence_schema

        raw = _finding(rule_hit="local_rule:sql_error")
        polluted = apply_evidence_schema(dict(raw))
        assert polluted["verified"] is True  # G 组渲染口径：确有此跨级推断
        det = compute_detection(polluted)
        assert det[DET_VERIFICATION] is False  # schema 口径：规则命中 != 验证
        assert resolve_status(polluted, det) == STATUS_CANDIDATE

    def test_g_schema_derived_reproduced_is_not_trusted(self):
        """G 组 reproduced 由 OOB 派生；本 schema 的 reproduction 必须为 False。"""
        from vulnclaw.core.models import apply_evidence_schema

        polluted = apply_evidence_schema(_finding(oob_confirmed=True))
        assert polluted["reproduced"] is True
        assert compute_detection(polluted)[DET_REPRODUCTION] is False

    def test_all_levels_can_coexist(self):
        out = to_schema_v1(_finding(
            rule_hit="local_rule:x", evidence="proof", burp_verified=True,
            exploit_reproduced=True, oob_confirmed=True,
        ))
        assert all(out["detection"].values())
        assert highest_detection_level(out["detection"]) == DET_OOB_CONFIRMED
        assert out["status"] == STATUS_OOB_CONFIRMED

    def test_verification_method_tokens(self):
        assert compute_detection(_finding(verification_method="local_rule:sqli"))[DET_RULE_MATCH]
        assert compute_detection(_finding(verification_method="burp_replay_diff"))[DET_VERIFICATION]
        assert compute_detection(_finding(verification_method="oob_engine_confirmed"))[DET_OOB_CONFIRMED]
        # 降级/预算兜底不是验证
        for method in ("local_fallback", "budget_fallback", "ai_batch"):
            det = compute_detection(_finding(verification_method=method))
            assert det[DET_VERIFICATION] is (method == "ai_batch"), method
        # "burp_replay_diff" 含 replay，但不得据此点亮 reproduction
        assert compute_detection(_finding(verification_method="burp_replay_diff"))[DET_REPRODUCTION] is False

    def test_false_positive_only_on_explicit_negative(self):
        assert is_false_positive(_finding(ai_verdict="误报")) is True
        assert is_false_positive(_finding(ai_verdict="非漏洞")) is True
        assert is_false_positive(_finding(verdict="false_positive")) is True
        # "待人工复核" 类复合裁决不得被判成误报（子串匹配会误杀）
        assert is_false_positive(_finding(ai_verdict="待人工复核（无回显/无响应证据）")) is False
        assert is_false_positive(_finding(ai_verdict="待人工复核（粗筛判误报，本地规则未命中）")) is False
        assert is_false_positive(_finding(ai_verdict="真实漏洞")) is False


# ============================================================
# 3. finding_id 稳定性
# ============================================================
class TestFindingId:
    def test_stable_for_same_input(self):
        a = _finding()
        b = dict(reversed(list(_finding().items())))  # 键序不同
        assert compute_finding_id(a) == compute_finding_id(b)
        assert compute_finding_id(a).startswith("f1-")
        assert len(compute_finding_id(a)) == 3 + 16

    def test_differs_on_identity_fields(self):
        base = _finding()
        assert compute_finding_id(base) != compute_finding_id(_finding(type="XSS"))
        assert compute_finding_id(base) != compute_finding_id(_finding(url="http://t.example.com/b.php?id=1"))
        assert compute_finding_id(base) != compute_finding_id(_finding(parameter="uid"))
        assert compute_finding_id(base) != compute_finding_id(_finding(method="POST"))

    def test_parameter_order_irrelevant(self):
        assert compute_finding_id(_finding(parameter="a,b")) == compute_finding_id(_finding(parameter="b,a"))
        assert compute_finding_id(_finding(parameter="a&b")) == compute_finding_id(_finding(parameter="b&a"))
        assert compute_finding_id(_finding(parameter=["a", "b"])) == compute_finding_id(_finding(parameter=["b", "a"]))
        assert compute_finding_id(_finding(parameter={"a": 1, "b": 2})) == \
            compute_finding_id(_finding(parameter={"b": 2, "a": 1}))
        assert compute_finding_id(_finding(parameter="a,b")) != compute_finding_id(_finding(parameter="a,c"))

    def test_url_query_and_trailing_slash_irrelevant(self):
        a = _finding(url="http://T.example.com/a.php?id=1&x=2")
        b = _finding(url="http://t.example.com/a.php?x=2&id=1")
        assert compute_finding_id(a) == compute_finding_id(b)
        assert compute_finding_id(_finding(url="http://t.example.com/a.php/")) == \
            compute_finding_id(_finding(url="http://t.example.com/a.php"))
        # scheme 参与身份（http 与 https 是不同请求）
        assert compute_finding_id(_finding(url="http://t.example.com/a")) != \
            compute_finding_id(_finding(url="https://t.example.com/a"))

    def test_evidence_text_does_not_affect_id(self):
        assert compute_finding_id(_finding(evidence="A")) == compute_finding_id(_finding(evidence="B"))

    def test_fail_closed_on_unidentifiable_input(self):
        assert compute_finding_id(None) == ""
        assert compute_finding_id("not-a-dict") == ""
        assert compute_finding_id({}) == ""
        assert compute_finding_id({"severity": "High"}) == ""
        assert to_schema_v1(None)["finding_id"] == ""

    def test_id_injected_into_view(self):
        out = to_schema_v1(_finding())
        assert out["finding_id"] == compute_finding_id(_finding())


# ============================================================
# 4. 幂等 / 兼容 / fail-closed
# ============================================================
class TestNormalizeCompat:
    def test_to_schema_v1_is_idempotent(self):
        first = to_schema_v1(_finding(evidence="proof", burp_verified=True, source="param_mining"))
        second = to_schema_v1(first)
        assert second == first

    def test_apply_schema_inplace_is_idempotent_and_identity_preserving(self):
        f = _finding(evidence="proof")
        assert apply_schema_inplace(f) is f
        snapshot = dict(f)
        apply_schema_inplace(f)
        assert f == snapshot

    def test_legacy_fields_untouched(self):
        legacy = _finding(evidence="proof-body", confidence="High", source="param_mining",
                          cvss=9.1, remediation="参数化查询", ai_verdict="真实漏洞")
        out = to_schema_v1(legacy)
        for key, value in legacy.items():
            assert out[key] == value, key
        assert isinstance(out["evidence"], str)  # evidence 仍是字符串，未被列表覆盖
        assert out["confidence"] == "High"       # 既有置信度不被推导值覆盖

    def test_evidence_list_goes_to_alias(self):
        out = to_schema_v1(_finding(evidence="proof-body"))
        assert any(it["source"] == "evidence" and it["kind"] == DET_RESPONSE_EVIDENCE
                   and it["detail"] == "proof-body" for it in out["evidence_items"])
        assert build_evidence_items({}) == []

    def test_existing_reproduction_dict_is_merged_not_replaced(self):
        legacy = _finding(reproduction={"method": "POST", "url": "http://t/x", "expected": "true"})
        out = to_schema_v1(legacy)
        assert out["reproduction"]["method"] == "POST"
        assert out["reproduction"]["expected"] == "true"
        assert out["reproduction"]["reproduced"] is False
        assert out["reproduction"]["signals"] == []

    def test_existing_oob_dict_is_merged_not_replaced(self):
        out = to_schema_v1(_finding(oob={"ts": "2026-09-13 10:00:00"}))
        assert out["oob"]["ts"] == "2026-09-13 10:00:00"
        assert out["oob"]["confirmed"] is False
        # schema 子键刻意避开 ts/detail，避免被 attach_oob_evidence 误当回调
        assert set(out["oob"]) & {"ts", "detail"} == {"ts"}

    def test_legacy_finding_without_schema_fields_is_compatible(self):
        out = to_schema_v1({"url": "http://t/x", "type": "XSS", "severity": "Low"})
        assert out["status"] == STATUS_CANDIDATE
        assert out["detection"] == {level: False for level in DETECTION_LEVELS}
        assert out["confidence"] == ""
        assert out["verification"]["verified"] is False
        assert out["oob"]["confirmed"] is False

    @pytest.mark.parametrize("bad", [None, 0, 42, "x", ["a"], object()])
    def test_illegal_input_fails_closed_to_candidate(self, bad):
        out = to_schema_v1(bad)
        assert out["status"] == STATUS_CANDIDATE
        assert out["finding_id"] == ""
        assert not any(out["detection"].values())
        assert out["verification"]["verified"] is False
        assert out["reproduction"]["reproduced"] is False
        assert out["oob"]["confirmed"] is False
        assert out["evidence_items"] == []

    def test_batch_helper(self):
        assert to_schema_v1_many(None) == []
        assert to_schema_v1_many([_finding(), None, "x"])[0]["schema_version"] == 1
        assert len(to_schema_v1_many([_finding(), _finding()])) == 2

    def test_is_schema_v1(self):
        assert is_schema_v1(to_schema_v1(_finding())) is True
        assert is_schema_v1(_finding()) is False
        assert is_schema_v1(None) is False


# ============================================================
# 5. 状态机
# ============================================================
class TestStatusMachine:
    @pytest.mark.parametrize("signal,expected", [
        ({}, STATUS_CANDIDATE),
        ({"rule_hit": "local_rule:x"}, STATUS_CANDIDATE),
        ({"evidence": "body"}, STATUS_SUSPECTED),
        ({"burp_verified": True}, STATUS_VERIFIED),
        ({"exploit_reproduced": True}, STATUS_REPRODUCED),
        ({"oob_confirmed": True}, STATUS_OOB_CONFIRMED),
        ({"ai_verdict": "误报"}, STATUS_FALSE_POSITIVE),
        ({"lifecycle": "fixed"}, STATUS_FIXED),
    ])
    def test_status_derivation(self, signal, expected):
        assert resolve_status(_finding(**signal)) == expected

    def test_governance_status_wins(self):
        for state in GOVERNANCE_STATUSES:
            assert resolve_status(_finding(status=state, oob_confirmed=True)) == state

    def test_derived_status_is_monotonic(self):
        # 既有 candidate 遇到验证证据 -> 升级，不降级
        assert resolve_status(_finding(status=STATUS_CANDIDATE, burp_verified=True)) == STATUS_VERIFIED
        # 既有 verified 遇到更弱证据 -> 保持
        assert resolve_status(_finding(status=STATUS_VERIFIED, evidence="body")) == STATUS_VERIFIED

    def test_advance_status_monotonic_and_governance_frozen(self):
        strong = {level: True for level in DETECTION_LEVELS}
        weak = {level: False for level in DETECTION_LEVELS}
        assert advance_status(STATUS_CANDIDATE, {DET_OOB_CONFIRMED: True}) == STATUS_OOB_CONFIRMED
        assert advance_status(STATUS_VERIFIED, weak) == STATUS_VERIFIED
        for state in (STATUS_FALSE_POSITIVE, STATUS_ACCEPTED, STATUS_FIXED, STATUS_CLOSED):
            assert advance_status(state, strong) == state
        assert advance_status("bogus", weak) == STATUS_CANDIDATE

    def test_transitions(self):
        assert can_transition(STATUS_CANDIDATE, STATUS_SUSPECTED) is True
        assert can_transition(STATUS_CANDIDATE, STATUS_REPRODUCED) is False
        assert can_transition(STATUS_CLOSED, "reopened") is True
        assert can_transition("reopened", STATUS_VERIFIED) is True
        assert can_transition(STATUS_CLOSED, STATUS_VERIFIED) is False
        assert can_transition("nope", STATUS_VERIFIED) is False
        assert can_transition(STATUS_VERIFIED, "nope") is False

    def test_gap_summary(self):
        stats = schema_gap_summary([
            _finding(rule_hit="local_rule:x"),
            _finding(rule_hit="local_rule:x", burp_verified=True),
            _finding(ai_verdict="误报"),
            "not-a-dict",
        ])
        assert stats["total"] == 3
        assert stats["rule_match"] == 2
        assert stats["verification"] == 1
        assert stats["rule_only_unverified"] == 1
        assert stats["false_positive"] == 1
        assert schema_gap_summary([])["total"] == 0


# ============================================================
# 6. 报告链路挂接零回归
# ============================================================
class TestReportIntegration:
    def _report(self):
        return {
            "scan_id": "scan-b1",
            "target": "http://t.example.com",
            "vulnerabilities": [
                {"url": "http://t.example.com/a?q=1", "type": "SQL注入", "severity": "Critical",
                 "parameter": "q", "evidence": "MySQL syntax error", "remediation": "参数化查询"},
                {"url": "http://t.example.com/b", "type": "XSS", "severity": "High",
                 "confidence": "medium"},
            ],
        }

    def test_enrich_report_adds_schema_keys_only(self):
        from vulnclaw.core.report_generator import enrich_report

        report = self._report()
        snapshot = [dict(v) for v in report["vulnerabilities"]]
        enrich_report(report)
        first = report["vulnerabilities"][0]
        for key in SCHEMA_ADDITIVE_KEYS:
            assert key in first, key
        # 既有键值一字不改（含渲染字段 evidence/confidence/remediation_tier）
        for before, after in zip(snapshot, report["vulnerabilities"]):
            for key, value in before.items():
                assert after[key] == value, key
        assert first["evidence"] == "MySQL syntax error"
        assert first["remediation_tier"].startswith("参数化查询")

    def test_enrich_report_does_not_inject_confidence(self):
        """confidence 是既有渲染字段：缺失时报告链路不得补写（渲染逐字节不变）。"""
        from vulnclaw.core.report_generator import enrich_report

        report = self._report()
        enrich_report(report)
        assert "confidence" not in report["vulnerabilities"][0]
        assert report["vulnerabilities"][1]["confidence"] == "medium"
        assert to_schema_v1({"url": "http://t/x", "type": "X"})["confidence"] == ""

    def test_enrich_report_idempotent(self):
        from vulnclaw.core.report_generator import enrich_report

        report = self._report()
        enrich_report(report)
        once = [dict(v) for v in report["vulnerabilities"]]
        enrich_report(report)
        assert [dict(v) for v in report["vulnerabilities"]] == once

    def test_normalize_vulns_semantics_unchanged(self):
        from vulnclaw.core.report_generator import enrich_report, normalize_vulns

        plain = self._report()
        before = normalize_vulns(plain["vulnerabilities"])
        report = self._report()
        enrich_report(report)
        after = normalize_vulns(report["vulnerabilities"])
        assert len(before) == len(after)
        assert [(v["url"], v["type"], v.get("parameter")) for v in before] == \
            [(v["url"], v["type"], v.get("parameter")) for v in after]
        assert [v["severity"] for v in before] == [v["severity"] for v in after]
        # G 组渲染口径字段仍按原语义产出
        assert after[0]["response_evidence"] is True

    def test_enrich_report_survives_bad_findings(self):
        from vulnclaw.core.report_generator import enrich_report

        report = {"target": "t", "vulnerabilities": [None, "x", {"url": "http://t/x", "type": "A"}]}
        enrich_report(report)
        assert report["vulnerabilities"][2]["schema_version"] == 1
