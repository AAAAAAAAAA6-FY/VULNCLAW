# -*- coding: utf-8 -*-
"""H 组验收：core/cost_model.py（成本模型）与 core/scan_profiles.py（扫描模式）。

全部离线、确定性：纯函数，无网络/无时钟/无 IO。
"""
import json

import pytest

from vulnclaw.core.cost_model import (
    COST_UNIT_REQUESTS,
    DEFAULT_ENGINE_COST,
    CostEstimate,
    engine_cost_profile,
    estimate_oob_polling_cost,
    estimate_report_cost,
    estimate_request_cost,
    estimate_scan_cost,
    risk_benefit_ratio,
)
from vulnclaw.core.scan_profiles import (
    PROFILES,
    PRIORITY_P0,
    apply_budget,
    engine_priority,
    get_profile,
    list_profiles,
)


# ============================================================
# cost_model
# ============================================================
class TestRequestCost:
    def test_sqli_profile_exact_numbers(self):
        est = estimate_request_cost("sqli", 12)
        # sqli 画像：1.5 请求/payload + 2 基线 = 2 + ceil(18) = 20
        assert est.requests == 20
        assert est.seconds == pytest.approx(20 * 0.3, abs=1e-9)
        assert est.relative_cost == pytest.approx(20 / COST_UNIT_REQUESTS, abs=1e-9)

    def test_zero_payloads_keeps_baseline_only(self):
        est = estimate_request_cost("sqli", 0)
        assert est.requests == 2  # 仅基线

    def test_unknown_engine_falls_back_to_default_profile(self):
        prof = engine_cost_profile("no_such_engine_xyz")
        assert prof == DEFAULT_ENGINE_COST
        est = estimate_request_cost("no_such_engine_xyz", 3)
        assert est.requests == 2 + 3  # 1.0/payload + 2 基线

    def test_latency_scales_seconds_not_requests(self):
        slow = estimate_request_cost("xss", 4, per_request_latency_ms=1000.0)
        fast = estimate_request_cost("xss", 4, per_request_latency_ms=100.0)
        assert slow.requests == fast.requests
        assert slow.seconds == pytest.approx(fast.seconds * 10, rel=1e-6)

    @pytest.mark.parametrize("bad", [-1, -0.5])
    def test_negative_payload_rejected(self, bad):
        with pytest.raises(ValueError):
            estimate_request_cost("sqli", bad)

    def test_non_numeric_payload_rejected(self):
        with pytest.raises(TypeError):
            estimate_request_cost("sqli", "12")
        with pytest.raises(TypeError):
            estimate_request_cost("sqli", True)  # bool 显式拒绝


class TestScanCost:
    def test_mapping_input_and_exact_totals(self):
        est = estimate_scan_cost({"sqli": 12, "xss": 0}, targets=1, concurrency=1)
        # sqli 20 + xss 1（baseline 1）= 21
        assert est.requests == 21
        assert dict(est.breakdown) == {"sqli": 20, "xss": 1}

    def test_list_and_tuple_forms_equivalent(self):
        a = estimate_scan_cost(["sqli", "xss"], targets=1)
        b = estimate_scan_cost([("sqli", 10), ("xss", 10)], targets=1)
        assert a.requests == b.requests
        assert a.breakdown == b.breakdown

    def test_targets_sequence_uses_len(self):
        one = estimate_scan_cost("sqli", targets=1)
        many = estimate_scan_cost("sqli", targets=["a", "b", "c"])
        assert many.requests == one.requests * 3

    def test_concurrency_dilutes_seconds_only(self):
        seq = estimate_scan_cost("sqli", targets=2, concurrency=1)
        par = estimate_scan_cost("sqli", targets=2, concurrency=4)
        assert seq.requests == par.requests
        assert par.seconds == pytest.approx(seq.seconds / 4, rel=1e-6)

    def test_invalid_inputs(self):
        with pytest.raises(ValueError):
            estimate_scan_cost("sqli", concurrency=0)
        with pytest.raises(TypeError):
            estimate_scan_cost("sqli", targets="not-a-seq")
        with pytest.raises(TypeError):
            estimate_scan_cost([123])  # 元素形态非法


class TestOobAndReportCost:
    def test_oob_polling_exact_numbers(self):
        est = estimate_oob_polling_cost(tokens=4, poll_interval_s=1.5, poll_timeout_s=15.0)
        # polls_per_token = ceil(15/1.5) = 10 -> 40 请求；等待 4*15=60s
        assert est.requests == 40
        assert est.seconds == pytest.approx(60.0, abs=1e-9)

    def test_oob_zero_tokens_is_free(self):
        est = estimate_oob_polling_cost(tokens=0)
        assert est.requests == 0 and est.seconds == 0.0

    def test_report_detail_monotonic(self):
        full = estimate_report_cost(10, detail="full")
        summary = estimate_report_cost(10, detail="summary")
        compact = estimate_report_cost(10, detail="compact")
        assert full.size_bytes > summary.size_bytes > compact.size_bytes
        assert full.requests == 0 and full.relative_cost > 0

    def test_report_invalid_detail_rejected(self):
        with pytest.raises(ValueError):
            estimate_report_cost(1, detail="verbose")


class TestRiskBenefit:
    def test_exact_composition(self):
        # critical 10.0 × internet 1.0 × certain 1.0 = 10.0
        assert risk_benefit_ratio("critical", "internet", "certain") == 10.0
        # high 7.0 × internal 0.55 × medium 0.7 = 2.695
        assert risk_benefit_ratio("high", "internal", "medium") == pytest.approx(2.695, abs=1e-6)

    def test_numeric_factors_clamped(self):
        assert risk_benefit_ratio("high", 5.0, 5.0) == 7.0  # 夹到 1.0
        assert risk_benefit_ratio("high", -1.0, -1.0) == 0.0  # 夹到 0.0

    def test_unknown_defaults(self):
        assert risk_benefit_ratio("unknown", "unknown", "low") == pytest.approx(1.0 * 0.5 * 0.35, abs=1e-6)

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            risk_benefit_ratio("super-critical")
        with pytest.raises(TypeError):
            risk_benefit_ratio("high", True, "medium")


class TestCostEstimateSerialization:
    def test_as_dict_json_serializable(self):
        est = estimate_scan_cost({"sqli": 4}, targets=2, concurrency=2)
        data = json.loads(json.dumps(est.as_dict()))
        assert data["requests"] == est.requests
        assert data["breakdown"] == [["sqli", est.requests // 2]]
        assert isinstance(est, CostEstimate)


# ============================================================
# scan_profiles
# ============================================================
class TestProfiles:
    def test_all_profiles_listed(self):
        names = list_profiles()
        assert names == list(PROFILES)
        for expected in ("fast", "standard", "deep", "low-noise", "oob", "api", "budget"):
            assert expected in names

    def test_get_profile_fail_closed(self):
        with pytest.raises(ValueError):
            get_profile("no-such-profile")
        assert get_profile("FAST").name == "fast"  # 大小写归一

    def test_low_noise_cheaper_than_standard(self):
        low = estimate_scan_cost(get_profile("low-noise").engine_spec(), targets=1)
        std = estimate_scan_cost(get_profile("standard").engine_spec(), targets=1)
        assert low.requests < std.requests

    def test_fast_budget_below_standard_budget(self):
        assert get_profile("fast").budget_requests < get_profile("standard").budget_requests

    def test_priority_mapping(self):
        assert engine_priority("sqli") == 2
        assert engine_priority("xxe") == 1
        assert engine_priority("deep_chimera") == 0

    def test_payload_depth_override(self):
        prof = get_profile("fast")
        assert prof.payload_count_for("sqli") == 4  # default_payload_depth
        overridden = prof.payload_depth.get("sqli")
        assert overridden is None or prof.payload_count_for("sqli") == overridden


class TestApplyBudget:
    def test_within_budget_returns_original_untouched(self):
        prof = get_profile("fast")
        result = apply_budget(prof)
        assert result.dropped == ()
        assert result.profile is prof
        assert result.reason == ""

    def test_zero_budget_means_unlimited(self):
        prof = get_profile("budget")
        result = apply_budget(prof, budget_requests=0)
        assert result.dropped == ()
        assert result.profile is prof

    def test_over_budget_trims_and_reports_dropped(self):
        result = apply_budget(get_profile("standard"), budget_requests=100)
        assert result.dropped, "预算 100 必须触发裁减"
        assert result.estimate.requests <= 100, "裁减后必须收进预算"
        assert result.dropped_estimate > 0
        assert "预算" in result.reason

    def test_trim_order_is_low_priority_first(self):
        result = apply_budget(get_profile("standard"), budget_requests=100)
        priorities = [engine_priority(name) for name in result.dropped]
        assert priorities == sorted(priorities), "被裁顺序必须按优先级非递减"
        # P0 引擎在全部 P1 被裁之前不得被裁
        first_p0 = next(
            (i for i, name in enumerate(result.dropped) if name in PRIORITY_P0), None
        )
        if first_p0 is not None:
            assert all(
                engine_priority(n) == 2 for n in result.dropped[first_p0:]
            ), "一旦开始裁 P0，其后不得再出现 P1"

    def test_trim_is_deterministic(self):
        a = apply_budget(get_profile("standard"), budget_requests=150)
        b = apply_budget(get_profile("standard"), budget_requests=150)
        assert a.dropped == b.dropped
        assert a.estimate.requests == b.estimate.requests

    def test_negative_budget_rejected(self):
        with pytest.raises(ValueError):
            apply_budget(get_profile("fast"), budget_requests=-1)

    def test_minimal_set_never_emptied(self):
        result = apply_budget(get_profile("standard"), budget_requests=1)
        assert len(result.profile.engines) >= 1, "最小可用集不得被裁空"
        assert "最小集" in result.reason
