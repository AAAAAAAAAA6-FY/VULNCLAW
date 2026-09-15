# -*- coding: utf-8 -*-
"""P2-① 统计化判定：core.stats（Welch t 检验）单元测试（2026-09-15）。

设计目标：时间盲注判定从"单次样本 + 拍脑袋阈值"升级为
"多次采样 + Welch t 检验 + 实用差值下限"。本测试验证统计核心：
真注入显著、单次尖峰抖动不显著、常数组确定性差异、样本不足 fail-safe。
"""
import math

import pytest

from vulnclaw.core.stats import welch_t, welch_significant, mean_of


class TestWelchSignificant:
    def test_true_injection_is_significant(self):
        """真注入：注入组稳定慢于对照组 → 显著"""
        treatment = [5.1, 5.3, 5.0]
        control = [0.31, 0.30, 0.32]
        sig, t = welch_significant(treatment, control)
        assert sig is True
        assert t > 10

    def test_single_spike_jitter_not_significant(self):
        """网络抖动：注入组一次尖峰一次正常 → 不显著（旧单次判据会误报的场景）"""
        treatment = [2.7, 0.30]
        control = [0.30, 0.31]
        sig, _ = welch_significant(treatment, control)
        assert sig is False

    def test_no_difference(self):
        """无注入：两组接近 → 不显著"""
        sig, _ = welch_significant([0.3, 0.35, 0.28], [0.31, 0.29, 0.33])
        assert sig is False

    def test_identical_constant_groups(self):
        """两组常数且相等 → 无差异"""
        sig, t = welch_significant([0.3, 0.3], [0.3, 0.3])
        assert sig is False
        assert t == 0.0

    def test_constant_groups_different_means(self):
        """两组常数但均值不同 → 确定性差异 → 显著（t=inf）"""
        sig, t = welch_significant([5.0, 5.0], [0.3, 0.3])
        assert sig is True
        assert math.isinf(t)

    def test_insufficient_samples_not_significant(self):
        """样本不足（任一组 <2）→ 不可判定 → False（调用方退回旧判据）"""
        sig, t = welch_significant([5.0], [0.3, 0.3])
        assert sig is False
        assert t == 0.0

    def test_moderate_stable_shift_is_significant(self):
        """中等稳定偏移（1.5s vs 0.3s）→ 显著"""
        sig, _ = welch_significant([1.5, 1.6, 1.55], [0.3, 0.32, 0.28])
        assert sig is True

    def test_negative_filtering(self):
        """非法样本（负值/None/非数）被过滤后仍可判定"""
        sig, _ = welch_significant([5.1, -1, None, 5.2], [0.3, "x", 0.31])
        assert sig is True


class TestWelchT:
    def test_direction(self):
        """t 的符号反映方向：treatment 慢 → t>0"""
        t = welch_t([5.0, 5.1], [0.3, 0.3])
        assert t > 0

    def test_symmetry(self):
        """交换两组 → t 变号"""
        t1 = welch_t([1.0, 1.1, 0.9], [0.3, 0.35, 0.25])
        t2 = welch_t([0.3, 0.35, 0.25], [1.0, 1.1, 0.9])
        assert t1 == pytest.approx(-t2, abs=1e-9)


class TestMeanOf:
    def test_filters_bad_samples(self):
        assert mean_of([1.0, None, "abc", -2, 3.0]) == pytest.approx(2.0)

    def test_empty(self):
        assert mean_of([]) == 0.0
