"""单元测试：AdaptiveRateLimiter 令牌获取 / QPS 自适应 / 冷却逻辑。

不依赖外网，全部用 asyncio 直接驱动。
"""
import asyncio
import time

import pytest

from vulnclaw.ai.v100.rate_limiter import AdaptiveRateLimiter


def run(coro):
    return asyncio.run(coro)


class TestAcquire:
    def test_first_acquire_returns_zero(self):
        rl = AdaptiveRateLimiter(initial_qps=5)
        wait = run(rl.acquire("glm-4-flash"))
        assert wait == 0

    def test_burst_limited_by_qps(self):
        """qps=2 时，第 3 个 1 秒窗口内请求必须返回等待。"""
        rl = AdaptiveRateLimiter(initial_qps=2)
        waits = [run(rl.acquire("glm-4-flash")) for _ in range(3)]
        assert waits[0] == 0
        assert waits[1] == 0
        assert waits[2] > 0  # 超过窗口配额，需要等待

    def test_unknown_model_uses_default_qps(self):
        rl = AdaptiveRateLimiter(initial_qps=3)
        wait = run(rl.acquire("unknown-model"))
        assert wait == 0


class TestCooldown:
    """注意：限流器有"启动 60 秒宽限期"（启动内 429 不惩罚），测试需先回拨 _last_adjust_time。"""

    @staticmethod
    def _make_limiter(qps=3):
        rl = AdaptiveRateLimiter(initial_qps=qps)
        rl._last_adjust_time = time.time() - 100  # 绕过 60s 宽限
        return rl

    def test_429_grace_period_no_penalty(self):
        """启动 60 秒内触发 429：不降 QPS、不冷却（设计行为）。"""
        rl = AdaptiveRateLimiter(initial_qps=10)
        run(rl.record_failure("glm-4-flash", status_code=429, error_msg="RateLimit"))
        assert rl._model_qps["glm-4-flash"] == 10
        assert rl.is_available("glm-4-flash") is True

    def test_429_sets_cooldown(self):
        """429 之后模型应不可用（冷却中）。"""
        rl = self._make_limiter()
        run(rl.record_failure("glm-4-flash", status_code=429, error_msg="RateLimit"))
        assert rl.is_available("glm-4-flash") is False

    def test_429_reduces_qps(self):
        rl = self._make_limiter(qps=10)
        before = rl._model_qps["glm-4-flash"]
        run(rl.record_failure("glm-4-flash", status_code=429, error_msg="429"))
        after = rl._model_qps["glm-4-flash"]
        assert after < before
        assert after >= rl._min_qps

    def test_500_reduces_qps_but_short_cooldown(self):
        rl = self._make_limiter(qps=8)
        run(rl.record_failure("glm-4-flash", status_code=500, error_msg="Internal Server Error"))
        assert rl._model_qps["glm-4-flash"] < 8
        # 短冷却 ~3s，仍应判不可用
        assert rl.is_available("glm-4-flash") is False

    def test_401_long_cooldown(self):
        rl = self._make_limiter()
        run(rl.record_failure("glm-4-flash", status_code=401, error_msg=""))
        assert rl.get_wait_time("glm-4-flash") > 60

    def test_cooldown_acquire_returns_wait(self):
        rl = self._make_limiter()
        run(rl.record_failure("glm-4-flash", status_code=429, error_msg="RateLimit"))
        wait = run(rl.acquire("glm-4-flash"))
        assert wait > 0


class TestSuccessRampUp:
    def test_success_raises_qps(self):
        """连续成功（>5 次 & 成功率>0.9 & 距上次调整>20s）后 QPS 应提升。"""
        rl = AdaptiveRateLimiter(initial_qps=2)
        rl._last_adjust_time = time.time() - 30  # 绕过 20s 调整间隔
        before = rl._model_qps["glm-4-flash"]
        for _ in range(8):
            run(rl.record_success("glm-4-flash"))
        after = rl._model_qps["glm-4-flash"]
        assert after > before

    def test_success_clears_failures(self):
        rl = AdaptiveRateLimiter(initial_qps=3)
        rl._failures["glm-4-flash"] = 3
        run(rl.record_success("glm-4-flash"))
        assert rl._failures["glm-4-flash"] == 2


class TestStatsAndReset:
    def test_stats_shape(self):
        rl = AdaptiveRateLimiter(initial_qps=3)
        run(rl.acquire("glm-4-flash"))
        run(rl.record_success("glm-4-flash"))
        stats = run(rl.get_stats())
        for key in ("current_qps", "initial_qps", "model_qps",
                    "total_requests", "success_requests",
                    "rate_limit_count", "success_rate"):
            assert key in stats
        assert stats["total_requests"] >= 1
        assert stats["success_requests"] >= 1

    def test_reset_restores_initial_qps(self):
        rl = AdaptiveRateLimiter(initial_qps=3)
        run(rl.record_failure("glm-4-flash", status_code=429, error_msg="RateLimit"))
        run(rl.reset())
        assert rl.current_qps == 3
        assert rl.is_available("glm-4-flash") is True
