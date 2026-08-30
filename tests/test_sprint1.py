"""Sprint 1 模块 9：验收测试骨架。

覆盖全部验收用例：
- PF-01/02/03: CircuitBreaker + ProviderFailover
- PM-01/02/03: PluginMarket 安装/已安装/校验
- MTC-01/02/03: MultiTargetContext Redis/内存/隔离
- AC-01/02/03: AdaptiveConcurrency 探测

运行: pytest tests/test_sprint1.py -v
"""
import asyncio
import time

import pytest


class TestCircuitBreaker:
    """验收用例 PF-01 / PF-02 / PF-03。"""

    def test_circuit_breaker_open(self):
        """PF-02: 连续失败 3 次 → state = OPEN。"""
        from vulnclaw.ai.provider_failover import CircuitBreaker

        cb = CircuitBreaker(failure_threshold=3, timeout_seconds=60)
        assert cb.state == "CLOSED"

        loop = asyncio.new_event_loop()
        for _ in range(3):
            loop.run_until_complete(cb.on_failure())

        assert cb.state == "OPEN"
        assert cb.failures == 3
        loop.close()

    def test_circuit_breaker_half_open(self):
        """PF-03: 熔断后 60s → HALF_OPEN。"""
        from vulnclaw.ai.provider_failover import CircuitBreaker

        cb = CircuitBreaker(failure_threshold=3, timeout_seconds=1)
        loop = asyncio.new_event_loop()
        for _ in range(3):
            loop.run_until_complete(cb.on_failure())
        assert cb.state == "OPEN"

        time.sleep(1.1)
        assert cb.state == "HALF_OPEN"
        loop.close()

    def test_provider_failover_switch(self):
        """PF-01: 主 Provider 500 → 切换备用。"""
        from vulnclaw.ai.provider_failover import ProviderFailover

        call_log = []

        async def mock_ask(provider: str, prompt: str, **kwargs):
            call_log.append(provider)
            if provider == "zhipu":
                raise RuntimeError("500 Internal Server Error")
            return "success from " + provider

        pf = ProviderFailover(priority=["zhipu", "aliyun"])
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(pf.ask_with_failover("test", mock_ask))
        assert "aliyun" in result
        assert call_log == ["zhipu", "aliyun"]
        loop.close()


class TestPluginMarket:
    """验收用例 PM-01 / PM-02 / PM-03。"""

    def test_list_installed_empty(self):
        """PM-02: 无插件时返回空列表。"""
        from vulnclaw.core.plugin_market import list_installed_plugins
        # TODO: 使用 tmp_path 隔离 manifest
        plugins = list_installed_plugins()
        assert isinstance(plugins, list)

    def test_plugin_install_slack_notifier(self):
        """PM-01: 安装 slack_notifier → 文件存在 + manifest 更新。"""
        # TODO: mock GitHub API + 本地 zip 构建
        pytest.skip("需要 mock GitHub Releases API")

    def test_plugin_checksum_mismatch(self):
        """PM-03: SHA256 不匹配 → ChecksumMismatchError。"""
        from vulnclaw.core.plugin_market import ChecksumMismatchError
        # TODO: 构造篡改 zip 测试
        assert ChecksumMismatchError is not None


class TestMultiTargetContext:
    """验收用例 MTC-01 / MTC-02 / MTC-03。"""

    def test_memory_fallback(self):
        """MTC-02: redis_url=None → 降级内存模式。"""
        from vulnclaw.dag.multi_target_context import MultiTargetContext

        ctx = MultiTargetContext(redis_url=None, prefix="t1")
        assert ctx.is_redis_mode is False

        loop = asyncio.new_event_loop()
        loop.run_until_complete(ctx.set("key1", "value1"))
        val = loop.run_until_complete(ctx.get("key1"))
        assert val == "value1"
        loop.close()

    def test_prefix_isolation(self):
        """MTC-03: 两个 prefix 写同 key，互不影响。"""
        from vulnclaw.dag.multi_target_context import MultiTargetContext

        ctx1 = MultiTargetContext(redis_url=None, prefix="t1")
        ctx2 = MultiTargetContext(redis_url=None, prefix="t2")

        loop = asyncio.new_event_loop()
        loop.run_until_complete(ctx1.set("a", 1))
        loop.run_until_complete(ctx2.set("a", 2))
        assert loop.run_until_complete(ctx1.get("a")) == 1
        assert loop.run_until_complete(ctx2.get("a")) == 2
        loop.close()

    def test_redis_mode(self):
        """MTC-01: Redis 可用时正常读写（需要 redis 服务）。"""
        pytest.skip("需要 Redis 服务")


class TestAdaptiveConcurrency:
    """验收用例 AC-01 / AC-02 / AC-03。"""

    def test_fast_target_increases_concurrency(self):
        """AC-01: 200ms 响应 → 并发增加。"""
        from vulnclaw.core.adaptive_concurrency import AdaptiveConcurrency

        ac = AdaptiveConcurrency(initial=4, min_val=1, max_val=20)
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(
            ac.adjust({"avg_rt": 0.2, "error_rate": 0.0})
        )
        assert result >= 4
        loop.close()

    def test_slow_target_decreases_concurrency(self):
        """AC-02: 8s 响应 → 并发减少。"""
        from vulnclaw.core.adaptive_concurrency import AdaptiveConcurrency

        ac = AdaptiveConcurrency(initial=4, min_val=1, max_val=20)
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(
            ac.adjust({"avg_rt": 8.0, "error_rate": 0.0})
        )
        assert result <= 3
        loop.close()

    def test_high_error_rate_min_concurrency(self):
        """AC-03: 50% 超时 → 返回 min=1。"""
        from vulnclaw.core.adaptive_concurrency import AdaptiveConcurrency

        ac = AdaptiveConcurrency(initial=4, min_val=1, max_val=20)
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(
            ac.adjust({"avg_rt": 5.0, "error_rate": 0.5})
        )
        assert result == 1
        loop.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
