"""单元测试：目标请求能力探测（Target Capacity Probe）。

状态机（指纹→渐进→短突发→收口）、注册表、回退、封顶、set_qps、消费点形状。
全部用注入假 send_one + 假 settings 的 asyncio 直驱模式，不依赖外网。
"""
import asyncio
from types import SimpleNamespace

import pytest

from vulnclaw.ai.v100.rate_limiter import AdaptiveRateLimiter
from vulnclaw.core.target_capacity_probe import (
    CapacityResult, ProbeSample, run_capacity_probe,
    get_capacity, get_safe_qps, get_safe_concurrency,
    set_capacity, reset_capacity, reset_all_capacity,
    compute_adaptive_budget,
)


TARGET = "http://probe.example.com/"


def run(coro):
    return asyncio.run(coro)


def make_cfg(**over):
    """假 settings：探测用最短时长，保证测试快速且无真实时钟依赖。"""
    base = dict(
        enable_target_probe=True,
        target_probe_timeout_s=30,
        target_probe_levels=[2.0, 4.0, 8.0, 16.0],
        target_probe_duration_s=0.001,
        target_probe_burst_multiplier=2.5,
        target_probe_burst_duration_s=0.001,
        target_probe_safety_factor=0.7,
        target_probe_qps_cap=50.0,
        target_probe_concurrency_cap=64,
        target_probe_ok_ratio=0.95,
        allowed_scope="",
        proxy=None,
        user_agent="test-ua",
    )
    base.update(over)
    return SimpleNamespace(**base)


def ok_sample(rt_ms=200.0, server="nginx"):
    return ProbeSample(status=200, rt_ms=rt_ms, latency_ms=rt_ms, headers={"Server": server})


def sig_sample(sig: str):
    """构造携带指定降级信号的采样（按信号选择状态码/错误文本）。"""
    mapping = {
        "429": (429, ""),
        "403": (403, ""),
        "5xx": (500, ""),
        "timeout": (0, "Request timed out"),
        "connect_reset": (0, "Connection reset by peer"),
        "other": (0, "boom"),
    }
    status, error = mapping[sig]
    return ProbeSample(status=status, rt_ms=50.0, error=error)


@pytest.fixture(autouse=True)
def _isolate_registry():
    yield
    reset_all_capacity()


def make_sender(rule):
    """rule(qps, is_fingerprint) -> ProbeSample；把 2xx/3xx 之外的场景全部提前过滤。"""
    async def sender(target, qps=None):
        return rule(qps)
    return sender


class TestFingerprint:
    def test_short_circuit_when_not_2xx(self):
        """指纹未拿 2xx/3xx → probed=False 短路。"""
        calls = []

        async def sender(target, qps=None):
            calls.append(True)
            return ProbeSample(status=404, rt_ms=50.0)

        r = run(run_capacity_probe(TARGET, settings=make_cfg(), send_one=sender))
        assert r.probed is False
        assert len(calls) == 1  # 只打了指纹请求
        assert get_safe_qps() is None
        assert get_safe_concurrency() is None

    def test_unreachable_never_raises(self):
        """send_one 抛 ConnectionRefusedError → probed=False 且不冒泡。"""
        async def sender(target, qps=None):
            raise ConnectionRefusedError("refused")

        r = run(run_capacity_probe(TARGET, settings=make_cfg(), send_one=sender))
        assert r.probed is False
        assert get_safe_qps() is None


class TestProgressive:
    def test_normal_convergence(self):
        """全 200 → 收敛到最高档 16QPS → safe=min(16*0.7,50)=11.2，burst OK。"""
        r = run(run_capacity_probe(
            TARGET, settings=make_cfg(), send_one=make_sender(lambda qps: ok_sample(rt_ms=200.0))))
        assert r.probed is True
        assert r.raw_qps == 16.0
        assert r.safe_qps == round(16.0 * 0.7, 2)
        assert r.burst_ok is True
        assert r.signal == ""
        assert get_safe_concurrency() == r.safe_concurrency

    def test_429_degrade(self):
        """档位升到 8 触发 429 → safe 取上一级 4QPS，signal=429。"""
        async def sender(target, qps=None):
            if qps is not None and qps > 4:
                return sig_sample("429")
            return ok_sample()

        r = run(run_capacity_probe(TARGET, settings=make_cfg(), send_one=sender))
        assert r.probed is True
        assert r.signal == "429"
        assert r.stopped_level_qps == 8.0
        assert r.raw_qps == 4.0
        assert r.safe_qps == round(4.0 * 0.7, 2)
        # burst 在 safe*2.5=7QPS 上发生——仍 >4，假发器仍返回 429 → burst 不通过
        assert r.burst_ok is False

    def test_403_degrade(self):
        async def sender(target, qps=None):
            if qps is not None and qps > 4:
                return sig_sample("403")
            return ok_sample()

        r = run(run_capacity_probe(TARGET, settings=make_cfg(), send_one=sender))
        assert r.signal == "403"
        assert r.safe_qps == round(4.0 * 0.7, 2)

    def test_5xx_degrade(self):
        async def sender(target, qps=None):
            if qps is not None and qps > 2:
                return sig_sample("5xx")
            return ok_sample()

        r = run(run_capacity_probe(TARGET, settings=make_cfg(), send_one=sender))
        assert r.signal == "5xx"
        assert r.stopped_level_qps == 4.0
        assert r.raw_qps == 2.0
        assert r.safe_qps == round(2.0 * 0.7, 2)

    def test_timeout_all_fail_backoff(self):
        """恒 timeout → 指纹即失败，probed=False，回退默认。"""
        r = run(run_capacity_probe(
            TARGET, settings=make_cfg(), send_one=make_sender(lambda qps: sig_sample("timeout"))))
        assert r.probed is False
        assert r.signal == "timeout"
        assert get_safe_qps() is None

    def test_qps_cap_and_concurrency_cap(self):
        """收敛到 200QPS → safe 截断到 50，并发截断到 64。"""
        cfg = make_cfg(target_probe_levels=[2.0, 8.0, 32.0, 64.0, 128.0, 200.0])
        r = run(run_capacity_probe(
            TARGET, settings=cfg, send_one=make_sender(lambda qps: ok_sample(rt_ms=1500.0))))
        assert r.probed is True
        assert r.raw_qps == 200.0
        assert r.safe_qps == 50.0  # min(200*0.7, 50)
        assert r.safe_concurrency == 64  # round(50*1.5)=75 → 截断到 64


class TestBurst:
    def test_burst_ok_when_all_ok(self):
        r = run(run_capacity_probe(
            TARGET, settings=make_cfg(), send_one=make_sender(lambda qps: ok_sample())))
        assert r.burst_ok is True
        assert r.safe_qps == round(16.0 * 0.7, 2)

    def test_burst_fail_keeps_safe(self):
        """突发段在 safe*2.5 上返 429 → burst_ok=False，但 safe 维持原值。"""
        async def sender(target, qps=None):
            if qps is not None and qps >= 16 * 2.5:
                return sig_sample("429")
            return ok_sample()

        r = run(run_capacity_probe(TARGET, settings=make_cfg(), send_one=sender))
        assert r.probed is True
        assert r.burst_ok is False
        assert r.raw_qps == 16.0
        assert r.safe_qps == round(16.0 * 0.7, 2)  # 突发失败不降 safe


class TestRegistryAndSwitch:
    def test_consumers_fall_back_to_none(self):
        """未探测：get_safe_* 返回 None（消费点走静态默认值）。"""
        assert get_safe_qps() is None
        assert get_safe_concurrency() is None

    def test_consumer_shape_uses_probe_result(self):
        """已探测（safe_concurrency=12）：消费点表达式直接取到 12。"""
        set_capacity(TARGET, CapacityResult(probed=True, safe_qps=8.0, safe_concurrency=12))
        assert get_safe_concurrency() == 12
        assert get_safe_qps() == 8.0
        assert int(get_safe_concurrency() or 10) == 12  # phases_executor 消费形状
        assert int(get_safe_concurrency() or 16) == 12  # recon/爬虫 消费形状

    def test_disable_switch_skips_probe(self):
        """enable_target_probe=False → 探测短路，send_one 不被调用。"""
        calls = []

        async def sender(target, qps=None):
            calls.append(True)
            return ok_sample()

        r = run(run_capacity_probe(TARGET, settings=make_cfg(enable_target_probe=False), send_one=sender))
        assert r.probed is False
        assert calls == []
        assert get_safe_qps() is None

    def test_host_key_isolation(self):
        """多目标按 host 隔离注册表；get_capacity 无参回退"最近一次"。"""
        set_capacity("http://a.com/", CapacityResult(probed=True, safe_qps=1.0, safe_concurrency=2))
        set_capacity("http://b.com/", CapacityResult(probed=True, safe_qps=3.0, safe_concurrency=4))
        assert get_capacity("http://a.com/").safe_qps == 1.0
        assert get_capacity("http://b.com/").safe_qps == 3.0
        reset_capacity("http://a.com/")
        # a.com 已清 → 无 target 参数消费点回退"最近一次结果"（b.com）
        assert get_safe_qps() == 3.0

    def test_timeout_budget_no_raise(self):
        """整体超时（target_probe_timeout_s=0.01）→ probed=False 不抛异常。"""
        async def slow(target, qps=None):
            await asyncio.sleep(5)
            return ok_sample()

        r = run(run_capacity_probe(
            TARGET, settings=make_cfg(target_probe_timeout_s=0.01), send_one=slow))
        assert r.probed is False


class TestSetQps:
    def test_set_qps_only_affects_target_model_bucket(self):
        rl = AdaptiveRateLimiter(initial_qps=3)
        run(rl.set_qps(8))
        assert rl.current_qps == 8
        assert rl._model_qps["glm-4-flash"] == 8
        # 其他 LLM 模型桶不受影响
        assert rl._model_qps["qwen-plus-2025-07-28"] == 3

        # 1 秒窗口内允许 8 次
        waits = [run(rl.acquire("glm-4-flash")) for _ in range(8)]
        assert all(w == 0 for w in waits)
        assert run(rl.acquire("glm-4-flash")) > 0  # 第 9 次需等待

    def test_set_qps_clamped_to_bounds(self):
        rl = AdaptiveRateLimiter(initial_qps=3)
        run(rl.set_qps(9999.0))
        assert rl.current_qps == rl._max_qps
        run(rl.set_qps(-5.0))
        assert rl.current_qps == rl._min_qps


class TestComputeAdaptiveBudget:
    """超时工作量自适应预算：地板保护 / 随规模放大 / 封顶 / 参数敏感性 / 回退默认。

    这些用例同时锁死一个历史 latent bug：函数内引用了未定义的 `settings`
    （模块只 import 为 `_default_settings`），所有不传 floor 的调用点
    （phases_executor / orchestrator）都会 NameError。修复后用真实 settings 回退。
    """

    def test_floor_protects_small_targets(self):
        """小目标：即便算出来很小，也维持地板（attack_node_budget）。"""
        v = compute_adaptive_budget(10, worker=8, rt_ms=200.0, per_task_s=4.0, floor=500.0)
        assert v == 500.0

    def test_scales_with_pending(self):
        """大目标（待执行多）→ 预算随规模放大，超过地板。"""
        v = compute_adaptive_budget(1000, worker=8, rt_ms=200.0, per_task_s=4.0, floor=500.0)
        # needed = 1000 * 4 * 1.0 / 8 * 1.3 = 650
        assert v == pytest.approx(650.0, abs=0.5)

    def test_cap_clamps(self):
        """封顶生效：极端 pending 也不无限放大。"""
        v = compute_adaptive_budget(1_000_000, worker=8, rt_ms=200.0, per_task_s=4.0,
                                    floor=500.0, cap=3600.0)
        assert v == 3600.0

    def test_worker_halves_budget(self):
        """并发翻倍 → 预算减半。"""
        a = compute_adaptive_budget(800, worker=4, rt_ms=200.0, per_task_s=4.0, floor=0.0)
        b = compute_adaptive_budget(800, worker=8, rt_ms=200.0, per_task_s=4.0, floor=0.0)
        assert b == pytest.approx(a / 2, rel=0.01)

    def test_rt_ms_scales(self):
        """RT 翻倍（rt_ms=400 vs 200）→ 预算翻倍。"""
        a = compute_adaptive_budget(800, worker=8, rt_ms=200.0, per_task_s=4.0, floor=0.0)
        b = compute_adaptive_budget(800, worker=8, rt_ms=400.0, per_task_s=4.0, floor=0.0)
        assert b == pytest.approx(a * 2, rel=0.01)

    def test_per_task_scales(self):
        """单任务耗时翻倍 → 预算翻倍。"""
        a = compute_adaptive_budget(800, worker=8, rt_ms=200.0, per_task_s=2.0, floor=0.0)
        b = compute_adaptive_budget(800, worker=8, rt_ms=200.0, per_task_s=4.0, floor=0.0)
        assert b == pytest.approx(a * 2, rel=0.01)

    def test_safety_factor(self):
        """安全系数翻倍 → 预算翻倍。"""
        a = compute_adaptive_budget(800, worker=8, rt_ms=200.0, per_task_s=4.0, floor=0.0, safety=1.3)
        b = compute_adaptive_budget(800, worker=8, rt_ms=200.0, per_task_s=4.0, floor=0.0, safety=2.6)
        assert b == pytest.approx(a * 2, rel=0.01)

    def test_negative_pending_treated_as_zero(self):
        """pending<=0 → 0，不放大（维持地板）。"""
        v = compute_adaptive_budget(-5, worker=8, rt_ms=200.0, per_task_s=4.0, floor=500.0)
        assert v == 500.0

    def test_fallback_to_defaults_no_crash(self):
        """不传任何参数（走 settings 回退分支）→ 不抛异常（修复前 NameError 回归）。

        注册表清空 → rt_ms 回退 200；worker 回退 orchestrator_max_concurrent；
        per_task_s 回退 attack_per_task_s；floor 回退 attack_node_budget。
        """
        reset_all_capacity()
        v = compute_adaptive_budget(100)  # 全走默认
        assert isinstance(v, float)
        assert v >= 500.0  # 默认地板 attack_node_budget

    def test_rt_floor_ratio(self):
        """rt 比率下限 0.5：极快目标（rt=10ms）单任务成本不被压到趋近 0。

        实测根因回归：本地靶机 rt~3ms 时 per_task 被压到 0.06s，预算失真。
        """
        # ratio = max(10/200, 0.5) = 0.5 → needed = 400*4*0.5/2*1.3 = 520
        v = compute_adaptive_budget(400, worker=2, rt_ms=10.0, per_task_s=4.0, floor=500.0)
        assert v == pytest.approx(520.0, abs=0.5)


class TestFastTargetConcurrencyFloor:
    """极快目标（本地靶机）并发下限：防打挂靠 safe_qps 限流，并发不应被压到 1。"""

    def test_fast_target_concurrency_floor(self):
        """rt=3ms 全 OK 收敛 → Little's Law 算出 0 → 下限抬到 4。"""
        r = run(run_capacity_probe(
            TARGET, settings=make_cfg(), send_one=make_sender(lambda qps: ok_sample(rt_ms=3.0))))
        assert r.probed is True
        assert r.safe_qps == round(16.0 * 0.7, 2)  # 11.2
        assert r.safe_concurrency >= 4  # 修复前 round(11.2*0.003)=0 → 1

    def test_slow_target_not_capped_by_floor(self):
        """慢目标（rt=1500ms、safe=50）并发 75 → 仍按 cap 64，不受下限影响。"""
        cfg = make_cfg(target_probe_levels=[2.0, 8.0, 32.0, 64.0, 128.0, 200.0])
        r = run(run_capacity_probe(
            TARGET, settings=cfg, send_one=make_sender(lambda qps: ok_sample(rt_ms=1500.0))))
        assert r.safe_concurrency == 64