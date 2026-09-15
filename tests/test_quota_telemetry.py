"""P1-2 回归：计划线配额消耗遥测（record_quota / _quota_log）端到端验证。

背景：第二次真实扫描发现 _quota_log 不支持 note= 关键字参数，导致 no-candidates
早退路径抛 TypeError 被吞，coverage.json 的 quota_usage 全空。本测试确定性复现
并锁死该修复，避免再烧 20 分钟真实扫描。
"""
import asyncio
import types

import vulnclaw.core.coverage as cov
from vulnclaw.ai.v100.phases import phases_taskgen as ptg


def _reset_ledger():
    cov._LEDGER = None
    return cov.get_coverage_ledger()


def test_quota_log_accepts_note_and_records():
    """复现真实崩溃：_quota_log(..., note='no_candidates') 之前抛
    TypeError: _quota_log() got an unexpected keyword argument 'note'。"""
    led = _reset_ledger()
    # 这是计划线 no-candidates 早退路径的真实调用形态
    ptg._quota_log("invariant_diff", 30, 0, 0, note="no_candidates")
    assert len(led._quotas) == 1
    q = led._quotas[0]
    assert q["line"] == "invariant_diff"
    assert q["verdict"] == "no_candidates"
    assert q["note"] == "no_candidates"


def test_quota_verdicts_saturated_wasted_balanced():
    """三态聚合：候选超预算→saturated；配额没用满→wasted；用满→balanced。"""
    led = _reset_ledger()
    led.record_quota("idor", limit=40, candidates=100, executed=40)       # candidates>limit
    led.record_quota("vulnspec", limit=10, candidates=3, executed=2)       # executed<limit
    led.record_quota("balanced_line", limit=10, candidates=10, executed=10)  # 用满→balanced
    u = led.quota_usage()
    assert u["lines"], "至少应记录 3 条"
    assert "idor" in u["saturated"], "候选超预算线应标记为 saturated"
    assert "vulnspec" in u["wasted"], "配额没用满线应标记为 wasted"
    assert "balanced_line" not in u["saturated"] and "balanced_line" not in u["wasted"]


def test_plan_line_no_candidates_records_telemetry():
    """实跑一条计划线（INVARIANT）的 no-candidates 路径，确认经修复后
    _quota_log(note=...) 真正落账，而非静默吞掉。"""
    _reset_ledger()

    # 保证 InvariantDiffEngine 可被 import（即便真实引擎缺依赖），空候选不会实例化它
    try:
        import vulnclaw.engines.invariant_diff_engine as ide  # noqa: F401
    except Exception:
        ide = types.ModuleType("vulnclaw.engines.invariant_diff_engine")
        import sys
        sys.modules["vulnclaw.engines.invariant_diff_engine"] = ide
    ide.InvariantDiffEngine = object  # 占位，no-candidates 路径用不到

    fake = types.SimpleNamespace(
        _recon_brief={}, target="http://example.com", _add_finding=lambda f: None
    )
    made = asyncio.run(ptg._run_invariant_diff_line(fake))
    assert made == 0, "空候选应早退，产出 0"

    led = cov.get_coverage_ledger()
    assert any(q["line"] == "invariant_diff" and q["verdict"] == "no_candidates"
               for q in led._quotas), "no-candidates 路径必须落账"


def test_all_six_plan_lines_bound():
    """P1-2-1：6 条计划线函数全部存在于模块命名空间（曾因 _run_invariant_diff_line
    漏进 __all__ 导致 AttributeError 崩块）。"""
    for name in ("_run_idor_dual_session_line", "_run_invariant_diff_line",
                 "_run_vulnspec_line", "_run_metamorphic_line",
                 "_run_nuclei_community_line", "_run_chain_planner_line"):
        assert hasattr(ptg, name), f"{name} 未绑定到 phases_taskgen"
