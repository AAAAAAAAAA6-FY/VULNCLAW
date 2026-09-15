# -*- coding: utf-8 -*-
"""阶段方法绑定完整性测试。

为什么存在：
  bind_phase_methods 按各 phases 模块的 __all__ 把函数绑到 V100Orchestrator。
  实测事故（rest.vulnweb.com 首扫）：__all__ 漏了 _run_invariant_diff_line →
  extras 阶段 AttributeError → vulnspec/metamorphic/sequence 全部静默不跑。
  本测试把"__all__ 名单完整性"和"extras 依赖的方法必须存在"钉死为回归红线。
"""
from types import SimpleNamespace

from vulnclaw.ai.v100.phases import bind_phase_methods
from vulnclaw.ai.v100.phases import (phases_recon, phases_report,
                                     phases_taskgen, phases_verify,
                                     phases_executor)


def _bound():
    """对哑对象执行真实绑定，返回该对象（MethodType 对任意实例都可用）。"""
    dummy = SimpleNamespace()
    bind_phase_methods(dummy)
    return dummy


class TestAllListsAreHonest:
    """每个模块的 __all__ 里的名字必须真实存在——防'__all__ 写了但函数没了'或反向。"""

    def test_taskgen_all_names_exist(self):
        for name in phases_taskgen.__all__:
            assert callable(getattr(phases_taskgen, name, None)), \
                f"phases_taskgen.__all__ 里的 {name} 不可调用（拼写错误或函数被删）"

    def test_recon_verify_executor_report_all_exist(self):
        for mod in (phases_recon, phases_verify, phases_executor, phases_report):
            for name in mod.__all__:
                assert callable(getattr(mod, name, None)), \
                    f"{mod.__name__}.__all__ 里的 {name} 不可调用"


class TestExtrasBlockDependencies:
    """_run_extras_block / _scan_idor 引用的 self 方法必须在绑定后存在。

    这份清单来自 phases/orchestrator 源码中的调用点（extras 链路），
    漏一个就是一次"扫描尾巴整段静默丢失"的事故。
    """

    REQUIRED = [
        # _run_extras_block（orchestrator.py）
        "_scan_idor",
        "_run_nuclei_community_line",
        "_check_default_creds",
        "_run_vulnspec_line",
        "_run_metamorphic_line",
        "_run_sequence_chain_line",
        # _scan_idor（phases_taskgen.py:95-101）
        "_run_idor_dual_session_line",
        "_run_invariant_diff_line",   # 本次事故的主角
        "_run_playbook_line",
        "_run_symbolic_line",
        "_run_chain_planner_line",
    ]

    def test_all_required_methods_bound(self):
        dummy = _bound()
        missing = [m for m in self.REQUIRED if not callable(getattr(dummy, m, None))]
        assert not missing, f"绑定后仍缺失的方法（extras 会静默丢段）: {missing}"

    def test_invariant_diff_line_is_bound(self):
        """事故回归红线：_run_invariant_diff_line 曾漏出 __all__ 导致 extras 崩块。"""
        dummy = _bound()
        assert callable(getattr(dummy, "_run_invariant_diff_line", None))
