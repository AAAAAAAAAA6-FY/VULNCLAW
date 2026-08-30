"""集成冒烟测试：引擎装配 / phases 绑定 / modules 门面 / 任务分派占位。

不依赖外网与真实 AI；只验证结构装配正确。
"""
import asyncio

import pytest


class TestEngineLoading:
    def test_engines_autodiscovered(self):
        from vulnclaw.core.scanner import _load_engines
        engines, engine_map = _load_engines()
        assert len(engines) >= 20, f"引擎装配数量异常: {len(engines)}"
        # 关键引擎必须在位
        for required in ("sqli", "xss", "lfi"):
            assert required in engine_map, f"缺少关键引擎: {required}"

    def test_every_engine_has_name(self):
        from vulnclaw.core.scanner import _load_engines
        engines, _ = _load_engines()
        names = [e.name for e in engines]
        assert len(names) == len(set(names)), "存在重复引擎 name"


class TestPhasesBinding:
    def test_all_phase_methods_bound(self):
        from vulnclaw.ai.v100.phases import (
            bind_phase_methods,
            phases_executor,
            phases_recon,
            phases_report,
            phases_taskgen,
            phases_verify,
        )

        required = set()
        for mod in (phases_recon, phases_taskgen, phases_executor, phases_verify, phases_report):
            required.update(mod.__all__)

        class Empty:
            pass

        e = Empty()
        bind_phase_methods(e)
        for name in required:
            assert hasattr(e, name), f"phase 方法未绑定: {name}"


class TestModulesFacade:
    def test_legacy_exports_available(self):
        from vulnclaw.modules import (  # noqa: F401
            alive_scan,
            port_scan,
            get_subdomains,
            get_subdomains_async,
            EndpointCollector,
            scan_session_security,
            verify_with_ai,
            batch_verify_with_ai,
            run_nuclei_async,
            run_ffuf_async,
            get_interactsh_domain_async,
            get_interactsh_poll,
            scan_idor,
            scan_vertical_privilege,
            scan_llm_injection,
            scan_spring_actuator,
            scan_oauth_hijack,
            scan_graphql_introspection,
            scan_dns_rebinding,
            run_all_advanced_ai_checks,
        )


class TestTaskDispatch:
    def test_phase2_placeholders_skip_cleanly(self):
        from vulnclaw.ai.v100.phases import phases_executor

        class DummyQueue:
            async def complete_task(self, *a, **k):
                pass

        class FakeOrchestrator:
            task_queue = DummyQueue()

        async def run_one(task_type):
            return await phases_executor._execute_task(
                FakeOrchestrator(), {"type": task_type}
            )

        for placeholder in ("stateful_flow", "multi_identity_compare", "openapi_spec_check"):
            assert asyncio.run(run_one(placeholder)) is None

    def test_unknown_type_returns_none(self):
        from vulnclaw.ai.v100.phases import phases_executor

        class FakeOrchestrator:
            pass

        result = asyncio.run(
            phases_executor._execute_task(FakeOrchestrator(), {"type": "__nope__"})
        )
        assert result is None


class TestSettingsPaths:
    def test_project_cache_dir_under_root(self):
        import os
        from vulnclaw.core.settings import PROJECT_CACHE_DIR, PROJECT_ROOT

        assert os.path.isdir(PROJECT_ROOT)
        assert PROJECT_CACHE_DIR.startswith(PROJECT_ROOT)
        assert PROJECT_CACHE_DIR.endswith("_runtime_cache")

    def test_wordlist_resolver_finds_config(self):
        from vulnclaw.modules.recon import _resolve_wordlist_path

        resolved = _resolve_wordlist_path("subdomains_top5000.txt")
        assert resolved.endswith("subdomains_top5000.txt")
