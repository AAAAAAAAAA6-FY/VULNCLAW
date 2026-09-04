# -*- coding: utf-8 -*-
"""A5.6: 阶段化工具裁剪测试。

覆盖：STAGE_TO_ROLE 映射正确性；stage_tool_keys 白名单收敛；
ReActAgent(stage=...) 工具集裁剪；role 优先于 stage；未知/空阶段保持全量。
"""
import pytest

from vulnclaw.ai.dispatcher import AGENT_ROLES, STAGE_TO_ROLE, stage_tool_keys


class TestStageToolKeys:
    def test_stage_role_mapping(self):
        assert STAGE_TO_ROLE["recon"] == "recon"
        assert STAGE_TO_ROLE["taskgen"] == "analysis"
        assert STAGE_TO_ROLE["execute"] == "exploit"
        assert STAGE_TO_ROLE["verify"] == "verify"

    def test_known_stage_returns_whitelist(self):
        tools = stage_tool_keys("recon")
        assert tools == list(AGENT_ROLES["recon"]["tools"])

    def test_case_insensitive_stage(self):
        assert stage_tool_keys("EXECUTE") == list(AGENT_ROLES["exploit"]["tools"])

    def test_unknown_or_empty_stage_returns_none(self):
        assert stage_tool_keys("bogus") is None
        assert stage_tool_keys("") is None
        assert stage_tool_keys(None) is None

    def test_whitelists_are_real_registered_tools(self):
        from vulnclaw.ai.tools import TOOL_REGISTRY
        for stage in ("recon", "execute", "verify"):
            keys = stage_tool_keys(stage)
            assert keys, f"{stage} 白名单不能为空"
            for k in keys:
                assert k in TOOL_REGISTRY, f"{stage} 白名单含未注册工具 {k}"


class TestReActAgentStageTrim:
    def _mk_agent(self, monkeypatch, stage="", role=""):
        import vulnclaw.ai.dispatcher as disp

        class _Ctx:
            def __init__(self):
                self.__dict__ = {}

        monkeypatch.setattr(disp, "get_llm_client", lambda: object())
        monkeypatch.setattr(disp, "get_memory", lambda: None)
        monkeypatch.setattr(disp, "get_scan_context", lambda: _Ctx())
        monkeypatch.setattr(disp, "get_rule_engine", lambda: None)
        return disp.ReActAgent(target="http://t.example.com", session=None,
                               max_iterations=2, stage=stage, role=role)

    def test_no_stage_no_role_keeps_full_toolkit(self, monkeypatch):
        from vulnclaw.ai.tools import TOOL_REGISTRY
        agent = self._mk_agent(monkeypatch)
        assert set(agent.tools) == set(TOOL_REGISTRY)

    def test_recon_stage_trims_to_recon_tools(self, monkeypatch):
        agent = self._mk_agent(monkeypatch, stage="recon")
        assert set(agent.tools) == set(AGENT_ROLES["recon"]["tools"])
        # recon 白名单不含利用类工具
        assert "file_upload" not in agent.tools

    def test_execute_stage_trims_to_exploit_tools(self, monkeypatch):
        agent = self._mk_agent(monkeypatch, stage="execute")
        assert set(agent.tools) == set(AGENT_ROLES["exploit"]["tools"])
        # exploit 白名单不含侦察工具
        assert "info_leak" not in agent.tools
        assert "security_headers" not in agent.tools

    def test_role_takes_precedence_over_stage(self, monkeypatch):
        agent = self._mk_agent(monkeypatch, stage="recon", role="analysis")
        assert set(agent.tools) == set(AGENT_ROLES["analysis"]["tools"])

    def test_unknown_stage_keeps_full_toolkit(self, monkeypatch):
        from vulnclaw.ai.tools import TOOL_REGISTRY
        agent = self._mk_agent(monkeypatch, stage="zzz")
        assert set(agent.tools) == set(TOOL_REGISTRY)