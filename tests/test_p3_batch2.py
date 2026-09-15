# -*- coding: utf-8 -*-
"""P3 第二批（2026-09-15）单元测试：

#7 多智能体辩论复核（verification_gateway.multi_agent_verify_batch）
#9 背压闸门（core.backpressure）
#10 JS 运行时 hook（core.js_hooks）
#11 原生 YAML 模板解释器（core.native_templates）
#12 run_sync 协程安全执行（core.utils）
#13 OOB 审计链内存封顶（core.oob_channel）
"""
import asyncio

import pytest


class TestRunSync:
    def test_outside_loop(self):
        from vulnclaw.core.utils import run_sync

        async def _c():
            return 42

        assert run_sync(_c()) == 42

    def test_inside_loop_no_crash(self):
        """事件循环内调用不再抛 RuntimeError（原 asyncio.run 会炸）"""
        from vulnclaw.core.utils import run_sync

        async def _inner():
            return "ok"

        async def _outer():
            return run_sync(_inner())

        assert asyncio.run(_outer()) == "ok"


class TestBackpressureGate:
    def test_disabled_always_proceeds(self):
        from vulnclaw.core.backpressure import BackpressureGate
        g = BackpressureGate(high=10, low=5, enabled=False)
        assert g.should_proceed(999) is True

    def test_enabled_blocks_at_high(self):
        from vulnclaw.core.backpressure import BackpressureGate
        g = BackpressureGate(high=10, low=5, enabled=True)
        assert g.should_proceed(9) is True
        assert g.should_proceed(10) is False
        assert g.should_proceed(11) is False

    def test_low_clamped_below_high(self):
        from vulnclaw.core.backpressure import BackpressureGate
        g = BackpressureGate(high=10, low=999, enabled=True)
        assert g.low < g.high


class TestJsHooks:
    def test_hook_js_covers_all_sinks(self):
        from vulnclaw.core.js_hooks import JS_HOOK
        for key in ("innerHTML", "eval", "document.write", "insertAdjacentHTML",
                    "cookie", "__vulnclaw_hits", "__vulnclaw_hooked",
                    "XMLHttpRequest", "fetch", "MutationObserver", "dom."):
            assert key in JS_HOOK

    def test_sink_taxonomy(self):
        from vulnclaw.core import js_hooks
        assert "cookie.read" in js_hooks.DATA_SINKS
        assert "xhr.open" in js_hooks.NET_SINKS and "fetch" in js_hooks.NET_SINKS
        assert "dom.script_inject" in js_hooks.OBSERVER_SINKS


class TestSyncRespText:
    def test_tuple_input(self):
        from vulnclaw.core.utils import sync_resp_text
        assert sync_resp_text((200, "body", {})) == "body"

    def test_unread_body_returns_empty(self):
        """未读 body 的 response：返回空串（绝不 asyncio.run / 阻塞）"""
        from vulnclaw.core.utils import sync_resp_text

        class _Resp:
            _body = None

        assert sync_resp_text(_Resp()) == ""

    def test_read_body_decoded(self):
        from vulnclaw.core.utils import sync_resp_text

        class _Resp:
            _body = "中文".encode("utf-8")

        assert sync_resp_text(_Resp()) == "中文"

    def test_garbage_safe(self):
        from vulnclaw.core.utils import sync_resp_text
        assert sync_resp_text(None) == ""
        assert sync_resp_text(object()) == ""

    def test_summarize_hits(self):
        from vulnclaw.core.js_hooks import summarize_hits
        hits = [{"sink": "innerHTML", "detail": "x"},
                {"sink": "eval", "detail": "y"},
                {"sink": "innerHTML"}]
        s = summarize_hits(hits)
        assert "innerHTML" in s and "eval" in s
        assert summarize_hits([]) == ""
        assert summarize_hits(None) == ""


class TestNativeTemplates:
    def test_status_matcher(self):
        from vulnclaw.core.native_templates import _match_one
        assert _match_one({"type": "status", "status": [200]}, 200, "") is True
        assert _match_one({"type": "status", "status": [200]}, 404, "") is False

    def test_word_matcher_and_negative(self):
        from vulnclaw.core.native_templates import _match_one
        assert _match_one({"type": "word", "words": ["root:x:"]}, 200, "a root:x:0:0") is True
        assert _match_one({"type": "word", "words": ["root:x:"]}, 200, "abc") is False
        assert _match_one({"type": "word", "words": ["root:x:"], "negative": True}, 200, "abc") is True

    def test_regex_matcher(self):
        from vulnclaw.core.native_templates import _match_one
        assert _match_one({"type": "regex", "regex": [r"v\d+\.\d+"]}, 200, "app v1.2 here") is True
        assert _match_one({"type": "regex", "regex": [r"^zzz$"]}, 200, "app v1.2") is False

    def test_unsupported_type_returns_false(self):
        from vulnclaw.core.native_templates import _match_one
        assert _match_one({"type": "dsl", "dsl": ["x"]}, 200, "x") is False

    @pytest.mark.asyncio
    async def test_run_template_end_to_end(self):
        """起本地 aiohttp 靶机跑原生模板：status+word matcher（condition=and）命中"""
        import aiohttp
        from aiohttp import web

        from vulnclaw.core.native_templates import run_template

        async def _h(request):
            return web.Response(text="SECRET_MARKER_12345", status=200)

        app = web.Application()
        app.router.add_get("/probe", _h)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = runner.addresses[0][1]
        tmpl = {
            "id": "test-native",
            "info": {"name": "Native Test", "severity": "high"},
            "http": [{
                "method": "GET", "path": ["/probe"],
                "matchers": [
                    {"type": "status", "status": [200]},
                    {"type": "word", "words": ["SECRET_MARKER_12345"]},
                ],
                "matchers-condition": "and",
            }],
        }
        try:
            async with aiohttp.ClientSession() as s:
                out = await run_template(tmpl, f"http://127.0.0.1:{port}", s)
        finally:
            await runner.cleanup()
        assert out is not None
        assert out["source"] == "native_template"
        assert out["severity"] == "High"

    @pytest.mark.asyncio
    async def test_run_template_flow_skipped(self):
        """多步 flow 模板：MVP 边界内返回 None（不误报）"""
        from vulnclaw.core.native_templates import run_template
        assert await run_template({"flow": "x", "http": [{}]}, "http://x", None) is None


class TestOobAuditCap:
    def test_cap_configured(self):
        from vulnclaw.core import oob_channel
        assert int(oob_channel._OOB_AUDIT_MAX) > 0
        assert len(oob_channel._OOB_AUDIT) <= oob_channel._OOB_AUDIT_MAX


class TestMultiAgentDebate:
    @pytest.mark.asyncio
    async def test_no_client_returns_none(self, monkeypatch):
        import vulnclaw.ai.core as ai_core
        monkeypatch.setattr(ai_core, "get_llm_client", lambda *a, **k: None)
        from vulnclaw.core.verification_gateway import multi_agent_verify_batch
        assert await multi_agent_verify_batch([{"type": "XSS"}]) is None

    @pytest.mark.asyncio
    async def test_majority_vote_marks_fp(self, monkeypatch):
        """3 路里 2 路判误报 → 标记为 llm_gate_reject（votes=2/3）"""
        import vulnclaw.ai.core as ai_core
        state = {"n": 0}

        class _Client:
            async def ask(self, prompt, **kw):
                state["n"] += 1
                if state["n"] <= 2:
                    return '{"verdicts": [{"index": 0, "likely_vuln": false, "confidence": "high"}]}'
                return '{"verdicts": []}'

        monkeypatch.setattr(ai_core, "get_llm_client", lambda *a, **k: _Client())
        from vulnclaw.core.verification_gateway import multi_agent_verify_batch
        out = await multi_agent_verify_batch([{"type": "XSS", "url": "http://x"}])
        assert out and out.get(0)
        assert out[0]["debate_votes"] == "2/3"

    @pytest.mark.asyncio
    async def test_single_vote_insufficient(self, monkeypatch):
        """仅 1 路判误报 → 多数票不足 → 不标记（None）"""
        import vulnclaw.ai.core as ai_core
        state = {"n": 0}

        class _Client:
            async def ask(self, prompt, **kw):
                state["n"] += 1
                if state["n"] == 1:
                    return '{"verdicts": [{"index": 0, "likely_vuln": false, "confidence": "high"}]}'
                return '{"verdicts": []}'

        monkeypatch.setattr(ai_core, "get_llm_client", lambda *a, **k: _Client())
        from vulnclaw.core.verification_gateway import multi_agent_verify_batch
        out = await multi_agent_verify_batch([{"type": "XSS"}])
        assert out is None


class TestDecisionLayers:
    """P3-8 三层决策：战略/战术层（确定性启发式路径）。"""

    def test_strategic_from_tech(self):
        from vulnclaw.ai.v100.decision_layers import strategic_plan
        plan = strategic_plan({"tech_stack": ["PHP/7.4", "nginx"]})
        assert plan["source"] == "heuristic"
        paths = [t["path"] for t in plan["targets"]]
        assert paths
        assert any("php" in t["reason"] or "nginx" in t["reason"] for t in plan["targets"])

    def test_strategic_generic_fallback(self):
        from vulnclaw.ai.v100.decision_layers import strategic_plan
        assert strategic_plan({})["targets"]  # 空输入也有通用兜底

    def test_tactical_by_path_semantics(self):
        from vulnclaw.ai.v100.decision_layers import tactical_plan
        t = tactical_plan("http://x/upload?file=1")
        assert "upload" in t["engines"] and "lfi" in t["engines"]
        t2 = tactical_plan("http://x/api/user?id=1")
        assert "idor" in t2["engines"] or "api_version" in t2["engines"]

    def test_inject_strategic_fields_only_adds_new_key(self):
        from vulnclaw.ai.v100.decision_layers import inject_strategic_fields

        class _T:
            def __init__(self, url):
                self.task_data = {"url": url}

        tasks = [_T("http://x/admin/login"), _T("http://x/other")]
        n = inject_strategic_fields(tasks, {"targets": [{"path": "/admin", "reason": "t"}]})
        assert n == 1
        assert tasks[0].task_data["strategic_priority"] == 1
        assert "strategic_priority" not in tasks[1].task_data

    def test_three_layer_off_by_default(self):
        from vulnclaw.ai.v100.decision_layers import three_layer_enabled
        assert three_layer_enabled() is False  # settings 未声明 → 默认关


# ============================================================
# T12 Prompt 版本管理：统一注册表 + 样例回归 + 一键 diff
# ============================================================
class TestPromptRegistry:
    """prompt 此前是散落在各 phase 里的字面量，改一个字没有任何回归信号。

    收口后：带版本号、配样例回归集、改 prompt 可一键出效果 diff。
    """

    PID = "verify.cross_batch"

    def test_render_injects_items_and_keeps_json_braces(self):
        """占位符用 replace 而非 format：prompt 里的 JSON 示例花括号须原样保留。"""
        from vulnclaw.ai.prompt_registry import render
        text = render(self.PID, items="CAND_LINE")
        assert text
        assert "CAND_LINE" in text
        assert '{"index": 0' in text, "JSON 示例被破坏（疑似误用 str.format）"

    def test_unknown_prompt_returns_empty_for_fallback(self):
        """注册表缺失时返回空串，调用方回退内嵌原文，绝不打断验证链路。"""
        from vulnclaw.ai.prompt_registry import render
        assert render("does.not.exist", items="x") == ""

    def test_regression_passes_on_registered_version(self):
        from vulnclaw.ai.prompt_registry import run_regression
        r = run_regression(self.PID)
        assert r["total"] >= 1
        assert r["failed"] == 0, r["cases"]
        assert r["passed"] == r["total"]

    def test_diff_detects_regression(self):
        """改坏规则段 → delta 必须为负（"改 prompt 有门禁"的核心断言）。"""
        from vulnclaw.ai.prompt_registry import get_prompt, prompt_diff
        tpl = get_prompt(self.PID)["template"]
        broken = tpl.replace("绝不猜测，宁可证据不足。", "可以适度猜测。")
        d = prompt_diff(self.PID, broken)
        assert d["text_changed"] is True
        assert d["regression_delta"] < 0, d
        assert d["unified_diff"], "必须给出文本级 diff"

    def test_list_prompts_exposes_version(self):
        from vulnclaw.ai.prompt_registry import list_prompts
        rows = list_prompts()
        assert any(r["id"] == self.PID and r["version"] >= 1 for r in rows)

    def test_all_registered_prompts_pass_own_regression(self):
        """每个已注册 prompt 都必须通过自己的样例回归（防新增 prompt 忘记配样例）。"""
        from vulnclaw.ai.prompt_registry import list_prompts, run_regression
        rows = list_prompts()
        assert rows
        for r in rows:
            res = run_regression(r["id"])
            assert res["total"] >= 1, f"{r['id']} 未配样例回归集"
            assert res["failed"] == 0, (r["id"], res["cases"])

    def test_new_prompts_registered(self):
        from vulnclaw.ai.prompt_registry import list_prompts
        ids = {r["id"] for r in list_prompts()}
        assert {"verify.cross_batch", "verify.single_evidence",
                "verify.dedupe", "strategic.plan_llm"} <= ids

    def test_single_evidence_renders_both_blocks(self):
        """单条裁决：证据包与 probe 观测两段都要注入（缺一段等于让 AI 盲判）。"""
        from vulnclaw.ai.prompt_registry import render
        t = render("verify.single_evidence", evidence_pack="EP", probe_summary="PS")
        assert "【证据包】\nEP" in t
        assert "【probe 观测结果】\nPS" in t

    def test_dedupe_and_strategic_render(self):
        from vulnclaw.ai.prompt_registry import render
        d = render("verify.dedupe", summary="S")
        assert "S" in d and "重复报告" in d
        s = render("strategic.plan_llm", tech="T", ports="P", vulns="V")
        assert "技术栈: T" in s and "端口: P" in s and "已发现漏洞: V" in s
