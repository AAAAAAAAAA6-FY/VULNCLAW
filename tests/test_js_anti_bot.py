#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""K.4 稳定性护栏测试：反爬/反调试识别 + 还原结果报告守卫。

验收口径（任务卡 K.4）：注入恶意混淆样本，还原失败时 finding 不出现
（落 pending_review / reject），日志有 fallback 标记。
"""
import asyncio

from vulnclaw.ai.js_retriever import JSTriage, safe_for_sandbox
from vulnclaw.ai.js_retriever.triage import (
    detect_anti_bot_features,
    eval_recipe_for_report,
)
from vulnclaw.ai.js_retriever.signer_pool import SignerPool

JS_DEBUGGER = 'function x(){debugger; return 1;}'
JS_WEBDRIVER = 'if(navigator.webdriver){return 0;}'
JS_CLEAN = 'function makeSign(t){return String.fromCharCode(t.charCodeAt(0)^0x5A);}'
JS_MALICIOUS = (
    'function x(){debugger; var b=eval("1+1");'
    'navigator.webdriver=true;'
    'Object.prototype.__proto__ = {};'
    'return b;}'
)


async def _triage_with(verdict, js):
    async def fake_llm(_s):
        return {"verdict": verdict, "algorithm": "t", "params": []}

    t = JSTriage(llm_ask=fake_llm, audit_dir="/tmp/js_triage_k4")
    return await t.triage(js, is_html=False)


def test_detect_debugger():
    feats = detect_anti_bot_features(JS_DEBUGGER)
    assert "debugger" in feats


def test_detect_webdriver_ignores_strings():
    assert detect_anti_bot_features('var s = "navigator.webdriver"') == []
    assert detect_anti_bot_features(JS_WEBDRIVER) == ["webdriver"]


def test_clean_js_no_features():
    assert detect_anti_bot_features(JS_CLEAN) == []


def test_b_path_blocked_by_debugger():
    """反调试特征存在 → B 路短路 C + fallback，沙箱绝不执行。"""
    res = asyncio.run(_triage_with("EXECUTE", JS_DEBUGGER))
    assert res["path"] == "C"
    assert res["reason"].startswith("anti_bot_blocked")
    assert res["exec"] == {}


def test_llm_recipe_pending_review():
    """LLM 摘要可复现 → 未验证 → pending_review + fallback（不进主报告）。"""
    res = asyncio.run(_triage_with("REPRODUCIBLE", JS_CLEAN))
    assert res["path"] == "A"
    gate = eval_recipe_for_report(res["recipe_meta"])
    assert gate["verdict"] == "pending_review"
    assert gate["fallback"] is True


def test_static_recipe_confirmed():
    gate = eval_recipe_for_report({"mode": "static", "validated": True})
    assert gate["verdict"] == "confirmed"
    assert gate["fallback"] is False


def test_sandbox_unvalidated_pending():
    gate = eval_recipe_for_report({"mode": "sandbox", "validated": False, "anti_bot": []})
    assert gate["verdict"] == "pending_review"
    assert gate["fallback"] is True


def test_malicious_obfuscation_no_report():
    """恶意混淆样本：全程不产生 confirmed（reject），finding 不出现。"""
    res = asyncio.run(_triage_with("EXECUTE", JS_MALICIOUS))
    feats = res["anti_bot"]
    assert "debugger" in feats and "webdriver" in feats
    gate = eval_recipe_for_report(res["recipe_meta"])
    assert gate["verdict"] == "reject"
    assert gate["fallback"] is True
    # signer 安全闸：恶意样本配方拒绝注册
    pool = SignerPool()
    ok = pool.register("/mal", {"mode": "sandbox", "js": JS_MALICIOUS, "func": "x"})
    assert ok is False
    assert pool.recipe_for("/mal") is None
