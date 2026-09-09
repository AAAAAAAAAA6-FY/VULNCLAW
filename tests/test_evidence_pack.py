# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A 方案契约测试：EvidencePack 证据打包器（全离线，不碰真目标）。"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest

from vulnclaw.ai.v100 import evidence_pack as ep


def _min_finding():
    return {
        "type": "xss",
        "severity": "High",
        "url": "https://x.com/?q=1",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "evidence": "no echo feature",
    }


# 1. 最小 finding 能渲染且含两栏
def test_build_evidence_pack_minimal_finding():
    out = ep.build_evidence_pack(_min_finding(), None)
    assert "【漏洞候选】" in out
    assert "【probe 观测结果】" in out
    assert "xss" in out
    assert "https://x.com/?q=1" in out


# 2. 超长 evidence：关键词窗口保留 + 中间省略
def test_smart_truncate_keeps_keyword_window():
    long_ev = "A" * 3000 + " root:0:0:/root /bin/bash " + "B" * 3000
    t = ep._smart_truncate(long_ev)
    assert len(t) <= ep.RESP_HEAD_KEEP
    assert "root:" in t


# 3. 长 base64 被替换为块标记、无长 token 泄露
def test_smart_truncate_strips_base64_blob():
    blob = "sig=" + "aB1dE2fGhI3jK4" * 20 + " tail"
    t = ep._smart_truncate(blob, budget=1000)
    assert "base64 块" in t
    # 块内原文长度被压缩，不应出现整段 token
    assert "aB1dE2fGhI3jK4aB1dE2fGhI3jK4aB1dE2fGhI3jK4" not in t


# 3b. 纯单字符长串不误伤（unique<4 不算 base64）
def test_smart_truncate_pure_alpha_not_base64():
    s = "x" * 500
    t = ep._smart_truncate(s, budget=1000)
    assert "base64 块" not in t
    assert len(t) == 500


# 4. <script>…</script> 块被裁剪
def test_smart_truncate_strips_script_block():
    s = "head <script>var x=1; var y=2; var z='aaaa';</script> tail"
    t = ep._smart_truncate(s, budget=1000)
    assert "JS 块" in t
    assert "var x=1" not in t


# 5. 超大 evidence 输出 <= 预算
def test_evidence_pack_budget_cap():
    v = dict(_min_finding(), evidence="C" * 50000)
    out = ep.build_evidence_pack(v, None)
    assert len(out) <= ep.EVIDENCE_PACK_MAX_CHARS


# 6. probe 传入时渲染观测信号
def test_probe_summary_embedded_when_probe_given():
    v = _min_finding()
    probe = {
        "ok": True, "base_status": 200, "attack_status": 500,
        "reflect": False, "status_shift": True, "len_diff": 0.3, "duration_diff": 2.0,
    }
    out = ep.build_evidence_pack(v, probe)
    assert "attack_status=500" in out
    assert "30.00%" in out
    assert "duration_diff=2.00s" in out


# 7. probe 失败/缺失 → 弱信号标记（fail-closed）
def test_probe_signal_gates_confirm_in_prompt_rules():
    assert "fail-closed" in ep._probe_summary({"ok": False, "error": "timeout"})
    assert "fail-closed" in ep._probe_summary(None)


# 8. 引擎结构化标志渲染
def test_evidence_pack_engine_flags():
    v = dict(_min_finding(), cmd_exec=True, time_verified=True)
    out = ep.build_evidence_pack(v, None)
    assert "cmd_exec" in out
    assert "time_verified" in out


# 9. 空值渲染（无），结构稳定
def test_evidence_pack_empty_values():
    out = ep.build_evidence_pack({"type": "unknown"}, None)
    assert "（无）" in out
    assert "【漏洞候选】" in out


# 10. OOB 证据段
def test_evidence_pack_oob():
    v = dict(_min_finding(), oob_evidence={"ts": "t1", "channel": "dns", "detail": "hit"})
    out = ep.build_evidence_pack(v, None)
    # oob 不作为必填栏，但存在时不应抛异常
    assert isinstance(out, str)


# 11. enrich_finding 可选参数默认路径不改变行为（零回归）
def test_enrich_finding_optional_resp_default_no_change():
    from vulnclaw.engines.base import enrich_finding

    f = {"url": "https://x.com/", "type": "xss", "evidence": "x"}
    out = enrich_finding(f)
    assert out["url"] == "https://x.com/"
    assert out["type"] == "xss"
    # 不传 resp → 不新增响应证据字段
    assert "response_preview" not in out
    assert "status_shift" not in out
    assert "diff_ratio" not in out
    assert "echo_feature" not in out


# 12. enrich_finding 传 attack_resp → 回填客观字段
def test_enrich_finding_attack_resp_backfill():
    from vulnclaw.engines.base import enrich_finding

    f = {"url": "https://x.com/?q=1", "type": "xss", "parameter": "q", "payload": "PWNED123"}
    normal = (200, "hello world", {})
    attack = (500, "hello world PWNED123 error", {})
    out = enrich_finding(f, normal_resp=normal, attack_resp=attack)
    assert out["response_preview"] is not None
    assert out["diff_ratio"] > 0
    assert out["status_shift"] is True  # 攻击 5xx vs 基线 2xx
    assert out["echo_feature"] is True  # payload 回显


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
