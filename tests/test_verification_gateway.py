# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""验证网关 + 审计凭证链 回归测试。

覆盖：
- 归一化：SARIF 2.1 / findings JSON / 中文严重级别名
- 去重合并与多源佐证
- 证据分诊（无证据降级）
- 本地规则层（SQL 错误证据 → verified）
- 置信度与状态阈值
- 审计凭证链：出证 / 审计校验 / 篡改检测 / HMAC 验签
- run_gateway 端到端（临时 SARIF 输入 → verified.sarif + receipt，全离线）
- PR 评论 markdown 构建（E3.3 的可测半边）
"""
import json

import pytest

from vulnclaw.core.audit_receipt import build_receipt_chain, verify_receipt_chain
import vulnclaw.core.verification_gateway as gw

# build_pr_markdown 在 scripts/pr_comment.py（scripts 不在 src 包内），
# 用路径导入以保持"纯增量不挪文件"。
import importlib.util as _ilu
from pathlib import Path as _Path

_SCRIPT = _Path(__file__).resolve().parents[1] / "scripts" / "pr_comment.py"
_spec = _ilu.spec_from_file_location("pr_comment", _SCRIPT)
pr_comment = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(pr_comment)


# ============================================================
# 归一化
# ============================================================
_SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "strix"}},
        "results": [
            {
                "ruleId": "sqli",
                "level": "error",
                "message": {"text": "SQL error near ' AND"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "http://t/a"}}}],
                "properties": {"parameter": "id", "payload": "' AND 1=1--"},
            },
            {
                "ruleId": "xss",
                "level": "warning",
                "message": {"text": "reflected"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "http://t/b"}}}],
            },
        ],
    }],
}


def test_normalize_sarif():
    findings, fmt = gw.normalize_input(_SARIF)
    assert fmt == "sarif"
    assert len(findings) == 2
    f0 = findings[0]
    assert f0["type"] == "sqli" and f0["severity"] == "high"  # level error → high
    assert f0["url"] == "http://t/a" and f0["parameter"] == "id"
    assert f0["source"] == "strix"
    assert findings[1]["severity"] == "medium"  # warning → medium


def test_normalize_findings_json_both_shapes():
    lst, fmt1 = gw.normalize_input([{"type": "xss", "url": "http://t/", "severity": "高危"}])
    assert fmt1 == "json_list" and lst[0]["severity"] == "high"
    wrapped, fmt2 = gw.normalize_input({"findings": [{"type": "sqli", "url": "http://t/"}]})
    assert fmt2 == "json_findings" and wrapped[0]["type"] == "sqli"


def test_normalize_severity_aliases():
    assert gw.normalize_severity("CRITICAL") == "critical"
    assert gw.normalize_severity("高危") == "high"
    assert gw.normalize_severity("warning") == "medium"
    assert gw.normalize_severity("不懂的级别") == "info"


# ============================================================
# 去重佐证 + 分诊 + 规则 + 评分
# ============================================================
def test_dedup_and_corroboration():
    merged = gw.dedup_and_corroborate([
        {"type": "sqli", "url": "http://t/a", "parameter": "id", "severity": "high",
         "evidence": "err", "source": "strix"},
        {"type": "SQLI", "url": "http://t/a", "parameter": "id", "severity": "critical",
         "evidence": "", "source": "burp"},
        {"type": "xss", "url": "http://t/b", "parameter": "", "severity": "low",
         "evidence": "x", "source": "strix"},
    ])
    sqli = [f for f in merged if f["type"].lower() == "sqli"][0]
    assert sqli["corroboration"] == 2 and set(sqli["sources"]) == {"strix", "burp"}
    assert sqli["severity"] == "critical"  # 双源冲突取高
    assert len(merged) == 2


def test_triage_downgrades_missing_evidence():
    f = gw.static_triage({"type": "x", "url": "u", "severity": "high", "evidence": ""})
    assert f["evidence_missing"] is True
    assert f["severity"] == "medium"  # 降一档
    f2 = gw.static_triage({"type": "x", "url": "u", "severity": "high", "evidence": "err near"})
    assert f2["evidence_present"] is True and f2["severity"] == "high"


def test_rule_hit_boosts_to_verified():
    f = gw.static_triage({
        "type": "sqli", "url": "http://t/a", "parameter": "", "severity": "high",
        "evidence": "MySQL server version for the right syntax to use near",
        "sources": ["x"], "corroboration": 1,
    })
    hit = gw._rule_verify(f)
    f["rule_hit"] = hit
    f["confidence"] = gw.score_confidence(f)
    f["status"] = gw.status_of(f)
    assert f["rule_hit"]  # evidence 带报错关键词 → 规则命中
    assert f["status"] == "verified"


def test_confidence_ordering():
    strong = gw.score_confidence({"evidence_present": True, "rule_hit": True,
                                  "corroboration": 2, "probe_confirmed": True})
    weak = gw.score_confidence({"evidence_present": False, "corroboration": 1})
    assert strong >= 95 and weak <= 40


# ============================================================
# 审计凭证链
# ============================================================
_RECORDS = [{"type": "sqli", "url": "http://t/a", "status": "verified", "confidence": 95},
            {"type": "xss", "url": "http://t/b", "status": "likely", "confidence": 60}]


def test_receipt_roundtrip_and_tamper_detection():
    rc = build_receipt_chain(_RECORDS, meta={"input": "x.sarif"})
    ok, reason = verify_receipt_chain(rc, _RECORDS)
    assert ok, reason
    # 篡改一条记录 → 暴露
    tampered = [dict(_RECORDS[0]), dict(_RECORDS[1])]
    tampered[0]["confidence"] = 1
    ok2, reason2 = verify_receipt_chain(rc, tampered)
    assert not ok2 and "篡改" in reason2
    # 删除一条 → 暴露
    ok3, _ = verify_receipt_chain(rc, _RECORDS[:1])
    assert not ok3


def test_receipt_hmac_signature():
    rc = build_receipt_chain(_RECORDS, secret="s3cret")
    assert "hmac" in rc
    ok, _ = verify_receipt_chain(rc, _RECORDS, secret="s3cret")
    assert ok
    ok_bad, reason = verify_receipt_chain(rc, _RECORDS, secret="wrong")
    assert not ok_bad and "HMAC" in reason
    ok_nokey, reason2 = verify_receipt_chain(rc, _RECORDS)
    assert not ok_nokey and "密钥" in reason2


# ============================================================
# run_gateway 端到端（全离线：probe/llm 关）
# ============================================================
@pytest.mark.asyncio
async def test_run_gateway_end_to_end(tmp_path):
    inp = tmp_path / "scanner-output.sarif"
    inp.write_text(json.dumps(_SARIF), encoding="utf-8")
    summary = await gw.run_gateway(input_path=str(inp), probe=False, use_llm=False)
    assert summary["ok"] is True
    assert summary["total"] == 2
    out = tmp_path / "scanner-output.verified.sarif"
    rc = tmp_path / "scanner-output.verified.receipt.json"
    assert out.is_file() and rc.is_file()
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert {r["properties"]["status"] for r in results} <= {"verified", "likely", "unverified"}
    # 凭证链可用 SARIF 内容反查
    audit = gw.verify_gateway_output(output_path=str(out), receipt_path=str(rc))
    assert audit["ok"] is True, audit


@pytest.mark.asyncio
async def test_run_gateway_rejects_missing_input():
    summary = await gw.run_gateway(input_path="Z:/no/such/file.sarif")
    assert summary["ok"] is False and "不存在" in summary["error"]


# ============================================================
# E3.3: PR 评论 markdown 构建
# ============================================================
def test_pr_markdown_contains_marker_counts_and_chain_root():
    findings = [
        {"type": "sqli", "url": "http://t/a", "severity": "high",
         "status": "verified", "confidence": 95},
        {"type": "info_leak", "url": "http://t/b", "severity": "low",
         "status": "unverified", "confidence": 40},
    ]
    md = pr_comment.build_pr_markdown(findings, chain_root="abc123")
    assert pr_comment.MARKER in md            # upsert 标记
    assert "high | 1" in md                   # 严重级分布
    assert "1 / 2" in md                      # verified 占比
    assert "`abc123`" in md                   # 凭证链根（审计锚）


def test_pr_markdown_empty_verified():
    md = pr_comment.build_pr_markdown(
        [{"type": "x", "url": "u", "severity": "info", "status": "unverified", "confidence": 30}])
    assert "没有达到 verified 阈值" in md


# ============================================================
# 盲复现验证闸门
# ============================================================
import asyncio  # noqa: E402  （仅本段异步用例使用，保持文件其余部分零改动）


def _guard():
    from vulnclaw.core.danger_guard import guard
    return guard


def _finding(**kw):
    base = {
        "type": "sqli", "url": "http://t/a?id=1", "parameter": "id",
        "payload": "' OR 1=1--", "evidence": "AI 推理：疑似注入，因为报错回显",
        "severity": "high",
    }
    base.update(kw)
    return base


class TestBlindView:
    def test_blind_view_strips_evidence_and_payload(self):
        f = _finding()
        v = gw.blind_view(f)
        assert set(v.keys()) == {"url", "parameter", "category"}
        assert "evidence" not in v and "payload" not in v
        blob = json.dumps(v, ensure_ascii=False)
        assert f["payload"] not in blob
        assert "AI 推理" not in blob

    def test_blind_view_preserves_target_and_param(self):
        v = gw.blind_view(_finding(url="http://x/y?p=1", parameter="p"))
        assert v["url"] == "http://x/y?p=1" and v["parameter"] == "p"


class TestBlindRouting:
    def test_category_mapping(self):
        assert gw.blind_category({"type": "sqli"}) == "sqli"
        assert gw.blind_category({"type": "XSS Reflected"}) == "xss"
        assert gw.blind_category({"type": "命令注入"}) == "cmdi"
        assert gw.blind_category({"type": "越权访问"}) == "idor"
        assert gw.blind_category({"type": "cors"}) == "cors"

    def test_chain_for_supported_categories(self):
        assert gw.blind_verifier_chain({"type": "sqli"}) == ("verify_sqli", "verify_sqli_time_based")
        assert gw.blind_verifier_chain({"type": "xss"}) == ("verify_xss",)
        assert gw.blind_verifier_chain({"type": "lfi"}) == ("verify_lfi",)
        assert gw.blind_verifier_chain({"type": "ssrf"}) == ("verify_ssrf",)

    def test_chain_empty_for_unsupported(self):
        assert gw.blind_verifier_chain({"type": "cors"}) == ()
        assert gw.blind_verifier_chain({"type": "info_leak"}) == ()


class TestBlindVerdict:
    @pytest.mark.asyncio
    async def test_confirmed(self, monkeypatch):
        async def _ok(method, view, session, sandbox):
            return {"exploitable": True, "method": "reflection_confirmed", "evidence": "标记回显"}

        monkeypatch.setattr(gw, "_run_verifier", _ok)
        monkeypatch.setattr(_guard(), "require_approval", lambda op, detail="": True)
        f = _finding()
        await gw._blind_repro_one(f, None, asyncio.Semaphore(2))
        assert f["blind_repro"] == "confirmed"
        assert f["blind_method"] == "reflection_confirmed"
        assert "blind_confirmed:reflection_confirmed" in f["signals"]

    @pytest.mark.asyncio
    async def test_refuted(self, monkeypatch):
        async def _no(method, view, session, sandbox):
            return {"exploitable": False, "method": "none"}

        monkeypatch.setattr(gw, "_run_verifier", _no)
        monkeypatch.setattr(_guard(), "require_approval", lambda op, detail="": True)
        f = _finding()
        await gw._blind_repro_one(f, None, asyncio.Semaphore(2))
        assert f["blind_repro"] == "refuted"
        assert "blind_refuted" in f["signals"]

    @pytest.mark.asyncio
    async def test_inconclusive_on_error(self, monkeypatch):
        async def _boom(method, view, session, sandbox):
            raise RuntimeError("network down")

        monkeypatch.setattr(gw, "_run_verifier", _boom)
        monkeypatch.setattr(_guard(), "require_approval", lambda op, detail="": True)
        f = _finding()
        await gw._blind_repro_one(f, None, asyncio.Semaphore(2))
        assert f["blind_repro"] == "inconclusive"
        assert f.get("blind_error")

    @pytest.mark.asyncio
    async def test_inconclusive_unsupported_category(self, monkeypatch):
        monkeypatch.setattr(_guard(), "require_approval", lambda op, detail="": True)
        f = _finding(type="cors")
        await gw._blind_repro_one(f, None, asyncio.Semaphore(2))
        assert f["blind_repro"] == "inconclusive"
        assert "blind_skip:unsupported:cors" in f["signals"]

    @pytest.mark.asyncio
    async def test_inconclusive_without_url_or_param(self, monkeypatch):
        f = _finding(url="", parameter="")
        await gw._blind_repro_one(f, None, asyncio.Semaphore(2))
        assert f["blind_repro"] == "inconclusive"
        assert "blind_skip:no_url" in f["signals"]


class TestBlindGatePolicy:
    @pytest.mark.asyncio
    async def test_danger_denied_is_inconclusive_without_penalty(self, monkeypatch):
        """门卫拒绝 = 闸门缺席：inconclusive 且不加分不扣分（与未跑闸门同分）。"""
        monkeypatch.setattr(_guard(), "require_approval", lambda op, detail="": False)
        f = _finding()
        await gw._blind_repro_one(f, None, asyncio.Semaphore(2))
        assert f["blind_repro"] == "inconclusive"
        assert "blind_skip:danger_denied" in f["signals"]
        assert gw.score_confidence(f) == gw.score_confidence({})

    def test_score_and_status_confirmed_vs_refuted(self):
        # base 取 75 分（evidence+多源佐证）：三态差值不被 100 封顶掩盖
        base = {"evidence_present": True, "corroboration": 2}
        conf = dict(base, blind_repro="confirmed")
        incon = dict(base, blind_repro="inconclusive")
        refu = dict(base, blind_repro="refuted")
        for d in (conf, incon, refu):
            d["confidence"] = gw.score_confidence(d)
        assert conf["confidence"] > incon["confidence"] > refu["confidence"]
        assert gw.status_of(conf) == "verified"
        assert gw.status_of(incon) == "verified"
        assert gw.status_of(refu) == "needs_review"  # 打不中不进 verified 台账

    @pytest.mark.asyncio
    async def test_cap_marks_remaining_skipped(self, monkeypatch):
        async def _no(method, view, session, sandbox):
            return {"exploitable": False}

        monkeypatch.setattr(gw, "_run_verifier", _no)
        monkeypatch.setattr(_guard(), "require_approval", lambda op, detail="": True)
        findings = [_finding(url=f"http://t/{i}?id=1") for i in range(5)]
        stats = await gw.run_blind_repro_gate(findings, None, max_targets=2)
        assert stats["skipped"] == 3
        assert all("blind_skip:cap" in f["signals"] for f in findings[2:])
        assert stats["refuted"] == 2


class TestBlindGateEndToEnd:
    @pytest.mark.asyncio
    async def test_gateway_with_blind_repro_keeps_receipt_intact(self, tmp_path, monkeypatch):
        """端到端：闸门跑通 -> SARIF 带盲字段 -> 凭证链仍可审计（关键回归）。"""
        async def _ok(method, view, session, sandbox):
            return {"exploitable": True, "method": "boolean_diff", "evidence": "长度变化"}

        monkeypatch.setattr(gw, "_run_verifier", _ok)
        monkeypatch.setattr(_guard(), "require_approval", lambda op, detail="": True)
        inp = tmp_path / "in.sarif"
        inp.write_text(json.dumps(_SARIF), encoding="utf-8")
        summary = await gw.run_gateway(input_path=str(inp), blind_repro=True, blind_max=10)
        assert summary["ok"] is True
        assert summary["blind_repro"]["confirmed"] >= 1

        out = tmp_path / "in.verified.sarif"
        props = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"][0]["properties"]
        assert props["blind_repro"] == "confirmed"
        assert props["blind_method"] == "boolean_diff"

        audit = gw.verify_gateway_output(
            output_path=str(out),
            receipt_path=str(tmp_path / "in.verified.receipt.json"),
        )
        assert audit["ok"] is True, audit
