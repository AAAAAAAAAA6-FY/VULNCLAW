# -*- coding: utf-8 -*-
"""SP2 确定性去重前置：指纹去重 + 语义疑似分组 + LLM 裁决合并。"""
from vulnclaw.core.dedupe import (
    deterministic_dedupe,
    findings_fingerprint,
    merge_llm_verdict,
)


def _f(url="http://t.example.com/a.php", ftype="SQL Injection", param="id",
       method="GET", severity="High", verdict="likely", confidence="high"):
    return {
        "url": url, "type": ftype, "parameter": param, "method": method,
        "severity": severity, "verdict": verdict, "confidence": confidence,
        "evidence": "evidence-text",
    }


class TestFingerprint:
    def test_query_stripped(self):
        a = findings_fingerprint(_f(url="http://t.example.com/a.php?id=1"))
        b = findings_fingerprint(_f(url="http://t.example.com/a.php?debug=1"))
        assert a == b

    def test_type_case_insensitive(self):
        a = findings_fingerprint(_f(ftype="SQL Injection"))
        b = findings_fingerprint(_f(ftype="sql injection"))
        assert a == b

    def test_param_differentiates(self):
        a = findings_fingerprint(_f(param="id"))
        b = findings_fingerprint(_f(param="name"))
        assert a != b


class TestDeterministicDedupe:
    def test_exact_dup_merged(self):
        kept, amb = deterministic_dedupe([_f(), _f()])
        assert len(kept) == 1
        assert amb == []

    def test_strongest_kept(self):
        weak = _f(severity="Low", verdict="suspicious", confidence="low")
        strong = _f(severity="Critical", verdict="confirm", confidence="high")
        kept, _ = deterministic_dedupe([weak, strong])
        assert kept[0]["severity"] == "Critical"
        assert kept[0]["verdict"] == "confirm"

    def test_different_param_not_merged(self):
        kept, amb = deterministic_dedupe([_f(param="id"), _f(param="name")])
        assert len(kept) == 2
        # 同位置同类型不同参数 -> 语义疑似组（供 LLM 裁决）
        assert len(amb) == 1
        assert amb[0]["count"] == 2

    def test_ambiguous_group_structure(self):
        kept, amb = deterministic_dedupe([_f(param="a"), _f(param="b")])
        g = amb[0]
        assert g["location"].endswith("/a.php")
        assert g["type"] == "sql injection"
        assert {c["parameter"] for c in g["candidates"]} == {"a", "b"}


class TestLLMMerge:
    def test_merge_drops_duplicates(self):
        f1 = _f(param="a")
        f2 = _f(param="b")
        kept, amb = deterministic_dedupe([f1, f2])
        loc = amb[0]["location"]
        # LLM 判 b 是 a 的重复 -> 保留 a（同强度保留先到），丢 b
        decided = {f"{loc}|b": True}
        merged = merge_llm_verdict(kept, amb, decided)
        assert len(merged) == 1
        assert merged[0]["parameter"] == "a"

    def test_merge_keeps_when_not_duplicate(self):
        f1 = _f(param="a")
        f2 = _f(param="b")
        kept, amb = deterministic_dedupe([f1, f2])
        merged = merge_llm_verdict(kept, amb, {})  # 未裁决 -> 全部保留
        assert len(merged) == 2