# -*- coding: utf-8 -*-
"""SP2 确定性去重前置：指纹去重 + 语义疑似分组 + LLM 裁决合并。"""
from vulnclaw.core.dedupe import (
    deterministic_dedupe,
    findings_fingerprint,
    merge_llm_verdict,
)


def _f(url="http://t.example.com/a.php", ftype="SQL Injection", param="id",
       method="GET", severity="High", verdict="likely", confidence="high",
       **extra):
    d = {
        "url": url, "type": ftype, "parameter": param, "method": method,
        "severity": severity, "verdict": verdict, "confidence": confidence,
        "evidence": "evidence-text",
    }
    d.update(extra)
    return d


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
        decided = {f"{loc}|sql injection|b": True}
        merged = merge_llm_verdict(kept, amb, decided)
        assert len(merged) == 1
        assert merged[0]["parameter"] == "a"

    def test_merge_keeps_when_not_duplicate(self):
        f1 = _f(param="a")
        f2 = _f(param="b")
        kept, amb = deterministic_dedupe([f1, f2])
        merged = merge_llm_verdict(kept, amb, {})  # 未裁决 -> 全部保留
        assert len(merged) == 2


class TestChineseConfidence:
    """H1: 引擎中文 confidence（高/中/低）必须参与合并选优（此前全部平权 0.5）。"""

    def test_confidence_rank_ordering(self):
        from vulnclaw.core.dedupe import _conf_of
        assert _conf_of({"confidence": "高"}) > _conf_of({"confidence": "中"})
        assert _conf_of({"confidence": "中"}) > _conf_of({"confidence": "低"})

    def test_float_01_confidence_supported(self):
        from vulnclaw.core.dedupe import _conf_of
        assert _conf_of({"confidence": 0.95}) >= 0.9
        assert _conf_of({"confidence": 0.7}) >= 0.6
        assert _conf_of({"confidence": 0.4}) < 0.6
        assert _conf_of({"confidence": 75}) == 0.7  # 0-100 尺度保持不变

    def test_strong_chinese_confidence_wins(self):
        weak = _f(severity="High", verdict="likely", confidence="中")
        strong = _f(severity="High", verdict="likely", confidence="高")
        kept, _ = deterministic_dedupe([weak, strong])
        assert kept[0]["confidence"] == "高"


class TestEvidenceMerge:
    """H2: 同强度合并不得丢弃后到者的场外证据/实锤字段。"""

    def test_same_strength_merges_evidence(self):
        a = _f()
        b = _f(nuclei_result="template-hit", burp_verified=True)
        kept, _ = deterministic_dedupe([a, b])
        assert len(kept) == 1
        assert kept[0]["nuclei_result"] == "template-hit"
        assert kept[0]["burp_verified"] is True

    def test_stronger_update_keeps_weak_hardproof(self):
        weak = _f(severity="Low", verdict="suspicious", confidence="low",
                  cross_confirmed=True)
        strong = _f(severity="Critical", verdict="confirm", confidence="high")
        kept, _ = deterministic_dedupe([weak, strong])
        assert kept[0]["severity"] == "Critical"
        assert kept[0]["cross_confirmed"] is True


class TestParamNorm:
    """H3: 参数名保留 _ - . 分隔符，不得因归一化误合并不同参数。"""

    def test_separators_do_not_merge(self):
        a = _f(param="user_id")
        b = _f(param="user.id")
        c = _f(param="user-id")
        assert findings_fingerprint(a) != findings_fingerprint(b)
        assert findings_fingerprint(b) != findings_fingerprint(c)
        kept, _ = deterministic_dedupe([a, b, c])
        assert len(kept) == 3


class TestLLMMergeKeyIncludesType:
    """H4: 裁决 key 含 type——裁删 sqli 不得误删同 param 的 xss。"""

    def test_same_param_different_type_not_dropped(self):
        f1 = _f(ftype="SQL Injection", param="id")
        f2 = _f(ftype="XSS", param="id")
        kept, _ = deterministic_dedupe([f1, f2])
        loc = "http://t.example.com/a.php"
        decided = {f"{loc}|sql injection|id": True}
        merged = merge_llm_verdict(kept, {}, decided)
        assert len(merged) == 1
        assert merged[0]["type"].lower() == "xss"