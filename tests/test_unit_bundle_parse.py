"""单元测试：bundle AI 批量判定的 JSON 解析兜底（_safe_parse_bundle_json）。"""
from vulnclaw.ai.v100.phases.phases_executor import _safe_parse_bundle_json


class TestJsonParsing:
    def test_plain_json_array(self):
        raw = '[{"index": 0, "has_vuln": true, "confidence": "high"}, {"index": 1, "has_vuln": false, "confidence": "low"}]'
        result = _safe_parse_bundle_json(raw)
        assert len(result) == 2
        assert result[0]["has_vuln"] is True
        assert result[1]["has_vuln"] is False

    def test_json_wrapped_in_code_fence(self):
        raw = '```json\n[{"index": 0, "has_vuln": true, "confidence": "high"}]\n```'
        result = _safe_parse_bundle_json(raw)
        assert len(result) == 1
        assert result[0]["index"] == 0

    def test_json_with_prefix_text(self):
        raw = 'Here is the verdict: [{"index": 0, "has_vuln": true, "confidence": "high"}] done.'
        result = _safe_parse_bundle_json(raw)
        assert len(result) == 1
        assert result[0]["has_vuln"] is True

    def test_single_dict_response(self):
        raw = '{"index": 0, "has_vuln": true, "confidence": "high"}'
        result = _safe_parse_bundle_json(raw)
        assert len(result) == 1

    def test_python_literal_style(self):
        raw = "[{'index': 0, 'has_vuln': True, 'confidence': 'high'}]"
        result = _safe_parse_bundle_json(raw)
        assert len(result) == 1
        assert result[0]["has_vuln"] is True


class TestRegexFallback:
    def test_loose_text_fallback(self):
        """宽松文本兜底：无逗号分隔时正则只出第一条（已知行为），关键是不崩且 verdict 正确。"""
        raw = "item index=0 has_vuln=true confidence=high"
        result = _safe_parse_bundle_json(raw)
        assert len(result) >= 1
        assert result[0]["has_vuln"] is True

    def test_loose_text_two_items_known_limitation(self):
        """已知局限：兜底正则为 DOTALL，多行宽松文本只会出第一条 verdict。

        结构化输出（json / literal）才是主路径；此处固化行为防止回归恶化。
        """
        raw = (
            "index=0, has_vuln=true, confidence=high\n"
            "index=1, has_vuln=false, confidence=low"
        )
        result = _safe_parse_bundle_json(raw)
        assert len(result) == 1  # 当前实现：跨行只解析第一条
        assert result[0]["has_vuln"] is True

    def test_garbage_returns_empty(self):
        assert _safe_parse_bundle_json("no structured data at all") == []

    def test_empty_string(self):
        assert _safe_parse_bundle_json("") == []

    def test_mixed_items_filters_non_dict(self):
        raw = '[{"index": 0, "has_vuln": true}, 42, "str"]'
        result = _safe_parse_bundle_json(raw)
        assert len(result) == 1
        assert result[0]["index"] == 0
