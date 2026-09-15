# -*- coding: utf-8 -*-
"""P2-② 上下文感知 XSS 判定单元测试（2026-09-15）。

验证 XSSEngine 三层判定重构：
- _locate_reflection_context：反射点上下文定位（body/attr/script/comment/tag）
- _is_xss_reflected：结构反射确认 → 上下文可达性 → 层 3 收紧
关键约束：不破坏现有检出（body 标准反射必须仍命中）。
"""
import pytest

from vulnclaw.engines.web_engines import XSSEngine


@pytest.fixture(scope="module")
def eng():
    return XSSEngine()


class TestLocateContext:
    def test_body(self, eng):
        html = "<html><body><p>hello</p><svg onload=alert(1)></body></html>"
        assert eng._locate_reflection_context(html, "<svg onload=alert(1)>") == "body"

    def test_attr(self, eng):
        html = '<input value="<svg onload=alert(1)>">'
        assert eng._locate_reflection_context(html, "<svg onload=alert(1)") == "attr"

    def test_script(self, eng):
        html = "<script>var x = \"';alert(1);//\";</script>"
        assert eng._locate_reflection_context(html, "';alert(1);//") == "script"

    def test_comment(self, eng):
        html = "<div><!-- <svg onload=alert(1)> --></div>"
        assert eng._locate_reflection_context(html, "<svg onload=alert(1)>") == "comment"

    def test_tag_name_position(self, eng):
        """反射点在标签名处（payload 将成为标签）"""
        assert eng._locate_reflection_context("<svg onload=alert(1)>", "svg onload") == "tag"

    def test_not_found_falls_back_body(self, eng):
        assert eng._locate_reflection_context("<p>x</p>", "<svg onload=zzz>") == "body"

    def test_garbage_input_safe(self, eng):
        assert eng._locate_reflection_context("", "") == "body"


class TestContextAwareDetection:
    def test_body_reflection_hits(self, eng):
        """标准反射（body 内原样回显）→ 命中（不破坏现有检出，E2E 依赖）"""
        html = "<html><body><p>search: <script>alert(1)</script></p></body></html>"
        assert eng._is_xss_reflected(html, "<script>alert(1)</script>") is True

    def test_encoded_reflection_hits(self, eng):
        """实体编码回显（&lt;script&gt;...）→ 保持旧行为命中"""
        html = "<div>q=&lt;script&gt;alert(1)&lt;/script&gt;</div>"
        assert eng._is_xss_reflected(html, "<script>alert(1)</script>") is True

    def test_comment_reflection_rejected(self, eng):
        """注释内回显 → 拒绝（永不执行）"""
        html = "<html><body><!-- <script>alert(1)</script> --></body></html>"
        assert eng._is_xss_reflected(html, "<script>alert(1)</script>") is False

    def test_script_block_html_tag_rejected(self, eng):
        """HTML 标签型 payload 落在 script 字符串内 → 死 payload，拒绝"""
        html = "<script>var q = \"<img src=x onerror=alert(1)>\";</script>"
        assert eng._is_xss_reflected(html, "<img src=x onerror=alert(1)>") is False

    def test_script_block_js_escape_hits(self, eng):
        """JS 语句注入型落在 script 内 → 有效"""
        html = "<script>var q = \"';alert(1);//\";</script>"
        assert eng._is_xss_reflected(html, "';alert(1);//") is True

    def test_script_close_escape_hits(self, eng):
        """</script> 闭合型 → 有效"""
        html = "<script>var q = \"</script><svg onload=alert(1)>\";</script>"
        assert eng._is_xss_reflected(html, "</script><svg onload=alert(1)>") is True

    def test_bare_word_no_hit(self, eng):
        """payload 未回显、仅正文裸词（alert/onerror 词）+ 页面骨架 → 不命中（层 3 收紧）"""
        html = ("<html><body><script>function alert(x){} "
                "window.addEventListener('error',function(){});</script></body></html>")
        assert eng._is_xss_reflected(html, "<script>alert(1)</script>") is False

    def test_event_handler_form_hits(self, eng):
        """payload 未回显但 onerror= 注入形态出现 → 命中（层 3 保留）"""
        html = "<html><body><img src=x onerror=alert(1)></body></html>"
        assert eng._is_xss_reflected(html, "<img src=q onerror=alert(1)>") is True

    def test_evidence_carries_context(self, eng):
        """evidence 带 [context=xxx] 前缀"""
        html = "<html><body><p>aa alert(1) bb</p></body></html>"
        ev = eng._extract_reflected_evidence(html, "<script>alert(1)</script>")
        assert ev.startswith("[context=")


def test_dom_clobbering_engine_registered():
    """P0-2: DOM Clobbering 引擎（XSS 利用链中间步骤）注册并可实例化。"""
    from vulnclaw.engines.dom_clobbering import DOMClobberingEngine
    eng = DOMClobberingEngine()
    assert eng.name == "dom_clobbering"
    assert isinstance(eng.DANGEROUS_NAMES, frozenset)
    for n in ("top", "self", "location", "document"):
        assert n in eng.DANGEROUS_NAMES, f"DANGEROUS_NAMES 缺 {n}"
