# -*- coding: utf-8 -*-
"""obfuscate_payload 回归测试：防止双重 URL 编码（N3 修复验证）。

历史 bug：obfuscate_payload 预编码出 %7c，再经 build_attack_url() 的 urlencode
二次编码成 %257c —— 靶机收到字面量 '%7c' 而非 '|'，注入失效且白占配额。
修复后 obfuscate_payload 只输出原始字符，编码统一由 build_attack_url 单次完成。
"""
import urllib.parse

from vulnclaw.core.utils import obfuscate_payload, build_attack_url

PAYLOADS = [
    "1' OR '1'='1",
    "1' AND SLEEP(5)--",
    "<script>alert(1)</script>",
    "1 UNION SELECT 1,2--",
    "admin'/**/OR/**/1=1#",
]


def test_obfuscate_never_emits_percent_encoding():
    """混淆输出不得含任何预编码的 %XX（双重编码的直接来源）。"""
    for _ in range(200):
        for base in PAYLOADS:
            obf = obfuscate_payload(base, 1)
            assert "%" not in obf, f"obfuscate_payload 输出含预编码: {obf!r}"


def test_obfuscate_roundtrip_via_build_attack_url():
    """经 build_attack_url 单次编码后，urlparse+parse_qs 解出值 == 原始混淆串。

    旧 bug 下 urlencode 会把 %7c 二次编码为 %257c，parse_qs 解出后 != obf，
    此处断言会在回归时立刻变红。
    """
    base_url = "http://127.0.0.1:8090/xss"
    for _ in range(50):
        for base in PAYLOADS:
            obf = obfuscate_payload(base, 1)
            url = build_attack_url(base_url, "s", obf)
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            decoded = qs.get("s", [""])[0]
            assert decoded == obf, f"双重编码：obf={obf!r} 服务端解出={decoded!r}"
