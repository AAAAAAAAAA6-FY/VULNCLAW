# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP19: 通用 POC 骨架 verify() 验证逻辑分支测试。"""

from vulnclaw.deepsec.poc_generator import POCGenerator


def _generate_script(finding):
    gen = POCGenerator()
    return gen._generate_generic(finding)


def _assert_compiles(script):
    compile(script, "<gen>", "exec")


def test_sql_type_injects_error_marker_check():
    """sql 类型 → 生成的脚本含 SQL 错误特征匹配代码，语法合法。"""
    script = _generate_script({
        "type": "sql_injection",
        "url": "http://t/x",
        "parameter": "q",
        "payload": "1' OR '1'='1",
    })
    assert "sql syntax" in script
    assert "you have an error" in script
    assert "mysql" in script
    assert "unclosed quotation mark" in script
    assert "return False" in script
    _assert_compiles(script)


def test_xss_type_injects_reflection_check():
    """xss 类型 → 含 payload 反射回显检查。"""
    script = _generate_script({
        "type": "xss",
        "url": "http://t/x",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
    })
    assert "PAYLOAD.replace" in script
    assert "resp.text.replace" in script
    assert "反射回显" in script
    _assert_compiles(script)


def test_rce_type_injects_command_markers():
    """rce 类型 → 含命令回显特征检查。"""
    script = _generate_script({
        "type": "command_injection",
        "url": "http://t/x",
        "parameter": "cmd",
        "payload": "echo TOKEN123",
    })
    assert "uid=" in script
    assert "id=" in script
    assert "PAYLOAD in resp.text" in script
    _assert_compiles(script)


def test_ssrf_type_injects_metadata_markers():
    """ssrf 类型 → 含云元数据特征检查。"""
    script = _generate_script({
        "type": "ssrf",
        "url": "http://t/x",
        "parameter": "url",
        "payload": "http://169.254.169.254/latest/meta-data/",
    })
    assert "instance-id" in script
    assert "ami-" in script
    assert "169.254" in script
    _assert_compiles(script)


def test_unknown_type_probe_and_compiles():
    """unknown 类型 → 探测型脚本（return True），语法合法。"""
    script = _generate_script({
        "type": "time_based_blind_notmapped",
        "url": "http://t/x",
        "parameter": "q",
        "payload": "' AND SLEEP(3)-- ",
    })
    assert "return True" in script
    assert "requests.get" in script
    _assert_compiles(script)


def test_post_method_injects_requests_post():
    """POST method → 生成脚本含 requests.post(data=params)。"""
    script = _generate_script({
        "type": "xss",
        "url": "http://t/x",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "method": "POST",
    })
    assert 'METHOD = "POST"' in script
    assert "requests.post(TARGET, data=params, timeout=10)" in script
    assert "requests.get(TARGET, params=params, timeout=10)" in script
    _assert_compiles(script)


def test_default_method_is_get():
    """method 缺省 → requests.get 分支。"""
    script = _generate_script({
        "type": "xss",
        "url": "http://t/x",
        "parameter": "q",
        "payload": "x",
    })
    assert 'METHOD = "GET"' in script
    assert "requests.get(TARGET, params=params, timeout=10)" in script
    _assert_compiles(script)
