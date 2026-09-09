# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SP27: 指令解析层（--instruction 账号密码直写）单元测试。

覆盖（全部离线）：
- Strix 长句 / 中文键值对 / email:pass / 自然语言连写 / 列表多账号 / 编号列表
- login_url / Focus / Out of scope 段提取
- 无凭据、重复去重、空文件、脱敏摘要
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from vulnclaw.core.instructions import (  # noqa: E402
    Instruction,
    load_instruction,
    parse_instruction_text,
)


def _one(ins):
    assert len(ins.accounts) == 1, ins.accounts
    return ins.accounts[0]


# ---------- 凭据格式矩阵 ----------

def test_strix_style_login():
    ins = parse_instruction_text("Login with email: admin@test.local, password: Secret#123")
    a = _one(ins)
    assert a.username == "admin@test.local"
    assert a.password == "Secret#123"


def test_strix_style_username():
    ins = parse_instruction_text("Login with username: alice, password: Passw0rd!")
    a = _one(ins)
    assert (a.username, a.password) == ("alice", "Passw0rd!")


def test_zh_kv_pair():
    ins = parse_instruction_text("账号: alice 密码: Passw0rd")
    a = _one(ins)
    assert (a.username, a.password) == ("alice", "Passw0rd")


def test_zh_kv_english():
    ins = parse_instruction_text("用户名: bob / 密码: Bob1234")
    a = _one(ins)
    assert (a.username, a.password) == ("bob", "Bob1234")


def test_email_pass_colon():
    ins = parse_instruction_text("user@example.com:Pass123")
    a = _one(ins)
    assert (a.username, a.password) == ("user@example.com", "Pass123")


def test_zh_free_text():
    ins = parse_instruction_text("邮箱 admin@x.com 密码 AdminPass123")
    a = _one(ins)
    assert (a.username, a.password) == ("admin@x.com", "AdminPass123")


def test_markdown_list_multi_accounts():
    text = (
        "- 管理员: admin@test.local / Admin#1\n"
        "- 普通用户: user@test.local / User#1"
    )
    ins = parse_instruction_text(text)
    assert len(ins.accounts) == 2
    roles = {a.role for a in ins.accounts}
    assert roles == {"管理员", "普通用户"}
    by_role = {a.role: (a.username, a.password) for a in ins.accounts}
    assert by_role["管理员"] == ("admin@test.local", "Admin#1")
    assert by_role["普通用户"] == ("user@test.local", "User#1")


def test_numbered_list():
    text = "1. Regular User  user@test.local / Reg123\n2. Admin  admin@test.local / Adm123"
    ins = parse_instruction_text(text)
    assert len(ins.accounts) == 2


def test_english_list_item_with_role():
    text = "- admin: admin@test.local / Pass1"
    ins = parse_instruction_text(text)
    a = _one(ins)
    assert a.role == "admin"


# ---------- 补充字段 ----------

def test_login_url_extract():
    ins = parse_instruction_text(
        "Login with email: admin@test.local, password: Pass1 "
        "login_url: https://app.test.local/admin/login"
    )
    assert ins.login_url == "https://app.test.local/admin/login"


def test_focus_and_exclude():
    ins = parse_instruction_text(
        "Login with email: admin@test.local, password: Pass1\n"
        "Focus on: /api, sql injection, xss\n"
        "Out of scope: /logout, /static"
    )
    assert ins.focus
    assert ins.exclude
    assert any("api" == x.lower() for x in ins.focus)
    assert any("logout" in x.lower() for x in ins.exclude)


def test_exclude_chinese():
    ins = parse_instruction_text("账号: a 密码: b\n重点: 登录接口\n排除: 退出接口")
    assert ins.focus
    assert ins.exclude


# ---------- 边界 ----------

def test_no_credentials():
    ins = parse_instruction_text("只扫 GET 接口")
    assert not ins.has_credentials
    assert ins.accounts == []


def test_empty_text():
    ins = parse_instruction_text("")
    assert not ins.has_credentials
    assert ins.focus == [] and ins.exclude == []


def test_none_text():
    ins = parse_instruction_text(None)
    assert not ins.has_credentials


def test_dedupe():
    text = "账号: alice 密码: Pass1\n账号: alice 密码: Pass1"
    ins = parse_instruction_text(text)
    assert len(ins.accounts) == 1


def test_masked_summary_no_password():
    ins = parse_instruction_text("Login with email: admin@test.local, password: TopSecret99")
    s = ins.masked_summary
    assert "TopSecret99" not in s
    assert "admin@test.local" in s
    assert "***" in s


# ---------- 文件加载 ----------

def test_load_instruction_file(tmp_path):
    f = tmp_path / "ins.txt"
    f.write_text("Login with email: f@test.local, password: Fp123", encoding="utf-8")
    ins = load_instruction(None, str(f))
    a = _one(ins)
    assert (a.username, a.password) == ("f@test.local", "Fp123")


def test_load_instruction_inline_priority(tmp_path):
    f = tmp_path / "ins.txt"
    f.write_text("账号: fileuser 密码: FilePass", encoding="utf-8")
    ins = load_instruction("账号: inlineuser 密码: InlinePass", str(f))
    a = _one(ins)
    assert a.username == "inlineuser"


def test_load_instruction_empty():
    ins = load_instruction(None, None)
    assert not ins.has_credentials


def test_load_instruction_missing_file(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        load_instruction(None, str(tmp_path / "nope.txt"))


def test_instruction_defaults():
    ins = Instruction()
    assert ins.accounts == [] and ins.focus == [] and ins.exclude == []
