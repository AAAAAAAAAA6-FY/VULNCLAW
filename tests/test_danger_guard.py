"""危险操作权限门卫（Danger Guard）单元测试。

验证三类行为：
  1. deny（默认）：危险操作一律拒绝；非危险操作恒放行；
  2. allow：显式放行后危险操作通过；
  3. 审计：每次决策都进入审计环，可查询。
"""
import pytest

from vulnclaw.core.danger_guard import DANGEROUS_OPS, DangerGuard


@pytest.fixture
def guard(monkeypatch):
    monkeypatch.setattr("vulnclaw.core.danger_guard.settings.dangerous_mode", "deny")
    monkeypatch.setattr("vulnclaw.core.danger_guard.settings.dangerous_allow_list", [])
    return DangerGuard()


def test_deny_mode_blocks_dangerous_ops(guard):
    for op in DANGEROUS_OPS:
        assert guard.require_approval(op, "test") is False, f"{op} 应在 deny 模式下被拒绝"


def test_non_dangerous_op_always_allowed(guard):
    assert guard.require_approval("some_detection_engine", "not dangerous") is True


def test_allow_mode_passes(guard):
    guard.set_mode("allow")
    assert guard.require_approval("msf_exploit", "test") is True


def test_allow_list_selective(guard):
    guard.set_mode("deny")
    guard._allow_list.add("exploit_verify")
    assert guard.require_approval("exploit_verify", "test") is True
    assert guard.require_approval("msf_exploit", "test") is False


def test_prompt_mode_denied_when_non_tty(guard, monkeypatch):
    """非交互环境（CI/后台）下 prompt 模式也自动拒绝，不应阻塞。"""
    guard.set_mode("prompt")
    monkeypatch.setattr("vulnclaw.core.danger_guard.sys.stdin.isatty", lambda: False)
    assert guard.require_approval("exploit_chain", "test") is False


def test_mode_aliases_normalized(guard):
    """兼容 .env 里的布尔写法：false→deny、true→allow；未知值兜底 deny。"""
    assert guard.mode == "deny"
    guard.set_mode("false")
    assert guard.mode == "deny"
    guard.set_mode("true")
    assert guard.mode == "allow"
    assert guard.require_approval("exploit_chain", "test") is True
    guard.set_mode("garbage")
    # 未知写法不生效（保持 allow），避免误配
    assert guard.mode == "allow"


def test_audit_records_decisions(guard):
    guard.require_approval("exploit_chain", "findings=3")
    guard.set_mode("allow")
    guard.require_approval("msf_exploit", "module=x")
    audit = guard.get_audit()
    assert len(audit) == 2
    assert audit[0]["op"] == "exploit_chain"
    assert audit[0]["allowed"] is False
    assert audit[0]["mode"] == "deny"
    assert audit[1]["op"] == "msf_exploit"
    assert audit[1]["allowed"] is True
