"""核心模块测试：工具注册表"""

import pytest
from vulnclaw.ai.tools import TOOL_REGISTRY, ENGINE_CONFIGS


def test_tool_registry_initialized():
    """TOOL_REGISTRY 初始化后应有引擎"""
    assert len(TOOL_REGISTRY) > 0


def test_tool_registry_has_sqli():
    """能按名称获取 SQL 注入引擎"""
    assert "sqli" in TOOL_REGISTRY


def test_engine_configs_count():
    """引擎配置数量应为 29+"""
    assert len(ENGINE_CONFIGS) >= 29


def test_all_engines_have_name():
    """所有注册引擎都有 name 属性"""
    for name, tool in TOOL_REGISTRY.items():
        assert tool.name, f"引擎 {name} 缺少 name 属性"


def test_tool_registry_has_deserialization():
    """反序列化引擎已注册"""
    assert "deserialization" in TOOL_REGISTRY


def test_tool_registry_has_dotnet_deserialization():
    """.NET 反序列化引擎已注册"""
    assert "dotnet_deserialization" in TOOL_REGISTRY


def test_tool_registry_has_jwt_advanced():
    """JWT 高级攻击引擎已注册（v102 合并至 JWTEngine，name=jwt）"""
    assert "jwt" in TOOL_REGISTRY


def test_tool_registry_has_sensitive_files():
    """敏感文件泄露引擎已注册（v102 合并至 InfoLeakEngine，name=info_leak）"""
    assert "info_leak" in TOOL_REGISTRY