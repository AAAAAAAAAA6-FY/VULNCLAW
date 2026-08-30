"""核心导入测试"""


def test_import_vulnclaw():
    import vulnclaw
    assert hasattr(vulnclaw, "__version__")


def test_import_config():
    from vulnclaw.config import settings
    assert settings is not None


def test_import_exceptions():
    from vulnclaw.exceptions import VULNCLAWError
    assert VULNCLAWError is not None


def test_import_engine_error():
    from vulnclaw.exceptions import EngineError
    assert EngineError is not None


def test_import_configuration_error():
    from vulnclaw.exceptions import ConfigurationError
    assert ConfigurationError is not None


def test_import_tool_error():
    from vulnclaw.exceptions import ToolError
    assert ToolError is not None


def test_import_scan_timeout_error():
    from vulnclaw.exceptions import ScanTimeoutError
    assert ScanTimeoutError is not None


def test_import_target_unreachable_error():
    from vulnclaw.exceptions import TargetUnreachableError
    assert TargetUnreachableError is not None


def test_exception_hierarchy():
    """验证异常继承关系"""
    from vulnclaw.exceptions import (
        VULNCLAWError, EngineError, ConfigurationError,
        ToolError, ScanTimeoutError, TargetUnreachableError
    )
    assert issubclass(EngineError, VULNCLAWError)
    assert issubclass(ConfigurationError, VULNCLAWError)
    assert issubclass(ToolError, VULNCLAWError)
    assert issubclass(ScanTimeoutError, VULNCLAWError)
    assert issubclass(TargetUnreachableError, VULNCLAWError)