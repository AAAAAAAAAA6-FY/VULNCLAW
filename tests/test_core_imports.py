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


# ==================================================================
# A4.5: LLM 语义缓存验收（OPTIMIZATION_ROADMAP P1-2）
# ==================================================================
import pytest


@pytest.fixture(autouse=True)
def _isolate_llm_shared_state():
    """LLM 语义缓存 / Provider 熔断是**进程级共享状态**，会制造"顺序依赖"假失败。

    实测：同 worker 内其它用例把 zhipu provider 打成 OPEN 后，本模块的缓存用例
    会在 `ask()` 里被熔断直接跳过 → `RuntimeError: 所有模型均被熔断跳过`，
    表现为"单独跑绿、全量跑红"。跑前统一复位，保证用例自洽（不依赖执行顺序）。
    """
    try:
        from vulnclaw.ai.core import LLMClient
        LLMClient._semantic_cache.clear()
        LLMClient._blocked_models = set()
        from vulnclaw.ai.provider_failover import get_provider_failover
        for cb in get_provider_failover()._breakers.values():
            cb._state = "CLOSED"
            cb._failures = 0
            cb._last_fail_time = None
    except Exception:  # noqa: BLE001 - 隔离失败不阻断用例本身
        pass
    yield


@pytest.mark.asyncio
async def test_llm_semantic_cache_hit():
    """同 prompt + use_cache=True：第二次命中缓存，网络层只调 1 次。"""
    from vulnclaw.ai.core import LLMClient

    client = LLMClient(api_key="test-key", models=["glm-4-flash"])
    calls = {"n": 0}

    async def fake_call_model_once(model, prompt, system, temperature, max_tokens, usage_site=None):
        calls["n"] += 1
        return "cached response"

    client._call_model_once = fake_call_model_once
    LLMClient._semantic_cache.clear()

    r1 = await client.ask("identical prompt for cache test", use_cache=True)
    r2 = await client.ask("identical prompt for cache test", use_cache=True)
    assert r1 == "cached response" and r2 == "cached response"
    assert calls["n"] == 1
    assert LLMClient.get_cache_stats()["size"] >= 1


@pytest.mark.asyncio
async def test_llm_semantic_cache_miss_on_diff_prompt():
    """不同 prompt 不命中缓存：网络调用 2 次。"""
    from vulnclaw.ai.core import LLMClient

    client = LLMClient(api_key="test-key", models=["glm-4-flash"])
    calls = {"n": 0}

    async def fake_call_model_once(model, prompt, system, temperature, max_tokens, usage_site=None):
        calls["n"] += 1
        return f"response-{calls['n']}"

    client._call_model_once = fake_call_model_once
    LLMClient._semantic_cache.clear()

    await client.ask("prompt A for cache test", use_cache=True)
    await client.ask("prompt B for cache test", use_cache=True)
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_llm_semantic_cache_disabled_by_default():
    """use_cache=False 不缓存：同 prompt 两次都走网络。"""
    from vulnclaw.ai.core import LLMClient

    client = LLMClient(api_key="test-key", models=["glm-4-flash"])
    calls = {"n": 0}

    async def fake_call_model_once(model, prompt, system, temperature, max_tokens, usage_site=None):
        calls["n"] += 1
        return "response"

    client._call_model_once = fake_call_model_once

    await client.ask("same prompt no cache", use_cache=False)
    await client.ask("same prompt no cache", use_cache=False)
    assert calls["n"] == 2


# ==================================================================
# 主链路冒烟（2026-09-16）：E2E 门禁不覆盖 orchestrator
# ==================================================================
# 事故背景：orchestrator.py 末尾曾混入 6 行 Markdown 表格残留导致 SyntaxError，
# 而 `eval_prf` 声明线 E2E **不经过 orchestrator**（直接驱引擎 + 声明匹配），
# F1=100% 完全无法发现 → 损坏潜伏多轮无人察觉。
# 本组断言把"主链路可导入 / 可实例化 / 无残留"变成显式门禁。
class TestMainChainSmoke:
    """主链路冒烟：任何文件级损坏都必须在测试里立刻暴露。"""

    def test_orchestrator_and_mixins_importable(self):
        """orchestrator 及其 3 个 mixin 必须可导入（防文件级损坏）。"""
        import importlib
        for mod in (
            "vulnclaw.ai.v100.orchestrator",
            "vulnclaw.ai.v100.orchestrator_models",
            "vulnclaw.ai.v100.orchestrator_stream",
            "vulnclaw.ai.v100.orchestrator_findings",
        ):
            importlib.import_module(mod)

    def test_orchestrator_class_exposes_core_methods(self):
        """V100Orchestrator 必须保留核心方法（mixin 拆分后不得丢方法）。

        注意：`compress_prompt` 是**模块级函数**（拆分时迁到 orchestrator_models
        并在 orchestrator 里再导出以保兼容），不是类方法 —— 它单独断言。
        """
        from vulnclaw.ai.v100.orchestrator import V100Orchestrator, compress_prompt
        for name in ("run", "_add_finding", "_ask_ai"):
            assert hasattr(V100Orchestrator, name), f"主链路方法缺失: {name}"
        assert callable(compress_prompt), "模块级 compress_prompt 再导出丢失"

    def test_main_chain_modules_parse(self):
        """AST 解析全部主链路模块（比 import 更快定位损坏行号）。"""
        import ast
        import pathlib
        base = pathlib.Path(__file__).resolve().parents[1] / "src" / "vulnclaw"
        targets = [base / "core" / "scanner.py"] + sorted((base / "ai" / "v100").glob("orchestrator*.py"))
        assert targets, "主链路模块定位失败"
        for p in targets:
            try:
                ast.parse(p.read_text(encoding="utf-8-sig"))
            except SyntaxError as exc:
                raise AssertionError(f"{p.name} 语法错误 @line {exc.lineno}: {exc.msg}") from exc

    def test_no_markdown_table_residue_in_src(self):
        """全 src 扫描：不得有 Markdown 表格残留（历史上真发生过，致 SyntaxError）。

        判据：以"数字 + tab"开头、且后续列形如 `xxx/yyy.py` 的行 ——
        正常 Python 代码不会长这样（连续 tab 分隔 + .py 路径列）。
        """
        import pathlib
        import re
        pat = re.compile(r"^\d+\t[^\t]+\t[^\t]+\.py\t")
        bad = []
        src = pathlib.Path(__file__).resolve().parents[1] / "src"
        for p in src.rglob("*.py"):
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if pat.match(line):
                    bad.append(f"{p.name}:{i}")
        assert not bad, f"发现表格残留（会导致 SyntaxError）: {bad[:5]}"