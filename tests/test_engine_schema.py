# -*- coding: utf-8 -*-
"""SP7: 逐引擎参数 schema 测试——签名自动同步 + engine.list 附 schema。"""
import pytest

from vulnclaw.core.scanner import engine_param_schema, get_all_engines


class TestEngineParamSchema:
    def test_schema_shape(self):
        engines = get_all_engines()
        assert len(engines) > 10
        for eng in engines:
            schema = engine_param_schema(eng)
            assert schema["type"] == "object"
            props = schema["properties"]
            assert isinstance(props, dict)
            for pname, pmeta in props.items():
                assert pmeta["type"] == "string"
                assert "required" in pmeta
                assert "default" in pmeta
            # schema 与引擎签名自动同步：额外具名参数必须出现在 props 中
            import inspect

            for attr, enabled in (("scan", hasattr(eng, "scan")), ("check", hasattr(eng, "check"))):
                if not enabled:
                    continue
                try:
                    sig = inspect.signature(getattr(type(eng), attr))
                except (TypeError, ValueError):
                    continue
                for pname, pp in sig.parameters.items():
                    if pname in {
                        "self", "url", "param", "normal_resp", "parsed_query",
                        "session", "target",
                    }:
                        continue
                    if pp.kind in (inspect.Parameter.VAR_POSITIONAL,
                                   inspect.Parameter.VAR_KEYWORD):
                        continue
                    assert pname in props, f"{eng.name}.{attr} 签名参数 {pname} 未同步进 schema"

    def test_schema_required_matches_capability(self):
        from vulnclaw.core.scanner import engine_capability

        for eng in get_all_engines():
            has_scan, has_check = engine_capability(eng)
            schema = engine_param_schema(eng)
            req = set(schema.get("required", []))
            if has_scan and not has_check:
                assert "target" in req
            if has_check:
                assert "url" in req and "param" in req

    def test_schema_json_serializable(self):
        import json

        for eng in get_all_engines():
            json.dumps(engine_param_schema(eng), default=str)


@pytest.mark.asyncio
async def test_engine_list_has_schema_in_mcp():
    """engine.list 返回逐引擎 schema（LLM agent 调工具直接用）。"""
    from vulnclaw.core.mcp_server import MCPJsonRpcHandler

    handler = MCPJsonRpcHandler(event_bus=None)
    import json as _json

    result = await handler._tool_engine_list({})
    data = _json.loads(result["content"][0]["text"])
    assert data["count"] > 10
    first = data["engines"][0]
    assert "schema" in first
    assert first["schema"]["type"] == "object"
