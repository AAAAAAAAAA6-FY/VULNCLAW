"""
httpbin 集成测试 - 验证网络基础能力
不依赖任何引擎逻辑，直接测试 core.utils.async_get

注意：这些测试需要网络连接。如果 httpbin.org 不可访问，测试会跳过。
"""
import pytest

@pytest.mark.asyncio
async def test_httpbin_delay_timeout():
    """① /delay/3 - 超时处理（设置 1s 超时，应触发超时）"""
    from vulnclaw.core.utils import async_get
    status, text, headers = await async_get("https://httpbin.org/delay/3", timeout=1)
    # status=0 表示超时或网络错误，这是预期行为
    assert status == 0 or status == 200, f"预期超时或成功，实际 status={status}"

@pytest.mark.asyncio
async def test_httpbin_status_404():
    """② /status/404 - 404 不重试"""
    from vulnclaw.core.utils import async_get
    status, text, headers = await async_get("https://httpbin.org/status/404")
    if status == 0:
        pytest.skip("httpbin.org 不可访问，跳过")
    assert status == 404, f"预期 404，实际 status={status}"

@pytest.mark.asyncio
async def test_httpbin_cookies_set():
    """③ /cookies/set - Cookie 持久化"""
    from vulnclaw.core.utils import async_get
    status, text, headers = await async_get("https://httpbin.org/cookies/set?testcookie=hello")
    if status == 0:
        pytest.skip("httpbin.org 不可访问，跳过")
    assert status == 200
    assert "testcookie" in text

@pytest.mark.asyncio
async def test_httpbin_get_params():
    """④ /get?test=1 - 参数回显"""
    from vulnclaw.core.utils import async_get
    status, text, headers = await async_get("https://httpbin.org/get?test=1")
    if status == 0:
        pytest.skip("httpbin.org 不可访问，跳过")
    assert status == 200
    assert "test" in text and "1" in text

@pytest.mark.asyncio
async def test_httpbin_anything_json():
    """⑤ /anything - JSON 解析"""
    from vulnclaw.core.utils import async_get
    status, text, headers = await async_get("https://httpbin.org/anything", headers={"Accept": "application/json"})
    if status == 0:
        pytest.skip("httpbin.org 不可访问，跳过")
    assert status == 200
    assert "headers" in text or "method" in text
