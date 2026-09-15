# -*- coding: utf-8 -*-
"""B4 资产面枚举端（modules/asset_surface.py）专项测试。

覆盖：主域/品牌派生、内网短路、桶名派生规则、GitHub 搜索降级、
子枚举器 fail-open 语义、enumerate_asset_surface 结构契约与授权合并。
"""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vulnclaw.modules import asset_surface as AS  # noqa: E402


# ---------------------------------------------------------------- 主域/品牌派生
def test_base_domain_simple():
    assert AS._base_domain("https://example.com/path") == "example.com"
    assert AS._base_domain("www.example.com") == "example.com"
    assert AS._base_domain("api.example.com:8080") == "example.com"


def test_base_domain_multi_level_suffix():
    assert AS._base_domain("https://m.example.com.cn/path") == "example.com.cn"
    assert AS._base_domain("www.example.co.uk") == "example.co.uk"
    assert AS._base_domain("example.test") == "example.test"


def test_base_domain_internal_shortcut():
    assert AS._base_domain("http://127.0.0.1:8092") == "127.0.0.1"
    assert AS._base_domain("http://10.0.0.1/") == "10.0.0.1"
    assert AS._base_domain("http://localhost/x") == "localhost"
    assert AS._base_domain("http://srv.internal/") == "srv.internal"


def test_brand_from():
    assert AS._brand_from("www.example.com") == "example"
    assert AS._brand_from("m.example.com.cn") == "example"
    assert AS._brand_from("api.example.test") == "example"
    assert AS._brand_from("") == ""
    assert AS._brand_from("example") == "example"


def test_strip_www_prefix_only():
    # 必须 startswith('www.') 判定，绝不 lstrip 字符集
    assert AS._strip_www("www.example.com") == "example.com"
    assert AS._strip_www("example.com") == "example.com"
    assert AS._strip_www("w.example.com") == "w.example.com"
    assert AS._strip_www("wwwexample.com") == "wwwexample.com"


def test_norm_url_candidate():
    assert AS._norm_url_candidate("m.example.com") == "https://m.example.com"
    assert AS._norm_url_candidate("https://m.example.com") == "https://m.example.com"
    assert AS._norm_url_candidate("") == ""


# ---------------------------------------------------------------- 内网短路
def test_is_internal_host():
    assert AS._is_internal_host("127.0.0.1")
    assert AS._is_internal_host("10.0.0.5")
    assert AS._is_internal_host("host.internal")
    assert AS._is_internal_host("srv.local")
    assert AS._is_internal_host("localhost")
    assert not AS._is_internal_host("example.com")
    # 空 host 视为"保守短路"：视作内部，避免对外部空域发起探测
    assert AS._is_internal_host("")
    assert AS._is_internal_host("192.168.1.1")


# ---------------------------------------------------------------- 桶名派生
def test_bucket_patterns_with_brand():
    patterns = [p.format(brand="acme") for p in AS.BUCKET_NAME_PATTERNS]
    assert "acme" in patterns
    assert "acme-assets" in patterns
    assert "acme-backups" in patterns
    assert all("acme" in p for p in patterns)  # 每个候选都含品牌词


def test_bucket_providers_shape():
    for provider, (tpl, markers) in AS.BUCKET_PROVIDERS.items():
        assert "{bucket}" in tpl, provider
        assert markers, provider
    # 覆盖主流厂商
    assert {"aws-s3", "gcs", "azure-blob"} <= set(AS.BUCKET_PROVIDERS)


def test_bucket_probe_nonexistent_absent():
    # 模拟"桶不存在"响应：存在性应判定 False
    from unittest.mock import patch

    class _Resp:
        status_code = 404
        text = "NoSuchBucket The specified bucket does not exist"
        headers = {"Content-Type": "application/xml"}

    with patch("requests.get", return_value=_Resp()):
        r = AS._bucket_probe_sync("x", "aws-s3", "https://{bucket}.s3.amazonaws.com/",
                                  ("NoSuchBucket", "specified bucket does not exist"))
        assert r["exists"] is False
        assert r["public"] is False


def test_bucket_probe_public_listable():
    from unittest.mock import patch

    class _Resp:
        status_code = 200
        text = "<ListBucketResult><Contents><Key>a.txt</Key></Contents></ListBucketResult>"
        headers = {"Content-Type": "application/xml"}

    with patch("requests.get", return_value=_Resp()):
        r = AS._bucket_probe_sync("x", "aws-s3", "https://{bucket}.s3.amazonaws.com/",
                                  ("NoSuchBucket",))
        assert r["exists"] is True
        assert r["public"] is True


# ---------------------------------------------------------------- 软404
def test_looks_like_soft404():
    assert AS._looks_like_soft404("")
    assert AS._looks_like_soft404("short")
    assert AS._looks_like_soft404("404 not found page")
    assert asyncio.run(_async_soft404()) is not None  # 空 body 判定


async def _async_soft404():
    return "x" if AS._looks_like_soft404("") else None


# ---------------------------------------------------------------- fail-open 语义
def test_enum_mobile_hosts_internal_short_circuit():
    r = asyncio.run(AS._enum_mobile_hosts("http://127.0.0.1:8092", "127.0.0.1", 30))
    assert r == {"hosts": [], "apk_urls": [], "alive_urls": []}


def test_enum_cloud_buckets_internal_short_circuit():
    r = asyncio.run(AS._enum_cloud_buckets("127.0.0.1", 30))
    assert r == {"buckets": [], "public_buckets": []}


def test_enum_api_docs_internal_short_circuit():
    r = asyncio.run(AS._enum_api_docs("http://127.0.0.1:8092", "127.0.0.1", 30))
    assert r == {"endpoints": []}


def test_enum_dev_facilities_internal_short_circuit():
    r = asyncio.run(AS._enum_dev_facilities("http://127.0.0.1:8092", "127.0.0.1", 30))
    assert r == {"git": [], "ci": [], "debug": [], "env": []}


# ---------------------------------------------------------------- 供应链解析（纯函数内走 mock async_get）
async def _run_supply_chain_with(body: str, js_list=None):
    from vulnclaw.core import utils

    async def _fake_get(*args, **kwargs):
        return (200, body, {})

    orig = utils.async_get
    utils.async_get = _fake_get
    try:
        return await AS._enum_supply_chain("https://example.com", {"js_endpoints": js_list or []}, 30)
    finally:
        utils.async_get = orig


def test_supply_chain_cdn_detection():
    body = '<script src="https://cdn.jsdelivr.net/npm/react@18.2.0/index.js"></script>'
    r = asyncio.run(_run_supply_chain_with(body))
    assert any("jsdelivr" in d for d in r["cdn_domains"])


def test_supply_chain_library_detection():
    body = 'cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js'
    r = asyncio.run(_run_supply_chain_with(body))
    assert any("jQuery" in lib for lib in r["libraries"])


# ---------------------------------------------------------------- 主入口契约
def test_enumerate_asset_surface_contract():
    r = asyncio.run(AS.enumerate_asset_surface(
        "http://127.0.0.1:8092", "127.0.0.1", brief={}, budget_s=20))
    # 结构契约：所有键齐备
    for key in ("target", "base_domain", "budget_s", "elapsed_s",
                "subdomains_candidates", "api_docs", "mobile",
                "supply_chain", "cloud", "dev_facilities", "public_repos",
                "extra_scan_urls", "lines"):
        assert key in r, key
    assert r["base_domain"] == "127.0.0.1"
    # 内网目标：无任何外部探测产物
    assert r["extra_scan_urls"] == []
    assert r["cloud"] == {"buckets": [], "public_buckets": []}
    assert r["lines"]["crawled_endpoints"] == []
    assert "subdomains" in r["lines"]


def test_enumerate_asset_surface_never_raises():
    # 异常目标 / 空 brief 也不抛
    r = asyncio.run(AS.enumerate_asset_surface("", "", brief=None, budget_s=2))
    assert isinstance(r, dict)
    assert r["target"] == ""


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--capture=no"]))