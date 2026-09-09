# -*- coding: utf-8 -*-
"""AntiScanDetector 判定阈值最小单测：正例/反例 + 配置项生效。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

import pytest

from vulnclaw.engines.auxiliary_engines import AntiScanDetector
from vulnclaw.config.settings import settings

UUID_TEXT = " ".join(f"id={{{{00000000-0000-0000-0000-{i:012d}}}}}" for i in range(20))
SMALL_TEXT = "x" * 100
BIG_TEXT = "y" * 9000


def test_honeypot_many_uuid():
    ok, msg = AntiScanDetector.is_honeypot(UUID_TEXT + BIG_TEXT, {})
    assert ok, "146个UUID+大文本应判蜜罐"
    assert "UUID" in msg


def test_honeypot_clean_text():
    ok, _ = AntiScanDetector.is_honeypot(SMALL_TEXT, {})
    assert not ok, "正常文本不应判蜜罐"


def test_fake404_big_body():
    ok, msg = AntiScanDetector.is_fake_404(BIG_TEXT, 404)
    assert ok, "404+大体积应判假404"
    assert "响应体过大" in msg


def test_fake404_small():
    ok, _ = AntiScanDetector.is_fake_404(SMALL_TEXT, 404)
    assert not ok


def test_rate_limited_text():
    ok, msg = AntiScanDetector.is_rate_limited("Try again later", {})
    assert ok, "too many requests 提示应判限流"
    assert "限流" in msg


def test_rate_limited_header():
    ok, _ = AntiScanDetector.is_rate_limited("ok", {"Retry-After": "120"})
    assert ok


def test_rate_limited_clean():
    ok, _ = AntiScanDetector.is_rate_limited(SMALL_TEXT, {})
    assert not ok


def test_ip_blocked():
    ok, msg = AntiScanDetector.is_ip_blocked("your ip is blocked", 403)
    assert ok, "403+blocked 应判封禁"
    assert "被封禁" in msg


def test_ip_blocked_clean():
    ok, _ = AntiScanDetector.is_ip_blocked(SMALL_TEXT, 200)
    assert not ok


def test_analyze_aggregate():
    r = AntiScanDetector.analyze_response(UUID_TEXT + BIG_TEXT, 404, {})
    assert r["is_honeypot"] and r["is_fake_404"]


@pytest.mark.parametrize("attrs", [
    {"anti_scan_uuid_threshold": 1, "anti_scan_honeypot_min_text": 10},       # UUID 计数+短文本双通道调低
    {"anti_scan_placeholder_threshold": 1},                                   # 2 个占位符即可命中
    {"anti_scan_fake404_min_text": 10},                                       # 20 字节 404 即判假404
])
def test_threshold_config_effective(monkeypatch, attrs):
    """验证配置项真实生效：调低阈值后小样本也命中。"""
    for k, v in attrs.items():
        monkeypatch.setattr(settings, k, v)
    if "anti_scan_fake404_min_text" in attrs:
        ok, _ = AntiScanDetector.is_fake_404("p" * 20, 404)
    elif "anti_scan_placeholder_threshold" in attrs:
        ok, _ = AntiScanDetector.is_honeypot("{{a}}{{b}}", {})
    else:
        text = "0".join("00000000-0000-0000-0000-%012d" % i for i in range(2))
        ok, _ = AntiScanDetector.is_honeypot(text, {})
    assert ok, f"{attrs} 调低后应命中"
