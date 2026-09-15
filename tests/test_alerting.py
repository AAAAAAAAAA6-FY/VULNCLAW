# -*- coding: utf-8 -*-
"""AlertSender 离线测试：卡片构建 / 限频 / 重试 / 平台路由。

全部 mock 发送器（patch _send_* 方法），不发真实网络请求。
"""
import pytest

from vulnclaw.core.settings import settings
from vulnclaw.core_modules.alerting import AlertSender


class TestBuildCard:
    def test_card_with_finding_contains_repro_and_url(self):
        card = AlertSender._build_card(
            "SQLi 命中",
            "msg",
            "critical",
            finding={
                "type": "SQL注入",
                "url": "http://x/search?q=1",
                "parameter": "q",
                "payload": "' OR 1=1 -- -",
            },
        )
        assert "SQL注入" in card["markdown"]
        assert "http://x/search?q=1" in card["markdown"]
        assert "' OR 1=1 -- -" in card["markdown"]  # 复现命令块
        assert card["url"] == "http://x/search?q=1"
        assert card["repro"] == "' OR 1=1 -- -"

    def test_card_without_finding_contains_message_and_url(self):
        card = AlertSender._build_card("标题", "正文消息", "info", url="http://a/b")
        assert "正文消息" in card["markdown"]
        assert "http://a/b" in card["markdown"]

    def test_card_title_truncated_to_100(self):
        card = AlertSender._build_card("x" * 300, "m", "info")
        assert len(card["title"]) == 100

    def test_unknown_severity_fallback_emoji(self):
        card = AlertSender._build_card("t", "m", "weird")
        assert "📢" in card["markdown"]


class TestSend:
    @pytest.mark.asyncio
    async def test_no_webhook_returns_false(self, monkeypatch):
        monkeypatch.setattr(settings, "alert_webhook", "", raising=False)
        sender = AlertSender(webhook_url="")
        assert await sender.send("t", "m") is False

    @pytest.mark.asyncio
    async def test_rate_limit_skips_second_noncritical(self, monkeypatch):
        sender = AlertSender(webhook_url="http://dingtalk.example/hook")
        calls = []

        async def fake_send(msg, card=None):
            calls.append(msg)
            return True

        monkeypatch.setattr(sender, "_send_dingtalk", fake_send)
        assert await sender.send("t1", "m1", severity="info") is True
        # 紧接第二次 info：限频跳过（发送器未被调用）
        assert await sender.send("t2", "m2", severity="info") is False
        assert len(calls) == 1

    @pytest.mark.asyncio
    async def test_critical_bypasses_rate_limit(self, monkeypatch):
        sender = AlertSender(webhook_url="http://dingtalk.example/hook")
        calls = []

        async def fake_send(msg, card=None):
            calls.append(msg)
            return True

        monkeypatch.setattr(sender, "_send_dingtalk", fake_send)
        assert await sender.send("t1", "m1", severity="info") is True
        assert await sender.send("t2", "m2", severity="critical") is True
        assert len(calls) == 2

    @pytest.mark.asyncio
    async def test_retry_until_success(self, monkeypatch):
        sender = AlertSender(webhook_url="http://dingtalk.example/hook")
        sender._retry_delay = 0  # 免等待
        attempts = []

        async def flaky_send(msg, card=None):
            attempts.append(1)
            return len(attempts) >= 2  # 首次失败、第二次成功

        monkeypatch.setattr(sender, "_send_dingtalk", flaky_send)
        assert await sender.send("t", "m", severity="critical") is True
        assert len(attempts) == 2

    @pytest.mark.asyncio
    async def test_all_retries_fail_returns_false(self, monkeypatch):
        sender = AlertSender(webhook_url="http://dingtalk.example/hook")
        sender._retry_delay = 0
        attempts = []

        async def always_fail(msg, card=None):
            attempts.append(1)
            return False

        monkeypatch.setattr(sender, "_send_dingtalk", always_fail)
        assert await sender.send("t", "m", severity="critical") is False
        assert len(attempts) == sender._max_retries


class TestPlatformRouting:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "webhook,expected_method",
        [
            ("http://oapi.dingtalk.com/robot/send?access_token=x", "_send_dingtalk"),
            ("http://open.feishu.cn/open-apis/bot/v2/hook/x", "_send_feishu"),
            ("http://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x", "_send_wecom"),
            ("http://custom.example/webhook", "_send_generic"),
        ],
    )
    async def test_webhook_routes_to_platform_sender(
        self, monkeypatch, webhook, expected_method
    ):
        sender = AlertSender(webhook_url=webhook)
        hit = {}

        def _patch(name):
            async def _fake(msg, card=None):
                hit["method"] = name
                return True

            monkeypatch.setattr(sender, name, _fake)

        for name in ("_send_dingtalk", "_send_feishu", "_send_wecom", "_send_generic"):
            _patch(name)
        assert await sender.send("t", "m", severity="critical") is True
        assert hit.get("method") == expected_method
