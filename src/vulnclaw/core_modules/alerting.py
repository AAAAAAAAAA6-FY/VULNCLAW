# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core_modules/alerting.py（R3 迁移自 core/alerting.py）
"""
告警模块：支持钉钉、飞书、企业微信 Webhook
功能：
1. 钉钉告警
2. 飞书告警
3. 企业微信告警
4. 通用 Webhook
5. 限频保护
6. 重试机制
"""

import asyncio
import time
import aiohttp
from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from typing import Any, Dict, List, Optional


class AlertSender:
    """告警发送器 - 带重试机制"""

    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or getattr(settings, 'alert_webhook', '')
        self._last_alert_time = 0
        self._min_interval = 10
        self._max_retries = 3
        self._retry_delay = 2

    async def send(
        self,
        title: str,
        message: str,
        severity: str = "info",
        url: str = "",
        finding: Optional[Dict] = None,
        bypass_rate_limit: bool = False,
    ) -> bool:
        """
        发送告警（P4-5: 默认发送富文本卡片）

        severity: info, warning, critical
        finding: 漏洞字典（可选），用于生成含漏洞名/URL/复现命令的结构化卡片
        bypass_rate_limit: 绕过限频（批量高危告警时使用）
        """
        if not self.webhook_url:
            logger.debug("告警 Webhook URL 未配置，跳过发送")
            return False

        if severity != "critical" and not bypass_rate_limit:
            now = time.time()
            if now - self._last_alert_time < self._min_interval:
                logger.debug(f"⏳ 告警限频，跳过: {title}")
                return False
            self._last_alert_time = now

        severity_emoji = {
            "info": "ℹ️",
            "warning": "⚠️",
            "critical": "🚨"
        }.get(severity, "📢")

        full_message = f"{severity_emoji} **{title}**\n\n{message}"
        if url:
            full_message += f"\n\n🔗 URL: {url}"

        # P4-5: 构建结构化卡片（未启用卡片时退化为纯文本）
        card = None
        if settings.alert_card_enabled:
            card = self._build_card(title, message, severity, url, finding)

        # 带重试的发送
        for attempt in range(self._max_retries):
            try:
                if "dingtalk" in self.webhook_url or "ding" in self.webhook_url:
                    success = await self._send_dingtalk(full_message, card)
                elif "feishu" in self.webhook_url or "lark" in self.webhook_url:
                    success = await self._send_feishu(full_message, card)
                elif "qyapi.weixin" in self.webhook_url:
                    success = await self._send_wecom(full_message, card)
                else:
                    success = await self._send_generic(full_message, card)

                if success:
                    return True

                if attempt < self._max_retries - 1:
                    await asyncio.sleep(self._retry_delay * (attempt + 1))
            except Exception as e:
                logger.error(f"❌ 告警发送失败 (尝试 {attempt + 1}/{self._max_retries}): {e}")
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(self._retry_delay * (attempt + 1))

        return False

    # ---------------- P4-5: 富文本卡片 ----------------
    @staticmethod
    def _build_card(
        title: str,
        message: str,
        severity: str,
        url: str = "",
        finding: Optional[Dict] = None,
    ) -> Dict:
        """生成结构化卡片内容（漏洞名称 / URL / 严重程度 / 复现命令）。"""
        emoji = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}.get(severity, "📢")
        lines = [f"{emoji} **{title}**", ""]
        repro = ""
        card_url = url or ""
        if finding:
            name = (
                finding.get("name")
                or finding.get("vuln_type")
                or finding.get("type")
                or "未知漏洞"
            )
            sev = str(finding.get("severity") or severity)
            card_url = finding.get("url") or url or ""
            param = finding.get("parameter") or finding.get("param") or ""
            cwe = finding.get("cwe") or ""
            cvss = finding.get("cvss") or finding.get("score") or ""
            desc = finding.get("description") or message
            repro = str(
                finding.get("poc")
                or finding.get("payload")
                or finding.get("reproduce")
                or ""
            )
            lines += [
                f"**漏洞名称**：{name}",
                f"**严重程度**：{sev}",
                f"**目标 URL**：{card_url}",
            ]
            if param:
                lines.append(f"**参数**：{param}")
            if cwe:
                lines.append(f"**CWE**：{cwe}")
            if cvss:
                lines.append(f"**评分**：{cvss}")
            if desc:
                lines += ["", str(desc)[:600]]
            if repro:
                lines += ["", "**复现命令**：", "```", repro[:500], "```"]
        else:
            lines.append(message)
            if url:
                lines += ["", f"🔗 URL: {url}"]
        return {
            "title": str(title)[:100],
            "markdown": "\n".join(lines),
            "url": card_url,
            "repro": repro,
            "severity": severity,
        }

    @staticmethod
    def _severity_color(severity: str) -> str:
        return {"critical": "red", "warning": "orange", "info": "green"}.get(
            severity, "blue"
        )

    async def _send_dingtalk(self, message: str, card: Optional[Dict] = None) -> bool:
        """钉钉：critical → markdown 卡片 + @所有人；其余 → actionCard（含"立即复现"按钮）。"""
        try:
            async with aiohttp.ClientSession() as session:
                if card:
                    if card["severity"] == "critical" and settings.alert_at_all_on_critical:
                        payload = {
                            "msgtype": "markdown",
                            "markdown": {"title": card["title"], "text": card["markdown"]},
                            "at": {"isAtAll": True},
                        }
                    elif card["url"].startswith("http"):
                        payload = {
                            "msgtype": "actionCard",
                            "actionCard": {
                                "title": card["title"],
                                "text": card["markdown"],
                                "hideAvatar": "0",
                                "btnOrientation": "0",
                                "btns": [
                                    {"title": "立即复现", "actionURL": card["url"]},
                                ],
                            },
                        }
                    else:
                        payload = {
                            "msgtype": "markdown",
                            "markdown": {"title": card["title"], "text": card["markdown"]},
                        }
                else:
                    payload = {"msgtype": "text", "text": {"content": message}}
                async with session.post(self.webhook_url, json=payload, timeout=10) as resp:
                    if resp.status != 200:
                        return False
                    try:
                        data = await resp.json(content_type=None)
                        if isinstance(data, dict) and data.get("errcode") not in (0, None):
                            logger.warning(f"⚠️ 钉钉告警返回异常: {str(data)[:200]}")
                            return False
                    except Exception:
                        pass
                    return True
        except Exception as e:
            logger.error(f"❌ 钉钉告警发送失败: {e}")
            return False

    async def _send_feishu(self, message: str, card: Optional[Dict] = None) -> bool:
        """飞书：interactive 卡片（含"立即复现"按钮 + 严重程度配色）。"""
        try:
            async with aiohttp.ClientSession() as session:
                if card:
                    elements = [
                        {"tag": "div", "text": {"tag": "lark_md", "content": card["markdown"]}},
                    ]
                    if card["url"].startswith("http"):
                        elements.append({
                            "tag": "action",
                            "actions": [{
                                "tag": "button",
                                "text": {"tag": "plain_text", "content": "立即复现"},
                                "type": "primary",
                                "url": card["url"],
                            }],
                        })
                    elements.append({"tag": "hr"})
                    elements.append({
                        "tag": "note",
                        "elements": [{"tag": "plain_text", "content": "VulnClaw 渗透测试平台 · 自动化告警"}],
                    })
                    payload = {
                        "msg_type": "interactive",
                        "card": {
                            "config": {"wide_screen_mode": True},
                            "header": {
                                "title": {"tag": "plain_text", "content": card["title"]},
                                "template": self._severity_color(card["severity"]),
                            },
                            "elements": elements,
                        },
                    }
                else:
                    payload = {"msg_type": "text", "content": {"text": message}}
                async with session.post(self.webhook_url, json=payload, timeout=10) as resp:
                    if resp.status != 200:
                        return False
                    try:
                        data = await resp.json(content_type=None)
                        if isinstance(data, dict) and data.get("code") not in (0, None):
                            logger.warning(f"⚠️ 飞书告警返回异常: {str(data)[:200]}")
                            return False
                    except Exception:
                        pass
                    return True
        except Exception as e:
            logger.error(f"❌ 飞书告警发送失败: {e}")
            return False

    async def _send_wecom(self, message: str, card: Optional[Dict] = None) -> bool:
        """企业微信：markdown 卡片；critical 时先发 text @所有人。"""
        try:
            async with aiohttp.ClientSession() as session:
                if card and card["severity"] == "critical" and settings.alert_at_all_on_critical:
                    await session.post(
                        self.webhook_url,
                        json={
                            "msgtype": "text",
                            "text": {
                                "content": f"🚨 高危漏洞告警：{card['title']}",
                                "mentioned_list": ["@all"],
                            },
                        },
                        timeout=10,
                    )
                if card:
                    payload = {"msgtype": "markdown", "markdown": {"content": card["markdown"]}}
                else:
                    payload = {"msgtype": "text", "text": {"content": message}}
                async with session.post(self.webhook_url, json=payload, timeout=10) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.error(f"❌ 企业微信告警发送失败: {e}")
            return False

    async def _send_generic(self, message: str, card: Optional[Dict] = None) -> bool:
        """通用 Webhook：附带卡片结构化字段。"""
        try:
            async with aiohttp.ClientSession() as session:
                payload: Dict = {
                    "title": "渗透测试告警",
                    "message": message,
                    "timestamp": time.time(),
                }
                if card:
                    payload.update({
                        "title": card["title"],
                        "markdown": card["markdown"],
                        "url": card["url"],
                        "severity": card["severity"],
                        "reproduce": card["repro"],
                    })
                async with session.post(self.webhook_url, json=payload, timeout=10) as resp:
                    return resp.status in (200, 201, 204)
        except Exception as e:
            logger.error(f"❌ 通用告警发送失败: {e}")
            return False


_alert_sender = None


def get_alert_sender() -> AlertSender:
    global _alert_sender
    if _alert_sender is None:
        _alert_sender = AlertSender()
    return _alert_sender


async def send_alert(
    title: str,
    message: str,
    severity: str = "info",
    url: str = "",
    finding: Optional[Dict] = None,
):
    """发送告警（P4-5: 支持传入 finding 生成富文本卡片）。"""
    sender = get_alert_sender()
    return await sender.send(title, message, severity, url, finding=finding)


async def alert_findings(findings: List[Dict], min_severity: str = "high") -> int:
    """P4-5: 扫描结束后按严重程度发送卡片告警。

    Args:
        findings: 漏洞列表。
        min_severity: 触发阈值（critical / high / medium / low）。

    Returns:
        成功发送的告警条数。
    """
    if not findings:
        return 0
    order = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0}
    threshold = order.get(str(min_severity).lower(), 2)
    sent = 0
    for finding in findings:
        sev = str(finding.get("severity") or "").lower()
        level = order.get(sev, 0)
        if level < threshold:
            continue
        name = (
            finding.get("name")
            or finding.get("vuln_type")
            or finding.get("type")
            or "漏洞"
        )
        is_critical = sev == "critical"
        ok = await send_alert(
            title=f"[{sev.upper()}] {name}",
            message=(
                finding.get("description")
                or finding.get("evidence")
                or "扫描发现漏洞，请查看报告"
            ),
            severity="critical" if is_critical else "warning",
            url=finding.get("url", ""),
            finding=finding,
            **({"bypass_rate_limit": True} if is_critical else {}),
        )
        if ok:
            sent += 1
        if not is_critical:
            await asyncio.sleep(1)  # 非致命级别错开，缓解限频
    if sent:
        logger.info(f"📣 [告警] 已发送 {sent} 条卡片告警")
    return sent


__all__ = ['AlertSender', 'get_alert_sender', 'send_alert', 'alert_findings']
