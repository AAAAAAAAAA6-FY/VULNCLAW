# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/browser_ai_agent.py
"""
AI 驱动的浏览器交互代理 - 最终稳定版 v4.0
修复：
1. 硬编码路径改为临时目录（跨平台兼容）
2. explore 方法增加 try...finally 防止僵尸进程
3. 所有路径使用 tempfile.gettempdir()
"""
from vulnclaw.ai.core import get_llm_client
from vulnclaw.core.settings import settings
from vulnclaw.core.logger import logger
import os
import json
import asyncio
import re
import tempfile
from typing import Dict, List, Optional

os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"


try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    logger.warning("⚠️ Playwright 未安装，浏览器代理不可用。请运行: pip install playwright && playwright install chromium")


def _get_default_proxy() -> str:
    return os.getenv("BURP_PROXY", "") or settings.proxy or ""


def _get_max_actions() -> int:
    return int(os.getenv("BROWSER_MAX_ACTIONS", "20"))


def _get_timeout() -> int:
    return int(os.getenv("BROWSER_TIMEOUT", "60000"))


def _get_profile_dir(profile_name: str = "chrome_profile_a") -> str:
    """获取跨平台兼容的配置文件目录"""
    profile_dir = os.path.join(tempfile.gettempdir(), f"pentest_{profile_name}")
    os.makedirs(profile_dir, exist_ok=True)
    return profile_dir


class BrowserAIAgent:
    def __init__(self, headless: bool = None, proxy: str = None):
        self.headless = headless if headless is not None else getattr(settings, 'browser_headless', True)
        self.proxy = proxy or _get_default_proxy()
        self.user_data_dir_a = _get_profile_dir("chrome_profile_a")
        self.user_data_dir_b = _get_profile_dir("chrome_profile_b")
        self.user_data_dir = self.user_data_dir_a

        self.client = get_llm_client()
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.playwright = None
        self.captured_requests: List[Dict] = []
        self.console_logs: List[Dict] = []
        self.max_actions = _get_max_actions()
        self.actions_taken = 0
        self._started = False
        self._use_profile_b = False
        self._clicked_selectors: set = set()
        self._consecutive_failures = 0

        logger.info(f"🌐 浏览器代理初始化: headless={self.headless}, proxy={self.proxy}, profile_a={self.user_data_dir_a}")
        logger.info(f"   🔄 最大操作步数: {self.max_actions}, 页面超时: {_get_timeout()}ms")

    async def start(self, use_profile_b: bool = False):
        if self._started:
            return
        if not HAS_PLAYWRIGHT:
            raise RuntimeError("Playwright 未安装")
        if use_profile_b and self.user_data_dir_b:
            self.user_data_dir = self.user_data_dir_b
        else:
            self.user_data_dir = self.user_data_dir_a

        self.playwright = await async_playwright().start()
        if self.user_data_dir:
            logger.info(f"   🔥 使用持久化 Profile: {self.user_data_dir}")
            self.context = await self.playwright.chromium.launch_persistent_context(
                user_data_dir=self.user_data_dir,
                headless=self.headless,
                proxy={"server": self.proxy} if self.proxy else None,
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            self.browser = self.context.browser
            self.page = self.context.pages[0] if self.context.pages else await self.context.new_page()
        else:
            logger.warning("⚠️ 未配置 Profile，使用临时浏览器")
            self.browser = await self.playwright.chromium.launch(
                headless=self.headless,
                proxy={"server": self.proxy} if self.proxy else None
            )
            self.context = await self.browser.new_context()
            self.page = await self.context.new_page()

        await self.page.route("**/*", self._capture_request)
        self.page.on("console", self._capture_console)
        self._started = True
        logger.info("🌐 浏览器代理已启动")

    async def stop(self):
        if not self._started:
            return
        try:
            await asyncio.wait_for(self._stop_internal(), timeout=10)
        except asyncio.TimeoutError:
            logger.warning("⚠️ 浏览器关闭超时，强制清理")
        finally:
            self._started = False

    async def _stop_internal(self):
        if not self._started:
            return
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            self._started = False
            logger.info("🌐 浏览器代理已停止")
        except Exception as e:
            logger.warning(f"浏览器关闭失败: {e}")

    async def _capture_request(self, route):
        try:
            req = route.request
            if req:
                self.captured_requests.append({
                    "url": req.url,
                    "method": req.method,
                    "headers": req.headers,
                    "post_data": req.post_data
                })
                if len(self.captured_requests) > 500:
                    self.captured_requests = self.captured_requests[-500:]
        except BaseException:
            logger.debug("suppressed exception (core audit)")
        await route.continue_()

    def _capture_console(self, msg):
        self.console_logs.append({"type": msg.type, "text": msg.text})

    async def analyze_page(self) -> Dict:
        try:
            await self.page.content()
            elements_raw = await self.page.evaluate("""
                () => {
                    const items = [];
                    document.querySelectorAll('a[href], button, input, [role="button"], [onclick], .btn, [class*="button"]')
                        .forEach(el => {
                            if (el.offsetParent !== null) {
                                let selector = '';
                                if (el.id) {
                                    selector = '#' + CSS.escape(el.id);
                                } else if (el.getAttribute('data-testid')) {
                                    selector = '[data-testid="' + CSS.escape(el.getAttribute('data-testid')) + '"]';
                                } else if (el.className && typeof el.className === 'string') {
                                    const classes = el.className.split(' ').filter(c => c && !c.startsWith('_'));
                                    if (classes.length) selector = '.' + CSS.escape(classes[0]);
                                }
                                if (!selector) selector = el.tagName.toLowerCase();
                                items.push({
                                    tag: el.tagName.toLowerCase(),
                                    text: (el.innerText || el.value || '').trim().slice(0, 30),
                                    selector: selector,
                                    href: el.href || ''
                                });
                            }
                        });
                    return items.slice(0, 50);
                }
            """)
            elements = [el for el in elements_raw if el.get('selector') not in self._clicked_selectors]
            apis = [req['url'] for req in self.captured_requests[-30:] if '/api/' in req['url'] or '/graphql' in req['url']]

            return {
                "url": self.page.url,
                "title": await self.page.title(),
                "elements": elements[:30],
                "new_apis": list(set(apis)),
                "console_errors": [log for log in self.console_logs if log['type'] in ('error', 'warning')]
            }
        except Exception as e:
            logger.warning(f"页面分析失败: {e}")
            return {"url": self.page.url, "elements": [], "new_apis": []}

    async def decide_action(self, analysis: Dict, history: List[str]) -> Dict:
        prompt = f"""
你是渗透测试专家，正在操作浏览器。当前页面有 {len(analysis.get('elements', []))} 个可交互元素。
URL: {analysis.get('url', '')}
新发现的 API: {analysis.get('new_apis', [])}
已执行操作: {history[-5:] if history else '无'}

请选择下一步操作，只输出 JSON 格式：
{{"action": "click", "selector": "CSS选择器", "reasoning": "简短说明"}}
或 {{"action": "finish", "reasoning": "完成探索"}}
"""
        try:
            result = await self.client.ask(prompt, system="只输出JSON", temperature=0.1, max_tokens=200)
            match = re.search(r'\{.*\}', result, re.DOTALL)
            if match:
                return json.loads(match.group())
            return {"action": "finish", "reasoning": "无法解析"}
        except BaseException:
            return {"action": "finish", "reasoning": "AI决策失败"}

    async def execute_action(self, action: Dict) -> bool:
        act = action.get('action')
        if act == 'finish':
            logger.info(f"✅ AI 完成探索: {action.get('reasoning', '')}")
            return False

        if act == 'click':
            selector = action.get('selector', '')
            if not selector:
                buttons = await self.page.query_selector_all('button')
                if buttons:
                    await buttons[0].click()
                    self._clicked_selectors.add('button')
                    return True
                return False

            logger.info(f"🖱️ AI 点击: {selector} ({action.get('reasoning', '')})")
            try:
                await self.page.click(selector, timeout=5000)
            except Exception as e:
                logger.warning(f"常规点击失败，尝试按文本查找: {e}")
                reasoning = action.get('reasoning', '')
                keywords = re.findall(r'[\u4e00-\u9fa5]+', reasoning)
                if keywords:
                    for kw in keywords:
                        els = await self.page.query_selector_all(f'text="{kw}"')
                        if els:
                            await els[0].click()
                            self._clicked_selectors.add(selector)
                            return True
                try:
                    await self.page.evaluate(f"document.querySelector('{selector}')?.click()")
                except BaseException:
                    logger.warning("JS点击也失败，跳过")
                    self._consecutive_failures += 1
                    if self._consecutive_failures >= 3:
                        logger.warning("连续失败3次，跳过当前元素")
                        self._consecutive_failures = 0
                        return True
                    return False
            self._clicked_selectors.add(selector)
            self._consecutive_failures = 0
            return True

        logger.warning(f"未知操作: {act}")
        return False

    async def explore(self, start_url: str, use_profile_b: bool = False) -> Dict:
        """修复：增加 try...finally 防止浏览器僵尸进程"""
        logger.info(f"🚀 AI 开始探索: {start_url}")

        try:
            if not self._started:
                await self.start(use_profile_b=use_profile_b)

            try:
                await self.page.goto(start_url, wait_until="networkidle", timeout=_get_timeout())
            except BaseException:
                await self.page.goto(start_url, timeout=_get_timeout())

            await asyncio.sleep(3)
            history, all_apis = [], []
            self.actions_taken = 0
            self._clicked_selectors.clear()
            self._consecutive_failures = 0

            while self.actions_taken < self.max_actions:
                analysis = await self.analyze_page()
                all_apis.extend(analysis.get('new_apis', []))
                if not analysis.get('elements'):
                    await self.page.evaluate("window.scrollBy(0, 300)")
                    await asyncio.sleep(1)

                action = await self.decide_action(analysis, history)
                if action.get('action') == 'finish':
                    break
                if await self.execute_action(action):
                    self.actions_taken += 1
                    history.append(f"{action.get('action')}: {action.get('reasoning', '')[:30]}")
                    await asyncio.sleep(2)

            return {
                "total_actions": self.actions_taken,
                "all_apis": list(set(all_apis)),
                "history": history
            }

        finally:
            # ===== 修复：确保浏览器被关闭，防止僵尸进程 =====
            await self.stop()

    async def _get_current_forms(self):
        try:
            return await self.page.evaluate("""
                () => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.querySelectorAll('input')).map(i => ({name: i.name, type: i.type}))
                }))
            """)
        except BaseException:
            return []


async def create_browser_agent(headless: bool = False, proxy: str = None):
    agent = BrowserAIAgent(headless=headless, proxy=proxy)
    await agent.start()
    return agent


__all__ = ['BrowserAIAgent', 'create_browser_agent', 'HAS_PLAYWRIGHT']
