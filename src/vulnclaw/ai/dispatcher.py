# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/dispatcher.py
"""
AI Agent 调度器 - ReAct循环版（路径A核心）- 优化版
包含：Plan-and-Execute 计划模式
"""
import json
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.context import get_scan_context
from vulnclaw.core.utils import async_get
from vulnclaw.core.session_manager import get_session_manager
from vulnclaw.core.settings import settings

# ===== 修复：所有合并后的 AI 模块统一从 ai.core 导入 =====
from vulnclaw.ai.core import (
    get_llm_client,
    get_memory,          # memory 已合并到 core.py
    get_rule_engine,     # rule_engine 已合并到 core.py
)
from vulnclaw.ai.tools import TOOL_REGISTRY, execute_tool


class ReActAgent:
    """推理-行动-观察循环 Agent - 计划执行版"""

    def __init__(self, target: str, session, max_iterations: int = None):
        self.target = target
        self.session = session

        # 从 .env 读取硬编码配置
        self.max_iterations = max_iterations or getattr(settings, 'agent_max_iterations', 15)
        self._max_failures_per_param = getattr(settings, 'agent_max_failures_per_param', 3)
        self._consecutive_failures_threshold = getattr(settings, 'agent_consecutive_failures_threshold', 6)

        self.llm = get_llm_client()
        self.memory = get_memory()           # 从 ai.core 获取
        self.context = get_scan_context()
        self.rule_engine = get_rule_engine() # 从 ai.core 获取
        self.tools = TOOL_REGISTRY

        self.history: List[Dict] = []
        self.findings: List[Dict] = []
        self.iteration = 0
        self._start_time = time.time()
        self.short_term_memory: List[Dict] = []
        self.short_term_memory_limit = 25
        self.tool_success_rates: Dict[str, float] = {}
        self.tool_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"success": 0, "failure": 0})
        self._shared_knowledge_key = "agent_shared_knowledge"

        self._recon_observation: Dict = {}

        self._consecutive_failures: int = 0
        self._failed_params: set = set()
        self._param_fail_count: Dict[str, int] = {}

        # 计划模式状态
        self.current_plan: List[str] = []
        self.plan_step: int = 0
        self.plan_fail_count: int = 0

        # 场景缓存
        self._scene_cache: Dict[str, Dict] = {}
        self._cache_hit_count: int = 0
        self._cache_miss_count: int = 0
        self._ensure_shared_knowledge()

    def _ensure_shared_knowledge(self) -> Dict:
        shared = getattr(self.context, self._shared_knowledge_key, None)
        if not isinstance(shared, dict):
            shared = {"tool_stats": {}, "experiences": [], "targets": {}}
            self.context.__dict__[self._shared_knowledge_key] = shared
        shared.setdefault("tool_stats", {})
        shared.setdefault("experiences", [])
        shared.setdefault("targets", {})
        self.context.__dict__[self._shared_knowledge_key] = shared
        return shared

    def _record_tool_outcome(self, tool_name: str, success: bool, payload: str = "", detail: str = ""):
        if not tool_name:
            return
        entry = {
            "tool": tool_name,
            "success": bool(success),
            "payload": str(payload)[:200],
            "detail": str(detail)[:200],
            "timestamp": time.time(),
            "target": self.target,
        }
        self.short_term_memory.append(entry)
        if len(self.short_term_memory) > self.short_term_memory_limit:
            self.short_term_memory = self.short_term_memory[-self.short_term_memory_limit:]

        stats = self.tool_stats[tool_name]
        if success:
            stats["success"] += 1
        else:
            stats["failure"] += 1

        shared = self._ensure_shared_knowledge()
        shared_tool_stats = shared["tool_stats"].setdefault(tool_name, {"success": 0, "failure": 0})
        if success:
            shared_tool_stats["success"] += 1
        else:
            shared_tool_stats["failure"] += 1

        self.tool_success_rates[tool_name] = self._estimate_tool_success(tool_name)
        logger.info(
            f"🧠 [ToolFeedback] tool={tool_name} success={success} score={self.tool_success_rates.get(tool_name, 0.5):.2f} "
            f"detail={detail[:80] or 'n/a'}"
        )

    def _estimate_tool_success(self, tool_name: str) -> float:
        if tool_name in self.tool_success_rates and self.tool_success_rates[tool_name] > 0:
            base = self.tool_success_rates[tool_name]
        else:
            base = 0.5
        local_stats = self.tool_stats.get(tool_name, {"success": 0, "failure": 0})
        local_success = local_stats.get("success", 0)
        local_failure = local_stats.get("failure", 0)
        total = local_success + local_failure
        if total:
            return (local_success / total) * 0.7 + base * 0.3

        shared = self._ensure_shared_knowledge().get("tool_stats", {})
        shared_stats = shared.get(tool_name, {"success": 0, "failure": 0})
        shared_success = shared_stats.get("success", 0)
        shared_failure = shared_stats.get("failure", 0)
        shared_total = shared_success + shared_failure
        if shared_total:
            return (shared_success / shared_total)
        return base

    def _rank_tools(self, tool_names: List[str]) -> List[str]:
        ranked = sorted(tool_names, key=lambda name: (-self._estimate_tool_success(name), name))
        return ranked

    def _share_knowledge(self, other_agent: Optional["ReActAgent"] = None) -> Dict:
        shared = self._ensure_shared_knowledge()
        seen = set()
        for entry in shared.get("experiences", []):
            if isinstance(entry, dict):
                seen.add((entry.get("target"), entry.get("tool"), entry.get("detail")))

        for item in self.short_term_memory:
            key = (item.get("target"), item.get("tool"), item.get("detail"))
            if key not in seen:
                shared["experiences"].append({
                    "target": item.get("target"),
                    "tool": item.get("tool"),
                    "success": item.get("success"),
                    "payload": item.get("payload"),
                    "detail": item.get("detail"),
                    "timestamp": item.get("timestamp"),
                })
                seen.add(key)

        if other_agent is not None:
            for item in getattr(other_agent, "short_term_memory", []):
                key = (item.get("target"), item.get("tool"), item.get("detail"))
                if key not in seen:
                    shared["experiences"].append({
                        "target": item.get("target"),
                        "tool": item.get("tool"),
                        "success": item.get("success"),
                        "payload": item.get("payload"),
                        "detail": item.get("detail"),
                        "timestamp": item.get("timestamp"),
                    })
                    seen.add(key)

        shared["targets"][self.target] = time.time()
        if other_agent is not None:
            shared["targets"][getattr(other_agent, "target", "unknown")] = time.time()

        self.context.__dict__[self._shared_knowledge_key] = shared
        logger.info(
            f"🔄 [KnowledgeSync] shared={len(shared.get('experiences', []))} items, "
            f"tools={sorted(shared.get('tool_stats', {}).keys())[:10]}"
        )
        return shared

    def _adjust_plan_after_feedback(self, action: Dict, observation: Dict):
        tool_name = action.get("tool")
        if not tool_name:
            return
        if observation.get("type") == "error":
            self.plan_fail_count += 1
            if self.current_plan and tool_name in self.current_plan:
                self.current_plan = [t for t in self.current_plan if t != tool_name]
                logger.info(f"🛠️ [PlanFeedback] tool={tool_name} failed; removing it from current plan")
        elif observation.get("type") in ("finding", "findings"):
            self.plan_fail_count = max(0, self.plan_fail_count - 1)
            logger.info(f"🎯 [PlanFeedback] tool={tool_name} produced a valid finding; reinforcing plan")

    async def run(self) -> Dict:
        logger.info(f"🤖 ReAct Agent 启动，目标: {self.target}")

        observation = await self._recon()
        self.history.append({"phase": "recon", "observation": observation})
        self._recon_observation = observation

        for self.iteration in range(self.max_iterations):
            logger.info(f"🔄 ReAct 第 {self.iteration + 1}/{self.max_iterations} 轮")

            thought = await self._think(observation)
            self.history.append({"iteration": self.iteration, "thought": thought})

            action = await self._decide_action(thought)
            self.history.append({"iteration": self.iteration, "action": action})

            result = await self._execute(action)
            self.history.append({"iteration": self.iteration, "result": result})

            is_valid = await self._verify_action(action, result)
            self.history.append({"iteration": self.iteration, "valid": is_valid})

            observation = await self._observe(result)
            self.history.append({"iteration": self.iteration, "observation": observation})

            tool_name = action.get("tool") if isinstance(action, dict) else None
            payload = json.dumps(action.get("params", {}), ensure_ascii=False) if isinstance(action, dict) else str(action)
            self._record_tool_outcome(
                tool_name,
                bool(await self._verify_action(action, result)),
                payload=payload,
                detail=observation.get("message", "")
            )
            self._adjust_plan_after_feedback(action, observation)
            self._share_knowledge()
            await self._update_memory(action, result, observation)

            if await self._should_stop(observation):
                logger.info(f"✅ Agent 在第 {self.iteration + 1} 轮决定停止")
                break

        return await self._generate_report()

    async def _recon(self) -> Dict:
        logger.info("🔍 侦察阶段...")

        try:
            resp = await async_get(self.target, session=self.session, timeout=10)
            status, text, headers = resp
            self.context.tech_stack = self._detect_tech_stack(headers, text)
        except Exception as e:
            logger.warning(f"侦察请求失败: {e}")
            status = 0
            text = ""
            headers = {}

        params = self._extract_params(self.target, text)
        self.context.total_urls = 1

        session_mgr = get_session_manager()
        has_auth = False
        if session_mgr:
            cookies = session_mgr.get_cookies_for_url(self.target)
            tokens = session_mgr.get_tokens('default')
            if cookies or tokens:
                has_auth = True

        prioritized_params = self._prioritize_params(params)

        observation = {
            "target": self.target,
            "status": status,
            "tech_stack": self.context.tech_stack,
            "params": prioritized_params,
            "has_auth": has_auth,
            "summary": f"目标 {self.target}，状态码 {status}，技术栈 {self.context.tech_stack}，发现 {len(params)} 个参数"
        }

        logger.info(f"📋 侦察完成: {observation['summary']}")
        return observation

    def _prioritize_params(self, params: List[str]) -> List[Dict]:
        priority_keywords = {
            'high': ['id', 'user', 'uid', 'file', 'path', 'url', 'redirect', 'callback', 'token', 'auth'],
            'medium': ['page', 'sort', 'order', 'filter', 'search', 'q', 's', 'query', 'name', 'email'],
            'low': ['_', 'timestamp', 'nonce', 'version', 'format', 'callback', 'v', 'ver', 'ts']
        }

        result = []
        for p in params:
            p_lower = p.lower()
            priority = 'low'
            for level, keywords in priority_keywords.items():
                if any(kw in p_lower for kw in keywords):
                    priority = level
                    break
            result.append({"param": p, "priority": priority})

        result.sort(key=lambda x: 0 if x['priority'] == 'high' else 1 if x['priority'] == 'medium' else 2)
        return result

    def _detect_tech_stack(self, headers: Dict, text: str) -> List[str]:
        techs = []
        server = headers.get("Server", "")
        x_powered = headers.get("X-Powered-By", "")
        if server:
            techs.append(server)
        if x_powered:
            techs.append(x_powered)

        keywords = {
            "wordpress": "WordPress", "laravel": "Laravel",
            "django": "Django", "react": "React",
            "vue": "Vue", "angular": "Angular",
            "spring": "Spring", "jquery": "jQuery",
            "express": "Express", "next.js": "Next.js",
            "php": "PHP", "java": "Java", "python": "Python",
            "ruby": "Ruby", "node.js": "Node.js", "go": "Go"
        }
        text_lower = text.lower()
        for kw, name in keywords.items():
            if kw in text_lower:
                techs.append(name)

        return list(set(techs))[:10]

    def _extract_params(self, url: str, text: str) -> List[str]:
        params = []
        if '?' in url:
            for part in url.split('?')[1].split('&'):
                if '=' in part:
                    params.append(part.split('=')[0])

        if text:
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', text, re.I)
            params.extend(inputs)

        return list(set(params))[:20]

    async def _think(self, observation: Dict) -> str:
        params_info = observation.get('params', [])
        high_priority = [p['param'] for p in params_info if p.get('priority') == 'high'][:5]
        medium_priority = [p['param'] for p in params_info if p.get('priority') == 'medium'][:5]

        # 修复：从只取前2个参数改为使用排序后的所有参数名，防止漏报危险参数
        all_param_names = [p['param'] for p in params_info]
        param_signature = '_'.join(sorted(all_param_names))[:100]

        tech_stack = observation.get('tech_stack', [])
        main_tech = frozenset(tech_stack[:3])
        # 修复：使用包含全参数的签名
        cache_key = f"{self.target}_{hash(main_tech)}_{param_signature}"

        if cache_key in self._scene_cache:
            self._cache_hit_count += 1
            logger.info(f"📖 场景缓存命中 (第 {self._cache_hit_count} 次)")
            return self._scene_cache[cache_key]

        prompt = f"""
你是渗透测试AI Agent。请分析当前状态，规划下一步行动。

【当前目标】{self.target}

【当前观察】
- 状态码: {observation.get('status', '未知')}
- 技术栈: {', '.join(observation.get('tech_stack', []))}
- 所有参数: {', '.join(all_param_names) if all_param_names else '无'}
- 高价值参数: {', '.join(high_priority) if high_priority else '无'}
- 中价值参数: {', '.join(medium_priority) if medium_priority else '无'}
- 已发现漏洞: {len(self.findings)} 个
- 已执行轮次: {self.iteration + 1}/{self.max_iterations}
- 已失败参数: {', '.join(self._failed_params) if self._failed_params else '无'}

【可用工具（共{len(self.tools)}个）】
{self._format_tools()}

请思考：
1. 当前最有价值的攻击面是什么？
2. 给出下一步决策。
"""
        try:
            # 强制开启 wrap_data 防止提示词注入
            result = await self.llm.ask(
                prompt,
                system="你是渗透测试AI Agent，擅长推理决策。",
                temperature=0.3,
                wrap_data=True
            )
            self._scene_cache[cache_key] = result.strip()
            self._cache_miss_count += 1
            return result.strip()
        except Exception as e:
            logger.warning(f"思考失败: {e}")
            return "继续使用常见漏洞检测工具探索目标。"

    async def _decide_action(self, thought: str) -> Dict:
        # 第一步：优先执行当前计划，但按历史成功率重新排序
        if self.current_plan and self.plan_step < len(self.current_plan) and self.plan_fail_count < 2:
            ranked_plan = self._rank_tools([t for t in self.current_plan if t in self.tools])
            if ranked_plan:
                next_tool = ranked_plan[0]
                self.plan_step += 1

                real_params = self._recon_observation.get('params', [])
                fallback_param = 'id'
                if real_params:
                    if isinstance(real_params[0], dict):
                        fallback_param = real_params[0].get('param', 'id')
                    else:
                        fallback_param = real_params[0]

                logger.info(
                    f"📋 [执行计划] tool={next_tool} success_rate={self._estimate_tool_success(next_tool):.2f} "
                    f"step={self.plan_step}/{len(self.current_plan)}"
                )
                return {
                    "tool": next_tool,
                    "params": {"url": self.target, "param": fallback_param},
                    "reason": f"执行多步计划中的 {next_tool}（按成功率优先）"
                }
            self.current_plan = []

        # 第二步：请求 AI 生成新计划，优先使用高成功率工具
        ordered_tool_names = self._rank_tools(list(self.tools.keys())[:20])
        tools_desc = []
        for name in ordered_tool_names:
            tool = self.tools[name]
            params = getattr(tool, "parameters", [])
            param_str = ", ".join([p.get("name", "") for p in params])
            score = self._estimate_tool_success(name)
            tools_desc.append(f"- {name}(score={score:.2f})({param_str}): {tool.description[:60]}")

        prompt = f"""
你是渗透测试AI Agent。根据以下思考，决定下一步行动。

【思考】
{thought}

【可用工具】
{chr(10).join(tools_desc)}

【当前状态】
- 已发现漏洞: {len(self.findings)}
- 已执行操作数: {len(self.history)}
- 剩余轮次: {self.max_iterations - self.iteration}
- 已失败参数: {', '.join(self._failed_params) if self._failed_params else '无'}

请制定一个不超过5步的进攻计划（plan），并选择当前执行的第一步（current_action）。
输出JSON格式：
{{
    "plan": ["sqli", "idor", "xss"],
    "current_action": "sqli",
    "params": {{"param": "id"}},
    "reason": "为什么要选择这个工具"
}}

如果认为已经完成测试，输出：
{{
    "plan": [],
    "current_action": "finish",
    "reason": "完成原因"
}}
"""

        for attempt in range(2):
            try:
                # 强制开启 wrap_data 防止提示词注入
                result = await self.llm.ask(
                    prompt,
                    system="你是渗透测试AI Agent，只输出JSON。",
                    temperature=0.2,
                    wrap_data=True
                )
                match = re.search(r'\{.*\}', result, re.DOTALL)
                if match:
                    action = json.loads(match.group())

                    # 第三步：解析并保存计划
                    if action.get("plan") and isinstance(action["plan"], list):
                        # 过滤掉工具库中不存在的
                        self.current_plan = [t for t in action["plan"] if t in self.tools][:5]
                        self.plan_step = 0
                        self.plan_fail_count = 0
                        logger.info(f"🗺️ 生成新计划: {self.current_plan}")

                    # 获取当前动作
                    action["tool"] = action.get("current_action", action.get("tool"))
                    params = action.get("params", {})
                    param = params.get("param", "")
                    if param in self._failed_params:
                        logger.info(f"⏭️ 参数 {param} 已在失败列表，自动跳过")
                        return {
                            "tool": "finish",
                            "reason": f"参数 {param} 已失败多次，跳过"
                        }
                    return action

                if attempt == 0:
                    logger.warning(f"⚠️ JSON解析失败，重试 ({attempt + 1}/2)...")
                    prompt += "\n请确保输出是有效的JSON格式。"
                    continue

            except Exception as e:
                logger.warning(f"决策失败 (尝试 {attempt + 1}/2): {e}")
                if attempt == 0:
                    continue

        # 回退逻辑（原有）
        logger.warning("⚠️ 决策解析失败，使用智能降级策略")
        real_params = self._recon_observation.get('params', [])
        tech_stack = self._recon_observation.get('tech_stack', [])
        tech_lower = ' '.join(tech_stack).lower()

        if real_params:
            if isinstance(real_params[0], dict):
                fallback_param = real_params[0].get('param', 'id')
            else:
                fallback_param = real_params[0]

            candidate_tools = []
            if any(t in tech_lower for t in ['java', 'spring', 'jsp', 'tomcat', 'jetty']):
                candidate_tools = ['sqli', 'xxe', 'el_injection', 'ssti', 'xss']
            elif 'php' in tech_lower:
                candidate_tools = ['sqli', 'lfi', 'ssti', 'xss', 'cmdi']
            elif any(t in tech_lower for t in ['python', 'django', 'flask']):
                candidate_tools = ['ssti', 'sqli', 'xss', 'ssrf']
            elif any(t in tech_lower for t in ['node', 'express', 'javascript']):
                candidate_tools = ['nosql', 'xss', 'sqli', 'ssti']
            elif any(t in tech_lower for t in ['api', 'graphql', 'json', 'rest']):
                candidate_tools = ['graphql', 'sqli', 'nosql', 'xss']
            elif any(t in tech_lower for t in ['asp', 'net', 'c#']):
                candidate_tools = ['sqli', 'xss', 'lfi', 'cmdi']
            else:
                candidate_tools = ['sqli', 'xss', 'ssti', 'lfi', 'cmdi', 'nosql', 'ssrf', 'xxe']

            param_lower = fallback_param.lower()
            if 'id' in param_lower or 'user' in param_lower or 'uid' in param_lower:
                candidate_tools = ['sqli', 'idor', 'xss'] + [t for t in candidate_tools if t not in ['sqli', 'idor', 'xss']]
            elif 'file' in param_lower or 'path' in param_lower:
                candidate_tools = ['lfi', 'sqli', 'xss'] + [t for t in candidate_tools if t not in ['lfi', 'sqli', 'xss']]
            elif 'url' in param_lower or 'redirect' in param_lower:
                candidate_tools = ['ssrf', 'open_redirect', 'xss'] + [t for t in candidate_tools if t not in ['ssrf', 'open_redirect', 'xss']]

            available_tools = self._rank_tools([t for t in candidate_tools if t in self.tools])

            if available_tools:
                selected_tool = available_tools[0]
                logger.info(
                    f"🔧 降级使用: {selected_tool} (success_rate={self._estimate_tool_success(selected_tool):.2f}, "
                    f"tech_stack={tech_stack}, param={fallback_param})"
                )
                return {
                    "tool": selected_tool,
                    "params": {"url": self.target, "param": fallback_param},
                    "reason": f"AI决策解析失败，按成功率优先降级使用 {selected_tool}"
                }
            else:
                logger.warning("⚠️ 无可用工具，降级为信息泄露检测")
                return {
                    "tool": "info_leak",
                    "params": {"url": self.target},
                    "reason": "AI决策解析失败，且无可用工具，降级为信息泄露检测"
                }
        else:
            logger.warning("⚠️ 无可用参数，降级为信息泄露检测")
            return {
                "tool": "info_leak",
                "params": {"url": self.target},
                "reason": "AI决策解析失败，且无可用参数，降级为信息泄露检测"
            }

    async def _execute(self, action: Dict) -> Any:
        tool_name = action.get("tool")
        params = action.get("params", {})
        reason = action.get("reason", "")

        if tool_name == "finish":
            logger.info(f"🏁 Agent决定结束: {reason}")
            return {"status": "finished", "reason": reason}

        if tool_name not in self.tools:
            logger.warning(f"⚠️ 未知工具: {tool_name}")
            return {"error": f"未知工具: {tool_name}"}

        if not self.rule_engine.can_call_tool(tool_name):
            logger.warning(f"⛔ 工具 {tool_name} 调用次数已达上限")
            return {"error": f"工具 {tool_name} 调用次数已达上限"}

        if "url" not in params or not params["url"]:
            params["url"] = self.target

        param = params.get("param", "")
        if param and param in self._failed_params:
            logger.info(f"⏭️ 跳过参数 {param}（已失败 {self._param_fail_count.get(param, 0)} 次）")
            return {"error": f"参数 {param} 已失败多次，跳过"}

        logger.info(f"🔧 执行: {tool_name} {params} - {reason}")

        try:
            result = await execute_tool(tool_name, **params)
            self.rule_engine.record_tool_call(tool_name, params, result)

            if result and isinstance(result, dict):
                if result.get("error") or not result.get("type"):
                    self._consecutive_failures += 1
                    if param:
                        self._param_fail_count[param] = self._param_fail_count.get(param, 0) + 1
                        if self._param_fail_count[param] >= self._max_failures_per_param:
                            self._failed_params.add(param)
                            logger.info(f"⛔ 参数 {param} 连续失败 {self._max_failures_per_param} 次，加入跳过列表")
                    if self._consecutive_failures >= self._consecutive_failures_threshold:
                        logger.info(f"⏹️ 连续 {self._consecutive_failures} 轮无发现，考虑切换攻击面")
                else:
                    self._consecutive_failures = 0
                    if param and param in self._param_fail_count:
                        self._param_fail_count[param] = max(0, self._param_fail_count[param] - 1)

            return result
        except Exception as e:
            logger.error(f"❌ 工具执行失败: {e}")
            return {"error": str(e)}

    async def _verify_action(self, action: Dict, result: Any) -> bool:
        if not result or isinstance(result, Exception):
            return False

        if isinstance(result, dict):
            if result.get("type") and "漏洞" in result.get("type", ""):
                evidence = result.get("evidence", "")
                strong_indicators = [
                    'error', 'syntax', 'root:', 'uid=', 'admin',
                    'true', 'false', 'SQL', 'mysql', 'postgres',
                    'alert', 'script', 'onerror', 'document.cookie'
                ]
                if any(ind in evidence.lower() for ind in strong_indicators):
                    logger.info(f"✅ 行动有效: {result.get('type')} (证据较强)")
                    return True
                else:
                    result["confidence"] = "低"
                    logger.info(f"⚠️ 证据较弱，标记为低置信度: {result.get('type')}")
                    return True

            if result.get("status") == "success" or result.get("message"):
                logger.debug("✅ 行动完成，无发现")
                return True

            if result.get("error"):
                error_msg = result.get("error", "").lower()
                if any(kw in error_msg for kw in ['timeout', 'connection', 'network', 'refused']):
                    logger.debug("⚠️ 网络错误，不计入失败计数")
                    return True
                logger.debug(f"❌ 行动失败: {result.get('error')}")
                return False

        if isinstance(result, list) and result:
            return True

        return True

    async def _observe(self, result: Any) -> Dict:
        if isinstance(result, dict):
            if result.get("status") == "finished":
                return {"type": "finish", "message": result.get("reason", "完成")}

            if "error" in result:
                return {"type": "error", "message": result["error"], "data": result}

            if "type" in result and ("漏洞" in result.get("type", "") or "注入" in result.get("type", "")):
                self.findings.append(result)
                return {"type": "finding", "message": f"发现 {result.get('type')}", "data": result}

            if "vulnerabilities" in result:
                vulns = result.get("vulnerabilities", [])
                if vulns:
                    self.findings.extend(vulns)
                    return {"type": "findings", "message": f"发现 {len(vulns)} 个漏洞", "data": vulns}

            for key in ["sqli", "xss", "lfi", "cmdi", "ssti", "ssrf", "xxe", "idor", "jwt"]:
                if key in result and result[key]:
                    self.findings.extend(result[key])
                    return {"type": "findings", "message": f"在 {key} 检测中发现漏洞", "data": result[key]}

            return {"type": "info", "message": "工具执行完成，无异常发现", "data": result}

        if isinstance(result, list) and result:
            self.findings.extend(result)
            return {"type": "findings", "message": f"发现 {len(result)} 个漏洞", "data": result}

        return {"type": "info", "message": "工具执行完成，无异常发现", "data": result}

    async def _update_memory(self, action: Dict, result: Any, observation: Dict):
        if observation.get("type") in ("finding", "findings"):
            findings = observation.get("data", [])
            if isinstance(findings, dict):
                findings = [findings]
            for f in findings:
                if isinstance(f, dict):
                    await self.memory.add_experience(
                        target=self.target,
                        vuln_type=f.get("type", "未知"),
                        payload=f.get("payload", ""),
                        success=True,
                        evidence=f.get("evidence", ""),
                        error_msg=""
                    )
                    tool_name = action.get("tool", "unknown")
                    logger.debug(f"📖 记忆已记录: {f.get('type')} (工具: {tool_name})")
        elif observation.get("type") == "error":
            await self.memory.add_experience(
                target=self.target,
                vuln_type="tool_error",
                payload=str(action.get("params", {})),
                success=False,
                evidence="",
                error_msg=observation.get("message", "")
            )

    async def _should_stop(self, observation: Dict) -> bool:
        if observation.get("type") == "finish":
            return True

        recent = self.history[-8:] if len(self.history) >= 8 else self.history
        recent_findings = [
            h for h in recent
            if h.get("observation", {}).get("type") in ("finding", "findings")
        ]
        if len(recent) >= 8 and not recent_findings:
            logger.info("⏹️ 连续3轮无发现，自动停止")
            return True

        if len(self.findings) >= 50:
            logger.info(f"⏹️ 已发现 {len(self.findings)} 个漏洞，达到上限")
            return True

        return False

    async def _generate_report(self) -> Dict:
        elapsed = int(time.time() - self._start_time)

        severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for v in self.findings:
            sev = v.get("severity", "Low")
            if sev in severity_count:
                severity_count[sev] += 1

        report = {
            "target": self.target,
            "scan_time": __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "elapsed_seconds": elapsed,
            "iterations": self.iteration + 1,
            "total_actions": len(self.history),
            "vulnerabilities": self.findings,
            "severity_stats": severity_count,
            "tech_stack": self.context.tech_stack,
            "history": self.history[-10:],
            "cache_hits": self._cache_hit_count,
            "cache_misses": self._cache_miss_count,
            "failed_params": list(self._failed_params),
            "consecutive_failures": self._consecutive_failures,
            "current_plan": self.current_plan
        }

        logger.info("=" * 60)
        logger.info(f"📊 扫描完成！发现 {len(self.findings)} 个漏洞，耗时 {elapsed}s")
        logger.info(f"   缓存命中: {self._cache_hit_count} 次，未命中: {self._cache_miss_count} 次")
        logger.info(f"   失败参数: {', '.join(self._failed_params) if self._failed_params else '无'}")
        logger.info(f"   Critical: {severity_count['Critical']}, High: {severity_count['High']}, "
                    f"Medium: {severity_count['Medium']}, Low: {severity_count['Low']}")
        logger.info("=" * 60)

        return report

    def _format_history(self) -> str:
        if not self.history:
            return "无"
        lines = []
        for h in self.history[-3:]:
            if "action" in h:
                action = h.get("action", {})
                lines.append(f"  - 执行: {action.get('tool', '未知')}")
            elif "observation" in h:
                obs = h.get("observation", {})
                lines.append(f"  - 观察: {obs.get('message', '')[:40]}")
        return "\n".join(lines) if lines else "无"

    def _format_tools(self) -> str:
        names = list(self.tools.keys())
        return ", ".join(names[:15])


class PayloadGenerator:
    """AI驱动的Payload变异生成器（用于WAF绕过）"""

    def __init__(self):
        self.client = get_llm_client()

    async def generate(
        self,
        error_msg: str,
        context: str,
        param_name: str = "",
        waf_type: str = None,
        response_context: str = ""
    ) -> List[str]:
        context_info = f"参数名: {param_name}\n错误信息: {error_msg}"
        if waf_type:
            context_info += f"\nWAF类型: {waf_type}"
        if response_context:
            context_info += f"\nWAF拦截响应片段: {response_context[:300]}"

        prompt = f"""
WAF拦截了以下Payload，请生成3个绕过变体。
{context_info}
原始上下文: {context}
要求:
- 使用大小写混淆、注释插入（/**/）、URL编码、双重编码、换行符（%0a）
- 如果响应片段包含特定WAF特征（如 cf-ray、x-amzn-RequestId），请针对该特征设计绕过
- 只输出JSON数组，例如: ["payload1", "payload2", "payload3"]
"""
        try:
            # 强制开启 wrap_data 防止提示词注入
            result = await self.client.ask(
                prompt,
                system="你是一个WAF绕过专家，只输出JSON数组。",
                temperature=0.4,
                max_tokens=800,
                wrap_data=True
            )
            clean = re.sub(r'```json\s*|\s*```', '', result)
            data = json.loads(clean)
            if isinstance(data, list):
                filtered = []
                for p in data:
                    if isinstance(p, str) and p != context and len(p) > 2:
                        filtered.append(p)
                return filtered[:3] if filtered else [context]
        except Exception as e:
            logger.debug(f"AI Payload生成失败: {e}")

        variants = [context]
        if waf_type:
            if waf_type == "cloudflare":
                variants.append(context.replace(" ", "/**/"))
                variants.append(context.replace(" ", "%0a"))
            elif waf_type == "aws_waf":
                variants.append(context.replace("'", "´"))
                variants.append(context.replace("=", " LIKE "))
            elif waf_type == "modsecurity":
                variants.append(context + "%00")
                variants.append(context.replace(" ", "\t"))
            else:
                variants.append(context.replace(" ", "/*!*/"))
                variants.append(context.upper())
        return list(set(variants))[:3]


_agent = None


def get_agent(target: str, session):
    global _agent
    _agent = ReActAgent(target, session)
    return _agent


__all__ = ['ReActAgent', 'get_agent', 'PayloadGenerator']