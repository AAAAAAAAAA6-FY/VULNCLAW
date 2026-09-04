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
import asyncio
import json
import re
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.context import get_scan_context
from vulnclaw.core.utils import async_get, build_attack_url
from vulnclaw.core.session_manager import get_session_manager
from vulnclaw.core.settings import settings

# ===== 修复：所有合并后的 AI 模块统一从 ai.core 导入 =====
from vulnclaw.ai.core import (
    get_llm_client,
    get_memory,          # memory 已合并到 core.py
    get_rule_engine,     # rule_engine 已合并到 core.py
)
from vulnclaw.ai.tools import TOOL_REGISTRY, execute_tool


# ==================================================================
# A2.1: 角色化子 Agent 配置——窄 prompt + 窄工具集，替代单一大 prompt
# ==================================================================
AGENT_ROLES: Dict[str, Dict[str, object]] = {
    "recon": {
        "system": (
            "你是渗透测试【侦察Agent】。目标是发现攻击面：URL 参数、隐藏端点、技术栈指纹、"
            "API 差异与头部线索。只做信息收集与推断，不做攻击性验证。"
        ),
        "tools": [
            "info_leak", "security_headers", "api_version_diff", "cors",
            "host_header", "crlf", "graphql", "session",
            # A5.2: CLI 侦察工具（本机已注册才可见）
            "httpx", "katana", "subfinder", "gau", "waybackurls", "nmap",
        ],
    },
    "analysis": {
        "system": (
            "你是渗透测试【分析Agent】。基于已知端点与参数，推断最可能存在的漏洞类型，"
            "给出验证优先级并逐个验证。优先高价值参数（id/file/url/callback）。"
        ),
        "tools": [
            "sqli", "xss", "lfi", "cmdi", "ssti", "idor", "ssrf", "xxe", "open_redirect",
        ],
    },
    "exploit": {
        "system": (
            "你是渗透测试【利用Agent】。对高置信候选漏洞构造利用载荷验证实际影响，"
            "禁止破坏性操作（不删数据、不写 shell、不外传数据），只做最小化影响验证。"
        ),
        "tools": [
            "sqli", "cmdi", "ssti", "el_injection", "deserialization",
            "dotnet_deserialization", "nosql", "file_upload", "jwt",
        ],
    },
    "verify": {
        "system": (
            "你是渗透测试【验证Agent】。复核候选漏洞的证据强度，剔除误报（如 WAF 拦截、"
            "通用错误页、时间波动），只保留可稳定复现的确认漏洞。"
        ),
        "tools": [
            "sqli", "xss", "lfi", "cmdi", "race_condition",
            "business_logic", "session", "jwt", "ldap",
        ],
    },
}


class Blackboard:
    """A2.2: 共享黑板——子 Agent 之间通过结构化 state 通信（端点/漏洞/证据），
    而非自然语言全量互传。带轻量 schema 校验（非法字段/类型直接拒绝写入）。
    """

    _SCHEMA = ("endpoints", "vulns", "evidence", "notes")

    def __init__(self) -> None:
        self._state: Dict[str, object] = {"endpoints": [], "vulns": [], "evidence": [], "notes": {}}

    def publish(self, key: str, value) -> bool:
        """写入黑板：列表字段追加、notes 字段合并；schema 不合法则拒绝。"""
        if key not in self._SCHEMA:
            logger.warning(f"[Blackboard] 非法字段 {key}，拒绝写入")
            return False
        if key in ("endpoints", "vulns", "evidence"):
            if not isinstance(value, list):
                logger.warning(f"[Blackboard] {key} 必须是 list，拒绝写入")
                return False
            self._state[key].extend(value)
            return True
        if key == "notes":
            if not isinstance(value, dict):
                logger.warning("[Blackboard] notes 必须是 dict，拒绝写入")
                return False
            self._state["notes"].update(value)
            return True
        return False

    def read(self, key: str = None):
        if key:
            return self._state.get(key)
        return dict(self._state)

    def digest(self, limit: int = 200) -> str:
        """生成注入 prompt 的结构化摘要（非自然语言全量互传）。"""
        eps = [str(e)[:40] for e in self._state["endpoints"][:5]]
        vulns = [
            f"{v.get('type', '')}/{v.get('severity', '')}" if isinstance(v, dict) else str(v)[:30]
            for v in self._state["vulns"][:5]
        ]
        text = (
            f"endpoints={eps}; vulns={vulns}; "
            f"evidence_count={len(self._state['evidence'])}"
        )
        return text[:limit]


class ReActAgent:
    """推理-行动-观察循环 Agent - 计划执行版"""

    def __init__(self, target: str, session, max_iterations: int = None, focus_param: str = "", role: str = "", blackboard=None):
        self.target = target
        self.session = session
        # S1: 聚焦单个参数深挖（V100 主链路回落时传入），空串=全参数模式
        self.focus_param = str(focus_param or "").strip()

        # 从 .env 读取硬编码配置
        self.max_iterations = max_iterations or getattr(settings, 'agent_max_iterations', 15)
        self._max_failures_per_param = getattr(settings, 'agent_max_failures_per_param', 3)
        self._consecutive_failures_threshold = getattr(settings, 'agent_consecutive_failures_threshold', 6)

        self.llm = get_llm_client()
        self.memory = get_memory()           # 从 ai.core 获取
        self.context = get_scan_context()
        self.rule_engine = get_rule_engine() # 从 ai.core 获取
        self.tools = TOOL_REGISTRY

        # A2.1: 角色化子 Agent——窄 prompt + 窄工具集（未知角色/未配置则保持全工具集）
        self.role = str(role or "").strip().lower()
        role_cfg = AGENT_ROLES.get(self.role) or {}
        self.role_system = str(role_cfg.get("system", "") or "")
        role_tools = role_cfg.get("tools")
        if role_tools:
            self.tools = {k: v for k, v in TOOL_REGISTRY.items() if k in role_tools}
        # A2.2: 共享黑板（子 Agent 间结构化通信；未传入则自建独立黑板）
        self.blackboard = blackboard if blackboard is not None else Blackboard()

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

        # S3.2: ClueEngine 线索引擎（由 V100 主链路深挖阶段注入）
        self.clue_engine = None
        # S3.1: 跨会话记忆召回缓存（run() 中召回一次）
        self._memory_recalled = False
        self._memory_note = ""
        # S3.3: 上下文压缩阈值（超过后历史滚动压缩为结构化纪要）
        self._compress_threshold = 15
        self._compressed_summary = ""
        # A1.2: Plan-then-Act——分阶段计划（recon/assume/verify/exploit）与消费游标。
        # 修复：current_plan/plan_step 此前未在 __init__ 初始化（零调用=零实战藏 bug），
        # _decide_action 直接读 self.current_plan[self.plan_step] 会 AttributeError。
        self.current_plan: List[Dict] = []
        self.plan_step = 0
        # A1.3: 反思循环——连续失败计数与策略切换次数
        self._consecutive_failures = 0
        self._strategy_switched = 0
        # Z3.4: OOB 盲打假设验证去重（target|param|payload 模板），每假设只打一次
        self._oob_attempted: set = set()
        # 外询专家去重：同一问题只委派一次，控制开销与外部调用次数
        self._expert_asked: set = set()

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

        # S3.1: 跨会话记忆召回（一次）——历史成功/失败经验注入决策，长程学习
        try:
            recalled = await self.memory.recall(self.target, n_results=3)
            if recalled:
                self._memory_note = ";\n".join(str(r)[:120] for r in recalled[:3])
                logger.info(f"🧠 [ScanMemory] 召回 {len(recalled)} 条历史经验")
        except Exception as _me:  # noqa: BLE001
            logger.debug(f"[ScanMemory] 召回失败: {_me}")
        self._memory_recalled = True

        # A1.2: Plan-then-Act——执行前先产出 JSON 分阶段计划
        await self._generate_plan()

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

            # A1.3: 反思循环——连续失败计数，≥2 次自动切换策略（_decide_action 会读到状态）
            if is_valid:
                self._consecutive_failures = 0
            else:
                self._consecutive_failures += 1
                if self._consecutive_failures >= 2:
                    self._strategy_switched += 1
                    logger.warning(
                        f"🔄 [Reflect] 连续失败 {self._consecutive_failures} 次，要求切换策略"
                    )

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
        # S1: 聚焦模式——把目标参数强制注入侦察结果，保证深挖命中
        if self.focus_param and self.focus_param not in params:
            params.append(self.focus_param)
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
            # S1: 聚焦参数强制最高优先级，深挖不会偏离目标参数
            if self.focus_param and p == self.focus_param:
                priority = 'high'
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
{self._global_context()}

【目标层摘要（A4.1 资产/经验，非全量）】
{self._target_context()}

【局部观察（A4.1 本轮全量）】
- 状态码: {observation.get('status', '未知')}
- 技术栈: {', '.join(observation.get('tech_stack', []))}
- 所有参数: {', '.join(all_param_names) if all_param_names else '无'}
- 高价值参数: {', '.join(high_priority) if high_priority else '无'}
- 中价值参数: {', '.join(medium_priority) if medium_priority else '无'}
- 已发现漏洞: {len(self.findings)} 个
- 已失败参数: {', '.join(self._failed_params) if self._failed_params else '无'}

【可用工具（共{len(self.tools)}个）】
{self._format_tools()}

【特殊动作（Z3.4 盲打假设验证 + 外询专家）】
oob_confirm(url,param,payload,timeout)：规则引擎全 miss 的无回显假设验证——注入带外地址并轮询回调，回调=Critical 实锤。payload 为载荷模板，用 {{{{OBS_DNS}}}}（DNS 外带）或 {{{{OBS_HTTP}}}}（HTTP 外带）占位，例如 ${{jndi:ldap://{{{{OBS_DNS}}}}/a}}、http://{{{{OBS_DNS}}}}/probe。适合 log4shell/fastjson/struts2-ognl/ssrf/xxe 等盲打场景。
ask_expert(question,context,system)：困惑时外询——内部知识盲区/判断依据不足时（未知漏洞类型、载荷不确定、技术栈陌生、证据难解释），把问题委派给已配置的外部 Agent 拿第二意见。只传分析所需文本，禁止传密钥/OOB token/本地路径；外部不可用会自动降级回本地，不影响流程。

请思考：
1. 当前最有价值的攻击面是什么？
2. 给出下一步决策。
"""
        try:
            # 强制开启 wrap_data 防止提示词注入
            result = await self.llm.ask(
                prompt,
                # A2.1: 角色化子 Agent 使用各自窄 system prompt
                system=self.role_system or "你是渗透测试AI Agent，擅长推理决策。",
                temperature=0.3,
                wrap_data=True,
                task_type="plan"
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
        # A5.2: 不截断工具清单（CLI 工具入册后总数 >30），由成功率排序决定优先级
        # A5.6 工具清单动态裁剪：侦察阶段（尚无计划）隐藏 dangerous 级利用工具（msf/sqlmap 利用等）
        phase = "recon" if (getattr(self, "_recon_observation", None)
                            and not getattr(self, "current_plan", None)) else "attack"
        ordered_tool_names = [
            n for n in self._rank_tools(list(self.tools.keys()))
            if not (phase == "recon" and getattr(self.tools[n], "danger_level", "safe") == "dangerous")
        ]
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

【历史纪要（S3.3 长程压缩）】
{self._compress_history()[:400]}

【线索（S3.2 ClueEngine）】
{self._get_review_clues()}

【历史经验（S3.1 跨会话记忆）】
{self._get_memory_experiences()}

【共享黑板（A2.2 子 Agent 结构化 state）】
{self.blackboard.digest() if self.blackboard else '无'}

【计划进度（A1.2 Plan-then-Act）】
{self._format_plan_progress()}

【策略状态（A1.3 反思循环）】
连续失败 {self._consecutive_failures} 次，累计切换策略 {self._strategy_switched} 次。
{'⚠️ 连续失败≥2次，必须更换工具/参数/攻击思路，禁止重试相同动作；若判断依据不足，可调用 ask_expert 咨询外部专家。' if self._consecutive_failures >= 2 else '可继续当前策略。'}

【可用工具】
{chr(10).join(tools_desc)}
- oob_confirm(score=0.95)(url,param,payload,timeout): Z3.4 无回显盲打假设验证——注入带外地址轮询回调，回调=Critical 实锤。payload 模板含 {{{{OBS_DNS}}}}/{{{{OBS_HTTP}}}} 占位。规则引擎全 miss 时对 log4shell/fastjson/ssrf/xxe 等盲打使用（可作 current_action）。
- ask_expert(score=0.8)(question,context): 困惑时外询——知识盲区/判断依据不足时委派外部 Agent 拿第二意见（REMOTE_AGENTS 未配置则自动降级）。只传分析文本，禁止密钥/OOB token/路径。

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
                    wrap_data=True,
                    task_type="plan"
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

        # Z3.4: 内置 OOB 盲打假设验证——规则引擎全 miss 时对无回显 0day/复杂漏洞
        # 假设做带外实锤（log4shell/fastjson/ssrf/xxe/ognl 等盲打场景）。
        # 不注册进 TOOL_REGISTRY，避免与工具层改动冲突；由 Agent 按需调用。
        if tool_name == "oob_confirm":
            return await self._execute_oob_confirm(params)

        # 困惑时外询：内部 Agent 保持精简稳定，遇知识盲区/判断依据不足时
        # 委派给已配置的外部 Agent（REMOTE_AGENTS）当第二意见。
        # 同样为内置动作（非 TOOL_REGISTRY），未配置/全失败自动降级回本地逻辑。
        if tool_name == "ask_expert":
            return await self._execute_ask_expert(params)

        if tool_name not in self.tools:
            logger.warning(f"⚠️ 未知工具: {tool_name}")
            return {"error": f"未知工具: {tool_name}"}

        if not self.rule_engine.can_call_tool(tool_name):
            logger.warning(f"⛔ 工具 {tool_name} 调用次数已达上限")
            return {"error": f"工具 {tool_name} 调用次数已达上限"}

        if "url" not in params or not params["url"]:
            params["url"] = self.target

        param = params.get("param", "")
        # S1: 聚焦模式缺省参数回退到 focus_param
        if not param and self.focus_param:
            param = self.focus_param
            params["param"] = param
        if param and param in self._failed_params:
            logger.info(f"⏭️ 跳过参数 {param}（已失败 {self._param_fail_count.get(param, 0)} 次）")
            return {"error": f"参数 {param} 已失败多次，跳过"}

        logger.info(f"🔧 执行: {tool_name} {params} - {reason}")

        # A1.6: Human-in-the-loop——危险操作走 DangerGuard 审批
        #（prompt 模式交互确认，deny 模式拒绝，allow 模式放行）
        # 说明：当前 30 个注册工具均为检测引擎，DANGEROUS_OPS 里的真实利用操作
        #（exploit_chain / msf_exploit / msf_shell_write / exploit_verify）已在
        # deepsec/exploit_chain.py、deepsec/msf_rpc.py、core/exploit_verify.py 内各自
        # require_approval。此处按 DANGEROUS_OPS 注册表做通用判定，是工具集扩展后
        # ReAct 直接调利用类工具时的防御性预留，不会误伤正常检测工具。
        try:
            from vulnclaw.core.danger_guard import DANGEROUS_OPS, guard
            _op = tool_name if tool_name in DANGEROUS_OPS else None
            if _op is None and "msf" in tool_name.lower():
                _op = "msf_exploit"
            if _op and not guard.require_approval(_op, f"{tool_name} @ {self.target}"):
                logger.warning(
                    f"🚫 [DangerGuard] 危险操作「{_op}」未获批准，跳过 {tool_name}（拒绝执行）"
                )
                return {"error": f"危险操作 {_op} 未获批准（DangerGuard deny）", "guard_denied": True}
        except Exception as _ge:  # noqa: BLE001
            logger.debug(f"[DangerGuard] 检查失败（放行兜底）: {_ge}")

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

    async def _execute_oob_confirm(self, params: Dict) -> Dict:
        """Z3.4: OOB 盲打假设验证（内置动作，非 TOOL_REGISTRY 工具）。

        场景：规则引擎对某参数全部 miss（无带内回显），Agent 可据此对 0day/复杂
        漏洞（log4shell/fastjson/struts2-ognl/ssrf/xxe 等）做"假设验证式"盲打：
        注入带外地址 → 轮询回调 → 命中即 Critical 实锤。

        参数（LLM 调用）：
          url     : 目标（缺省 self.target）
          param   : 注入参数（缺省 self.focus_param）
          payload : 载荷模板，含 {OBS_DNS} 或 {OBS_HTTP} 占位符，例如
                    '${jndi:ldap://{OBS_DNS}/a}' / 'http://{OBS_DNS}/probe'
          timeout : 回调等待秒数（默认 12）

        低误报铁律：OOB 通道不可用 / 超时无回调 → 一律返回 None 语义（不误报）；
        回调须 token 精确匹配，拒绝假 oast 域名（由 core.oob_channel 保证）。
        """
        url = str(params.get("url") or self.target or "")
        param = str(params.get("param") or self.focus_param or "")
        payload_tpl = str(params.get("payload", "") or "")
        timeout = int(params.get("timeout", 12) or 12)
        if not url:
            return {"error": "oob_confirm 缺少目标 url"}
        if not payload_tpl:
            return {"error": "oob_confirm 需要 payload 模板（含 {OBS_DNS} 或 {OBS_HTTP}）"}

        # 每 (目标|参数|模板) 只盲打一次，控制开销与请求突刺
        dedup_key = f"{url}|{param}|{payload_tpl}"
        if dedup_key in self._oob_attempted:
            return {"info": f"OOB 假设已尝试过，跳过（{dedup_key[:80]}）", "dedup": True}
        self._oob_attempted.add(dedup_key)

        from vulnclaw.core.oob_channel import OOBChannel

        ch = OOBChannel()
        try:
            probe = await ch.make_probe("https")
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[OOBConfirm] 通道异常: {exc}")
            return {"error": f"OOB 通道异常: {exc}"}
        if not probe:
            logger.info("ℹ️ [OOBConfirm] OOB 通道不可用（interactsh/dnslog 均失败），盲打跳过（不误报）")
            return {"info": "OOB 通道不可用，盲打跳过（不误报）"}

        token = probe["token"]
        obs_dns = probe["dns"]
        obs_http = probe["url"]
        payload = payload_tpl.replace("{OBS_HTTP}", obs_http).replace("{OBS_DNS}", obs_dns)
        attack_url = build_attack_url(url, param, payload) if param else (
            (url + ("&" if "?" in url else "?") + payload)
        )
        logger.info(f"🧪 [OOBConfirm] 盲打 {param or 'URL'} -> {obs_dns}（token={token}）")

        try:
            # 禁跟随重定向：目标若把 payload 里的 OOB 地址反射进 Location，
            # 扫描器自身跟随 302 会主动请求它，自产回调并被 token 命中 → 误判实锤。
            await async_get(attack_url, session=self.session, timeout=settings.timeout, no_retry=True, allow_redirects=False)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[OOBConfirm] 注入请求失败: {exc}")

        hits = await ch.wait_for_interaction(token, timeout=max(4, min(timeout, 25)))
        if not hits:
            return {"info": f"OOB 探测未收到回调（{timeout}s），未确认（不误报）", "probe": obs_dns, "token": token}

        proto = hits[0].protocol
        callback = f"{proto}://{obs_dns}/ 于 {hits[0].time or '-'}"
        finding = {
            "url": attack_url,
            "parameter": param,
            "payload": payload,
            "type": f"ReAct-OOB盲打实锤({payload_tpl[:40]})",
            "severity": "Critical",
            "ai_verdict": "高",
            "confidence": "high",
            "evidence": (
                f"Agent 对无回显参数 `{param or 'URL'}` 注入带外载荷后，捕获 token 精确匹配的 "
                f"{proto} 回调 {callback} —— 盲打假设验证成立，可能可 RCE/SSRF 外带",
            ),
            "oob_confirmed": True,
            "oob_token": token,
            "oob_provider": probe.get("provider", ""),
            "source": "react_agent",
            "recommendation": "人工复核回调证据，确认利用链后按漏洞类型升级组件版本",
        }
        logger.info(f"✅ [OOBConfirm] token={token} 回调实锤 → Critical")
        return finding

    async def _execute_ask_expert(self, params: Dict) -> Dict:
        """困惑时外询：内部 Agent 保持精简稳定，遇知识盲区/判断依据不足时，
        把问题委派给已配置的外部 Agent（REMOTE_AGENTS）当第二意见。

        参数（LLM 调用）：
          question  : 要咨询的问题（必填）
          system    : 可选，外部 Agent 的角色/system 提示
          context   : 可选，附加上下文（技术栈/已观察现象），会拼进问题
          max_tokens: 可选，外部回答长度上限（默认 800）

        安全与降级：
          - 只传分析所需文本，question 里禁止密钥/OOB token/本地路径（prompt 层已约束）
          - 未配置 REMOTE_AGENTS / 全部委派失败 / 超时 → 返回 None 语义，不影响主流程
          - 同一问题去重，只委派一次，控制外部调用成本
        """
        question = str(params.get("question", "") or "").strip()
        if not question:
            return {"error": "ask_expert 需要 question 参数"}

        dedup_key = question[:120]
        if dedup_key in self._expert_asked:
            return {"info": f"该问题已咨询过外部专家，跳过（{dedup_key[:60]}）", "dedup": True}
        self._expert_asked.add(dedup_key)

        system = str(params.get("system", "") or "你是渗透测试领域专家，给出简洁、可执行的判断与建议。")
        context = str(params.get("context", "") or "")
        max_tokens = int(params.get("max_tokens", 800) or 800)

        try:
            from vulnclaw.ai.remote_agents import delegate_analysis
        except Exception as exc:
            logger.debug(f"[外询] remote_agents 导入失败，回退本地逻辑: {exc}")
            return {"info": "外部专家不可用，按本地经验继续", "type": "expert_unavailable"}

        prompt = f"【附加上下文】\n{context}\n\n【问题】\n{question}" if context else question
        try:
            answer = await asyncio.wait_for(
                delegate_analysis(prompt, system=system, max_tokens=max_tokens), timeout=25
            )
        except asyncio.TimeoutError:
            logger.warning("[外询] 外部专家超时（25s），回退本地逻辑")
            return {"info": "外部专家超时，按本地经验继续", "type": "expert_unavailable"}
        if not answer:
            logger.info("[外询] 外部专家不可用（未配置 REMOTE_AGENTS 或全部熔断），回退本地逻辑")
            return {"info": "外部专家不可用，按本地经验继续", "type": "expert_unavailable"}
        logger.info(f"[外询] 外部专家返回 {len(answer)} 字")
        return {
            "type": "expert_advice",
            "answer": answer,
            "question": question[:120],
            "source": "remote_agent",
        }

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
            # A4.3: 工具输出裁剪（原始 stdout 千行只入日志，喂 LLM 用摘要）
            result = self._clip_tool_output(result)
            # A2.2: 端点写入共享黑板（结构化 state，非自然语言全量互传）
            if result.get("url"):
                self._publish_blackboard({"endpoints": [str(result["url"])]})

            if result.get("status") == "finished":
                return {"type": "finish", "message": result.get("reason", "完成")}

            if "error" in result:
                return {"type": "error", "message": result["error"], "data": result}

            if "type" in result and ("漏洞" in result.get("type", "") or "注入" in result.get("type", "")):
                self.findings.append(result)
                self._publish_blackboard({"vulns": [result]})
                return {"type": "finding", "message": f"发现 {result.get('type')}", "data": result}

            if "vulnerabilities" in result:
                vulns = result.get("vulnerabilities", [])
                if vulns:
                    self.findings.extend(vulns)
                    self._publish_blackboard({"vulns": vulns})
                    return {"type": "findings", "message": f"发现 {len(vulns)} 个漏洞", "data": vulns}

            for key in ["sqli", "xss", "lfi", "cmdi", "ssti", "ssrf", "xxe", "idor", "jwt"]:
                if key in result and result[key]:
                    self.findings.extend(result[key])
                    self._publish_blackboard({"vulns": result[key]})
                    return {"type": "findings", "message": f"在 {key} 检测中发现漏洞", "data": result[key]}

            # 外询专家意见：写入黑板 notes 供各子 Agent 共享，作为下轮决策依据
            if result.get("type") == "expert_advice":
                answer = str(result.get("answer", ""))
                self._publish_blackboard({"notes": {"expert_advice": answer[:500]}})
                return {"type": "expert_advice", "message": f"外部专家意见: {answer[:200]}", "data": result}

            return {"type": "info", "message": "工具执行完成，无异常发现", "data": result}

        if isinstance(result, list) and result:
            self.findings.extend(result)
            self._publish_blackboard({"vulns": result})
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

    # ---------------- S3: 唤醒闲置资产 ----------------
    def _compress_history(self, keep_last: int = 3) -> str:
        """S3.3: 上下文压缩——超过阈值后把 history 滚动压缩为结构化纪要（对标 Strix MemoryCompressor）。

        长程多轮场景（ReAct 深挖 max_iterations 较大）下，对话不断累积，
        若不压缩会导致 prompt 膨胀、token 成本上升。压缩只保留动作骨架，
        最近 keep_last 轮保留全量细节。
        """
        if not self.history:
            return "无"
        if len(self.history) <= self._compress_threshold:
            return self._format_history()
        compact_entries = self.history[:-keep_last]
        parts = []
        for h in compact_entries:
            if "thought" in h:
                parts.append(f"思考:{str(h.get('thought', ''))[:50]}")
            elif "action" in h:
                a = h.get("action", {})
                if isinstance(a, dict):
                    parts.append(f"行动:{a.get('tool')}({str(a.get('reason', ''))[:25]})")
            elif "result" in h:
                r = h.get("result")
                if isinstance(r, dict):
                    parts.append(f"结果:{r.get('type')}/{r.get('severity', '')}/valid={h.get('valid')}")
                else:
                    parts.append(f"结果:{str(r)[:30]}/valid={h.get('valid')}")
        body = "; ".join(parts) if parts else "[无可压缩内容]"
        self._compressed_summary = f"[已压缩{len(compact_entries)}轮] {body[:300]}"
        return f"{self._compressed_summary} ... 【最近】{self._format_history()}"

    def _get_review_clues(self) -> str:
        """S3.2: 从扫描上下文读取 ClueEngine 线索，作为 ReAct 决策候选。"""
        try:
            if self.clue_engine is not None and hasattr(self.context, "get_review_clues_sorted"):
                clues = self.context.get_review_clues_sorted()
            else:
                clues = []
        except Exception:  # noqa: BLE001
            clues = []
        if not clues:
            return "无"
        lines = []
        for c in clues[:5]:
            if isinstance(c, dict):
                lines.append(
                    f"  - [{c.get('priority', '?')}] {c.get('type', '?')}: "
                    f"{str(c.get('evidence', ''))[:80]}"
                )
        return "\n".join(lines) if lines else "无"

    def _get_memory_experiences(self) -> str:
        """S3.1: 读取跨会话记忆召回结果（run() 已召回一次并缓存）。"""
        return self._memory_note if self._memory_recalled and self._memory_note else "无"

    def _publish_blackboard(self, payload: Dict) -> None:
        """A2.2: 把结构化结果写入共享黑板（写入失败不影响主流程）。"""
        if not self.blackboard:
            return
        try:
            for key, value in (payload or {}).items():
                self.blackboard.publish(key, value)
        except Exception:  # noqa: BLE001
            logger.debug("suppressed exception (core audit)")

    # ---------------- A4: 上下文管理 ----------------
    def _global_context(self) -> str:
        """A4.1: 全局层——任务目标与角色定位（摘要，每次 LLM 调用都带）。"""
        role_label = self.role.upper() if self.role else "通用"
        return (
            f"【全局目标】{self.target} | 角色={role_label} | "
            f"阶段={self.iteration + 1}/{self.max_iterations}"
        )

    def _target_context(self) -> str:
        """A4.1: 目标层——已知资产/经验/统计摘要（黑板+记忆+统计，非全量互传）。

        设计：LLM 调用只带全局摘要 + 局部全量，目标层用摘要避免 token 膨胀。
        """
        parts = []
        obs = self._recon_observation or {}
        if obs.get("tech_stack"):
            parts.append(f"技术栈={','.join(str(t) for t in obs['tech_stack'][:3])}")
        parts.append(f"已发现漏洞={len(self.findings)}")
        if self._failed_params:
            parts.append(f"已失败参数={','.join(list(self._failed_params)[:5])}")
        if self.blackboard:
            parts.append(f"黑板={self.blackboard.digest(150)}")
        if self._memory_recalled and self._memory_note:
            parts.append(f"历史经验={self._memory_note[:120]}")
        return " | ".join(parts) if parts else "无"

    def _clip_tool_output(self, result: Any) -> Any:
        """A4.3: 工具输出裁剪——原始 stdout/stderr/output 超阈值只入日志，喂 LLM 用裁剪摘要。

        防止 nuclei/ffuf 千行原始输出进入 prompt 撑爆 token。结构化字段（type/severity/
        evidence/url）原样保留。
        """
        if not isinstance(result, dict):
            return result
        max_chars = int(getattr(settings, "context_clip_max_chars", 1500))
        for raw_key in ("stdout", "stderr", "raw_output", "output"):
            raw = result.get(raw_key)
            if isinstance(raw, str) and len(raw) > max_chars:
                logger.debug(
                    f"[Clip] {raw_key} 原始 {len(raw)} 字符超阈值，喂 LLM 用裁剪摘要"
                )
                result[raw_key] = raw[:max_chars] + f"...[已裁剪，原始 {len(raw)} 字符见日志]"
        return result

    async def _generate_plan(self) -> None:
        """A1.2: Plan-then-Act——执行前先产出分阶段计划（recon→assume→verify→exploit）。

        current_plan 为按阶段排序的工具名列表（与 _decide_action 的消费逻辑兼容）；
        LLM 不可用/失败时降级为动态决策。
        """
        if not self.llm:
            return
        obs = self._recon_observation or {}
        params = obs.get("params") or []
        param_names = ", ".join(
            p.get("param", "") if isinstance(p, dict) else str(p) for p in params[:10]
        )
        known_tools = " ".join(list(self.tools.keys())[:25])
        prompt = (
            "你是渗透测试规划Agent。基于侦察信息，为单个目标制定分阶段渗透计划。\n"
            f"【侦察】target={obs.get('target')} status={obs.get('status')} "
            f"tech_stack={obs.get('tech_stack')} params={param_names}\n"
            f"【可选工具】{known_tools}\n"
            "【要求】输出 JSON 数组，按 侦察/假设/验证/利用 四阶段顺序排列，"
            "每项仅含工具名（必须来自可选工具）。数量 3-6 个。只输出 JSON 数组。"
        )
        try:
            resp = await self.llm.ask(prompt, temperature=0.3, max_tokens=400, task_type="plan")
            data = json.loads(resp)
            if isinstance(data, list) and data:
                plan = [str(t) for t in data if str(t) in self.tools]
                if plan:
                    self.current_plan = plan
                    self.plan_step = 0
                    logger.info(f"🗺️ [Plan] 预生成 {len(plan)} 步计划: {plan}")
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[Plan] 计划预生成失败，降级为动态决策: {e}")

    def _format_plan_progress(self) -> str:
        """A1.2: 展示计划中尚未消费的步骤（供 _decide_action 参考）。"""
        if not self.current_plan:
            return "无计划（动态决策）"
        pending = self.current_plan[self.plan_step:]
        if not pending:
            return "计划已全部执行"
        return " -> ".join(str(t) for t in pending[:5])

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


# ============================================================
# P2-1: AgentCoordinator —— strix 式可寻址 agent 树 + mailbox + 快照
# 构建于现有 Blackboard / AGENT_ROLES / run_engine 之上：
#   * 根 agent 按角色分解任务，派生 recon/analysis/exploit/verify 子 agent（并发）
#   * agent 间用 mailbox 投递结构化消息（发现/提问/委派），共享 snapshot 保持一致视图
#   * 子 agent 以确定性引擎套件为主（Tier-1 广覆盖），LLM 仅做根编排与可选推理
# ============================================================

def _parse_target(target: str):
    """拆分目标为 base(url 无 query) / full(原样) / params(query 参数名列表)。"""
    if "?" not in target:
        return target, target, []
    base, q = target.split("?", 1)
    params = []
    for pair in q.split("&"):
        if "=" in pair:
            params.append(pair.split("=", 1)[0])
    return base, target, params


class Mailbox:
    """可寻址信箱：agent 之间用结构化消息通信（发现/提问/委派/状态）。

    每个地址一条入队队列；post 精确投递，broadcast 投给子树全部子代理。
    非阻塞投递，接收方 drain 消费。这是 strix 多 agent 消息传递的轻量实现。
    """

    def __init__(self) -> None:
        self._boxes: Dict[str, deque] = {}
        self._lock = asyncio.Lock()

    def _ensure(self, addr: str) -> deque:
        return self._boxes.setdefault(addr, deque())

    async def post(self, to_addr: str, message: Dict) -> None:
        async with self._lock:
            self._ensure(to_addr).append(message)

    async def broadcast(self, tree_prefix: str, message: Dict) -> None:
        async with self._lock:
            for a in list(self._boxes.keys()):
                if a == tree_prefix or a.startswith(tree_prefix + "."):
                    self._boxes[a].append(message)

    async def drain(self, addr: str) -> List[Dict]:
        """取出某地址所有积压消息（非阻塞）。"""
        out: List[Dict] = []
        async with self._lock:
            dq = self._boxes.get(addr)
            while dq:
                out.append(dq.popleft())
        return out

    def pending(self, addr: str) -> int:
        return len(self._boxes.get(addr, ()))


class Snapshot:
    """共享快照：整棵树看到的"世界状态"一致视图（strix context 快照的等价物）。

    含共享黑板 state、全局 findings、各 agent 状态。任一 agent 启动即从最新
    快照 bootstrap，避免重复侦察与冲突调度；版本号随每次更新自增。
    """

    def __init__(self) -> None:
        self.version = 0
        self.blackboard = Blackboard()
        self.findings: List[Dict] = []
        self.agent_status: Dict[str, Dict] = {}
        self._lock = asyncio.Lock()

    async def update(self, *, findings=None, status=None, publish=None) -> int:
        async with self._lock:
            if findings:
                self.findings.extend(findings)
            if status:
                self.agent_status.update(status)
            if publish:
                for k, v in (publish or {}).items():
                    self.blackboard.publish(k, v)
            self.version += 1
            return self.version

    def digest(self, limit: int = 400) -> str:
        eps = [str(e)[:40] for e in self.blackboard._state["endpoints"][:5]]
        vulns = [
            f"{v.get('type', '')}/{v.get('severity', '')}"
            for v in self.findings[:5] if isinstance(v, dict)
        ]
        ags = [f"{a}:{s.get('state', '?')}" for a, s in list(self.agent_status.items())[:6]]
        return f"v{self.version} endpoints={eps} vulns={vulns} agents={ags}"[:limit]


_TOOL_CAP_CACHE: Dict[str, tuple] = {}


def _findings_key(f: Dict) -> tuple:
    return (
        str(f.get("url", "")), str(f.get("parameter", "")), str(f.get("type", "")),
        str(f.get("method", "")), str(f.get("source", "")), str(f.get("evidence", ""))[:80],
    )


def _dedup_findings(findings: List[Dict]) -> List[Dict]:
    """跨 agent 去重（strix 在产出端合并同因发现）：按 url/param/type/method/source/evidence 指纹。"""
    seen = set()
    out: List[Dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        k = _findings_key(f)
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def _tool_capability(tool_name: str) -> tuple:
    """复用 P0-1 的能力探测：该工具引擎是否支持 scan / check。"""
    if tool_name in _TOOL_CAP_CACHE:
        return _TOOL_CAP_CACHE[tool_name]
    has_scan = has_check = False
    try:
        from vulnclaw.core.scanner import get_engine_by_name, engine_capability
        eng = get_engine_by_name(tool_name)
        if eng is not None:
            has_scan, has_check = engine_capability(eng)
    except Exception:
        logger.debug("suppressed exception (core audit)")
    _TOOL_CAP_CACHE[tool_name] = (has_scan, has_check)
    return has_scan, has_check


class AgentNode:
    """可寻址 agent 树节点：一个角色化执行单元（确定性引擎套件 + 可选 LLM 推理）。"""

    def __init__(self, coordinator: "AgentCoordinator", addr: str, role: str,
                 parent: Optional["AgentNode"], focus: str = None):
        self.coordinator = coordinator
        self.addr = addr
        self.role = role
        self.parent = parent
        self.focus = focus
        self.children: List["AgentNode"] = []
        self.status = {"state": "init", "iterations": 0, "findings": 0}
        self.blackboard = coordinator.snapshot.blackboard
        self.mailbox = coordinator.mailbox
        role_cfg = (AGENT_ROLES.get(role) or {})
        self.tools = list(role_cfg.get("tools", []))
        self.system = role_cfg.get("system", "")
        self.llm = None
        try:
            from vulnclaw.ai.core import get_llm_client
            if getattr(settings, "ai_mode", 1):
                self.llm = get_llm_client()
        except Exception:
            self.llm = None

    async def run(self, target: str, session) -> List[Dict]:
        self.status["state"] = "running"
        await self.coordinator.snapshot.update(status={self.addr: dict(self.status)})

        # 目标集：原始目标 + 共享黑板中已发现端点（多 agent 知识融合：recon 产出、其余消费）
        _, full0, params0 = _parse_target(target)
        targets = [(target, full0, params0)]
        try:
            for ep in (self.blackboard.consume("endpoints") or []):
                if isinstance(ep, str) and ep != target:
                    _, ep_full, ep_params = _parse_target(ep)
                    targets.append((ep, ep_full, ep_params))
        except Exception:
            pass

        findings: List[Dict] = []
        for tool_name in self.tools:
            if tool_name not in TOOL_REGISTRY:
                continue
            has_scan, has_check = _tool_capability(tool_name)
            try:
                for (orig, full, params) in targets:
                    base = orig.split("?")[0]
                    if has_scan:
                        f = await self._call(tool_name, target=base, param="", session=session)
                        findings = self._merge(findings, f)
                    if has_check and params:
                        for p in params:
                            # focus 参数优先；否则遍历 query 参数
                            if self.focus and p != self.focus:
                                continue
                            f = await self._call(tool_name, target=full, param=p, session=session)
                            findings = self._merge(findings, f)
            except Exception as e:
                logger.warning(f"[AgentNode {self.addr}] 工具 {tool_name} 失败: {e}")

        if findings:
            # 写入共享快照/黑板（兄弟 agent 可见），并通知父/根
            await self.coordinator.snapshot.update(
                findings=findings,
                publish={"vulns": findings, "endpoints": [base]},
            )
            await self.mailbox.post(self.coordinator.root_addr, {
                "type": "finding", "from": self.addr, "findings": findings,
            })
        self.status["findings"] = len(findings)
        self.status["state"] = "done"
        await self.coordinator.snapshot.update(status={self.addr: dict(self.status)})
        return findings

    async def _call(self, tool_name: str, *, target: str, param: str, session) -> List[Dict]:
        """复用 P0-1 统一适配层 run_engine 执行单个引擎工具。"""
        from vulnclaw.core.scanner import run_engine
        try:
            res = await run_engine(tool_name, target=target or None, param=param or None, session=session)
        except Exception as e:
            logger.debug(f"[AgentNode {self.addr}] run_engine({tool_name}) 跳过: {e}")
            return []
        return self._extract(res)

    @staticmethod
    def _extract(res) -> List[Dict]:
        if not isinstance(res, dict):
            return list(res) if isinstance(res, list) else []
        out: List[Dict] = []
        if res.get("type") == "漏洞":
            data = res.get("data")
            if isinstance(data, list):
                out.extend(data)
            elif isinstance(data, dict):
                out.append(data)
        for k in ("sqli", "xss", "lfi", "cmdi", "ssti", "ssrf", "xxe", "idor", "jwt",
                 "vulnerabilities", "findings", "data"):
            if k in res and res[k]:
                v = res[k]
                out.extend(v if isinstance(v, list) else [v])
        return [x for x in out if isinstance(x, dict)]

    @staticmethod
    def _merge(a: List[Dict], b: List[Dict]) -> List[Dict]:
        for x in b:
            if x not in a:
                a.append(x)
        return a


class AgentCoordinator:
    """可寻址 agent 树协调器（strix AgentCoordinator 融合版）。

    根 agent 按角色分解任务并派生子 agent（recon/analysis/exploit/verify 等），
    并发执行；agent 间通过 mailbox 通信、共享 snapshot 保持一致视图。
    最终聚合所有 findings 返回。LLM 仅用于"根编排决策"与可选 agent 推理，
    主执行以确定性引擎为主（Tier-1 快/廉），可叠加 LLM 推理。
    """

    def __init__(self, target: str, session):
        self.target = target
        self.session = session
        self.snapshot = Snapshot()
        self.mailbox = Mailbox()
        self.nodes: Dict[str, AgentNode] = {}
        self.root_addr = "root"
        self.root = AgentNode(self, self.root_addr, role="", parent=None)
        self.nodes[self.root_addr] = self.root
        self._tree_lock = asyncio.Lock()

    async def spawn(self, role: str, parent_addr: str = "root", focus: str = None) -> AgentNode:
        async with self._tree_lock:
            parent = self.nodes.get(parent_addr) or self.root
            child_addr = role if parent_addr == "root" else f"{parent_addr}.{role}"
            if child_addr in self.nodes:
                return self.nodes[child_addr]
            node = AgentNode(self, child_addr, role, parent, focus=focus)
            parent.children.append(node)
            self.nodes[child_addr] = node
            logger.info(f"🌲 [Coordinator] 派生 agent: {child_addr} (role={role}, focus={focus})")
            return node

    async def coordinate(self, roles: List[str] = None) -> Dict:
        roles = roles or ["recon", "analysis", "exploit", "verify"]
        # LLM 根编排（可选）：可用则让 LLM 决定角色顺序/裁剪；否则默认全跑
        if getattr(settings, "ai_mode", 1):
            try:
                plan = await self._llm_plan_roles(roles)
                if plan:
                    roles = plan
            except Exception as e:
                logger.debug(f"[Coordinator] LLM 编排失败，使用默认角色集: {e}")

        # 两波并发：先跑 recon（知识生产者，写入共享黑板端点/漏洞），
        # 再并发其余角色并消费 recon 的共享知识（strix 式共享上下文）。
        recon_findings: List[Dict] = []
        rest = list(roles)
        if "recon" in rest:
            rest.remove("recon")
            recon_node = await self.spawn("recon", "root")
            recon_findings = await recon_node.run(self.target, self.session)

        tasks = []
        for role in rest:
            node = await self.spawn(role, "root")
            tasks.append(asyncio.create_task(node.run(self.target, self.session)))
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: List[Dict] = []
        all_findings.extend(recon_findings)
        for r in results:
            if isinstance(r, Exception):
                logger.warning(f"[Coordinator] agent 执行异常: {r}")
                continue
            all_findings.extend(r)

        # 回收 mailbox 中 agent 主动 post 的发现（兜底，避免漏收）
        root_msgs = await self.mailbox.drain(self.root_addr)
        for m in root_msgs:
            if m.get("type") == "finding" and m.get("findings"):
                all_findings.extend([f for f in m["findings"] if isinstance(f, dict)])

        # 跨 agent 去重（角色天然重叠，如 analysis/exploit/verify 都跑 sqli）
        all_findings = _dedup_findings(all_findings)

        self.root.status["state"] = "done"
        await self.snapshot.update(status={self.root_addr: dict(self.root.status)})
        return {
            "target": self.target,
            "snapshot_version": self.snapshot.version,
            "agents": {a: n.status for a, n in self.nodes.items()},
            "findings": all_findings,
            "blackboard": self.snapshot.blackboard.digest(),
        }

    def bridge_into(self, orchestrator) -> None:
        """把协调器的共享知识（黑板 + findings）并入主编排器状态，供最终报告使用。

        去重后逐一 _add_finding（编排器侧再次按 key 去重），并把共享黑板摘要
        写入编排器 blackboard（若其具备 publish），使多 agent 深扫成果透传进报告。
        """
        try:
            merged = _dedup_findings(self.snapshot.findings)
            for f in merged:
                if isinstance(f, dict):
                    f.setdefault("source", "agent_coordinator")
                    orchestrator._add_finding(f)
            ob = getattr(orchestrator, "blackboard", None)
            if ob is not None and hasattr(ob, "publish"):
                ob.publish("agent_coordinator_knowledge", self.snapshot.blackboard.digest())
        except Exception as e:
            logger.warning(f"⚠️ [AgentCoordinator] bridge_into 失败（不影响主链路）: {e}")

    async def _llm_plan_roles(self, roles: List[str]) -> Optional[List[str]]:
        try:
            from vulnclaw.ai.core import get_llm_client
            client = get_llm_client()
        except Exception:
            return None
        prompt = (
            f"你是渗透测试编排器。目标 {self.target}，可用角色: {roles}。"
            "请返回要并发执行的角色顺序列表（JSON 数组，可为其子集），"
            "例如 [\"recon\",\"analysis\",\"exploit\",\"verify\"]。只输出 JSON 数组。"
        )
        try:
            resp = await client.ask(
                prompt, system="你是渗透测试编排器，只输出JSON数组。",
                temperature=0.2, max_tokens=200, task_type="plan",
            )
            data = json.loads(resp)
            if isinstance(data, list) and data:
                return [str(x) for x in data if str(x) in roles]
        except Exception:
            return None
        return None


_agent = None


def get_agent(target: str, session):
    global _agent
    _agent = ReActAgent(target, session)
    return _agent


__all__ = ['ReActAgent', 'get_agent', 'PayloadGenerator',
           'AgentCoordinator', 'AgentNode', 'Mailbox', 'Snapshot']