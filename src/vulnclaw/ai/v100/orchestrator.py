# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""v100 orchestrator facade and public scan entry point."""
import asyncio
import gc
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from vulnclaw.core.logger import logger
from vulnclaw.core.context import get_scan_context
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get
from vulnclaw.core.scanner import _load_engines
from vulnclaw.core.session_manager import get_session_manager
from vulnclaw.ai.core import get_llm_client, get_memory
from vulnclaw.ai.burp import get_burp_controller, get_burp_client
from .rate_limiter import get_rate_limiter
from .batch_processor import BatchProcessor
from .local_filter import get_local_filter
from .smart_queue import SmartTaskQueue
from .provider_balancer import get_balancer
from vulnclaw.engines.input_engines import BusinessLogicEngine


def compress_prompt(prompt: str, max_len: int = 16000) -> str:
    """P1-2: 超长 Prompt 压缩——超过 4k Token(~16000 字符)时仅保留
    (url, param, engine) 三元组关键行与判定指令，大幅降低 Token 消耗。"""
    if len(prompt) <= max_len:
        return prompt
    keys = ("url", "param", "engine", "URL", "参数", "目标", "index", "type")
    kept = [
        ln.strip()
        for ln in prompt.splitlines()
        if ln.strip() and any(k in ln for k in keys)
    ]
    header = "以下为压缩后的(URL,参数,引擎)三元组清单，请逐项判断是否存在漏洞：\n"
    body = "\n".join(kept)
    if len(body) > max_len:
        body = body[:max_len]
    logger.info(
        "♻️ [LLMCache] Prompt 压缩: %s → %s 字符（保留 %s 行三元组）",
        len(prompt), len(header + body), len(kept),
    )
    return header + body
from vulnclaw.engines.auxiliary_engines import APIVersionDiffEngine, RequestSmugglingEngine, HTTP2WebSocketEngine
from vulnclaw.engines.http_engines import CachePoisonEngine
from .phases import bind_phase_methods
from vulnclaw.core_modules.metrics import get_metrics
class V100Orchestrator:
    """v100 facade coordinating the scan phases."""
    _safe_params = {
        'callback', '_', 'timestamp', 'nonce', 'version', 'format',
        'cors', 't', 'v', 'ver', 'ts', 'time', 'rand', 'random',
        'session', 'token', 'csrf', 'authenticity_token', 'utf8'
    }

    def __init__(self, target: str, session, max_tasks: int = None, initial_qps: int = None):
        self.target = target
        self.session = session
        self._user_max_tasks = max_tasks
        self._user_initial_qps = initial_qps
        self.max_tasks = max_tasks if max_tasks is not None else 200
        self.context = get_scan_context()
        self.shared_knowledge = self._ensure_shared_knowledge()
        self._normal_responses_lock = asyncio.Lock()
        self._normal_responses: Dict[str, Dict] = {}
        self._max_normal_responses = 500
        # 优化5: 基线响应 single-flight（同一 URL 的并发任务只发一次 baseline GET）
        self._normal_resp_inflight: Dict[str, Any] = {}
        self.memory = None
        self.rate_limiter = None
        self.batch_processor = None
        self.local_filter = None
        self.task_queue = None
        self.burp = get_burp_controller()
        self.burp_client = get_burp_client()
        self.burp_available = False
        self._burp_cookies = {}
        self._burp_tokens = {}
        self._collaborator_domain = None
        self.balancer = get_balancer()
        self._model_to_provider = {}
        self.engines, self.engine_map = _load_engines()
        # 初始化SPA检测器并传递给所有引擎（detect 延迟到 run() 异步上下文执行，
        # 修复：__init__ 是同步方法，await 导致 SyntaxError 使整个包无法导入）
        from vulnclaw.core.detectors.spa_detector import SpaFingerprintDetector
        spa_detector = SpaFingerprintDetector(self.session)

        for engine in self.engines:
            engine.spa_detector = spa_detector
        self._spa_detector = spa_detector

        self._ensure_engines()
        logger.info(f"✅ 加载 {len(self.engines)} 个漏洞检测引擎（已配置SPA检测器）")
        self._model_pool = self._get_model_pool()
        self._ai_enabled = bool(self._model_pool)
        self._model_index = 0
        self._model_lock = asyncio.Lock()
        self._model_stats = {m: 0 for m in self._model_pool}
        self._model_failures = {m: 0 for m in self._model_pool}
        self._timeout_streaks: Dict[str, int] = {}  # P2-1: 任务类型连续超时计数
        self.findings: List[Dict] = []
        self._finding_keys: Set[tuple] = set()
        self._pending_verify: List[Dict] = []
        self._max_pending_verify = 2000  # 限制最大待验证数
        # --- 流水线验证（stream-verify）状态 ------------------------------------------------
        # 流式 verify：动态预算（P3-1）或 3 秒超时 → 触发一次增量 verify。
        # _stream_budget_n 作为基础批大小，预算 = min(50, 5 + len(pending)//10) + 令牌自适应。
        self._stream_budget_n = 5
        self._stream_timeout_s = 2.0  # 性能优化：3.0→2.0，让 finding 更快进入流式验证
        self._pending_verify_lock = asyncio.Lock()
        self._stream_event = asyncio.Event()
        self._stream_task: Optional["asyncio.Task[None]"] = None
        self._stream_started = False
        self._stream_stopped = False
        # 已流过增量 verify 或被放入批量队列的条目指纹（去重 key）。
        # 去重 key 与 _verify_all_findings 中最终入 findings 的保持一致。
        self._stream_touched_keys: Set[tuple] = set()
        self._stream_processed_count = 0
        self._stream_batches = 0
        self._stream_errors = 0
        self._recon_brief: Dict = {}
        self._processed_params: set = set()
        self._burp_params: set = set()
        # S1: engine_bundle 首次执行结果（param -> [result, ...]），供 ReAct 深挖判断模糊参数
        self._bundle_results: Dict[str, List[Dict]] = {}
        self._start_time = time.time()
        self._total_engine_calls = 0
        self._direct_findings = 0
        self._burp_findings = 0
        self._burp_scan_task = None  # 步骤3：并行 Burp 扫描任务句柄
        self._nuclei_findings = 0
        self._idor_findings = 0
        self._cred_findings = 0
        self._business_findings = 0
        self._api_version_findings = 0
        self._smuggling_findings = 0
        self._http2_ws_findings = 0
        self._cache_poison_findings = 0
        self._task_counter = 0
        self._concurrency_semaphore = asyncio.Semaphore(7)
        self._stats_ttl = 1.0
        self._rate_stats_cache: Optional[Tuple[float, Dict]] = None
        self._model_stats_cache: Optional[Tuple[float, Dict]] = None
        self._stats_cache_lock = asyncio.Lock()
        self._enable_deep_recon = True
        self._enable_idor = True
        self._enable_default_creds = True
        self._enable_ffuf = True
        self._enable_business_logic = True
        self._enable_api_version = True
        self._enable_smuggling = True
        self._enable_http2_ws = True
        bind_phase_methods(self)
        self._check_burp_sync()
        self._init_multi_role()
        logger.info("=" * 70)
        logger.info("🧠 v100 终极版 (5模型自动负载均衡 + 智能调速)")
        logger.info(f"   目标: {target}")
        logger.info(f"   用户设定最大任务: {max_tasks or '自动'}")
        logger.info(f"   用户设定初始QPS: {initial_qps or '自动'}")
        logger.info(f"   引擎: {len(self.engines)} 个")
        logger.info(f"   AI模型池: {self._model_pool} ({len(self._model_pool)} 个，{'启用' if self._ai_enabled else '纯引擎模式'})")
        logger.info(f"   Burp: {'✅ 可用' if self.burp_available else '❌ 不可用'}")
        logger.info("   并发上限: 40 任务, 8 QPS（保护模式）")
        logger.info("=" * 70)

    def _ensure_shared_knowledge(self) -> Dict[str, Dict]:
        shared = getattr(self.context, "shared_knowledge", None)
        if not isinstance(shared, dict):
            shared = {"tool_stats": {}, "experiences": [], "targets": {}}
            self.context.__dict__["shared_knowledge"] = shared
        shared.setdefault("tool_stats", {})
        shared.setdefault("experiences", [])
        shared.setdefault("targets", {})
        self.context.__dict__["shared_knowledge"] = shared
        return shared

    def _share_knowledge(self, tool_name: str = "", success: bool = True, detail: str = "") -> Dict[str, Dict]:
        shared = self._ensure_shared_knowledge()
        tool_key = tool_name or "unknown"
        stats = shared["tool_stats"].setdefault(tool_key, {"success": 0, "failure": 0})
        if success:
            stats["success"] += 1
        else:
            stats["failure"] += 1
        shared["targets"][self.target] = time.time()
        if detail:
            shared.setdefault("experiences", []).append({
                "target": self.target,
                "tool": tool_key,
                "success": bool(success),
                "detail": detail[:200],
                "timestamp": time.time(),
            })
        logger.debug(f"🔁 [OrchestratorKnowledge] tool={tool_key} success={success} stats={stats}")
        return shared

    async def _auto_tune(self) -> tuple:
        if self._user_max_tasks is not None and self._user_initial_qps is not None:
            return self._user_initial_qps, self._user_max_tasks

        score = 0
        try:
            logger.info("   📊 正在探测目标抗压能力...")
            status, body, headers = await async_get(self.target, session=self.session, timeout=10)

            cf_ray = headers.get('CF-Ray', '')
            server = headers.get('Server', '')
            x_powered = headers.get('X-Powered-By', '')

            if cf_ray or 'cloudflare' in server.lower():
                score += 20
                logger.info("      🔍 检测到 Cloudflare CDN (+20)")
            if 'akamai' in server.lower() or 'akamaitech' in server.lower():
                score += 20
                logger.info("      🔍 检测到 Akamai CDN (+20)")
            if 'fastly' in server.lower():
                score += 15
                logger.info("      🔍 检测到 Fastly CDN (+15)")
            if 'cloudfront' in server.lower() or 'aws' in server.lower():
                score += 15
                logger.info("      🔍 检测到 AWS CloudFront (+15)")

            if status == 200:
                score += 5
            if status in (403, 401):
                score += 3

            if 'java' in x_powered.lower() or 'jetty' in server.lower() or 'tomcat' in server.lower():
                score += 5
                logger.info("      🔍 检测到 Java 后端 (+5)")
            if 'go' in server.lower():
                score += 5
                logger.info("      🔍 检测到 Go 后端 (+5)")

            waf_headers = ['x-sucuri-id', 'x-akamai-transformed', 'x-iinfo', 'x-cdn', 'x-protected-by']
            for h in waf_headers:
                if h in headers:
                    score += 5
                    logger.info(f"      🔍 检测到 WAF 头部: {h} (+5)")
                    break

            if score >= 50:
                qps = min(8, 5 + score // 15)
                tasks = min(40, 20 + score // 5)
                level = "🚀 超大型站（极速模式，已限保护上限）"
            elif score >= 35:
                qps = min(6, 4 + score // 12)
                tasks = min(30, 15 + score // 6)
                level = "📈 大型站（高速模式）"
            elif score >= 20:
                qps = 4
                tasks = 20
                level = "📊 中型站（平衡模式）"
            else:
                qps = 2
                tasks = 15
                level = "🐢 小型站（保守模式）"

            logger.info(f"   ⚡ 自适应调速: {level}")
            logger.info(f"      📊 抗压分数: {score} 分 → QPS: {qps}, 并发任务: {tasks}")

            if self._user_initial_qps is not None:
                qps = self._user_initial_qps
            if self._user_max_tasks is not None:
                tasks = self._user_max_tasks

            return qps, tasks

        except Exception as e:
            logger.warning(f"   ⚠️ 自适应调速探测失败: {e}，使用保守默认值")
            return 2, 15

    def _force_gc(self):
        gc.collect()
        logger.debug("   🧹 主动 GC 释放内存")

    async def _safe_execute_task(self, task: Dict) -> Optional[Dict]:
        result = None
        try:
            result = await self._execute_task(task)
        except asyncio.CancelledError:
            logger.debug(f"⏹️ 任务被取消，重新入队: {task}")
            if task and hasattr(self.task_queue, 'retry_task'):
                await self.task_queue.retry_task(task.get('task_id', ''))
            raise
        except Exception as e:
            logger.warning(f"   ❌ 任务异常: {e}")
        finally:
            # 修复：移除 task.clear()。原代码在任务超时/取消后被 clear，
            # 但队列重排队的是同一个 dict 引用 → 重试执行的是"空任务"，
            # 每次空跑满 120s 超时，烧完重试预算后被丢弃（有效工作全部丢失）。
            self._task_counter += 1
            if self._task_counter % 20 == 0:
                self._force_gc()
        return result

    def _check_burp_sync(self):
        if not self.burp_client:
            self.burp_available = False
            logger.warning("⚠️ Burp 客户端未初始化")
            return

        try:
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    self.burp_available = True
                    logger.info("🔌 Burp 将在首次 API 调用时自动检测")
                    return
            except RuntimeError:
                pass

            self.burp_available = asyncio.run(self.burp_client.get_status())
        except Exception as e:
            logger.warning(f"⚠️ Burp 连接检测异常: {e}")
            self.burp_available = False

        if self.burp_available:
            logger.info("🔌 Burp 连接成功")
        else:
            logger.info("ℹ️ Burp 不可用，使用独立模式运行")

    def _get_model_pool(self) -> List[str]:
        """读取 AI 模型池（0~N 个）。

        AI_MODELS 为空或未配置 → 返回空列表 = 纯引擎模式，
        不调用任何 AI，扫描照常执行（AI 增强自动降级跳过）。
        """
        try:
            from vulnclaw.ai.core import get_configured_ai_models
            pool = get_configured_ai_models()
            if not pool:
                logger.info("ℹ️ 未配置 AI 模型（AI_MODELS 为空），进入纯引擎模式")
            return pool
        except Exception as e:
            logger.warning(f"加载模型池失败: {e}，使用默认模型")
            return getattr(settings, 'DEFAULT_AI_MODEL_CODES', ["1", "2", "4", "5"])

    def _models_for_task(self, task_type: str) -> List[str]:
        """P2-1: 任务类型 → 候选模型列表（router 推荐 ∩ 全局池）。

        verify→大模型(glm-4.7)、filter→小模型(glm-4-flash)，
        其余任务退回全局池轮询，保持既有行为。
        """
        try:
            from vulnclaw.ai.core import get_model_router
            router = get_model_router()
            preferred = router.get_models_for_task(task_type, max_models=3)
            candidates = [m for m in preferred if m in self._model_pool]
            if candidates:
                return candidates
        except Exception as e:  # noqa: BLE001
            logger.debug(f"任务模型路由失败，使用全局池: {e}")
        return list(self._model_pool)

    async def _get_next_model(self, task_type: str = "default") -> str:
        async with self._model_lock:
            if not self._model_pool:
                return ""

            candidates = self._models_for_task(task_type)
            for offset in range(len(candidates)):
                idx = (self._model_index + offset) % len(candidates)
                candidate = candidates[idx]
                if self._model_failures.get(candidate, 0) <= 3:
                    self._model_index = (idx + 1) % len(candidates)
                    self._model_stats[candidate] = self._model_stats.get(candidate, 0) + 1
                    return candidate

            # 任务候选全失败 → 退回全局池兜底
            for offset in range(len(self._model_pool)):
                idx = (self._model_index + offset) % len(self._model_pool)
                candidate = self._model_pool[idx]
                if self._model_failures.get(candidate, 0) <= 3:
                    self._model_index = (idx + 1) % len(self._model_pool)
                    self._model_stats[candidate] = self._model_stats.get(candidate, 0) + 1
                    return candidate

            for m in self._model_pool:
                self._model_failures[m] = 0
            self._model_stats[self._model_pool[0]] = self._model_stats.get(self._model_pool[0], 0) + 1
            return self._model_pool[0]

    async def _record_model_result(self, model: str, success: bool, error_msg: str = ""):
        async with self._model_lock:
            if success:
                self._model_failures[model] = max(0, self._model_failures.get(model, 0) - 1)
            else:
                self._model_failures[model] = self._model_failures.get(model, 0) + 1
                if self._model_failures[model] >= 5:
                    logger.warning(f"⚠️ 模型 {model} 连续失败 {self._model_failures[model]} 次，将暂时跳过")
        self._share_knowledge(f"model:{model}", success=success, detail=error_msg or "ok")

    async def _get_model_stats(self) -> Dict:
        async with self._model_lock:
            return {
                "total_calls": sum(self._model_stats.values()),
                "per_model": dict(self._model_stats),
                "failures": dict(self._model_failures),
            }

    async def get_rate_stats_cached(self) -> Dict:
        now = time.time()
        if self._rate_stats_cache is not None:
            ts, cached = self._rate_stats_cache
            if now - ts < self._stats_ttl:
                return cached
        async with self._stats_cache_lock:
            now = time.time()
            if self._rate_stats_cache is not None:
                ts, cached = self._rate_stats_cache
                if now - ts < self._stats_ttl:
                    return cached
            fresh = await self.rate_limiter.get_stats()
            self._rate_stats_cache = (now, fresh)
            return fresh

    async def get_model_stats_cached(self) -> Dict:
        now = time.time()
        if self._model_stats_cache is not None:
            ts, cached = self._model_stats_cache
            if now - ts < self._stats_ttl:
                return cached
        async with self._stats_cache_lock:
            now = time.time()
            if self._model_stats_cache is not None:
                ts, cached = self._model_stats_cache
                if now - ts < self._stats_ttl:
                    return cached
            fresh = await self._get_model_stats()
            self._model_stats_cache = (now, fresh)
            return fresh

    async def _penalize_task_models(self, task_type: str):
        """P2-1: 连续 2 次超时 → 临时拉黑该任务主模型（failures=5 跳过），自动降级更小模型。"""
        try:
            from vulnclaw.ai.core import get_model_router
            router = get_model_router()
            primary = router.recommend_primary_model(task_type)
            async with self._model_lock:
                if primary and primary in self._model_failures:
                    self._model_failures[primary] = max(self._model_failures.get(primary, 0), 5)
                    logger.warning(f"⏱️ [P2-1] 任务 {task_type} 连续 2 次超时，临时降级主模型 {primary}")
        except Exception as e:  # noqa: BLE001
            logger.debug(f"超时模型降级失败: {e}")

    async def _ask_ai(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.1,
        max_tokens: int = 2048,
        compress: bool = False,   # P1-2: 超长 Prompt 压缩为三元组
        use_cache: bool = False,  # P1-2: 语义缓存（1h TTL）
        task_type: str = "default",  # P2-1: verify→大模型 / filter→小模型
    ) -> str:
        """带总超时的 AI 调用入口。

        修复 attack 节点挂起：底层 client.ask 无外层超时（GLM-4.7 内层超时 3600s），
        429 退避 + 多模型 fallback 链最坏可阻塞数十分钟。这里包 90s 硬超时，
        超时直接抛错，由调用方的任务重试/引擎跳过逻辑兜底。
        """
        if not getattr(self, '_ai_enabled', True):
            raise RuntimeError("AI 未配置（纯引擎模式），跳过 AI 增强")
        if compress:
            prompt = compress_prompt(prompt)
        try:
            return await asyncio.wait_for(
                self._ask_ai_impl(prompt, system, temperature, max_tokens, use_cache=use_cache, task_type=task_type),
                timeout=90.0,
            )
        except asyncio.TimeoutError as exc:
            # P2-1: 连续 2 次超时 → 自动降级更小模型
            self._timeout_streaks[task_type] = self._timeout_streaks.get(task_type, 0) + 1
            if self._timeout_streaks[task_type] >= 2:
                self._timeout_streaks[task_type] = 0
                await self._penalize_task_models(task_type)
            raise RuntimeError(f"AI 调用总超时 (90s): {prompt[:60]}...") from exc

    async def _ask_ai_impl(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.1,
        max_tokens: int = 2048,
        use_cache: bool = False,  # P1-2
        task_type: str = "default",  # P2-1
    ) -> str:
        model = await self._get_next_model(task_type)
        fallback_model_name = model

        try:
            client = get_llm_client(force_new=False, models=[model])
            result = await client.ask(
                prompt,
                system=system,
                temperature=temperature,
                max_tokens=max_tokens,
                wrap_data=True,          # 安全加固
                retries=2,
                use_cache=use_cache,     # P1-2
            )
            await self._record_model_result(model, True)
            return result
        except Exception as e:
            await self._record_model_result(model, False, str(e))
            fallback_model = await self._get_next_model()
            if fallback_model != model:
                logger.warning(f"🔄 模型 {model} 失败，切换到 {fallback_model}")
                try:
                    client = get_llm_client(force_new=False, models=[fallback_model])
                    result = await client.ask(
                        prompt,
                        system=system,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        wrap_data=True,
                        retries=1
                    )
                    await self._record_model_result(fallback_model, True)
                    return result
                except Exception as e2:
                    await self._record_model_result(fallback_model, False, str(e2))
                    try:
                        client, provider_key, model_from_balancer = await self.balancer.get_client()
                        result = await client.ask(
                            prompt,
                            system=system,
                            temperature=temperature,
                            max_tokens=max_tokens,
                            wrap_data=True,
                            retries=1
                        )
                        await self._record_model_result(model_from_balancer, True)
                        return result
                    except Exception as e3:
                        await self._record_model_result(fallback_model_name, False, str(e3))
                        raise RuntimeError(f"所有模型调用失败（含负载均衡器）: {e3}")
            try:
                client, provider_key, model_from_balancer = await self.balancer.get_client()
                result = await client.ask(
                    prompt,
                    system=system,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    wrap_data=True,
                    retries=1
                )
                await self._record_model_result(model_from_balancer, True)
                return result
            except Exception as e3:
                await self._record_model_result(fallback_model_name, False, str(e3))
                raise RuntimeError(f"所有模型调用失败（含负载均衡器）: {e3}")

    def _ensure_engines(self):
        engine_classes = {
            "business_logic": BusinessLogicEngine,
            "api_version_diff": APIVersionDiffEngine,
            "request_smuggling": RequestSmugglingEngine,
            "http2_ws": HTTP2WebSocketEngine,
            "cache_poison": CachePoisonEngine,
        }
        for name, cls in engine_classes.items():
            if name not in self.engine_map:
                engine = cls()
                self.engines.append(engine)
                self.engine_map[name] = engine
                logger.info(f"   ➕ 添加增强引擎: {name}")

    def _init_multi_role(self):
        try:
            session_mgr = get_session_manager()
            if self.burp_available:
                target_domain = urlparse(self.target).netloc
                count = session_mgr.load_from_burp_plugin(target_domain=target_domain)
                if count > 0:
                    logger.info(f"👤 从Burp加载了 {count} 个角色的凭证")
                    return
            from vulnclaw.core.browser_cookie import get_browser_cookies
            domain = urlparse(self.target).netloc
            cookies = get_browser_cookies(domain)
            if cookies:
                session_mgr.set_default_cookies(cookies)
                session_mgr.add_session("default", cookie_dict=cookies)
                logger.info(f"🍪 从浏览器加载了 {len(cookies)} 个Cookie")
                return
            logger.info("ℹ️ 未检测到多角色会话，IDOR检测将跳过")
        except Exception:
            pass

    def _finding_verify_key(self, finding: Dict) -> tuple:
        """去重 key：与 _verify_all_findings / _add_finding 口径一致。"""
        return (
            str(finding.get('url', '')),
            str(finding.get('parameter', '')),
            str(finding.get('type', '')),
            str(finding.get('method', 'unknown')),
            str(finding.get('source', '')),
            # 再加一段短 evidence hash，避免"同一 param 同 engine 不同证据"被误合并去重。
            (str(finding.get('evidence', ''))[:80]).strip(),
        )

    # -------------------------------------------------------------------------
    # 流水线验证（stream-verify）：attack 节点边出 finding 边后台 verify。
    # 触发条件：(1) 新增后累计未处理 pending >= 动态预算；或 (2) 距上次触发 >= 3 秒。
    # 收尾阶段：stop(wait_pending=True) 会等所有存量 pending 跑完再返回。
    # -------------------------------------------------------------------------
    def _stream_budget(self) -> int:
        """P3-1: 动态批大小预算。

        公式：budget = min(50, 5 + len(pending)//10)；
        再结合 rate_limiter 令牌余量自适应——余量充足(+10) 放大批次，
        余量不足(//2) 收窄，避免高并发时每秒频繁触发 AI 调用。
        """
        try:
            pending_count = len(self._pending_verify)
        except Exception:
            pending_count = 0
        base = min(50, self._stream_budget_n + pending_count // 10)
        tokens = 50.0
        if self.rate_limiter is not None:
            try:
                tokens = float(self.rate_limiter.available_tokens())
            except Exception:
                tokens = 50.0
        if tokens >= 25:
            return min(50, base + 10)
        if tokens >= 10:
            return base
        return max(1, base // 2)

    def _start_stream_verify(self) -> None:
        """启动后台流式 verify 协程（幂等）。"""
        if self._stream_started or self._stream_stopped:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.debug("[StreamVerify] 当前没有运行的事件循环，跳过后台流式 verify 启动")
            return
        self._stream_started = True
        self._stream_task = loop.create_task(self._stream_verify_loop())
        logger.info(
            "🧪 [StreamVerify] 后台启动: batch≥动态预算(min(50,5+pending//10)+令牌自适应) 或 %.1fs 触发增量验证",
            self._stream_timeout_s,
        )

    async def _stop_stream_verify(self, wait_pending: bool = True) -> None:
        """停止流式 verify 协程，可选择等存量 pending 刷完。"""
        if self._stream_stopped:
            return
        if not self._stream_started or self._stream_task is None:
            self._stream_stopped = True
            if wait_pending:
                await self._stream_flush_pending(force_all=True, final_flush=True)
            return
        # 先把最后一批刷掉（含 final_flush 兜底），再停后台循环。
        if wait_pending:
            try:
                await asyncio.wait_for(self._stream_flush_pending(force_all=True, final_flush=True), timeout=900.0)
            except asyncio.TimeoutError:
                logger.warning("⏰ [StreamVerify] 收尾 flush 超时（900s），强制关闭后台协程")
            except Exception as exc:  # noqa: BLE001
                self._stream_errors += 1
                logger.warning("⚠️ [StreamVerify] 收尾 flush 异常: %s", exc)
        self._stream_stopped = True
        self._stream_event.set()  # 让 wait_for 立即退出
        task = self._stream_task
        self._stream_task = None
        if task is not None and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=10.0)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass
        logger.info(
            "🧪 [StreamVerify] 已停止: %s 条/%s 批处理, 去重集大小=%s, 错误=%s",
            self._stream_processed_count,
            self._stream_batches,
            len(self._stream_touched_keys),
            self._stream_errors,
        )

    async def _stream_notify_pending(self, just_added: int = 1) -> None:
        """`_execute_engine_check` 往 _pending_verify 追加 finding 后调用：唤醒后台 loop 做阈值判断。"""
        if not self._stream_started or self._stream_stopped:
            return
        # 阈值触发：当前待处理数达到动态 batch 上限 → 立即触发 flush。
        async with self._pending_verify_lock:
            pending_count = len(self._pending_verify)
            if pending_count >= self._stream_budget():
                self._stream_event.set()
                return
        # 否则 set event 让下一轮 sleep 可被打断；但通常 timeout 到点也会自动刷。
        self._stream_event.set()

    async def _stream_verify_loop(self) -> None:
        """后台协程：不断等 (budget 条件 or 3s timeout) 然后刷一批增量。"""
        try:
            while not self._stream_stopped:
                # 先尝试等 3 秒；如果 event 被设置，说明达到阈值或被显式唤醒。
                try:
                    await asyncio.wait_for(self._stream_event.wait(), timeout=self._stream_timeout_s)
                except asyncio.TimeoutError:
                    pass
                except asyncio.CancelledError:
                    raise
                except Exception:  # pragma: no cover - 事件 wait 本身不该抛
                    pass
                # 清 event 后执行一次增量 flush；如果 pending 仍然不够阈值，
                # flush 内部会按"至少取 1 条 + 已经 >= timeout_s" 的策略决定是否实际验证。
                self._stream_event.clear()
                if self._stream_stopped:
                    break
                try:
                    await self._stream_flush_pending(force_all=False, final_flush=False)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    self._stream_errors += 1
                    logger.warning("⚠️ [StreamVerify] 批次异常: %s", exc)
        except asyncio.CancelledError:
            logger.debug("[StreamVerify] 后台协程被 cancel")
            raise

    async def _stream_flush_pending(self, force_all: bool, final_flush: bool) -> None:
        """把 `_pending_verify` 中尚未被 stream 处理过的条目捞出来做增量验证。

        - `force_all=True` / `final_flush=True`：忽略 batch 阈值，一次性刷光当前全部 pending。
        - `force_all=False`：仅在 pending 累积 >= batch_size 时执行（定时触发也属于"强制刷一次"）。
        """
        # 1) 在 lock 下收集 fresh 批次，并同步标记 touched，避免并发 flush 重复处理。
        batch: List[Dict] = []
        async with self._pending_verify_lock:
            if not self._pending_verify:
                return
            if not force_all and not final_flush and len(self._pending_verify) < self._stream_budget():
                return
            for v in self._pending_verify:
                k = self._finding_verify_key(v)
                if k in self._stream_touched_keys:
                    continue
                self._stream_touched_keys.add(k)
                batch.append(v)
        if not batch:
            return

        self._stream_batches += 1
        self._stream_processed_count += len(batch)
        logger.info(
            "🧪 [StreamVerify] 增量批次 #%s: %s 条 (force_all=%s, final=%s)",
            self._stream_batches,
            len(batch),
            force_all,
            final_flush,
        )
        try:
            await self._stream_verify_batch(batch)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            self._stream_errors += 1
            logger.warning("⚠️ [StreamVerify] 批次 #%s 失败: %s", self._stream_batches, exc)

    async def _stream_verify_batch(self, batch: List[Dict]) -> None:
        """对一小批 pending 调用现有 cross-verify 流水线：
        直接复用 _verify_all_findings 入口，保证与收尾阶段完全一致的升级/HTTP/exploit 逻辑。
        为避免和 stop_stream_verify 并发时互相打架，这里再临时用 batch 替换 pending 列表。
        """
        # 保存 & 替换：让 _verify_all_findings 只处理这批增量。
        # 修复：_stream_flush_pending 在收集批次时就已把条目加入 _stream_touched_keys，
        # 而 _verify_all_findings 会跳过 touched 条目 → stream 批次从未真正验证
        # （表现为"增量批次 #N: X 条"后紧跟"收尾阶段跳过 X 条"，finding 全部丢失）。
        # 验证前临时摘除 batch keys，验证后恢复，收尾阶段仍不会重复处理。
        batch_keys = {self._finding_verify_key(v) for v in batch}
        async with self._pending_verify_lock:
            saved_pending = list(self._pending_verify)
            self._pending_verify = list(batch)
            self._stream_touched_keys -= batch_keys
        try:
            await self._verify_all_findings()
        finally:
            async with self._pending_verify_lock:
                self._stream_touched_keys |= batch_keys
                # 合并回：保留原始 pending 的顺序（因为我们不会从中删 touched，只是为了未来 debug 完整）。
                # 注意：_verify_all_findings 内部不会清空 _pending_verify，因此这里简单 restore 即可。
                # 把 batch 中原本在 saved_pending 里的元素也放回去（为了保持后续调试信息一致）。
                merged: List[Dict] = list(saved_pending)
                seen_keys = {self._finding_verify_key(v) for v in merged}
                for v in batch:
                    if self._finding_verify_key(v) not in seen_keys:
                        merged.append(v)
                self._pending_verify = merged

    def _add_finding(self, finding: Dict):
        key = (
            finding.get('url', ''),
            finding.get('parameter', ''),
            finding.get('type', ''),
            finding.get('method', 'unknown')
        )
        if key not in self._finding_keys:
            self._finding_keys.add(key)
            # 轨道2 2.1/2.2: 统一后处理（复现信息 + 双源确认标记），避免逐引擎改造
            try:
                self._enrich_finding(finding)
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"finding 后处理跳过: {exc}")
            self.findings.append(finding)
            try:
                get_metrics().inc_vuln(
                    str(finding.get('severity', 'unknown')) or 'unknown',
                    str(finding.get('type', 'unknown')) or 'unknown',
                )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 轨道2 2.1: PoC 复现信息（reproduction_steps + curl_command）
    # ------------------------------------------------------------------
    _REPRO_EXPECTATION = {
        "sqli": "响应出现数据库报错（如 You have an error in your SQL syntax）或布尔/延时差异",
        "nosql": "响应出现 NoSQL 报错，或条件恒真/恒假返回不同",
        "xss": "payload 原样回显且未转义（查看页面源码确认未被编码）",
        "cmdi": "响应中包含命令执行结果（如 uid=0(root) 或 whoami 输出）",
        "rce": "响应中包含命令执行结果（如 uid=0(root)）",
        "lfi": "响应中包含目标文件内容（如 /etc/passwd 的 root:x:0:0）",
        "rfi": "远程文件内容被包含并在服务端执行",
        "ssrf": "服务端发起对外请求（OOB/DNS 回调或内网响应回显）",
        "xxe": "外部实体内容被解析回显或产生 OOB 回调",
        "ssti": "模板表达式被求值（如 {{7*7}} → 49）",
        "el_injection": "EL/SpEL 表达式被求值（如 ${7*7} → 49）",
        "deserialization": "反序列化被触发（延时 / OOB 回调 / 命令执行迹象）",
        "open_redirect": "响应 301/302 且 Location 指向外部域名",
        "idor": "可访问或篡改其他用户对象的资源",
        "file_upload": "上传文件可被访问且在服务端被解析执行",
        "jwt": "伪造/篡改的 token 被服务端接受",
        "oauth": "redirect_uri / state 校验被绕过",
        "cors": "Access-Control-Allow-Origin 反射任意 Origin 且允许凭证",
        "crlf": "响应头被注入（Set-Cookie 或自定义头）",
        "host_header": "Host 头被反射进链接或缓存键",
        "cache_poison": "缓存被写入恶意内容，其他用户可命中",
        "graphql": "GraphQL 内省/注入查询返回预期数据",
        "info_leak": "响应中包含敏感信息（路径 / 堆栈 / 密钥）",
        "security_headers": "缺失关键安全响应头（CSP / HSTS / X-Frame-Options）",
        "race_condition": "并发请求导致状态不一致（超额 / 重复提交）",
        "business_logic": "业务逻辑校验被绕过（金额 / 数量 / 权限）",
        "ldap": "LDAP 查询被注入，返回非预期条目",
        "xpath": "XPath 表达式被注入，返回非预期节点",
        "hpp": "同名参数被拼接，服务端行为与预期不一致",
        "smuggling": "前后端解析不一致，请求被走私",
    }

    @staticmethod
    def _sh_quote(value: str) -> str:
        """shell 单引号安全转义（payload 常含引号，直接拼接会破坏命令）。"""
        return "'" + str(value).replace("'", "'\\''") + "'"

    def _expected_observation(self, finding: Dict) -> str:
        """2.1: 按漏洞类型给出"预期现象"描述。"""
        vtype = str(finding.get("type", "")).lower()
        for key, expect in self._REPRO_EXPECTATION.items():
            if key in vtype:
                return expect
        return "响应与正常基线出现显著差异（对比状态码 / 长度 / 内容）"

    def _build_repro_url(self, finding: Dict) -> str:
        """2.1: 构造复现 URL（GET 时把 payload 注入目标参数）。"""
        url = str(finding.get("url") or self.target or "").strip()
        param = finding.get("parameter") or finding.get("param") or ""
        payload = str(finding.get("payload") or "")
        method = str(finding.get("method") or "GET").upper()
        if not param or not payload or method != "GET":
            return url
        try:
            from vulnclaw.core.utils import build_attack_url

            base, _, query = url.partition("?")
            return build_attack_url(base, param, payload, query)
        except Exception:  # noqa: BLE001
            return url

    def _request_cookie_header(self) -> str:
        """2.1: 提取复现所需的 Cookie（会话 + Burp 抓取）。"""
        cookies: Dict[str, str] = {}
        try:
            burp_cookies = (self._recon_brief or {}).get("burp_cookies") or {}
            if isinstance(burp_cookies, dict):
                cookies.update({str(k): str(v) for k, v in burp_cookies.items()})
        except Exception:  # noqa: BLE001
            pass
        try:
            if self.session is not None and getattr(self.session, "cookies", None):
                for k, v in self.session.cookies.items():
                    cookies.setdefault(str(k), str(v))
        except Exception:  # noqa: BLE001
            pass
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def _build_curl_command(self, finding: Dict, attack_url: str) -> str:
        """2.1: 生成可直接复制执行的 curl 复现命令。"""
        method = str(finding.get("method") or "GET").upper()
        if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            method = "GET"
        param = finding.get("parameter") or finding.get("param") or ""
        payload = str(finding.get("payload") or "")

        parts = [f"curl -i -s -k -X {method}", self._sh_quote(attack_url)]

        if method != "GET" and param and payload:
            parts.append(f"--data-urlencode {self._sh_quote(f'{param}={payload}')}")
        elif method != "GET":
            parts.append(f"--data {self._sh_quote(finding.get('data', '') or '')}")

        for header_key, header_val in (finding.get("headers") or {}).items():
            if str(header_key).lower() in ("cookie", "content-length", "host"):
                continue
            parts.append(f"-H {self._sh_quote(f'{header_key}: {header_val}')}")

        if getattr(settings, "report_include_cookie", True):
            cookie = self._request_cookie_header()
            if cookie:
                parts.append(f"-H {self._sh_quote(f'Cookie: {cookie}')}")

        return " ".join(p for p in parts if p)

    def _enrich_finding(self, finding: Dict) -> Dict:
        """轨道2 2.1/2.2: 为单条 finding 补齐复现信息与双源确认标记。"""
        attack_url = self._build_repro_url(finding)
        curl = self._build_curl_command(finding, attack_url)
        method = str(finding.get("method") or "GET").upper()
        param = finding.get("parameter") or finding.get("param") or ""
        payload = str(finding.get("payload") or "")
        expected = self._expected_observation(finding)

        finding.setdefault("curl_command", curl)
        finding.setdefault("reproduction", {
            "method": method,
            "url": attack_url,
            "parameter": param,
            "payload": payload,
            "expected": expected,
        })
        finding.setdefault("reproduction_steps", [
            f"1. 以 {method} 方法请求: {attack_url}"
            + (f"（参数 {param} 赋值为 payload）" if param and payload else ""),
            f"2. 注入 Payload: {payload[:300]}" if payload else "2. 无需额外 payload，直接请求目标 URL",
            f"3. 预期现象: {expected}",
            f"4. 复现命令（可直接复制执行）: {curl}",
        ])

        # 轨道2 2.2: 双源确认（引擎命中 + Burp 独立确认）
        burp_ok = bool(finding.get("burp_confirmed") or finding.get("burp_verified"))
        if burp_ok:
            finding["cross_confirmed"] = True
            sources = [str(s) for s in (finding.get("confirmation_sources") or [])]
            if "burp" not in sources:
                sources.append("burp")
            primary = str(finding.get("engine") or finding.get("type") or "engine")
            if primary not in sources:
                sources.insert(0, primary)
            finding["confirmation_sources"] = sources
        else:
            finding.setdefault("cross_confirmed", False)
        return finding

    async def run(self) -> Dict:
        # P4-3: 后台更新 Nuclei 模板（不阻塞扫描启动，收尾时回收）
        self._nuclei_update_task = None
        try:
            from vulnclaw.modules.vuln_scanner.cve_nuclei import update_nuclei_templates

            self._nuclei_update_task = asyncio.create_task(update_nuclei_templates())
        except Exception as exc:
            logger.debug(f"Nuclei 模板更新任务未启动: {exc}")
        try:
            auto_qps, auto_tasks = await self._auto_tune()

            # SPA 检测（延迟到异步上下文执行，不阻塞 __init__）
            try:
                if getattr(self, "_spa_detector", None) is not None:
                    await self._spa_detector.detect(self.target)
            except Exception as _se:  # noqa: BLE001
                logger.debug(f"SPA 检测失败（不影响扫描）: {_se}")

            self.initial_qps = auto_qps
            self.max_tasks = auto_tasks

            self.rate_limiter = get_rate_limiter(self.initial_qps)
            self.batch_processor = BatchProcessor(max_batch_size=5)
            self.local_filter = get_local_filter()
            self.task_queue = SmartTaskQueue(max_size=2000)

            self.balancer.init_clients(self.rate_limiter)

            self._model_to_provider = {}
            for provider_key, config in self.balancer.providers.items():
                if config.get("client") is not None:
                    model_name = config.get("model")
                    if model_name:
                        self._model_to_provider[model_name] = provider_key
            if self._model_to_provider:
                logger.info(f"   📋 模型-Provider映射: {self._model_to_provider}")

            try:
                loop = asyncio.get_running_loop()
                self.memory = await asyncio.wait_for(
                    loop.run_in_executor(None, get_memory),
                    timeout=60.0
                )
            except (asyncio.TimeoutError, Exception):
                logger.warning("⚠️ ChromaDB 初始化超时，降级到内存模式")
                self.memory = None

            await self._recon()
            await self._generate_tasks()
            # 在任务执行之前启动流水线验证后台协程，任务边产出 finding 边验证。
            self._start_stream_verify()
            await self._execute_with_limiting()

            # S2: 跨引擎攻击链路由——基于 S2.1 链信息把已确认发现串成后续动作
            #（SSRF->内网探测/Redis 未授权，文件上传/LFI->RCE 链）。
            await self._run_chain_router()

            # S1: ReActAgent 深挖阶段（插桩点：_generate_tasks 之后、全局扫描之前）。
            # 对 engine_bundle 首次执行结果全部 low/info 或判定模糊的参数，
            # 用 ReActAgent 做多轮深度渗透（V100=广度覆盖，ReAct=单点深度）。
            await self._run_react_deep_dive()

            # 步骤3：并行提交 Burp 扫描（与下面各全局扫描同时进行，收尾前合并结果）
            self._burp_scan_task = asyncio.create_task(self._run_burp_scan())

            if self._collaborator_domain:
                await self._check_collaborator_callback()

            if self._enable_idor:
                await self._scan_idor()

            if self._enable_default_creds:
                await self._check_default_creds()

            if self._enable_business_logic:
                await self._run_business_logic_scan()
            if self._enable_api_version:
                await self._run_api_version_scan()
            if self._enable_smuggling:
                await self._run_smuggling_scan()
            if self._enable_http2_ws:
                await self._run_http2_ws_scan()
            await self._run_cache_poison_scan()

            # 步骤3：等待并行 Burp 扫描完成并合并其结果
            if self._burp_scan_task is not None:
                try:
                    await self._burp_scan_task
                except Exception as e:
                    logger.warning(f"⚠️ Burp 扫描任务异常: {e}")
                finally:
                    self._burp_scan_task = None

            # 等所有流式 verify 把存量 pending 跑完；再收尾剩余未被流式 pick 的。
            await self._stop_stream_verify(wait_pending=True)
            await self._verify_all_findings()

            self._force_gc()
            await self._finalize_nuclei_update()
            # S3.1: 扫描收尾——把本次关键发现写入 VectorMemory（跨会话学习）
            await self._persist_scan_memory()
            return await self._generate_report()
        except Exception as e:
            logger.error(f"扫描过程中发生错误: {e}")
            import traceback
            traceback.print_exc()
            await self._finalize_nuclei_update()
            # S3.1: 扫描收尾——把本次关键发现写入 VectorMemory（跨会话学习）
            await self._persist_scan_memory()
            return await self._generate_report()

    async def _finalize_nuclei_update(self) -> None:
        """P4-3: 回收 Nuclei 模板更新后台任务（最多再等 5s）。"""
        task = getattr(self, "_nuclei_update_task", None)
        if task is None:
            return
        try:
            if not task.done():
                await asyncio.wait_for(asyncio.shield(task), timeout=5)
        except Exception:
            task.cancel()
        finally:
            self._nuclei_update_task = None

async def run_v100_scan(target: str, session, max_tasks: int = None, initial_qps: int = None) -> Dict:
    system = V100Orchestrator(target, session, max_tasks, initial_qps)
    return await system.run()

__all__ = ['V100Orchestrator', 'run_v100_scan']
