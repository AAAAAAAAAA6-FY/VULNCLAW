# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""v100 orchestrator facade and public scan entry point."""
import asyncio
import contextlib
import gc
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from vulnclaw.core.logger import logger
from vulnclaw.core.context import get_scan_context
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, vuln_category
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
from vulnclaw.modules.live_intake import LiveIntake, drain_pending, set_live_intake
class V100Orchestrator:
    """v100 facade coordinating the scan phases."""
    _safe_params = {
        'callback', '_', 'timestamp', 'nonce', 'version', 'format',
        'cors', 't', 'v', 'ver', 'ts', 'time', 'rand', 'random',
        'session', 'token', 'csrf', 'authenticity_token', 'utf8'
    }

    def __init__(self, target: str, session, max_tasks: int = None, initial_qps: int = None, resume: bool = False):
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
        # E4: 早停——参数已确认高危/严重漏洞则跳过剩余引擎（减少无效调用）
        self._confirmed_params: set = set()
        self._confirmed_categories: Dict = {}
        # E1: 增量扫描——记录已扫 (engine, target, param)，下次运行跳过
        self._incremental_scanned: set = set()
        try:
            import os as _os
            import json as _json
            if getattr(settings, "incremental_scan", False):
                _ip = getattr(settings, "incremental_state_file", "") or ""
                if _ip and _os.path.exists(_ip):
                    with open(_ip, "r", encoding="utf-8") as _f:
                        _loaded = _json.load(_f)
                    for _k in _loaded:
                        if isinstance(_k, (list, tuple)) and len(_k) == 3:
                            self._incremental_scanned.add(tuple(_k))
        except Exception:
            logger.debug("suppressed exception (core audit)")
        # P5-1: SQLite 断点续扫存储（A4.6 落地）
        # 每个 target 一个确定性 DB：PROJECT_CACHE_DIR/persistence/<safe_target>.db
        self._resume = bool(resume)
        self._resume_stage_index = -1
        self._resume_skip_done = False   # 续扫时主循环跳过已扫 (engine,target,param)
        self._checkpoint = None
        try:
            from vulnclaw.core_modules.sqlite_persistence import (
                SqliteCheckpointStore,
                db_path_for_target,
            )
            self._checkpoint = SqliteCheckpointStore(db_path_for_target(self.target))
            if self._resume:
                _info = self._checkpoint.resume_info()
                if _info.get("should_resume"):
                    self._resume_stage_index = int(_info["stage_index"])
                    logger.info(
                        f"♻️ [P5-1 续扫] 检测到断点: 已完成阶段 #{self._resume_stage_index}，"
                        f"将从下一阶段恢复（kill -9 不重扫已完成阶段）"
                    )
                else:
                    logger.info(f"ℹ️ [P5-1 续扫] 无有效断点（{_info.get('reason','')}），按全新扫描进行")
            else:
                # 非续扫模式：清空可能存在的上一次残留检查点，保证全新起点
                self._checkpoint.reset()
                self._checkpoint.init_scan(scan_id="", target=self.target)
        except Exception as _e:  # noqa: BLE001
            logger.warning(f"⚠️ [P5-1] 检查点存储初始化失败（降级为无持久化）: {_e}")
            self._checkpoint = None
        # S1: engine_bundle 首次执行结果（param -> [result, ...]），供 ReAct 深挖判断模糊参数
        self._bundle_results: Dict[str, List[Dict]] = {}
        self._start_time = time.time()
        self._total_engine_calls = 0
        # G4 可观测性：每引擎统计（调用/命中/超时/错误/耗时）+ 每阶段耗时
        self._engine_metrics: Dict[str, Dict] = {}
        self._phase_timings: Dict[str, float] = {}
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
                logger.debug("suppressed exception (core audit)")

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
        usage_site: str = "",  # A4.4/SP8: 成本台账调用点标签
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
                self._ask_ai_impl(prompt, system, temperature, max_tokens, use_cache=use_cache, task_type=task_type, usage_site=usage_site),
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
                usage_site=usage_site or None,  # A4.4/SP8: 成本台账调用点
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
                        retries=1,
                        usage_site=usage_site or None,
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
                            retries=1,
                            usage_site=usage_site or None,
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
                    retries=1,
                    usage_site=usage_site or None,
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
            logger.debug("suppressed exception (core audit)")

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
                logger.debug("suppressed exception (core audit)")
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
                    logger.debug("suppressed exception (core audit)")
                except asyncio.CancelledError:
                    raise
                except Exception:  # pragma: no cover - 事件 wait 本身不该抛
                    logger.debug("suppressed exception (core audit)")
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
                # 关键修复（漏检根因）：验证期间 phases_executor 会无锁 append 新 finding 到
                # 临时替换的 list(batch) 上，若仅重建 saved_pending 会把这些新条目静默丢弃
                # （SQLi 在批次验证窗口排队 → finally 重建后条目标记丢失 → 不进最终报告）。
                # 因此先取回临时 list 的当前内容，与 saved_pending / batch 合并去重。
                transient_items = list(self._pending_verify)
                merged: List[Dict] = list(saved_pending)
                seen_keys = {self._finding_verify_key(v) for v in merged}
                for v in [*batch, *transient_items]:
                    if self._finding_verify_key(v) not in seen_keys:
                        merged.append(v)
                        seen_keys.add(self._finding_verify_key(v))
                self._pending_verify = merged


    @staticmethod
    def _classify_finding_verdict(finding: Dict) -> str:
        """C4-C10 三档分级：confirm / likely / suspicious。

        严格低误报优先，规则保持可解释：
        1) 硬实锤（exploited / burp_verified / cross_confirmed / OOB 回调）或
           高置信(高/high/>=90)且 ai_verdict=真实漏洞  -> confirm；
        2) ai_verdict=真实漏洞 且置信中等（中/medium）  -> likely（需人工复核，概率较高）；
        3) 其余（待人工复核 / 已跳过 / 预算已满 / 低优先级 / 非漏洞 / low）-> suspicious。
        """
        if finding.get("verdict"):
            return finding["verdict"]
        if (
            finding.get("exploited")
            or finding.get("burp_verified")
            or finding.get("cross_confirmed")
            or finding.get("oob_confirmed")
            or finding.get("collaborator_callback")
        ):
            return "confirm"
        verdict = str(finding.get("ai_verdict", ""))
        if (
            "待人工复核" in verdict
            or "已跳过" in verdict
            or "预算已满" in verdict
            or "低优先级" in verdict
        ):
            return "suspicious"
        is_real = "真实漏洞" in verdict
        conf = finding.get("confidence")
        if isinstance(conf, int) and conf >= 90:
            return "confirm"
        if isinstance(conf, str):
            base_conf = conf.split("（")[0].split(" (")[0].strip().lower()
            if base_conf in ("高", "high"):
                return "confirm" if is_real else "suspicious"
            if base_conf.startswith("中") or base_conf == "medium":
                return "likely" if is_real else "suspicious"
            return "suspicious"
        return "likely" if is_real else "suspicious"
    def _add_finding(self, finding: Dict):
        try:
            finding["verdict"] = self._classify_finding_verdict(finding)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"verdict 分级失败，跳过: {exc}")
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
            # SP16.1 回注：产出 finding → bandit 正样本（默认关，无代价）
            if self._bandit is not None:
                try:
                    self._bandit.record(self._bandit.key_from_finding(finding), hit=True)
                except Exception:  # noqa: BLE001
                    logger.debug("[SP16.1] bandit hit 回注失败，跳过", exc_info=True)
            # P5-1: 增量持久化 finding 到 SQLite 检查点（kill -9 不丢，续扫自动并入）
            if getattr(self, "_checkpoint", None) is not None:
                try:
                    self._checkpoint.add_finding(finding)
                except Exception:  # noqa: BLE001
                    logger.debug("suppressed exception (core audit)")
            # E4: 记录已确认高危/严重漏洞的参数（按大类），供早停跳过“同类”剩余引擎
            try:
                if str(finding.get('severity', '')).lower() in ('high', 'critical'):
                    _cp = (finding.get('url', ''), finding.get('parameter', ''))
                    self._confirmed_params.add(_cp)
                    self._confirmed_categories.setdefault(_cp, set()).add(
                        vuln_category(finding.get('type', '') or finding.get('engine', ''))
                    )
            except Exception:
                logger.debug("suppressed exception (core audit)")
            try:
                get_metrics().inc_vuln(
                    str(finding.get('severity', 'unknown')) or 'unknown',
                    str(finding.get('type', 'unknown')) or 'unknown',
                )
            except Exception:
                logger.debug("suppressed exception (core audit)")

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
            logger.debug("suppressed exception (core audit)")
        try:
            if self.session is not None and getattr(self.session, "cookies", None):
                for k, v in self.session.cookies.items():
                    cookies.setdefault(str(k), str(v))
        except Exception:  # noqa: BLE001
            logger.debug("suppressed exception (core audit)")
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

    def _record_engine_metric(self, name: str, elapsed: float, hit: bool, timeout: bool = False, error: bool = False) -> None:
        m = self._engine_metrics.setdefault(
            name, {"calls": 0, "hits": 0, "timeouts": 0, "errors": 0, "total_time": 0.0}
        )
        m["calls"] += 1
        m["total_time"] += elapsed
        if hit:
            m["hits"] += 1
        if timeout:
            m["timeouts"] += 1
        if error:
            m["errors"] += 1

    def _emit_metrics(self, report: Optional[Dict] = None) -> None:
        """G4 可观测性：扫描结束输出指标（落盘 _runtime_cache/metrics/ + 日志摘要）。"""
        try:
            import time as _t
            from vulnclaw.paths import RUNTIME_DIR
            from pathlib import Path
            from vulnclaw.core.utils import _atomic_write_json
            metrics_dir = Path(str(RUNTIME_DIR)) / "metrics"
            metrics_dir.mkdir(parents=True, exist_ok=True)
            metrics = {
                "target": self.target,
                "scan_duration_s": round(_t.time() - self._start_time, 2),
                "total_engine_calls": self._total_engine_calls,
                "total_findings": len(self.findings),
                "ai_cost_usd": self._ai_cost_usd(),
                "engine_metrics": self._engine_metrics,
                "phase_timings": self._phase_timings,
                "model_stats": self._model_stats,
            }
            _atomic_write_json(metrics_dir / f"metrics_{_t.strftime('%Y%m%d_%H%M%S')}.json", metrics)
            logger.info(
                f"📊 扫描指标已落盘 metrics/: 引擎调用 {metrics['total_engine_calls']} 次 / "
                f"命中 {metrics['total_findings']} / 耗时 {metrics['scan_duration_s']}s"
            )
        except Exception as _me:
            logger.debug(f"指标落盘失败（不影响扫描）: {_me}")

    def _ai_cost_usd(self) -> float:
        """C1 成本核算：从 LLM 客户端单例的 TokenBudget 取累计成本（美元）。"""
        try:
            from vulnclaw.ai.core import get_llm_client
            client = get_llm_client()
            return round(float(getattr(client.budget, "cost_estimate", 0.0)), 4)
        except Exception:
            return 0.0

    def _maybe_trip_cost_breaker(self) -> None:
        """C3: AI 成本预算熔断。扫描阶段累计成本超预算则降级为纯引擎模式（ai_mode=0），防失控。"""
        if not getattr(settings, "ai_cost_circuit_breaker", True):
            return
        try:
            cost = self._ai_cost_usd()
        except Exception:
            return
        if cost > getattr(settings, "ai_cost_budget_usd", 0.5):
            logger.warning(
                f"💸 [C3 熔断] AI 累计成本 ${cost:.4f} 超预算 "
                f"${getattr(settings, 'ai_cost_budget_usd', 0.5):.4f}，降级为纯引擎模式（ai_mode=0）"
            )
            settings.ai_mode = 0

    def _save_incremental_state(self) -> None:
        """E1: 增量扫描——把本次已扫 (engine, target, param) 落盘，供下次运行跳过。"""
        try:
            if not getattr(settings, "incremental_scan", False):
                return
            _ip = getattr(settings, "incremental_state_file", "") or ""
            if not _ip:
                return
            from pathlib import Path
            from vulnclaw.core.utils import _atomic_write_json
            _data = [list(k) for k in self._incremental_scanned]
            _atomic_write_json(Path(_ip), _data)
        except Exception as _e:  # noqa: BLE001
            logger.debug(f"   [增量] 状态保存失败（忽略）: {_e}")

    async def _save_target_profile_a32(self) -> None:
        """A3.2: 目标画像持久化——recon brief → 指纹画像落库，下次增量只测变化面。

        复用 IncrementalSaver.save_target_profile（此前零调用的预留 API）。
        只在 incremental_scan 开启时写入；失败静默（不影响扫描主流程）。
        """
        try:
            if not getattr(settings, "incremental_scan", False):
                return
            brief = getattr(self, "_recon_brief", None)
            if not brief:
                return
            from vulnclaw.core_modules.asset_profile import build_asset_profile, save_profile

            profile = build_asset_profile(self.target, brief)
            await save_profile(self.target, profile)
            logger.info(
                f"   🗃️ [A3.2] 目标画像已落库: {len(profile.get('assets', {}))} 个端点指纹"
                f"（TTL {getattr(settings, 'asset_profile_ttl_hours', 168.0)}h）"
            )
        except Exception as _e:  # noqa: BLE001
            logger.debug(f"   [A3.2] 画像保存失败（忽略）: {_e}")

    async def _run_agent_coordinator(self) -> None:
        """P2-1: 多智能体协调器（strix 式可寻址 agent 树）——可选增强通道。

        默认关闭（settings.agent_coordinator_enabled=False），开启后作为主链路之外的
        补充深扫：把目标交给 AgentCoordinator 派生 recon/analysis/exploit/verify 子 agent
        并发执行，复用确定性引擎（Tier-1）并把发现合并进 findings。任何异常都被吞掉，
        绝不影响主链路出报告。
        """
        if not getattr(settings, "agent_coordinator_enabled", False):
            return
        try:
            from vulnclaw.ai.dispatcher import AgentCoordinator
            coord = AgentCoordinator(self.target, self.session)
            # P6-2: 开跑前召回目标历史经验（同指纹跨会话学习），收尾沉淀本次成果
            await coord.recall_memory()
            await coord.coordinate()
            coord.bridge_into(self)  # 把多 agent 共享知识（含 recon 产出）并入 findings/黑板
            await coord.persist_memory()
            logger.info(
                f"🌲 [AgentCoordinator] 完成: agents={len(coord.nodes)}, "
                f"snapshot={coord.snapshot.version}, 黑板={coord.snapshot.blackboard.digest()}"
            )
        except Exception as e:
            logger.warning(f"⚠️ [AgentCoordinator] 执行失败（不影响主链路）: {e}")

    async def _feed_live_intake(self) -> None:
        """SP15.3 D4.2: recon 采集端点 -> 实时补测任务入队（开关默认关, 零行为回归）。

        仅喂 crawler 采集结果（crawled_endpoints）；浏览器流/Burp 流由各自
        写入点回注（后续增强）。评分不达标/重复注入面由 LiveIntake 内部滤除。
        """
        try:
            if not getattr(settings, "live_intake_enabled", False):
                return
            if getattr(self, "_live_intake", None) is None:
                return
            brief = self._recon_brief or {}
            fed = 0
            # R2-A S1: 浏览器 render 流 / Burp 流量流回注的待入队任务（本轮统一入队）
            for td in drain_pending():
                await self.task_queue.add_task(td, td.get("priority", 8))
                fed += 1
            for ep in brief.get("crawled_endpoints", []) or []:
                if not isinstance(ep, dict) or not ep.get("url"):
                    continue
                params = {k: "" for k in (ep.get("params") or [])}
                tasks = self._live_intake.hit(
                    url=str(ep["url"]), source="crawl", params=params)
                if not tasks:
                    continue
                for td in tasks:
                    await self.task_queue.add_task(td, td["priority"])
                    fed += 1
            if fed:
                logger.info(f"   [SP15.3] 实时补测: 采集->任务 {fed} 条联邦入队")
        except Exception:
            logger.warning("[SP15.3] live intake feed 失败，跳过", exc_info=True)

    async def _run_react_gated_deep_dive(self) -> None:
        """S1: ReActAgent 深挖阶段门卫入口（V100 主链路插桩，插在 taskgen 之后、全局扫描之前）。

        S1.1：deep 开启（settings.enable_react_dive，由 --deep / ENABLE_REACT_DIVE 触发）时，
              输出阶段节点日志 [S1] 深度挖掘（段前缀标识），作为深挖阶段起点节点。
        S1.2：agent 执行前过 danger_guard——deep 深挖属探测级；danger 放行配置缺失
              （默认 deny，未显式 --dangerous）时自动降级为本地确定性兜底：
              跳过 LLM 多轮深挖，但绝不中断扫描（复用 danger_guard 默认 deny=步骤跳过、
              扫描继续 语义）。
        S1.3：深挖 finding 由 orchestrator._add_finding 回写并标记 source=react_agent
              （见 phases_executor._merge_react_findings），与引擎来源（engine）区分，
              进入 verify 与报告；不破坏既有 finding 结构，source 为新增可选字段。
        """
        if not getattr(settings, "enable_react_dive", False):
            # 未开启 deep：保持与现状完全一致，交给 _run_react_deep_dive 打印"未开启"后返回。
            return await self._run_react_deep_dive()
        logger.info(
            "[S1] 深度挖掘 阶段启动（ReActAgent 单点深度：V100=广度覆盖，ReAct=深度推理）"
        )
        if not self._deep_dive_danger_allowed():
            logger.warning(
                "[S1] 深度挖掘 danger_guard 未放行，降级为本地确定性兜底（扫描继续，不启用 LLM 深挖）"
            )
            return None
        return await self._run_react_deep_dive()

    def _deep_dive_danger_allowed(self) -> bool:
        """S1.2: deep 深挖属探测级——执行前咨询 danger_guard。

        返回 True=放行 LLM 深挖；False=降级为本地确定性兜底。
        danger 放行配置缺失（默认 deny）或 danger_guard 异常时一律返回 False，
        绝不中断扫描。复用 DANGEROUS_OPS 中已有的单点深度渗透 op 作审批键。
        """
        try:
            from vulnclaw.core.danger_guard import guard
            return bool(
                guard.require_approval(
                    'remote_deep_penetrate',
                    detail=f"V100 主链路 ReAct 深挖 target={getattr(self, 'target', '')}",
                )
            )
        except Exception:  # noqa: BLE001
            logger.debug("[S1] danger_guard 不可用，按 deny 处理（降级本地确定性兜底）")
            return False

    # ============================================================
    # P5-1: 断点续扫阶段定义 + 阶段检查点上下文管理器
    # 阶段顺序即 run() 执行顺序；每一阶段在开始前写 start、结束后写 done，
    # 续扫时已完成阶段（index <= _resume_stage_index）整段跳过。
    # ============================================================
    _STAGES = [
        "recon",            # 侦察
        "taskgen",          # 任务生成
        "scan",             # 主扫描循环（引擎广覆盖）
        "chain_router",     # 跨引擎攻击链路由
        "react_deep_dive",  # ReAct 深挖
        "agent_coordinator",# 多智能体协调器（可选）
        "extras",           # Burp/IDOR/默认凭证/业务逻辑/... 补充扫描
        "verify",           # 验证 + 报告前收尾
        "report",           # 报告生成
    ]

    @contextlib.asynccontextmanager
    async def _stage(self, name: str):
        """阶段检查点上下文管理器。

        yield 值：True=本段实际执行；False=续扫跳过（已完成）。
        """
        idx = self._STAGES.index(name)
        if self._checkpoint is not None and self._resume and idx <= self._resume_stage_index:
            logger.info(f"♻️ [P5-1] 跳过已完成阶段: {name} (#{idx})")
            yield False
            return
        if self._checkpoint is not None:
            try:
                self._checkpoint.save_stage_start(idx, name)
            except Exception:  # noqa: BLE001
                logger.debug("suppressed exception (core audit)")
        try:
            yield True
        finally:
            if self._checkpoint is not None:
                try:
                    self._checkpoint.save_stage_done(idx, name)
                except Exception:  # noqa: BLE001
                    logger.debug("suppressed exception (core audit)")

    def _seed_resume_state(self) -> None:
        """续扫：把断点中已落盘的发现 / 已扫三元组 / agent 记忆回填进本次运行。"""
        if self._checkpoint is None or not self._resume:
            return
        # 1) 已扫 (engine,target,param) → 主循环跳过
        try:
            done = self._checkpoint.load_done_tasks()
            if done:
                self._incremental_scanned.update(done)
                self._resume_skip_done = True
                logger.info(f"♻️ [P5-1] 已恢复 {len(done)} 个已扫 (engine,target,param)，主循环将跳过")
        except Exception as _e:  # noqa: BLE001
            logger.debug(f"[P5-1] 恢复已扫三元组失败: {_e}")
        # 2) 增量 findings → 直接并入本次 findings（避免重复工作丢失）
        try:
            loaded = self._checkpoint.load_findings()
            for f in loaded:
                key = (
                    f.get('url', ''), f.get('parameter', ''), f.get('type', ''),
                    f.get('method', 'unknown'),
                )
                if key not in self._finding_keys:
                    self._finding_keys.add(key)
                    self.findings.append(f)
            if loaded:
                logger.info(f"♻️ [P5-1] 已恢复 {len(loaded)} 条历史发现并入 findings")
        except Exception as _e:  # noqa: BLE001
            logger.debug(f"[P5-1] 恢复 findings 失败: {_e}")
        # 3) agent 记忆 / shared_knowledge 经验（A4.6：含 agent 记忆）
        try:
            mem = self._checkpoint.load_agent_memory("shared_knowledge")
            if isinstance(mem, dict):
                shared = self._ensure_shared_knowledge()
                shared.setdefault("experiences", [])
                for exp in (mem.get("experiences") or []):
                    shared["experiences"].append(exp)
                logger.info(f"♻️ [P5-1] 已恢复 agent 记忆（经验 {len(mem.get('experiences') or [])} 条）")
        except Exception as _e:  # noqa: BLE001
            logger.debug(f"[P5-1] 恢复 agent 记忆失败: {_e}")

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
            self._bandit = None
            if getattr(settings, "rl_bandit_enabled", False):
                from vulnclaw.ai.v100.bandit import ContextualBandit
                self._bandit = ContextualBandit(
                    influence=int(getattr(settings, "rl_bandit_influence", 2) or 2),
                    feed_dir=str(getattr(settings, "rl_bandit_feed_dir", "") or ""),
                )
            self.task_queue = SmartTaskQueue(max_size=2000, bandit=self._bandit)
            self._live_intake = LiveIntake()  # SP15.3 D4.2 实时补测管线（默认关）
            # R2-A S1: 登记全局实例，供 render/Burp 采集点无 orchestrator 引用时回注
            set_live_intake(self._live_intake)

            # P5-1: 续扫——回填断点中的 findings / 已扫三元组 / agent 记忆
            self._seed_resume_state()

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

            _pt = time.monotonic()
            async with self._stage("recon"):
                await self._recon()
            self._phase_timings['recon'] = time.monotonic() - _pt
            _pt = time.monotonic()
            async with self._stage("taskgen"):
                await self._generate_tasks()
            self._phase_timings['taskgen'] = time.monotonic() - _pt
            await self._feed_live_intake()
            async with self._stage("scan"):
                # 在任务执行之前启动流水线验证后台协程，任务边产出 finding 边验证。
                self._start_stream_verify()
                _pt = time.monotonic()
                await self._execute_with_limiting()
                self._phase_timings['scan'] = time.monotonic() - _pt

            # C3: 成本预算熔断——扫描阶段累计 AI 成本超预算则降级纯引擎模式，防失控
            self._maybe_trip_cost_breaker()

            async with self._stage("chain_router"):
                # S2: 跨引擎攻击链路由——基于 S2.1 链信息把已确认发现串成后续动作
                #（SSRF->内网探测/Redis 未授权，文件上传/LFI->RCE 链）。
                await self._run_chain_router()

            async with self._stage("react_deep_dive"):
                # S1: ReActAgent 深挖阶段（插桩点：_generate_tasks 之后、全局扫描之前）。
                # 对 engine_bundle 首次执行结果全部 low/info 或判定模糊的参数，
                # 用 ReActAgent 做多轮深度渗透（V100=广度覆盖，ReAct=单点深度）。
                # deep 触发 by --deep/ENABLE_REACT_DIVE；执行前过 danger_guard 门卫（S1.2）。
                await self._run_react_gated_deep_dive()

            async with self._stage("agent_coordinator"):
                # P2-1: 多智能体协调器（strix 式可寻址 agent 树）——可选增强通道。
                # 默认关闭，开启后作为主链路之外的补充深扫，复用确定性引擎并把发现合并进 findings。
                await self._run_agent_coordinator()

            async with self._stage("extras"):
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

            async with self._stage("verify"):
                # 等所有流式 verify 把存量 pending 跑完；再收尾剩余未被流式 pick 的。
                await self._stop_stream_verify(wait_pending=True)
                _pt = time.monotonic()
                await self._verify_all_findings()
                # C9/C10: AI 去重 + 幻觉抑制（配置默认开启；异常则保留原始结果，绝不阻断出报告）
                try:
                    if getattr(settings, "llm_as_judge_dedup", False) or getattr(settings, "hallucination_suppression", False):
                        from vulnclaw.ai.v100.phases.phases_verify import llm_judge_dedup, hallucination_suppress
                        self.findings = await llm_judge_dedup(self, self.findings)
                        self.findings = hallucination_suppress(self, self.findings)
                except Exception as _ce:  # noqa: BLE001
                    logger.warning(f"⚠️ C9/C10 后处理异常，保留原始 findings: {_ce}")
                self._phase_timings['verify'] = time.monotonic() - _pt

            self._force_gc()
            await self._finalize_nuclei_update()
            # S3.1: 扫描收尾——把本次关键发现写入 VectorMemory（跨会话学习）
            await self._persist_scan_memory()
            self._save_incremental_state()
            # A3.2: 目标画像落库（增量扫描只测变化面的数据基础）
            await self._save_target_profile_a32()
            # P5-1: 把 shared_knowledge 经验落盘，供续扫恢复 agent 记忆（A4.6）
            if self._checkpoint is not None:
                try:
                    self._checkpoint.save_agent_memory("shared_knowledge", self._ensure_shared_knowledge())
                except Exception:  # noqa: BLE001
                    logger.debug("suppressed exception (core audit)")
            async with self._stage("report"):
                # P5-1: 收尾前把全部 findings 落盘（双保险，_add_finding 增量已覆盖）
                if self._checkpoint is not None:
                    try:
                        for f in self.findings:
                            self._checkpoint.add_finding(f)
                    except Exception:  # noqa: BLE001
                        logger.debug("suppressed exception (core audit)")
                _pt = time.monotonic()
                report = await self._generate_report()
                self._phase_timings['report'] = time.monotonic() - _pt
            self._emit_metrics(report)
            # P5-1: 标记正常完成（后续 --resume-scan 不会误判为可恢复断点）
            if self._checkpoint is not None:
                try:
                    self._checkpoint.mark_finished()
                except Exception:  # noqa: BLE001
                    logger.debug("suppressed exception (core audit)")
            return report
        except Exception as e:
            logger.error(f"扫描过程中发生错误: {e}")
            import traceback
            traceback.print_exc()
            await self._finalize_nuclei_update()
            # S3.1: 扫描收尾——把本次关键发现写入 VectorMemory（跨会话学习）
            await self._persist_scan_memory()
            self._save_incremental_state()
            await self._save_target_profile_a32()
            try:
                self._emit_metrics()
            except Exception:
                logger.debug("suppressed exception (core audit)")
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

async def run_v100_scan(target: str, session, max_tasks: int = None, initial_qps: int = None, resume: bool = False) -> Dict:
    system = V100Orchestrator(target, session, max_tasks, initial_qps, resume=resume)
    return await system.run()

__all__ = ['V100Orchestrator', 'run_v100_scan']
