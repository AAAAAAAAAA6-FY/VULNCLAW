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
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from vulnclaw.core.logger import logger, audit_suppressed
from vulnclaw.core.context import get_scan_context
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get, vuln_category
from vulnclaw.core.scanner import _load_engines
from vulnclaw.core.oob_channel import reset_oob_breaker
from vulnclaw.core.auth.session_manager import get_session_manager
from vulnclaw.ai.core import get_memory
from vulnclaw.ai.burp import get_burp_controller, get_burp_client
from .rate_limiter import get_rate_limiter
from .batch_processor import BatchProcessor
from .local_filter import get_local_filter
from .smart_queue import SmartTaskQueue
from .provider_balancer import get_balancer
from vulnclaw.engines.input_engines import BusinessLogicEngine

from vulnclaw.engines.auxiliary_engines import APIVersionDiffEngine, RequestSmugglingEngine, HTTP2WebSocketEngine
from vulnclaw.engines.http_engines import CachePoisonEngine
from .orchestrator_models import ModelRoutingMixin, compress_prompt  # noqa: F401 (向后兼容再导出)
from .orchestrator_stream import StreamVerifyMixin
from .orchestrator_findings import FindingEvidenceMixin
from .phases import bind_phase_methods
from vulnclaw.core_modules.metrics import get_metrics
from vulnclaw.modules.live_intake import LiveIntake, drain_pending, set_live_intake


def build_multi_role_sessions(session_mgr, role_tokens: Dict[str, Dict], domain: str = "127.0.0.1") -> int:
    """多角色会话装载函数（供 IDOR/BOLA 多账号 E2E 与脚本直接调用）。

    背景：`_init_multi_role` 只为单个 "default" 角色建会话，导致 IDOREngine
    `scan_with_roles` 拿不到 ≥2 个角色而一直"IDOR 检测将跳过"。本函数为
    role_tokens 中的每个角色建立独立会话（各自 Authorization / Cookie）并注入
    session_manager，让多角色扫描链路可被真实调用。

    刻意**不修改** `_init_multi_role` 的行为——单会话默认语义保持不变，
    多角色装载由调用方显式触发（本文件内最小改动，不动架构）。

    参数
    ----
    session_mgr: SessionManager 实例（session_manager.get_session_manager()）
    role_tokens : {role: {"authorization" 或 "token": str, ["cookie"|"cookies"]: Dict}}
    domain      : Cookie 域名键（本地 mock 用 127.0.0.1）
    返回已注入角色数。
    """
    count = 0
    for role, creds in (role_tokens or {}).items():
        if not isinstance(creds, dict):
            continue
        token_dict: Dict[str, str] = {}
        extra_headers: Dict[str, str] = {}
        _auth = creds.get("authorization") or creds.get("token") or creds.get("Authorization")
        if _auth:
            _bearer = _auth if str(_auth).startswith(("Bearer ", "Basic ")) else f"Bearer {_auth}"
            token_dict["Authorization"] = _bearer
            # add_session 在构造 aiohttp.ClientSession 之后才把 token 写进 headers，
            # 而 aiohttp 构造时已快照该 dict → token 发不出去（真实多角色会 401）。
            # 用 extra_headers（构造前合并）确保 Authorization 进入会话默认头。
            extra_headers["Authorization"] = _bearer
        cookie_dict = creds.get("cookie") or creds.get("cookies")
        session_mgr.add_session(
            role=role,
            cookie_dict=cookie_dict if isinstance(cookie_dict, dict) and cookie_dict else None,
            token_dict=token_dict or None,
            extra_headers=extra_headers or None,
            domain=domain or "127.0.0.1",
        )
        count += 1
    return count


class V100Orchestrator(ModelRoutingMixin, StreamVerifyMixin, FindingEvidenceMixin):
    """v100 facade coordinating the scan phases."""
    _safe_params = {
        'callback', '_', 'timestamp', 'nonce', 'version', 'format',
        'cors', 't', 'v', 'ver', 'ts', 'time', 'rand', 'random',
        'session', 'token', 'csrf', 'authenticity_token', 'utf8'
    }

    def __init__(self, target: str, session, max_tasks: int = None, initial_qps: int = None, resume: bool = False,
                 profile: str = "", adaptive: bool = False):
        self.target = target
        self.session = session
        self._user_max_tasks = max_tasks
        self._user_initial_qps = initial_qps
        self.scan_adaptive = bool(adaptive)
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
        # 工作流10：扫描预算模式（空=不启用，保持全量默认行为）
        self.scan_profile_name = str(profile or "")
        self.scan_profile_applied = False
        self.scan_payload_depth = 0
        self.scan_payload_depth_map = {}
        self.scan_concurrency = 0
        self.scan_budget_requests = 0
        if self.scan_profile_name:
            self.scan_profile_applied = self._apply_scan_profile()
        logger.info(f"✅ 加载 {len(self.engines)} 个漏洞检测引擎（已配置SPA检测器）")
        self._model_pool = self._get_model_pool()
        self._ai_enabled = bool(self._model_pool)
        self._model_index = 0
        self._model_lock = asyncio.Lock()
        self._model_stats = {m: 0 for m in self._model_pool}
        self._model_failures = {m: 0 for m in self._model_pool}
        self._timeout_streaks: Dict[str, int] = {}  # P2-1: 任务类型连续超时计数
        self.findings: List[Dict] = []
        self._pending_review: List[Dict] = []  # 终稿收敛：AI/技术均未实锤的存疑发现
        self._finding_keys: Set[tuple] = set()
        # 修复"越扫越卡"：url+type 级 O(1) 去重索引，替代 executor 各全局扫描线
        # 对 self.findings 的全量 any(...) 遍历（findings 越多每次判定越慢 = O(n^2)）。
        self._seen_ut: Set[tuple] = set()
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
            audit_suppressed()
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
        # SP18 编排可观测性：协调阶段（chain_router/react_deep_dive/agent_coordinator）起止时间
        self._orchestration_stages: Dict[str, Tuple[float, float]] = {}
        self._coord_dispatch_count: int = 0  # SP18 协调器派发子 agent 数
        # SH17.1 阶段预算：per-phase wall-clock 上限（settings 带默认值；<=0 不限制）
        self._phase_timeouts_hit: List[str] = []
        self._phase_budgets: Dict[str, int] = {}
        for _n in self._STAGES:
            _b = int(getattr(settings, f'phase_timeout_{_n}_s', 0) or 0)
            if _b > 0:
                self._phase_budgets[_n] = _b
        self._direct_findings = 0
        self._burp_findings = 0
        self._burp_scan_task = None  # 步骤3：并行 Burp 扫描任务句柄
        self._browser_passive_task = None  # 浏览器被动爬虫后台任务
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
            status, body, headers = await async_get(self.target, session=self.session, timeout=settings.request_timeout)

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
                audit_suppressed()

            # P3-12：run_sync 安全包装（在事件循环内被调用时不再抛 RuntimeError）
            from vulnclaw.core.utils import run_sync as _run_sync_burp
            self.burp_available = _run_sync_burp(self.burp_client.get_status())
        except Exception as e:
            logger.warning(f"⚠️ Burp 连接检测异常: {e}")
            self.burp_available = False

        if self.burp_available:
            logger.info("🔌 Burp 连接成功")
        else:
            logger.info("ℹ️ Burp 不可用，将使用浏览器被动爬虫采集流量")

    async def _run_browser_passive(self):
        """后台被动爬虫：启动 Playwright 浏览器 → 爬取目标 → 流量回注 LiveIntake。

        Burp 不在时自动运行，将页面请求/响应对注入引擎管线做被动分析。
        注意：不使用 settings.proxy（可能是未启动的 Burp 地址），浏览器直连目标。
        """
        try:
            from vulnclaw.core.browser_ai_agent import BrowserAIAgent, passive_pairs_to_intake
        except ImportError:
            logger.debug("浏览器被动爬虫模块不可用，跳过")
            return
        agent = BrowserAIAgent(headless=True, proxy=None)
        try:
            pairs = await agent.passive_crawl(self.target, timeout=30)
            if pairs:
                fed = passive_pairs_to_intake(pairs, source="browser_passive")
                logger.info(f"🕵️ [被动爬虫] 收集 {len(pairs)} 条流量，回注 {fed} 个参数到引擎管线")
            else:
                logger.debug("🕵️ [被动爬虫] 未捕获到有效流量")
        except Exception as e:
            logger.warning(f"⚠️ 被动爬虫异常: {e}")
        finally:
            try:
                await agent.stop()
            except Exception:
                pass

    def _apply_scan_profile(self) -> bool:
        """工作流10：按 ScanProfile 收窄引擎集合，并落并发/payload 深度/超时/请求预算。

        安全策略：模式未知、或收窄后一个引擎都不剩 → 保守回退全量并告警，
        绝不静默清空引擎集合（宁可多扫，不可漏扫）。
        """
        try:
            from vulnclaw.core.scan_profiles import get_profile
            try:
                prof = get_profile(self.scan_profile_name)
            except ValueError as _verr:
                # get_profile 对未登记模式 fail-closed 抛 ValueError，转成 warning 告警
                logger.warning(
                    f"未知扫描模式 {self.scan_profile_name!r}（{_verr}），忽略（保持全量引擎）"
                )
                return False
            if prof.engines:
                want = set(prof.engines)
                keep = [e for e in self.engines if getattr(e, "name", "") in want]
                if not keep:
                    logger.warning(f"模式 {prof.name} 未匹配到已注册引擎，保守回退全量")
                    return False
                self.engines = keep
                self.engine_map = {getattr(e, "name", ""): e for e in keep}
            self.scan_payload_depth = int(prof.default_payload_depth)
            self.scan_payload_depth_map = dict(prof.payload_depth)
            self.scan_concurrency = int(prof.concurrency)
            self.scan_budget_requests = int(prof.budget_requests)
            if prof.scan_timeout_s:
                try:
                    from vulnclaw.config.settings import settings
                    settings.max_scan_time = int(prof.scan_timeout_s)
                except Exception as exc:  # noqa: BLE001 - 超时覆盖失败不阻塞
                    logger.debug(f"模式超时应用失败（忽略）: {exc}")
            logger.info(
                f"🎯 扫描模式 {prof.name}: 引擎 {len(self.engines)} 个 / payload 深度 "
                f"{prof.default_payload_depth} / 并发 {prof.concurrency} / 请求预算 "
                f"{prof.budget_requests or '不限'}（{prof.description}）"
            )
            return True
        except Exception as exc:  # noqa: BLE001 - 模式是增强项，失败保持全量
            logger.debug(f"扫描模式应用失败（忽略，保持全量）: {exc}")
            return False

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
            from vulnclaw.core.auth.browser_cookie import get_browser_cookies
            domain = urlparse(self.target).netloc
            cookies = get_browser_cookies(domain)
            if cookies:
                session_mgr.set_default_cookies(cookies)
                session_mgr.add_session("default", cookie_dict=cookies)
                logger.info(f"🍪 从浏览器加载了 {len(cookies)} 个Cookie")
                return
            logger.info("ℹ️ 未检测到多角色会话，IDOR检测将跳过")
        except Exception:
            audit_suppressed()

    # -------------------------------------------------------------------------
    # 流水线验证（stream-verify）：attack 节点边出 finding 边后台 verify。
    # 触发条件：(1) 新增后累计未处理 pending >= 动态预算；或 (2) 距上次触发 >= 3 秒。
    # 收尾阶段：stop(wait_pending=True) 会等所有存量 pending 跑完再返回。
    # -------------------------------------------------------------------------

    def _add_finding(self, finding: Dict):
        # 第2点：已知负样本端点拦截（2026-09-06）。命中 negative_endpoints 的 url
        # 在落库前判误报丢弃，避免 /safe 类已知安全端点污染报告（验证层补拦截）。
        _neg = [x.strip() for x in (getattr(settings, "negative_endpoints", "") or "").split(",") if x.strip()]
        if _neg:
            _url = str(finding.get("url", ""))
            if any(n in _url for n in _neg):
                logger.info(f"   [负样本] {finding.get('type')} @ {_url} 命中负样本清单，判误报丢弃")
                return
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
            self._seen_ut.add((str(finding.get("url", "")), str(finding.get("type", ""))))
            # SP16.1 回注：产出 finding → bandit 正样本（默认关，无代价）
            # K2: _bandit 在 run() 内第1669行才初始化，此前 _add_finding 可能已被全局
            # 扫描调用 → getattr 守卫，避免 AttributeError 击穿整条全局扫描线。
            if getattr(self, "_bandit", None) is not None:
                try:
                    self._bandit.record(self._bandit.key_from_finding(finding), hit=True)
                except Exception:  # noqa: BLE001
                    logger.debug("[SP16.1] bandit hit 回注失败，跳过", exc_info=True)
            # P5-1: 增量持久化 finding 到 SQLite 检查点（kill -9 不丢，续扫自动并入）
            if getattr(self, "_checkpoint", None) is not None:
                try:
                    self._checkpoint.add_finding(finding)
                except Exception:  # noqa: BLE001
                    audit_suppressed()
            # E4: 记录已确认高危/严重漏洞的参数（按大类），供早停跳过“同类”剩余引擎
            try:
                if str(finding.get('severity', '')).lower() in ('high', 'critical'):
                    _cp = (finding.get('url', ''), finding.get('parameter', ''))
                    self._confirmed_params.add(_cp)
                    self._confirmed_categories.setdefault(_cp, set()).add(
                        vuln_category(finding.get('type', '') or finding.get('engine', ''))
                    )
            except Exception:
                audit_suppressed()
            try:
                get_metrics().inc_vuln(
                    str(finding.get('severity', 'unknown')) or 'unknown',
                    str(finding.get('type', 'unknown')) or 'unknown',
                )
            except Exception:
                audit_suppressed()

    # ------------------------------------------------------------------
    # 轨道2 2.1: PoC 复现信息（reproduction_steps + curl_command）
    # ------------------------------------------------------------------

    async def _run_extras_block(self) -> None:
        """SH17.1：extras 阶段主体（与 Burp 并行，收尾合并）。"""
        # 步骤3：并行提交 Burp 扫描（与下面各全局扫描同时进行，收尾前合并结果）
        self._burp_scan_task = asyncio.create_task(self._run_burp_scan())

        if self._collaborator_domain:
            await self._check_collaborator_callback()

        if self._enable_idor:
            # 实测教训（rest.vulnweb.com 首扫）：_scan_idor 内部任一计划线缺失
            # （如 __all__ 漏绑定）会让 AttributeError 冒泡炸掉整个 extras 块，
            # 后续 vulnspec/metamorphic/sequence 全部不跑——与其他分支一致加隔离。
            try:
                await self._scan_idor()
            except Exception:  # noqa: BLE001 - IDOR 线异常不阻断 extras 其余分支
                audit_suppressed()

        # C 方案社区线（2026-09-08）：Nuclei 社区模板通用检测，与 extras 收尾一并执行
        if (
            getattr(settings, "nuclei_community_line", True)
            or True  # _enable_idor 关闭时社区线仍可独立跑（开关单独控制，fail-closed 内部保证）
        ):
            try:
                await self._run_nuclei_community_line()
            except Exception:  # noqa: BLE001 - 社区线异常不阻断 extras
                audit_suppressed()

        if self._enable_default_creds:
            await self._check_default_creds()

        # 多步序列 / 并发竞态线（2026-09-10）：默认关闭（会真实重复提交业务动作，有副作用）
        if getattr(settings, "sequence_chain_enabled", False):
            try:
                await self._run_sequence_chain_line()
            except Exception:  # noqa: BLE001 - 序列线异常不阻断 extras
                audit_suppressed()

        # 声明驱动产线（2026-09-10）：声明集覆盖老引擎够不到的注入位置
        if getattr(settings, "vulnspec_line_enabled", True):
            try:
                await self._run_vulnspec_line()
            except Exception:  # noqa: BLE001 - 声明线异常不阻断 extras
                audit_suppressed()

        # 元orphic 不变量产线（ID 越权候选为只读，零副作用）
        if getattr(settings, "metamorphic_line_enabled", True):
            try:
                await self._run_metamorphic_line()
            except Exception:  # noqa: BLE001
                audit_suppressed()

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
        if self._browser_passive_task is not None and not self._browser_passive_task.done():
            try:
                await self._browser_passive_task
            except Exception as e:
                logger.warning(f"⚠️ 浏览器被动爬虫任务异常: {e}")
            finally:
                self._browser_passive_task = None

    # 注: _run_verify_block / _apply_final_review_gate 已迁至 phases/phases_verify.py
    # （H 组 orchestrator 拆分），经 bind_phase_methods 绑定，此处不再保留类级副本。

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
            self._coord_dispatch_count = int(getattr(coord, "nodes", None) and len(coord.nodes) or 0)
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
        """S1.2: 本地 ReAct 深挖属探测级（读响应/验证参数），默认放行。

        返回 True=放行 LLM 深挖；False=降级为本地确定性兜底。
        SP22 变更：不再套用"远程 Agent 实际攻击"审批键 remote_deep_penetrate
        （该键保留给 MCP 远程深渗透，保持默认 deny），改用非危险键 react_dive_probe
        ——danger_guard 对非危险操作恒放行并保留审计；guard 异常时仍按 deny
        降级本地兜底，绝不中断扫描。企业如需彻底关闭深挖：ENABLE_REACT_DIVE=false。
        """
        try:
            from vulnclaw.core.danger_guard import guard
            return bool(
                guard.require_approval(
                    'react_dive_probe',
                    detail=f"V100 本地 ReAct 探测级深挖 target={getattr(self, 'target', '')}",
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
                audit_suppressed()
        try:
            yield True
        finally:
            if self._checkpoint is not None:
                try:
                    self._checkpoint.save_stage_done(idx, name)
                except Exception:  # noqa: BLE001
                    audit_suppressed()

    async def _run_phase_timeboxed(self, name: str, coro):
        """SH17.1 阶段预算：单阶段 wall-clock 超时只中断本阶段，跳过继续（不整扫报废）。
        预算随阶段工作量自适应（2026-09-06）：findings 驱动阶段∝len(findings)，
        scan∝pending，recon/taskgen∝目标数；未探出规模时回退静态 floor。
        动态值写回 self._phase_budgets[name]，供阶段内部(如 attack 内层)读取保证 内层<外层。"""
        _dyn = self._recompute_phase_budget(name)
        if _dyn and _dyn > 0:
            self._phase_budgets[name] = int(_dyn)
            logger.info(f"   [deadline] {name} 阶段预算(自适应): {self._phase_budgets[name]}s")
        budget = self._phase_budgets.get(name, 0)
        if not budget:
            return await coro
        try:
            return await asyncio.wait_for(coro, timeout=float(budget))
        except asyncio.TimeoutError:
            self._phase_timeouts_hit.append(name)
            logger.warning(f"⏱️ [SH17.1] 阶段超时: {name}（预算 {budget}s），跳过继续")
            return None

    def _recompute_phase_budget(self, name: str) -> float:
        """按阶段工作量动态重算预算，复用公共 compute_adaptive_budget。
        各阶段工作量信号：scan=待执行任务数(pending)；verify/extras/agent_coordinator/
        chain_router/react_deep_dive/report/fallback=已产 findings 数；recon/taskgen 因
        循环依赖(规模由自身发现)无开始前信号，按目标数缩放(单目标=地板)。"""
        from vulnclaw.core.target_capacity_probe import compute_adaptive_budget
        _pending = (self.task_queue.pending_count() if hasattr(self, "task_queue")
                    and hasattr(self.task_queue, "pending_count") else 0)
        _findings = len(getattr(self, "findings", []) or [])
        _targets = len(getattr(self, "targets", []) or [getattr(self, "target", "")]) or 1
        if name == "scan":
            return compute_adaptive_budget(_pending, cap=float(getattr(settings, "max_scan_time", 3600))) + 80
        if name == "recon":
            # recon 自身发现规模，开始前未知；按目标数缩放，单目标维持地板 240
            # 大站防线（2026-09-07）：爬虫产出常在预算尾部才成批出现（audible 745 端点于
            # 239s 附近就绪），固定 240s 地板会把刚要入队的爬取掐断。floor 只是 wall-clock
            # 上限，小站提前返回不受影响，故可安全放大：单目标 240→480，多目标 ×8 封顶。
            _floor = 480.0 if _targets <= 1 else min(240.0 * _targets, 1920.0)
            return compute_adaptive_budget(_targets, worker=1, rt_ms=200.0, per_task_s=40.0, floor=_floor)
        if name == "taskgen":
            return compute_adaptive_budget(_targets, worker=1, rt_ms=200.0, per_task_s=20.0, floor=60.0)
        # findings 驱动阶段：预算∝已确认发现数
        _per = {
            "verify": 1.5, "extras": 3.0, "agent_coordinator": 4.0,
            "chain_router": 0.8, "react_deep_dive": 2.0, "report": 0.4, "fallback": 1.0,
        }.get(name, 1.0)
        _floor = float(getattr(settings, f"phase_timeout_{name}_s", 120) or 120)
        return compute_adaptive_budget(_findings, worker=1, per_task_s=_per, floor=_floor)

    def _coord_enabled(self, name: str) -> bool:
        """SP18: 协调阶段是否被配置启用（关闭时跳过，不写 0 假值）。"""
        if name == "chain_router":
            return bool(getattr(settings, "enable_chain_router", True))
        if name == "react_deep_dive":
            return bool(getattr(settings, "enable_react_dive", False))
        if name == "agent_coordinator":
            return bool(getattr(settings, "agent_coordinator_enabled", False))
        return True

    async def _record_coord_timing(self, name: str, enabled_stage: bool, coro):
        """SP18: 执行协调阶段协程，仅当阶段实际启用时写入耗时与编排账本起止时间。"""
        _start = time.monotonic()
        result = await coro
        if enabled_stage and self._coord_enabled(name):
            self._phase_timings[name] = time.monotonic() - _start
            self._orchestration_stages[name] = (_start, time.monotonic())
        return result

    def orchestration_ledger(self) -> Dict:
        """SP18: 返回各协调阶段的决策摘要账本（阶段名 -> 起止/耗时/关键决策计数）。

        决策计数复用既有可观测来源：chain 路由合入的 finding 数（source=chain_router）、
        ReAct 深挖合入数（source=react_agent）、协调器派发子 agent 数（node 数）；
        无计数器时仅提供耗时，绝不新造复杂机制。
        """
        ledger: Dict[str, Dict] = {}
        stages = getattr(self, "_orchestration_stages", None) or {}
        findings = getattr(self, "findings", None) or []
        chain_routes = sum(1 for f in findings if isinstance(f, dict) and f.get("source") == "chain_router")
        dive_count = sum(1 for f in findings if isinstance(f, dict) and f.get("source") == "react_agent")
        for name in ("chain_router", "react_deep_dive", "agent_coordinator"):
            if name not in stages:
                continue
            start, end = stages[name]
            entry: Dict = {"start": start, "end": end, "elapsed": end - start}
            if name == "chain_router":
                entry["chain_routes"] = chain_routes
            elif name == "react_deep_dive":
                entry["dive_count"] = dive_count
            elif name == "agent_coordinator":
                entry["agents_dispatched"] = int(getattr(self, "_coord_dispatch_count", 0) or 0)
            ledger[name] = entry
        return ledger

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
                    self._seen_ut.add((str(f.get("url", "")), str(f.get("type", ""))))
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
        # P0 修复：每次扫描开场重置 OOB 进程级状态（熔断计数/通道/域名与 session 缓存），
        # 避免上一扫描的 miss_streak 残留导致本目标带外验证永久跳过。
        try:
            reset_oob_breaker()
        except Exception:  # noqa: BLE001
            logger.debug("reset_oob_breaker 调用失败（不影响扫描）")
        # G5/AI 横幅：起扫时明示 AI 验证可用性（模型池为空 = 纯引擎模式，强告警）
        try:
            _pool_now = list(getattr(self, "_model_pool", []) or [])
            if _pool_now:
                logger.info(
                    "🔔 [AI 验证] 已启用: %d 个模型 - %s｜verify 将执行 粗筛→多模型投票→技术验证→Burp 双源",
                    len(_pool_now), ", ".join(_pool_now[:4] + (["..."] if len(_pool_now) > 4 else []))
                )
            else:
                logger.warning(
                    "🚨 当前无可用 AI 模型（AI_MODELS 为空或未配置）——扫描将进入纯引擎模式，"
                    "误报率风险偏高，建议配置 AI_MODELS/AI_API_KEY 后再扫"
                )
        except Exception:  # noqa: BLE001
            audit_suppressed()

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
            self.batch_processor = BatchProcessor(max_batch_size=settings.ai_batch_size)
            self.local_filter = get_local_filter()
            self._bandit = None
            if getattr(settings, "rl_bandit_enabled", False):
                from vulnclaw.ai.v100.bandit import ContextualBandit
                self._bandit = ContextualBandit(
                    influence=int(getattr(settings, "rl_bandit_influence", 2) or 2),
                    feed_dir=str(getattr(settings, "rl_bandit_feed_dir", "") or ""),
                    # P3-⑤：跨扫描状态持久化（默认空=不落盘，行为不变）
                    state_path=str(getattr(settings, "rl_bandit_state_path", "") or ""),
                )
            self.task_queue = SmartTaskQueue(max_size=2000, bandit=self._bandit)
            self._live_intake = LiveIntake()  # SP15.3 D4.2 实时补测管线（默认关）
            # R2-A S1: 登记全局实例，供 render/Burp 采集点无 orchestrator 引用时回注
            set_live_intake(self._live_intake)

            # P5-1: 续扫——回填断点中的 findings / 已扫三元组 / agent 记忆
            self._seed_resume_state()

            self._browser_passive_task = None
            if not self.burp_available and not getattr(settings, "no_passive", False):
                self._browser_passive_task = asyncio.create_task(self._run_browser_passive())

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

            # DualAgent：广度（主链路 scan）+ 深度（AgentCoordinator）并行开关判定。
            # 需 dual_agent_parallel 与 agent_coordinator_enabled 同时开启；任一关闭走原串行路径。
            _dual = bool(getattr(settings, "dual_agent_parallel", False)) and self._coord_enabled("agent_coordinator")
            self._dual_agent_coord_elapsed = 0.0
            if _dual:
                logger.info("   [DualAgent] 已启用双智能体并行：广度 scan 与深度 AgentCoordinator 同时执行")
            _pt = time.monotonic()
            async with self._stage("recon"):
                await self._run_phase_timeboxed("recon", self._recon())
            self._phase_timings['recon'] = time.monotonic() - _pt
            _pt = time.monotonic()
            async with self._stage("taskgen"):
                await self._run_phase_timeboxed("taskgen", self._generate_tasks())
            self._phase_timings['taskgen'] = time.monotonic() - _pt
            await self._feed_live_intake()
            async with self._stage("scan"):
                # 在任务执行之前启动流水线验证后台协程，任务边产出 finding 边验证。
                self._start_stream_verify()
                _pt = time.monotonic()
                if _dual:
                    # DualAgent：广度（10 worker 引擎扫描）与深度（AgentCoordinator
                    # recon/analysis/exploit/verify agent 树）gather 并行——
                    # 共享同一 rate_limiter / session / adaptive_concurrency（LLM 与目标双限流），
                    # 副 agent findings 经 bridge_into -> _add_finding 双重去重合并；
                    # 副 agent 受 phase_timeout_agent_coordinator_s 软截止，到点收割不拖累主链路，
                    # 汇合墙钟 = max(主链路, 副通道) 而非串行相加。
                    _t0 = time.monotonic()
                    await asyncio.gather(
                        self._run_phase_timeboxed("scan", self._execute_with_limiting()),
                        self._run_phase_timeboxed("agent_coordinator", self._run_agent_coordinator()),
                        return_exceptions=True,
                    )
                    self._dual_agent_coord_elapsed = time.monotonic() - _t0
                    logger.info(
                        f"   [DualAgent] 广度+深度并行汇合（副 agent 段耗时 {self._dual_agent_coord_elapsed:.0f}s）"
                    )
                else:
                    await self._run_phase_timeboxed("scan", self._execute_with_limiting())
                self._phase_timings['scan'] = time.monotonic() - _pt

            # C3: 成本预算熔断——扫描阶段累计 AI 成本超预算则降级纯引擎模式，防失控
            self._maybe_trip_cost_breaker()

            async with self._stage("chain_router") as _ran_chain:
                # S2: 跨引擎攻击链路由——基于 S2.1 链信息把已确认发现串成后续动作
                #（SSRF->内网探测/Redis 未授权，文件上传/LFI->RCE 链）。
                await self._record_coord_timing("chain_router", _ran_chain,
                    self._run_phase_timeboxed("chain_router", self._run_chain_router()))

            async with self._stage("react_deep_dive") as _ran_react:
                # S1: ReActAgent 深挖阶段（插桩点：_generate_tasks 之后、全局扫描之前）。
                # 对 engine_bundle 首次执行结果全部 low/info 或判定模糊的参数，
                # 用 ReActAgent 做多轮深度渗透（V100=广度覆盖，ReAct=单点深度）。
                # deep 触发 by --deep/ENABLE_REACT_DIVE；执行前过 danger_guard 门卫（S1.2）。
                await self._record_coord_timing("react_deep_dive", _ran_react,
                    self._run_phase_timeboxed("react_deep_dive", self._run_react_gated_deep_dive()))

            async with self._stage("agent_coordinator") as _ran_coord:
                # P2-1: 多智能体协调器（strix 式可寻址 agent 树）——可选增强通道。
                # 默认关闭，开启后作为主链路之外的补充深扫，复用确定性引擎并把发现合并进 findings。
                if _dual:
                    # DualAgent 模式：已在 scan stage 内与主链路 gather 并行执行过，
                    # 此处仅补计时/账本（_STAGES 顺序与 P5-1 checkpoint 语义保持不变，不重复执行）。
                    self._phase_timings['agent_coordinator'] = float(getattr(self, "_dual_agent_coord_elapsed", 0.0))
                    logger.info("   [DualAgent] agent_coordinator 已随 scan 并行执行，本段仅记账不重复跑")
                else:
                    await self._record_coord_timing("agent_coordinator", _ran_coord,
                        self._run_phase_timeboxed("agent_coordinator", self._run_agent_coordinator()))

            async with self._stage("extras"):
                # SH17.1：extras 阶段预算（settings.phase_timeout_extras_s），超时跳过未完成补充分支
                await self._run_phase_timeboxed("extras", self._run_extras_block())

            async with self._stage("verify"):
                # SH17.1：verify 阶段预算（settings.phase_timeout_verify_s），超时保留原始 findings
                await self._run_phase_timeboxed("verify", self._run_verify_block())

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
                    audit_suppressed()
            self._apply_final_review_gate()
            async with self._stage("report"):
                # P5-1: 收尾前把全部 findings 落盘（双保险，_add_finding 增量已覆盖）
                # P1-11：单事务批量写，替代 N 次 commit（收尾不再触发 N 次 fsync）
                if self._checkpoint is not None:
                    try:
                        if hasattr(self._checkpoint, "add_findings"):
                            self._checkpoint.add_findings(self.findings)
                        else:  # 老接口（自定义 checkpoint）保持逐条写
                            for f in self.findings:
                                self._checkpoint.add_finding(f)
                    except Exception:  # noqa: BLE001
                        audit_suppressed()
                _pt = time.monotonic()
                report = await self._run_phase_timeboxed("report", self._generate_report())
                self._phase_timings['report'] = time.monotonic() - _pt
            # SH17.1: 实际命中的阶段超时写进报告（账本可查）
            if isinstance(report, dict):
                report["phase_timeouts"] = list(self._phase_timeouts_hit)
                report["orchestration"] = self.orchestration_ledger()
            self._emit_metrics(report)
            # P5-1: 标记正常完成（后续 --resume-scan 不会误判为可恢复断点）
            if self._checkpoint is not None:
                try:
                    self._checkpoint.mark_finished()
                except Exception:  # noqa: BLE001
                    audit_suppressed()
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
                audit_suppressed()
            self._apply_final_review_gate()
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

async def run_v100_scan(target: str, session, max_tasks: int = None, initial_qps: int = None, resume: bool = False,
                        profile: str = "", adaptive: bool = False) -> Dict:
    system = V100Orchestrator(target, session, max_tasks, initial_qps, resume=resume, profile=profile,
                              adaptive=adaptive)
    return await system.run()

__all__ = ['V100Orchestrator', 'run_v100_scan']
1	JWT kid/JWK 注入	engines/auth_engines.py	中	从 2 个 fixture → 6+，覆盖真实 CVE
2	GraphQL alias 批量攻击	engines/net_engines.py	中	graphql 引擎当前只有 introspection + 基础注入
3	Prototype Pollution gadget 提示	engines/web_advanced_engines.py	小	加一个 gadget fingerprints 库，现有引擎直接引用
4	sqli fixture 深度化	tests/fixtures/engines/sqli.yaml	小	从~4 个 case → 12+（WAF 绕过、盲注、堆叠）
5	xss fixture 深度化	tests/fixtures/engines/xss.yaml	小	补 attribute/JS context/SVG/mutation XSS
6	ssrf fixture 补盲	tests/fixtures/engines/ssrf.yaml	小	补 gopher/302 跳转/DNS rebind 基础 case