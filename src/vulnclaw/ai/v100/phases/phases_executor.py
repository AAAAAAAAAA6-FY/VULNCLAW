# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Implementation functions for the v100 executor phase."""
import asyncio
import contextlib
import time
import ast
import json
import re
from typing import Any, Dict, List, Optional
from vulnclaw.core.logger import logger
from vulnclaw.core.scanner import safe_request, get_engine_by_name
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import cap, get_tool_path, vuln_category
from vulnclaw.engines.input_engines import BusinessLogicEngine
from vulnclaw.engines.auxiliary_engines import APIVersionDiffEngine, RequestSmugglingEngine, HTTP2WebSocketEngine
from vulnclaw.engines.http_engines import CachePoisonEngine
from vulnclaw.engines.base import annotate_chain_info
from vulnclaw.deepsec.sqlmap_wrapper import SQLMapWrapper
from vulnclaw.ai.v100.smart_queue import is_protected_task
from vulnclaw.core.http_client import url_in_scope, parse_scope

# ============================================================
# D 方案: 引擎目标域硬约束 + 粘滞剔除簿记（2026-09-08）
# ============================================================
def _engine_task_target_allowed(self, task) -> tuple:
    """D2: 引擎任务目标域硬约束（fail-closed）。

    目标必须满足以下任一条件才放行：
      - 命中 ALLOWED_SCOPE 白名单（URL 级）；
      - 属于主扫描目标的域或子域（主域判定即使 ALLOWED_SCOPE 未配置也生效）。
    其余一律拒绝且不发起任何请求。
    """
    try:
        from urllib.parse import urlparse as _up_d
        target = str(task.get("target", "") or "")
        if not target:
            return True, "无目标"
        parsed = _up_d(target)
        host = (parsed.hostname or "").lower()
        if not host:
            return True, "目标无 host（相对路径，交由请求层判定）"
        main_parsed = _up_d(str(getattr(self, "target", "") or ""))
        main = (main_parsed.hostname or "").lower()
        if main and (host == main or host.endswith("." + main)):
            # 同主机端口隔离：主目标显式指定端口时，任务有效端口须一致，
            # 防同主机多服务（本地多靶场 8791 vs 8090）跨目标串扫。
            main_port = main_parsed.port
            if main_port is not None:
                task_port = parsed.port if parsed.port is not None else (
                    443 if (parsed.scheme or "").lower() == "https" else 80)
                if task_port != main_port:
                    entries = parse_scope()
                    if entries and url_in_scope(target, entries):
                        return True, "allowed_scope 白名单"
                    return False, f"host={host} 端口越界(main:{main_port} task:{task_port})"
            return True, "主域/子域"
        entries = parse_scope()
        if entries and url_in_scope(target, entries):
            return True, "allowed_scope 白名单"
        return False, f"host={host} 不在授权域(main={main or '未知'} scope={entries or '未配置'})"
    except Exception as _e:  # noqa: BLE001
        return False, f"域校验异常: {_e}"


def _sticky_mark_failed(self, task) -> None:
    """D1.2: 记录 (engine,target,param) 失败次数，达阈值写墓碑黑名单。"""
    if not hasattr(self, "_sticky_fail_counter"):
        self._sticky_fail_counter = {}
        self._sticky_blacklist = set()
    key = (str(task.get("engine", "")), str(task.get("target", "")), str(task.get("param", "")))
    n = self._sticky_fail_counter.get(key, 0) + 1
    self._sticky_fail_counter[key] = n
    threshold = int(getattr(settings, "sticky_fail_threshold", 2))
    if n >= threshold:
        self._sticky_blacklist.add(key)
        logger.warning(
            f"   [D1] 粘滞剔除: {key[0]}/{key[2]} 累计失败 {n} 次，后续同键任务跳过"
        )
async def _run_business_logic_scan(self):
    try:
        logger.info("🧬 [BusinessLogic] 全局扫描...")
        engine = BusinessLogicEngine()
        results = await engine.scan(self.target, self.session)
        for r in results:
            if (str(r.get('url', '')), str(r.get('type', ''))) not in self._seen_ut:
                self._add_finding(r)
                self._business_findings += 1
                logger.info(f"   📌 业务逻辑: {r.get('type')}")
    except Exception as e:
        logger.warning(f"⚠️ 业务逻辑扫描失败: {e}")
async def _run_api_version_scan(self):
    try:
        logger.info("📌 [APIVersion] 全局扫描...")
        engine = APIVersionDiffEngine()
        results = await engine.scan(self.target, self.session)
        for r in results:
            if (str(r.get('url', '')), str(r.get('type', ''))) not in self._seen_ut:
                self._add_finding(r)
                self._api_version_findings += 1
                logger.info(f"   📌 API版本: {r.get('type')}")
    except Exception as e:
        logger.warning(f"⚠️ API版本差异扫描失败: {e}")
async def _run_smuggling_scan(self):
    try:
        logger.info("🩹 [Smuggling] 全局扫描...")
        engine = RequestSmugglingEngine()
        results = await engine.scan(self.target, self.session)
        for r in results:
            if (str(r.get('url', '')), str(r.get('type', ''))) not in self._seen_ut:
                self._add_finding(r)
                self._smuggling_findings += 1
                logger.info(f"   🩹 请求走私: {r.get('type')}")
    except Exception as e:
        logger.warning(f"⚠️ 请求走私扫描失败: {e}")
async def _run_http2_ws_scan(self):
    try:
        logger.info("🔌 [HTTP2/WS] 全局扫描...")
        engine = HTTP2WebSocketEngine()
        results = await engine.scan(self.target, self.session)
        for r in results:
            if (str(r.get('url', '')), str(r.get('type', ''))) not in self._seen_ut:
                self._add_finding(r)
                self._http2_ws_findings += 1
                logger.info(f"   🔌 HTTP2/WS: {r.get('type')}")
    except Exception as e:
        logger.warning(f"⚠️ HTTP2/WS扫描失败: {e}")
async def _run_cache_poison_scan(self):
    try:
        logger.info("🧬 [CachePoison] 全局扫描...")
        engine = CachePoisonEngine()
        results = await engine.scan(self.target, self.session)
        for r in results:
            if (str(r.get('url', '')), str(r.get('type', ''))) not in self._seen_ut:
                self._add_finding(r)
                self._cache_poison_findings += 1
                logger.info(f"   🔗 缓存投毒: {r.get('type')}")
    except Exception as e:
        logger.warning(f"⚠️ 缓存投毒扫描失败: {e}")

# 步骤3：Burp Scanner 集成 —— 提交扫描 + 轮询 + 结果合并
_BURP_SEV_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_BURP_MAX_SUBMIT = 10  # 避免打爆 Burp / 目标（请求数翻倍）


def _collect_burp_candidates(self):
    """端点级去重：只提交自家引擎未产出 finding 的攻击面 URL。"""
    base = str(getattr(self, "target", "")).rstrip("/")
    scanned = set()
    for f in getattr(self, "findings", []) or []:
        u = str(f.get("url") or "")
        if u:
            scanned.add(u.split("?")[0].rstrip("/"))

    brief = getattr(self, "_recon_brief", None) or {}
    raw = []
    for ep in (brief.get("js_endpoints") or []) + (brief.get("apis") or []):
        ep = str(ep)
        if not ep or len(ep) < 2:
            continue
        if ep.startswith(("http://", "https://")):
            url = ep
        elif ep.startswith("/"):
            url = base + ep
        else:
            continue  # 无法归一化的跳过
        url = url.split("?")[0].rstrip("/")
        if url in scanned or url == base:
            continue
        raw.append(url)

    seen = set()
    ordered = []
    for u in raw:
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    return ordered[:_BURP_MAX_SUBMIT]


async def _run_burp_scan(self):
    """步骤3：把端点提交给 Burp Scanner，结果合并进主 findings。

    合并规则（双源冲突取高 severity）：
      - url+parameter+type+method 与已有 finding 相同 → 不重复添加，
        若 Burp 严重级更高则升级已有 finding 并标记 burp_confirmed；
      - 否则作为新 finding 加入，source=burp_scanner。
    """
    if not getattr(self, "burp_available", False) or not getattr(self, "burp_client", None):
        return
    try:
        candidates = _collect_burp_candidates(self)
        if candidates:
            logger.info(f"🔍 [Burp] 提交 {len(candidates)} 个端点给 Burp Scanner（自家引擎未覆盖）")
        findings = await self.burp_client.scan_and_collect(urls=candidates)
        if not findings:
            return

        merged = 0
        upgraded = 0
        for nf in findings:
            key = (
                nf.get("url", ""),
                nf.get("parameter", ""),
                nf.get("type", ""),
                nf.get("method", "unknown"),
            )
            existing = None
            for f in self.findings:
                if (f.get("url", ""), f.get("parameter", ""),
                        f.get("type", ""), f.get("method", "unknown")) == key:
                    existing = f
                    break
            if existing is not None:
                old_rank = _BURP_SEV_RANK.get(str(existing.get("severity", "Low")), 1)
                new_rank = _BURP_SEV_RANK.get(str(nf.get("severity", "Medium")), 2)
                if new_rank > old_rank:
                    existing["severity"] = nf.get("severity")
                    upgraded += 1
                existing["burp_confirmed"] = True
            else:
                self._add_finding(nf)
                self._burp_findings += 1
                merged += 1
        logger.info(
            f"📥 [Burp] 结果合并完成: 新增 {merged}，升级 {upgraded}，"
            f"共处理 {len(findings)} 条 issue"
        )
    except Exception as e:
        logger.warning(f"⚠️ Burp Scanner 集成失败: {e}")


async def _execute_with_limiting(self):
    # ★★★ 关键修复：兜底检查 rate_limiter ★★★
    if getattr(self, 'rate_limiter', None) is None:
        from vulnclaw.ai.v100.rate_limiter import get_rate_limiter
        self.rate_limiter = get_rate_limiter(getattr(self, 'initial_qps', 3))
        logger.warning("⚠️ [_execute_with_limiting] 自动创建 rate_limiter（兜底）")
    logger.info("⚔️ [攻击执行] 开始执行（多消费者并发模式）...")
    if getattr(settings, "engine_target_scope_enforce", True):
        from urllib.parse import urlparse as _up_d
        _mh = str(getattr(self, "target", "") or "")
        _main_host = (_up_d(_mh).hostname or "?").lower() if _mh else "?"
        _scope_entries = parse_scope()
        logger.info(
            f"   [D2] 引擎目标域硬约束 ON: 主域={_main_host} "
            f"scope={_scope_entries or '未配置(退化为仅主域)'} "
            f"粘滞剔除阈值={getattr(settings, 'sticky_fail_threshold', 2)}"
        )
    # 消费点3：引擎任务并发优先读目标请求能力探测结果（未探测/失败 → None → 原静态默认值）
    from vulnclaw.core.target_capacity_probe import get_safe_concurrency
    # 工作流10：显式扫描模式指定的并发优先（用户显式意图 > 自动探测）
    _profile_conc = int(getattr(self, "scan_concurrency", 0) or 0)
    # 工作流10：--adaptive 自适应并发（探测目标 RTT/错误率后给推荐并发；默认关闭）
    if getattr(self, "scan_adaptive", False):
        try:
            from vulnclaw.core.adaptive_concurrency import get_adaptive_concurrency
            _adaptive_rec = int(await get_adaptive_concurrency().probe(self.target) or 0)
            if _adaptive_rec > 0:
                _profile_conc = _adaptive_rec
                logger.info(f"   [adaptive] 目标探测推荐并发: {_adaptive_rec}")
        except Exception as exc:  # noqa: BLE001 - 探测失败回退原并发
            logger.debug(f"自适应并发探测失败（忽略）: {exc}")
    MAX_CONCURRENT = _profile_conc or int(get_safe_concurrency() or getattr(settings, "orchestrator_max_concurrent", 10))
    # 第3次修复：attack 阶段预算硬顶（settings.attack_node_budget，P0 已收口为正式字段，
    # 默认 500s 且须小于外层 phase_timeout_scan_s=600）。LLM QPS 降级(1.5~2.1)时任务
    # 墙钟时间不可控，用 deadline 保证 attack 节点耗时上限。超预算任务判败出队
    # （SP21.2：动态补测任务 protected 保留宽限窗口），已产出的 finding 已进 StreamVerify 队列。
    # 超时工作量自适应（2026-09-06）：与 scan 外层预算同源(compute_adaptive_budget)，
    # 保证 内层 < 外层。封顶用外层动态预算-余量（外层已在 orchestrator taskgen 后重算）。
    from vulnclaw.core.target_capacity_probe import get_capacity, compute_adaptive_budget
    _worker = MAX_CONCURRENT  # 已取 get_safe_concurrency() or 静态默认值
    _cap = get_capacity()
    _avg_rt_ms = (_cap.avg_rt_ms if (_cap and _cap.probed) else 200.0)
    _pending = self.task_queue.pending_count() if hasattr(self.task_queue, "pending_count") else 0
    _outer = float((getattr(self, "_phase_budgets", {}) or {}).get(
        "scan", getattr(settings, "phase_timeout_scan_s", 600)))
    attack_budget = min(compute_adaptive_budget(_pending, _worker, _avg_rt_ms), _outer - 80)
    self._attack_deadline_ts = time.time() + attack_budget
    logger.info(f"   [deadline] attack 阶段预算(自适应): {attack_budget:.0f}s | 待执行={_pending} worker={_worker} rt={_avg_rt_ms:.0f}ms 外层={_outer:.0f}s")
    # 调度信号量：worker 并发跑 _run_one_task，但真正调用任务体再限流一层。
    # 注：该 semaphore 与 _run_one_task 内部 rate_limiter/并发模型叠加后，
    # 瞬时出请求上限为 MAX_CONCURRENT * 每个引擎平均并发子请求（通常<=2）。
    execute_semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    count_lock = asyncio.Lock()
    processed = 0
    last_reported = 0
    queue_ended = asyncio.Event()  # 策略3：sentinel 守望者触发后通知 worker 立即退
    async def _worker(worker_id: int):
        nonlocal processed, last_reported
        while True:
            if queue_ended.is_set():
                return
            # P3-9 背压：verify 待处理堆积超阈值时暂停取新任务（默认关：
            # settings.backpressure_enabled=False 恒放行，行为不变）
            try:
                from vulnclaw.core.backpressure import get_backpressure_gate
                _bp = get_backpressure_gate()
                _pending = getattr(self, "_pending_verify", None)
                if _bp.enabled and _pending is not None:
                    while not _bp.should_proceed(len(_pending)) and not queue_ended.is_set():
                        await asyncio.sleep(_bp.poll)
            except Exception:  # noqa: BLE001 - 背压为增强项，异常绝不影响 worker
                pass
            # 诊断 watchdog：记录每个 worker 当前所处阶段
            self._dbg_workers[worker_id] = "get_next"
            # 拿到真实 task_id → 不再用 time.time() 传假值
            full = await self.task_queue.get_next_full()
            if full is None:
                # 队列为空但尚未发 sentinel → 短暂退让（避免消费者“空转”抢锁）
                # 正常路径下 sentinel 守望者很快就会封队，这里等一下即退出
                await asyncio.sleep(0.05)
                continue
            task_id, task = full
            _pick_ts = getattr(self, "_task_pick_ts", None)
            if _pick_ts is None:
                _pick_ts = dict()
                self._task_pick_ts = _pick_ts
            _pick_ts.setdefault(task_id, time.time())
            # sentinel：让 worker 收到结束信号
            if isinstance(task, dict) and task.get("__done_sentinel__") is True:
                logger.info(f"   🏁 [w{worker_id}] 收到 sentinel，退出")
                return
            # _run_one_task 内会：获取下一个模型 → 限流 acquire → semaphore → 执行
            self._dbg_workers[worker_id] = f"run:{task_id}"
            logger.info(f"   ▶️ [w{worker_id}] pick {task_id} {task.get('engine', 'unknown')}/{task.get('param', '')}")
            try:
                result = await self._run_one_task(task, task_id, execute_semaphore)
            except asyncio.CancelledError:
                logger.warning(f"   ⛔ [w{worker_id}] worker 被 CancelledError 终止 (task={task_id})")
                raise
            except Exception as e:
                logger.warning(f"   ❌ [w{worker_id}] 任务异常: "
                               f"{task.get('engine', '?')}/{task.get('param', '')} - {e}")
                # 兜底完成标记，避免 pending 队列一直悬着
                try:
                    await self.task_queue.complete_task(task_id, success=False)
                except Exception:
                    logger.debug("suppressed exception (core audit)")
                continue
            # 并发安全计数 + 每 10 次日志
            async with count_lock:
                processed += 1
                if processed - last_reported >= 10:
                    last_reported = processed
                    try:
                        # 策略6：5s TTL 缓存版，避免 1s 内重复取两次统计
                        stats = await self.get_rate_stats_cached()
                        model_stats = await self.get_model_stats_cached()
                        per_model = model_stats.get('per_model', {})
                        logger.info(
                            f"   📊 进度: {processed} 个任务 "
                            f"QPS: {stats['current_qps']:.1f}, "
                            f"发现: {len(self.findings) + len(self._pending_verify)}"
                        )
                        if per_model:
                            logger.info(
                                f"   🔧 模型调用: "
                                f"{', '.join([f'{k}:{v}' for k, v in per_model.items()])}"
                            )
                    except Exception:
                        # 日志统计不应影响主流程
                        pass
            # 避免 pylint 抱怨"unused variable"：真实 result 已在 complete_task 中记录
            _ = result
    async def _sentinel_guard():
        """策略3：生产端封队 → 等队列 pending 连续稳定“空”两次 → 广播 sentinel。
        目的：
          - 防止"还有任务在执行，执行完会 retry 入队"时过早发 sentinel；
          - 连续 2 次（间隔 200ms）drained → 可安全认为不会再有新任务进来了。
        调度审计A（自愈）：is_drained 异常有界重试（连续5次失败即放弃等待，
        直接广播，避免 guard 空转）；finally 兜底广播 sentinel——哪怕中途崩溃，
        worker 也能收到 sentinel 正常退出，杜绝攻击阶段永久挂起。
        """
        try:
            stable = 0
            fail = 0
            _guard_start = time.monotonic()
            # 审计I3: 封板不再是"连续 2 次≈400ms"就广播——动态补测任务(param_mining
            # /live:*)延迟入队时 400ms 空窗会被误判为空 → 补测任务入队后无人消费。
            # 双条件：连续 2 次 drained 且 总观察时长 ≥ 1.0s；仍由 fail>=5 有界兜底。
            _MinObserve = 1.0
            while True:
                try:
                    drained = await self.task_queue.is_drained()
                    fail = 0
                except Exception as _qd:
                    fail += 1
                    if fail >= 5:
                        break
                    await asyncio.sleep(0.2)
                    continue
                stable = (stable + 1) if drained else 0
                if stable >= 2 and time.monotonic() - _guard_start >= _MinObserve:
                    break
                await asyncio.sleep(0.2)
        finally:
            if not queue_ended.is_set():
                try:
                    # 给所有 worker 一人一个 sentinel（priority=0 最高优先级会立刻被弹出）
                    await self.task_queue.mark_production_done(num_consumers=MAX_CONCURRENT)
                except Exception as _mp:
                    logger.warning(f"⛔ [sentinel] 兑底广播 sentinel 失败: {_mp}")
                queue_ended.set()
    # ============================================================
    # 正式启动：N 个 worker + 1 个 sentinel 守望者
    # ============================================================
    workers = [asyncio.create_task(_worker(i)) for i in range(MAX_CONCURRENT)]
    guard = asyncio.create_task(_sentinel_guard())
    self._dbg_workers = {}

    async def _watchdog():
        """诊断 watchdog：每 30s 输出队列/worker 状态，用于定位静默挂起点。"""
        while True:
            await asyncio.sleep(30)
            try:
                q = self.task_queue
                alive = sum(1 for w in workers if not w.done())
                # 调度审计A（兜底）：guard 异常退出且未广播，而队列已 drained →
                # 强发 sentinel，防止 worker 们永久空转、attack 阶段永不结束。
                if not queue_ended.is_set() and guard.done() and await q.is_drained():
                    await self.task_queue.mark_production_done(num_consumers=MAX_CONCURRENT)
                    queue_ended.set()
                    logger.warning(
                        "🚨 [watchdog][A修复] sentinel 守望者异常退出未广播，已兑底强制广播"
                    )
                _pick_ts = getattr(self, "_task_pick_ts", {}) or {}
                _now = time.time()
                _stale = sorted(
                    ((_tid, _now - _ts) for _tid, _ts in _pick_ts.items() if _now - _ts > 300),
                    key=lambda x: -x[1],
                )
                info = (
                    f"   👁 [watchdog] queue={len(q._queue)} pending={len(q._pending_tasks)} "
                    f"drained={await q.is_drained()} workers_alive={alive} "
                    f"workers={dict(getattr(self, '_dbg_workers', {}))}"
                )
                if _stale:
                    info += f" stale={_stale[0][1]:.0f}s:{_stale[0][0]}"
                    if _stale[0][1] > 600:
                        logger.warning(
                            f"   🚨 [D1.3] 任务滞留超过 600s: {_stale[0][0]}（回查其 engine/param）"
                        )
                    # 调度审计K（自愈）：滞留任务强制判失败并出队。
                    # 否则 pending 恒非空 → is_drained() 永远 False → sentinel 不广播
                    # → 所有 worker 永久空转 get_next，attack 阶段挂死（真扫实证：
                    # task_63 滞留 300s 即导致 queue=0/pending=2/drained=False）。
                    # 取舍：宁可把卡死任务判失败（后续可补测），也不让整阶段挂起。
                    _reaped = 0
                    for _tid, _age in _stale:
                        if _age <= 300:
                            continue
                        try:
                            await self.task_queue.complete_task(_tid, success=False)
                            _reaped += 1
                        except Exception:
                            logger.debug("suppressed exception (core audit)")
                        try:
                            self._task_pick_ts.pop(_tid, None)
                        except Exception:
                            logger.debug("suppressed exception (core audit)")
                    if _reaped:
                        logger.warning(
                            f"   🧹 [D1.3] 强制回收 {_reaped} 个滞留任务(>300s)，"
                            f"解除 drained 阻塞"
                        )
                logger.info(info)
            except Exception as e:
                logger.warning(f"   👁 [watchdog] 异常: {e}")

    watchdog = asyncio.create_task(_watchdog())

    async def _orphan_spy():
        """D1.1: 孤儿协程诊断——运行中且不属于 worker/guard/spy 的任务打 WARNING 定位。"""
        while True:
            await asyncio.sleep(15)
            try:
                managed = {id(t) for t in workers} | {id(guard), id(enforcer), id(watchdog)}
                leaks = []
                for t in asyncio.all_tasks():
                    if t is asyncio.current_task() or t.done() or id(t) in managed:
                        continue
                    try:
                        f = t.get_coro().cr_frame
                        loc = f"{f.f_code.co_filename.split(chr(92))[-1]}:{f.f_lineno}" if f else "?"
                    except Exception:  # noqa: BLE001
                        loc = "?"
                    leaks.append(loc)
                if leaks:
                    logger.warning(
                        f"   👁 [D1.1] 孤儿协程泄漏 {len(leaks)} 个（持续存在则需排查）: {leaks[:5]}"
                    )
            except Exception as _s:  # noqa: BLE001
                logger.debug(f"   👁 [D1.1] spy 异常: {_s}")

    spy = asyncio.create_task(_orphan_spy())

    async def _deadline_enforcer():
        """预算耗尽时清空未执行任务并通知 worker 收尾。

        SP21.2：清空前先保留动态补测任务（param_mining / live:*），给宽限窗口
        执行完，避免固定墙钟误杀阶段中后期入队的补测任务（真扫观察项收口）；
        无受保护任务时行为与旧版完全一致（零回归）。
        """
        await asyncio.sleep(attack_budget)
        try:
            grace = float(getattr(settings, "attack_dynamic_grace_s", 45.0))
            n = await self.task_queue.fail_all_pending(
                reason=f"attack 预算 {attack_budget:.0f}s 耗尽", protect=True
            )
            protected = await self.task_queue.protected_pending_count()
            if protected:
                logger.warning(
                    f"   [deadline] 保留 {protected} 个动态补测任务, 宽限 {grace:.0f}s 内执行"
                )
                # 审计E: 宽限窗口不再是纯等待——主动消费并执行受保护补测任务，
                # 兑现 SP21.2 宽限意图（原实现：workers 已退出，补测任务无人消费，
                # 干等 45s 后被 fail_all_pending(protect=False) 直接判败=静默丢弃）
                _g_until = time.time() + grace
                while time.time() < _g_until:
                    _full = await self.task_queue.get_next_full()
                    if _full is None:
                        await asyncio.sleep(0.2)
                        continue
                    _g_id, _g_task = _full
                    if isinstance(_g_task, dict) and _g_task.get("__done_sentinel__") is True:
                        continue
                    self._dbg_workers[9999] = f"grace:{_g_id}"
                    try:
                        await self._run_one_task(_g_task, _g_id, execute_semaphore)
                    except asyncio.CancelledError:
                        raise
                    except Exception as _ge:
                        logger.warning(f"   [grace] 补测任务异常 {_g_id}: {_ge}")
                        try:
                            await self.task_queue.complete_task(_g_id, success=False)
                        except Exception:
                            logger.debug("suppressed exception (core audit)")
                n += await self.task_queue.fail_all_pending(
                    reason=f"宽限 {grace:.0f}s 结束", protect=False
                )
            queue_ended.set()
            logger.warning(
                f"   [deadline] attack 预算 {attack_budget:.0f}s 耗尽: "
                f"清空 {n} 个未执行任务, 已产出 finding={len(self.findings) + len(self._pending_verify)}"
            )
        except Exception as e:
            logger.warning(f"   [deadline] enforcer 异常: {e}")

    enforcer = asyncio.create_task(_deadline_enforcer())
    try:
        # sentinel guard 尽先于最新 worker 结束：一旦 drained 就广播 sentinel，
        # 等 guard 完成后，再 gather 所有 worker 正常退出
        await guard
        await asyncio.gather(*workers, return_exceptions=True)
    except Exception:
        # 任意异常：先全量 cancel，再上报
        for t in workers + [guard, watchdog, spy]:
            if not t.done():
                t.cancel()
        await asyncio.gather(*workers, guard, watchdog, spy, return_exceptions=True)
        raise
    finally:
        watchdog.cancel()
        enforcer.cancel()
        spy.cancel()
    logger.info(f"   Execution complete: {processed} tasks")
async def _run_one_task(self, task: Dict, task_id: str, semaphore: asyncio.Semaphore):
    """单任务完整生命周期（模型选择 → 限流 → 执行），整体受超时约束。

    第3次修复：
    1. 模型选择/限流等待原先在 wait_for 作用域之外，500错误风暴下降级 QPS 1.5
       时 acquire 可无限阻塞（task_1 卡 9 分钟的根因）—— 现全部纳入超时。
    2. 超时上限取 min(240s, attack 剩余预算)，保证 attack 节点墙钟时间可控。
    3. 超时/异常一律判败出队，不再 requeue（240s x 3 重试 = 960s 是耗时失控主因）。
    """
    # D2: 引擎目标域硬约束（fail-closed）——外域任务在被消费前剔除，不发任何请求。
    if getattr(settings, "engine_target_scope_enforce", True):
        allowed, reason = _engine_task_target_allowed(self, task)
        if not allowed:
            logger.warning(
                f"   [D2] 越界目标剔除: {task.get('engine', '?')}/"
                f"{task.get('param', '')} target={str(task.get('target', ''))[:120]} ({reason})"
            )
            if hasattr(self.task_queue, 'complete_task'):
                await self.task_queue.complete_task(task_id, success=False)
            return None
# SP27: 指令消费——排除项过滤 + 重点(target)增强（--instruction 的 Focus/Out of scope）
    _ins_ctx = getattr(settings, "instruction_context", None)
    if _ins_ctx:
        _tgt = str(task.get("target", ""))
        if _ins_ctx.exclude and any(_k in _tgt for _k in _ins_ctx.exclude):
            logger.info(f"   ⏭️ [SP27] 指令排除命中，跳过任务: {_tgt}")
            if hasattr(self.task_queue, 'complete_task'):
                await self.task_queue.complete_task(task_id, success=True)
            return None
        if _ins_ctx.focus and any(_k in _tgt for _k in _ins_ctx.focus):
            task["payload_limit"] = max(int(task.get("payload_limit", 5)), 12)
    deadline_ts = getattr(self, "_attack_deadline_ts", None)
    _is_dynamic = is_protected_task(task)
    if deadline_ts is not None:
        budget = deadline_ts - time.time()
        if budget <= 0 and not _is_dynamic:
            logger.warning(f"   [deadline] 预算已耗尽，任务直接判败出队: {task_id}")
            if hasattr(self.task_queue, 'complete_task'):
                await self.task_queue.complete_task(task_id, success=False)
            return None
        if budget > 0:
            timeout = max(10.0, min(240.0, budget))
        else:
            # SP21.2: 动态补测任务在预算耗尽后仍给宽限窗口（<=60s 上限）
            grace = float(getattr(settings, "attack_dynamic_grace_s", 45.0))
            timeout = max(10.0, min(60.0, grace))
    else:
        timeout = 240.0

    async def _lifecycle():
        model = await asyncio.wait_for(self._get_next_model(), timeout=settings.subprocess_timeout)
        wait_time = await asyncio.wait_for(self.rate_limiter.acquire(model), timeout=60)
        if wait_time > 0:
            await asyncio.sleep(min(wait_time, 30))
        async with semaphore:
            return await self._safe_execute_task(task)

    try:
        result = await asyncio.wait_for(_lifecycle(), timeout=timeout)
        if hasattr(self.task_queue, 'complete_task'):
            await self.task_queue.complete_task(task_id, success=True)
        self._task_pick_ts.pop(task_id, None)
        return result
    except asyncio.CancelledError:
        logger.debug(f"   [cancel] 任务被取消: {task_id}")
        if hasattr(self.task_queue, 'complete_task'):
            await self.task_queue.complete_task(task_id, success=False)
        self._task_pick_ts.pop(task_id, None)
        raise
    except asyncio.TimeoutError:
        self._sticky_mark_failed(task)
        logger.warning(
            f"   [timeout] 任务执行超时 ({timeout:.0f}s), 判失败出队(不重试): "
            f"{task.get('engine', 'unknown')}/{task.get('param', '')}"
        )
        if hasattr(self.task_queue, 'complete_task'):
            await self.task_queue.complete_task(task_id, success=False)
        self._task_pick_ts.pop(task_id, None)
        return None
    except Exception as e:
        self._sticky_mark_failed(task)
        logger.warning(f"   [error] 任务异常: {task.get('engine', 'unknown')}/{task.get('param', '')} - {e}")
        if hasattr(self.task_queue, 'complete_task'):
            await self.task_queue.complete_task(task_id, success=False)
        self._task_pick_ts.pop(task_id, None)
        return None
async def _execute_task(self, task: Dict) -> Optional[Dict]:
    task_type = task.get("type", "engine_check")
    if task_type == "global_scan":
        return await self._execute_global_scan(task)
    elif task_type == "engine_bundle":
        return await self._execute_engine_bundle(task)
    elif task_type == "batch":
        # P1-4: BatchProcessor 批量任务（一次 AI 调用判定多个子任务）
        return await self._execute_batch(task)
    elif task_type in ("engine_check", "api_check"):
        return await self._execute_engine_check(task)
    elif task_type == "cve_scan":
        # Z1.2：CVE 索引命中的高危 CVE 专项扫描（nuclei -id）
        return await _execute_cve_scan(self, task)
    elif task_type in {"stateful_flow", "multi_identity_compare", "openapi_spec_check"}:
        logger.warning(
            "Skipping phase-2 placeholder task type %s (framework stub, not yet implemented)",
            task_type,
        )
        return None
    else:
        logger.warning("Unknown task type: %s", task_type)
        return None


async def _execute_batch(self, task: Dict) -> Optional[List[Dict]]:
    """P1-4: 批量任务——子任务规则引擎并行跑，合并为一次 AI 判定，结果回写。

    子任务为 engine_check（同参数多引擎）；先并行执行规则引擎收集响应片段，
    再组装成批量 Prompt 一次 AI 判定，确认项直接记录为 finding。
    """
    from vulnclaw.ai.v100.batch_processor import BatchProcessor
    bp = self.batch_processor
    if bp is None:
        bp = BatchProcessor(max_batch_size=settings.ai_batch_size)
        self.batch_processor = bp
    subtasks = task.get("tasks", [])
    if not subtasks:
        return None

    async def _run_one(sub: Dict):
        try:
            res = await self._execute_engine_check(sub)
            if isinstance(res, dict):
                return {**sub, "response_snippet": str(res.get("evidence", ""))[:300]}
            return sub
        except Exception as e:
            logger.warning(f"   [batch] 子任务执行失败: {e}")
            return sub

    enriched = await asyncio.gather(*(_run_one(s) for s in subtasks), return_exceptions=True)
    batch = {
        **task,
        "tasks": [e if isinstance(e, dict) else s for e, s in zip(enriched, subtasks)],
    }
    prompt = bp.generate_batch_prompt(batch)
    try:
        raw = await self._ask_ai(prompt, compress=True, task_type="verify")
    except Exception as e:
        logger.warning(f"   [batch] AI 判定失败，保留规则结果: {e}")
        return None
    verdicts = bp.parse_batch_response(raw, batch)
    confirmed = []
    for v in verdicts:
        if v.get("has_vuln"):
            sub = v.get("task", {}) or {}
            confirmed.append({
                "url": sub.get("target", self.target),
                "type": sub.get("engine", "batch"),
                "parameter": sub.get("param", ""),
                "severity": v.get("severity", "Medium"),
                "confidence": v.get("confidence", "低"),
                "evidence": v.get("evidence", ""),
                "ai_verdict": "真实漏洞",
                "bundle_engine": sub.get("engine", "batch"),
            })
    for f in confirmed:
        if (str(f.get('url', '')), str(f.get('type', ''))) not in self._seen_ut:
            self._add_finding(f)
            logger.info(f"   📦 [Batch] 确认: {f.get('type')} @ {f.get('parameter')}")
    return confirmed or None


def _safe_parse_bundle_json(raw_response: str) -> List[Dict[str, Any]]:
    """Parse a batch verdict response with JSON, literal, and regex fallbacks."""
    text = raw_response.strip()
    candidates = [text]
    match = re.search(r"\[[\s\S]*\]", text)
    if match:
        candidates.append(match.group(0))
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
            if isinstance(parsed, dict):
                return [parsed]
        except (json.JSONDecodeError, TypeError):
            logger.debug("suppressed exception (core audit)")
        try:
            parsed = ast.literal_eval(candidate)
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
            if isinstance(parsed, dict):
                return [parsed]
        except (ValueError, SyntaxError, TypeError):
            logger.debug("suppressed exception (core audit)")
    results = []
    pattern = re.compile(
        r"(?:index|idx|\"index\"|'index')\s*[:=]\s*(\d+).*?"
        r"(?:has_vuln|\"has_vuln\"|'has_vuln')\s*[:=]\s*(true|false).*?"
        r"(?:confidence|\"confidence\"|'confidence')\s*[:=]\s*[\"']?([^,}\"']+)",
        re.IGNORECASE | re.DOTALL,
    )
    for item in pattern.finditer(text):
        results.append({
            "index": int(item.group(1)),
            "has_vuln": item.group(2).lower() == "true",
            "confidence": item.group(3).strip(),
            "evidence": "",
        })
    return results
async def _execute_engine_bundle(self, task: Dict) -> Optional[Dict]:
    """Run bundled engine checks concurrently, then request one batch AI verdict.

    优化（建议 1）：3 个 top engine 不再串行调用，而是用 asyncio.gather 一起
    跑，单个 bundle 的规则执行时长从 sum(t_i) 降到 max(t_i)；同时为了不让
    一个参数同时发出 3×payload_limit 个 HTTP 请求打爆目标，再叠加一层
    bundle 内部小限流（默认 2），这样对 initial_qps=3 的弱目标也更友好。
    单个引擎异常不会让整个 bundle 失败，而是过滤后保留剩下的正常结果。
    """
    engines = task.get("engines", [])
    if not engines:
        return None

    bundle_sem = getattr(self, "_bundle_engine_semaphore", None)
    if bundle_sem is None:
        bundle_sem = asyncio.Semaphore(2)
        self._bundle_engine_semaphore = bundle_sem

    async def _run_one(engine_name: str):
        async with bundle_sem:
            try:
                return await self._execute_engine_check({
                    **task,
                    "type": "engine_check",
                    "engine": engine_name,
                })
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "   ⚠️ Bundle 引擎 %s 异常（已跳过，不影响其它引擎）: %s",
                    engine_name,
                    exc,
                )
                return None

    # 整改清单 item 3：外层取消（整扫中止/超时）时显式回收所有 _run_one 子协程，
    # 杜绝子任务以 "cancelling" 态堆积成孤儿协程。仅做取消回收、不加硬超时，
    # 避免误杀合法慢引擎导致漏检（fail-closed 优先于速度）。
    gather_task = asyncio.gather(*(_run_one(name) for name in engines), return_exceptions=False)
    try:
        results = await gather_task
    except asyncio.CancelledError:
        gather_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await gather_task
        raise
    local_results = [
        {"engine": name, "result": result}
        for name, result in zip(engines, results)
        if isinstance(result, dict)
    ]
    if not local_results:
        return None
    # A4.3: 工具输出裁剪——每条 evidence 超阈值截断，防止 nuclei/ffuf 千行输出撑爆 LLM token
    _clip_max = int(getattr(settings, "context_clip_max_chars", 1500))
    evidence = [
        {
            "index": index,
            "engine": item["engine"],
            "type": item["result"].get("type", item["engine"]),
            "evidence": str(item["result"].get("evidence", ""))[:_clip_max],
        }
        for index, item in enumerate(local_results)
    ]
    prompt = (
        "请一次性判断以下多个引擎检测结果。只返回 JSON 数组，每项包含 "
        "index、has_vuln(true/false)、confidence、evidence。\n"
        f"检测结果\n{json.dumps(evidence, ensure_ascii=False, default=str)}"
    )
    try:
        parsed = _safe_parse_bundle_json(await self._ask_ai(prompt, compress=True, task_type="verify"))
    except Exception as exc:
        logger.warning(f"   ⚠️ Bundle AI 判定失败，保留规则结果: {exc}")
        parsed = []
    by_index = {item.get("index"): item for item in parsed if isinstance(item.get("index"), int)}
    for index, item in enumerate(local_results):
        verdict = by_index.get(index)
        result = item["result"]
        if verdict:
            result["ai_verdict"] = "真实漏洞" if verdict.get("has_vuln") else "非漏洞"
            result["ai_confidence"] = verdict.get("confidence", "")
            if verdict.get("evidence"):
                result["ai_evidence"] = verdict["evidence"]
        else:
            result["ai_verdict"] = "Bundle解析失败，采用规则结果"
        result["bundle_engine"] = item["engine"]
        # S2.1: 原地标注链信息（_pending_verify 与返回值共享同一 dict，
        # 拷贝式标注会导致最终报告丢失 chain_info——端到端实测发现）
        if isinstance(result, dict):
            try:
                result["chain_info"] = annotate_chain_info(
                    result, task.get("url") or self.target, str(task.get("param") or "")
                ).get("chain_info")
            except Exception:  # noqa: BLE001
                logger.debug("suppressed exception (core audit)")
    bundle_results = [item["result"] for item in local_results]
    # S1.2: 记录 bundle 首次执行结果（供 ReAct 深挖判断"本地判定模糊"）
    try:
        param_key = str(task.get("param") or "")
        if param_key:
            bucket = getattr(self, "_bundle_results", None)
            if bucket is None:
                bucket = {}
                self._bundle_results = bucket
            bucket.setdefault(param_key, []).extend(bundle_results)
    except Exception as _be:  # noqa: BLE001
        logger.debug(f"   [ReActDive] 记录 bundle 结果失败（不影响扫描）: {_be}")
    return {
        "type": "engine_bundle",
        "engine": engines,
        "param": task.get("param"),
        "results": bundle_results,
    }


# ------------------------------------------------------------------
# S1: ReActAgent 深挖阶段 —— V100=批量广度，ReAct=单点深度
# ------------------------------------------------------------------
async def _run_react_deep_dive(self):
    """S1: 深挖阶段——对本地判定模糊的参数启用 ReActAgent 多轮深挖。

    触发条件（S1.2）：engine_bundle 首次执行结果全部 low/info，或该参数无高/中危 finding。
    复用（S1 设计）：TOOL_REGISTRY 30 工具 + tool_success_rates 排序 + PlanFeedback。
    定位固化（S1.3）：深挖 finding 标记 source=react_agent 合入主链路。
    """
    if not getattr(self, "_ai_enabled", True):
        logger.info("ℹ️ [ReActDive] 纯引擎模式（AI 未配置），跳过深挖")
        return
    if not getattr(settings, "enable_react_dive", False):
        logger.info("ℹ️ [ReActDive] 未开启（ENABLE_REACT_DIVE=false / 未传 --deep），跳过深挖")
        return
    # A2.3: 多 Agent 编排模式（角色化子 Agent + 共享黑板 + 竞争协作）优先
    if getattr(settings, "enable_agent_roles", False):
        await self._run_multi_agent_dive()
        return
    candidates = self._collect_react_candidates()
    if not candidates:
        logger.info("ℹ️ [ReActDive] 无本地判定模糊参数，跳过深挖")
        return
    max_params = int(getattr(settings, "react_dive_max_params", 3))
    max_iters = int(getattr(settings, "react_dive_max_iterations", 5))
    per_budget = float(getattr(settings, "react_dive_budget", 150.0))
    logger.info(
        f"🤖 [ReActDive] 深挖阶段启动：{len(candidates)} 个模糊参数，"
        f"深挖前 {max_params} 个（每参数 ≤{max_iters} 轮，预算 {per_budget:.0f}s）"
    )
    from vulnclaw.ai.dispatcher import ReActAgent

    # S3.2: 唤醒 ClueEngine——用 recon 发现的 URL 预生成线索并注入 Agent 决策候选
    clue_engine = None
    if getattr(settings, "enable_clue_engine", True):
        try:
            from vulnclaw.ai.core import ClueEngine
            clue_engine = ClueEngine(self.session, self.target)
            await asyncio.wait_for(self._generate_clues_for_dive(clue_engine), timeout=float(settings.ai_router_timeout))
        except Exception as _ce:  # noqa: BLE001
            logger.debug(f"[ClueEngine] 预生成线索失败（继续深挖）: {_ce}")

    total_merged = 0
    for param in candidates[:max_params]:
        try:
            agent = ReActAgent(self.target, self.session, max_iterations=max_iters, focus_param=param, stage="execute")
            # S3.2: 注入 ClueEngine，使 _decide_action 读取上下文线索
            if clue_engine is not None:
                agent.clue_engine = clue_engine
            # 复用主链路已初始化的 memory（全局单例），避免二次阻塞初始化
            if getattr(self, "memory", None) is not None:
                agent.memory = self.memory
            report = await asyncio.wait_for(agent.run(), timeout=per_budget)
            total_merged += self._merge_react_findings(report, param)
        except asyncio.TimeoutError:
            logger.warning(f"⏰ [ReActDive] 参数 {param} 深挖超时（{per_budget:.0f}s），跳过")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"⚠️ [ReActDive] 参数 {param} 深挖异常: {exc}")
    logger.info(f"🤖 [ReActDive] 深挖阶段完成：共合入 {total_merged} 个 finding")


def _collect_react_candidates(self) -> List[str]:
    """S1.2: 收集"本地判定模糊"的参数。

    判定规则：该参数无高/中危 finding，且 bundle 首次执行结果为空或全部 low/info
    （= 规则引擎与 AI 批量判定都无法形成有效结论，交给 ReAct 单点深挖）。
    """
    bundle_results = getattr(self, "_bundle_results", None) or {}
    if not bundle_results:
        return []
    # 验收/调试：REACT_DIVE_FORCE=true 时跳过"模糊"门槛，把所有已执行参数交深挖，
    # 用于验证 ReActAgent 链路本身（默认关闭，不改变正常扫描行为）。
    if getattr(settings, "react_dive_force", False):
        forced = [p for p in bundle_results if p]
        logger.warning(
            f"⚠️ [ReActDive] react_dive_force 已开启：跳过模糊判定门槛，"
            f"强制深挖 {len(forced)} 个参数（会产生真实 LLM 调用与审计记录）"
        )
        return forced
    param_has_strong = set()
    for f in getattr(self, "findings", []) or []:
        p = f.get("parameter") or f.get("param") or ""
        sev = str(f.get("severity", "")).lower()
        if p and sev in ("high", "critical", "严重", "高"):
            param_has_strong.add(p)
    candidates = []
    for param, results in bundle_results.items():
        if param in param_has_strong:
            continue
        if not results:
            candidates.append(param)
            continue
        all_low = all(
            str(r.get("severity", "low")).lower() in ("low", "info", "低", "信息", "")
            for r in results
        )
        if all_low:
            candidates.append(param)
    return candidates


def _merge_react_findings(self, report: Dict, param: str) -> int:
    """S1.3: 把 ReAct 深挖产出的 finding 合入主链路（source=react_agent 定位固化）。"""
    vulns = (report or {}).get("vulnerabilities") or []
    merged = 0
    for v in vulns:
        if not isinstance(v, dict):
            continue
        if not v.get("type"):
            continue
        v.setdefault("url", getattr(self, "target", ""))
        v.setdefault("parameter", param)
        v.setdefault("source", "react_agent")
        if not v.get("severity"):
            v["severity"] = "Medium"
        self._add_finding(v)
        merged += 1
    if merged:
        logger.info(f"🤖 [ReActDive] 参数 {param} 深挖产出 {merged} 个 finding（source=react_agent）")
    return merged


# ------------------------------------------------------------------
# S2: 跨引擎攻击链路由（chain_router）
# ------------------------------------------------------------------
async def _run_chain_router(self):
    """S2.2: 跨引擎攻击链路由——基于 S2.1 链信息把已确认发现串成后续动作。

    确定性规则链（LLM 决策链后续叠加）：
      - SSRF -> 对 evidence 中的内网地址做二次探测；命中 6379/Redis 特征 -> Redis 未授权链
      - 文件上传 / LFI -> 验证上传产物是否可被服务端解析执行（-> RCE 链）
    所有链式 finding 标记 source=chain_router。
    """
    if not getattr(settings, "enable_chain_router", True):
        logger.debug("[ChainRouter] 未开启（ENABLE_CHAIN_ROUTER=false），跳过")
        return
    findings = getattr(self, "findings", None) or []
    chained = 0
    for f in list(findings):
        if not isinstance(f, dict):
            continue
        ftype = str(f.get("type", "")).lower()
        if "ssrf" in ftype or "ssr" in ftype:
            chained += await self._chain_ssrf(f)
        elif any(k in ftype for k in ("upload", "上传", "lfi", "文件包含")):
            chained += await self._chain_upload(f)
    if chained:
        logger.info(f"🔗 [ChainRouter] 攻击链合入 {chained} 个链式 finding（source=chain_router）")


async def _chain_ssrf(self, finding: Dict) -> int:
    """SSRF -> 内网探测 / Redis 未授权链。"""
    from vulnclaw.core.utils import build_attack_url, async_get

    url = str(finding.get("url", ""))
    param = str(finding.get("parameter", "") or "")
    evidence = str(finding.get("evidence", "") or "")
    if not url or not param:
        return 0
    intranet_addrs = re.findall(
        r"(?:https?://)?(?:127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d{1,5})?(?:[/\w.?&=%-]*)",
        evidence,
    )
    if not intranet_addrs:
        return 0
    chained = 0
    seen = set()
    for addr in cap(intranet_addrs, settings.max_intranet_addrs):
        if addr in seen:
            continue
        seen.add(addr)
        try:
            attack_url = build_attack_url(url, param, addr, "")
            resp = await async_get(attack_url, session=self.session, timeout=8, no_retry=True)
            if resp is None or resp[0] == 0:
                continue
            status, text = resp[0], str(resp[1] or "")
            text_head = text[:200]
            is_redis = bool(
                re.match(r"^[+-$*:]", text_head)
                or "redis_version" in text_head
                or "redis" in text_head.lower()
            )
            self._add_finding({
                "url": url,
                "parameter": param,
                "payload": addr,
                "type": "SSRF-Redis未授权" if is_redis else "SSRF-内网探测",
                "severity": "Critical" if is_redis else "High",
                "ai_verdict": "高（SSRF链复测命中）",
                "confidence": "high",
                "evidence": f"SSRF 通过 {param} 访问内网 {addr}，状态 {status}"
                            f"{'，Redis 未授权特征' if is_redis else ''}",
                "source": "chain_router",
            })
            chained += 1
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[ChainRouter] SSRF 探测 {addr} 失败: {exc}")
    return chained


async def _chain_upload(self, finding: Dict) -> int:
    """文件上传/LFI -> 上传产物可执行性验证（-> RCE 链）。"""
    from vulnclaw.core.utils import async_get

    evidence = str(finding.get("evidence", "") or "")
    upload_urls = re.findall(r"https?://\S+", evidence)
    if not upload_urls:
        return 0
    chained = 0
    for u in cap(upload_urls, settings.max_upload_urls):
        try:
            resp = await async_get(u, session=self.session, timeout=10, no_retry=True)
            if resp is None or resp[0] == 0:
                continue
            status = resp[0]
            headers = resp[2] if len(resp) > 2 and isinstance(resp[2], dict) else {}
            text = str(resp[1] or "")
            ctype = str(headers.get("content-type", "")).lower() if headers else ""
            # 可执行判断：非纯静态类型 + 响应体非空（脚本被解析执行返回动态内容）
            executable = bool(text) and (not ctype or "text/html" in ctype or "text/plain" in ctype)
            if executable:
                self._add_finding({
                    "url": u,
                    "type": "文件上传-可执行文件",
                    "severity": "High",
                    "ai_verdict": "高（上传产物可被解析执行，疑似 RCE 链）",
                    "confidence": "medium",
                    "evidence": f"上传产物 {u} 可被访问且内容为 {ctype or '未知类型'}（状态 {status}），"
                                f"存在被服务端解析执行的可能（-> RCE 链）",
                    "source": "chain_router",
                })
                chained += 1
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[ChainRouter] 上传产物验证 {u} 失败: {exc}")
    return chained


async def _generate_clues_for_dive(self, engine=None):
    """S3.2: 深挖前用 recon 发现的 URL 预生成 ClueEngine 线索（写入扫描上下文）。

    engine 为空时走 process_url_for_clues 对外接口（自建引擎并带 session/target）。
    """
    brief = getattr(self, "_recon_brief", None) or {}
    url_pool = []
    for key in ("apis", "js_endpoints", "found_dirs"):
        for u in brief.get(key, []) or []:
            if isinstance(u, str) and u.startswith("http"):
                url_pool.append(u)
    url_pool = cap(list(dict.fromkeys(url_pool)), settings.max_url_pool)
    if not url_pool:
        return
    for u in url_pool:
        try:
            normal = await _fetch_normal_response(self, u)
            status, text = normal[0], str(normal[1] or "")
            headers = normal[2] if len(normal) > 2 else {}
            if engine is not None:
                await engine.process_url(u, status, text, headers, 0.0)
            else:
                from vulnclaw.ai.core import process_url_for_clues
                await process_url_for_clues(
                    u, status, text, headers, 0.0,
                    attack_status=None, attack_text=None, payload=None, waf_type=None,
                    session=self.session, target=self.target
                )
        except Exception as _ge:  # noqa: BLE001
            logger.debug(f"[ClueEngine] 线索生成 {u} 失败: {_ge}")


async def _persist_scan_memory(self):
    """S3.1: 扫描收尾——把本次关键发现写入 VectorMemory（跨会话学习）。

    下一次扫描对同指纹目标会自动召回（见 ReActAgent.run() 的 memory.recall）。
    """
    try:
        memory = getattr(self, "memory", None)
        if memory is None:
            return
        written = 0
        for f in getattr(self, "findings", None) or []:
            if not isinstance(f, dict):
                continue
            vuln_type = str(f.get("type", "") or "")
            if not vuln_type:
                continue
            await memory.add_experience(
                target=getattr(self, "target", ""),
                vuln_type=vuln_type,
                payload=str(f.get("payload", "") or ""),
                success=True,
                evidence=str(f.get("evidence", "") or "")[:500],
            )
            written += 1
        if written:
            logger.info(f"🧠 [ScanMemory] 写入 {written} 条扫描经验到 VectorMemory")
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[ScanMemory] 写入失败（不影响扫描）: {exc}")


# ------------------------------------------------------------------
# A2: 多 Agent 协作（角色化子 Agent + 共享黑板 + 竞争协作 + 冲突消解）
# ------------------------------------------------------------------
async def _run_multi_agent_dive(self):
    """A2.3: 主编排者——spawn 角色化子 Agent 并行深挖，共享黑板，父层只做分解与调度。

    A2.4: 竞争协作（enable_agent_race）——同一高价值参数派 2 个不同策略子 Agent，
          取先确认者（asyncio.wait FIRST_COMPLETED），避免重复成本。
    A2.5: 结果合并与冲突消解——按证据强度规则（severity 权重 + 证据长度 + payload/AI 判定）取强去重。
    """
    if not getattr(self, "_ai_enabled", True):
        logger.info("ℹ️ [MultiAgent] 纯引擎模式（AI 未配置），跳过")
        return
    candidates = self._collect_react_candidates()
    if not candidates:
        logger.info("ℹ️ [MultiAgent] 无本地判定模糊参数，跳过")
        return
    from vulnclaw.ai.dispatcher import AGENT_ROLES, Blackboard, ReActAgent

    max_params = int(getattr(settings, "multi_agent_max_params", 1))
    max_iters = int(getattr(settings, "multi_agent_max_iterations", 4))
    per_budget = float(getattr(settings, "react_dive_budget", 150.0))
    race = bool(getattr(settings, "enable_agent_race", False))
    roles = [r for r in ("analysis", "verify") if r in AGENT_ROLES]

    logger.info(
        f"🤝 [MultiAgent] 编排启动：{len(candidates)} 个候选，角色 {roles}，"
        f"竞争模式={race}，每角色 ≤{max_iters} 轮"
    )
    blackboard = Blackboard()
    total_merged = 0
    for param in candidates[:max_params]:
        try:
            agents = [
                ReActAgent(self.target, self.session, max_iterations=max_iters,
                           focus_param=param, role=r, blackboard=blackboard)
                for r in roles
            ]
            for a in agents:
                if getattr(self, "memory", None) is not None:
                    a.memory = self.memory

            if race and len(agents) > 1:
                # A2.4: 取先确认者，其余取消（控制重复成本）
                tasks = [asyncio.create_task(a.run()) for a in agents]
                done, pending = await asyncio.wait(
                    tasks, timeout=per_budget, return_when=asyncio.FIRST_COMPLETED
                )
                for t in pending:
                    t.cancel()
                # 审计P（孤儿协程根治）：cancel() 只是"发起取消请求"，协程要运行到
                # 下一个 await 点才真正结束、finally 才会执行。不 await 的话任务会
                # 停在 cancelling 状态持续堆积——真扫实证 D1.1 报的 217 个孤儿协程
                # 正来源于此（每个参数的竞争协作都留下一批未回收 task）。
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                reports = []
                for t in done:
                    try:
                        if not t.cancelled() and not t.exception():
                            reports.append(t.result())
                    except Exception:  # noqa: BLE001
                        continue
            else:
                results = await asyncio.gather(*[a.run() for a in agents], return_exceptions=True)
                reports = [r for r in results if isinstance(r, dict)]

            raw_findings = []
            for rep in reports:
                raw_findings.extend((rep or {}).get("vulnerabilities") or [])
            merged_findings = self._resolve_agent_conflicts(raw_findings)
            total_merged += self._merge_react_findings({"vulnerabilities": merged_findings}, param)
        except asyncio.TimeoutError:
            logger.warning(f"⏰ [MultiAgent] 参数 {param} 编排超时（{per_budget:.0f}s），跳过")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"⚠️ [MultiAgent] 参数 {param} 编排异常: {exc}")
    logger.info(f"🤝 [MultiAgent] 编排完成：合入 {total_merged} 个 finding")


def _resolve_agent_conflicts(self, findings: List[Dict]) -> List[Dict]:
    """A2.5: 多 Agent 结果合并与冲突消解——同 url+type+param 取证据更强者。

    证据强度 = severity 权重 × 100 + 证据文本长度（上限 300）/10 + payload(20) + AI 判定(10)。
    """
    sev_weight = {
        "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
        "严重": 4, "高": 3, "中": 2, "低": 1,
    }
    best: Dict[tuple, tuple] = {}
    for f in findings or []:
        if not isinstance(f, dict) or not f.get("type"):
            continue
        key = (
            str(f.get("url", "")),
            str(f.get("type", "")).lower(),
            str(f.get("parameter", "")),
        )
        score = sev_weight.get(str(f.get("severity", "")).lower(), 0) * 100
        score += min(len(str(f.get("evidence", "") or "")), 300) / 10
        if f.get("payload"):
            score += 20
        if f.get("ai_verdict"):
            score += 10
        prev = best.get(key)
        if prev is None or score > prev[0]:
            best[key] = (score, f)
    return [v for _, v in best.values()]
async def _execute_cve_scan(self, task: Dict) -> Optional[Dict]:
    """Z1.2：按 CVE 索引命中的模板 ID 跑 nuclei 专项扫描，命中经 AI 过滤后入报告。

    数据腿闭环的"注入检出"端：只跑索引锁定的高危 CVE 模板（-id），
    避免全量 tag 扫描的盲区；nuclei 缺失/失败静默降级，不误报。
    """
    target = task.get("target", self.target)
    cve_ids = task.get("cve_ids") or []
    if not cve_ids:
        return None
    try:
        from vulnclaw.modules.vuln_scanner import run_nuclei_async, verify_nuclei_with_ai_async
        logger.info(
            f"🎯 [CVE任务] 执行 CVE 专项扫描: {len(cve_ids)} 个模板 "
            f"({','.join(str(c)[:20] for c in cve_ids[:5])}...) target={target}"
        )
        results = await asyncio.wait_for(
            run_nuclei_async(
                target, severity="critical,high", timeout=120, template_ids=cve_ids
            ),
            timeout=150,
        )
        if not results:
            logger.info(f"🎯 [CVE任务] 未命中（{len(cve_ids)} 个 CVE 模板均无匹配）")
            return None
        for item in await verify_nuclei_with_ai_async(results, target):
            if item.get("ai_verdict") != "真实漏洞":
                continue
            ftype = f"CVE: {item.get('template') or item.get('info') or '未知'}"
            if (str(item.get('url', target)), str(ftype)) in self._seen_ut:
                continue
            finding = {
                "type": ftype,
                "severity": item.get("severity", "High"),
                "evidence": item.get("matched", "")[:200],
                "url": item.get("url", target),
                "source": "cve_index_nuclei",
                "confidence": "high",
                "ai_reason": item.get("ai_reason", ""),
            }
            # A8.2：命中 CVE 即生成 PoC / 复现命令（nuclei -id 即权威 PoC）
            try:
                from vulnclaw.deepsec.poc_generator import build_cve_poc
                cve_id = item.get("template") or item.get("info") or ""
                poc = await build_cve_poc(cve_id, finding=item)
                finding["reproduce_cmd"] = poc.get("nuclei_cmd", "")
                finding["poc"] = poc.get("poc_script", "")
                finding["cve_poc"] = poc
            except Exception as pe:  # noqa: BLE001
                logger.debug(f"🎯 [CVE任务] PoC 生成跳过: {pe}")
            self._add_finding(finding)
            if hasattr(self, "_nuclei_findings"):
                self._nuclei_findings += 1
    except asyncio.TimeoutError:
        logger.warning(f"🎯 [CVE任务] nuclei 专项扫描超时，跳过")
    except Exception as e:
        logger.warning(f"🎯 [CVE任务] 执行异常（不影响主流程）: {e}")
    return None


def _global_scan_endpoints(orch) -> List[str]:
    """收集 recon 阶段发现的所有端点 URL，供全局（目标级）引擎精准探测。

    框架升级：此前全局引擎只拿到根 target，导致路径级漏洞（/redirect、/cors、
    /.env 等）对全局引擎不可见。现在把已发现端点（js_endpoints/apis/found_dirs）
    归一化后一并传入，新增/改造的全局引擎可据此逐端点探测。
    """
    base = str(getattr(orch, "target", "")).rstrip("/")
    brief = getattr(orch, "_recon_brief", None) or {}
    out: List[str] = []
    for key in ("js_endpoints", "apis", "found_dirs", "crawled_endpoints", "ws_endpoints"):
        for u in brief.get(key, []) or []:
            if isinstance(u, dict):
                u = u.get("url") or ""
            if not isinstance(u, str) or not u:
                continue
            if u.startswith("http") or u.startswith("ws"):
                out.append(u.split("?")[0].rstrip("/"))
            elif u.startswith("/"):
                out.append((base + u).split("?")[0].rstrip("/"))
    return list(dict.fromkeys(out)) or [base]


async def _execute_global_scan(self, task: Dict) -> Optional[Dict]:
    engine_name = task.get("engine")
    target = task.get("target", self.target)
    engine = get_engine_by_name(engine_name)
    if not engine or not hasattr(engine, 'scan'):
        logger.debug(f"   ⚠️ 引擎 {engine_name} 无 scan 方法")
        return None
    start = time.monotonic()
    # E1: 增量扫描——跳过上次已扫全局引擎
    # P5-1: 续扫模式下（_resume_skip_done）复用同一跳过逻辑，避免重扫已扫引擎
    if getattr(settings, "incremental_scan", False) or getattr(self, "_resume_skip_done", False):
        _gkey = (engine_name, target, "")
        if _gkey in self._incremental_scanned:
            logger.info(f"   ⏭️ [增量] 已扫过全局引擎: {engine_name}")
            return None
        self._incremental_scanned.add(_gkey)
        if getattr(self, "_checkpoint", None) is not None:
            try:
                self._checkpoint.mark_task_done(engine_name, target, "")
            except Exception:  # noqa: BLE001
                logger.debug("suppressed exception (core audit)")
    try:
        if engine_name == "info_leak":
            max_paths = task.get("max_paths", 150)  # 修复：使用传入的参数
            results = await engine.scan(target, self.session, max_paths=max_paths, endpoints=_global_scan_endpoints(self))
        else:
            results = await engine.scan(target, self.session, endpoints=_global_scan_endpoints(self))
        if results:
            for r in results:
                if (str(r.get('url', '')), str(r.get('type', ''))) not in self._seen_ut:
                    # S2.1: 全局扫描路径同样标注链信息（端到端实测：多数 finding 来自该路径）
                    if isinstance(r, dict):
                        try:
                            r["chain_info"] = annotate_chain_info(r, target, str(r.get("parameter", "") or "")).get("chain_info")
                        except Exception:  # noqa: BLE001
                            logger.debug("suppressed exception (core audit)")
                    self._add_finding(r)
                    logger.info(f"   🌐 {engine_name} 发现: {r.get('type')}")
                    if engine_name == "business_logic":
                        self._business_findings += 1
                    elif engine_name == "api_version_diff":
                        self._api_version_findings += 1
                    elif engine_name == "request_smuggling":
                        self._smuggling_findings += 1
                    elif engine_name == "http2_ws":
                        self._http2_ws_findings += 1
                    elif engine_name == "cache_poison":
                        self._cache_poison_findings += 1
        self._record_engine_metric(engine_name, time.monotonic() - start, hit=bool(results))
    except Exception as e:
        self._record_engine_metric(engine_name, time.monotonic() - start, hit=False, error=True)
        logger.warning(f"全局扫描 {engine_name} 失败: {e}")
    return None
async def _fetch_normal_response(self, target: str):
    """优化5: 拉取基线响应并写入缓存（single-flight 保证同 target 只请求一次）。"""
    if not hasattr(self, "_normal_resp_inflight"):
        self._normal_resp_inflight = {}
    try:
        resp = await safe_request(target, self.session, method="GET", timeout=10)
        if resp is None:
            logger.debug("   ⚠️ safe_request 返回 None，使用默认空响应")
            normal_resp = (200, "", {})
        else:
            normal_resp = (resp[0], resp[1], resp[2] if len(resp) > 2 else {})
    except BaseException:
        normal_resp = (200, "", {})
    async with self._normal_responses_lock:
        if target not in self._normal_responses:
            if len(self._normal_responses) >= self._max_normal_responses:
                oldest_key = next(iter(self._normal_responses))
                del self._normal_responses[oldest_key]
            self._normal_responses[target] = normal_resp
    return normal_resp


async def _maybe_sqlmap_confirm(result: Dict, target: str, param: str) -> None:
    """对 SQLi 类检出调用 sqlmap 做轻量确认（不提取数据），成功则 enrich finding。

    失败/未实锤均不影响原引擎检测结果（优雅降级）。
    """
    rtype = str(result.get("type", ""))
    if "SQL" not in rtype.upper() and "注入" not in rtype and "sql" not in rtype.lower():
        return
    if not getattr(settings, "sqli_sqlmap_confirm", True):
        return
    if get_tool_path("sqlmap") is None:
        return
    try:
        wrapper = SQLMapWrapper(target, session=None, timeout=120, level=2, risk=1)
        conf = await wrapper.confirm(target, param, method="GET")
        if conf.get("confirmed"):
            result["sqlmap_confirmed"] = True
            result["confidence"] = "high"
            result["evidence"] = (str(result.get("evidence", "")) + " | [sqlmap 已确认注入点]")[:500]
            try:
                result["poc"] = wrapper.generate_poc(result)
            except Exception:  # noqa: BLE001
                logger.debug("suppressed exception (core audit)")
            # 实锤后做最小化数据提取（仅数据库指纹，证明可利用性，不导出业务数据）
            if getattr(settings, "sqli_sqlmap_extract", True):
                try:
                    ext = await wrapper.extract(target, param, method="GET")
                    if ext.get("extracted"):
                        result["sqlmap_extracted"] = {
                            key: value
                            for key, value in ext.items()
                            if key not in ("raw_tail", "extracted") and value
                        }
                        result["exploit_verified"] = True
                        result["evidence"] = (
                            f"{str(result.get('evidence', ''))} | "
                            f"[sqlmap 实锤并提取: {result['sqlmap_extracted']}]"
                        )[:800]
                        logger.info(f"   💉 [SQLMap] 数据提取成功: {result['sqlmap_extracted']}")
                except Exception as _extend_err:  # noqa: BLE001
                    logger.debug(f"   💉 [SQLMap] 数据提取异常（忽略）: {_extend_err}")
            logger.info(f"   💉 [SQLMap] 确认 SQLi: {target} param={param}")
        else:
            logger.debug(f"   💉 [SQLMap] 轻量确认未实锤（保留原引擎判定）: {param}")
    except Exception as _e:  # noqa: BLE001
        logger.debug(f"   💉 [SQLMap] 确认异常（忽略）: {_e}")


async def _execute_engine_check(self, task: Dict) -> Optional[Dict]:
    engine_name = task.get("engine")
    target = task.get("target", self.target)
    # K.3：签名前置——任务携带 SignerPool 生成的合法签名 URL 时覆盖裸 target
    # （signer query 由 build_attack_url 合并进每次载荷请求，引擎零改动）
    if task.get("signed_url"):
        target = task["signed_url"]
    param = task.get("param")
    payload_limit = task.get("payload_limit", 5)
    if not engine_name or not param:
        return None
    self._processed_params.add(param)
    # D1.2: 粘滞墓碑——已被剔除的粘滞任务不再占 worker
    if int(getattr(settings, "sticky_fail_threshold", 2)) > 0:
        if not hasattr(self, "_sticky_blacklist"):
            self._sticky_blacklist = set()
        _skey = (engine_name, target, str(param or ""))
        if _skey in self._sticky_blacklist:
            logger.info(f"   ⏭️ [D1] 粘滞剔除命中，跳过: {engine_name}/{param}")
            return None
    # E4: 早停——该参数已确认同类高危/严重漏洞才跳过（按漏洞大类生效），
    # 避免 XSS 确认后把同参数的 SQLi/SSTI/LFI/CMDi 等正交大类一并误杀（漏报根因）。
    if getattr(settings, "engine_early_stop_on_confirmed", True) and (target, param) in self._confirmed_params:
        _confirmed_cats = self._confirmed_categories.get((target, param), set())
        _eng_cat = vuln_category(engine_name)
        if _eng_cat in _confirmed_cats:
            logger.info(f"   ⏭️ [早停] 同参数已确认同类漏洞({_eng_cat})，跳过 {engine_name} on {param}")
            return None
    # E1: 增量扫描——跳过上次已扫端点/参数
    # P5-1: 续扫模式下（_resume_skip_done）复用同一跳过逻辑，避免重扫已扫 (engine,target,param)
    if getattr(settings, "incremental_scan", False) or getattr(self, "_resume_skip_done", False):
        _inc_key = (engine_name, target, param)
        if _inc_key in self._incremental_scanned:
            logger.info(f"   ⏭️ [增量] 已扫过: {engine_name} {param}")
            return None
    engine = get_engine_by_name(engine_name)
    if not engine:
        logger.debug(f"   ⚠️ 未知引擎: {engine_name}")
        return None
    # P4-2: 机器事实覆盖账本——V100 直调 engine.check 绕过了 scanner.run_engine，
    # 导致 bundle 引擎（含 coverage_fallback 兜底）长期不落账、coverage 永远 never_ran
    # （实测 8090：兜底引擎已 pick 执行，gaps 仍 66）。此处补同口径记账，异常零传播。
    _ledger = None
    try:
        from vulnclaw.core.coverage import get_coverage_ledger
        _ledger = get_coverage_ledger(target=str(target))
    except Exception:  # noqa: BLE001
        _ledger = None
    # 优化5: 获取正常响应（single-flight）—— 并发任务对同一 target 只发一次 baseline GET。
    # 注意：key 保持完整 URL（含 query），不按 path 归一化，避免基线语义变化引发误报。
    async with self._normal_responses_lock:
        normal_resp = self._normal_responses.get(target)
        inflight = self._normal_resp_inflight.get(target)
        if normal_resp is None and inflight is None:
            inflight = asyncio.ensure_future(_fetch_normal_response(self, target))
            self._normal_resp_inflight[target] = inflight
    if normal_resp is None and inflight is not None:
        try:
            normal_resp = await asyncio.shield(inflight)
        except Exception:
            normal_resp = (200, "", {})
        finally:
            async with self._normal_responses_lock:
                self._normal_resp_inflight.pop(target, None)
    if normal_resp is None:
        normal_resp = (200, "", {})
    parsed_query = target.split('?')[1] if '?' in target else ''
    current_model = await self._get_next_model()
    provider_key = self._model_to_provider.get(current_model)
    _t0 = time.monotonic()
    try:
        if hasattr(engine, 'max_payloads'):
            engine.max_payloads = payload_limit
        kwargs = {}
        if engine_name in ("cmdi", "ssrf") and self._collaborator_domain:
            kwargs["interactsh_domain"] = self._collaborator_domain
        if engine_name == "state_chain":
            # 二次/存储型触发需要已知消费端点列表；recon 未发现端点时引擎自行跳过该分支
            kwargs["endpoints"] = _global_scan_endpoints(self)
        if getattr(settings, "incremental_scan", False) or getattr(self, "_resume_skip_done", False):
            self._incremental_scanned.add((engine_name, target, param))
            if getattr(self, "_checkpoint", None) is not None:
                try:
                    self._checkpoint.mark_task_done(engine_name, target, param)
                except Exception:  # noqa: BLE001
                    logger.debug("suppressed exception (core audit)")
        result = await asyncio.wait_for(
            engine.check(
                url=target,
                param=param,
                normal_resp=normal_resp,
                parsed_query=parsed_query,
                session=self.session,
                **kwargs
            ),
            timeout=120
        )
        self._total_engine_calls += 1
        self._record_engine_metric(engine_name, time.monotonic() - _t0, hit=bool(result))
        if _ledger is not None:
            try:
                _ledger.record_run(str(target), engine_name,
                                   findings=1 if result else 0,
                                   duration=round(time.monotonic() - _t0, 3))
            except Exception:  # noqa: BLE001
                pass
        if result:
            # 自动成长-读取端（2026-09-15）：账本强误报指纹过滤（默认关零影响）。
            # 命中 (vuln_type, 归一化参数) 强误报签名 -> 不进待验证队列，不计命中。
            # 注：此时 result 尚无 parameter 字段（下方排队才补），
            # 直接以任务参数为准补一个快照字段供抑制匹配，不改动原始 result 结构。
            try:
                from vulnclaw.growth.bridges import suppress_findings
                _snap = dict(result)
                _snap.setdefault("parameter", param)
                _kept, _suppressed = suppress_findings(_snap)
                if _suppressed:
                    logger.info(f"   ⏭️ [Growth] 账本抑制强误报: {result.get('type', engine_name)} on {param}")
                    if _kept is None:
                        await self.rate_limiter.record_success(current_model)
                        if provider_key:
                            await self.balancer.record_result(provider_key, success=True)
                        return None
            except Exception:  # noqa: BLE001
                pass
            # S3: SQLi 类检出 → sqlmap 轻量确认（POC 级，不提取数据），升级为实锤
            # 关键：确认失败/异常绝不影响引擎原始检出，避免丢 finding
            try:
                await _maybe_sqlmap_confirm(result, target, param)
            except Exception as _ce:  # noqa: BLE001
                logger.debug("   [SQLMap] 确认异常（忽略，保留引擎判定）: %s", _ce)
            # S2.1: 结构化链信息标注（HTTP状态/可控点/回显特征/可链性），供跨引擎攻击链路由消费
            try:
                result = annotate_chain_info(result, target, param)
            except Exception:  # noqa: BLE001
                logger.debug("suppressed exception (core audit)")
            if 'role' in kwargs and 'response' in kwargs:
                await self.context.store_role_response(
                    kwargs.get('role', 'default'),
                    target,
                    kwargs.get('response', '')
                )
            # 修复：不再直接添加 direct_finding，统一进入待验证队列
            direct_finding = self.local_filter.quick_rule_check(param, result.get("evidence", ""), target)
            if direct_finding:
                # 灏嗚鍒欏彂鐜颁綔涓烘櫘閫氱枒浼兼紡娲炲姞鍏ュ緟楠岃瘉鍒楄〃
                direct_finding['parameter'] = param
                direct_finding['url'] = target
                direct_finding['source'] = 'local_filter'
                self._pending_verify.append(direct_finding)
                try:
                    await self._stream_notify_pending(1)
                except Exception as _se:
                    logger.debug("   [StreamVerify] notify direct_finding 失败（不影响 finding）: %s", _se)
                logger.info(f"   Rule finding queued for verification: {direct_finding.get('type')} (param: {param})")
                # 仍然将引擎结果也加入待验证（避免漏掉）
                result["parameter"] = param
                self._pending_verify.append(result)
                try:
                    await self._stream_notify_pending(1)
                except Exception as _se:
                    logger.debug("   [StreamVerify] notify engine result 失败（不影响 finding）: %s", _se)
                await self.rate_limiter.record_success(current_model)
                if provider_key:
                    await self.balancer.record_result(provider_key, success=True)
                return result
            result["parameter"] = param
            self._pending_verify.append(result)
            try:
                await self._stream_notify_pending(1)
            except Exception as _se:
                logger.debug("   [StreamVerify] notify finding 失败（不影响 finding）: %s", _se)
            logger.info(f"   Finding queued for verification: {result.get('type')} (param: {param})")
            await self.rate_limiter.record_success(current_model)
            if provider_key:
                await self.balancer.record_result(provider_key, success=True)
            return result
        await self.rate_limiter.record_success(current_model)
        if provider_key:
            await self.balancer.record_result(provider_key, success=True)
        return None
    except asyncio.TimeoutError:
        await self.rate_limiter.record_failure(current_model, 408, "Timeout")
        if provider_key:
            await self.balancer.record_result(provider_key, success=False, status_code=408)
        logger.warning(f"   ⏭️ 引擎检查超时(60s): {engine_name} {param}")
        self._record_engine_metric(engine_name, time.monotonic() - _t0, hit=False, timeout=True)
        if _ledger is not None:
            try:
                _ledger.record_failed(str(target), engine_name, "timeout")
            except Exception:  # noqa: BLE001
                pass
        return None
    except Exception as e:
        error_str = str(e)
        await self.rate_limiter.record_failure(current_model, 500, error_str)
        await self._record_model_result(current_model, False, error_str)
        if provider_key:
            await self.balancer.record_result(provider_key, success=False, status_code=500)
        logger.debug(f"   ❌ 执行失败: {e}")
        self._record_engine_metric(engine_name, time.monotonic() - _t0, hit=False, error=True)
        if _ledger is not None:
            try:
                _ledger.record_failed(str(target), engine_name, error_str[:200])
            except Exception:  # noqa: BLE001
                pass
        return None
__all__ = ['_run_business_logic_scan', '_run_api_version_scan', '_run_smuggling_scan', '_run_http2_ws_scan', '_run_cache_poison_scan', '_run_burp_scan', '_execute_with_limiting', '_run_one_task', '_execute_task', '_safe_parse_bundle_json', '_execute_engine_bundle', '_execute_global_scan', '_execute_engine_check', '_run_react_deep_dive', '_collect_react_candidates', '_merge_react_findings', '_run_chain_router', '_chain_ssrf', '_chain_upload', '_generate_clues_for_dive', '_persist_scan_memory', '_run_multi_agent_dive', '_resolve_agent_conflicts', '_sticky_mark_failed']
