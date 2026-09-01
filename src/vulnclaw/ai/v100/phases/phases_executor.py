# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Implementation functions for the v100 executor phase."""
import asyncio
import time
import ast
import json
import re
from typing import Any, Dict, List, Optional
from vulnclaw.core.logger import logger
from vulnclaw.core.scanner import safe_request, get_engine_by_name
from vulnclaw.core.settings import settings
from vulnclaw.engines.input_engines import BusinessLogicEngine
from vulnclaw.engines.auxiliary_engines import APIVersionDiffEngine, RequestSmugglingEngine, HTTP2WebSocketEngine
from vulnclaw.engines.http_engines import CachePoisonEngine
from vulnclaw.engines.base import annotate_chain_info
async def _run_business_logic_scan(self):
    try:
        logger.info("🧬 [BusinessLogic] 全局扫描...")
        engine = BusinessLogicEngine()
        results = await engine.scan(self.target, self.session)
        for r in results:
            if not any(f.get('url') == r.get('url') and f.get('type') == r.get('type') for f in self.findings):
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
            if not any(f.get('url') == r.get('url') and f.get('type') == r.get('type') for f in self.findings):
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
            if not any(f.get('url') == r.get('url') and f.get('type') == r.get('type') for f in self.findings):
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
            if not any(f.get('url') == r.get('url') and f.get('type') == r.get('type') for f in self.findings):
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
            if not any(f.get('url') == r.get('url') and f.get('type') == r.get('type') for f in self.findings):
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
    MAX_CONCURRENT = int(getattr(settings, "orchestrator_max_concurrent", 10))
    # 第3次修复：attack 阶段预算硬顶。LLM QPS 降级(1.5~2.1)时任务墙钟时间不可控，
    # 用 deadline 保证 attack 节点耗时上限（目标 <=130s）。超预算任务判败出队，
    # 已产出的 finding 已进 StreamVerify 队列，不受影响。
    attack_budget = float(getattr(settings, "attack_node_budget", 130.0))
    self._attack_deadline_ts = time.time() + attack_budget
    logger.info(f"   [deadline] attack 阶段预算: {attack_budget:.0f}s")
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
                    pass
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
        """
        stable = 0
        while True:
            drained = await self.task_queue.is_drained()
            stable = (stable + 1) if drained else 0
            if stable >= 2:
                break
            await asyncio.sleep(0.2)
        # 给所有 worker 一人一个 sentinel（priority=0 最高优先级会立刻被弹出）
        await self.task_queue.mark_production_done(num_consumers=MAX_CONCURRENT)
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
                logger.info(
                    f"   👁 [watchdog] queue={len(q._queue)} pending={len(q._pending_tasks)} "
                    f"drained={await q.is_drained()} workers_alive={alive} "
                    f"workers={dict(getattr(self, '_dbg_workers', {}))}"
                )
            except Exception as e:
                logger.warning(f"   👁 [watchdog] 异常: {e}")

    watchdog = asyncio.create_task(_watchdog())

    async def _deadline_enforcer():
        """预算耗尽时清空未执行任务并通知 worker 收尾。"""
        await asyncio.sleep(attack_budget)
        try:
            n = await self.task_queue.fail_all_pending(reason=f"attack 预算 {attack_budget:.0f}s 耗尽")
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
        # 浠讳綍寮傚父锛氬厛鍏ㄩ噺 cancel锛屽啀鎶?
        for t in workers + [guard, watchdog]:
            if not t.done():
                t.cancel()
        await asyncio.gather(*workers, guard, watchdog, return_exceptions=True)
        raise
    finally:
        watchdog.cancel()
        enforcer.cancel()
    logger.info(f"   Execution complete: {processed} tasks")
async def _run_one_task(self, task: Dict, task_id: str, semaphore: asyncio.Semaphore):
    """单任务完整生命周期（模型选择 → 限流 → 执行），整体受超时约束。

    第3次修复：
    1. 模型选择/限流等待原先在 wait_for 作用域之外，500错误风暴下降级 QPS 1.5
       时 acquire 可无限阻塞（task_1 卡 9 分钟的根因）—— 现全部纳入超时。
    2. 超时上限取 min(240s, attack 剩余预算)，保证 attack 节点墙钟时间可控。
    3. 超时/异常一律判败出队，不再 requeue（240s x 3 重试 = 960s 是耗时失控主因）。
    """
    deadline_ts = getattr(self, "_attack_deadline_ts", None)
    if deadline_ts is not None:
        budget = deadline_ts - time.time()
        if budget <= 0:
            logger.warning(f"   [deadline] 预算已耗尽，任务直接判败出队: {task_id}")
            if hasattr(self.task_queue, 'complete_task'):
                await self.task_queue.complete_task(task_id, success=False)
            return None
        timeout = max(10.0, min(240.0, budget))
    else:
        timeout = 240.0

    async def _lifecycle():
        model = await asyncio.wait_for(self._get_next_model(), timeout=30)
        wait_time = await asyncio.wait_for(self.rate_limiter.acquire(model), timeout=60)
        if wait_time > 0:
            await asyncio.sleep(min(wait_time, 30))
        async with semaphore:
            return await self._safe_execute_task(task)

    try:
        result = await asyncio.wait_for(_lifecycle(), timeout=timeout)
        if hasattr(self.task_queue, 'complete_task'):
            await self.task_queue.complete_task(task_id, success=True)
        return result
    except asyncio.CancelledError:
        logger.debug(f"   [cancel] 任务被取消: {task_id}")
        if hasattr(self.task_queue, 'complete_task'):
            await self.task_queue.complete_task(task_id, success=False)
        raise
    except asyncio.TimeoutError:
        logger.warning(
            f"   [timeout] 任务执行超时 ({timeout:.0f}s), 判失败出队(不重试): "
            f"{task.get('engine', 'unknown')}/{task.get('param', '')}"
        )
        if hasattr(self.task_queue, 'complete_task'):
            await self.task_queue.complete_task(task_id, success=False)
        return None
    except Exception as e:
        logger.warning(f"   [error] 任务异常: {task.get('engine', 'unknown')}/{task.get('param', '')} - {e}")
        if hasattr(self.task_queue, 'complete_task'):
            await self.task_queue.complete_task(task_id, success=False)
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
        return await self._execute_cve_scan(task)
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
        bp = BatchProcessor(max_batch_size=5)
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
        if not any(x.get('url') == f.get('url') and x.get('type') == f.get('type') for x in self.findings):
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
            pass
        try:
            parsed = ast.literal_eval(candidate)
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
            if isinstance(parsed, dict):
                return [parsed]
        except (ValueError, SyntaxError, TypeError):
            pass
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

    results = await asyncio.gather(
        *(_run_one(name) for name in engines),
        return_exceptions=False,
    )
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
        parsed = self._safe_parse_bundle_json(await self._ask_ai(prompt, compress=True, task_type="verify"))
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
                pass
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
            await asyncio.wait_for(self._generate_clues_for_dive(clue_engine), timeout=45)
        except Exception as _ce:  # noqa: BLE001
            logger.debug(f"[ClueEngine] 预生成线索失败（继续深挖）: {_ce}")

    total_merged = 0
    for param in candidates[:max_params]:
        try:
            agent = ReActAgent(self.target, self.session, max_iterations=max_iters, focus_param=param)
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
    for addr in intranet_addrs[:3]:
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
    for u in upload_urls[:3]:
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
    url_pool = list(dict.fromkeys(url_pool))[:3]
    if not url_pool:
        return
    for u in url_pool:
        try:
            normal = await self._fetch_normal_response(u)
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
            if any(f.get('type') == ftype and f.get('url') == item.get('url', target) for f in self.findings):
                continue
            self._add_finding({
                "type": ftype,
                "severity": item.get("severity", "High"),
                "evidence": item.get("matched", "")[:200],
                "url": item.get("url", target),
                "source": "cve_index_nuclei",
                "confidence": "high",
                "ai_reason": item.get("ai_reason", ""),
            })
            if hasattr(self, "_nuclei_findings"):
                self._nuclei_findings += 1
    except asyncio.TimeoutError:
        logger.warning(f"🎯 [CVE任务] nuclei 专项扫描超时，跳过")
    except Exception as e:
        logger.warning(f"🎯 [CVE任务] 执行异常（不影响主流程）: {e}")
    return None


async def _execute_global_scan(self, task: Dict) -> Optional[Dict]:
    engine_name = task.get("engine")
    target = task.get("target", self.target)
    engine = get_engine_by_name(engine_name)
    if not engine or not hasattr(engine, 'scan'):
        logger.debug(f"   ⚠️ 引擎 {engine_name} 无 scan 方法")
        return None
    try:
        if engine_name == "info_leak":
            max_paths = task.get("max_paths", 150)  # 修复：使用传入的参数
            results = await engine.scan(target, self.session, max_paths=max_paths)
        else:
            results = await engine.scan(target, self.session)
        if results:
            for r in results:
                if not any(f.get('url') == r.get('url') and f.get('type') == r.get('type') for f in self.findings):
                    # S2.1: 全局扫描路径同样标注链信息（端到端实测：多数 finding 来自该路径）
                    if isinstance(r, dict):
                        try:
                            r["chain_info"] = annotate_chain_info(r, target, str(r.get("parameter", "") or "")).get("chain_info")
                        except Exception:  # noqa: BLE001
                            pass
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
    except Exception as e:
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


async def _execute_engine_check(self, task: Dict) -> Optional[Dict]:
    engine_name = task.get("engine")
    target = task.get("target", self.target)
    param = task.get("param")
    payload_limit = task.get("payload_limit", 5)
    if not engine_name or not param:
        return None
    self._processed_params.add(param)
    engine = get_engine_by_name(engine_name)
    if not engine:
        logger.debug(f"   ⚠️ 未知引擎: {engine_name}")
        return None
    # 优化5: 获取正常响应（single-flight）—— 并发任务对同一 target 只发一次 baseline GET。
    # 注意：key 保持完整 URL（含 query），不按 path 归一化，避免基线语义变化引发误报。
    async with self._normal_responses_lock:
        normal_resp = self._normal_responses.get(target)
        inflight = self._normal_resp_inflight.get(target)
        if normal_resp is None and inflight is None:
            inflight = asyncio.ensure_future(self._fetch_normal_response(target))
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
    try:
        if hasattr(engine, 'max_payloads'):
            engine.max_payloads = payload_limit
        kwargs = {}
        if engine_name in ("cmdi", "ssrf") and self._collaborator_domain:
            kwargs["interactsh_domain"] = self._collaborator_domain
        result = await asyncio.wait_for(
            engine.check(
                url=target,
                param=param,
                normal_resp=normal_resp,
                parsed_query=parsed_query,
                session=self.session,
                **kwargs
            ),
            timeout=60
        )
        self._total_engine_calls += 1
        if result:
            # S2.1: 结构化链信息标注（HTTP状态/可控点/回显特征/可链性），供跨引擎攻击链路由消费
            try:
                result = annotate_chain_info(result, target, param)
            except Exception:  # noqa: BLE001
                pass
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
        return None
    except Exception as e:
        error_str = str(e)
        await self.rate_limiter.record_failure(current_model, 500, error_str)
        await self._record_model_result(current_model, False, error_str)
        if provider_key:
            await self.balancer.record_result(provider_key, success=False, status_code=500)
        logger.debug(f"   ❌ 执行失败: {e}")
        return None
__all__ = ['_run_business_logic_scan', '_run_api_version_scan', '_run_smuggling_scan', '_run_http2_ws_scan', '_run_cache_poison_scan', '_run_burp_scan', '_execute_with_limiting', '_run_one_task', '_execute_task', '_safe_parse_bundle_json', '_execute_engine_bundle', '_execute_global_scan', '_execute_engine_check', '_run_react_deep_dive', '_collect_react_candidates', '_merge_react_findings', '_run_chain_router', '_chain_ssrf', '_chain_upload', '_generate_clues_for_dive', '_persist_scan_memory', '_run_multi_agent_dive', '_resolve_agent_conflicts']
