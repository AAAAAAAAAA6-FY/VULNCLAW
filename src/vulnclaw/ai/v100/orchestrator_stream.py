# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""A4.4 流水线验证：attack 边出 finding 边后台 verify（拆出的 mixin）。

拆分原因：orchestrator.py 单文件过大（1661 行），按内聚性拆成 mixin；
方法体逐字迁移（未改一行逻辑），`V100Orchestrator` 多继承后行为不变。
"""
import asyncio
from typing import Dict, List

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings


class StreamVerifyMixin:
    """A4.4 流水线验证：attack 边出 finding 边后台 verify（拆出的 mixin）。"""

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
                await asyncio.wait_for(self._stream_flush_pending(force_all=True, final_flush=True), timeout=float(settings.chain_flush_timeout))
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
                await asyncio.wait_for(task, timeout=settings.request_timeout)
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
        _batch_ok = False
        try:
            await self._verify_all_findings()
            _batch_ok = True
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            raise
        finally:
            async with self._pending_verify_lock:
                if _batch_ok:
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
