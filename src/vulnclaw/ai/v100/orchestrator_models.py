# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""AI 模型路由与调用（从 orchestrator.py 拆出的 mixin）。

拆分原因：orchestrator.py 单文件过大（1661 行），按内聚性拆成 mixin；
方法体逐字迁移（未改一行逻辑），`V100Orchestrator` 多继承后行为不变。
"""
import asyncio
import time
from typing import Dict, List

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.ai.core import get_llm_client


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


class ModelRoutingMixin:
    """AI 模型路由与调用（从 orchestrator.py 拆出的 mixin）。"""

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
                timeout=float(settings.ai_router_timeout),
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
        usage_site: str = "",  # A4.4/SP8: 成本台账调用点标签
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
