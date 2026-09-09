# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/target_capacity_probe.py
"""
目标请求能力探测（Target Capacity Probe）

扫描早期对目标做"请求能力探测"：指纹推断 → 渐进加压 → 短突发确认，
测出目标的安全 QPS 与安全并发上限，动态应用到全链路（爬虫并发 / 全局
HTTP RPS / 引擎任务并发）。探测失败自动回退静态默认值（probed=False），
行为与未启用时完全一致（零风险开关）。

只依赖 core.logger / core.settings / aiohttp / urllib，避免循环导入。
多目标按 host 隔离注册表；未探测/关闭/失败时 get_safe_*() 返回 None，
消费点沿用原静态默认值。
"""

import asyncio
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

import aiohttp

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings as _default_settings


# ============================================================
# 结果对象（对外只读）
# ============================================================
@dataclass
class CapacityResult:
    probed: bool = False               # 是否成功测出容量
    safe_qps: float = 4.0              # 应用的安全 QPS（已含安全系数）
    safe_concurrency: int = 8          # 应用的安全并发上限
    raw_qps: float = 0.0               # 探测收敛的最高 OK 档 QPS（未乘安全系数）
    avg_rt_ms: float = 0.0             # 指纹基线 RT（毫秒）
    stopped_level_qps: float = 0.0     # 触发降级信号的 QPS 档（0=未触发）
    signal: str = ""                   # 降级信号：429/403/5xx/timeout/connect_reset/low_success/latency
    latency_spike: bool = False        # 是否由延迟尖峰触发降级
    burst_ok: bool = False             # 短突发确认是否全通过
    fingerprint: str = ""              # 指纹摘要（status/Server）


@dataclass
class ProbeSample:
    """一次探测请求的采样结果（send_one 注入接口也用此形状，便于单测）。"""
    status: int = 0
    latency_ms: float = 0.0            # 首字节耗时（毫秒）
    rt_ms: float = 0.0                 # 完整请求耗时（毫秒）
    error: str = ""
    headers: Dict[str, str] = field(default_factory=dict)


# ============================================================
# 模块级注册表（单一数据源）
# ============================================================
_REGISTRY: Dict[str, CapacityResult] = {}
_ROOT_KEY = ""  # 单目标兜底根 key：消费点无 target 参数时读"最近一次结果"


def _normalize(target: str) -> str:
    """规范化注册表 key：netloc 小写；解析失败回退原始串；空串保留为根 key。"""
    try:
        netloc = urllib.parse.urlparse(target).netloc
        if netloc:
            return netloc.lower()
    except Exception:  # noqa: BLE001
        pass
    return target.lower() if target else _ROOT_KEY


def set_capacity(target: str, r: CapacityResult) -> None:
    _REGISTRY[_normalize(target)] = r
    _REGISTRY[_ROOT_KEY] = r  # 单目标根兜底，消费点无需传 target


def get_capacity(target: str = "") -> Optional[CapacityResult]:
    r = _REGISTRY.get(_normalize(target))
    if r is not None:
        return r
    return _REGISTRY.get(_ROOT_KEY)


def reset_capacity(target: str) -> None:
    _REGISTRY.pop(_normalize(target), None)


def reset_all_capacity() -> None:
    _REGISTRY.clear()


def get_safe_qps(target: str = "") -> Optional[float]:
    r = get_capacity(target)
    return r.safe_qps if r and r.probed else None


def get_safe_concurrency(target: str = "") -> Optional[int]:
    r = get_capacity(target)
    return r.safe_concurrency if r and r.probed else None


def compute_adaptive_budget(pending: int, worker: Optional[int] = None,
                            rt_ms: Optional[float] = None, per_task_s: Optional[float] = None,
                            safety: float = 1.3, floor: Optional[float] = None,
                            cap: Optional[float] = None) -> float:
    """超时工作量自适应：预算 = 待执行数 × 单任务耗时 / 并发 × 安全系数，封顶防无限放大。

    单任务耗时由目标真实RT(容量探测)或经验值决定；未探测时回退默认。供 attack 内层预算
    与 scan 外层预算同源调用，保证 内层 < 外层。
    """
    if worker is None:
        worker = int(get_safe_concurrency() or getattr(_default_settings, "orchestrator_max_concurrent", 10))
    if rt_ms is None:
        _c = get_capacity()
        rt_ms = (_c.avg_rt_ms if (_c and _c.probed) else 200.0)
    if per_task_s is None:
        per_task_s = float(getattr(_default_settings, "attack_per_task_s", 4.0))
    # rt 比率下限 0.5：单任务耗时由 AI 验证主导，极快目标（本地靶机 rt~3ms）不应把
    # 单任务成本压到趋近 0，否则预算被算小 → 攻击阶段被地板截断（实测检出率 20% 根因之一）
    _t = per_task_s * max(rt_ms / 200.0, 0.5)
    _needed = (max(int(pending), 0) * _t / max(int(worker), 1)) * safety
    _lo = float(floor if floor is not None else getattr(_default_settings, "attack_node_budget", 500.0))
    _v = max(_needed, _lo)
    if cap is not None:
        _v = min(_v, float(cap))
    return _v


# ============================================================
# 主入口
# ============================================================
async def run_capacity_probe(target: str, *, settings: Any = None,
                             send_one: Optional[Callable] = None) -> CapacityResult:
    """对目标做请求能力探测，结果写入注册表并返回。

    - settings：可注入假配置（单测用）；默认读取全局 settings。
    - send_one：可注入假发送器（单测用）；默认用独立 aiohttp 会话直连。
    任何失败都只会产生 probed=False 的结果，绝不 re-raise 影响主流程。
    """
    cfg = settings if settings is not None else _default_settings
    if not getattr(cfg, "enable_target_probe", True):
        r = CapacityResult(probed=False)
        set_capacity(target, r)
        return r
    timeout_s = float(getattr(cfg, "target_probe_timeout_s", 45) or 45)
    try:
        return await asyncio.wait_for(
            _run_impl(target, cfg=cfg, send_one=send_one), timeout=timeout_s
        )
    except asyncio.CancelledError:
        raise
    except Exception as e:  # noqa: BLE001
        logger.warning(f"🛡️ [容量探测] 整体超时/异常（沿用默认限流）: {e!r}")
        r = CapacityResult(probed=False)
        set_capacity(target, r)
        return r


async def _run_impl(target: str, *, cfg: Any, send_one: Optional[Callable]) -> CapacityResult:
    if send_one is None:
        # 探测专属独立会话直连：天然绕过 _global_rate_limit，不污染共享会话与 LLM 限流桶
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=8, enable_cleanup_closed=True),
            timeout=aiohttp.ClientTimeout(total=float(getattr(cfg, "timeout", 15) or 15)),
        ) as sess:
            send_one = _make_default_send(cfg, sess)
            prober = _Prober(target, send_one, cfg)
            result = await prober.run()
    else:
        prober = _Prober(target, send_one, cfg)
        result = await prober.run()
    set_capacity(target, result)
    return result


# ============================================================
# 默认发送器（独立会话直连 + scope/代理校验）
# ============================================================
def _make_default_send(cfg: Any, session: aiohttp.ClientSession) -> Callable:
    ua = (getattr(cfg, "user_agent", None) or "").strip() or \
        (getattr(_default_settings, "user_agent", None) or "").strip() or \
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"

    async def send_one(target: str, qps: Optional[float] = None) -> ProbeSample:
        timeout = float(getattr(cfg, "timeout", 15) or 15)
        max_body = int(getattr(cfg, "target_probe_max_body", 65536) or 65536)
        proxy = getattr(cfg, "proxy", None) or getattr(_default_settings, "proxy", None)
        parsed = urllib.parse.urlparse(target)
        if parsed.hostname and parsed.hostname.lower() in ("127.0.0.1", "localhost"):
            proxy = None  # 与 core/utils._http_request 行为一致：本机地址强制不走代理
        # E5.1 scope 硬约束（未配置则放行，兼容旧行为）
        scope = (getattr(cfg, "allowed_scope", "") or "").strip() or \
            (getattr(_default_settings, "allowed_scope", "") or "").strip()
        if scope:
            try:
                from vulnclaw.core.http_client import url_in_scope, ScopeGuardError
                if not url_in_scope(target):
                    raise ScopeGuardError(
                        f"E5 越界请求被容量探测拦截（超出 allowed_scope）: {target}"
                    )
            except ImportError:
                pass

        start = time.perf_counter()
        t_headers = start
        status = 0
        headers: Dict[str, str] = {}
        try:
            kwargs: Dict[str, Any] = {"proxy": proxy} if proxy else {}
            async with session.get(
                target,
                headers={"User-Agent": ua},
                timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=False,
                **kwargs,
            ) as resp:
                t_headers = time.perf_counter()
                status = resp.status
                headers = dict(resp.headers) or {}
                try:
                    await resp.content.read(max_body + 1)  # 只读头部片段，快速完成请求
                except Exception:  # noqa: BLE001
                    pass
            t_end = time.perf_counter()
            return ProbeSample(
                status=status,
                latency_ms=(t_headers - start) * 1000.0,
                rt_ms=(t_end - start) * 1000.0,
                headers=headers,
            )
        except asyncio.TimeoutError:
            error = "timeout"
        except (aiohttp.ClientConnectorError, aiohttp.ClientOSError, ConnectionError):
            error = "connect_reset"
        except aiohttp.ClientError as e:
            error = f"other: {e}"
        except Exception as e:  # noqa: BLE001
            error = f"other: {e!r}"
        return ProbeSample(rt_ms=(time.perf_counter() - start) * 1000.0, error=error)

    return send_one


# ============================================================
# 状态机：指纹 → 渐进加压 → 短突发确认 → 收口
# ============================================================
class _Prober:
    def __init__(self, target: str, send_one: Callable, cfg: Any):
        self.target = target
        self.send_one = send_one
        self.cfg = cfg
        self.result = CapacityResult()
        self.base_rt_ms = 0.0

    async def run(self) -> CapacityResult:
        try:
            if not await self._fingerprint():
                return self.result
            last_ok = await self._progressive()
            self.result.raw_qps = last_ok
            if last_ok > 0:
                await self._burst(last_ok)
            self._finalize(last_ok)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            logger.warning(f"🛡️ [容量探测] 阶段异常（沿用默认限流）: {e!r}")
            self.result.probed = False
        return self.result

    # ---- 1) 指纹推断 ----
    async def _fingerprint(self) -> bool:
        await asyncio.sleep(0.15)  # 冷静期，避免冷启动突发
        s = await self.send_one(self.target)
        sig = self._classify(s)
        if s.status in (200, 201, 202, 204, 301, 302, 303, 307, 308) and not sig:
            self.base_rt_ms = s.rt_ms or s.latency_ms or 200.0
            server = (s.headers.get("Server", "") if isinstance(s.headers, dict) else "") or "unknown"
            self.result.fingerprint = f"{s.status}/{server}"
            self.result.avg_rt_ms = self.base_rt_ms
            logger.info(f"🛡️ [容量探测] 指纹: {self.result.fingerprint}, 基线RT={self.base_rt_ms:.0f}ms")
            return True
        if sig:
            self.result.signal = sig
        logger.warning(f"🛡️ [容量探测] 指纹请求未获 2xx/3xx（status={s.status}, sig={sig!r}），探测短路")
        self.result.probed = False
        return False

    # ---- 2) 渐进加压 ----
    async def _progressive(self) -> float:
        levels = getattr(self.cfg, "target_probe_levels", None) or [2.0, 4.0, 8.0, 16.0]
        duration = float(getattr(self.cfg, "target_probe_duration_s", 1.0) or 1.0)
        ok_ratio = float(getattr(self.cfg, "target_probe_ok_ratio", 0.95) or 0.95)
        last_ok = 0.0
        cur = 0.0
        for level in levels:
            qps = float(level)
            n = max(1, round(duration * qps))
            interval = (duration / n) if duration > 0 and n > 0 else 0.0
            ok_n = 0
            rt_total = 0.0
            rt_n = 0
            degraded_sig = ""
            for _i in range(n):
                await asyncio.sleep(interval)  # 严格按档位 QPS 摊匀发包
                s = await self.send_one(self.target, qps=qps)
                sig = self._classify(s)
                if s.rt_ms and s.rt_ms > 0:
                    rt_total += s.rt_ms
                    rt_n += 1
                if sig == "":
                    ok_n += 1
                elif not degraded_sig:
                    degraded_sig = sig
            avg_rt = rt_total / rt_n if rt_n else 0.0
            ratio = ok_n / n
            spike = False
            if self.base_rt_ms > 0 and avg_rt > max(2 * self.base_rt_ms, self.base_rt_ms + 3000):
                spike = True
                if not degraded_sig:
                    degraded_sig = "latency"
            if degraded_sig or ratio < ok_ratio:
                self.result.stopped_level_qps = qps
                self.result.signal = degraded_sig or "low_success"
                self.result.latency_spike = spike
                logger.info(
                    f"🛡️ [容量探测] 档位 {qps:g}QPS 触发降级: signal={self.result.signal}"
                    f", 成功率={ratio:.0%}, avg_rt={avg_rt:.0f}ms"
                )
                cur = last_ok
                break
            last_ok = qps
            cur = qps
            logger.debug(f"🛡️ [容量探测] 档位 {qps:g}QPS 全 OK")
        return cur

    # ---- 3) 短突发确认 ----
    async def _burst(self, safe_qps: float) -> None:
        mult = float(getattr(self.cfg, "target_probe_burst_multiplier", 2.5) or 2.5)
        burst_dur = float(getattr(self.cfg, "target_probe_burst_duration_s", 0.5) or 0.5)
        qps = safe_qps * mult
        n = max(2, min(20, round(burst_dur * qps)))
        interval = (burst_dur / n) if burst_dur > 0 and n > 0 else 0.0
        ok_n = 0
        degraded_sig = ""
        for _i in range(n):
            await asyncio.sleep(interval)
            s = await self.send_one(self.target, qps=qps)
            sig = self._classify(s)
            if sig == "":
                ok_n += 1
            elif not degraded_sig:
                degraded_sig = sig
        if ok_n == n:
            self.result.burst_ok = True
            logger.info(f"🛡️ [容量探测] 短突发 {qps:g}QPS×{n} 全 OK")
        else:
            self.result.burst_ok = False
            # 渐进档已记录降级则不覆盖（保留更早/更保守的档位信号）
            if not self.result.signal:
                self.result.signal = degraded_sig or "burst_low_success"
            if not self.result.stopped_level_qps:
                self.result.stopped_level_qps = qps
            logger.info(f"🛡️ [容量探测] 短突发 {qps:g}QPS×{n} 触发降级: {self.result.signal}")

    # ---- 4) 收口 ----
    def _finalize(self, raw_qps: float) -> None:
        cap_qps = float(getattr(self.cfg, "target_probe_qps_cap", 50) or 50)
        cap_cc = int(getattr(self.cfg, "target_probe_concurrency_cap", 64) or 64)
        factor = float(getattr(self.cfg, "target_probe_safety_factor", 0.7) or 0.7)
        r = self.result
        if raw_qps <= 0:
            # 首档即降级：取最低档为原始值，仍走安全系数但下沉下限
            levels = getattr(self.cfg, "target_probe_levels", None) or [2.0]
            raw_qps = min(float(x) for x in levels)
            if r.signal == "":
                r.signal = "floor"
        r.raw_qps = raw_qps
        r.safe_qps = round(min(max(0.5, raw_qps * factor), cap_qps), 2)
        rt_s = (self.base_rt_ms or 200.0) / 1000.0
        # 并发下限 min(4, cap_cc)：防打挂的主闸门是 safe_qps 限流而非并发数；
        # 极快目标（本地靶机 rt~3ms）按 Little's Law 会算出并发 0→1，攻击任务
        # （AI 验证主导）被压成串行，预算内跑不完大量任务（实测 398 任务被截断）
        r.safe_concurrency = max(min(4, cap_cc), min(round(r.safe_qps * rt_s), cap_cc))
        r.probed = True
        logger.info(
            f"🛡️ [容量探测] 完成: raw={r.raw_qps:g}QPS → safe_qps={r.safe_qps:g},"
            f" safe_concurrency={r.safe_concurrency}"
        )

    @staticmethod
    def _classify(s) -> str:
        """返回降级信号字符串；'' = 正常。"""
        err = (s.error or "").lower()
        if s.status == 429:
            return "429"
        if s.status == 403:
            return "403"
        if s.status and s.status >= 500:
            return "5xx"
        if "timeout" in err or "timed out" in err:
            return "timeout"
        if ("reset" in err or "connection" in err or "refused" in err
                or "unreachable" in err or "closed" in err):
            return "connect_reset"
        if err:
            return "other"
        return ""


__all__ = [
    "CapacityResult", "ProbeSample", "run_capacity_probe",
    "set_capacity", "get_capacity", "reset_capacity", "reset_all_capacity",
    "get_safe_qps", "get_safe_concurrency",
]