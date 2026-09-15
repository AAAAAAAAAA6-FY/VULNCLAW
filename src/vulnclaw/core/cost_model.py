# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""扫描成本模型（纯函数 / 确定性 / 零 IO / 零网络 / 零 AI）。

设计约束
--------
1. **纯函数**：同一输入永远得到同一输出，无随机、无时钟、无文件、无网络。
   唯一"外部"依赖是本模块顶部的可调常数（改动常数即改动估算口径）。
2. **可审计**：每个引擎的请求代价都在 ``ENGINE_COST_PROFILES`` 里显式列出，
   便于与 ``scripts/benchmark.py`` 的 REQUEST 计数（``EVAL_REQUESTS``/
   ``FIXTURE_REQUESTS``）逐项对账；缺口回退 ``DEFAULT_ENGINE_COST``。
3. **不猜事故**：输入非法一律 ``ValueError``/``TypeError``，绝不静默取默认值
   （静默默认会把"参数写错"伪装成"成本很低"）。

成本单位口径（relative_cost）
----------------------------
- 请求类（``estimate_request_cost`` / ``estimate_scan_cost`` /
  ``estimate_oob_polling_cost``）：1 成本单位 = ``COST_UNIT_REQUESTS`` 个请求；
- 报告类（``estimate_report_cost``）：1 成本单位 = ``COST_UNIT_BYTES`` 字节产物。
两类单位不可跨类比较，各自在自己的量纲内单调可比。
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple, Union

__all__ = [
    "COST_UNIT_BYTES",
    "COST_UNIT_REQUESTS",
    "DEFAULT_ENGINE_COST",
    "DEFAULT_PAYLOAD_COUNT",
    "DEFAULT_REQUEST_LATENCY_MS",
    "ENGINE_COST_PROFILES",
    "EXPOSURE_FACTORS",
    "SEVERITY_WEIGHTS",
    "CONFIDENCE_FACTORS",
    "CostEstimate",
    "EngineCostProfile",
    "engine_cost_profile",
    "estimate_oob_polling_cost",
    "estimate_report_cost",
    "estimate_request_cost",
    "estimate_scan_cost",
    "risk_benefit_ratio",
]

# ---------------------------------------------------------------
# 可调常数（唯一"外部依赖"；改这里 = 改估算口径）
# ---------------------------------------------------------------
#: 单请求经验 RTT（毫秒）。本地/常规 Web 目标实测中位数约 0.3s；
#: 真实目标请用 ``per_request_latency_ms`` 显式覆盖（如容量探测测得的 RT）。
DEFAULT_REQUEST_LATENCY_MS: float = 300.0
#: 1 个"成本单位" = 100 请求
COST_UNIT_REQUESTS: float = 100.0
#: 1 个"成本单位" = 200 KB 报告产物
COST_UNIT_BYTES: float = 200_000.0
#: 未显式给出 payload 深度时的默认条数
DEFAULT_PAYLOAD_COUNT: int = 10
#: OOB 轮询默认间隔（秒）——与 ``core/oob_channel.wait_for_interaction`` 的默认
#: ``interval=1.5`` 对齐，改动此处需同步该处。
DEFAULT_OOB_POLL_INTERVAL_S: float = 1.5
#: 报告渲染固定开销（字节 / 秒）
_REPORT_FIXED_BYTES: int = 8_192
_REPORT_FIXED_SECONDS: float = 0.5


# ---------------------------------------------------------------
# 引擎请求代价表
# ---------------------------------------------------------------
@dataclass(frozen=True)
class EngineCostProfile:
    """单个引擎的请求代价画像。

    Attributes:
        requests_per_payload: 每条 payload 触发的请求数（含确认/复测请求）。
        baseline_requests: 引擎启动固定开销（指纹、基线采样、握手等）。
        payload_depth_hint: 该引擎"跑满"所需的 payload 条数经验值。
    """

    requests_per_payload: float
    baseline_requests: int
    payload_depth_hint: int


#: 兜底画像：未登记引擎（自定义/第三方引擎）按"1 请求/payload + 2 基线"计。
DEFAULT_ENGINE_COST = EngineCostProfile(
    requests_per_payload=1.0, baseline_requests=2, payload_depth_hint=10
)

#: 引擎 → 请求代价画像（键与 ``vulnclaw.engines.ENGINE_REGISTRY`` 的 name 对齐）。
ENGINE_COST_PROFILES: Dict[str, EngineCostProfile] = {
    # ---- 注入 / 模糊测试（核心）----
    "sqli": EngineCostProfile(1.5, 2, 12),
    "xss": EngineCostProfile(1.0, 1, 12),
    "cmdi": EngineCostProfile(1.5, 2, 10),
    "lfi": EngineCostProfile(1.5, 2, 10),
    "rfi": EngineCostProfile(1.0, 2, 8),
    "ssti": EngineCostProfile(1.5, 2, 10),
    "nosql": EngineCostProfile(1.0, 1, 8),
    "ldap": EngineCostProfile(1.0, 1, 8),
    "xpath_injection": EngineCostProfile(1.0, 2, 8),
    "ssi_injection": EngineCostProfile(1.0, 2, 8),
    "el_injection": EngineCostProfile(1.5, 2, 10),
    "crlf": EngineCostProfile(1.0, 1, 8),
    "hpp": EngineCostProfile(2.0, 2, 8),
    "prototype_pollution": EngineCostProfile(1.0, 1, 8),
    "jsonp_hijacking": EngineCostProfile(1.0, 1, 6),
    "request_smuggling": EngineCostProfile(3.0, 4, 6),
    "http2_ws": EngineCostProfile(2.0, 3, 6),
    "parsing_shadow": EngineCostProfile(2.0, 2, 8),
    "llm_injection": EngineCostProfile(1.0, 2, 8),
    # ---- 反序列化 / 框架 RCE（多为单发探测器）----
    "deserialization": EngineCostProfile(1.0, 2, 10),
    "dotnet_deserialization": EngineCostProfile(1.0, 2, 8),
    "view_state": EngineCostProfile(1.0, 2, 6),
    "log4shell": EngineCostProfile(1.5, 3, 8),
    "fastjson_deserialization": EngineCostProfile(1.0, 2, 6),
    "struts2_ognl": EngineCostProfile(1.0, 2, 6),
    "spring4shell": EngineCostProfile(1.0, 2, 6),
    "shiro_rememberme": EngineCostProfile(1.0, 2, 6),
    "spring_cloud_gateway": EngineCostProfile(1.0, 2, 6),
    # ---- 带外回连（盲打：等待成本远大于请求成本）----
    "ssrf": EngineCostProfile(2.0, 3, 10),
    "xxe": EngineCostProfile(2.0, 2, 8),
    # ---- 上传 / 重定向 / 缓存 ----
    "file_upload": EngineCostProfile(1.5, 3, 6),
    "open_redirect": EngineCostProfile(1.0, 1, 8),
    "cors": EngineCostProfile(1.0, 2, 6),
    "host_header": EngineCostProfile(1.0, 2, 6),
    "web_cache_deception": EngineCostProfile(2.0, 2, 6),
    "cache_poison": EngineCostProfile(2.0, 3, 6),
    # ---- 暴露面（多为单路径单请求，极便宜）----
    "security_headers": EngineCostProfile(1.0, 1, 1),
    "info_leak": EngineCostProfile(1.0, 1, 8),
    "backup_file_leak": EngineCostProfile(1.0, 1, 20),
    "source_code_leak": EngineCostProfile(1.0, 1, 20),
    "swagger_api_doc": EngineCostProfile(1.0, 1, 10),
    "spring_actuator": EngineCostProfile(1.0, 1, 15),
    "prometheus_metrics": EngineCostProfile(1.0, 1, 5),
    "admin_console_exposure": EngineCostProfile(1.0, 1, 15),
    "confluence_exposure": EngineCostProfile(1.0, 1, 6),
    "nacos_exposure": EngineCostProfile(1.0, 1, 6),
    "solr_exposure": EngineCostProfile(1.0, 1, 6),
    "container_platform_exposure": EngineCostProfile(1.0, 1, 6),
    "cloud_container_exposure": EngineCostProfile(1.0, 1, 6),
    "container_security": EngineCostProfile(1.0, 1, 5),
    "verb_tampering": EngineCostProfile(1.0, 5, 1),
    "dns_security": EngineCostProfile(1.0, 2, 4),
    "tls_security": EngineCostProfile(1.0, 2, 4),
    # ---- API / 组件 ----
    "api_security": EngineCostProfile(1.0, 2, 10),
    "api_version": EngineCostProfile(1.0, 2, 6),
    "api_version_diff": EngineCostProfile(2.0, 4, 6),
    "mass_assignment": EngineCostProfile(1.0, 2, 8),
    "mobile_api": EngineCostProfile(1.0, 2, 8),
    "websocket_security": EngineCostProfile(1.0, 2, 6),
    "graphql": EngineCostProfile(1.0, 3, 8),
    "graphql_introspection": EngineCostProfile(1.0, 2, 2),
    "js_library_cve": EngineCostProfile(1.0, 2, 5),
    "backend_component_cve": EngineCostProfile(1.0, 2, 5),
    # ---- 认证 / 会话（多身份差分，请求成对）----
    "idor": EngineCostProfile(1.0, 2, 10),
    "idor_dual_session": EngineCostProfile(2.0, 3, 10),
    "jwt": EngineCostProfile(1.0, 2, 8),
    "oauth": EngineCostProfile(1.0, 2, 6),
    "session": EngineCostProfile(1.0, 2, 6),
    "weak_credential": EngineCostProfile(1.0, 2, 10),
    "auth_enumeration": EngineCostProfile(1.0, 2, 8),
    "password_reset": EngineCostProfile(1.0, 2, 6),
    "csrf": EngineCostProfile(1.0, 2, 6),
    "rate_limit": EngineCostProfile(1.5, 3, 10),
    # ---- 业务逻辑（需状态机 / 并发复现，代价最高）----
    "business_logic": EngineCostProfile(2.0, 3, 8),
    "race_condition": EngineCostProfile(3.0, 4, 6),
    "state_chain": EngineCostProfile(2.0, 3, 6),
    # ---- 实验性深挖 ----
    "deep_chimera": EngineCostProfile(3.0, 5, 8),
    "symbolic_logic": EngineCostProfile(1.5, 2, 6),
}


def engine_cost_profile(engine_name: str) -> EngineCostProfile:
    """返回引擎的请求代价画像；未登记引擎回退 ``DEFAULT_ENGINE_COST``。"""
    return ENGINE_COST_PROFILES.get(str(engine_name), DEFAULT_ENGINE_COST)


# ---------------------------------------------------------------
# 通用返回结构
# ---------------------------------------------------------------
@dataclass(frozen=True)
class CostEstimate:
    """一次成本估算结果（不可变）。

    Attributes:
        requests: 预计 HTTP 请求数（报告类估算恒为 0）。
        seconds: 预计墙钟耗时（秒）。
        relative_cost: 相对成本（量纲见模块 docstring）。
        size_bytes: 产物字节数（仅报告类估算非 0）。
        breakdown: 逐引擎请求数明细（``((engine, requests), ...)``）。
    """

    requests: int
    seconds: float
    relative_cost: float
    size_bytes: int = 0
    breakdown: Tuple[Tuple[str, int], ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        """转为可 JSON 序列化的 dict。"""
        data = asdict(self)
        data["breakdown"] = [list(item) for item in self.breakdown]
        return data


# ---------------------------------------------------------------
# 估算函数
# ---------------------------------------------------------------
def estimate_request_cost(
    engine_name: str,
    payload_count: int,
    per_request_latency_ms: float = DEFAULT_REQUEST_LATENCY_MS,
) -> CostEstimate:
    """估算"单引擎 × 单目标 × N 条 payload"的请求成本。

    Args:
        engine_name: 引擎名（``ENGINE_REGISTRY`` 的 name；未登记走兜底画像）。
        payload_count: payload 条数（0 = 只跑基线请求）。
        per_request_latency_ms: 单请求经验耗时（毫秒），默认 300ms。

    Raises:
        ValueError: payload_count 为负 / 延迟为负或非有限。
        TypeError: 参数类型非法。
    """
    count = _as_non_negative_int(payload_count, "payload_count")
    latency_ms = _as_positive_float(per_request_latency_ms, "per_request_latency_ms")
    prof = engine_cost_profile(engine_name)
    requests = int(prof.baseline_requests + math.ceil(count * prof.requests_per_payload))
    seconds = requests * latency_ms / 1000.0
    return CostEstimate(
        requests=requests,
        seconds=round(seconds, 6),
        relative_cost=round(requests / COST_UNIT_REQUESTS, 6),
        breakdown=((str(engine_name), requests),),
    )


def estimate_scan_cost(
    engines: Union[Mapping[str, int], Iterable[Union[str, Tuple[str, int]]], str],
    targets: Union[int, Sequence[Any]] = 1,
    concurrency: int = 1,
    per_request_latency_ms: float = DEFAULT_REQUEST_LATENCY_MS,
) -> CostEstimate:
    """估算整轮扫描的请求成本。

    并发模型是**理想线性摊薄**（``seconds = 总请求 × 单请求耗时 / 并发``），
    因此结果是乐观下界：真实墙钟还会叠加限速、反扫描退避、AI 验证等开销。

    Args:
        engines: 引擎集合，三种写法均可——
            * ``{"sqli": 12, "xss": 8}``（引擎 → payload 深度）
            * ``["sqli", "xss"]``（用默认 payload 深度）
            * ``[("sqli", 12), ("xss", 8)]``
        targets: 目标数量，或目标序列（取 ``len``）。
        concurrency: 并发度（>= 1）。
        per_request_latency_ms: 单请求经验耗时（毫秒）。

    Raises:
        ValueError: 并发 < 1 / payload 为负 / 目标数为负 / 延迟非法。
        TypeError: engines 元素形态非法。
    """
    items = _normalize_engine_spec(engines)
    target_count = _normalize_target_count(targets)
    conc = _as_positive_int(concurrency, "concurrency")
    latency_ms = _as_positive_float(per_request_latency_ms, "per_request_latency_ms")

    breakdown: List[Tuple[str, int]] = []
    per_target = 0
    for name, payload_count in items:
        prof = engine_cost_profile(name)
        req = int(prof.baseline_requests + math.ceil(payload_count * prof.requests_per_payload))
        breakdown.append((name, req))
        per_target += req

    total_requests = per_target * target_count
    seconds = total_requests * latency_ms / 1000.0 / conc
    return CostEstimate(
        requests=total_requests,
        seconds=round(seconds, 6),
        relative_cost=round(total_requests / COST_UNIT_REQUESTS, 6),
        breakdown=tuple(breakdown),
    )


def estimate_oob_polling_cost(
    tokens: int,
    poll_interval_s: float = DEFAULT_OOB_POLL_INTERVAL_S,
    poll_timeout_s: float = 15.0,
    concurrency: int = 1,
) -> CostEstimate:
    """估算带外回连（OOB）轮询成本。

    与 ``core/oob_channel.wait_for_interaction`` 的真实行为对齐：**按 token 轮询**，
    每个 token 在 ``poll_timeout_s`` 内每 ``poll_interval_s`` 拉一次，
    每拉一次 = 1 个通道请求（interactsh 子进程查询 / dnslog getrecords）。

    Args:
        tokens: 待等待的 token 数（= 注入的盲打 payload 数）。
        poll_interval_s: 轮询间隔（秒，> 0）。
        poll_timeout_s: 单 token 等待上限（秒，> 0）。
        concurrency: 并发等待的任务数（>= 1），用于摊薄墙钟。

    Raises:
        ValueError: tokens 为负 / 间隔或超时非正 / 并发 < 1。
    """
    tok = _as_non_negative_int(tokens, "tokens")
    interval = _as_positive_float(poll_interval_s, "poll_interval_s")
    timeout = _as_positive_float(poll_timeout_s, "poll_timeout_s")
    conc = _as_positive_int(concurrency, "concurrency")

    polls_per_token = max(1, int(math.ceil(timeout / interval)))
    requests = tok * polls_per_token
    seconds = tok * timeout / conc
    return CostEstimate(
        requests=requests,
        seconds=round(seconds, 6),
        relative_cost=round(requests / COST_UNIT_REQUESTS, 6),
        breakdown=(("oob_polling", requests),),
    )


#: 报告详细度 → (每条 finding 字节数, 每条 finding 渲染秒数)
_REPORT_DETAIL_COST: Dict[str, Tuple[int, float]] = {
    "full": (4_200, 0.020),
    "summary": (900, 0.008),
    "compact": (420, 0.004),
}


def estimate_report_cost(finding_count: int, detail: str = "full") -> CostEstimate:
    """估算报告产物成本（字节 / 渲染耗时）。

    Args:
        finding_count: 漏洞条数（>= 0）。
        detail: 详细度，取值与 ``core/report_generator.compact_report`` 对齐：
            ``full`` / ``summary`` / ``compact``。

    Raises:
        ValueError: finding_count 为负 / detail 非法。
    """
    count = _as_non_negative_int(finding_count, "finding_count")
    key = str(detail).strip().lower()
    if key not in _REPORT_DETAIL_COST:
        raise ValueError(
            f"不支持的报告详细度 {detail!r}；可用: {', '.join(sorted(_REPORT_DETAIL_COST))}"
        )
    per_bytes, per_seconds = _REPORT_DETAIL_COST[key]
    size_bytes = _REPORT_FIXED_BYTES + count * per_bytes
    seconds = _REPORT_FIXED_SECONDS + count * per_seconds
    return CostEstimate(
        requests=0,
        seconds=round(seconds, 6),
        relative_cost=round(size_bytes / COST_UNIT_BYTES, 6),
        size_bytes=size_bytes,
        breakdown=((f"report:{key}", size_bytes),),
    )


# ---------------------------------------------------------------
# 风险收益
# ---------------------------------------------------------------
#: 严重度 → 风险权重（0~10 量纲）
SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 1.0,
    "unknown": 1.0,
}

#: 暴露面 → 可达性系数（0~1）
EXPOSURE_FACTORS: Dict[str, float] = {
    "internet": 1.0,
    "external": 1.0,
    "public": 1.0,
    "dmz": 0.8,
    "internal": 0.55,
    "intranet": 0.55,
    "authenticated": 0.35,
    "auth": 0.35,
    "local": 0.2,
    "unknown": 0.5,
}

#: 置信度 → 系数（0~1）
CONFIDENCE_FACTORS: Dict[str, float] = {
    "certain": 1.0,
    "confirmed": 1.0,
    "high": 0.9,
    "firm": 0.8,
    "medium": 0.7,
    "tentative": 0.5,
    "low": 0.35,
    "unverified": 0.3,
}


def risk_benefit_ratio(
    severity: str,
    exposure: Union[str, float] = "unknown",
    confidence: Union[str, float] = "medium",
) -> float:
    """最小实现的风险收益比：``严重度权重 × 暴露系数 × 置信度系数``。

    用于预算裁减时判断"这个引擎值不值得留"以及报告排序参考。
    返回 0~10 的浮点数（越大 = 越值得花请求预算）。

    Args:
        severity: 严重度字符串（``critical``/``high``/``medium``/``low``/``info``）。
        exposure: 暴露面字符串，或 0~1 数值（越界会被夹到区间内）。
        confidence: 置信度字符串，或 0~1 数值（越界会被夹到区间内）。

    Raises:
        ValueError: severity 非空但未登记；exposure/confidence 字符串未登记。
    """
    weight = _lookup_factor(severity, SEVERITY_WEIGHTS, "severity")
    exp = _coerce_factor(exposure, EXPOSURE_FACTORS, "exposure")
    conf = _coerce_factor(confidence, CONFIDENCE_FACTORS, "confidence")
    return round(weight * exp * conf, 4)


# ---------------------------------------------------------------
# 内部工具（同样是纯函数）
# ---------------------------------------------------------------
def _lookup_factor(value: Any, table: Mapping[str, float], label: str) -> float:
    if value is None:
        return table["unknown"]
    if isinstance(value, bool):  # bool 是 int 子类，显式拒绝避免 True→1.0 的歧义
        raise TypeError(f"{label} 不接受布尔值")
    if isinstance(value, (int, float)):
        return float(value)
    key = str(value).strip().lower()
    if not key:
        return table["unknown"]
    if key not in table:
        raise ValueError(
            f"未登记的 {label}={value!r}；可用: {', '.join(sorted(table))}"
        )
    return table[key]


def _coerce_factor(
    value: Any, table: Mapping[str, float], label: str
) -> float:
    factor = _lookup_factor(value, table, label)
    return min(1.0, max(0.0, float(factor)))


def _as_non_negative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{label} 必须是整数，得到 {type(value).__name__}")
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{label} 必须是整数，得到 {value!r}")
    ivalue = int(value)
    if ivalue < 0:
        raise ValueError(f"{label} 不能为负：{ivalue}")
    return ivalue


def _as_positive_int(value: Any, label: str) -> int:
    ivalue = _as_non_negative_int(value, label)
    if ivalue < 1:
        raise ValueError(f"{label} 必须 >= 1，得到 {ivalue}")
    return ivalue


def _as_positive_float(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{label} 必须是数字，得到 {type(value).__name__}")
    fvalue = float(value)
    if not math.isfinite(fvalue):
        raise ValueError(f"{label} 必须是有限数字，得到 {fvalue!r}")
    if fvalue < 0:
        raise ValueError(f"{label} 不能为负：{fvalue}")
    return fvalue


def _normalize_engine_spec(
    engines: Union[Mapping[str, int], Iterable[Union[str, Tuple[str, int]]], str]
) -> List[Tuple[str, int]]:
    """把多种引擎写法统一成 ``[(engine, payload_count), ...]``（保持输入顺序）。"""
    if isinstance(engines, str):
        return [(engines, DEFAULT_PAYLOAD_COUNT)]
    if isinstance(engines, Mapping):
        pairs: List[Any] = list(engines.items())
    else:
        try:
            pairs = list(engines)
        except TypeError as exc:  # noqa: BLE001
            raise TypeError(f"engines 必须是映射或可迭代对象，得到 {type(engines).__name__}") from exc

    out: List[Tuple[str, int]] = []
    for item in pairs:
        if isinstance(item, str):
            out.append((item, DEFAULT_PAYLOAD_COUNT))
            continue
        if isinstance(item, (tuple, list)) and len(item) == 2:
            out.append(
                (str(item[0]), _as_non_negative_int(item[1], f"engines[{item[0]}]"))
            )
            continue
        raise TypeError(f"engines 元素必须是 str 或 (name, payload_count)，得到 {item!r}")
    return out


def _normalize_target_count(targets: Union[int, Sequence[Any]]) -> int:
    if isinstance(targets, bool):
        raise TypeError("targets 不接受布尔值")
    if isinstance(targets, int):
        if targets < 0:
            raise ValueError(f"targets 不能为负：{targets}")
        return targets
    if isinstance(targets, str):
        raise TypeError("targets 不接受 str（请传目标数量或目标序列）")
    try:
        count = len(targets)  # type: ignore[arg-type]
    except TypeError as exc:  # noqa: BLE001
        raise TypeError(f"targets 必须是 int 或序列，得到 {type(targets).__name__}") from exc
    return int(count)
