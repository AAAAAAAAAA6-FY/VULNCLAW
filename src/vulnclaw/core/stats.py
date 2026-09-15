#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""轻量统计判定工具（P2-①：统计化判定，2026-09-15）。

背景：时间盲注/布尔 diff 的判定长期使用"拍脑袋阈值"
（`diff > baseline_rtt + 1.0`、`difflib 比率 > 0.15`，且基线只采 1 次）。
网络抖动（TLS 握手尖峰 2.7s）或页面动态噪声都能越过单次样本阈值，
这正是若干误报工单的根因。

本模块提供**不依赖 scipy** 的 Welch t 检验：只回答一个问题——
"处理组样本是否显著异于对照组"。依赖已有 numpy；t 分布临界值直接
内置小样本表（渗透场景 n≤5，查表比为此引入 30MB scipy 划算）。

使用原则（调用方必须遵守）：
- 两组样本各 ≥2 才启用统计判定；样本不足时退回旧阈值逻辑（fail-safe）。
- 统计显著 ≠ 有意义：调用方必须同时要求最小实用差值
  （如时间盲注要求 mean 差 ≥ max(1.5s, sleep*0.4)），
  防止"0.3s 的显著差异"刷分。
- 双侧 p≈0.02（单侧 0.01）是刻意保守的选择：宁漏过疑似样本，
  不放一个"网络抖动型"误报进报告。
"""
from __future__ import annotations

import math
from typing import List, Optional, Sequence, Tuple

try:
    import numpy as _np
except ImportError:  # pragma: no cover
    _np = None

# t 分布单侧 0.01（双侧 0.02）临界值表；键为自由度下界，取 ≤df 的最大键（保守）。
_T_CRIT: Tuple[Tuple[float, float], ...] = (
    (2.0, 6.965), (3.0, 4.541), (4.0, 3.747), (5.0, 3.365),
    (6.0, 3.143), (7.0, 2.998), (8.0, 2.896), (9.0, 2.821),
    (10.0, 2.764), (15.0, 2.602), (30.0, 2.457),
)
_T_CRIT_LARGE = 2.326  # df>30：近似正态 z(0.01)


def _clean(samples: Sequence[Optional[float]]) -> List[float]:
    """过滤 None/非数/负值/NaN，保留有限非负浮点。"""
    out: List[float] = []
    for x in samples:
        try:
            v = float(x)
        except (TypeError, ValueError):
            continue
        if math.isfinite(v) and v >= 0:
            out.append(v)
    return out


def _mean_var(a: List[float]) -> Tuple[float, float]:
    if _np is not None:
        return float(_np.mean(a)), float(_np.var(a, ddof=1))
    ma = sum(a) / len(a)
    va = sum((x - ma) ** 2 for x in a) / (len(a) - 1)
    return ma, va


def welch_t(treatment: Sequence[float], control: Sequence[float]) -> float:
    """Welch t 统计量 = (mean_t - mean_c) / sqrt(var_t/n_t + var_c/n_c)。

    约定：
    - 任一组有效样本 <2 → 返回 0.0（不可判定，调用方应退回旧判据）。
    - 两组均无方差但均值不同 → 返回 math.inf（确定性差异，视为显著）。
    - 两组均无方差且均值相同 → 返回 0.0（无差异）。
    """
    a = _clean(treatment)
    b = _clean(control)
    if len(a) < 2 or len(b) < 2:
        return 0.0
    ma, va = _mean_var(a)
    mb, vb = _mean_var(b)
    se = math.sqrt(va / len(a) + vb / len(b))
    if se == 0.0:
        return math.inf if ma != mb else 0.0
    return (ma - mb) / se


def _welch_df(a: List[float], b: List[float]) -> float:
    """Welch–Satterthwaite 近似自由度。"""
    _ma, va = _mean_var(a)
    _mb, vb = _mean_var(b)
    na, nb = len(a), len(b)
    num = (va / na + vb / nb) ** 2
    den = (va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1)
    return num / den if den > 0 else 1.0


def _t_crit(df: float) -> float:
    """按自由度取保守临界值：取 ≤df 的最大键对应值。"""
    if df >= 30.0:
        return _T_CRIT_LARGE
    crit = _T_CRIT[0][1]
    for d, c in _T_CRIT:
        if d <= df:
            crit = c
        else:
            break
    return crit


def welch_significant(
    treatment: Sequence[float],
    control: Sequence[float],
    min_df: float = 2.0,
) -> Tuple[bool, float]:
    """双侧 p≈0.02 的 Welch 显著性判断（小样本保守版）。

    返回 (是否显著, t 统计量)。自由度用 Welch–Satterthwaite 近似；
    df 先 clamp 到 min_df（默认 2）再查临界值——方差失衡会把 df 塌缩到
    ≈1（如注入组抖动大、对照组极稳），此时**不直接判死**，而是用最保守
    临界值（t(0.01, df=2)=6.965）把关：单次尖峰（t≈1）过不去，
    真注入（t>50）能过。保守靠临界值表，而不是靠一票否决。
    """
    a = _clean(treatment)
    b = _clean(control)
    t = welch_t(a, b)
    if t == 0.0:
        return False, t
    if not math.isfinite(t):
        # 两组均无方差：确定性差异 → 显著与否交给调用方的实用差值下限把关。
        return True, t
    df = _welch_df(a, b)
    return abs(t) > _t_crit(max(df, min_df)), t


def mean_of(samples: Sequence[Optional[float]]) -> float:
    """安全均值（过滤非法样本；空 → 0.0）。"""
    a = _clean(samples)
    return sum(a) / len(a) if a else 0.0
