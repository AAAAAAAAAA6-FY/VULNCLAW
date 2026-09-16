# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""方向2：实战回灌闭环——扫描经验账本（自动成长第一腿）。

职责：
- absorb：把每次扫描的 findings + 判定（confirm/miss/fp）回流成结构化事实，
  跨扫描持久到 JSONL 台账（_runtime_cache/growth/feedback.jsonl）。
- recommend：按 漏洞类型 x 技术栈 统计历史有效 payload，供任务生成/深挖阶段
  优先复用（自动提炼有效载荷）。
- suppress：统计强误报指纹，产出自动抑制名单，服务低误报红线
  （同一 type+参数 连续被判 fp 达阈值 -> 进黑名单）。

设计约束：
- 纯增量追加，不改写历史；读取时线性扫描全量（MVP 量级安全）。
- 线程安全（threading.Lock），不依赖事件循环，同步接口。
- 不调用任何 LLM，纯数据管道——零新增模型成本。
"""
import json
import os
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

_UUID_LIKE = re.compile(r"[0-9a-f]{8,12}(?:[-_][0-9a-f]{4,16}){0,3}")
_FEEDBACK_PATH: Optional[str] = None  # 测试可 monkeypatch
_LOCK = threading.Lock()


def _default_path() -> str:
    global _FEEDBACK_PATH
    if _FEEDBACK_PATH is None:
        _FEEDBACK_PATH = os.path.join("_runtime_cache", "growth", "feedback.jsonl")
    return _FEEDBACK_PATH


def _host_of(target: str) -> str:
    """提取 URL/域名的主机部分（只落 host，不落明文完整参数）。"""
    from urllib.parse import urlparse
    t = str(target or "").strip()
    if not t:
        return ""
    if t.startswith(("http://", "https://")):
        return urlparse(t).hostname or t
    return t.split("/")[0]


def _norm_param(param: str) -> str:
    """参数归一化：去掉常见随机 token（uuid/hex/time），便于聚类误报指纹。"""
    p = str(param or "").strip().lower()
    if not p:
        return ""
    return _UUID_LIKE.sub("x", p)[:64]


class FeedbackLedger:
    """实战回灌账本（追加式 JSONL，纯增量）。"""

    def __init__(self, path: Optional[str] = None):
        self._path = os.path.abspath(path or _default_path())
        os.makedirs(os.path.dirname(self._path), exist_ok=True)

    # ---------------- 写入 ----------------
    def record(self, fact: Dict[str, Any]) -> None:
        """追加一条经验事实（自动补 ts/id，未提供时）。"""
        fact = dict(fact or {})
        fact.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        fact.setdefault("id", uuid.uuid4().hex[:12])
        with _LOCK:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(fact, ensure_ascii=False) + "\n")

    def absorb_finding(
        self,
        finding: Dict[str, Any],
        tech_stack: Optional[List[str]] = None,
        verdict: str = "confirm",
        target: str = "",
    ) -> None:
        """把一条扫描 finding + 判定写为经验事实。

        verdict:
          - confirm  命中且验证通过（有效 payload）
          - miss     检测到但未复现（弱证据）
          - fp       确认误报（进入 suppress 统计）
        """
        fact = {
            "kind": "finding",
            "vuln_type": str(finding.get("type") or finding.get("vuln_type") or ""),
            "engine": str(finding.get("engine") or ""),
            "param": str(finding.get("parameter") or finding.get("param") or ""),
            "payload": str(finding.get("payload") or ""),
            "severity": str(finding.get("severity") or ""),
            "evidence": str(finding.get("evidence") or "")[:300],
            "verdict": str(verdict).strip().lower(),
            "tech_stack": [str(t) for t in (tech_stack or [])][:8],
            "target_host": _host_of(target),
            "confidence": finding.get("confidence"),
        }
        self.record(fact)

    def absorb_scan(
        self,
        findings: List[Dict[str, Any]],
        tech_stack: Optional[List[str]] = None,
        target: str = "",
        verdicts: Optional[Dict[str, str]] = None,
    ) -> int:
        """批量吸收一次扫描的 findings。

        verdicts: {finding_id/type: "confirm"|"miss"|"fp"}，缺省按 finding
        自带的 verified/confirmed 判定。
        """
        n = 0
        for f in findings or []:
            vid = str(f.get("id") or f.get("type") or "")
            if verdicts and vid in verdicts:
                v = verdicts[vid]
            elif f.get("verified") is True or f.get("confirmed") is True:
                v = "confirm"
            elif f.get("verified") is False or f.get("confirmed") is False:
                v = "fp"
            else:
                # 中文 confidence（"高/中/低"）此前不匹配 ("high", 1) → 真实报告
                # 全被判成 miss（弱证据），飞轮只能收废料。补齐中英口径。
                _conf = str(f.get("confidence") or "").strip().lower()
                v = ("confirm" if (f.get("confidence") in (1,)
                                   or _conf in ("high", "confirmed", "verify", "true", "高", "确信"))
                     else "miss")
            self.absorb_finding(f, tech_stack=tech_stack, verdict=v, target=target)
            n += 1
        return n

    def absorb_verify(
        self,
        finding: Dict[str, Any],
        verdict: str,
        reason: str = "",
        payload: str = "",
        payload_reproduced: bool = False,
        target: str = "",
        tech_stack: Optional[List[str]] = None,
    ) -> bool:
        """回流单条 AI 验证裁决（T11 写端）。

        把 verify 阶段对某 finding 的裁决结论结构化落盘（结论/理由/payload/
        证据摘要/是否复现成功）。指纹口径与 absorb_finding 完全一致
        (vuln_type, param, payload, target_host)，并叠加 verdict 去重：
        同指纹同裁决已回流过（source=verify 行）则跳过，返回 False（幂等）。

        verdict: confirm（确认/复现成功） / rejected（未确认）等，归一到底层口径。
        """
        f = dict(finding or {})
        v = str(verdict).strip().lower() or "rejected"
        vt = str(f.get("type") or f.get("vuln_type") or "")
        pm = str(f.get("parameter") or f.get("param") or "")
        pl = str(payload or f.get("payload") or "")
        th = _host_of(str(target or f.get("target") or ""))
        fp = (vt, pm, pl, th, v)
        for row in self.rows():
            if str(row.get("source")) != "verify":
                continue
            if (str(row.get("vuln_type") or ""),
                    str(row.get("param") or ""),
                    str(row.get("payload") or ""),
                    str(row.get("target_host") or ""),
                    str(row.get("verdict") or "")) == fp:
                return False
        fact = {
            "kind": "finding",
            "source": "verify",
            "vuln_type": vt,
            "engine": str(f.get("engine") or ""),
            "param": pm,
            "payload": pl,
            "severity": str(f.get("severity") or ""),
            "evidence": str(f.get("evidence") or "")[:300],
            "verdict": v,
            "tech_stack": [str(t) for t in (tech_stack or [])][:8],
            "target_host": th,
            "confidence": f.get("confidence"),
            "verify_reason": str(reason or "")[:300],
            "payload_reproduced": bool(payload_reproduced),
        }
        self.record(fact)
        return True

    # ---------------- 读取 ----------------
    def rows(self) -> List[Dict[str, Any]]:
        """读全量事实（追加式账本，MVP 量级线性扫描安全）。"""
        if not os.path.exists(self._path):
            return []
        out = []
        with _LOCK:
            with open(self._path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return out

    def recommend_payloads(
        self,
        vuln_type: str,
        tech_stack: Optional[List[str]] = None,
        k: int = 3,
    ) -> List[str]:
        """按 漏洞类型 x 技术栈 推荐历史有效 payload（有 confirm 记录且未被误报污染）。

        pollution：某 payload 只要出现过 fp 判定，则不推荐（防误报累积）。
        """
        vt = str(vuln_type or "").strip().lower()
        stack = set(str(s).strip().lower() for s in (tech_stack or []) if s)
        counts: Dict[str, int] = {}
        polluted: set = set()
        for r in self.rows():
            if str(r.get("kind", "")) != "finding":
                continue
            if vt and str(r.get("vuln_type", "")).strip().lower() != vt:
                continue
            payload = str(r.get("payload") or "").strip()
            if not payload:
                continue
            rs = set(str(s).lower() for s in (r.get("tech_stack") or []))
            if stack and not (rs & stack):
                continue
            verdict = str(r.get("verdict") or "confirm")
            if verdict == "fp":
                polluted.add(payload)
            elif verdict == "confirm":
                counts[payload] = counts.get(payload, 0) + 1
        ranked = sorted(
            (p for p in counts if p not in polluted),
            key=lambda _p: (-counts[_p], _p),
        )
        return ranked[:k]

    def suppressed_signatures(self, min_shadow: int = 2) -> List[str]:
        """强误报指纹：同一 (vuln_type, 归一化参数) 累计 fp 达阈值 -> 抑制签名。

        签名格式："<vuln_type>|<norm_param>"，供扫描侧跳过该类参数。
        """
        shadow: Dict[str, int] = {}
        for r in self.rows():
            if str(r.get("kind", "")) != "finding":
                continue
            if str(r.get("verdict")) not in ("fp",):
                continue
            vt = str(r.get("vuln_type", "")).strip().lower()
            np_ = _norm_param(r.get("param"))
            if not vt:
                continue
            key = f"{vt}|{np_}" if np_ else f"{vt}|*"
            shadow[key] = shadow.get(key, 0) + 1
        return sorted(key for key, n in shadow.items() if n >= min_shadow)

    # ---------------- 摘要 ----------------
    def snapshot(self) -> Dict[str, Any]:
        rows = self.rows()
        by_verdict: Dict[str, int] = {}
        payload_count = 0
        for r in rows:
            v = str(r.get("verdict") or "unknown")
            by_verdict[v] = by_verdict.get(v, 0) + 1
            if r.get("payload"):
                payload_count += 1
        return {
            "facts": len(rows),
            "by_verdict": by_verdict,
            "payload_facts": payload_count,
            "suppressed": len(self.suppressed_signatures()),
            "path": self._path,
        }


_LEDGER: Optional[FeedbackLedger] = None


def get_feedback_ledger() -> FeedbackLedger:
    """单例出口（账本路径由 _FEEDBACK_PATH/默认 runtime cache 决定）。"""
    global _LEDGER
    if _LEDGER is None:
        _LEDGER = FeedbackLedger()
    return _LEDGER


def reset_feedback_ledger() -> None:
    """测试用：重置单例。"""
    global _LEDGER
    _LEDGER = None