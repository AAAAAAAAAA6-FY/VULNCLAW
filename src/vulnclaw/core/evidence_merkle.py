#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""证据 Merkle 链（P3-④，2026-09-15）。

问题：扫描报告（JSON/HTML/SARIF）与 PoC 产物此前全是"裸奔"文件——
改一个 PoC 字符、删一条 finding 都无法察觉。core/audit_receipt.py 已有
hash chain + HMAC 能力，但只服务 `verify` 子命令与工具治理事件，
主扫描报告从未接入。

本模块补上主报告的证据出证：
- leaf_hash(v)：一条 finding 的证据叶子摘要（poc + evidence + 响应快照）
- build_merkle：标准二叉 Merkle（奇数层末位复制自身，避免歧义）
- merkle_proof / verify_proof：单条证据可独立验证，不必重算全树
- build_evidence_chain / verify_evidence_chain：报告级出证与验真

设计约束：
- **零外部依赖**（stdlib hashlib），纯函数；
- **只新增 report 顶层字段**（evidence_root / evidence_chain），不改任何
  既有键 → SARIF/HTML/下游 autofix 全不受影响；
- 旧报告无 evidence_root 即视为"未出证"，verify 返回 False 而非报错（fail-open）；
- 出证失败一律静默（绝不阻断报告落盘）。
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Tuple

_ALGO = "sha256"
MAX_LEAVES = 500


def _canon(obj: Any) -> str:
    # 与 core/audit_receipt.py 的规范化保持一致（sort_keys + ensure_ascii=False）
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def leaf_hash(v: Dict) -> str:
    """一条 finding 的证据叶子摘要。

    只取"证据性"字段（身份键 + poc_sha256 + evidence + response_preview），
    不含置信度/时间等易变字段 —— 保证同一份证据重复计算结果一致。
    """
    return _sha(_canon({
        "url": str(v.get("url") or ""),
        "type": str(v.get("type") or ""),
        "parameter": str(v.get("parameter") or ""),
        "poc_sha256": str(v.get("poc_sha256") or ""),
        "evidence": str(v.get("evidence") or ""),
        "response_preview": str(v.get("response_preview") or ""),
    }))


def build_merkle(leaves: List[str]) -> Dict:
    """标准二叉 Merkle 树。奇数个节点时末位复制自身（业界通行做法）。"""
    if not leaves:
        return {"algo": _ALGO, "root": "", "levels": [], "count": 0}
    level = [str(x) for x in leaves]
    levels: List[List[str]] = [list(level)]
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [_sha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(list(level))
    return {"algo": _ALGO, "root": level[0], "levels": levels, "count": len(leaves)}


def merkle_proof(levels: List[List[str]], index: int) -> List[Dict]:
    """取第 index 片叶子的存在性证明：[(兄弟哈希, 左右位置), ...]（自底向上）。"""
    proof: List[Dict] = []
    if not levels:
        return proof
    i = int(index)
    for lvl in levels[:-1]:
        if i % 2 == 0:
            sib = lvl[i + 1] if i + 1 < len(lvl) else lvl[i]  # 奇数复制情形
            side = "right"
        else:
            sib = lvl[i - 1]
            side = "left"
        proof.append({"hash": sib, "side": side})
        i //= 2
    return proof


def verify_proof(leaf: str, index: int, proof: List[Dict], root: str) -> bool:
    """用叶子 + 证明重算根，与 root 比对。"""
    h = str(leaf)
    for step in proof or []:
        sib = str(step.get("hash") or "")
        h = _sha(h + sib) if str(step.get("side")) == "right" else _sha(sib + h)
    return h == str(root)


def build_evidence_chain(report: Dict, max_leaves: int = MAX_LEAVES) -> Dict:
    """报告 → 证据链（叶子摘要 + Merkle 根 + 可验证元数据）。"""
    vulns = [v for v in ((report or {}).get("vulnerabilities") or []) if isinstance(v, dict)]
    leaves = [leaf_hash(v) for v in vulns[:max(1, int(max_leaves))]]
    tree = build_merkle(leaves)
    return {
        "algo": _ALGO,
        "root": tree["root"],
        "count": tree["count"],
        "levels": tree["levels"],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def verify_evidence_chain(report: Dict) -> Tuple[bool, str]:
    """重算报告证据链并与 report["evidence_root"] 比对。

    旧报告（无 evidence_root）→ (False, "未出证")，不抛异常。
    """
    root = str((report or {}).get("evidence_root") or "")
    if not root:
        return False, "未出证（报告无 evidence_root）"
    tree = build_evidence_chain(report)
    if not tree.get("root"):
        return False, "无证据叶子"
    ok = tree["root"] == root
    return ok, ("一致" if ok else "证据链不匹配（产物被改动）")
