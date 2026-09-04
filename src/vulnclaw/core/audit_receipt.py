# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""审计凭证链（Audit Receipt Chain）——防篡改的验证结果收据。

对一批验证后的 finding 逐条出证并串成 hash chain：

    entry_i.receipt_hash = sha256(entry_{i-1}.receipt_hash || sha256(record_i))

任何一条记录被改动（内容/顺序/删除），重算后的 chain_root 都会对不上，
篡改即暴露。可选 HMAC 签名：持有密钥方可伪造，密钥外置（如 CI secret）
时收据具备"来源可证"属性。

纯函数、零依赖、零网络——审计是合规卖点，不能引入新的信任假设。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional, Tuple

RECEIPT_VERSION = "1"
_ALGO = "sha256"
_GENESIS = "0" * 64


def _canon(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_receipt_chain(
    records: List[Dict],
    meta: Optional[Dict] = None,
    secret: str = "",
) -> Dict:
    """对 records（按给定顺序）逐条出证，返回可序列化的凭证链。

    Args:
        records: 已验证 finding 的规范 dict 列表（顺序即出证顺序）。
        meta: 附加元信息（输入名/网关版本/开关状态），参与根签名。
        secret: 可选 HMAC 密钥——设置后收据附 hmac(chain_root)，验真需同密钥。
    """
    entries: List[Dict] = []
    prev = _GENESIS
    for i, rec in enumerate(records):
        record_hash = _sha(_canon(rec))
        receipt_hash = _sha(f"{prev}|{record_hash}")
        entries.append({
            "index": i,
            "record_hash": record_hash,
            "prev_hash": prev,
            "receipt_hash": receipt_hash,
        })
        prev = receipt_hash
    receipt = {
        "version": RECEIPT_VERSION,
        "algo": _ALGO,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "count": len(records),
        "meta": dict(meta or {}),
        "entries": entries,
        "chain_root": prev,
    }
    if secret:
        receipt["hmac"] = hmac.new(
            secret.encode("utf-8"), prev.encode("utf-8"), hashlib.sha256
        ).hexdigest()
    return receipt


def verify_receipt_chain(
    receipt: Dict,
    records: List[Dict],
    secret: str = "",
) -> Tuple[bool, str]:
    """用 records 重算整条链并与 receipt 比对。

    Returns:
        (ok, reason)。records 内容/顺序/条数与出证时不一致 → False。
        receipt 带 hmac 且 secret 正确 → 伪造（连 records 一起改）也会因
        HMAC 不匹配而失败。
    """
    if not isinstance(receipt, dict):
        return False, "receipt 不是 dict"
    rebuilt = build_receipt_chain(records, meta=receipt.get("meta") or {})
    if rebuilt["count"] != receipt.get("count"):
        return False, f"条数不一致: 出证 {receipt.get('count')} vs 重算 {rebuilt['count']}"
    old_entries = receipt.get("entries") or []
    for ent in rebuilt["entries"]:
        i = ent["index"]
        if i >= len(old_entries):
            return False, f"凭证缺少第 {i} 条 entry（疑似删除记录）"
        if ent["record_hash"] != old_entries[i].get("record_hash"):
            return False, f"第 {i} 条记录被篡改（record_hash 不匹配）"
    if rebuilt["chain_root"] != receipt.get("chain_root"):
        return False, "chain_root 不匹配（记录内容或顺序被改动）"
    want = receipt.get("hmac")
    if want:
        if not secret:
            return False, "收据带 HMAC 签名但未提供验签密钥"
        calc = hmac.new(
            secret.encode("utf-8"), rebuilt["chain_root"].encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(calc, str(want)):
            return False, "HMAC 验签失败（密钥不符或收据被伪造）"
    return True, "ok"
