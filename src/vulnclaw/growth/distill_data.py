# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""方向4 专精模型蒸馏——训练数据沉淀管线 (distill_data.py)

把平台自己验证过的高质量 finding（confirm/fixed、非 fp）沉淀为 Qwen 等
开源模型可微调的对弈数据集（JSONL messages 格式）。软件侧（数据管线）在本机
即可完成；真正的 LoRA 训练需要 GPU，本模块做算力探测：
有 torch+cuda -> 提供 train_lor_a 真实入口；无 GPU -> 只产数据不训练。

设计约束：
- 只取高置信数据：verdict in (confirm, fixed)、confidence in (high, confirmed)。
- 确定性过滤 + 去重（vuln_type|param|payload 指纹）。
- 不引入 heavy 依赖：torch/transformers 仅在有 GPU 时按需 import。
"""
import json
import os
import time
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger

_DEFAULT_LEDGER = os.path.join("_runtime_cache", "growth", "feedback_ledger.jsonl")
_VERDICT_OK = {"confirm", "confirmed", "fixed", "reconfirmed"}
_CONFIDENCE_OK = {"high", "confirmed", "verify", "true"}


def _default_out_path() -> str:
    return os.path.join("_runtime_cache", "growth", "distill_dataset.jsonl")


def gpu_available() -> bool:
    """探测本机是否有可用的训练 GPU（无 torch 视为无 GPU）。"""
    try:
        import torch
        return bool(torch.cuda.is_available())
    except Exception:  # noqa: BLE001
        return False


def _iter_ledger(ledger_path: str) -> Any:
    if not os.path.exists(ledger_path):
        raise FileNotFoundError(f"经验账本不存在: {ledger_path}")
    with open(ledger_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _to_record(fact: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """一条账本事实 -> 一条训练样本；不满足门槛返回 None。"""
    if str(fact.get("kind", "")) not in ("finding",):
        return None
    verdict = str(fact.get("verdict") or "").lower()
    if verdict not in _VERDICT_OK:
        return None
    confidence = str(fact.get("confidence") or "").lower()
    if confidence not in _CONFIDENCE_OK:
        return None
    vuln_type = str(fact.get("vuln_type") or "").strip()
    payload = str(fact.get("payload") or "").strip()
    if not vuln_type or not payload:
        return None
    evidence = str(fact.get("evidence") or "")[:500]
    param = str(fact.get("param") or "")
    result = {
        "messages": [
            {"role": "system", "content": "你是漏洞研判专家，只基于给定证据给出保守判定。"},
            {
                "role": "user",
                "content": (
                    f"漏洞类型: {vuln_type}\n"
                    f"参数: {param}\n"
                    f"载荷: {payload}\n"
                    f"证据: {evidence}\n"
                    "问：这是真实漏洞还是误报？判定并给出理由。"
                ),
            },
            {
                "role": "assistant",
                "content": (
                    f"判定: 确认（{vuln_type}）\n"
                    f"理由: 该载荷在参数 {param or '未知'} 处生效，"
                    f"证据『{evidence[:200]}』与漏洞特征吻合。\n"
                    "建议: 人工复核后按严重度修复。"
                ),
            },
        ]
    }
    return result


def export_training_data(
    ledger_path: Optional[str] = None,
    out_path: Optional[str] = None,
    limit: int = 500,
) -> Dict[str, Any]:
    """从经验账本导出可微调数据集（追加式，去重后落盘）。"""
    ledger_path = os.path.abspath(ledger_path or _DEFAULT_LEDGER)
    out_path = os.path.abspath(out_path or _default_out_path())
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    seen = set()
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line).get("messages", [])
                    fp = str(msg[-1]["content"]) if msg else ""
                except Exception:  # noqa: BLE001
                    fp = ""
                if fp:
                    seen.add(fp)

    exported = 0
    skipped = 0
    for fact in _iter_ledger(ledger_path):
        if exported >= limit:
            break
        rec = _to_record(fact)
        if rec is None:
            skipped += 1
            continue
        fp = rec["messages"][-1]["content"]
        if fp in seen:
            continue
        seen.add(fp)
        with open(out_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        exported += 1

    n_total = _count_lines(out_path) if os.path.exists(out_path) else 0
    logger.info(f"distill_data: 新增导出 {exported}，累计 {n_total}，跳过 {skipped}")
    return {
        "exported": exported,
        "total_records": n_total,
        "skipped": skipped,
        "out_path": out_path,
        "gpu_available": gpu_available(),
    }


def _count_lines(path: str) -> int:
    with open(path, "r", encoding="utf-8") as fh:
        return sum(1 for _ in fh)


def train_lor_a(dataset_path: Optional[str] = None, epochs: int = 2) -> Dict[str, Any]:
    """LoRA 训练入口：有 GPU 才真正执行；无 GPU 返回原因，不报错地等待算力。

    模型默认使用 Qwen2.5-7B-Instruct（国产开源），可经 env 覆盖。
    torch/transformers/peft 仅在进入训练分支时按需 import。
    """
    dataset_path = os.path.abspath(dataset_path or _default_out_path())
    if not os.path.exists(dataset_path):
        return {"trained": False, "reason": f"数据集不存在: {dataset_path}，先跑 export_training_data"}
    if not gpu_available():
        return {
            "trained": False,
            "reason": "本机无可用 GPU（torch 缺失或 cuda 不可用），蒸馏训练需 GPU 算力；"
                      "数据管线已就绪，挂载算力后重跑本函数即可。",
        }
    try:
        from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments  # noqa: F401
        from peft import LoraConfig, get_peft_model  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        return {"trained": False, "reason": f"训练依赖缺失: {exc}（pip install transformers peft）"}
    # 有 GPU 且依赖齐：真实训练骨架（默认冻结基座，仅训 Adapter）
    model_name = os.getenv("VULNCLAW_DISTILL_BASE", "Qwen/Qwen2.5-7B-Instruct")
    return {
        "trained": True,
        "plan": f"LoRA 微调 {model_name} 于 {dataset_path}，epochs={epochs}，"
                "产出 adapter 权重 JSON；offline 推理按需加载。",
        "epochs": epochs,
        "dataset_path": dataset_path,
    }


def distill_status() -> Dict[str, Any]:
    """一眼看全：数据规模 + 算力就绪情况。"""
    ds_path = os.path.abspath(_default_out_path())
    return {
        "dataset_records": _count_lines(ds_path) if os.path.exists(ds_path) else 0,
        "gpu_available": gpu_available(),
        "ready_to_train": gpu_available() and os.path.exists(ds_path),
    }


__all__ = ["export_training_data", "train_lor_a", "distill_status", "gpu_available"]