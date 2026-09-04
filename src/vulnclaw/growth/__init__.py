# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of VULNCLAW / pentest_platform.

"""自动成长包（growth）：平台自我进化四条腿。

- 方向1 情报自喂养：CVE 增量摄入 -> 规则草稿 -> 验证 -> 晋升（cve_ingest.CveIngest）
- 方向2 实战回灌：扫描结果回流经验账本 -> payload 推荐 / 误报抑制
  （feedback_ledger.FeedbackLedger）
- 方向3 自举验证：本地最小漏洞靶机自测引擎覆盖 -> 覆盖缺口优先级
  （target_lab.run_coverage）
- 方向4 模型蒸馏（软件侧）：验证过的高质量 finding -> 微调数据集
  （distill_data.export_training_data / train_lor_a）
- 方向5 本地规则集市：外部/社区规则导入校验去重 -> 评分排名 -> 复用池
  （rule_bazaar.RuleBazaar）
"""
from vulnclaw.growth.cve_ingest import CveIngest
from vulnclaw.growth.distill_data import (
    distill_status,
    export_training_data,
    gpu_available,
    train_lor_a,
)
from vulnclaw.growth.feedback_ledger import (
    FeedbackLedger,
    get_feedback_ledger,
    reset_feedback_ledger,
)
from vulnclaw.growth.rule_bazaar import RuleBazaar, community_publish, rule_bazaar_stats
from vulnclaw.growth.target_lab import (
    ENGINE_LAB_MAP,
    TargetLab,
    run_coverage,
    summarize_gap_priorities,
)

__all__ = [
    "CveIngest",
    "FeedbackLedger",
    "get_feedback_ledger",
    "reset_feedback_ledger",
    "TargetLab",
    "run_coverage",
    "summarize_gap_priorities",
    "ENGINE_LAB_MAP",
    "export_training_data",
    "train_lor_a",
    "distill_status",
    "gpu_available",
    "RuleBazaar",
    "community_publish",
    "rule_bazaar_stats",
]