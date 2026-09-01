# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""A3.4 教训库：记录验证阶段误报根因，供下次同目标同类型验证时查询，减少重复误报。

以 JSONL 持久化（append-only），每行一条教训。核心函数 record_lesson / query_lessons /
has_false_positive 可被 phases_verify 在误报判定时调用。
"""
import json
import os
from dataclasses import asdict, dataclass
from typing import List

try:  # 软导入：隔离环境也能独立加载，不硬绑完整 vulnclaw 包
    from vulnclaw.core.logger import logger
except Exception:  # noqa: BLE001
    import logging
    logger = logging.getLogger("vulnclaw.lessons")

LESSON_DIR = os.path.dirname(__file__)
LESSON_FILE = os.path.join(LESSON_DIR, "lessons.jsonl")


@dataclass
class Lesson:
    target_hash: str
    vuln_type: str
    reason: str
    context: str = ""
    count: int = 1

    def to_line(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_line(cls, line: str) -> "Lesson":
        return cls(**json.loads(line))


class LessonStore:
    def __init__(self, path: str = LESSON_FILE):
        self.path = path

    def record(self, target_hash: str, vuln_type: str, reason: str, context: str = "") -> None:
        lesson = Lesson(target_hash=target_hash, vuln_type=vuln_type,
                        reason=reason, context=context)
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(lesson.to_line() + "\n")
        except OSError as exc:
            logger.warning(f"⚠️ 记录教训失败: {exc}")

    def query(self, target_hash: str, vuln_type: str) -> List[Lesson]:
        out: List[Lesson] = []
        if not os.path.exists(self.path):
            return out
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        les = Lesson.from_line(line)
                    except json.JSONDecodeError:
                        continue
                    if les.target_hash == target_hash and les.vuln_type == vuln_type:
                        out.append(les)
        except OSError as exc:
            logger.warning(f"⚠️ 查询教训失败: {exc}")
        return out

    def has_false_positive(self, target_hash: str, vuln_type: str) -> bool:
        return any("误报" in l.reason or "false_positive" in l.reason
                   for l in self.query(target_hash, vuln_type))


# 便捷单例
_default_store = LessonStore()


def record_lesson(target_hash, vuln_type, reason, context=""):
    _default_store.record(target_hash, vuln_type, reason, context)


def query_lessons(target_hash, vuln_type):
    return _default_store.query(target_hash, vuln_type)


def has_false_positive(target_hash, vuln_type):
    return _default_store.has_false_positive(target_hash, vuln_type)


__all__ = ["Lesson", "LessonStore", "record_lesson", "query_lessons", "has_false_positive"]
