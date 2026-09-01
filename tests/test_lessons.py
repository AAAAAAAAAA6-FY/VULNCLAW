# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""A3.4 教训库单测（使用临时文件，避免污染默认 lessons.jsonl）。"""
import os
import tempfile

from vulnclaw.ai.memory.lessons.lesson_store import LessonStore


def test_record_and_query(tmp_path):
    store = LessonStore(path=str(tmp_path / "lessons.jsonl"))
    store.record("target-hash-1", "XSS", "误报：反射参数被 WAF 回显但无执行")
    store.record("target-hash-1", "XSS", "误报：静态资源误匹配")
    lessons = store.query("target-hash-1", "XSS")
    assert len(lessons) == 2
    assert lessons[0].vuln_type == "XSS"


def test_has_false_positive(tmp_path):
    store = LessonStore(path=str(tmp_path / "lessons.jsonl"))
    assert store.has_false_positive("h", "SQLi") is False
    store.record("h", "SQLi", "误报：误报原因-参数过滤")
    assert store.has_false_positive("h", "SQLi") is True


def test_query_miss(tmp_path):
    store = LessonStore(path=str(tmp_path / "lessons.jsonl"))
    store.record("h1", "XSS", "误报：x")
    assert store.query("h2", "XSS") == []
    assert store.query("h1", "SQLi") == []
