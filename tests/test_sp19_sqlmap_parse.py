# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 19：sqlmap_wrapper 深度链路实扫后半程解析补全的单元测试。

覆盖四件事：
  1. stdout available databases 内联 / 多行两种格式解析；
  2. SQLMap JSON 结果（{"data": [...]} 与 {db: {"tables": ...}}）字段抽取；
  3. JSON 缺失键 / 坏 JSON / 空 dict 的优雅降级（不抛异常、结构完整）；
  4. check_waf 的 WAF 关键词识别与无匹配回退逻辑。

说明：项目 pytest 为 asyncio_mode=strict，异步方法统一用 asyncio.run 驱动，
不依赖 pytest-asyncio。全文件无 emoji（Windows GBK 控制台硬约束）。
"""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

from vulnclaw.deepsec.sqlmap_wrapper import SQLMapWrapper


def _make_wrapper() -> SQLMapWrapper:
    """构造封装器实例（不触发任何真实 sqlmap 子进程）。"""
    return SQLMapWrapper(target="http://test.local")


def _write_json(tmp_path, payload) -> str:
    """把 payload 写入临时 JSON 结果文件，返回路径。"""
    p = tmp_path / "result.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return str(p)


# ============================================================
# 1. available databases 解析（stdout 文本）
# ============================================================
class TestParseDatabases:
    def test_inline_database_list(self):
        w = _make_wrapper()
        out = "available databases [2]: db1, db2\n"
        result = w._parse_results("", out)
        assert result["databases"] == ["db1", "db2"]

    def test_multiline_database_list(self):
        w = _make_wrapper()
        out = (
            "available databases [2]:\n"
            "[*] db1\n"
            "[*] db2\n"
            "[19:00:00] [INFO] fetching tables for database: db1\n"
        )
        result = w._parse_results("", out)
        assert result["databases"] == ["db1", "db2"]

    def test_multiline_mixed_styles_dedup(self):
        w = _make_wrapper()
        out = (
            "available databases [3]:\n"
            "[*] db1\n"
            "[x] db2\n"
            "   db3\n"
            "[*] db1\n"
            "[19:00:00] [INFO] done\n"
        )
        result = w._parse_results("", out)
        assert result["databases"] == ["db1", "db2", "db3"]

    def test_inline_with_trailing_log_line(self):
        w = _make_wrapper()
        out = (
            "[19:00:00] [INFO] testing connection\n"
            "available databases [2]: db1, db2\n"
            "[19:00:01] [INFO] fetching tables\n"
        )
        result = w._parse_results("", out)
        assert result["databases"] == ["db1", "db2"]


# ============================================================
# 2. SQLMap JSON 结果解析
# ============================================================
class TestParseJson:
    def test_data_list_structure(self, tmp_path):
        payload = {
            "data": [
                {
                    "url": "http://x/?id=1",
                    "value": {
                        "banner": "MySQL 5.7.40",
                        "current_db": "testdb",
                        "current_user": "root@localhost",
                        "databases": ["information_schema", "testdb"],
                        "tables": {"testdb": ["users", "orders"]},
                        "columns": {"testdb.users": ["id", "name"]},
                        "dump": {"testdb.users": [["1", "a"], ["2", "b"]]},
                    },
                }
            ]
        }
        w = _make_wrapper()
        result = w._parse_results(_write_json(tmp_path, payload), "")
        assert result["banner"] == "MySQL 5.7.40"
        assert result["current_db"] == "testdb"
        assert result["current_user"] == "root@localhost"
        assert result["databases"] == ["information_schema", "testdb"]
        assert result["tables"] == {"testdb": ["users", "orders"]}
        assert result["columns"] == {"testdb.users": ["id", "name"]}
        assert result["dump"] == {"testdb.users": [["1", "a"], ["2", "b"]]}
        assert "raw" in result and result["raw"] == payload

    def test_value_aliases_db_user(self, tmp_path):
        payload = {
            "data": [{"value": {"db": "mydb", "user": "app", "banner": "PostgreSQL 14"}}]
        }
        w = _make_wrapper()
        result = w._parse_results(_write_json(tmp_path, payload), "")
        assert result["current_db"] == "mydb"
        assert result["current_user"] == "app"

    def test_dump_entries_sampling_first_five(self, tmp_path):
        payload = {
            "data": [
                {"value": {"entries": [[f"row{i}"] for i in range(8)]}}
            ]
        }
        w = _make_wrapper()
        result = w._parse_results(_write_json(tmp_path, payload), "")
        assert result["dump"] == [[f"row{i}"] for i in range(5)]

    def test_db_map_structure(self, tmp_path):
        payload = {
            "mydb": {
                "tables": {
                    "users": {
                        "entries": [
                            ["a", "1"], ["b", "2"], ["c", "3"],
                            ["d", "4"], ["e", "5"], ["f", "6"],
                        ]
                    }
                }
            }
        }
        w = _make_wrapper()
        result = w._parse_results(_write_json(tmp_path, payload), "")
        assert result["databases"] == ["mydb"]
        assert "users" in result["tables"]
        assert result["dump"] == {
            "users": [["a", "1"], ["b", "2"], ["c", "3"], ["d", "4"], ["e", "5"]]
        }

    def test_json_merges_with_stdout_databases(self, tmp_path):
        payload = {"data": [{"value": {"databases": ["db1", "db3"]}}]}
        w = _make_wrapper()
        out = "available databases [2]:\n[*] db1\n[*] db2\n"
        result = w._parse_results(_write_json(tmp_path, payload), out)
        # stdout 解析在前，JSON 补充去重
        assert result["databases"] == ["db1", "db2", "db3"]


# ============================================================
# 3. 优雅降级：坏 JSON / 空 dict / 缺失键
# ============================================================
class TestJsonGracefulDegrade:
    def test_bad_json_no_raise(self, tmp_path):
        p = tmp_path / "result.json"
        p.write_text("{not valid json", encoding="utf-8")
        w = _make_wrapper()
        result = w._parse_results(str(p), "")
        assert result["banner"] == ""
        assert result["current_db"] == ""
        assert result["current_user"] == ""
        assert result["databases"] == []
        assert result["tables"] == {}
        assert result["columns"] == {}
        assert result["dump"] == {}

    def test_empty_dict_json(self, tmp_path):
        w = _make_wrapper()
        result = w._parse_results(_write_json(tmp_path, {}), "")
        assert result["banner"] == ""
        assert result["current_db"] == ""
        assert result["databases"] == []
        assert result["tables"] == {}
        assert result["columns"] == {}
        assert result["dump"] == {}

    def test_missing_value_keys(self, tmp_path):
        payload = {"data": [{"value": {"banner": "x"}}]}
        w = _make_wrapper()
        result = w._parse_results(_write_json(tmp_path, payload), "")
        assert result["banner"] == "x"
        assert result["current_db"] == ""
        assert result["current_user"] == ""
        assert result["databases"] == []
        assert result["tables"] == {}
        assert result["columns"] == {}
        assert result["dump"] == {}

    def test_malformed_value_not_dict(self, tmp_path):
        payload = {"data": [{"value": "oops"}]}
        w = _make_wrapper()
        result = w._parse_results(_write_json(tmp_path, payload), "")
        assert result["banner"] == ""
        assert result["databases"] == []

    def test_missing_output_file(self, tmp_path):
        w = _make_wrapper()
        result = w._parse_results(str(tmp_path / "nonexistent.json"), "")
        assert result["banner"] == ""
        assert result["databases"] == []


# ============================================================
# 4. check_waf 关键词识别与回退
# ============================================================
class TestCheckWaf:
    def _run(self, output_text: str) -> dict:
        """mock 掉 sqlmap 子进程，返回 check_waf 的结果字典。"""

        async def _scenario():
            proc = MagicMock()
            proc.communicate = AsyncMock(
                return_value=(output_text.encode("utf-8", "replace"), b"")
            )
            proc.returncode = 0
            with patch(
                "vulnclaw.deepsec.sqlmap_wrapper.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=proc),
            ):
                w = _make_wrapper()
                return await w.check_waf("http://test.local")

        return asyncio.run(_scenario())

    def test_cloudflare_keyword(self):
        result = self._run("The site is behind Cloudflare (Cloudflare) WAF\n")
        assert result["has_waf"] is True
        assert result["waf_type"] == "cloudflare"

    def test_baota_keyword(self):
        result = self._run("detected 宝塔 WAF protection enabled\n")
        assert result["has_waf"] is True
        assert result["waf_type"] == "baota"

    def test_fallback_to_first_waf_line(self):
        result = self._run("Custom WAF detected\n[INFO] something else\n")
        assert result["has_waf"] is True
        assert result["waf_type"] == "Custom WAF detected"

    def test_no_waf_keyword_no_waf_line(self):
        # 有关键词前身文本但不含 "WAF"，保持回退为空串（has_waf 判定不因关键词而放宽）
        result = self._run("site responds normally, no protection\n")
        assert result["has_waf"] is False
        assert result["waf_type"] == ""

    def test_exception_path(self):
        async def _scenario():
            with patch(
                "vulnclaw.deepsec.sqlmap_wrapper.asyncio.create_subprocess_exec",
                new=AsyncMock(side_effect=OSError("no sqlmap")),
            ):
                w = _make_wrapper()
                return await w.check_waf("http://test.local")

        result = asyncio.run(_scenario())
        assert result["has_waf"] is False
        assert result["waf_type"] == ""
        assert result["error"] == "check failed"
