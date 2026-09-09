# -*- coding: utf-8 -*-
"""SP29: 验证兜底信号补全——LDAP/反序列化/命令注入时间盲注的引擎证据
不再被 LLM 一票否决后静默丢弃（根因修复回归测试）。"""
from vulnclaw.ai.v100.phases.phases_verify import _local_rule_verify, _technical_signal_present


class TestTechnicalSignal:
    def test_ldap_error_echo_high(self):
        """LDAP 报错回显（LDAPException）必须视为强证据，即使 type 含'注入'也不走 SQL 分支。"""
        v = {"type": "LDAP注入(通配符-全部匹配)", "evidence": "javax.naming.NamingException: LDAPException; invalid search filter"}
        assert _technical_signal_present(v) is True
        assert _local_rule_verify(None, v) == "ldap_error_marker"

    def test_ldap_result_code(self):
        v = {"type": "LDAP注入(OR注入-admin)", "evidence": "result code 32, LDAP search failed"}
        assert _technical_signal_present(v) is True
        assert _local_rule_verify(None, v) == "ldap_error_marker"

    def test_ldap_suspicious_diff_only_fp(self):
        """仅响应差分无 LDAP 错误特征：严格误报策略下不保留。"""
        v = {"type": "LDAP注入-疑似(*)(uid=*)", "evidence": "响应长度异常变化 23.5%，可能返回额外数据"}
        assert _technical_signal_present(v) is False
        assert _local_rule_verify(None, v) == ""

    def test_cmdi_cmd_exec_flag(self):
        v = {"type": "命令注入-CMD执行(id)", "evidence": "检测到命令输出: uid=0(root)", "cmd_exec": True}
        assert _technical_signal_present(v) is True
        assert _local_rule_verify(None, v) == "engine_hard_flag"

    def test_cmdi_time_verified_flag(self):
        v = {"type": "命令注入-时间盲注(ping -c 10 127.0.0.1)", "time_verified": True,
             "evidence": "延时 payload 两次平均 5.2s，sleep 0 对照 0.3s，差异显著（A/B 复核通过）"}
        assert _technical_signal_present(v) is True
        assert _local_rule_verify(None, v) == "engine_hard_flag"

    def test_cmdi_time_evidence_no_flag(self):
        """即使标志缺失，时间盲注 A/B 复核证据文本本身也应命中。"""
        v = {"type": "命令注入-时间盲注(ping)", "evidence": "sleep 0 对照 0.2s，A/B 复核通过"}
        assert _technical_signal_present(v) is True
        assert _local_rule_verify(None, v) == "cmdi_output_marker"

    def test_cmdi_suspicious_diff_only_fp(self):
        v = {"type": "命令注入-疑似(ping)", "evidence": "响应长度异常变化 30.0%"}
        assert _technical_signal_present(v) is False
        assert _local_rule_verify(None, v) == ""

    def test_deser_confirmed_flag(self):
        v = {"type": "反序列化注入-Java Jackson @type 反序列化", "deser_confirmed": True,
             "evidence": "注入 Java Jackson @type 反序列化 后出现 java 反序列化错误回显；经无害 gadget 盲验证（DNS 回调命中(DNSlog/URLDNS)）实锤反序列化可执行"}
        assert _technical_signal_present(v) is True
        assert _local_rule_verify(None, v) == "engine_hard_flag"

    def test_deser_error_echo_no_flag(self):
        v = {"type": "反序列化注入-Python pickle 反序列化", "evidence": "参数 x 注入 Python pickle 反序列化 后出现 python 反序列化错误回显"}
        assert _technical_signal_present(v) is True
        assert _local_rule_verify(None, v) == "deser_error_marker"

    def test_deser_sql_branch_not_triggered(self):
        """deser 证据不含 SQL 关键词时不得被通用'注入'分支误放行之外丢弃。"""
        v = {"type": "反序列化注入-Phi", "evidence": "参数 x 注入 后出现 反序列化错误回显（无 SQL 痕迹）"}
        assert "注入" in v["type"]
        assert _technical_signal_present(v) is True

    def test_nosql_error_echo(self):
        """NoSQL(MongoDB) 报错回显应命中 nosql 分支（'NoSQL' 含 'sql' 子串，不得落回 SQL 分支失配）。"""
        v = {"type": "NoSQL注入", "evidence": "Invalid BSON field name 'x' in collection 'users' — MongoDB server error"}
        assert _technical_signal_present(v) is True
        assert _local_rule_verify(None, v) == "nosql_error_marker"

    def test_nosql_types_without_sql_evidence(self):
        """NoSQL 类型 + 通用异常回显（非 SQL 关键词）也应保留。"""
        v = {"type": "NoSQL注入-疑似", "evidence": "Operation failed: exception parsing query"}
        assert _technical_signal_present(v) is True

    def test_sql_type_still_sql_keywords(self):
        """SQL 类型仍走 SQL 关键词判定（回归）。"""
        v = {"type": "SQL注入-报错注入", "evidence": "You have an error in your SQL syntax near '1'"}
        assert _technical_signal_present(v) is True
        assert _local_rule_verify(None, v) == "sql_error_marker"

    def test_negatives(self):
        assert _technical_signal_present({"type": "LDAP注入-疑似(*)",
                                          "evidence": "响应长度异常变化 10.0%"}) is False
        assert _technical_signal_present({"type": "命令注入-疑似(*)",
                                          "evidence": "响应长度异常变化 5.0%"}) is False
        assert _technical_signal_present({"type": "信息泄露", "evidence": "xxx"}) is False
        assert _local_rule_verify(None, {"type": "信息泄露", "evidence": "xxx"}) == ""