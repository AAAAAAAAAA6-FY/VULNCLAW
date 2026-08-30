"""单元测试：_is_internal_domain 内网/回环/伪TLD 分类器。"""
from vulnclaw.modules.recon import _is_internal_domain


class TestLoopbackAndPrivate:
    def test_loopback_v4(self):
        assert _is_internal_domain("127.0.0.1") is True

    def test_loopback_range(self):
        assert _is_internal_domain("127.255.255.254") is True

    def test_private_10(self):
        assert _is_internal_domain("10.0.0.5") is True

    def test_private_172(self):
        assert _is_internal_domain("172.16.1.1") is True

    def test_private_192(self):
        assert _is_internal_domain("192.168.1.100") is True

    def test_link_local(self):
        assert _is_internal_domain("169.254.169.254") is True

    def test_loopback_v6(self):
        assert _is_internal_domain("::1") is True


class TestPseudoTld:
    def test_local(self):
        assert _is_internal_domain("myhost.local") is True

    def test_internal(self):
        assert _is_internal_domain("app.internal") is True

    def test_corp(self):
        assert _is_internal_domain("git.corp") is True

    def test_lan(self):
        assert _is_internal_domain("nas.lan") is True


class TestPublicDomains:
    def test_public_domain(self):
        assert _is_internal_domain("baidu.com") is False

    def test_public_subdomain(self):
        assert _is_internal_domain("api.stripe.com") is False

    def test_multi_tld(self):
        assert _is_internal_domain("sub.example.co.uk") is False

    def test_public_ip(self):
        assert _is_internal_domain("8.8.8.8") is False

    def test_public_ip2(self):
        assert _is_internal_domain("1.1.1.1") is False


class TestEdgeCases:
    def test_empty(self):
        assert _is_internal_domain("") is True

    def test_none_like(self):
        assert _is_internal_domain(None) is True

    def test_bare_hostname(self):
        # 无点主机名视为内网
        assert _is_internal_domain("localhost") is True

    def test_whitespace(self):
        assert _is_internal_domain("  127.0.0.1  ") is True

    def test_uppercase(self):
        assert _is_internal_domain("MYAPP.LOCAL") is True

    def test_trailing_dot_ip(self):
        assert _is_internal_domain("127.0.0.1.") is True
