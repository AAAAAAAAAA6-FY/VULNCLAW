"""领域模板补充性测试：完备性 + 提示词枚举同步（2026-09-11 扩充 6 -> 12 领域）。"""
from vulnclaw.engines.playbook_engine import DOMAIN_TEMPLATES, _domain_names

# 四类不变量语义关键字（feature 名命中任一即视为覆盖该类别）
_K = {
    "binding": ("口令重置", "账号激活", "绑定", "密码"),
    "amount": ("金额", "充值", "提现", "转账", "支付", "结算", "缴费", "还款", "借贷", "退款", "订阅", "套餐"),
    "once": ("券", "码", "兑换", "积分", "礼包", "权益", "领取", "领奖"),
    "state": ("状态", "流转", "进度", "审批", "订单", "行程", "运单", "入住", "装备", "证照", "材料"),
}

MIN_DOMAINS = 10


def test_template_count_and_shape():
    assert len(DOMAIN_TEMPLATES) >= MIN_DOMAINS, f"{len(DOMAIN_TEMPLATES)} 领域 < {MIN_DOMAINS}"
    for domain, meta in DOMAIN_TEMPLATES.items():
        feats = meta.get("features") or []
        assert feats, f"{domain} 无 features"
        assert len(feats) >= 4, f"{domain} features 过少: {feats}"
        assert all(isinstance(f, str) and f for f in feats)


def test_each_domain_covers_multiple_invariants():
    """每个领域应至少覆盖 2 类不变量（保证任一候选端点都能落差分剧本）。"""
    for domain, meta in DOMAIN_TEMPLATES.items():
        feats = meta.get("features") or []
        covered = set()
        for f in feats:
            for kind, words in _K.items():
                if any(w in f for w in words):
                    covered.add(kind)
        assert len(covered) >= 2, f"{domain} 只覆盖 {covered}（features={feats}）"


def test_domain_names_sync():
    names = _domain_names()
    for d in DOMAIN_TEMPLATES:
        assert d in names
    # LLM 提示词硬编码枚举已废除，枚举以模板为准（无重复、保序）
    assert len(DOMAIN_TEMPLATES) == len(names.split("\u3001"))


def test_common_domains_present():
    for d in ("\u7535\u5546/\u4ea4\u6613", "SaaS/\u540e\u53f0", "\u91d1\u878d/\u652f\u4ed8",
              "\u6e38\u620f/\u5a31\u4e50", "\u653f\u52a1/\u6c11\u751f", "\u901a\u7528"):
        assert d in DOMAIN_TEMPLATES
