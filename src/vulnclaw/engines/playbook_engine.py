# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""B3 L3 剧本生成器（PlaybookEngine）。

LLM 功能语义标注：从网站首页/robots/JS 端点文本提取业务功能清单
（口令重置/充值/优惠券/支付等），结合领域模板把功能映射为
「动作序列 + 期望状态」的结构化剧本，交 B2 差分不变量引擎逐动作差分
（绑定 / 金额守恒 / 一次性 / 状态机四类不变量，机器可裁决）。

执行链路：annotate(≤1 次 cheap LLM，失败静默降级本地 hint) → 生成剧本
→ 逐动作差分（复用 InvariantDiffEngine 检查器，注入 LLM/模板标注的参数名，
覆盖 B2 仅靠 URL hint 抓不到的端点）。

Safety（红线，与 B2 一致）：
- 只读 GET 探测，不重复提交真实业务副作用
- 所有异常 fail-closed 返回 None / 空表，绝不阻断主扫描
- 产出一律 ai_verdict="待验证"，走 verify/AI 复核与终稿收敛门，防误报
- 每目标最多 1 次 cheap 档 LLM 标注调用，成本护栏
"""
from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from vulnclaw.core.logger import logger
from vulnclaw.engines.invariant_diff_engine import InvariantDiffEngine

# ---------------------------------------------------------------- 语义资源
# 功能语义 → 四类机器可裁决不变量（中英 hint 与 B2 kind_map 同源）
_INVARIANT_TEMPLATES: dict[str, dict] = {
    "binding": {
        "expect": "仅凭据属主可完成该操作，篡改身份参数不得成功",
        "params": [("ident", "u_<rnd>"), ("token", "t_<rnd>")],
        "severity": "High",
    },
    "amount": {
        "expect": "金额类动作必须拒绝非正值，资金守恒不得被破坏",
        "params": [("amount", "1")],
        "severity": "High",
    },
    "once": {
        "expect": "一次性权益/兑换码不得重复领取",
        "params": [("code", "c_<rnd>")],
        "severity": "Medium",
    },
    "state": {
        "expect": "状态机前置步骤不可跳过，未完成前置不得直达终态",
        "params": [],
        "severity": "Medium",
    },
}

# 领域模板：领域 → 典型功能语义（LLM 降级、待选领域枚举与剧本元信息使用）
# 约定：每个领域尽量同时覆盖四类不变量（口令重置/激活=binding、金额=amount、
# 兑换码/券/权益=once、状态流转=state），确保 LLM 命中任一候选项都有差分剧本可落。
DOMAIN_TEMPLATES: dict[str, dict[str, list[str]]] = {
    "电商/交易": {"features": ["口令重置", "余额充值", "转账/提现", "优惠券领取", "支付/订单结账", "退款申请"]},
    "金融/支付": {"features": ["口令重置", "充值", "提现", "转账", "支付结算", "借贷/还款"]},
    "社交/内容": {"features": ["口令重置", "会员领取", "积分兑换", "内容打赏", "关注/拉黑"]},
    "SaaS/后台": {"features": ["口令重置", "账号激活", "订阅/套餐", "发票/结算", "试用领取", "权限/角色"]},
    "教育/工具": {"features": ["口令重置", "账号激活", "课程兑换", "积分/代金券", "报名/考试"]},
    "招聘/人力": {"features": ["口令重置", "账号激活", "简历投递", "职位/会员订阅", "积分/推荐奖励"]},
    "医疗/健康": {"features": ["口令重置", "挂号预约", "费用结算", "保险/就诊核验", "处方/报告状态"]},
    "出行/物流": {"features": ["口令重置", "余额充值", "订单支付", "优惠券领取", "行程/运单状态变更", "退款"]},
    "旅游/酒旅": {"features": ["口令重置", "预订支付", "优惠券/兑换码", "退款", "订单/入住状态"]},
    "游戏/娱乐": {"features": ["口令重置", "游戏充值", "道具/礼包兑换", "活动领奖", "账号/装备状态"]},
    "政务/民生": {"features": ["口令重置", "业务申请/审批", "费用缴纳", "进度查询", "证照/材料状态"]},
    "通用": {"features": ["口令重置", "金额操作", "优惠码/权益", "状态流转", "身份/账号绑定"]},
}


def _domain_names() -> str:
    """待选领域枚举（供 LLM 提示词使用，避免硬编码漂移）。"""
    return "、".join(DOMAIN_TEMPLATES)

# LLM 标注输出 JSON 的固定 schema
_ANNOTATE_SYSTEM = "只输出 JSON，不要解释。"
_ANNOTATE_FORMAT = (
    '\n\n只输出 JSON：{"features": [{"feature": "功能名", "domain": "领域名", '
    '"endpoints": ["/reset", "/charge"], "actions": ["动作1", "动作2"]}]}'
    "\n要求：endpoints 只列给出的候选中的路径，可以一个功能对应多个端点；"
    "无法对应任何端点则该 feature 不输出；没有功能则输出空 features；必须严格 JSON 合法。"
)


# ---------------------------------------------------------------- 剧本模型
@dataclass
class PlaybookAction:
    """剧本中的单步骤动作。"""

    seq: int                         # 动作顺序
    verb: str                        # 动作语义（reset/charge/coupon/pay...）
    url: str                         # 触发该动作的绝对 URL（不含注入参数）
    params: dict[str, str] = field(default_factory=dict)   # 动作关键参数（注入用于差分）
    invariant: str = ""              # 绑定的不变量检查器：binding/amount/once/state
    expect_ok: bool = True           # 期望该动作在合法情形下成功


@dataclass
class Playbook:
    """结构化剧本：LLM 标注功能 × 领域模板 → 动作序列 + 期望状态。"""

    id: str
    title: str
    domain: str
    feature: str
    invariant: str
    expected_state: str
    actions: list[PlaybookAction] = field(default_factory=list)
    source: str = ""                 # llm / local（标注来源，可审计）
    generated_at: str = ""

    @property
    def evidence_tag(self) -> str:
        return f"feature={self.feature} domain={self.domain} invariant={self.invariant}"

    def describe(self) -> str:
        acts = " → ".join(
            f"{a.verb}@{a.url.split('?')[0] if a.url else ''}" for a in self.actions
        )
        return f"[{self.id}] {self.title}：{acts}（期望：{self.expected_state}）"


# ---------------------------------------------------------------- 小工具
def _abs_url(target: str, u: str) -> str | None:
    """相对/绝对端点规范化。畸形 scheme（data:/htttps:// 等）一律跳过。"""
    s = str(u or "").strip()
    if not s or s.startswith(("#", "javascript:", "data:")):
        return None
    if s.startswith(("http://", "https://")):
        return s.split("#")[0]
    if s.startswith("/"):
        base = str(target or "").strip()
        if not base.startswith(("http://", "https://")):
            return None
        return urljoin(base if base.endswith("/") else base + "/", s.lstrip("/")).split("#")[0]
    return None


def _map_llm_to_real(llm_eps: list[str], real_eps: list[str]) -> list[str]:
    """LLM 输出路径 → 反向映射回真实候选端点。

    LLM 常把完整 URL 简写为路径（如 `http://h/logic/vuln/reset` → `/vuln/reset`），
    直接拿来拼 URL 会失真（丢前缀 → 404）。这里做后缀/包含匹配，命中真实端点；
    映射失败（找不到）的端点直接丢弃，宁可少不可错。
    """
    real_paths = []
    for u in real_eps:
        p = urlparse(str(u)).path.rstrip("/")
        if p:
            real_paths.append((p, str(u)))
    out: list[str] = []
    for le in llm_eps:
        lep = urlparse(str(le or "").split("?")[0]).path.rstrip("/")
        if not lep:
            continue
        cands = [u for p, u in real_paths if p.endswith(lep) or lep.endswith(p)]
        if not cands:
            continue
        cands.sort(key=lambda u: (len(urlparse(u).path), u))  # 最短（最具体）路径优先
        out.append(cands[0])
    seen, res = set(), []
    for u in out:
        if u not in seen:
            seen.add(u)
            res.append(u)
    return res


def _with_params(url: str, params: dict[str, str]) -> str:
    """将参数注入 URL query（追加，不覆盖已有键）。"""
    if not url or not params:
        return url
    parsed = urlparse(url)
    qs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    existing = {k for k, _ in qs}
    qs.extend((k, v) for k, v in params.items() if k not in existing)
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _collect_seed_endpoints(brief: dict | None, target: str) -> list[str]:
    """合并 brief 多源端点（crawled + js + apis + 根），去重保序。"""
    seen, out = set(), []
    sources = []
    if brief:
        sources += [u for u in (brief.get("crawled_endpoints") or []) if isinstance(u, str)]
        sources += [u for u in (brief.get("js_endpoints") or []) if isinstance(u, str)]
        sources += [u for u in (brief.get("apis") or []) if isinstance(u, str)]
    if target and str(target).startswith(("http://", "https://")):
        sources.append(str(target))
    for raw in sources:
        u = _abs_url(target, raw)
        if not u:
            continue
        key = u.split("?")[0]
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out


async def _grab_resource_texts_async(
    target: str, timeout: int = 8, client=None
) -> dict[str, str]:
    """抓取首页与 robots.txt 明文摘要（异步版本，失败静默）。"""
    import aiohttp

    out: dict[str, str] = {}

    async def _one(path: str) -> str | None:
        url = urljoin(target if target.endswith("/") else target + "/", path.lstrip("/"))
        try:
            if client is not None:
                async with client.get(url) as r:
                    return (await r.text(errors="replace"))[:4000] or ""
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout), raise_for_status=False
            ) as s, s.get(url) as r:
                return (await r.text(errors="replace"))[:4000] or ""
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[PLAYBOOK] grab {url} failed: {exc}")
            return None

    try:
        home, robots = await asyncio.gather(_one(""), _one("robots.txt"))
        out["home"] = home or ""
        out["robots"] = robots or ""
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[PLAYBOOK] resource grab failed: {exc}")
    return out


# ---------------------------------------------------------------- LLM 标注
async def _annotate_features_llm(
    target: str, endpoints: list[str], texts: dict[str, str]
) -> list[dict]:
    """LLM 功能语义标注（1 次 cheap 档调用）。任何失败返回空表（降级本地）。"""
    try:
        from vulnclaw.ai.core import get_llm_client

        client = get_llm_client()
        if client is None:
            return []
        home = str(texts.get("home", "") or "")
        robots = str(texts.get("robots", "") or "")
        # 文本去 HTML 标签与压缩（控制 token 成本）
        clean = re.sub(r"<[^>]+>", " ", home)[:1500]
        clean = " ".join(clean.split())[:1200]
        ep_lines = "\n".join(f"- {u}" for u in endpoints[:120]) or "(无)"
        prompt = (
            "你是网站功能语义分析器。下面是一个网站目标的首页文字摘要、robots.txt 与候选端点。"
            "请识别其业务功能清单（例如：注册/登录/口令重置/余额充值/转账/提现/优惠券/兑换/支付/订单状态变更），"
            "并给出每个功能涉及的候选端点路径（只从候选中挑，可以多个端点对应一个功能；"
            "也可以一个端点对应多个功能的不变量检查角度）。\n\n"
            f"【首页摘要】\n{clean or '(抓取失败)'}\n\n"
            f"【robots.txt】\n{str(robots)[:600] or '(空)'}\n\n"
            f"【候选端点】\n{ep_lines}\n\n"
            "要求：feature 用中文功能名；domain 只能用下属领域之一（"
            + _domain_names()
            + "）。"
            + _ANNOTATE_FORMAT
        )
        raw = await client.ask(
            prompt,
            system=_ANNOTATE_SYSTEM,
            temperature=0.0,
            max_tokens=1200,
            task_type="filter",   # 便宜快档（cost_router filter 语义）
            usage_site="playbook:annotate",
        )
        from vulnclaw.modules.vuln_scanner import safe_extract_json

        data = safe_extract_json(raw)
        if isinstance(data, dict):
            data = data.get("features") or []
        out: list[dict] = []
        for item in data or []:
            if not isinstance(item, dict) or not item.get("feature"):
                continue
            eps = [e for e in (item.get("endpoints") or []) if isinstance(e, str)]
            out.append({
                "feature": str(item.get("feature"))[:40],
                "domain": str(item.get("domain") or "通用")[:20] or "通用",
                "endpoints": eps,
            })
        return out
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[PLAYBOOK] LLM 语义标注不可用（降级本地）: {exc}")
        return []


def _kind_label(kind: str) -> str:
    return {
        "binding": "口令重置/账号激活（绑定校验）",
        "amount": "余额/金额操作（守恒校验）",
        "once": "优惠券/兑换码（一次性校验）",
        "state": "订单支付/状态流转（状态机校验）",
    }.get(kind, kind)


_SHORT_LABELS = {
    "binding": "绑定校验",
    "amount": "金额守恒",
    "once": "一次性校验",
    "state": "状态机校验",
}


def _annotate_features_local(endpoints: list[str]) -> list[dict]:
    """本地 hint 降级标注：按 kind_map 命中分桶为功能（无 LLM 成本）。"""
    from vulnclaw.engines.invariant_diff_engine import ACTION_HINTS as _AH

    buckets: dict[str, list[str]] = {}
    for u in endpoints:
        p = u.split("?")[0]
        if not _AH.search(p):
            continue
        for kind, pat in InvariantDiffEngine.kind_map.items():
            if pat.search(p):
                buckets.setdefault(kind, []).append(u)
                break
    return [
        {"feature": _kind_label(k) + "（本地识别）", "domain": "通用", "endpoints": eps}
        for k, eps in buckets.items() if eps
    ]


def _infer_action_verbs(kind: str, feature: str = "") -> list[str]:
    """按不变量类别给出典型动作序列（供剧本结构展示；差分的主角是不变量检查器）。"""
    base = {
        "binding": ["提交账号获取凭据", "携带凭据+身份执行关键操作"],
        "amount": ["设置金额发起操作"],
        "once": ["提交一次性码"],
        "state": ["携带完成标记直接调用终态接口"],
    }.get(kind, ["触发业务动作"])
    if feature and kind == "binding":
        return ["提交账号获取重置凭据", "携带凭据+目标用户执行重置"]
    return base


# ---------------------------------------------------------------- 剧本引擎
class PlaybookEngine:
    """B3 剧本生成器：LLM 功能语义标注 → 结构化剧本 → 逐动作差分验证。"""

    name = "playbook_gen"
    description = "B3 LLM 功能语义标注 + 差分剧本生成器（链接不变量引擎）"

    def __init__(self, timeout: int = 10):
        self._timeout = timeout
        self._inv = InvariantDiffEngine(timeout=timeout)

    # ---- 生成 ----------------------------------------------------------
    async def generate_playbooks(
        self, brief: dict | None, target: str = "", session=None
    ) -> list[Playbook]:
        """生成结构化剧本列表。任何异常返回空表（fail-closed）。"""
        try:
            target = str(target or (brief or {}).get("target") or "")
            if not str(target).startswith(("http://", "https://")):
                return []
            endpoints = _collect_seed_endpoints(brief, target)
            if not endpoints:
                logger.info("ℹ️ [PLAYBOOK] 无候选端点，跳过剧本生成")
                return []

            texts = await _grab_resource_texts_async(target, timeout=8, client=session)
            features = await _annotate_features_llm(target, endpoints, texts)
            source = "llm"
            if not features:
                features = _annotate_features_local(endpoints)
                source = "local"
            if not features:
                logger.info("ℹ️ [PLAYBOOK] 未识别业务功能语义端点，跳过")
                return []

            # LLM 端点是简写路径，反向映射回真实候选端点（失真/找不到的直接丢弃）
            if source == "llm":
                for ft in features:
                    ft["endpoints"] = _map_llm_to_real(ft["endpoints"], endpoints)

            books: list[Playbook] = []
            for ft in features:
                books.extend(self._feature_to_playbooks(ft, target, source))
            logger.info(
                f"🎭 [PLAYBOOK] {source} 标注：{len(features)} 功能 → {len(books)} 剧本"
            )
            return books
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[PLAYBOOK] 剧本生成失败（跳过）: {exc}")
            return []

    def _feature_to_playbooks(
        self, feature: dict, target: str, source: str
    ) -> list[Playbook]:
        """一个功能 → 按命中不变量生成剧本（每个端点归属首个命中不变量）。"""
        feats = str(feature.get("feature") or "")
        domain = str(feature.get("domain") or "通用")
        eps = feature.get("endpoints") or []
        out: list[Playbook] = []
        for u in eps:
            p = u.split("?")[0]
            for kind, tmpl in _INVARIANT_TEMPLATES.items():
                pat = InvariantDiffEngine.kind_map.get(kind)
                if not pat or not pat.search(p):
                    continue
                action_seqs = _infer_action_verbs(kind, feats)
                rnd = uuid.uuid4().hex[:8]
                params = {
                    name: tpl.replace("<rnd>", rnd)
                    for name, tpl in tmpl["params"]
                }
                actions = [
                    PlaybookAction(
                        seq=i + 1,
                        verb=verb,
                        url=u,
                        params=dict(params),
                        invariant=kind,
                        expect_ok=True,
                    )
                    for i, verb in enumerate(action_seqs)
                ]
                out.append(Playbook(
                    id=f"pb-{uuid.uuid4().hex[:8]}",
                    title=(
                        f"{feats or _kind_label(kind)}（"
                        f"{_SHORT_LABELS.get(kind, _kind_label(kind))}差分剧本）"
                    ),
                    domain=domain,
                    feature=feats or _kind_label(kind),
                    invariant=kind,
                    expected_state=tmpl["expect"],
                    actions=actions,
                    source=source,
                    generated_at="",  # 由调用方给时间
                ))
                break  # 每个端点归属其第一个命中不变量（避免剧本爆炸）
        return out

    # ---- 执行 ----------------------------------------------------------
    async def execute(self, book: Playbook, budget_s: float = 120) -> dict | None:
        """逐动作差分执行剧本；violation 聚合为 finding，任何失败 fail-closed None。"""
        checks = {
            "binding": self._inv._binding_check,
            "amount": self._inv._amount_check,
            "once": self._inv._once_check,
            "state": self._inv._state_skip_check,
        }
        fn = checks.get(book.invariant)
        if fn is None or not book.actions:
            return None
        try:
            start = asyncio.get_event_loop().time()
            results: list[dict] = []
            for act in book.actions:
                if asyncio.get_event_loop().time() - start > budget_s:
                    logger.debug(f"[PLAYBOOK] 执行预算耗尽，截断剧本 {book.id}")
                    break
                url = _with_params(act.url, act.params)
                try:
                    r = await fn(url)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    logger.debug(f"[PLAYBOOK] {book.invariant} 差分失败: {exc}")
                    continue
                if r:
                    r["url"] = url
                    results.append(r)
            if not results:
                return None
            return self._build_finding(book, results)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[PLAYBOOK] 剧本 {book.id} 执行异常（跳过）: {exc}")
            return None

    def _build_finding(self, book: Playbook, results: list[dict]) -> dict:
        _sev = {"High": 3, "Medium": 2, "Low": 1}
        top = max(results, key=lambda r: _sev.get(r.get("severity", "Low"), 1))
        kinds = ",".join(r.get("kind", book.invariant) for r in results)
        marker = top.get("marker", book.invariant)
        desc = "；".join(r.get("evidence", "") for r in results)
        actions = " → ".join(
            f"步骤{a.seq}[{a.verb}] {a.url.split('?')[0] if a.url else a.url}"
            for a in book.actions
        )
        ctx = (
            f"剧本 {book.id}（来源={book.source}，功能「{book.feature}」，领域「{book.domain}」，"
            f"不变量=「{book.invariant}」）期望：{book.expected_state}。动作序列：{actions}。"
        )
        trace = [
            {"family": "playbook", "kind": r.get("kind", book.invariant),
             "marker": r.get("marker", "")} for r in results
        ]
        return {
            "url": results[0].get("url", ""),
            "type": "业务逻辑不变量违反（剧本差分证实）",
            "severity": top.get("severity", "Medium"),
            "title": f"剧本验证失败：{book.feature}（{_kind_label(book.invariant)}，{marker}）",
            "description": ctx + desc,
            "evidence": desc,
            "evidence_chain": ctx,
            "evidence_trace": trace,
            "ai_verdict": "待验证",
            "confidence": "medium",
            "method": "playbook_engine",
            "playbook": {
                "id": book.id,
                "title": book.title,
                "domain": book.domain,
                "feature": book.feature,
                "invariant": book.invariant,
                "expected_state": book.expected_state,
                "source": book.source,
                "n_actions": len(book.actions),
                "n_violations": len(results),
            },
            "cvss": self._cvss(top.get("severity", "Medium"), kinds),
            "remediation": "服务端对关键业务动作强制校验不变量（凭据属主绑定/金额非负/幂等键/状态机前置条件）",
            "recommendation": "按资源属主与流程前置条件做强校验；关键动作加幂等键；资金类动作拒绝非正值",
        }

    @staticmethod
    def _cvss(severity: str, kinds: str) -> str:
        if severity == "High":
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"


__all__ = [
    "DOMAIN_TEMPLATES",
    "Playbook",
    "PlaybookAction",
    "PlaybookEngine",
    "_annotate_features_llm",
    "_annotate_features_local",
    "_collect_seed_endpoints",
    "_infer_action_verbs",
    "_with_params",
]