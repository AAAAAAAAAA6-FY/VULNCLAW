# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

# core/knowledge.py
"""A3.3 通用漏洞模式库：按指纹（框架+版本）映射已知弱点速查，减少 LLM 重复推导。

模式库以 YAML 维护在 core/data/knowledge/，可被引擎/验证 prompt 引用，
让 Agent 针对识别到的技术栈直接获得「已知弱点清单」而非每次重新推理。
"""
import os
from typing import Dict, List

import yaml

from vulnclaw.core.logger import logger

_KNOWLEDGE_DIR = os.path.join(os.path.dirname(__file__), "data", "knowledge")


def load_vuln_knowledge() -> Dict:
    """加载所有漏洞模式库 YAML，合并为 {框架: {weaknesses: [...]}} 字典。"""
    data: Dict = {}
    try:
        if not os.path.isdir(_KNOWLEDGE_DIR):
            return data
        for fname in sorted(os.listdir(_KNOWLEDGE_DIR)):
            if not fname.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(_KNOWLEDGE_DIR, fname)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    parsed = yaml.safe_load(fh) or {}
                if isinstance(parsed, dict):
                    data.update(parsed)
            except (OSError, yaml.YAMLError) as exc:
                logger.warning(f"⚠️ 加载漏洞模式库 {fname} 失败: {exc}")
    except OSError as exc:
        logger.warning(f"⚠️ 读取漏洞模式库目录失败: {exc}")
    return data


def format_knowledge_for_prompt(tech_stack: List[str]) -> str:
    """返回与给定技术栈匹配的已知弱点速查文本（供 prompt 注入）。无匹配返回空串。"""
    kb = load_vuln_knowledge()
    if not tech_stack:
        return ""
    stack_lower = [s.lower() for s in tech_stack]
    hits: List[str] = []
    for framework, info in kb.items():
        if not any(framework.lower() in s or s in framework.lower() for s in stack_lower):
            continue
        if isinstance(info, dict):
            weaknesses = info.get("weaknesses", []) or []
            detail = "; ".join(str(w) for w in weaknesses) if weaknesses else ""
            hits.append(f"- {framework}: {detail}" if detail else f"- {framework}")
        else:
            hits.append(f"- {framework}")
    return "\n".join(hits)


# ==================================================================
# P6-1: Skills 知识包（程序性知识，对标 strix skills）
# ==================================================================
# 与 A3.3 模式库互补：模式库回答「这个框架有什么已知弱点」（静态事实清单），
# skills 回答「这类目标该怎么打」（可执行测试套路）。按上下文触发注入 Agent
# prompt，并给出推荐引擎，作为 Tier-1 确定性引擎广覆盖的靶向指引。
# 每个 skill：id -> {name, category, triggers{tech,param,vuln,role}, tools, body}
SKILLS: Dict[str, Dict] = {
    "sqli_error_based": {
        "name": "报错型 SQL 注入",
        "category": "injection",
        "triggers": {"param": ["id", "uid", "user_id", "pid", "cat", "article", "no", "order"],
                     "vuln": ["sql", "sqli", "注入", "database"],
                     "role": ["analysis", "exploit", "verify"]},
        "tools": ["sqli"],
        "body": ("1) 探测：单/双引号、反斜杠观察报错或响应差异；2) 定列数 ORDER BY n 二分；"
                 "3) 回显位 UNION SELECT null,null…；4) 报错函数 extractvalue/updatexml/"
                 "floor(rand(0)*2)（MySQL）、CAST((SELECT..) AS int)（MSSQL）、utl_inaddr（Oracle）；"
                 "5) 指纹 version()/@@version。禁 UPDATE/DELETE/DROP 等破坏性语句。"),
        # SP6: payload 桥种子——exploit_chain 可直接引用（三腿沉淀·静态定义腿）
        "payloads": ["' OR 1=1 -- -", "' AND 1=1 -- -", "\" OR 1=1 -- -",
                     "1' AND '1'='1", "1' UNION SELECT NULL,2,3 -- -"],
    },
    "blind_sqli_oob": {
        "name": "无回显 SQL 注入（盲注/OOB）",
        "category": "injection",
        "triggers": {"param": ["id", "uid", "search", "q", "sort", "filter"],
                     "vuln": ["sql", "sqli", "blind", "盲注", "注入"],
                     "role": ["analysis", "exploit"]},
        "tools": ["sqli"],
        "body": ("页面无报错/无回显时：1) 布尔盲注（真/假条件对比响应长度与内容差异）；"
                 "2) 时间盲注 sleep()/benchmark()/WAITFOR DELAY，注意与网络抖动区分，需多次取基线；"
                 "3) 有 oob_confirm 时优先带外（DNS/HTTP 外带），回调=实锤，比时间盲注可靠。"),
    },
    "ssti_rce": {
        "name": "模板注入 SSTI",
        "category": "injection",
        "triggers": {"param": ["name", "tpl", "template", "view", "render", "msg", "content"],
                     "vuln": ["ssti", "template", "模板"],
                     "tech": ["python", "flask", "django", "jinja", "java", "freemarker", "velocity", "php", "twig"],
                     "role": ["analysis", "exploit"]},
        "tools": ["ssti", "el_injection"],
        "body": ("1) 探测 {{7*7}} / ${7*7} / <%= 7*7 %> 看是否回显 49；2) 判引擎：Jinja2/Twig/"
                 "Freemarker/Velocity/Smarty 语法差异定类型；3) 升 RCE：Jinja2 走 subclasses 链、"
                 "Freemarker 走 Execute/New、Velocity 走 Runtime.exec；4) 只验证命令执行输出，不落马不改写文件。"),
    },
    "lfi_file_read": {
        "name": "本地文件包含读取 LFI",
        "category": "info_disclosure",
        "triggers": {"param": ["file", "page", "path", "dir", "doc", "template", "load", "include"],
                     "vuln": ["lfi", "file read", "文件包含", "path traversal", "读取"],
                     "role": ["exploit", "verify"]},
        "tools": ["lfi"],
        "body": ("1) 经典穿越 ../../../../etc/passwd 逐级加 ../；2) 过滤绕过：....// 递归替换、"
                 "URL 编码 %2e%2e/、二次编码 %252e；3) PHP 封装协议 php://filter/convert.base64-encode"
                 "/resource= 读源码；4) 命中特征 root:0:0 或 window 配置键即证据；5) 只读不写。"),
        "payloads": ["../../../../etc/passwd", "....//....//....//....//etc/passwd",
                     "..%2f..%2f..%2f..%2fetc/passwd",
                     "php://filter/convert.base64-encode/resource=/etc/passwd"],
    },
    "jwt_attacks": {
        "name": "JWT 攻击面",
        "category": "auth",
        "triggers": {"param": ["token", "jwt", "access_token", "id_token"],
                     "vuln": ["jwt", "token", "auth"],
                     "tech": ["jwt", "oauth", "keycloak", "auth0"],
                     "role": ["analysis", "exploit", "verify"]},
        "tools": ["jwt"],
        "body": ("1) alg=none 绕过签名；2) RS256→HS256 混淆（用公钥当 HMAC 密钥）；3) kid 注入"
                 "（指向可控路径/命令）；4) 弱密钥爆破（secret/123456）；5) jku/x5u 指向攻击者 JWKS；"
                 "6) 过期/未校验 exp、nbf。验证必须对比「改前后响应差异」，避免把通用 401 当成功。"),
    },
    "graphql_attack": {
        "name": "GraphQL 攻击面",
        "category": "api",
        "triggers": {"param": ["query", "variables", "operationName"],
                     "vuln": ["graphql", "api"],
                     "tech": ["graphql", "apollo", "hasura"],
                     "role": ["recon", "analysis"]},
        "tools": ["graphql"],
        "body": ("1) 内省 __schema{types{name,fields{name}}} 拿全量接口；2) 未授权：跳过 Authorization "
                 "直接查敏感字段；3) 别名/批处理绕过限流与计数（aliases 批量枚举）；4) mutation 越权；"
                 "5) 报错开启时从 debug 信息反推后端类型；6) 深度嵌套查询造成 DoS 需谨慎（不压测）。"),
    },
    "ssrf_bypass": {
        "name": "SSRF 与绕过",
        "category": "injection",
        "triggers": {"param": ["url", "uri", "callback", "next", "redirect", "fetch", "webhook", "target", "dest"],
                     "vuln": ["ssrf", "redirect", "跳转"],
                     "role": ["analysis", "exploit"]},
        "tools": ["ssrf", "open_redirect"],
        "body": ("1) 先确认回显型/无回显型；2) 内网探测 127.0.0.1/10.0.0.0/8 与云元数据 "
                 "169.254.169.254；3) 绕过：十进制/八进制/十六进制 IP、0.0.0.0、[::]、DNS rebinding、"
                 "URL 解析差异（@、#、\\）；4) 协议 file://、gopher://、dict://；5) 无回显用 oob_confirm 外带。"),
    },
    "idor_mass_assignment": {
        "name": "越权与批量赋值",
        "category": "authz",
        "triggers": {"param": ["id", "uid", "user", "role", "admin", "isadmin", "group", "order_id"],
                     "vuln": ["idor", "越权", "authz", "mass"],
                     "role": ["analysis", "verify"]},
        "tools": ["idor", "mass_assignment", "business_logic"],
        "body": ("1) 水平越权：替换 id 遍历他人资源（对比两账号响应）；2) 垂直越权：普通用户访问"
                 "管理员接口/字段；3) 批量赋值：注入 role/isAdmin/balance 等本不应由客户端提交的字段；"
                 "4) API 版本回退 /v2→/v1 权限校验更弱；5) 判据必须是有差异的实际数据返回，不是通用 404/403。"),
    },
    "file_upload_bypass": {
        "name": "文件上传绕过",
        "category": "file",
        "triggers": {"param": ["file", "upload", "avatar", "image"],
                     "vuln": ["upload", "上传", "file"],
                     "tech": ["iis", "nginx", "apache", "tomcat", "php", "asp"],
                     "role": ["analysis", "exploit"]},
        "tools": ["file_upload"],
        "body": ("1) 双重扩展名 shell.php.jpg；2) 大小写/末尾点空格（IIS）；3) Content-Type 与 magic bytes "
                 "伪造；4) 解析漏洞：IIS 分号、Nginx 空字节 %00、Apache 多扩展名；5) 配置文件 .user.ini/"
                 ".htaccess 改写解析；6) 只上传无害验证文件（不落 Webshell），验证「能否被解析执行」即可。"),
    },
    "waf_bypass": {
        "name": "WAF 绕过与载荷变异",
        "category": "evasion",
        "triggers": {"vuln": ["waf", "blocked", "拦截", "403", "forbidden"],
                     "param": ["id", "q", "search", "name", "url"],
                     "role": ["analysis", "exploit", "verify"]},
        "tools": ["sqli", "xss", "cmdi"],
        "body": ("被拦截时按序尝试：1) 大小写/关键字拆分；2) 内联注释 /!50000select/（MySQL）；"
                 "3) URL/双重/Unicode 编码；4) HTTP 参数污染（同参数重复）；5) 分块传输与超长参数；"
                 "6) 换等价函数/语法（substr↔mid、sleep↔benchmark）；7) 用 payload_mutator 自动变异。"),
    },
    "deserialization_rce": {
        "name": "反序列化 RCE",
        "category": "injection",
        "triggers": {"param": ["data", "payload", "obj", "ser", "viewstate", "rO0AB"],
                     "vuln": ["deserialization", "反序列化", "rce", "viewstate"],
                     "tech": ["java", "spring", "struts", "weblogic", "fastjson", "jackson", ".net", "asp"],
                     "role": ["analysis", "exploit"]},
        "tools": ["deserialization", "dotnet_deserialization"],
        "body": ("1) 识别序列化格式：Java rO0AB/base64、.NET ViewState（__VIEWSTATE）、PHP serialize、"
                 "Python pickle；2) 有回显用探测链触发报错/DNS 外带，无回显用 oob_confirm；"
                 "3) .NET 需 MachineKey 才能伪造 ViewState；4) 只做最小验证（外带回调），不落地执行恶意代码。"),
    },
    "race_condition": {
        "name": "条件竞争",
        "category": "logic",
        "triggers": {"param": ["amount", "count", "quantity", "coupon", "balance"],
                     "vuln": ["race", "竞争", "concurrency"],
                     "role": ["analysis", "verify"]},
        "tools": ["race_condition", "business_logic"],
        "body": ("1) 选有状态变更的接口（下单/提现/领券/点赞）；2) 同一请求并发 N 次（需同步发起，"
                 "非串行）；3) 判据：超额发放/余额异常/库存穿透，且结果可复现；4) 排除网络抖动导致的"
                 "假阳性，至少重复一轮；5) 不做压测，并发数以验证为限。"),
    },
    "authz_path_method": {
        "name": "路径/方法级绕过",
        "category": "authz",
        "triggers": {"param": ["path", "file", "dir", "page", "include", "template", "doc"],
                     "vuln": ["403", "401", "unauthorized", "path", "lfi", "traversal"],
                     "role": ["analysis", "verify"]},
        "tools": ["lfi", "idor", "business_logic"],
        "body": ("1) 路径归一化绕过：../、..%2f、....//、%252e%252e；2) 方法绕过：GET↔POST↔PUT↔HEAD、"
                 "X-HTTP-Method-Override；3) 头绕过：X-Original-URL/X-Rewrite-URL/X-Forwarded-For；"
                 "4) 分号截断与后缀追加（/admin;、/admin.json）；5) 判据是与原响应有实质差异，不是同一错误页。"),
    },
}


def _norm(value) -> str:
    return str(value or "").lower()


def list_skills() -> List[Dict]:
    """P6-1: 列出全部 skills 知识包（id/name/category/tools），供 MCP/调试使用。"""
    out: List[Dict] = []
    for sid, sk in SKILLS.items():
        out.append({"id": sid, "name": sk.get("name", sid),
                    "category": sk.get("category", ""), "tools": list(sk.get("tools", []) or [])})
    return sorted(out, key=lambda x: x["id"])


def select_skills(
    tech_stack: List[str] = None,
    params: List[str] = None,
    vuln_types: List[str] = None,
    role: str = "",
    top_n: int = 3,
) -> List[Dict]:
    """P6-1: 按上下文给 skills 知识包打分（技术栈/参数/已发现漏洞类型/角色），返回 top_n。

    权重：技术栈命中 3（最强信号）、参数名 2、漏洞类型 2、角色 1。零命中不返回。
    """
    tech_s = " ".join(_norm(t) for t in (tech_stack or []))
    param_s = " ".join(_norm(p) for p in (params or []))
    vuln_s = " ".join(_norm(v) for v in (vuln_types or []))
    role_s = _norm(role)
    scored = []
    for sid, sk in SKILLS.items():
        trig = sk.get("triggers", {}) or {}
        score = 0
        for kw in trig.get("tech", []) or []:
            if _norm(kw) and _norm(kw) in tech_s:
                score += 3
        for kw in trig.get("param", []) or []:
            if _norm(kw) and _norm(kw) in param_s:
                score += 2
        for kw in trig.get("vuln", []) or []:
            if _norm(kw) and _norm(kw) in vuln_s:
                score += 2
        for kw in trig.get("role", []) or []:
            if _norm(kw) == role_s:
                score += 1
        if score > 0:
            item = dict(sk)
            item["id"] = sid
            item["score"] = score
            scored.append((score, sid, item))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [item for _, _, item in scored[:max(1, int(top_n or 3))]]


def skill_tools_for(
    tech_stack: List[str] = None,
    params: List[str] = None,
    vuln_types: List[str] = None,
    role: str = "",
    top_n: int = 5,
) -> List[str]:
    """P6-1: 命中 skills 推荐的确定性引擎名（去重保序），供 AgentNode 做靶向补工具。"""
    tools: List[str] = []
    for sk in select_skills(tech_stack=tech_stack, params=params,
                            vuln_types=vuln_types, role=role, top_n=top_n):
        for t in sk.get("tools", []) or []:
            if t and t not in tools:
                tools.append(t)
    return tools


def format_skills_for_prompt(
    tech_stack: List[str] = None,
    params: List[str] = None,
    vuln_types: List[str] = None,
    role: str = "",
    top_n: int = 3,
    max_chars: int = 1200,
) -> str:
    """P6-1: 命中 skills 渲染为 prompt 片段（有上限，防 token 膨胀）。无命中返回空串。"""
    hits = select_skills(tech_stack=tech_stack, params=params,
                         vuln_types=vuln_types, role=role, top_n=top_n)
    if not hits:
        return ""
    lines: List[str] = []
    for sk in hits:
        lines.append(f"- 【{sk.get('name', '')}】({sk['id']}, score={sk['score']})")
        lines.append(f"  套路: {sk.get('body', '')}")
        if sk.get("tools"):
            lines.append(f"  推荐引擎: {', '.join(sk['tools'])}")
    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[:max_chars] + " …(已截断)"
    return text


__all__ = [
    "load_vuln_knowledge", "format_knowledge_for_prompt",
    "SKILLS", "list_skills", "select_skills", "skill_tools_for", "format_skills_for_prompt",
]


# ==================================================================
# SP6: skill payload × exploit_chain 三腿沉淀闭环
# ==================================================================
# 静态定义腿（SKILLS[].payloads）+ 生成腿沉降台账（技能化 AI 新漏洞/验证
# 成功 payload，写 _runtime_cache/metrics/skill_payloads.json 跨扫描持久）。
# exploit_chain 通过 skill_payloads() 引用，命中后 register_payload() 反向闭环。

_PAYLOAD_LEDGER = None


def _payload_ledger_path() -> str:
    """生成腿沉降台账路径（相对 CWD，测试可 monkeypatch）。"""
    global _PAYLOAD_LEDGER
    if _PAYLOAD_LEDGER is None:
        _PAYLOAD_LEDGER = os.path.join("_runtime_cache", "metrics", "skill_payloads.json")
    return _PAYLOAD_LEDGER


def skill_payloads(skill_id: str) -> List[str]:
    """三腿沉淀 payload 统一出口：技能静态定义 + 生成腿沉降台账（去重）。"""
    out: List[str] = []
    meta = SKILLS.get(skill_id)
    if meta:
        for pl in (meta.get("payloads") or []):
            if pl not in out:
                out.append(pl)
    try:
        import json
        path = _payload_ledger_path()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh) or {}
            for pl in (data.get(skill_id) or []):
                if pl not in out:
                    out.append(pl)
    except Exception:
        logger.debug("suppressed exception (core audit)")
    return out


def register_payload(skill_id: str, payload: str) -> bool:
    """生成腿技能化：验证成功 payload 沉降进台账（幂等；失败静默不影响利用链）。"""
    try:
        import json
        data = {}
        path = _payload_ledger_path()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh) or {}
        bucket = data.setdefault(skill_id, [])
        if payload in bucket:
            return False
        bucket.append(payload)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
        return True
    except Exception:
        logger.debug("suppressed exception (core audit)")
        return False


def reset_payload_ledger() -> None:
    """测试用：清空沉降台账。"""
    try:
        path = _payload_ledger_path()
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        logger.debug("suppressed exception (core audit)")
