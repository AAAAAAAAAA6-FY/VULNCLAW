# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/interop.py
"""工具生态互导：多源 finding 导入/导出 + 统一字段映射。

存在意义
--------
扫描器（VULNCLAW）与周边生态（Nuclei / Burp Suite / ZAP / SARIF 消费者 /
CSV 台账 / 原始 HTTP 报文）各自有独立的 finding 表示。本模块提供**单一统一
模型** ``UnifiedFinding`` 与一组**纯函数**导入器/导出器，使"别家产出的
finding"能进入 VULNCLAW 报告链路，"VULNCLAW 的 finding"能交给别家工具。

设计铁律
--------
1. **离线 + 确定性**：不联网、不调 AI、不读外部文件、不使用时间戳/UUID/随机数。
   同一输入必然产出同一输出（``export_*`` 可直接做字节级比对）。
2. **fail-closed**：解析失败或缺关键字段**跳过并计数**，绝不"编造"字段值。
   导入器返回 ``ImportResult``（``list`` 子类），带 ``skipped`` / ``errors``。
3. **只读依赖**：只读式引用 ``core.finding_schema``（计算 missing finding_id）
   与报告口径字段名（type/severity/url/method/parameter/evidence/confidence/
   source），不修改任何既有模块。
4. **互导而非行为等价**：本模块只保证 **finding 级**字段互导，**不**追求
   与 Nuclei/Burp/ZAP 的探测语义、模板引擎、请求重放行为等价（见
   ``docs/INTEROP.md`` 已知限制）。

lossless 扩展（round-trip 保真）
-------------------------------
外部格式本身不承载 ``verification`` / ``reproduction`` / ``oob`` /
``finding_id`` 等字段。为让"导出→再导入"严格一致，导出器会写入**带命名空间
的扩展位**（Nuclei JSONL 顶层键、Burp XML ``<vulnclaw-extension>``、
SARIF ``properties.vulnclaw``、CSV 独立列）。导入器**优先读扩展位**，
缺失时才退回外部格式的原生字段（即第三方真实产物路径）。

字段映射表 ``FIELD_MAPPING`` 覆盖**每个格式的每个统一字段**（含"无来源"
时的推导说明），供文档与测试引用（测试断言其键集合与 ``UNIFIED_FIELDS``
完全一致，杜绝字段漏映射）。
"""
from __future__ import annotations

import base64
import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, fields
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit

from vulnclaw.core.finding_schema import compute_finding_id

# ============================================================
# 常量
# ============================================================
INTEROP_VERSION = 1

#: 统一模型字段顺序（与 ``UnifiedFinding`` 声明顺序严格一致，测试锁死）
UNIFIED_FIELDS: Tuple[str, ...] = (
    "source", "scanner", "rule_id", "title", "finding_id",
    "severity", "confidence", "url", "method", "parameter",
    "request", "response", "evidence", "verification", "reproduction",
    "oob", "raw",
)

#: 参与"导出→导入"JSON 往返的字段（``raw`` 是原始条目存档，不参与往返）
LOSSY_EXCLUDED_FIELDS: Tuple[str, ...] = ("raw",)

#: round-trip 扩展位在各格式中的落点（文档与测试引用）
EXT_KEY_NUCLEI = "vulnclaw"
EXT_TAG_BURP = "vulnclaw-extension"
EXT_KEY_SARIF = "vulnclaw"

#: Nuclei JSONL 中承载统一字段的"顶层扩展键"（Nuclei 原生无 method/parameter）
EXT_KEYS_NUCLEI_TOP: Tuple[str, ...] = ("method", "parameter")

#: 扩展位承载的字段（导出写入 / 导入优先读取）
#: 注意：``severity`` 与 ``evidence`` 也在其中——外部格式对它们存在**展示默认值**
#: （如 Nuclei severity 必填 "info"、SARIF message 不可为空），若不落扩展位，
#: 空值会在往返中被"默认值化"，破坏 round-trip 保真。
EXT_FIELDS: Tuple[str, ...] = (
    "finding_id", "source", "scanner", "title", "severity",
    "confidence", "evidence", "verification", "reproduction", "oob",
)

SEVERITY_LEVELS: Tuple[str, ...] = ("critical", "high", "medium", "low", "info")

#: SARIF 2.1.0 schema URI（与 report_generator.generate_sarif 同值，便于消费者复用）
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
#: SARIF ruleId / rule.id 前缀（与 report_generator 同形态：VULNCLAW-0001）
SARIF_RULE_PREFIX = "VULNCLAW"

DEFAULT_SCANNER_VULNCLAW = "vulnclaw"


# ============================================================
# 基础工具（全部幂等、无副作用）
# ============================================================
_INVALID = object()
_WS_RE = re.compile(r"\s+")
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_RAW_REQUEST_RE = re.compile(
    r"^(?P<method>[A-Z]{3,10})[ \t]+(?P<target>[^ \t]+)[ \t]+HTTP/(?P<version>\d\.\d)[ \t]*$",
    re.MULTILINE,
)
_B64_WS_RE = re.compile(r"\s+")


def _s(value: Any) -> str:
    """标量转文本（None → ""；列表 → 逗号连接；其它 → str）。"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return ", ".join(t for t in (_s(v) for v in value) if t)
    return str(value).strip()


def _first(*values: Any) -> str:
    """返回首个非空文本（全空 → ""）。"""
    for value in values:
        text = _s(value)
        if text:
            return text
    return ""


def _loads(text: Any) -> Any:
    """宽松 JSON 解析：失败返回哨兵 ``_INVALID``（不抛异常）。

    捕获 ``RecursionError``：深层嵌套 JSON 会由 ``json.loads`` 抛出它，
    而它是 ``RuntimeError`` 子类、**不是** ``JSONDecodeError``。
    """
    try:
        return json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return _INVALID


def _dumps(obj: Any, *, indent: Optional[int] = None, sort_keys: bool = False) -> str:
    """确定性 JSON 序列化（``ensure_ascii=False``，无时间戳/随机成分）。"""
    return json.dumps(obj, ensure_ascii=False, indent=indent, sort_keys=sort_keys,
                      separators=(", ", ": ") if indent else (",", ":"))


def _slug(value: Any, *, fallback: str = "") -> str:
    """规则名 → 稳定 slug（Nuclei template-id 兜底用）。"""
    text = _SLUG_RE.sub("-", _s(value).lower()).strip("-")
    return text or fallback


def _ext_take(ext: Any, key: str, default: Any = "") -> str:
    """扩展位取值：**键存在即采信（空值也是值）**，缺失才回落外部格式原生字段。

    这是 round-trip 保真的关键：外部格式常对空值填展示默认值（Nuclei severity
    缺省 "info"、SARIF message 不可为空），若用 ``_first``（跳过空串）取值，
    空值会被"默认值化"，往返即不一致。
    """
    if isinstance(ext, dict) and key in ext:
        return _s(ext.get(key))
    return _s(default)


def _origin(url: Any, *, lower_netloc: bool = True) -> str:
    """URL → ``scheme://netloc``（无 scheme/netloc → ""）。

    ``lower_netloc=False`` 保留原始大小写（Burp XML 往返需要逐字节还原 URL）。
    """
    raw = _s(url)
    if not raw or "://" not in raw:
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return ""
    if not parts.scheme or not parts.netloc:
        return ""
    netloc = parts.netloc.lower() if lower_netloc else parts.netloc
    return "{}://{}".format(parts.scheme.lower(), netloc)


def _query_params(url: Any) -> str:
    """URL 查询串 → 去重保序的参数名（逗号连接；无 → ""）。"""
    raw = _s(url)
    if not raw:
        return ""
    try:
        query = urlsplit(raw).query
    except ValueError:
        return ""
    names: List[str] = []
    for key, _val in parse_qsl(query, keep_blank_values=True):
        if key and key not in names:
            names.append(key)
    return ",".join(names)


def _path_of(url: Any) -> str:
    """URL → path?query（无 scheme 时按原样返回）。"""
    raw = _s(url)
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw
    if not parts.scheme or not parts.netloc:
        return raw
    path = parts.path or "/"
    return "{}?{}".format(path, parts.query) if parts.query else path


def _join_url(host: Any, target: Any) -> str:
    """``host``（origin 或裸域名）+ ``target``（path 或绝对 URL）→ 绝对 URL。"""
    tgt = _s(target)
    if tgt.lower().startswith(("http://", "https://")):
        return tgt
    base = _s(host)
    if not base:
        return tgt
    if "://" not in base:
        base = "http://" + base
    if not tgt:
        return base
    return base.rstrip("/") + "/" + tgt.lstrip("/")


def _decode_base64(text: Any) -> str:
    """宽容 base64 解码（失败 → ""，绝不抛异常）。"""
    raw = _B64_WS_RE.sub("", _s(text))
    if not raw:
        return ""
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return ""


def _request_method(text: Any) -> str:
    """从原始 HTTP 报文/curl 命令中提取方法（无 → ""）。"""
    raw = _s(text)
    if not raw:
        return ""
    first = raw.replace("\r\n", "\n").split("\n", 1)[0].strip()
    match = re.match(r"^([A-Z]{3,10})\s+\S+", first)
    if match:
        return match.group(1).upper()
    curl = re.search(r"(?:^|\s)-X\s+([A-Z]{3,10})(?:\s|$)", raw)
    if curl:
        return curl.group(1).upper()
    return ""


# ============================================================
# 规范化：severity / confidence
# ============================================================
_SEVERITY_ALIASES: Dict[str, str] = {
    # critical
    "critical": "critical", "crit": "critical", "c": "critical", "4": "critical",
    # high（SARIF level=error；ZAP riskcode=3；Burp High）
    "high": "high", "h": "high", "error": "high", "3": "high", "severe": "high",
    # medium（SARIF level=warning；ZAP riskcode=2；Burp Medium）
    "medium": "medium", "med": "medium", "moderate": "medium", "m": "medium",
    "warning": "medium", "2": "medium",
    # low（SARIF level=note；ZAP riskcode=1；Burp Low）
    "low": "low", "l": "low", "note": "low", "minor": "low", "1": "low",
    # info（ZAP riskcode=0；Burp Information）
    "info": "info", "informational": "info", "information": "info",
    "0": "info", "none": "info", "unknown": "info",
}

_CONFIDENCE_ALIASES: Dict[str, str] = {
    "high": "high", "certain": "high", "confirmed": "high", "3": "high", "4": "high",
    "medium": "medium", "firm": "medium", "moderate": "medium", "2": "medium",
    "low": "low", "tentative": "low", "1": "low", "0": "low",
}

#: ZAP ``riskdesc`` 形如 ``"High (High)"`` → 取括号前主级别
_RISKDESC_RE = re.compile(r"^([A-Za-z]+)")

#: Burp severity/confidence 的规范书写（导出用）
_BURP_SEVERITY_OUT: Dict[str, str] = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Information", "": "Information",
}
_BURP_CONFIDENCE_OUT: Dict[str, str] = {
    "high": "Certain", "medium": "Firm", "low": "Tentative", "": "Tentative",
}


def normalize_severity(value: Any) -> str:
    """严重度 → 统一五档（critical/high/medium/low/info）。

    - 空输入 → ""（fail-closed，不猜）；
    - 可识别变体（SARIF level / ZAP riskcode / Burp 名称 / 数字 0-4）→ 规范档位；
    - 非空但不可识别 → ""（**不降级为 info，避免把未知严重度伪装成确认结论**）。
    """
    key = _s(value).lower()
    if not key:
        return ""
    if key in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[key]
    desc = _RISKDESC_RE.match(key)
    if desc and desc.group(1) in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[desc.group(1)]
    return ""


def normalize_confidence(value: Any) -> str:
    """置信度 → 统一三档（high/medium/low）；空/不可识别 → ""。"""
    key = _s(value).lower()
    if not key:
        return ""
    if key in _CONFIDENCE_ALIASES:
        return _CONFIDENCE_ALIASES[key]
    return ""


# ============================================================
# 导入结果：既是 list[UnifiedFinding]，又携带跳过计数
# ============================================================
class ImportResult(list):
    """导入结果（``list[UnifiedFinding]`` + ``skipped`` / ``errors``）。

    作为 ``list`` 使用（迭代 / len / 索引 / 相等比较全部照常），
    额外暴露 fail-closed 计数：
      - ``skipped``：被跳过的坏条目数（解析失败或关键字段缺失）；
      - ``errors`` ：逐条跳过原因（确定性顺序，便于判读与测试断言）。
    """

    __slots__ = ("skipped", "errors")

    def __init__(self, findings: Iterable[Any] = (), skipped: int = 0,
                 errors: Iterable[str] = ()) -> None:
        super().__init__(findings)
        self.skipped = int(skipped)
        self.errors = list(errors)

    def add_skip(self, reason: str) -> None:
        """登记一条跳过（计数 +1 并保留原因）。"""
        self.skipped += 1
        self.errors.append(str(reason))


# ============================================================
# 统一模型
# ============================================================
@dataclass
class UnifiedFinding:
    """跨工具统一 finding。

    字段
    ----
    source        来源通道（vulnclaw/nuclei/burp/zap/sarif/csv/raw_http）
    scanner       产出工具名（如 ``nuclei``、``Burp Suite``、``ZAP``）
    rule_id       规则/模板/插件标识（机器可读，用于去重与追踪）
    title         人类可读漏洞名（映射回报告口径 ``type``；本模块对规格的
                  唯一增补字段——没有它无法生成报告可消费的 finding）
    finding_id    稳定身份哈希；缺失时由 ``resolve_id()`` 以
                  ``(url, method, title, parameter)`` 调用 finding_schema 计算
    severity      统一五档（critical/high/medium/low/info）或 ""（未知）
    confidence    统一三档（high/medium/low）或 ""
    url           目标 URL
    method        HTTP 方法（大写）
    parameter     受影响参数名（多参数逗号连接）
    request       原始请求（文本；Burp/Curl 形态）
    response      原始响应（文本）
    evidence      响应证据/命中证据原文
    verification  验证层证据文本（工具自带的"已确认"背书）
    reproduction  独立复现证据文本
    oob           带外回调证据文本
    raw           原始条目存档（原样 dict；不参与导出往返）
    """

    source: str = ""
    scanner: str = ""
    rule_id: str = ""
    title: str = ""
    finding_id: str = ""
    severity: str = ""
    confidence: str = ""
    url: str = ""
    method: str = ""
    parameter: str = ""
    request: str = ""
    response: str = ""
    evidence: str = ""
    verification: str = ""
    reproduction: str = ""
    oob: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    # ---------- 身份 ----------
    def resolve_id(self) -> str:
        """返回稳定 finding_id：自带优先，缺失时按 finding_schema 口径计算。

        纯函数（不修改自身）；``(url, method, title, parameter)`` 全空 → ""。
        """
        if self.finding_id:
            return self.finding_id
        return compute_finding_id({
            "url": self.url,
            "method": self.method,
            "type": self.title,
            "parameter": self.parameter,
        })

    # ---------- 视图 ----------
    def to_dict(self) -> Dict[str, str]:
        """统一模型字典（不含 ``raw``；用于 JSONL 往返）。

        ``finding_id`` 输出 ``resolve_id()``（缺失即补齐），保证落盘产物带稳定身份。
        """
        return {
            name: (self.resolve_id() if name == "finding_id" else _s(getattr(self, name)))
            for name in UNIFIED_FIELDS if name not in LOSSY_EXCLUDED_FIELDS
        }

    def to_native(self) -> Dict[str, Any]:
        """VULNCLAW 报告口径字典（``type/severity/url/method/parameter/
        evidence/confidence/source`` + 互导附加键）。

        键名与 ``report_generator`` 渲染消费字段对齐，可直接喂
        ``report_data["vulnerabilities"]``；``payload`` 刻意不写
        （统一模型不含 payload，见 docs/INTEROP.md 已知限制）。
        """
        return {
            "type": self.title,
            "severity": self.severity,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "source": self.source,
            # --- 互导附加键（只增不改，渲染层忽略未知键） ---
            "title": self.title,
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "finding_id": self.resolve_id(),
            "verification": self.verification,
            "reproduction": self.reproduction,
            "oob": self.oob,
            "request": self.request,
            "response": self.response,
        }

    # ---------- 反序列化 ----------
    @classmethod
    def from_dict(cls, data: Any) -> Optional["UnifiedFinding"]:
        """从 dict 还原（非 dict → ``None``；未知键忽略；缺失字段置 ""）。"""
        if not isinstance(data, dict):
            return None
        known = {f.name for f in fields(cls)}
        kwargs: Dict[str, Any] = {}
        for name in known - {"raw"}:
            kwargs[name] = _s(data.get(name))
        raw = data.get("raw")
        kwargs["raw"] = dict(raw) if isinstance(raw, dict) else {}
        return cls(**kwargs)


def _uf_from_native(data: Any, *, source: str = "", scanner: str = "") -> Optional[UnifiedFinding]:
    """报告口径 dict → ``UnifiedFinding``（供 JSON/CSV/原生清单导入复用）。"""
    if not isinstance(data, dict):
        return None
    kwargs: Dict[str, Any] = {}
    for name in UNIFIED_FIELDS:
        if name in LOSSY_EXCLUDED_FIELDS:
            continue
        kwargs[name] = _s(data.get(name))
    # 报告口径别名：type → title
    kwargs["title"] = _first(data.get("title"), data.get("type"), data.get("name"),
                             data.get("alert"))
    kwargs["source"] = _first(data.get("source"), source)
    kwargs["scanner"] = _first(data.get("scanner"), scanner)
    kwargs["evidence"] = _first(data.get("evidence"), data.get("detail"),
                                data.get("description"), data.get("issueDetail"))
    kwargs["url"] = _first(data.get("url"), data.get("location"), data.get("uri"))
    kwargs["method"] = _s(data.get("method")).upper()
    kwargs["raw"] = dict(data)
    return UnifiedFinding(**kwargs)


# ============================================================
# 导入器
# ============================================================
def import_nuclei_jsonl(text: Any) -> ImportResult:
    """Nuclei JSONL（``-jsonl`` 输出）→ 统一模型列表。

    识别字段：``template-id``/``info.name``/``info.severity``/``matched-at``/
    ``host``/``request``/``response``/``curl-command``/``extracted-results``/
    ``matcher-name``/``info.tags``。
    """
    out = ImportResult()
    for lineno, line in enumerate(str(text or "").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        obj = _loads(line)
        if not isinstance(obj, dict):
            out.add_skip("nuclei: 第 {} 行非 JSON 对象".format(lineno))
            continue
        info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
        ext = obj.get(EXT_KEY_NUCLEI) if isinstance(obj.get(EXT_KEY_NUCLEI), dict) else {}
        rule_id = _s(_first(obj.get("template-id"), obj.get("templateID"), obj.get("template")))
        title = _first(info.get("name"), obj.get("matcher-name"), rule_id)
        url = _first(obj.get("matched-at"), obj.get("matched"), obj.get("host"))
        if not (url or rule_id or title):
            out.add_skip("nuclei: 第 {} 行缺 matched-at/template-id".format(lineno))
            continue
        if "://" not in url and url and not _origin(url):
            url = _join_url(obj.get("host"), url)
        request = _first(obj.get("request"), obj.get("curl-command"))
        tags = info.get("tags")
        tags_text = ",".join(_s(t) for t in tags) if isinstance(tags, list) else _s(tags)
        kind = _s(obj.get("type")).lower()
        extracted = obj.get("extracted-results")
        if isinstance(extracted, list):
            extracted_text = ", ".join(t for t in (_s(v) for v in extracted) if t)
        else:
            extracted_text = _s(extracted)
        if "method" in obj:
            method = _s(obj.get("method")).upper()
        else:
            method = _request_method(request) or ("GET" if url else "")
        parameter = _s(obj.get("parameter")) if "parameter" in obj else _query_params(url)
        finding = UnifiedFinding(
            source=_ext_take(ext, "source", "nuclei"),
            scanner=_ext_take(ext, "scanner", "nuclei"),
            rule_id=rule_id,
            title=_ext_take(ext, "title", title),
            finding_id=_ext_take(ext, "finding_id", ""),
            severity=normalize_severity(_ext_take(
                ext, "severity", _first(info.get("severity"), obj.get("severity")))),
            confidence=normalize_confidence(_ext_take(ext, "confidence", "")),
            url=url,
            method=method,
            parameter=parameter,
            request=request,
            response=_s(obj.get("response")),
            evidence=_ext_take(ext, "evidence", _first(extracted_text, info.get("description"))),
            verification=_ext_take(ext, "verification", ""),
            reproduction=_ext_take(ext, "reproduction", ""),
            oob=_ext_take(ext, "oob", ""),
            raw=dict(obj),
        )
        # OOB 启发式仅在**无扩展位**时生效（保证带扩展导出的结果 100% 可逆）
        if not ext and (kind == "dns" or "interactsh" in tags_text.lower()
                        or "oob" in tags_text.lower()):
            finding.oob = url
        out.append(finding)
    return out


def _xml_text(parent: Optional[ET.Element], tag: str) -> str:
    if parent is None:
        return ""
    node = parent.find(tag)
    return _xml_payload(node)


def _xml_payload(node: Optional[ET.Element]) -> str:
    """读元素文本；``base64="true"`` 时解码（失败 → ""）。"""
    if node is None:
        return ""
    text = node.text or ""
    if _s(node.get("base64")).lower() == "true":
        return _decode_base64(text)
    return text.strip()


def _xml_ext_take(ext: Optional[ET.Element], tag: str, default: Any = "") -> str:
    """XML 扩展位取值（元素存在即采信，缺失才回落；语义同 ``_ext_take``）。"""
    if ext is None:
        return _s(default)
    node = ext.find(tag)
    if node is None:
        return _s(default)
    return _xml_payload(node)


def import_burp_xml(text: Any) -> ImportResult:
    """Burp Suite issue 导出 XML → 统一模型列表。

    识别 ``<issues><issue>`` 结构：``name``/``type``/``host``/``path``/
    ``location``/``severity``/``confidence``/``issueDetail``/
    ``requestresponse/{request,response}``（支持 ``base64="true"``）。
    """
    out = ImportResult()
    src = str(text or "")
    if not src.strip():
        return out
    try:
        root = ET.fromstring(src)
    except ET.ParseError as exc:
        out.add_skip("burp: XML 解析失败: {}".format(exc))
        return out
    issues = [root] if root.tag == "issue" else list(root.findall(".//issue"))
    if not issues:
        out.add_skip("burp: 未找到 <issue> 元素")
        return out
    for idx, issue in enumerate(issues, 1):
        ext = issue.find(EXT_TAG_BURP)
        host = _xml_text(issue, "host")
        location = _xml_text(issue, "location")
        path = _xml_text(issue, "path")
        if not (location or path or host):
            out.add_skip("burp: issue[{}] 缺 host/path/location".format(idx))
            continue
        url = _join_url(host, location or path)
        request = response = ""
        rr = issue.find("requestresponse")
        if rr is not None:
            request = _xml_payload(rr.find("request"))
            response = _xml_payload(rr.find("response"))
        detail = _xml_text(issue, "issueDetail")
        out.append(UnifiedFinding(
            source=_xml_ext_take(ext, "source", "burp"),
            scanner=_xml_ext_take(ext, "scanner", "Burp Suite"),
            rule_id=_xml_ext_take(ext, "rule-id", _xml_text(issue, "type")),
            title=_xml_ext_take(ext, "title", _first(_xml_text(issue, "name"),
                                                    _xml_text(issue, "type"))),
            finding_id=_xml_ext_take(ext, "finding-id", ""),
            severity=normalize_severity(_xml_ext_take(
                ext, "severity", _xml_text(issue, "severity"))),
            confidence=normalize_confidence(_xml_ext_take(
                ext, "confidence", _xml_text(issue, "confidence"))),
            url=url,
            method=_s(_xml_ext_take(ext, "method", _request_method(request)
                                    or ("GET" if url else ""))).upper(),
            parameter=_xml_ext_take(ext, "parameter", _query_params(url)),
            request=request,
            response=response,
            evidence=_xml_ext_take(ext, "evidence", detail),
            verification=_xml_ext_take(ext, "verification", ""),
            reproduction=_xml_ext_take(ext, "reproduction", ""),
            oob=_xml_ext_take(ext, "oob", ""),
            raw={},
        ))
    return out


def import_zap_json(text: Any) -> ImportResult:
    """ZAP JSON 报告 → 统一模型列表（site → alerts → instances 展开）。

    识别字段：``site[].@name`` / ``alerts[].alert|name`` / ``pluginid`` /
    ``riskcode|riskdesc`` / ``confidence`` / ``instances[].uri|method|param|
    attack|evidence|otherinfo``。
    """
    out = ImportResult()
    data = _loads(text)
    if data is _INVALID:
        out.add_skip("zap: 顶层非合法 JSON")
        return out
    sites: List[Any] = []
    if isinstance(data, dict):
        site = data.get("site")
        if isinstance(site, list):
            sites = site
        elif isinstance(site, dict):
            sites = [site]
        elif isinstance(data.get("alerts"), list):
            sites = [data]
    elif isinstance(data, list):
        sites = [{"alerts": data}]
    if not sites:
        out.add_skip("zap: 未找到 site/alerts 结构")
        return out
    for si, site in enumerate(sites, 1):
        if not isinstance(site, dict):
            out.add_skip("zap: site[{}] 非对象".format(si))
            continue
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            out.add_skip("zap: site[{}] 缺 alerts[]".format(si))
            continue
        site_url = _s(_first(site.get("@name"), site.get("name")))
        for ai, alert in enumerate(alerts, 1):
            if not isinstance(alert, dict):
                out.add_skip("zap: site[{}].alerts[{}] 非对象".format(si, ai))
                continue
            instances = alert.get("instances")
            if not isinstance(instances, list) or not instances:
                instances = [{}]
            for ii, inst in enumerate(instances, 1):
                inst = inst if isinstance(inst, dict) else {}
                url = _first(inst.get("uri"), inst.get("url"), site_url)
                title = _first(alert.get("alert"), alert.get("name"))
                rule_id = _s(_first(alert.get("alertRef"), alert.get("pluginid"),
                                    alert.get("pluginId")))
                if not (url or title or rule_id):
                    out.add_skip("zap: site[{}].alerts[{}].instances[{}] 全空".format(si, ai, ii))
                    continue
                out.append(UnifiedFinding(
                    source="zap",
                    scanner="ZAP",
                    rule_id=rule_id,
                    title=title,
                    severity=normalize_severity(_first(alert.get("riskcode"),
                                                       alert.get("riskdesc"),
                                                       alert.get("risk"))),
                    confidence=normalize_confidence(
                        _first(inst.get("confidence"), alert.get("confidence"))),
                    url=url,
                    method=_s(inst.get("method")).upper() or ("GET" if url else ""),
                    parameter=_first(inst.get("param"), _query_params(url)),
                    evidence=_first(inst.get("evidence"), inst.get("attack"),
                                    inst.get("otherinfo"), alert.get("desc")),
                    raw=dict(alert),
                ))
    return out


def _sarif_rule_of(result: Dict[str, Any], rules: Sequence[Any]) -> Dict[str, Any]:
    """定位 SARIF result 引用的 rule（ruleId 优先，回退 ruleIndex）。"""
    rule_id = _s(result.get("ruleId"))
    for rule in rules:
        if isinstance(rule, dict) and rule_id and _s(rule.get("id")) == rule_id:
            return rule
    idx = result.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules) and isinstance(rules[idx], dict):
        return rules[idx]
    return {}


def _sarif_location(result: Dict[str, Any]) -> Tuple[str, str]:
    """SARIF result → ``(uri, snippet)``（兼容两种 locations 嵌套形态）。"""
    locs = result.get("locations")
    if not isinstance(locs, list) or not locs:
        return "", ""
    loc = locs[0] if isinstance(locs[0], dict) else {}
    physical = loc.get("physicalLocation")
    if not isinstance(physical, dict):
        inner = loc.get("location")
        physical = inner.get("physicalLocation") if isinstance(inner, dict) else None
    if not isinstance(physical, dict):
        return "", ""
    artifact = physical.get("artifactLocation")
    uri = _s(artifact.get("uri")) if isinstance(artifact, dict) else ""
    region = physical.get("region")
    snippet = ""
    if isinstance(region, dict):
        raw_snippet = region.get("snippet")
        snippet = _first(raw_snippet.get("text") if isinstance(raw_snippet, dict) else raw_snippet)
    return uri, snippet


def import_sarif(text: Any) -> ImportResult:
    """SARIF 2.1.0 → 统一模型列表（runs[].results[] 展开）。

    — 标准路径：``tool.driver.rules[]`` + ``results[].ruleId/level/message/
    locations[].physicalLocation``；
    — 扩展路径：``result.properties`` 内的 ``type`` / ``confidence`` /
    ``severity`` / ``rule_id`` / ``finding_id`` 与 ``properties.vulnclaw``
    命名空间（本模块 ``export_sarif`` 的无损往返位）。
    """
    out = ImportResult()
    data = _loads(text)
    if not isinstance(data, dict):
        out.add_skip("sarif: 顶层非 JSON 对象")
        return out
    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        out.add_skip("sarif: 缺 runs[]")
        return out
    for ri, run in enumerate(runs, 1):
        if not isinstance(run, dict):
            out.add_skip("sarif: run[{}] 非对象".format(ri))
            continue
        tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
        driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
        rules = driver.get("rules") if isinstance(driver.get("rules"), list) else []
        scanner = _first(driver.get("name"), "sarif")
        results = run.get("results")
        if not isinstance(results, list):
            out.add_skip("sarif: run[{}] 缺 results[]".format(ri))
            continue
        for xi, result in enumerate(results, 1):
            if not isinstance(result, dict):
                out.add_skip("sarif: run[{}].results[{}] 非对象".format(ri, xi))
                continue
            props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
            ext = props.get(EXT_KEY_SARIF) if isinstance(props.get(EXT_KEY_SARIF), dict) else {}
            rule = _sarif_rule_of(result, rules)
            rule_props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
            rule_id = _first(props.get("rule_id"), result.get("ruleId"), rule.get("id"))
            title = _first(props.get("type"), rule.get("name"),
                           (rule.get("shortDescription") or {}).get("text")
                           if isinstance(rule.get("shortDescription"), dict) else "",
                           rule_id)
            uri, snippet = _sarif_location(result)
            message = result.get("message")
            if isinstance(message, dict):
                message = _first(message.get("text"), message.get("markdown"))
            if not (uri or title or rule_id):
                out.add_skip("sarif: run[{}].results[{}] 全空".format(ri, xi))
                continue
            native_rule_id = rule_id if "rule_id" in props else _first(
                result.get("ruleId"), rule.get("id"))
            native_parameter = _first(snippet, _query_params(uri)) if "parameter" not in props \
                else _s(props.get("parameter"))
            out.append(UnifiedFinding(
                source=_ext_take(ext, "source", "sarif"),
                scanner=_ext_take(ext, "scanner", scanner),
                rule_id=_ext_take(ext, "rule_id", native_rule_id),
                title=_ext_take(ext, "title", title),
                finding_id=_ext_take(ext, "finding_id", _s(props.get("finding_id"))),
                severity=normalize_severity(_ext_take(
                    ext, "severity", _first(props.get("severity"),
                                            rule_props.get("severity"),
                                            result.get("level")))),
                confidence=normalize_confidence(_ext_take(
                    ext, "confidence", _s(props.get("confidence")))),
                url=uri,
                method=_s(props.get("method")).upper(),
                parameter=native_parameter,
                evidence=_ext_take(ext, "evidence", message),
                verification=_ext_take(ext, "verification", ""),
                reproduction=_ext_take(ext, "reproduction", ""),
                oob=_ext_take(ext, "oob", ""),
                raw=dict(result),
            ))
    return out


#: 统一模型 ↔ CSV 列（顺序即输出列序，确定性）
CSV_COLUMNS: Tuple[str, ...] = (
    "source", "scanner", "rule_id", "finding_id", "title", "severity",
    "confidence", "url", "method", "parameter", "evidence",
    "verification", "reproduction", "oob",
)

#: 报告口径 CSV 列（``report_generator._CSV_COLUMNS`` 形态，导入侧兼容识别）
_NATIVE_CSV_HINTS: Tuple[str, ...] = ("type", "remediation", "remediation_tier")


def import_csv(text: Any) -> ImportResult:
    """CSV → 统一模型列表（读取表头按名取列，列序无关）。

    兼容两类表头：本模块 ``CSV_COLUMNS``（无损往返）与报告口径
    ``type/severity/url/parameter/method/source``。
    行内既无 url 又无 title/type → 跳过并计数。
    """
    out = ImportResult()
    src = str(text or "").lstrip("\ufeff")
    if not src.strip():
        return out
    reader = csv.DictReader(io.StringIO(src))
    header = reader.fieldnames
    if not header:
        out.add_skip("csv: 缺表头")
        return out
    for lineno, row in enumerate(reader, 2):
        row = {_s(k).lower(): v for k, v in row.items() if k is not None}
        url = _s(row.get("url"))
        title = _first(row.get("title"), row.get("type"), row.get("name"), row.get("alert"))
        if not (url or title):
            out.add_skip("csv: 第 {} 行缺 url/title".format(lineno))
            continue
        parameter = _s(row.get("parameter")) if "parameter" in row else _query_params(url)
        out.append(UnifiedFinding(
            source=_first(row.get("source"), "csv"),
            scanner=_first(row.get("scanner"), "csv"),
            rule_id=_s(row.get("rule_id")),
            title=title,
            finding_id=_s(row.get("finding_id")),
            severity=normalize_severity(row.get("severity")),
            confidence=normalize_confidence(row.get("confidence")),
            url=url,
            method=_s(row.get("method")).upper() or ("GET" if url else ""),
            parameter=parameter,
            evidence=_first(row.get("evidence"), row.get("detail"),
                            row.get("description"), row.get("issueDetail")),
            verification=_s(row.get("verification")),
            reproduction=_s(row.get("reproduction")),
            oob=_s(row.get("oob")),
            raw=dict(row),
        ))
    return out


def _parse_raw_request(block: str) -> Optional[UnifiedFinding]:
    """单块原始 HTTP 请求 → ``UnifiedFinding``（缺 Host 的相对路径 → None）。"""
    lines = block.replace("\r\n", "\n").split("\n")
    if not lines:
        return None
    match = re.match(r"^([A-Z]{3,10})[ \t]+([^ \t]+)[ \t]+HTTP/(\d\.\d)[ \t]*$", lines[0])
    if not match:
        return None
    method, target = match.group(1).upper(), match.group(2)
    headers: Dict[str, str] = {}
    order: List[str] = []
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        if not key:
            continue
        if key not in headers:
            order.append(key)
            headers[key] = value.strip()
        else:
            headers[key] = "{}, {}".format(headers[key], value.strip())
    host = _s(headers.get("host"))
    if target.lower().startswith(("http://", "https://")):
        url = target
        if "://" not in _s(headers.get("host")) and not host:
            parts = urlsplit(url)
            host = parts.netloc
    elif host:
        scheme = "https" if host.endswith(":443") else "http"
        url = "{}://{}{}".format(scheme, host, target if target.startswith("/") else "/" + target)
    else:
        return None
    finding = UnifiedFinding(
        source="raw_http",
        scanner="raw_http",
        url=url,
        method=method,
        parameter=_query_params(url),
        request=block,
        raw={
            "host": host,
            "path": target,
            "headers": dict(headers),
            "header_order": order,
            "cookie": _s(headers.get("cookie")),
            "content_type": _s(headers.get("content-type")),
        },
    )
    return finding


def import_raw_http(text: Any) -> ImportResult:
    """原始 HTTP 报文（可多请求串联）→ 统一模型列表。

    以 ``METHOD target HTTP/x.y`` 请求行为锚切块，解析出 host / path /
    method / headers / cookie（存入 ``finding.raw``）。
    **缺 Host 头的相对路径请求跳过**（无法构成可用 URL，fail-closed）。
    """
    out = ImportResult()
    src = str(text or "")
    if not src.strip():
        return out
    normalized = src.replace("\r\n", "\n")
    matches = list(_RAW_REQUEST_RE.finditer(normalized))
    if not matches:
        out.add_skip("raw_http: 未找到 HTTP 请求行")
        return out
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(normalized)
        block = normalized[match.start():end].strip("\n")
        finding = _parse_raw_request(block)
        if finding is None:
            out.add_skip("raw_http: 第 {} 个请求块解析失败（缺 Host 或请求行非法）".format(i + 1))
            continue
        out.append(finding)
    return out


def import_jsonl(text: Any) -> ImportResult:
    """统一模型 JSONL（``export_jsonl`` 产物）→ 统一模型列表。"""
    out = ImportResult()
    for lineno, line in enumerate(str(text or "").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        obj = _loads(line)
        if not isinstance(obj, dict):
            out.add_skip("jsonl: 第 {} 行非 JSON 对象".format(lineno))
            continue
        finding = UnifiedFinding.from_dict(obj)
        if finding is None or not (finding.url or finding.title or finding.rule_id):
            out.add_skip("jsonl: 第 {} 行缺 url/title/rule_id".format(lineno))
            continue
        out.append(finding)
    return out


def import_vulnclaw_json(text: Any) -> ImportResult:
    """VULNCLAW 原生 JSON（``export_vulnclaw_json`` / 报告口径清单）→ 统一模型。

    接受：顶层 list、单 dict、或 ``{"vulnerabilities": [...]}`` 报告结构。
    """
    out = ImportResult()
    data = _loads(text)
    if data is _INVALID:
        out.add_skip("vulnclaw_json: 顶层非法 JSON")
        return out
    if isinstance(data, dict):
        if isinstance(data.get("vulnerabilities"), list):
            items = data["vulnerabilities"]
        else:
            items = [data]
    elif isinstance(data, list):
        items = data
    else:
        out.add_skip("vulnclaw_json: 顶层既非对象也非数组")
        return out
    for idx, item in enumerate(items, 1):
        finding = _uf_from_native(item, source=DEFAULT_SCANNER_VULNCLAW,
                                  scanner=DEFAULT_SCANNER_VULNCLAW)
        if finding is None or not (finding.url or finding.title or finding.rule_id):
            out.add_skip("vulnclaw_json: 第 {} 条非对象或缺 url/type".format(idx))
            continue
        out.append(finding)
    return out


#: 导入器注册表（格式键 → 函数）
IMPORTERS: Dict[str, Any] = {
    "vulnclaw_json": import_vulnclaw_json,
    "jsonl": import_jsonl,
    "nuclei_jsonl": import_nuclei_jsonl,
    "burp_xml": import_burp_xml,
    "zap_json": import_zap_json,
    "sarif": import_sarif,
    "csv": import_csv,
    "raw_http": import_raw_http,
}

#: 格式别名（宽松解析，全部小写）
FORMAT_ALIASES: Dict[str, str] = {
    "vulnclaw": "vulnclaw_json", "vulnclaw-json": "vulnclaw_json",
    "json": "vulnclaw_json", "native": "vulnclaw_json",
    "jsonlines": "jsonl", "ndjson": "jsonl", "unified_jsonl": "jsonl",
    "nuclei": "nuclei_jsonl", "nuclei-jsonl": "nuclei_jsonl",
    "burp": "burp_xml", "burp-xml": "burp_xml", "xml": "burp_xml",
    "zap": "zap_json", "zap-json": "zap_json",
    "sarif21": "sarif", "sarif2": "sarif",
    "raw-http": "raw_http", "rawhttp": "raw_http", "http": "raw_http",
    "md": "markdown", "markdown": "markdown",
}


def resolve_format(fmt: Any) -> str:
    """格式名归一化（别名 → 注册键）；未知 → 原样小写字符串。"""
    key = _s(fmt).lower().replace(" ", "_")
    return FORMAT_ALIASES.get(key, key)


def import_any(text: Any, fmt: Any) -> ImportResult:
    """按格式名分派导入；未知格式 → ``ValueError``（显式失败，不静默）。"""
    key = resolve_format(fmt)
    importer = IMPORTERS.get(key)
    if importer is None:
        raise ValueError("interop: 不支持的导入格式: {!r}".format(fmt))
    return importer(text)


# ============================================================
# 导出器（全部返回 str，确定性；空输入返回空清单而非异常）
# ============================================================
def _iter_uf(findings: Any) -> Iterator[UnifiedFinding]:
    """把任意输入宽容地转成 ``UnifiedFinding`` 迭代器。

    - ``UnifiedFinding`` → 原样；
    - ``dict`` → ``_uf_from_native`` 归一；
    - 其它（None/数字/字符串）→ **跳过**，绝不抛异常（导出层 fail-closed）。
    """
    if findings is None:
        return
    if isinstance(findings, (UnifiedFinding, dict)):
        findings = [findings]
    try:
        items = list(findings)
    except TypeError:
        return
    for item in items:
        if isinstance(item, UnifiedFinding):
            yield item
        elif isinstance(item, dict):
            converted = _uf_from_native(item)
            if converted is not None:
                yield converted


def _ext_payload(uf: UnifiedFinding) -> Dict[str, str]:
    """扩展位载荷（EXT_FIELDS）；``finding_id`` 用 ``resolve_id()`` 保证稳定。"""
    payload: Dict[str, str] = {}
    for name in EXT_FIELDS:
        if name == "finding_id":
            payload[name] = uf.resolve_id()
        else:
            payload[name] = _s(getattr(uf, name))
    return payload


def to_unified_dicts(findings: Any) -> List[Dict[str, str]]:
    """统一模型 → dict 列表（不含 ``raw``）。"""
    return [uf.to_dict() for uf in _iter_uf(findings)]


def to_native_findings(findings: Any) -> List[Dict[str, Any]]:
    """统一模型 → VULNCLAW 报告口径 dict 列表。"""
    return [uf.to_native() for uf in _iter_uf(findings)]


def export_jsonl(findings: Any) -> str:
    """统一模型 JSONL（每行一个 finding；键序固定；末行带换行）。"""
    lines = [_dumps(record, sort_keys=True) for record in to_unified_dicts(findings)]
    return "".join(line + "\n" for line in lines)


def export_vulnclaw_json(findings: Any) -> str:
    """VULNCLAW 报告口径 JSON（list；缩进 2；无时间戳）。"""
    return _dumps(to_native_findings(findings), indent=2)


def export_csv(findings: Any) -> str:
    """统一模型 CSV（列序 = ``CSV_COLUMNS``）。

    ``request`` / ``response`` 不入列（体积大且含换行），见 docs/INTEROP.md。
    行分隔符固定 ``\\n``（确定性，跨平台字节一致）。
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(CSV_COLUMNS), lineterminator="\n")
    writer.writeheader()
    for uf in _iter_uf(findings):
        writer.writerow({col: _cell(uf, col) for col in CSV_COLUMNS})
    return buffer.getvalue()


def _cell(uf: UnifiedFinding, column: str) -> str:
    if column == "finding_id":
        return uf.resolve_id()
    return _s(getattr(uf, column, ""))


def export_sarif(findings: Any) -> str:
    """SARIF 2.1.0 JSON 文本（结构与 ``report_generator.generate_sarif`` 同形，
    便于 CI/DevSecOps 消费者直接复用；额外写 ``properties.vulnclaw`` 无损扩展位）。"""
    rules: List[Dict[str, Any]] = []
    rule_ids: Dict[str, str] = {}
    results: List[Dict[str, Any]] = []
    for uf in _iter_uf(findings):
        key = _first(uf.title, uf.rule_id, "Vulnerability")
        if key not in rule_ids:
            rule_ids[key] = "{}-{:04d}".format(SARIF_RULE_PREFIX, len(rule_ids) + 1)
            rules.append({
                "id": rule_ids[key],
                "name": key,
                "shortDescription": {"text": key[:200]},
                "fullDescription": {"text": _s(uf.evidence)[:500]},
                "properties": {"severity": uf.severity or "info",
                               "rule_id": uf.rule_id},
            })
        results.append({
            "ruleId": rule_ids[key],
            "level": _sarif_level(uf.severity),
            "message": {"text": _s(uf.evidence)[:500] or key},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uf.url},
                    "region": {"startLine": 1, "snippet": {"text": uf.parameter[:200]}},
                }
            }],
            "properties": {
                "type": key,
                "severity": uf.severity,
                "confidence": uf.confidence,
                "rule_id": uf.rule_id,
                "finding_id": uf.resolve_id(),
                "method": uf.method,
                "parameter": uf.parameter,
                EXT_KEY_SARIF: _ext_payload(uf),
            },
        })
    sarif = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": DEFAULT_SCANNER_VULNCLAW, "version": "1.0",
                                "informationUri": "https://github.com/vulnclaw",
                                "rules": rules}},
            "results": results,
        }],
    }
    return _dumps(sarif, indent=2)


def _sarif_level(severity: str) -> str:
    """统一严重度 → SARIF level（与 report_generator._sarif_level 同口径）。"""
    sev = _s(severity).lower()
    if sev in ("critical", "high"):
        return "error"
    if sev == "medium":
        return "warning"
    return "note"


def export_nuclei_jsonl(findings: Any) -> str:
    """Nuclei JSONL 形态（每行一个 JSON；可被 ``import_nuclei_jsonl`` 无损回读）。"""
    lines: List[str] = []
    for uf in _iter_uf(findings):
        template_id = _first(uf.rule_id, _slug(uf.title, fallback="vulnclaw-finding"))
        record = {
            "template-id": template_id,
            "info": {
                "name": _first(uf.title, template_id),
                "severity": uf.severity or "info",
                "description": uf.evidence,
                "tags": [],
            },
            "type": "http",
            "host": _origin(uf.url) or uf.url,
            "matched-at": uf.url,
            "matcher-name": "",
            "extracted-results": [uf.evidence] if uf.evidence else [],
            "request": uf.request,
            "response": uf.response,
            # --- 无损扩展位（Nuclei 消费者忽略未知键；本模块导入时优先读取）---
            "method": uf.method,
            "parameter": uf.parameter,
            EXT_KEY_NUCLEI: _ext_payload(uf),
        }
        lines.append(_dumps(record, sort_keys=True))
    return "".join(line + "\n" for line in lines)


def export_burp_xml(findings: Any) -> str:
    """Burp Suite issue XML 形态（无 ``exportTime`` 以保证确定性）。

    ``request`` / ``response`` 以 ``base64="true"`` 承载（可含二进制/换行）；
    统一模型附加字段写入 ``<vulnclaw-extension>``（Burp 忽略未知子元素）。
    """
    root = ET.Element("issues", attrib={"burpVersion": "0"})
    for idx, uf in enumerate(_iter_uf(findings), 1):
        issue = ET.SubElement(root, "issue")
        ET.SubElement(issue, "serialNumber").text = str(idx)
        ET.SubElement(issue, "name").text = _first(uf.title, uf.rule_id, "Finding")
        # lower_netloc=False：保留 URL 原始大小写，保证 location+host 可逐字节还原
        origin = _origin(uf.url, lower_netloc=False) or uf.url
        ET.SubElement(issue, "host").text = origin
        ET.SubElement(issue, "path").text = _path_of(uf.url)
        ET.SubElement(issue, "location").text = _path_of(uf.url)
        ET.SubElement(issue, "severity").text = _BURP_SEVERITY_OUT.get(uf.severity, "Information")
        ET.SubElement(issue, "confidence").text = _BURP_CONFIDENCE_OUT.get(uf.confidence, "Tentative")
        ET.SubElement(issue, "issueDetail").text = uf.evidence
        rr = ET.SubElement(issue, "requestresponse")
        request_node = ET.SubElement(rr, "request", attrib={"base64": "true"})
        request_node.text = base64.b64encode(uf.request.encode("utf-8")).decode("ascii")
        response_node = ET.SubElement(rr, "response", attrib={"base64": "true"})
        response_node.text = base64.b64encode(uf.response.encode("utf-8")).decode("ascii")
        ext = ET.SubElement(issue, EXT_TAG_BURP)
        ext_fields = _ext_payload(uf)
        ext_fields["rule-id"] = uf.rule_id
        ext_fields["finding-id"] = ext_fields.pop("finding_id", "")
        ext_fields["method"] = uf.method
        ext_fields["parameter"] = uf.parameter
        for key in ("source", "scanner", "rule-id", "title", "finding-id", "severity",
                    "confidence", "method", "parameter", "evidence", "verification",
                    "reproduction", "oob"):
            ET.SubElement(ext, key).text = ext_fields.get(key, "")
    body = ET.tostring(root, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + body + "\n"


def export_markdown(findings: Any) -> str:
    """Markdown 表格清单（人类可读；含严重度分布摘要）。"""
    items = list(_iter_uf(findings))
    lines = ["# VULNCLAW 工具互导发现清单", "", "共 {} 条发现。".format(len(items)), ""]
    counts: Dict[str, int] = {level: 0 for level in SEVERITY_LEVELS}
    for uf in items:
        if uf.severity in counts:
            counts[uf.severity] += 1
    summary = "，".join("{}={}".format(level, counts[level]) for level in SEVERITY_LEVELS)
    lines.extend(["严重度分布：{}（未识别 {} 条）。".format(
        summary, len(items) - sum(counts.values())), ""])
    if not items:
        lines.append("（无发现）")
        return "\n".join(lines) + "\n"
    lines.append("| # | 标题 | 严重度 | 置信度 | 方法 | URL | 参数 | 规则 | 来源 | 证据 |")
    lines.append("|---|------|--------|--------|------|-----|------|------|------|------|")
    for idx, uf in enumerate(items, 1):
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            idx, _md_cell(_first(uf.title, uf.rule_id)), _md_cell(uf.severity or "-"),
            _md_cell(uf.confidence or "-"), _md_cell(uf.method or "-"), _md_cell(uf.url),
            _md_cell(uf.parameter or "-"), _md_cell(uf.rule_id or "-"),
            _md_cell(uf.source or "-"), _md_cell(_s(uf.evidence)[:160]),
        ))
    return "\n".join(lines) + "\n"


def _md_cell(value: Any) -> str:
    """Markdown 单元格转义（管道符与换行会破坏表格）。"""
    return _WS_RE.sub(" ", _s(value).replace("|", "\\|")).strip() or "-"


#: 导出器注册表（格式键 → 函数）
EXPORTERS: Dict[str, Any] = {
    "vulnclaw_json": export_vulnclaw_json,
    "jsonl": export_jsonl,
    "csv": export_csv,
    "sarif": export_sarif,
    "nuclei_jsonl": export_nuclei_jsonl,
    "burp_xml": export_burp_xml,
    "markdown": export_markdown,
}


def export_any(findings: Any, fmt: Any) -> str:
    """按格式名分派导出；未知格式 → ``ValueError``。"""
    key = resolve_format(fmt)
    exporter = EXPORTERS.get(key)
    if exporter is None:
        raise ValueError("interop: 不支持的导出格式: {!r}".format(fmt))
    return exporter(findings)


def supported_formats() -> Dict[str, Dict[str, bool]]:
    """支持矩阵：``{格式: {"import": bool, "export": bool}}``（确定性排序）。"""
    keys = sorted(set(IMPORTERS) | set(EXPORTERS))
    return {key: {"import": key in IMPORTERS, "export": key in EXPORTERS} for key in keys}


# ============================================================
# 字段映射表（文档与测试共用的事实来源）
# ============================================================
# 取值说明：
#   ``const:x``   固定值
#   ``derive:x``  由其它字段推导（见函数注释）
#   ``n/a``       该格式不承载此字段（导入后为 ""，绝不编造）
#   ``ext.<f>``   无损扩展位（vulnclaw-extension / properties.vulnclaw）
#   多来源用 `` | `` 连接，顺序即回退优先级。
FIELD_MAPPING: Dict[str, Dict[str, str]] = {
    "vulnclaw_json": {
        "source": "source | const:vulnclaw", "scanner": "scanner | const:vulnclaw",
        "rule_id": "rule_id", "title": "title | type | name",
        "finding_id": "finding_id | derive:compute_finding_id(url,method,title,parameter)",
        "severity": "severity", "confidence": "confidence", "url": "url | location",
        "method": "method", "parameter": "parameter | derive:url query keys",
        "request": "request", "response": "response",
        "evidence": "evidence | detail | description",
        "verification": "verification", "reproduction": "reproduction", "oob": "oob",
        "raw": "整条原始对象",
    },
    "jsonl": {
        "source": "source", "scanner": "scanner", "rule_id": "rule_id", "title": "title",
        "finding_id": "finding_id | derive:compute_finding_id(...)",
        "severity": "severity", "confidence": "confidence", "url": "url", "method": "method",
        "parameter": "parameter", "request": "request", "response": "response",
        "evidence": "evidence", "verification": "verification",
        "reproduction": "reproduction", "oob": "oob", "raw": "n/a（raw 不参与往返）",
    },
    "nuclei_jsonl": {
        "source": "ext.source | const:nuclei", "scanner": "ext.scanner | const:nuclei",
        "rule_id": "template-id | templateID | template",
        "title": "ext.title | info.name | matcher-name | template-id",
        "finding_id": "ext.finding_id | derive:compute_finding_id(...)",
        "severity": "ext.severity | info.severity | severity", "confidence": "ext.confidence",
        "url": "matched-at | matched | host | derive:host+target",
        "method": "method | derive:request 请求行 | derive:curl-command -X | const:GET",
        "parameter": "parameter | derive:matched-at query keys",
        "request": "request | curl-command", "response": "response",
        "evidence": "ext.evidence | extracted-results | info.description",
        "verification": "ext.verification",
        "reproduction": "ext.reproduction",
        "oob": "ext.oob | derive:type=dns/tags 含 oob|interactsh 时的 matched-at（仅无扩展位时）",
        "raw": "整行 JSON 对象",
    },
    "burp_xml": {
        "source": "ext.source | const:burp", "scanner": "ext.scanner | const:Burp Suite",
        "rule_id": "ext.rule-id | issue/type", "title": "ext.title | issue/name | issue/type",
        "finding_id": "ext.finding-id | derive:compute_finding_id(...)",
        "severity": "ext.severity | issue/severity",
        "confidence": "ext.confidence | issue/confidence",
        "url": "derive:issue/host + (issue/location | issue/path)",
        "method": "ext.method | derive:request 请求行 | const:GET",
        "parameter": "ext.parameter | derive:location query keys",
        "request": "requestresponse/request（base64=true 时解码）",
        "response": "requestresponse/response（base64=true 时解码）",
        "evidence": "ext.evidence | issue/issueDetail", "verification": "ext.verification",
        "reproduction": "ext.reproduction", "oob": "ext.oob",
        "raw": "n/a（XML 不归档原文，避免重复膨胀）",
    },
    "zap_json": {
        "source": "const:zap", "scanner": "const:ZAP",
        "rule_id": "alertRef | pluginid | pluginId", "title": "alert | name",
        "finding_id": "derive:compute_finding_id(...)",
        "severity": "riskcode | riskdesc | risk", "confidence": "instance.confidence | alert.confidence",
        "url": "instance.uri | instance.url | site.@name",
        "method": "instance.method | const:GET", "parameter": "instance.param | derive:uri query keys",
        "request": "n/a（ZAP JSON 报告不携带原始报文）",
        "response": "n/a（ZAP JSON 报告不携带原始报文）",
        "evidence": "instance.evidence | instance.attack | instance.otherinfo | alert.desc",
        "verification": "n/a", "reproduction": "n/a", "oob": "n/a",
        "raw": "整条 alert 对象",
    },
    "sarif": {
        "source": "ext.source | const:sarif",
        "scanner": "ext.scanner | run.tool.driver.name",
        "rule_id": "properties.rule_id | result.ruleId | rule.id",
        "title": "properties.type | rule.name | rule.shortDescription.text | ruleId",
        "finding_id": "ext.finding_id | properties.finding_id | derive:compute_finding_id(...)",
        "severity": "ext.severity | properties.severity | rule.properties.severity | result.level",
        "confidence": "ext.confidence | properties.confidence",
        "url": "locations[0].physicalLocation.artifactLocation.uri",
        "method": "properties.method",
        "parameter": "properties.parameter | region.snippet.text | derive:uri query keys",
        "request": "n/a（SARIF 不含原始报文）", "response": "n/a（SARIF 不含原始报文）",
        "evidence": "ext.evidence | result.message.text | result.message.markdown",
        "verification": "ext.verification", "reproduction": "ext.reproduction", "oob": "ext.oob",
        "raw": "整条 result 对象",
    },
    "csv": {
        "source": "source | const:csv", "scanner": "scanner | const:csv",
        "rule_id": "rule_id", "title": "title | type | name | alert",
        "finding_id": "finding_id | derive:compute_finding_id(...)",
        "severity": "severity", "confidence": "confidence", "url": "url",
        "method": "method | const:GET", "parameter": "parameter | derive:url query keys",
        "request": "n/a（CSV 列不含 request，见已知限制）",
        "response": "n/a（CSV 列不含 response，见已知限制）",
        "evidence": "evidence | detail | description | issueDetail",
        "verification": "verification", "reproduction": "reproduction", "oob": "oob",
        "raw": "整行 dict",
    },
    "raw_http": {
        "source": "const:raw_http", "scanner": "const:raw_http",
        "rule_id": "n/a（原始报文不含规则信息）",
        "title": "n/a（原始报文不含漏洞名）",
        "finding_id": "derive:compute_finding_id(...)",
        "severity": "n/a（原始报文不含严重度）", "confidence": "n/a",
        "url": "derive:Host 头 + 请求行 target（绝对 URL target 直接用）",
        "method": "请求行 method", "parameter": "derive:url query keys",
        "request": "整个请求块原文", "response": "n/a（本导入器只吃请求侧）",
        "evidence": "n/a（原始报文不含证据结论）", "verification": "n/a",
        "reproduction": "n/a", "oob": "n/a",
        "raw": "host/path/headers/header_order/cookie/content_type",
    },
}


__all__ = [
    "INTEROP_VERSION",
    "UNIFIED_FIELDS", "LOSSY_EXCLUDED_FIELDS", "SEVERITY_LEVELS", "CSV_COLUMNS",
    "EXT_KEY_NUCLEI", "EXT_TAG_BURP", "EXT_KEY_SARIF", "EXT_KEYS_NUCLEI_TOP",
    "EXT_FIELDS", "SARIF_SCHEMA_URI", "SARIF_RULE_PREFIX",
    "UnifiedFinding", "ImportResult",
    "normalize_severity", "normalize_confidence",
    "import_nuclei_jsonl", "import_burp_xml", "import_zap_json", "import_sarif",
    "import_csv", "import_raw_http", "import_jsonl", "import_vulnclaw_json",
    "IMPORTERS", "FORMAT_ALIASES", "resolve_format", "import_any",
    "export_vulnclaw_json", "export_jsonl", "export_csv", "export_sarif",
    "export_nuclei_jsonl", "export_burp_xml", "export_markdown", "export_any",
    "EXPORTERS", "supported_formats", "to_unified_dicts", "to_native_findings",
    "FIELD_MAPPING",
]
