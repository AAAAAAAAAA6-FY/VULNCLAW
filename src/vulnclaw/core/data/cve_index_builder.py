# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/data/cve_index_builder.py  (Z1.1)
"""
CVE 情报索引构建器（0day/复杂漏洞检出的情报驱动底座）。

数据源：thirdparty/nuclei-templates/cves.json（NDJSON，每行一个 CVE 条目）：
    {"ID":"CVE-...","Info":{"Name":...,"Severity":...,"Description":...,
     "Classification":{"CVSSScore":...}},"file_path":"http/cves/.../CVE-....yaml"}

职责：
  1. 解析 NDJSON → 结构化记录（id/name/severity/cvss/file_path/description）
  2. 从标题与描述中启发式抽取「组件关键词」与「版本号」，构建倒排：
       组件(小写 token) → [CVE]
  3. 落盘为可查询索引（默认 thirdparty/nuclei-templates/cve_index/）
  4. 提供组件+版本 → 候选 CVE 的查询接口，供复盘任务生成/引擎使用

设计原则（避免误报）：
  - 标题/描述子串匹配是「候选」而非「实锤」；命中后仍须引擎做带内或 OOB 验证。
  - 版本区间解析失败时不排除，仅标记 base_versions 候选。
  - 纯本地、无网络、无外部依赖。
"""
import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set

import yaml

from vulnclaw.core.logger import logger
from vulnclaw.paths import PROJECT_ROOT

# ============================================================
# 常量
# ============================================================
_DEFAULT_SRC = os.path.join("thirdparty", "nuclei-templates", "cves.json")
_DEFAULT_OUT = os.path.join("thirdparty", "nuclei-templates", "cve_index")

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_CVE_YEAR_RE = re.compile(r"CVE-(\d{4})-", re.IGNORECASE)


def _cve_year(cve_id: str) -> int:
    """从 CVE-YYYY-NNNN 提取年份（越新越可能未打补丁，排序时越靠前），无法解析返回 0。"""
    m = _CVE_YEAR_RE.match(str(cve_id or ""))
    return int(m.group(1)) if m else 0

# 常见「漏洞类型/无信息量」词，做组件抽取时剔除（避免把漏洞类型当成组件）
_VULN_NOISE = {
    "multiple", "cross-site", "scripting", "xss", "injection", "remote", "code",
    "execution", "arbitrary", "information", "disclosure", "vulnerability",
    "vulnerabilities", "ending", "allows", "allowing", "unauthenticated",
    "authenticated", "privilege", "privileges", "denial", "service", "dos",
    "local", "directory", "traversal", "bypass", "authentication",
    "folder", "version", "versions", "ver", "cve", "cves", "stack", "based",
    "trace", "the", "and", "of", "in", "to", "for", "a", "via", "conversion",
    "overflow", "memory", "corruption", "use-after-free", "integer", "command",
}
_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
_COMPONENT_ALIASES = {
    "tomcat": {"tomcat", "jakarta tomcat", "apache tomcat"},
    "squirrelmail": {"squirrelmail"},
    "struts": {"struts", "apache struts", "struts2", "struts 2"},
    "spring": {"spring", "spring framework", "spring boot", "spring4shell"},
    "fastjson": {"fastjson", "fastjson2", "alibaba fastjson"},
    "shiro": {"apache shiro", "shiro", "shirorememberme"},
    "log4j": {"log4j", "log4j2", "apache log4j", "cve-2021-44228"},
    "log4shell": {"log4shell", "cve-2021-44228"},
    "viewstate": {"viewstate", ".net viewstate"},
    "weblogic": {"weblogic", "oracle weblogic"},
    "jboss": {"jboss", "jboss-as", "jbossapplication"},
    "jenkins": {"jenkins"},
    "nacos": {"nacos"},
    "confluence": {"confluence", "atlassian confluence"},
    "jira": {"jira", "atlassian jira"},
    "drupal": {"drupal"},
    "joomla": {"joomla"},
    "wordpress": {"wordpress", "wp-", "wp "},
    "grafana": {"grafana"},
    "gitlab": {"gitlab"},
    "phpmyadmin": {"phpmyadmin"},
    "exim": {"exim"},
    "openssh": {"openssh", "open ssh"},
    "keycloak": {"keycloak"},
    "solr": {"solr", "apache solr"},
    "elasticsearch": {"elasticsearch"},
    "flink": {"apache flink", "flink"},
    "cassandra": {"cassandra", "apache cassandra"},
    "adminer": {"adminer"},
    "oracle": {"oracle"},
}

_STOPWORDS = {"the", "and", "of", "in", "to", "for", "a", "an", "via", "on", "with", "is", "are"}


# ============================================================
# 数据结构
# ============================================================
@dataclass
class CVEEntry:
    cve_id: str
    name: str
    severity: str
    cvss: Optional[float]
    file_path: str
    description: str
    components: List[str] = field(default_factory=list)
    versions: List[str] = field(default_factory=list)


# ============================================================
# 解析工具
# ============================================================
def _normalize_component(word: str) -> str:
    """组件别名 → 标准名；否则返回小写去空后原词。"""
    lower = word.strip().lower()
    if not lower:
        return ""
    for standard, aliases in _COMPONENT_ALIASES.items():
        if lower in aliases:
            return standard
    return lower


def _extract_components(title: str, description: str) -> List[str]:
    """从名称+描述中抽取组件关键词。返回去重后的标准名列表。"""
    text = f"{title} {description}"
    found: Set[str] = set()

    # 1) 别名精确命中（组合词，替代词表）
    low = text.lower()
    for standard, aliases in _COMPONENT_ALIASES.items():
        if any(alias in low for alias in aliases):
            found.add(standard)

    # 2) 从标题分词：去掉漏洞类型噪声 / 版本 / 停用词，剩余词视为产品候选
    for tok in re.split(r"[\s\-/()\[\].]+", title):
        t = tok.strip().lower()
        if not t or t in _VULN_NOISE or t in _STOPWORDS or len(t) < 2:
            continue
        found.add(t)

    return sorted(found)


def _extract_versions(title: str) -> List[str]:
    """从标题抽取类版本号 token，去重。"""
    return list(dict.fromkeys(_VERSION_RE.findall(title)))


# ============================================================
# CVE 模板解析（Z1.3 增量入库用）
# ============================================================
def parse_cve_template(path: str) -> Optional[CVEEntry]:
    """从单个 nuclei CVE 模板 yaml 解析出 CVEEntry。

    模板结构：info.id / info.name / info.severity / info.classification.cvss-score /
    info.description。返回 None 表示不是带 id 的 CVE 模板。
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = yaml.safe_load(f)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    info = data.get("info") or {}
    # nuclei CVE 模板的 id 通常在顶层（部分在 info.id），两处都取
    cve_id = data.get("id") or info.get("id") or ""
    if not cve_id or not str(cve_id).upper().startswith("CVE-"):
        return None
    name = info.get("name") or cve_id
    desc = info.get("description") or ""
    sev = str(info.get("severity") or "info").lower()
    try:
        cvss = float((info.get("classification") or {}).get("cvss-score") or 0)
    except (TypeError, ValueError):
        cvss = None
    # 模板相对路径（相对 cve 目录，便于定位）；兼容 Win/Linux 分隔符
    norm = path.replace("\\", "/")
    rel = "http/cves/" + norm.split("http/cves/", 1)[-1] if "http/cves" in norm else norm
    return CVEEntry(
        cve_id=str(cve_id).upper(),
        name=name,
        severity=sev,
        cvss=cvss,
        file_path=rel,
        description=desc,
        components=_extract_components(name, desc),
        versions=_extract_versions(name),
    )


def _iter_cve_templates(cve_dir: str) -> List[str]:
    """收集 cve 模板目录下所有 yaml 绝对路径。"""
    if not os.path.isdir(cve_dir):
        return []
    out = []
    for root, _dirs, files in os.walk(cve_dir):
        for fn in files:
            if fn.lower().endswith((".yaml", ".yml")):
                out.append(os.path.join(root, fn))
    return sorted(out)


# ============================================================
# 索引类
# ============================================================
class CVEIndex:
    """CVE 情报索引。

    用法：
        idx = CVEIndex.build()                      # 重新构建并落盘
        idx = CVEIndex()                            # 加载已落盘索引
        hits = idx.search("tomcat")                 # 组件候选
        hits = idx.search("tomcat", version="3.1")  # 组件+版本候选
        n = idx.count                               # 有效 CVE 总数
    """

    def __init__(self, index_dir: Optional[str] = None):
        root = str(PROJECT_ROOT)
        self.index_dir = index_dir or os.path.join(root, _DEFAULT_OUT)
        self.source_path = os.path.join(root, _DEFAULT_SRC)
        # 增量收录文件：sync 时比对上游新增 CVE 模板写入，load 时与主索引合并
        self.extra_path = os.path.join(self.index_dir, "extra_records.jsonl")
        self.records: List[CVEEntry] = []
        # by_component: 标准组件名 → [record index]
        self._by_component: Dict[str, List[int]] = {}

    # ---------- 构建 ----------
    def parse_source(self) -> List[CVEEntry]:
        """解析 NDJSON 源文件，返回记录列表（不落盘）。"""
        if not os.path.exists(self.source_path):
            logger.error(f"[CVEIndex] 源文件不存在: {self.source_path}")
            return []
        entries: List[CVEEntry] = []
        seen: Set[str] = set()
        with open(self.source_path, encoding="utf-8") as f:
            for ln, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                cve_id = obj.get("ID") or ""
                if not cve_id or cve_id in seen:
                    continue
                seen.add(cve_id)
                info = obj.get("Info") or {}
                name = info.get("Name") or cve_id
                severity = (info.get("Severity") or "info").lower()
                desc = info.get("Description") or ""
                try:
                    cvss = float(info.get("Classification", {}).get("CVSSScore") or 0)
                except (TypeError, ValueError):
                    cvss = None
                entries.append(
                    CVEEntry(
                        cve_id=cve_id,
                        name=name,
                        severity=severity,
                        cvss=cvss,
                        file_path=obj.get("file_path") or "",
                        description=desc,
                        components=_extract_components(name, desc),
                        versions=_extract_versions(name),
                    )
                )
        logger.info(f"[CVEIndex] 源解析完成: {len(entries)} 条（去重后）")
        return entries

    def _rebuild_internal_index(self):
        self._by_component = {}
        for i, rec in enumerate(self.records):
            for comp in rec.components:
                self._by_component.setdefault(comp, []).append(i)

    def build(self) -> int:
        """解析源 + 构建内存索引 + 落盘。返回记录数；失败返回 -1。"""
        self.records = self.parse_source()
        if not self.records:
            return -1
        self._rebuild_internal_index()
        os.makedirs(self.index_dir, exist_ok=True)
        self._write_records(self.index_dir)
        self._write_meta(self.index_dir)
        return len(self.records)

    # ---------- 落盘 ----------
    def _records_path(self, d): return os.path.join(d, "records.jsonl")
    def _meta_path(self, d): return os.path.join(d, "index_meta.json")

    def _write_records(self, d):
        tmp = self._records_path(d) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for rec in self.records:
                f.write(json.dumps(asdict(rec), ensure_ascii=False) + "\n")
        os.replace(tmp, self._records_path(d))

    def _write_meta(self, d):
        by_sev = {}
        for rec in self.records:
            by_sev[rec.severity] = by_sev.get(rec.severity, 0) + 1
        meta = {
            "built_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": self.source_path,
            "count": len(self.records),
            "by_severity": by_sev,
            "components": len(self._by_component),
        }
        tmp = self._meta_path(d) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self._meta_path(d))

    # ---------- 加载 ----------
    def load(self) -> bool:
        """从磁盘加载已构建索引（主索引 + 增量额外记录合并）。成功返回 True。"""
        rec_path = self._records_path(self.index_dir)
        if not os.path.exists(rec_path):
            return False
        self.records = []
        seen: Set[str] = set()
        for p in (rec_path, self.extra_path):
            if not os.path.exists(p):
                continue
            with open(p, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    cve_id = d.get("cve_id", "")
                    if not cve_id or cve_id in seen:
                        continue
                    seen.add(cve_id)
                    self.records.append(CVEEntry(**d))
        self._rebuild_internal_index()
        return bool(self.records)

    # ---------- 增量收录（Z1.3） ----------
    def _load_extra_records(self) -> Dict[str, CVEEntry]:
        """读取现有 extra_records.jsonl 为 {cve_id: entry}。"""
        out: Dict[str, CVEEntry] = {}
        if os.path.exists(self.extra_path):
            with open(self.extra_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if d.get("cve_id"):
                        out[d["cve_id"]] = CVEEntry(**d)
        return out

    def _write_extra_records(self, records: Dict[str, CVEEntry]) -> None:
        os.makedirs(os.path.dirname(self.extra_path), exist_ok=True)
        tmp = self.extra_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for cve_id in sorted(records):
                f.write(json.dumps(asdict(records[cve_id]), ensure_ascii=False) + "\n")
        os.replace(tmp, self.extra_path)

    def ingest_records(self, new_entries: List[CVEEntry]) -> int:
        """将新 CVE 记录增量写入 extra_records.jsonl（跳过已存在），返回实际新增数。"""
        if not new_entries:
            return 0
        existing = self._load_extra_records()
        added = 0
        for rec in new_entries:
            if rec.cve_id not in existing:
                existing[rec.cve_id] = rec
                added += 1
        if added:
            self._write_extra_records(existing)
            logger.info(f"[CVEIndex] 增量收录 {added} 条新 CVE 模板 -> {self.extra_path}")
        return added

    def sync_from_templates(self, cve_dir: Optional[str] = None) -> int:
        """比对上游 CVE 模板目录，新增模板增量入库。返回新增数量。

        默认扫描 thirdparty/nuclei-templates/http/cves/。
        """
        if not cve_dir:
            cve_dir = os.path.join(str(PROJECT_ROOT), "thirdparty", "nuclei-templates", "http", "cves")
        new_entries: List[CVEEntry] = []
        for path in _iter_cve_templates(cve_dir):
            rec = parse_cve_template(path)
            if rec:
                new_entries.append(rec)
        return self.ingest_records(new_entries)

    # ---------- 查询 ----------
    @property
    def count(self) -> int:
        return len(self.records)

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for rec in self.records:
            counts[rec.severity] = counts.get(rec.severity, 0) + 1
        return counts

    def search(
        self,
        component: str,
        version: Optional[str] = None,
        min_severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[CVEEntry]:
        """组件(+版本) → 候选 CVE 列表。

        - component 会经别名归一化 + 标题子串匹配（横向放宽，避免漏）。
        - version 存在时仅保留「版本可能命中」或「版本未知」的候选（不误排除）。
        - min_severity 提供严重度阈值下限（critical/high/medium/low/info）。
        - 返回顺序：全量过滤后按「严重度降序 → CVE 年份倒序」排序，再取前 limit 条。
        """
        if not self.records:
            self.load()

        canonical = _normalize_component(component)
        candidates: Set[int] = set()
        if canonical:
            candidates.update(self._by_component.get(canonical, ()))
        low = component.strip().lower()
        if low:
            for i, rec in enumerate(self.records):
                if low in rec.name.lower():
                    candidates.add(i)

        min_rank = _SEVERITY_ORDER.get(min_severity, 0) if min_severity else 0
        version_target = version.strip().lower() if version else None

        out = []
        # 先全量收集通过严重度/版本过滤的候选，再统一排序，最后才截断。
        # 旧实现在循环内就 `if len(out) >= limit: break`，等于"按索引插入顺序
        # 取前 N 条再在切片内排序"——高危/新 CVE 会被老 CVE 挤出候选集，
        # nuclei -id 精扫（phases_executor._execute_cve_scan）因此系统性漏检。
        for i in sorted(candidates):
            rec = self.records[i]
            if _SEVERITY_ORDER.get(rec.severity, -1) < min_rank:
                continue
            if version_target:
                if rec.versions:
                    if not any(vt.startswith(version_target) or version_target.startswith(vt)
                               for vt in rec.versions):
                        continue
            out.append(rec)
        # 排序：严重度降序 → CVE 年份倒序（越新越可能未打补丁）→ ID 稳定兜底
        out.sort(key=lambda r: (
            _SEVERITY_ORDER.get(r.severity, -1),
            _cve_year(r.cve_id),
            r.cve_id or "",
        ), reverse=True)
        return out[:limit]

    def search_all(self, max_items: int = -1) -> List[CVEEntry]:
        """全量候选（按严重度降序），max_items<0 表示不限。"""
        out = sorted(self.records,
                     key=lambda r: _SEVERITY_ORDER.get(r.severity, -1), reverse=True)
        return out[:max_items] if max_items > 0 else out


def build_index(index_dir: Optional[str] = None) -> int:
    """便捷入口：构建并落盘索引，返回 CVE 条数。"""
    idx = CVEIndex(index_dir=index_dir)
    return idx.build()


def sync_cve_index(index_dir: Optional[str] = None) -> Dict:
    """Z1.3 增量同步入口：比对上游新 CVE 模板并增量入库。

    Returns:
        {"scanned": 扫描模板数, "added": 新增入库数, "extra_total": 累计增量条数, "index": 入库后索引总数}
    """
    idx = CVEIndex(index_dir=index_dir)
    added = idx.sync_from_templates()
    # 加载合并（主索引 + 增量）得到可检索总数
    idx.load()
    extra_total = len(idx._load_extra_records())
    return {
        "added": added,
        "extra_total": extra_total,
        "index_total": idx.count,
    }


# ============================================================
# A8.4：情报源接入（NVD / ExploitDB / GitHub Advisory）
# 全部由环境变量开关，未配置则静默跳过（不联网、不影响主流程）。
# 命中后增量写入 extra_records.jsonl，与主索引合并供 _gen_cve_task 检索。
# ============================================================
_NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
_NVD_API_URL = os.environ.get(
    "NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
).strip()
_GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
_EXPLOITDB_PATH = os.environ.get("EXPLOITDB_PATH", "").strip()


def _norm_severity(cvss: Optional[float]) -> str:
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


async def _fetch_nvd(days: int = 7) -> List[CVEEntry]:
    """从 NVD API 拉取近 days 天新增 CVE，归一化为 CVEEntry（需 NVD_API_KEY）。"""
    if not _NVD_API_KEY:
        return []
    try:
        import aiohttp
        from vulnclaw.core.utils import get_shared_session
        session = await get_shared_session()
        start = time.strftime(
            "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - days * 86400)
        )
        params = {"pubStartDate": start, "resultsPerPage": 500}
        headers = {"apiKey": _NVD_API_KEY}
        async with session.get(
            _NVD_API_URL, params=params, headers=headers,
            timeout=aiohttp.ClientTimeout(total=60),
        ) as resp:
            if resp.status != 200:
                logger.warning(f"[情报源] NVD 返回 {resp.status}")
                return []
            data = await resp.json()
        out: List[CVEEntry] = []
        for vuln in (data.get("vulnerabilities") or []):
            c = vuln.get("cve", {})
            cid = c.get("id") or ""
            if not cid:
                continue
            descr = ""
            for d in (c.get("descriptions") or []):
                if d.get("lang") == "en":
                    descr = d.get("value", "")
                    break
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                mm = (c.get("metrics") or {}).get(key)
                if mm:
                    cvss = float(mm[0].get("cvssData", {}).get("baseScore", 0))
                    break
            out.append(CVEEntry(
                cve_id=cid, name=cid, severity=_norm_severity(cvss),
                cvss=cvss, file_path="", description=descr,
                components=_extract_components(cid + " " + descr, descr),
                versions=[],
            ))
        logger.info(f"[情报源] NVD 拉取 {len(out)} 条近 {days} 天 CVE")
        return out
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[情报源] NVD 拉取失败: {e}")
        return []


def _scan_exploitdb() -> List[CVEEntry]:
    """扫描本地 ExploitDB 镜像，抽取 CVE -> exploit 路径，作为 PoC 指针增量收录。"""
    if not _EXPLOITDB_PATH or not os.path.isdir(_EXPLOITDB_PATH):
        return []
    out: List[CVEEntry] = []
    try:
        import csv
        csv_path = os.path.join(_EXPLOITDB_PATH, "files_exploits.csv")
        if os.path.isfile(csv_path):
            with open(csv_path, encoding="utf-8", errors="replace") as f:
                for row in csv.DictReader(f):
                    desc = row.get("description") or ""
                    codes = re.findall(r"CVE-\d{4}-\d+", desc, re.IGNORECASE)
                    path = row.get("path") or row.get("file") or ""
                    for cid in codes:
                        cid = cid.upper()
                        out.append(CVEEntry(
                            cve_id=cid, name=cid, severity="high", cvss=None,
                            file_path=os.path.join(_EXPLOITDB_PATH, path) if path else "",
                            description=f"[ExploitDB] {desc}",
                            components=_extract_components(cid + " " + desc, desc),
                            versions=[],
                        ))
        logger.info(f"[情报源] ExploitDB 抽取 {len(out)} 条 CVE->exploit 映射")
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[情报源] ExploitDB 扫描失败: {e}")
    return out


async def _fetch_github_advisories() -> List[CVEEntry]:
    """从 GitHub Advisory Database 拉取带 CVE 编号的 advisory（需 GITHUB_TOKEN）。"""
    if not _GITHUB_TOKEN:
        return []
    try:
        import aiohttp
        from vulnclaw.core.utils import get_shared_session
        session = await get_shared_session()
        headers = {
            "Authorization": f"Bearer {_GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
        }
        url = ("https://api.github.com/advisories?type=reviewed"
               "&per_page=100&sort=published&direction=desc")
        async with session.get(
            url, headers=headers, timeout=aiohttp.ClientTimeout(total=60)
        ) as resp:
            if resp.status != 200:
                logger.warning(f"[情报源] GitHub Advisory 返回 {resp.status}")
                return []
            data = await resp.json()
        out: List[CVEEntry] = []
        for adv in (data or []):
            cid = (adv.get("cve_id") or "").upper()
            if not cid:
                continue
            sev = (adv.get("severity") or "medium").lower()
            desc = adv.get("summary") or adv.get("description") or ""
            cvss = None
            try:
                cvss = float((adv.get("cvss") or {}).get("score") or 0) or None
            except (TypeError, ValueError):
                pass
            out.append(CVEEntry(
                cve_id=cid, name=cid,
                severity=sev if sev in _SEVERITY_ORDER else "medium",
                cvss=cvss, file_path="", description=desc,
                components=_extract_components(cid + " " + desc, desc),
                versions=[],
            ))
        logger.info(f"[情报源] GitHub Advisory 拉取 {len(out)} 条")
        return out
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[情报源] GitHub Advisory 拉取失败: {e}")
        return []


async def sync_intel_sources(days: int = 7) -> int:
    """A8.4：从已配置的情报源增量更新 cve_index，返回新增条数。

    环境变量开关：NVD_API_KEY / EXPLOITDB_PATH / GITHUB_TOKEN。
    均未配置则直接返回 0（不联网）。
    """
    entries: List[CVEEntry] = []
    nvd = await _fetch_nvd(days)
    if nvd:
        entries.extend(nvd)
    edb = _scan_exploitdb()
    if edb:
        entries.extend(edb)
    gh = await _fetch_github_advisories()
    if gh:
        entries.extend(gh)
    if not entries:
        return 0
    return CVEIndex().ingest_records(entries)


__all__ = [
    "CVEEntry", "CVEIndex", "build_index", "sync_cve_index", "parse_cve_template",
    "sync_intel_sources",
]