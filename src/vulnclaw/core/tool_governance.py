# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""工具治理层（Tool Governance）——平台第六层能力。

四件事（落地方案 A/B 阶段 + C 阶段轻量版）：
1. 目录中心化：core/data/tool_directory.yaml 是受管工具的唯一权威声明。
   版本钉定：升级 = 管理员改 yaml + 显式重装；运行期永不自动升版（结果可复现）。
2. 供应链安全：运行前 sha256 抽检（以 thirdparty/tool_manifest.json 安装记录
   或目录钉定值为基准）→ 不符即隔离（改名 .quarantined-*）→ 治理事件入哈希链。
   抽检按 (path, mtime, size) 记忆，同文件不重复哈希。
3. 健康降级：连续失败 ≥N → TTL 降级；能力解析自动跳过不健康候选；成功即复位。
4. 全量审计：每次调用一行 tool_usage.jsonl；治理事件（隔离/校验失败）进
   哈希审计链（复用 audit_receipt.build_receipt_chain）。

设计红线：治理层任何异常都不得影响工具执行本身（所有钩子吞异常）。
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnclaw.core.audit_receipt import build_receipt_chain
from vulnclaw.core.logger import logger

GOVERNANCE_VERSION = "1.0.0"
_DIR_YAML = Path(__file__).resolve().parent / "data" / "tool_directory.yaml"
_GENESIS = "0" * 64


def _canon(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class ToolGovernance:
    """工具治理引擎：目录 / 完整性 / 健康 / 审计。base_dir 仅测试用。"""

    def __init__(self, base_dir: Optional[str] = None):
        self._dir_cache: Optional[Dict] = None
        self._integrity_memo: Dict[str, Dict] = {}   # name -> {path,mtime,size,verdict}
        self._health_state: Dict[str, Dict] = {}     # name -> {consecutive_failures, degraded_until, last_error}
        self._health_loaded = False
        if base_dir:
            base = Path(base_dir)
            self.health_file = base / "health.json"
            self.usage_file = base / "tool_usage.jsonl"
            self.events_file = base / "integrity_events.json"
            self.chain_file = base / "integrity_chain.json"
            self._thirdparty_dir: Optional[Path] = base / "thirdparty"
        else:
            from vulnclaw.paths import RUNTIME_DIR

            rt = Path(str(RUNTIME_DIR))
            self.health_file = rt / "tools" / "health.json"
            self.usage_file = rt / "metrics" / "tool_usage.jsonl"
            self.events_file = rt / "tools" / "integrity_events.json"
            self.chain_file = rt / "tools" / "integrity_chain.json"
            self._thirdparty_dir = None              # 延迟解析 PROJECT_ROOT/thirdparty

    # ---------------- 目录 ----------------
    def directory(self, force: bool = False) -> Dict:
        if self._dir_cache is None or force:
            try:
                import yaml

                data = yaml.safe_load(_DIR_YAML.read_text(encoding="utf-8")) or {}
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"⚠️ [ToolGov] 目录加载失败，降级为空目录: {exc}")
                data = {"version": 0, "tools": {}, "capabilities": {},
                        "defaults": {"verify_on_use": False}}
            data.setdefault("tools", {})
            data.setdefault("capabilities", {})
            data.setdefault("defaults", {})
            self._dir_cache = data
        return self._dir_cache

    def get_tool(self, name: str) -> Optional[Dict]:
        return self.directory().get("tools", {}).get(name)

    def all_tool_names(self) -> List[str]:
        return list(self.directory().get("tools", {}).keys())

    # ---------------- 健康降级 ----------------
    def _load_health(self) -> None:
        if self._health_loaded:
            return
        try:
            if self.health_file.is_file():
                self._health_state = json.loads(self.health_file.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            self._health_state = {}
        self._health_loaded = True

    def _save_health(self) -> None:
        try:
            self.health_file.parent.mkdir(parents=True, exist_ok=True)
            self.health_file.write_text(
                json.dumps(self._health_state, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[ToolGov] 健康状态落盘失败（忽略）: {exc}")

    def is_healthy(self, name: str) -> bool:
        self._load_health()
        st = self._health_state.get(name)
        if not st:
            return True
        if int(st.get("degraded_until") or 0) > time.time():
            return False
        return True

    def health_snapshot(self, name: str) -> Dict:
        self._load_health()
        st = dict(self._health_state.get(name) or {})
        st["healthy"] = self.is_healthy(name)
        return st

    def record_result(self, name: str, success: bool,
                      duration_ms: int = 0, error: str = "") -> None:
        """健康记录 + 调用审计（tool_usage.jsonl）。"""
        self._load_health()
        max_fail = int(((self.directory().get("defaults") or {}).get("health")
                        or {}).get("max_consecutive_failures", 3))
        ttl = int(((self.directory().get("defaults") or {}).get("health")
                   or {}).get("degraded_ttl_seconds", 600))
        st = self._health_state.setdefault(name, {"consecutive_failures": 0,
                                                  "degraded_until": 0, "last_error": ""})
        if success:
            st["consecutive_failures"] = 0
            st["degraded_until"] = 0
            st["last_error"] = ""
        else:
            st["consecutive_failures"] = int(st.get("consecutive_failures") or 0) + 1
            st["last_error"] = str(error or "")[:200]
            if st["consecutive_failures"] >= max_fail:
                st["degraded_until"] = time.time() + ttl
                logger.warning(
                    f"⚠️ [ToolGov] {name} 连续失败 {st['consecutive_failures']} 次，"
                    f"降级 {ttl}s（能力解析将自动绕过）")
        self._save_health()

        spec = self.get_tool(name) or {}
        row = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "tool": name,
            "capability": spec.get("capability", ""),
            "success": bool(success),
            "duration_ms": int(duration_ms),
            "error": str(error or "")[:200],
        }
        try:
            self.usage_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.usage_file, "a", encoding="utf-8") as fp:
                fp.write(json.dumps(row, ensure_ascii=False) + "\n")
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[ToolGov] 调用审计写失败（忽略）: {exc}")

    def audit_snapshot(self, tail: int = 20) -> Dict:
        self._load_health()
        rows: List[Dict] = []
        try:
            if self.usage_file.is_file():
                lines = self.usage_file.read_text(encoding="utf-8").splitlines()
                rows = [json.loads(x) for x in lines[-tail:] if x.strip()]
        except Exception:  # noqa: BLE001
            rows = []
        chain_root = ""
        try:
            if self.chain_file.is_file():
                chain_root = str(json.loads(
                    self.chain_file.read_text(encoding="utf-8")).get("chain_root", ""))
        except Exception:  # noqa: BLE001
            pass
        return {"usage_tail": rows, "chain_root": chain_root,
                "health": {k: self.health_snapshot(k) for k in self._health_state}}

    # ---------------- 供应链完整性 ----------------
    def _manifest_hash(self, name: str) -> Optional[str]:
        """安装时记录的 SHA256（thirdparty/tool_manifest.json）。"""
        try:
            if self._thirdparty_dir is None:
                from vulnclaw.paths import PROJECT_ROOT

                third = Path(str(PROJECT_ROOT)) / "thirdparty"
            else:
                third = self._thirdparty_dir
            mf = third / "tool_manifest.json"
            if mf.is_file():
                data = json.loads(mf.read_text(encoding="utf-8"))
                ent = data.get(name) or {}
                return str(ent.get("sha256") or "") or None
        except Exception:  # noqa: BLE001
            pass
        return None

    def _pinned_hash(self, name: str) -> Optional[str]:
        spec = self.get_tool(name) or {}
        return str(spec.get("sha256") or "") or None

    def audit_event(self, kind: str, detail: Dict) -> None:
        """治理事件 → 追加进哈希审计链（复用 audit_receipt）。"""
        try:
            events: List[Dict] = []
            if self.events_file.is_file():
                events = json.loads(self.events_file.read_text(encoding="utf-8"))
            events.append({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                           "kind": kind, "detail": detail})
            chain = build_receipt_chain(events, meta={"kind": "tool_governance",
                                                      "version": GOVERNANCE_VERSION})
            self.events_file.parent.mkdir(parents=True, exist_ok=True)
            self.events_file.write_text(json.dumps(events, ensure_ascii=False, indent=2),
                                        encoding="utf-8")
            self.chain_file.write_text(json.dumps(chain, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[ToolGov] 治理事件入链失败（忽略）: {exc}")

    def integrity_check(self, name: str, force: bool = False) -> Dict:
        """运行前完整性抽检。返回 {status: ok|unpinned|absent|quarantined|...}。

        基准 hash 优先级：tool_manifest.json（安装时记录）> 目录钉定值。
        不匹配 → 二进制隔离（改名 .quarantined-<ts>）+ 治理事件入链。
        按 (path, mtime, size) 记忆，同一文件不重复哈希。
        """
        memo = self._integrity_memo.get(name)
        try:
            from vulnclaw.core.tool_registry import resolve_tool_path

            path_str = resolve_tool_path(name)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[ToolGov] 解析工具路径失败: {exc}")
            return {"status": "resolve_error", "error": str(exc)}
        if not path_str:
            return {"status": "absent"}
        path = Path(path_str)
        try:
            stat = path.stat()
            fingerprint = (str(path), stat.st_mtime, stat.st_size)
        except OSError as exc:
            return {"status": "stat_error", "error": str(exc)}
        if not force and memo and memo.get("fingerprint") == fingerprint:
            return memo.get("verdict") or {"status": "unknown"}

        verdict: Dict[str, Any]
        ref = self._manifest_hash(name) or self._pinned_hash(name)
        if not ref:
            verdict = {"status": "unpinned"}
        else:
            try:
                cur = _sha256_file(path)
            except OSError as exc:
                verdict = {"status": "hash_error", "error": str(exc)}
            else:
                if cur == ref:
                    verdict = {"status": "ok", "sha256": cur}
                else:
                    quarantined = path.with_name(
                        path.name + f".quarantined-{time.strftime('%Y%m%d_%H%M%S')}")
                    try:
                        path.rename(quarantined)
                        verdict = {"status": "quarantined", "expected_sha256": ref,
                                   "actual_sha256": cur, "quarantined_to": str(quarantined)}
                        logger.warning(
                            f"🚨 [ToolGov] {name} SHA256 与基准不符，已隔离: {quarantined.name}")
                    except OSError as exc:
                        verdict = {"status": "mismatch_quarantine_failed",
                                   "expected_sha256": ref, "actual_sha256": cur,
                                   "error": str(exc)}
                    self.audit_event("integrity_mismatch", {
                        "tool": name, "expected": ref, "actual": cur,
                        "action": verdict.get("status"),
                    })
        self._integrity_memo[name] = {"fingerprint": fingerprint, "verdict": verdict}
        return verdict

    def pre_run(self, name: str) -> None:
        """运行前钩子：完整性抽检（仅供观测/隔离，绝不阻塞执行）。"""
        if not bool(((self.directory().get("defaults") or {}).get("verify_on_use"))):
            return
        try:
            verdict = self.integrity_check(name)
            if verdict.get("status") == "quarantined":
                # 隔离后二进制缺失 → 上层自然走失败/降级链
                logger.warning(f"🚨 [ToolGov] {name} 已因完整性校验失败被隔离")
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[ToolGov] pre_run 异常（忽略）: {exc}")

    def post_run(self, name: str, success: bool,
                 duration_ms: int = 0, error: str = "") -> None:
        try:
            self.record_result(name, success=success,
                               duration_ms=duration_ms, error=error)
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[ToolGov] post_run 异常（忽略）: {exc}")

    # ---------------- 能力解析（降级链） ----------------
    def resolve_capability(self, capability: str) -> List[Dict]:
        """能力 → 按序候选（缺失/不健康自动跳过；全灭时附内置兜底标记）。"""
        cap = (self.directory().get("capabilities") or {}).get(capability) or {}
        out: List[Dict] = []
        for cand in cap.get("candidates") or []:
            healthy = self.is_healthy(cand)
            try:
                from vulnclaw.core.tool_registry import resolve_tool_path

                available = resolve_tool_path(cand) is not None
            except Exception:  # noqa: BLE001
                available = False
            out.append({"tool": cand, "available": available,
                        "healthy": healthy, "usable": available and healthy})
        if cap.get("builtin_fallback") and cap.get("builtin_fallback") != "none":
            if not any(e.get("usable") for e in out):
                out.append({"tool": cap["builtin_fallback"], "builtin": True,
                            "usable": True, "note": "全部外部候选不可用，启用内置兜底"})
        return out

    # ---------------- 总览 ----------------
    def status_snapshot(self) -> Dict:
        tools = []
        for name in self.all_tool_names():
            spec = self.get_tool(name) or {}
            try:
                from vulnclaw.core.tool_registry import resolve_tool_path

                available = resolve_tool_path(name) is not None
            except Exception:  # noqa: BLE001
                available = False
            tools.append({
                "name": name,
                "capability": spec.get("capability", ""),
                "danger": spec.get("danger", "safe"),
                "pinned_version": spec.get("ver", ""),
                "available": available,
                "health": self.health_snapshot(name),
                "integrity": self.integrity_check(name),
            })
        chain_root = ""
        try:
            if self.chain_file.is_file():
                chain_root = str(json.loads(
                    self.chain_file.read_text(encoding="utf-8")).get("chain_root", ""))
        except Exception:  # noqa: BLE001
            pass
        return {"governance_version": GOVERNANCE_VERSION,
                "directory_version": self.directory().get("version"),
                "tools": tools, "integrity_chain_root": chain_root}

    def verify_all(self) -> List[Dict]:
        """强制全量完整性校验（CLI tools verify）。"""
        return [dict(self.integrity_check(name, force=True), tool=name)
                for name in self.all_tool_names()]


_GOV: Optional[ToolGovernance] = None


def get_governance(base_dir: Optional[str] = None) -> ToolGovernance:
    """进程级单例；base_dir 仅测试/隔离场景用（返回独立实例）。"""
    global _GOV
    if base_dir is not None:
        return ToolGovernance(base_dir=base_dir)
    if _GOV is None:
        _GOV = ToolGovernance()
    return _GOV


__all__ = ["ToolGovernance", "get_governance", "GOVERNANCE_VERSION"]
