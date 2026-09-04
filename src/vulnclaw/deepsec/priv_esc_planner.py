# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# deepsec/priv_esc_planner.py
"""
权限提升路径规划（C2.2，受控）—— 低权 shell → 提权点枚举 → 逐步尝试。

安全铁律（受控）：
  1. 枚举 = 只读命令（uname/id/sudo -l/SUID 查找/组/cron/环境变量），零副作用。
  2. 尝试（attempt）= 每步先经 danger_guard.require_approval("privilege_escalation")，
     deny 模式一律拒绝，命令不落地；仅 allow 模式 + 显式放行才执行验证命令。
  3. attempt 命令全部为"验证型"（sudo -n true / docker ps / ls SUID 条目等），
     不写入文件、不修改权限、不反弹 shell，只确认提权面是否存在。
  4. 产物为链图 JSON：{finding_id, strategy, success, chain:[gate:approval → priv_esc:<step>]}，
     可被 AttackGraph.from_chains 消费（E1.4 双端统一图模型）。
  5. 代码与日志不含 emoji（Windows GBK 控制台安全）。
"""
import json
from typing import Dict, List, Optional

from vulnclaw.core.danger_guard import guard as _default_guard
from vulnclaw.core.logger import logger

# 只读枚举命令表（platform=auto 时先 uname 探测，再选对应命令集）
LINUX_ENUM = [
    "uname -a",
    "id",
    "sudo -l",
    "find / -perm -4000 -type f 2>/dev/null",
    "groups",
    "cat /etc/crontab 2>/dev/null",
    "ls -la /var/spool/cron 2>/dev/null",
    "cat /etc/passwd 2>/dev/null",
    "env",
    "ip a 2>/dev/null || ifconfig",
]
WINDOWS_ENUM = [
    "whoami /all",
    "net user",
    "net localgroup administrators",
    "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    "sc query type= service",
    "systeminfo",
]


class PrivEscPlanner:
    """受控提权路径规划器。

    Args:
        channel: 命令通道（实现 async execute_command(cmd, context) -> str）。
            不传 = 纯规划模式（仅 plan，不 execute）。
        guard: DangerGuard 实例（默认进程级单例；测试可注入假守卫）。
        target: 目标资产标识（链图 asset 节点）。
        finding_id: 触发提权规划的依据 finding（链图 vuln 节点）。
    """

    # 提权候选向量分类表：(strategy, 枚举特征正则, 验证命令, 说明)
    VECTORS = [
        ("sudo_nopasswd", r"nopasswd", "sudo -n true",
         "sudo NOPASSWD 条目：当前用户可免密提权执行命令"),
        ("suid_binary", r"rwsr", "true",
         "SUID 二进制存在：可尝试已知提权利用（gtfo-bins）"),
        ("docker_group", r"\bdocker\b", "docker ps",
         "当前用户属 docker 组：docker run 挂载宿主可提权"),
        ("writable_world", r"rwrwrw", "true",
         "全局可写可疑文件/目录存在：可尝试文件置换提权"),
        ("cron_root", r"root.*(cron|crontab)", "true",
         "root 定时任务可见：可尝试替换可写脚本提权"),
    ]

    def __init__(self, channel=None, guard=None, target: str = "", finding_id: str = ""):
        self.channel = channel
        self.guard = guard if guard is not None else _default_guard
        self.target = target or ""
        self.finding_id = finding_id or "priv_esc"
        self._enum_results: List[Dict] = []
        self._plan: List[Dict] = []
        self._plan_outputs: Dict[str, str] = {}

    # ---------- 只读枚举 ----------
    async def enumerate(self, platform: str = "auto", timeout: float = 8.0) -> List[Dict]:
        """执行只读枚举，产出结构化候选向量（每条含命令/输出摘要/命中候选）。"""
        if self.channel is None:
            return []
        cmds = list(LINUX_ENUM)
        if platform == "windows":
            cmds = list(WINDOWS_ENUM)
        elif platform == "auto":
            try:
                probe = await self.channel.execute_command(
                    "uname -s", {"url": self.target}
                )
                if isinstance(probe, str) and "windows" in probe.lower():
                    cmds = list(WINDOWS_ENUM)
            except Exception:  # noqa: BLE001
                pass
        results: List[Dict] = []
        for cmd in cmds:
            try:
                out = str(await self.channel.execute_command(cmd, {"url": self.target}) or "")
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"[PrivEsc] 枚举命令失败 {cmd}: {exc}")
                out = ""
            results.append({
                "cmd": cmd,
                "output": out[:400],
                "matched": self._match_vectors(out),
                "duration_ms": 0,
            })
        self._enum_results = results
        self._plan = self._build_plan(results)
        return results

    def _match_vectors(self, text: str) -> List[str]:
        low = str(text or "").lower()
        hits = []
        for strategy, pattern, _cmd, _note in self.VECTORS:
            import re
            if re.search(pattern, low, re.I):
                hits.append(strategy)
        return hits

    # ---------- 规划 ----------
    def _build_plan(self, results: List[Dict]) -> List[Dict]:
        """枚举结果 → 链图 step 序列（enum 已执行 / attempt 待审批 / verify 校验）。"""
        plan: List[Dict] = []
        all_vecs: set = set()
        suid_path, cron_path = "", ""
        for r in results:
            all_vecs.update(r.get("matched", []))
            if "suid_binary" in r.get("matched", []):
                m = __import__("re").findall(
                    r"-rws[a-z-]*\s+\d+\s+\w+\s+\w+\s+\d+\s+[\w./-]+", r.get("output", "")
                )
                if m:
                    suid_path = m[-1].split()[-1]
            if "cron_root" in r.get("matched", []):
                m = __import__("re").findall(r"\S+", r.get("output", ""))
                if m:
                    cron_path = m[-1]
        for step in results:
            plan.append({
                "id": f"enum:{step['cmd'][:24].replace(' ', '_')}",
                "kind": "enum",
                "cmd": step["cmd"],
                "strategy": "enum",
                "matched": step["matched"],
                "approved": True,
                "status": "done",
            })
        for strategy, _pat, base_cmd, note in self.VECTORS:
            if strategy not in all_vecs:
                continue
            cmd = base_cmd
            if strategy == "suid_binary" and suid_path:
                cmd = f"ls -l {suid_path}"
            if strategy == "cron_root" and cron_path:
                cmd = f"cat {cron_path}"
            plan.append({
                "id": f"attempt:{strategy}",
                "kind": "attempt",
                "cmd": cmd,
                "strategy": strategy,
                "note": note,
                "approved": False,
                "status": "pending_approval",
            })
        plan.append({
            "id": "verify:priv_esc_summary",
            "kind": "verify",
            "cmd": "",
            "strategy": "verify",
            "approved": True,
            "status": "pending",
        })
        return plan

    def plan(self) -> List[Dict]:
        """返回链图 step 序列（JSON 安全：无自定义对象）。"""
        if not self._plan:
            self._plan = self._build_plan(self._enum_results)
        return list(self._plan)

    # ---------- 受控执行 ----------
    async def execute(self) -> Dict:
        """逐步尝试：每个 attempt 先经 DangerGuard 审批，deny → 命令不落地。

        Returns:
            {finding_id, strategy, success, target, chain:[{node, strategy, success}]}
            结果可直接交给 AttackGraph.from_chains（E1.4 双端消费）。
        """
        chain: List[Dict] = []
        success = False
        strategy = "priv_esc"
        allowed_any = False
        for step in self.plan():
            if step["kind"] == "attempt":
                ok = self.guard.require_approval(
                    "privilege_escalation",
                    detail=f"{step['strategy']}: {step['cmd']} @ {self.target}",
                )
                if not ok:
                    chain.append({"node": "gate:approval", "strategy": "denied"})
                    logger.info(
                        f"[PrivEsc] 审批拒绝，跳过 {step['strategy']}（命令未落地）"
                    )
                    continue
                allowed_any = True
                out = ""
                if self.channel is not None:
                    try:
                        out = str(await self.channel.execute_command(
                            step["cmd"], {"url": self.target}
                        ) or "")
                    except Exception as exc:  # noqa: BLE001
                        logger.debug(f"[PrivEsc] attempt 执行异常 {step['cmd']}: {exc}")
                        out = ""
                self._plan_outputs[step["id"]] = out
                step_success = self._judge(step["strategy"], out)
                step["approved"] = True
                step["status"] = "done" if step_success else "failed"
                chain.append({
                    "node": f"priv_esc:{step['strategy']}",
                    "strategy": step["strategy"],
                    "success": step_success,
                })
                if step_success:
                    success = True
        if allowed_any:
            chain.insert(0, {
                "node": "gate:approval", "strategy": "allow", "success": True,
            })
        chain.append({"node": "verify:priv_esc_summary", "strategy": "verify"})
        return {
            "finding_id": self.finding_id,
            "strategy": strategy,
            "success": success,
            "target": self.target,
            "chain": chain,
        }

    @staticmethod
    def _judge(strategy: str, out: str) -> bool:
        """attempt 成功判定：输出非空且无"拒绝/不存在"字样（保守，宁少报）。"""
        low = str(out or "").lower()
        denials = ("permission denied", "denied", "not found", "no such", "unknown option",
                   "command not found", "couldn't open", "cannot open")
        if any(d in low for d in denials):
            return False
        return bool(str(out or "").strip())

    # ---------- JSON 往返（E1.4 / 持久化） ----------
    def to_json(self) -> str:
        return json.dumps({
            "target": self.target,
            "finding_id": self.finding_id,
            "plan": self.plan(),
            "enum_results": self._enum_results,
        }, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> "PrivEscPlanner":
        data = json.loads(text)
        p = cls(target=data.get("target", ""), finding_id=data.get("finding_id", ""))
        p._plan = data.get("plan", [])
        p._enum_results = data.get("enum_results", [])
        return p