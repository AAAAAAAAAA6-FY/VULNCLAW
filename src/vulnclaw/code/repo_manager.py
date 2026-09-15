# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 2 模块 1：代码仓库管理器。

职责：clone 仓库到临时目录 → 供代码扫描引擎使用 → 扫描完成后清理。
支持 Git URL、本地路径、压缩包三种输入。

安全边界（2026-09-15 安全审计 P0-1/P0-2 修复）：
  - **归档路径穿越（Zip Slip）**：`extractall()` 直接信任成员名，`../../`、
    绝对路径、符号链接成员可写出 dest 之外。现在逐成员校验：拒绝绝对路径/
    盘符/`..`/链接类/设备类成员，`realpath` 后必须仍落在 dest 下；并加
    成员数/解压体积上限防压缩包炸弹。
  - **本地目录越界**：过去 `os.symlink(abspath(url), dest)` 无边界，可把
    `code.audit` 变成任意本地目录读取器（且 symlink 让边界永久外扩）。
    现在：源路径自身是链接则拒绝；默认**复制而非链接**（symlinks=False，
    逐文件边界校验）；配置了 `code_audit_allowed_roots` 时强制根校验。
"""
import asyncio
import os
import shutil
import zipfile
from typing import Iterable, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import get_tool_path

# 压缩包炸弹防护上限
_MAX_MEMBERS = 20000
_MAX_UNCOMPRESSED = 512 * 1024 * 1024  # 512MB


def _is_within(base: str, target: str) -> bool:
    """target（已 realpath）是否仍位于 base（已 realpath）之内。"""
    try:
        b = os.path.realpath(base)
        t = os.path.realpath(target)
    except OSError:
        return False
    return t == b or t.startswith(b + os.sep) or t.startswith(b + "/")


def _unsafe_member(name: str) -> bool:
    """归档成员名是否危险：绝对路径/盘符/UNC/上级引用/空。"""
    if not name:
        return True
    n = name.replace("\\", "/")
    if n.startswith("/") or n.startswith("//"):
        return True
    if len(n) >= 2 and n[1] == ":":          # C:/...
        return True
    if n.startswith("\\\\"):
        return True
    parts = [p for p in n.split("/") if p not in ("", ".")]
    return any(p == ".." for p in parts)


def _allowed_roots() -> list:
    """显式批准的代码审计根目录（配置为空=不强制，仅记录告警）。"""
    try:
        from vulnclaw.config.settings import settings
        raw = str(getattr(settings, "code_audit_allowed_roots", "") or "")
    except Exception:  # noqa: BLE001
        return []
    return [os.path.realpath(p.strip()) for p in raw.split(",") if p.strip()]


def _within_allowed_roots(path: str) -> bool:
    roots = _allowed_roots()
    if not roots:
        return True
    rp = os.path.realpath(path)
    return any(rp == r or rp.startswith(r + os.sep) or rp.startswith(r + "/")
               for r in roots)


class RepoManager:
    """代码仓库管理器：clone → 供扫描 → cleanup。"""

    def __init__(self, workspace: Optional[str] = None):
        """初始化仓库管理器。

        Args:
            workspace: 工作目录，默认为 _runtime_cache/code_workspace/
        """
        self.workspace = workspace or "_runtime_cache/code_workspace"
        self._cloned_dirs: list[str] = []

    async def clone_repo(self, url: str, branch: str = "main") -> str:
        """Clone 仓库到临时目录。

        支持三种输入：
        - Git URL (https://github.com/...): 使用 git clone
        - 本地目录: 创建符号链接
        - 压缩包 (.zip/.tar.gz): 解压

        Args:
            url: Git URL / 本地路径 / 压缩包路径。
            branch: 分支名（仅 Git URL 有效）。

        Returns:
            Clone 后的本地目录路径。

        Raises:
            RuntimeError: clone 失败。
        """
        repo_name = self._extract_repo_name(url)
        dest = os.path.join(self.workspace, repo_name)
        os.makedirs(self.workspace, exist_ok=True)

        # 如果目标目录已存在，先清理
        if os.path.exists(dest):
            shutil.rmtree(dest, ignore_errors=True)

        if url.startswith(("http://", "https://", "git@")) or url.endswith(".git"):
            await self._git_clone(url, branch, dest)
        elif os.path.isdir(url):
            # 本地目录：P0-2 —— 拒绝源链接、强制根校验、复制而非链接
            src = os.path.realpath(url)
            if os.path.islink(url):
                raise RuntimeError(
                    f"拒绝符号链接源目录（边界可被外扩）: {url} → {src}")
            if not _within_allowed_roots(src):
                raise RuntimeError(
                    f"本地目录不在批准根目录内（code_audit_allowed_roots）: {src}")
            shutil.copytree(src, dest, symlinks=False)  # symlinks=False → 复制内容不建链接
            logger.info(f"📦 [RepoManager] 本地目录复制(边界已校验): {src} → {dest}")
        elif url.endswith((".zip", ".tar.gz", ".tgz")):
            await self._extract_archive(url, dest)
        else:
            raise RuntimeError(f"不支持的 URL 格式: {url}")

        self._cloned_dirs.append(dest)
        logger.info(f"📦 [RepoManager] 仓库就绪: {dest}")
        return dest

    async def _git_clone(self, url: str, branch: str, dest: str) -> None:
        """执行 git clone。"""
        git_path = get_tool_path("git") or "git"
        cmd = [git_path, "clone", "--depth", "1", "--branch", branch, url, dest]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(
                f"git clone 失败 (exit={process.returncode}): {stderr.decode().strip()}"
            )
        logger.info(f"📦 [RepoManager] git clone 成功: {url}")

    async def _extract_archive(self, archive_path: str, dest: str) -> None:
        """解压压缩包到目标目录（P0-1：逐成员防穿越 + 防炸弹）。

        任何可疑成员一律**跳过并告警**（不抛错中断整包，但绝不写出 dest 之外）。
        """
        dest_root = os.path.realpath(dest)
        os.makedirs(dest_root, exist_ok=True)
        skipped = 0
        extracted = 0
        total_size = 0

        def _bump_size(n: int) -> None:
            nonlocal total_size
            total_size += int(n or 0)
            if total_size > _MAX_UNCOMPRESSED:
                raise RuntimeError(
                    f"解压体积超上限 {_MAX_UNCOMPRESSED} 字节（疑似压缩包炸弹）")

        if archive_path.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as zf:
                infos = zf.infolist()
                if len(infos) > _MAX_MEMBERS:
                    raise RuntimeError(f"归档成员数超上限: {len(infos)}")
                for info in infos:
                    if _unsafe_member(info.filename):
                        skipped += 1
                        continue
                    # 符号链接/设备类成员（zip 外部属性高位存 Unix mode）
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode in (0o120000, 0o100000, 0o020000, 0o060000):
                        skipped += 1  # symlink/regular?/chardev/blockdev
                        continue
                    target = os.path.realpath(os.path.join(dest_root, info.filename))
                    if not _is_within(dest_root, target):
                        skipped += 1
                        continue
                    _bump_size(info.file_size)
                    zf.extract(info, dest_root)
                    extracted += 1
        else:
            import tarfile
            with tarfile.open(archive_path, "r:gz") as tf:
                members = tf.getmembers()
                if len(members) > _MAX_MEMBERS:
                    raise RuntimeError(f"归档成员数超上限: {len(members)}")
                safe = []
                for m in members:
                    if m.issym() or m.islnk() or m.isdev() or m.isfifo():
                        skipped += 1
                        continue
                    if not (m.isfile() or m.isdir()):
                        skipped += 1
                        continue
                    if _unsafe_member(m.name):
                        skipped += 1
                        continue
                    target = os.path.realpath(os.path.join(dest_root, m.name))
                    if not _is_within(dest_root, target):
                        skipped += 1
                        continue
                    _bump_size(m.size)
                    safe.append(m)
                    extracted += 1
                # filter="data"（Python 3.12+）作为第二道防线：拦链接/设备/绝对路径
                try:
                    tf.extractall(dest_root, members=safe, filter="data")
                except TypeError:  # 旧 Python 无 filter 参数
                    tf.extractall(dest_root, members=safe)

        if skipped:
            logger.warning(f"🚫 [RepoManager] 跳过 {skipped} 个越界/危险归档成员")
        logger.info(
            f"📦 [RepoManager] 解压完成: {archive_path} → {dest_root}（{extracted} 个成员）")

    def _extract_repo_name(self, url: str) -> str:
        """从 URL 中提取仓库名。"""
        if url.endswith(".git"):
            url = url[:-4]
        name = url.rstrip("/\\").replace("\\", "/").split("/")[-1]
        if name.endswith((".zip", ".tar.gz", ".tgz")):
            name = name.rsplit(".", 2)[0] if name.endswith(".tar.gz") else name.rsplit(".", 1)[0]
        return name or "repo"

    def cleanup(self) -> None:
        """清理所有已 clone 的目录。"""
        for d in self._cloned_dirs:
            if os.path.islink(d):
                os.unlink(d)
            elif os.path.isdir(d):
                shutil.rmtree(d, ignore_errors=True)
        self._cloned_dirs.clear()
        logger.info("🧹 [RepoManager] 清理完成")


# --- 全局单例 ---
_repo_manager: Optional[RepoManager] = None


def get_repo_manager() -> RepoManager:
    global _repo_manager
    if _repo_manager is None:
        _repo_manager = RepoManager()
    return _repo_manager
