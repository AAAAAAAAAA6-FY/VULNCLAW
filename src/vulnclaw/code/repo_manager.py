# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 2 模块 1：代码仓库管理器。

职责：clone 仓库到临时目录 → 供代码扫描引擎使用 → 扫描完成后清理。
支持 Git URL、本地路径、压缩包三种输入。
"""
import asyncio
import os
import shutil
import zipfile
from typing import Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import get_tool_path


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
            # 本地目录：优先符号链接，Windows 无权限时降级为复制
            try:
                os.symlink(os.path.abspath(url), dest)
                logger.info(f"📦 [RepoManager] 本地目录链接: {url} → {dest}")
            except (OSError, NotImplementedError):
                shutil.copytree(url, dest)
                logger.info(f"📦 [RepoManager] 本地目录复制(降级): {url} → {dest}")
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
        """解压压缩包到目标目录。"""
        if archive_path.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(dest)
        else:
            import tarfile
            with tarfile.open(archive_path, "r:gz") as tf:
                tf.extractall(dest)
        logger.info(f"📦 [RepoManager] 解压完成: {archive_path} → {dest}")

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
