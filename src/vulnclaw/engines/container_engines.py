# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""
容器/K8s 安全检测引擎
检测 Docker/Kubernetes 配置风险（特权容器、敏感挂载、危险 capability 等）
"""
import re
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import async_get
from vulnclaw.engines.base import BaseEngine


__all__ = ['ContainerSecurityEngine']
class ContainerSecurityEngine(BaseEngine):
    """容器/Kubernetes 配置风险检测引擎"""

    name = "container_security"
    description = "检测 Docker/Kubernetes 配置风险"

    # 敏感挂载路径
    SENSITIVE_MOUNTS = [
        "/var/run/docker.sock",
        "/",
        "/etc",
        "/root",
        "/home",
        "/proc",
        "/sys",
    ]

    # 危险 capability
    DANGEROUS_CAPS = [
        "CAP_SYS_ADMIN",
        "CAP_NET_RAW",
        "CAP_NET_ADMIN",
        "CAP_SYS_PTRACE",
        "CAP_SYS_MODULE",
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_SYS_RAWIO",
        "CAP_SYSLOG",
        "CAP_SYS_TIME",
        "CAP_SYS_BOOT",
        "CAP_SYS_TTY_CONFIG",
        "CAP_SYS_CHROOT",
        "CAP_SYS_RESOURCE",
    ]

    # 检测模式：文件路径 → 风险描述
    RISK_INDICATORS = {
        r"/var/run/docker\.sock": "Docker socket 挂载，可逃逸容器",
        r"/proc/self/root": "根文件系统挂载，可访问宿主机文件",
        r"/etc/kubernetes": "Kubernetes 配置目录挂载",
        r"/var/lib/kubelet": "Kubelet 数据目录挂载",
        r"securityContext\.privileged.*true": "特权容器模式启用",
        r"runAsUser.*0": "容器以 root 用户运行",
        r"readOnlyRootFilesystem.*false": "根文件系统可写",
        r"allowPrivilegeEscalation.*true": "允许权限提升",
    }

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        """检测单个 URL 中的容器配置风险"""
        if isinstance(normal_resp, tuple):
            text = normal_resp[1]
            normal_resp[2] if len(normal_resp) > 2 else {}
        else:
            text = await normal_resp.text()

        findings = []

        # 1. 检测响应中的风险特征
        for pattern, desc in self.RISK_INDICATORS.items():
            if re.search(pattern, text, re.IGNORECASE):
                findings.append({
                    "type": f"容器配置风险: {desc}",
                    "severity": "High",
                    "evidence": f"检测到模式: {pattern}",
                    "confidence": "高",
                    "url": url,
                })

        if findings:
            # 返回最高危的发现
            findings.sort(key=lambda x: 0 if x.get("severity") == "Critical" else 1 if x.get("severity") == "High" else 2)
            return findings[0]

        return None

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """全局扫描容器/K8s 配置风险"""
        findings = []
        logger.info(f"🔍 [ContainerSecurity] 扫描容器配置风险: {target}")

        try:
            # 尝试获取 kube-system 命名空间信息（K8s 环境）
            kube_urls = [
                f"{target.rstrip('/')}/api/v1/namespaces/kube-system/pods",
                f"{target.rstrip('/')}/api/v1/nodes",
                f"{target.rstrip('/')}/api/v1/pods",
            ]

            for url in kube_urls[:3]:
                try:
                    resp = await async_get(url, session=session, timeout=5)
                    if isinstance(resp, tuple):
                        text = resp[1]
                        status = resp[0]
                    else:
                        text = await resp.text()
                        status = resp.status

                    if status == 200 and "items" in text:
                        # 检测 K8s 配置风险
                        risk_finding = await self.check(url, "config", (status, text, {}), "", session)
                        if risk_finding:
                            findings.append(risk_finding)
                            break
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"ContainerSecurity 扫描异常: {e}")

        logger.info(f"   ✅ ContainerSecurity 完成，发现 {len(findings)} 个风险")
        return findings