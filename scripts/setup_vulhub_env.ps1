# Vulhub 真实靶场环境自动准备（一键脚本）
#
# 用法（只需 2 次人工操作）：
#   1. 资源管理器里右键本文件 -> "使用 PowerShell 运行"
#      （首次会弹 UAC 用户账户控制，点"是"即可；本机当前为非管理员终端）
#   2. 脚本跑完会提示重启 -> 重启系统一次
#   3. 重启后到 https://www.docker.com/products/docker-desktop/ 下载安装 Docker Desktop
#      （安装时务必勾选 "Use the WSL 2 backend"，Windows 10 Home 无 Hyper-V）
#   4. 启动 Docker Desktop，鲸鱼图标变绿后，告诉我，我来跑 `python scripts/lab_vulhub.py --pin`
#
# 说明：本机为 Windows 10 Home China，无 Hyper-V，Vulhub 的 Linux 容器只能走 WSL2 后端；
#       下方命令启用 WSL2 特性并安装 Ubuntu 发行版（联网下载，约数百 MB）。

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
$ErrorActionPreference = "Continue"

Write-Host "=== 1/3 启用 WSL2 + 虚拟机平台（需管理员）==="
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

Write-Host "=== 2/3 安装 Ubuntu 发行版（联网下载）==="
wsl --install -d Ubuntu

Write-Host "=== 3/3 完成提示 ==="
Write-Host "WSL2 + Ubuntu 安装中。完成后请【重启系统一次】。"
Write-Host "重启后安装 Docker Desktop（务必选 WSL 2 backend）："
Write-Host "  https://www.docker.com/products/docker-desktop/"
Write-Host "Docker 启动变绿后，运行 Vulnclaw 的 lab_vulhub.py 即可真实执行 10 个 Vulhub 场景。"
