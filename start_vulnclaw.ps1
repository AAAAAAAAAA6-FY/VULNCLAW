#!/usr/bin/env pwsh
<#
.SYNOPSIS
    VULNCLAW 渗透测试平台启动脚本（Windows PowerShell）

.DESCRIPTION
    一键启动：检查环境 → 配置 → 健康检查 → 启动扫描

.PARAMETER Target
    目标 URL（必填）

.PARAMETER Mode
    运行模式：single（默认）/ dag / deep / code

.PARAMETER Agents
    DAG 模式并行 Agent 数量（默认 3）

.PARAMETER MaxTasks
    最大任务数（默认 200）

.PARAMETER QPS
    初始 QPS（默认 3）

.PARAMETER Deep
    启用深度利用链（生成 POC）

.PARAMETER Dangerous
    危险模式：实际执行利用（配合 -Deep 使用）

.PARAMETER Code
    启用代码安全扫描

.PARAMETER Repo
    代码仓库 URL（配合 -Code 使用）

.PARAMETER Health
    仅运行健康检查

.PARAMETER Help
    显示帮助

.EXAMPLE
    .\start_vulnclaw.ps1 -Target http://testphp.vulnweb.com

.EXAMPLE
    .\start_vulnclaw.ps1 -Target http://target.com -Mode dag -Agents 6

.EXAMPLE
    .\start_vulnclaw.ps1 -Target http://target.com -Deep -Dangerous
#>

param(
    [string]$Target,
    [ValidateSet("single", "dag", "deep", "code")]
    [string]$Mode = "single",
    [int]$Agents = 3,
    [int]$MaxTasks = 200,
    [int]$QPS = 3,
    [switch]$Deep,
    [switch]$Dangerous,
    [switch]$Code,
    [string]$Repo,
    [string]$Lang = "python",
    [switch]$Health,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# 禁止 Python 写入 .pyc/__pycache__，防止根目录出现缓存垃圾
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PYTHONPYCACHEPREFIX = ""

# ---------- Nuclei / uncover 配置目录重定向 ----------
# 说明：nuclei-cli 在 Windows 下默认写 `$HOME/.config/`，如果 $HOME 没设
# 或指向项目根，会在根目录生成 .config/nuclei / .config/uncover 垃圾。
# 全部重定向到 _runtime_cache/tools/
$ToolsDir = Join-Path $ScriptDir "_runtime_cache\tools"
foreach ($sub in @("nuclei","uncover")) {
    New-Item -ItemType Directory -Force -Path (Join-Path $ToolsDir $sub) | Out-Null
}
$env:HOME                = $ToolsDir
$env:USERPROFILE         = $ToolsDir
$env:NUCLEI_CONFIG_DIR   = Join-Path $ToolsDir "nuclei"
$env:UNCOVER_CONFIG_DIR  = Join-Path $ToolsDir "uncover"
$env:TQDM_DISABLE        = "1"

# 清理根目录残留的 .config/__pycache__（如果在更早的操作中已生成）
foreach ($junk in @("$(Join-Path $ScriptDir '.config')","$(Join-Path $ScriptDir '__pycache__')","$(Join-Path $ScriptDir '.pytest_cache')")) {
    if (Test-Path $junk) { Remove-Item -Recurse -Force $junk -ErrorAction SilentlyContinue }
}

# 颜色输出函数
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success { Write-ColorOutput $args "Green" }
function Write-Info { Write-ColorOutput $args "Cyan" }
function Write-Warning { Write-ColorOutput $args "Yellow" }
function Write-Error { Write-ColorOutput $args "Red" }

# 显示 Banner
function Show-Banner {
    Write-Host ""
    Write-ColorOutput "╔════════════════════════════════════════════════════════════╗" "Magenta"
    Write-ColorOutput "║                    VULNCLAW 渗透测试平台                    ║" "Magenta"
    Write-ColorOutput "║                   v100 限流感知版 · Sprint 3                ║" "Magenta"
    Write-ColorOutput "╚════════════════════════════════════════════════════════════╝" "Magenta"
    Write-Host ""
}

# 检查 Python 版本
function Check-Python {
    Write-Info "[1/4] 检查 Python 环境..."

    $pythonCmd = $null
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            $version = & $cmd --version 2>&1
            if ($version -match "Python (\d+)\.(\d+)") {
                $major = [int]$Matches[1]
                $minor = [int]$Matches[2]
                if ($major -ge 3 -and $minor -ge 11) {
                    $pythonCmd = $cmd
                    Write-Success "   ✅ 找到 Python $major.$minor ($cmd)"
                    break
                } else {
                    Write-Warning "   ⚠️ $cmd 版本 $major.$minor < 3.11，跳过"
                }
            }
        } catch { }
    }

    if (-not $pythonCmd) {
        Write-Error "   ❌ 未找到 Python >= 3.11"
        Write-Info "   请从 https://www.python.org/downloads/ 安装 Python 3.11+"
        exit 1
    }

    return $pythonCmd
}

# 检查虚拟环境
function Check-Venv {
    param([string]$PythonCmd)

    Write-Info "[2/4] 检查虚拟环境..."

    $venvPath = Join-Path $ScriptDir "venv"
    $activateScript = Join-Path $venvPath "Scripts\Activate.ps1"

    if (Test-Path $activateScript) {
        Write-Success "   ✅ 虚拟环境已存在"
    } else {
        Write-Info "   创建虚拟环境..."
        & $PythonCmd -m venv $venvPath
        if ($LASTEXITCODE -ne 0) {
            Write-Error "   ❌ 创建虚拟环境失败"
            exit 1
        }
        Write-Success "   ✅ 虚拟环境创建成功"
    }

    # 激活虚拟环境
    & $activateScript

    # 安装依赖
    Write-Info "   检查依赖..."
    $requirementsPath = Join-Path $ScriptDir "requirements.txt"
    if (-not (Test-Path $requirementsPath)) {
        $requirementsPath = Join-Path $ScriptDir "pyproject.toml"
    }

    if (Test-Path $requirementsPath) {
        try {
            pip install -e . --quiet 2>&1 | Out-Null
            Write-Success "   ✅ 依赖已安装"
        } catch {
            Write-Warning "   ⚠️ 依赖安装有警告，继续..."
        }
    }
}

# 检查 .env 配置
function Check-EnvConfig {
    Write-Info "[3/4] 检查配置..."

    $envPath = Join-Path $ScriptDir ".env"
    $envExamplePath = Join-Path $ScriptDir ".env.example"

    if (-not (Test-Path $envPath)) {
        if (Test-Path $envExamplePath) {
            Write-Warning "   ⚠️ .env 不存在，从模板复制..."
            Copy-Item $envExamplePath $envPath
            Write-Info "   请编辑 .env 配置 AI API Key"
            Write-Info "   或运行: python tools_menu.py"
        } else {
            Write-Warning "   ⚠️ .env 和 .env.example 均不存在"
        }
    } else {
        Write-Success "   ✅ .env 配置文件存在"
    }
}

# 运行健康检查
function Run-HealthCheck {
    Write-Info "[4/4] 运行健康检查..."

    $scanPath = Join-Path $ScriptDir "scan.py"
    & python $scanPath --health

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "   ⚠️ 健康检查发现问题，请查看上方输出"
    }
}

# 构建命令行参数
function Build-Arguments {
    $args = @()

    if ($Health) {
        return @("--health")
    }

    if (-not $Target) {
        Write-Error "❌ 缺少目标 URL，请使用 -Target 参数"
        Write-Info "示例: .\start_vulnclaw.ps1 -Target http://example.com"
        exit 1
    }

    $args += @("-t", $Target)
    $args += @("--max-tasks", $MaxTasks)
    $args += @("--initial-qps", $QPS)

    switch ($Mode) {
        "dag" {
            $args += @("--dag", "--agents", $Agents)
        }
        "deep" {
            $args += @("--dag", "--agents", $Agents, "--deep")
            if ($Dangerous) {
                $args += "--dangerous"
            }
        }
        "code" {
            $args += @("--code")
            if ($Repo) {
                $args += @("--repo", $Repo)
            }
            $args += @("--lang", $Lang)
        }
        default {
            # single mode
            if ($Deep) {
                $args += "--deep"
                if ($Dangerous) {
                    $args += "--dangerous"
                }
            }
            if ($Code) {
                $args += "--code"
                if ($Repo) {
                    $args += @("--repo", $Repo)
                }
            }
        }
    }

    return $args
}

# 主函数
function Main {
    Show-Banner

    if ($Help) {
        Get-Help -Name $PSCommandPath -Detailed
        exit 0
    }

    $pythonCmd = Check-Python
    Check-Venv -PythonCmd $pythonCmd
    Check-EnvConfig

    # 如果只是健康检查
    if ($Health) {
        Run-HealthCheck
        exit 0
    }

    Run-HealthCheck

    # 构建并执行命令
    $args = Build-Arguments
    $scanPath = Join-Path $ScriptDir "scan.py"

    Write-Host ""
    Write-Info "═══════════════════════════════════════════════════════════"
    Write-Info "启动命令: python scan.py $($args -join ' ')"
    Write-Info "═══════════════════════════════════════════════════════════"
    Write-Host ""

    & python $scanPath @args
}

Main