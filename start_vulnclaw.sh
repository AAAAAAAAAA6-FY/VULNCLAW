#!/usr/bin/env bash
# ============================================================
# VULNCLAW 渗透测试平台启动脚本（Linux / macOS）
# 一键启动：检查环境 → 配置 → 健康检查 → 启动扫描
#
# 用法:
#   ./start_vulnclaw.sh -t http://testphp.vulnweb.com
#   ./start_vulnclaw.sh -t http://target.com --dag --agents 6
#   ./start_vulnclaw.sh -t http://target.com --deep --dangerous
#   ./start_vulnclaw.sh --health
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------- 禁止 Python 写入 __pycache__，防止根目录出现缓存垃圾 ----------
export PYTHONDONTWRITEBYTECODE=1
# 清理任何可能存在的前缀
unset PYTHONPYCACHEPREFIX

# ---------- 颜色输出 ----------
if [[ -t 1 ]]; then
    C_MAGENTA='\033[0;35m'; C_GREEN='\033[0;32m'; C_CYAN='\033[0;36m'
    C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'; C_RESET='\033[0m'
else
    C_MAGENTA=''; C_GREEN=''; C_CYAN=''; C_YELLOW=''; C_RED=''; C_RESET=''
fi

info()    { echo -e "${C_CYAN}$*${C_RESET}"; }
success() { echo -e "${C_GREEN}$*${C_RESET}"; }
warn()    { echo -e "${C_YELLOW}$*${C_RESET}"; }
error()   { echo -e "${C_RED}$*${C_RESET}"; }

banner() {
    echo ""
    echo -e "${C_MAGENTA}╔════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_MAGENTA}║                    VULNCLAW 渗透测试平台                    ║${C_RESET}"
    echo -e "${C_MAGENTA}║                   v101 · Sprint 4                          ║${C_RESET}"
    echo -e "${C_MAGENTA}╚════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

usage() {
    cat <<EOF
用法: $0 [-t TARGET] [选项]

必选（--health 时可省略）:
  -t, --target URL        目标 URL

模式:
  --dag                   DAG 调度模式
  --deep                  启用深度利用链（生成 POC）
  --dangerous             危险模式：实际执行利用（配合 --deep）
  --code                  启用代码安全扫描
  --repo URL              代码仓库 URL（配合 --code）
  --lang LANG             代码扫描语言（python/javascript/java/go）
  --master                以分布式 Master 节点运行（需 Redis）
  --worker                以分布式 Worker 节点运行（需 Redis）
  --redis-url URL         Redis 连接 URL（默认 redis://localhost:6379/0）

调度参数:
  --agents N              DAG 并行 Agent 数（默认 3）
  --max-tasks N           最大任务数（默认 200）
  --initial-qps N         初始 QPS（默认 3）

其他:
  --proxy URL             HTTP 代理
  --no-cookie             跳过 Cookie 自动获取
  --health                仅运行健康检查
  -h, --help              显示本帮助
EOF
    exit 0
}

# ---------- 参数解析 ----------
TARGET="" MODE_ARGS=() HEALTH_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)      TARGET="$2"; shift 2 ;;
        --dag)            MODE_ARGS+=("--dag"); shift ;;
        --deep)           MODE_ARGS+=("--deep"); shift ;;
        --dangerous)      MODE_ARGS+=("--dangerous"); shift ;;
        --code)           MODE_ARGS+=("--code"); shift ;;
        --repo)           MODE_ARGS+=("--repo" "$2"); shift 2 ;;
        --lang)           MODE_ARGS+=("--lang" "$2"); shift 2 ;;
        --agents)         MODE_ARGS+=("--agents" "$2"); shift 2 ;;
        --max-tasks)      MODE_ARGS+=("--max-tasks" "$2"); shift 2 ;;
        --initial-qps)    MODE_ARGS+=("--initial-qps" "$2"); shift 2 ;;
        --proxy)          MODE_ARGS+=("--proxy" "$2"); shift 2 ;;
        --no-cookie)      MODE_ARGS+=("--no-cookie"); shift ;;
        --master)         MODE_ARGS+=("--distributed" "--master"); shift ;;
        --worker)         MODE_ARGS+=("--distributed" "--worker"); shift ;;
        --redis-url)      MODE_ARGS+=("--redis-url" "$2"); shift 2 ;;
        --health)         HEALTH_ONLY=1; shift ;;
        -h|--help)        usage ;;
        *)                error "未知参数: $1"; usage ;;
    esac
done

# Master/Worker 分布式模式无需扫描目标
DISTRIBUTED_MODE=0
if [[ " ${MODE_ARGS[*]} " == *" --master "* || " ${MODE_ARGS[*]} " == *" --worker "* ]]; then
    DISTRIBUTED_MODE=1
fi

# ---------- 1. 检查 Python ----------
check_python() {
    info "[1/4] 检查 Python 环境..."
    local found=""
    # 允许通过环境变量强制指定解释器：VULNCLAW_PYTHON=/path/to/python3.12
    if [[ -n "${VULNCLAW_PYTHON:-}" ]]; then
        if [[ -x "$VULNCLAW_PYTHON" ]] || command -v "$VULNCLAW_PYTHON" >/dev/null 2>&1; then
            found="$VULNCLAW_PYTHON"
            success "   ✅ 使用指定解释器 $VULNCLAW_PYTHON"
        else
            error "   ❌ VULNCLAW_PYTHON 指定的解释器不可用: $VULNCLAW_PYTHON"
            exit 1
        fi
    fi
    if [[ -z "$found" ]]; then
        for cmd in python3 python; do
            if command -v "$cmd" >/dev/null 2>&1; then
                local ver
                ver="$("$cmd" --version 2>&1 | grep -oP 'Python \K[0-9]+\.[0-9]+' || true)"
                if [[ -n "$ver" ]]; then
                    local major="${ver%%.*}" minor="${ver##*.}"
                    if [[ "$major" -ge 3 && "$minor" -ge 11 ]]; then
                        found="$cmd"
                        success "   ✅ 找到 Python $ver ($cmd)"
                        break
                    else
                        warn "   ⚠️ $cmd 版本 $ver < 3.11，跳过"
                    fi
                fi
            fi
        done
    fi
    if [[ -z "$found" ]]; then
        error "   ❌ 未找到 Python >= 3.11"
        info "   请安装 Python 3.11+: https://www.python.org/downloads/"
        info "   或通过 VULNCLAW_PYTHON 指定解释器路径"
        exit 1
    fi
    PYTHON_CMD="$found"
}

# ---------- 2. 虚拟环境与依赖 ----------
check_venv() {
    info "[2/4] 检查虚拟环境..."
    local venv_dir="$SCRIPT_DIR/venv"
    if [[ ! -d "$venv_dir" ]]; then
        info "   创建虚拟环境..."
        "$PYTHON_CMD" -m venv "$venv_dir"
        success "   ✅ 虚拟环境创建成功"
    else
        success "   ✅ 虚拟环境已存在"
    fi
    # shellcheck disable=SC1091
    source "$venv_dir/bin/activate"

    info "   检查依赖..."
    if pip install -e . --quiet >/dev/null 2>&1; then
        success "   ✅ 依赖已安装"
    else
        warn "   ⚠️ 依赖安装有警告，继续..."
    fi

    # 关键依赖导入校验：缺失的关键包直接给出明确指引
    local missing=()
    for pkg in pydantic_settings aiohttp requests redis yaml; do
        if ! "$PYTHON_CMD" -c "import $pkg" >/dev/null 2>&1; then
            missing+=("$pkg")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "   ❌ 关键依赖缺失: ${missing[*]}"
        error "   请运行: pip install -e . 后重试"
        exit 1
    fi
    success "   ✅ 关键依赖导入校验通过（pydantic-settings/aiohttp/requests/redis/pyyaml）"
}

# ---------- 3. 检查配置 ----------
check_env() {
    info "[3/4] 检查配置..."
    if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
        if [[ -f "$SCRIPT_DIR/.env.example" ]]; then
            warn "   ⚠️ .env 不存在，从模板复制..."
            cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
            info "   ✅ 已生成 .env（默认配置）"
        else
            warn "   ⚠️ .env 与 .env.example 均不存在"
        fi
    else
        success "   ✅ .env 配置文件存在"
    fi

    # AI Key 检查：占位符或缺失时提醒（--health 模式跳过，因为健康检查不依赖 AI）
    if [[ "$HEALTH_ONLY" -ne 1 ]]; then
        local api_key
        api_key="$(grep -E '^AI_API_KEY=' "$SCRIPT_DIR/.env" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
        if [[ -z "$api_key" || "$api_key" == *"your_api_key"* ]]; then
            warn "   ⚠️ .env 中未配置有效的 AI_API_KEY（AI 交叉验证将降级/不可用）"
            info "   请编辑 $SCRIPT_DIR/.env 填入 API Key，或运行: $PYTHON_CMD $SCRIPT_DIR/tools_menu.py"
        else
            success "   ✅ AI_API_KEY 已配置"
        fi
    fi
}

# ---------- 4. 健康检查 ----------
run_health() {
    info "[4/4] 运行健康检查..."
    "$PYTHON_CMD" "$SCRIPT_DIR/scan.py" --health || warn "   ⚠️ 健康检查发现问题，请查看上方输出"
}

# ---------- 主流程 ----------
main() {
    banner
    check_python
    check_venv
    check_env
    run_health

    if [[ "$HEALTH_ONLY" -eq 1 ]]; then
        exit 0
    fi

    if [[ "$DISTRIBUTED_MODE" -eq 1 ]]; then
        # 分布式模式：透传参数即可（scan.py 会分发到 master/worker）
        echo ""
        info "═══════════════════════════════════════════════════════════"
        info "启动命令: python scan.py ${MODE_ARGS[*]}"
        info "═══════════════════════════════════════════════════════════"
        echo ""
        "$PYTHON_CMD" "$SCRIPT_DIR/scan.py" "${MODE_ARGS[@]}"
        return 0
    fi

    if [[ -z "$TARGET" ]]; then
        error "❌ 缺少目标 URL，请使用 -t/--target 参数（或 --health 仅做健康检查）"
        usage
    fi

    echo ""
    info "═══════════════════════════════════════════════════════════"
    info "启动命令: python scan.py -t $TARGET ${MODE_ARGS[*]}"
    info "═══════════════════════════════════════════════════════════"
    echo ""

    "$PYTHON_CMD" "$SCRIPT_DIR/scan.py" -t "$TARGET" "${MODE_ARGS[@]}"
}

main
