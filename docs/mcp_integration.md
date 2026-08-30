# MCP 集成指南：让外部 AI 直接调用 VULNCLAW

[MCP（Model Context Protocol）](https://spec.modelcontextprotocol.io/) 是 AI 客户端调用外部工具的标准协议。
本项目内置 MCP Server，任何支持 MCP 的客户端（Cursor / Claude Desktop / ZCode / TraeWork 等）
都能把扫描器当"外设"直接调用，而不需要它理解命令行。

---

## 1. 启动方式

两种传输模式，按客户端在哪台机器上选：

```bash
# A. stdio（默认，推荐）—— 客户端装在你本机时用这个
vulnclaw mcp serve
# 等价写法
python -m vulnclaw.core.mcp_server

# B. HTTP —— 客户端在另一台机器/云端时用这个
vulnclaw mcp http                     # 默认只听 127.0.0.1（外网连不进来）
vulnclaw mcp http --host 0.0.0.0 --token-file ./token.txt   # 对外开放（强制 token）
vulnclaw mcp token                    # 生成强随机 token
```

| | stdio | HTTP（默认） | HTTP（对外） |
|---|---|---|---|
| 谁能连 | 本机客户端 | 只有本机 | 网络可达者 |
| 需要密码 | 不需要 | 不需要 | **强制** |
| 风险 | 无 | 无（外网不可达） | 低（见第 6 节） |

> HTTP 模式下监听非本机地址（`--host 0.0.0.0`）却没给 token 时，**程序会拒绝启动**，
> 不提供"裸奔"选项。这是硬闸门，不是警告。

传输层是 **stdio**（stdin 收 JSON-RPC，stdout 回 JSON-RPC）。
所有日志输出到 **stderr**，不会污染协议流；被调度子流程（如代码审计的进度打印）的 stdout
也会被重定向到 stderr，保证协议帧干净。

---

## 2. 客户端配置

**一键生成（推荐）**，不用手抄路径：

```bash
vulnclaw mcp install --client cursor                 # 打印配置，手动粘贴
vulnclaw mcp install --client cursor --write         # 自动写入（先备份 .bak，再合并，不覆盖其它 server）
vulnclaw mcp install --client claude-desktop --write
vulnclaw mcp install --mode http --http-url http://127.0.0.1:8765/mcp --token <TOKEN>
```

`--client` 可选 `cursor` / `claude-desktop` / `generic`；`--write` 只在你明确要求时才动磁盘文件，
写入前会把原文件备份成 `.bak`，并把 `vulnclaw` 合并进已有的 `mcpServers`，不会清掉你配的其它 server。

手动配置的话，在客户端的 MCP 配置文件里加一个 server 条目（`mcpServers` 字段）：

```json
{
  "mcpServers": {
    "vulnclaw": {
      "command": "python",
      "args": ["-m", "vulnclaw.core.mcp_server"],
      "cwd": "/absolute/path/to/pentest_platform",
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

各客户端的配置文件位置：

| 客户端 | 配置文件 |
|---|---|
| Cursor | `~/.cursor/mcp.json`（项目级：`.cursor/mcp.json`） |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）<br>`%APPDATA%/Claude/claude_desktop_config.json`（Windows） |
| ZCode / TraeWork | 设置中的 MCP Server 面板，字段同上 |

> `cwd` 必须指向项目根目录——`.env` 与 `_runtime_cache/` 都按项目根解析。
> Windows 下 `command` 可用虚拟环境的绝对路径：`C:/path/to/venv/Scripts/python.exe`。

配置完成后，在客户端里应该能看到 `vulnclaw` 及其 9 个工具。

---

## 3. 工具清单

| 工具 | 用途 | 危险 | 必填参数 |
|---|---|---|---|
| `scan.start` | 启动一次完整扫描（异步，返回 scan_id） | ⚠️ 是 | `target` |
| `scan.status` | 查询扫描进度与统计 | 否 | `scan_id` |
| `scan.findings` | 获取已发现漏洞列表 | 否 | `scan_id` |
| `scan.api_audit` | API 深度审计（GraphQL DoS / 限速绕过 / JWT 重放） | ⚠️ 是 | `target` |
| `scan.deep` | 单点深度渗透：ReAct 推理 Agent 自主「侦察→思考→决策→执行→观察」循环 | ⚠️ 是 | `target` |
| `browser.explore` | AI 浏览器代理自主探索站点，发现 API 端点与流程 | ⚠️ 是 | `url` |
| `exploit.verify` | 对单个漏洞做利用验证（HTTP 重放 + OOB + SafeExploit） | ⚠️ 是 | `url`, `parameter`, `type` |
| `code.audit` | 代码审计（Semgrep + CodeQL + 依赖 CVE + AI 复核） | 否 | `repo` |
| `intel.lookup` | 威胁情报查询（Shodan 优先、Censys 兜底） | 否 | `target` |
| `scan.danger_guard_status` | 查询权限门卫模式、危险操作清单、审批审计 | 否 | — |

工具声明遵循 MCP 2025-06-18 的 `annotations`：主动攻击类工具标注 `destructiveHint: true`，
只读查询类标注 `readOnlyHint: true`。支持该字段的客户端会在调用前提示用户确认。

### 典型调用链

```
scan.start(target=...) → scan_id
        ↓  （轮询）
scan.status(scan_id)   → 进度 / findings_count
        ↓
scan.findings(scan_id) → 漏洞列表（含 curl_command / cwe / remediation）
```

可选增强：对高危项调用 `exploit.verify` 做利用确认；用 `intel.lookup` 补充目标资产的暴露面情报；
对某个可疑接口想深挖时改用 `scan.deep`。

### `scan.deep` 与 `scan.start` 怎么选

| | `scan.start`（V100） | `scan.deep`（ReAct） |
|---|---|---|
| 覆盖面 | 全站批量（子域/端点/参数 × 引擎矩阵） | 单个 URL 深挖 |
| 速度 | 分钟级 | **慢**：每轮 20~35 秒（含 LLM 推理），默认 15 轮约 5~8 分钟 |
| 决策方式 | 固定调度 + 引擎矩阵 | Agent 自主决策调用哪个工具，带工具成功率学习 |
| 产出质量 | 完整（CWE / curl 复现 / 修复建议 / 置信度） | **原始 finding**，`severity`/`type` 可能缺失 |
| 适合 | 常规扫描、要交付报告 | 单点攻坚、V100 扫不出时的补充 |

> `scan.deep` 实测（本地靶场，3 轮）可检出 LFI 类漏洞，但产出为 Agent 原始 finding——
> 返回值里的 `missing_severity_count` 会告诉你有多少条缺严重度。
> 需要可交付级报告时，请回到 `scan.start`。

---

## 4. 危险操作门卫（Danger Guard）

对"会实际影响目标"的操作实行统一审批，**默认全部拒绝**。这是安全默认（secure by default），
避免 AI 客户端在无人值守时自发执行利用。

受控操作：

| op | 说明 |
|---|---|
| `exploit_verify` | 对已确认漏洞执行利用验证 |
| `exploit_chain` | 深度利用链（POC 生成 + 自动利用 + 回连确认） |
| `msf_exploit` | 通过 Metasploit RPC 执行利用模块 |
| `msf_shell_write` | 向已建立会话的 shell 写入命令 |

三种模式（`DANGEROUS_MODE`，也支持 `false` / `true` 写法）：

| 模式 | 行为 |
|---|---|
| `deny`（默认） | 一律拒绝 |
| `prompt` | 交互终端逐次确认；**非交互环境自动拒绝**（MCP 场景即如此） |
| `allow` | 放行 |

放行方式（三选一）：

```bash
# 1. CLI 显式开启
python scan.py scan -t <target> --deep --dangerous

# 2. 全局放行（.env 或客户端 env）
DANGEROUS_MODE=allow

# 3. 只放行特定操作（推荐：最小权限）
DANGEROUS_ALLOW=exploit_verify
```

被拒绝时工具**不会报错**，而是返回：

```json
{"exploitable": false, "reason": "danger_denied: 利用验证被权限门卫拒绝"}
```

所有决策（放行/拒绝/操作/模式）都进内存审计环，可用 `scan.danger_guard_status` 查询。

> MCP 场景下客户端通常是非交互的，所以 `prompt` 模式等价于 `deny`；
> 想让 AI 自主完成利用验证，请显式设置 `DANGEROUS_ALLOW=exploit_verify`。

---

## 5. HTTP 模式安全设计

**默认状态风险为零**：不指定 `--host` 时只监听 `127.0.0.1`，外网物理不可达，所以免鉴权也是安全的。
风险只在你主动 `--host 0.0.0.0` 开门之后才出现——此时按下述机制收敛到最低。

| 措施 | 说明 |
|---|---|
| 启动硬闸门 | 非本机地址 + 无 token → **直接拒绝启动**（不是警告，是起不来） |
| 强 token | `vulnclaw mcp token` 生成 32 字节 URL-safe 随机串（约 43 字符），不接受弱密码 |
| 恒定时间比较 | 用 `hmac.compare_digest` 校验，防时序侧信道逐字符猜测 |
| 失败不泄露 | 无 header / token 错 / 格式错，一律返回完全相同的 `401 Unauthorized` |
| 体积上限 | 请求体 512KB，超限直接拒绝 |
| token 走文件 | 支持 `--token-file`，避免密码留在 shell 历史与进程列表里 |
| 第二道锁 | 即便 token 泄露，`danger_guard` 仍默认拒绝所有危险操作（利用 / MSF），对方打不出实质攻击 |
| **失败自动封禁** | 同一 IP 连续 5 次密码错 → 封禁 15 分钟（返回 `429`），压缩探测面并降噪 |
| **IP 白名单** | `--allow-ip` 可重复指定（支持 CIDR），名单外直接 `403`；不指定则不限制 |
| **随机端口** | `--port 0` 由系统分配随机端口，消掉绝大部分自动扫描噪音 |
| **不采信伪造来源** | 默认只按真实连接 IP 判定，忽略 `X-Forwarded-For`；只有显式 `--trust-proxy`（确认在反向代理后）才采信，否则任何人都能伪造头绕过白名单 |

开启加固后的完整形态：

```bash
vulnclaw mcp http \
  --host 0.0.0.0 \
  --port 0 \
  --token-file ./token.txt \
  --allow-ip 203.0.113.5 \
  --allow-ip 10.0.0.0/8
```

### 防密码泄露

| 泄露路径 | 处理方式 |
|---|---|
| 命令行传密码被 `ps` 看到 | 使用 `--token` 时会打印警告，推荐改用 `--token-file` |
| 配置文件里的明文密码 | 屏幕输出自动脱敏为 `Bearer ***`；写入后权限收紧为 `600`（macOS/Linux）；并提示不要提交进 Git |
| 日志与屏幕 | 全程不打印 token；鉴权失败日志只记录来源 IP，不记录任何凭证内容 |

### 入侵检测（IDS）：破解即封禁

HTTP 模式下内置四道检测，命中即封禁，**封禁结果落盘持久化**（重启后依然有效）。

**零容忍规则**——命中立即永久封禁，不给试探机会：

| 信号 | 判定 | 为什么可以零容忍 |
|---|---|---|
| 路径探测 | 访问 `/mcp`、`/healthz` **之外**的任何路径 | 正常的 MCP 客户端只会访问这两个路径；去试 `/admin`、`/.env` 的一定是扫描器 |
| 攻击工具特征 | User-Agent 含 `sqlmap` / `nmap` / `nikto` / `masscan` / `acunetix` 等 | 正常客户端不会顶着这些 UA 来；已排除 `curl`、`python-requests` 等通用工具，避免误伤自己 |

**渐进规则**——不一击永久，避免你手滑打错密码就把自己锁死：

| 信号 | 处置 |
|---|---|
| 连续 5 次密码错误 | 记 1 次违规，封禁 **15 分钟** |
| 再次触发 | 逐级升级：**1 小时 → 1 天 → 7 天 → 永久** |
| 10 秒内超过 60 次请求 | 记 1 次违规（洪泛 / 自动化工具特征） |

封禁表管理：

```bash
vulnclaw mcp banlist                    # 查看封禁列表
vulnclaw mcp banlist --unban 1.2.3.4    # 解封单个 IP
vulnclaw mcp banlist --all              # 清空整表（把自己锁死时的自救手段）
```

> 封禁表存于 `_runtime_cache/mcp_banned.json`。万一你自己的 IP 被误封，上面两条命令即可恢复。

**残留风险（无法消除，需自行权衡）**：

1. **token 泄露 = 对方能发起扫描**。不要提交进仓库，也不要在聊天里明文传。
2. **明文 HTTP 会泄露 token**。对外暴露时请走 HTTPS 反向代理或 SSH 隧道，不要把端口直接挂公网。
3. **任何网络服务都可能有未知漏洞**，这一点无法承诺为零。

建议的最小暴露做法：只在需要远程接入时临时启动、用完即停；或让它只听 `127.0.0.1`，通过 SSH 隧道访问。

## 6. 验证接入

不打开客户端也能自测协议是否正常（发两条 JSON-RPC，期望回两条响应）：

```bash
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | python -m vulnclaw.core.mcp_server
```

正常输出：两行 JSON（id=1 的 initialize 结果 + id=2 的 9 个工具清单），
进程在 stdin 关闭后自行退出。**stdout 只应有 JSON，不应有日志。**

---

## 7. 排错

| 现象 | 原因与处理 |
|---|---|
| 客户端看不到工具 | 检查 `cwd` 是否为项目根、Python 是否为装了依赖的解释器（`pip install -e .`） |
| 工具列表为空或报错 | 看客户端的 MCP 日志（stderr）；常见是 `.env` 缺失或依赖未装 |
| 输出出现非 JSON 内容 | 协议被 stdout 污染；本项目已把日志与子流程输出全部导向 stderr，若仍出现请提 issue |
| `exploit.verify` 总返回 `danger_denied` | 门卫默认拒绝，见第 4 节放行 |
| `browser.explore` 报 Playwright 未安装 | `pip install playwright && playwright install chromium` |
| `intel.lookup` 返回 `available: false` | 未配置 `SHODAN_API_KEY` 或 `CENSYS_API_ID/SECRET`，属正常降级 |
| `code.audit` 耗时长 | Semgrep + CodeQL 全量扫描本就较慢，建议限定仓库规模；摘要见 `code_audit_summary.json` |
