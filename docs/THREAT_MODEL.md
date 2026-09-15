# 扫描器自身威胁模型（THREAT MODEL）

> F2 组交付。原则：**只写已核实的防护**，未实现/未核实的明确列为残余风险，不夸大。
> 配套验收：`tests/test_platform_security.py`（离线确定性）。

## 1. 资产与信任边界

| 资产 | 说明 |
|---|---|
| 扫描器主机 | 执行进程、`_runtime_cache/`、第三方工具（thirdparty/） |
| 凭据 | `.env`（代理/模型 key/OOB token）、目标账号（instructions 模块） |
| 出站网络 | 对目标的请求（唯一"对外进攻面"） |
| 入站接口 | MCP HTTP 服务（默认 127.0.0.1:8765） |
| 报告产物 | HTML/Markdown/JSON/SARIF（可能被分享给第三方看） |

信任边界（由外到内）：

```
目标响应（完全不可信）
  └─> 解析器 → [tool_output_guard 信封] → LLM 上下文
用户输入 ─> CLI 参数 ─> [danger_guard 门卫] ─> 危险操作（利用/MSF/shell）
LLM 指令 ─> 工具调用 ─> [tool_registry] ─> 第三方工具进程
扫描请求 ─> [http_client._scope_guard] ─> 出站网络
```

## 2. 已核实的防护

| # | 威胁 | 防护 | 位置 | 验收 |
|---|---|---|---|---|
| 1 | 越界出站（扫描范围失控） | `allowed_scope` 白名单硬拦截（httpx event hook 层 raise，不可被上层绕过） | `core/http_client.py` `url_in_scope`/`_scope_guard`/`ScopeGuardError` | `TestUrlInScope`/`TestScopeGuardHook` |
| 2 | 危险操作误执行 | fail-closed 门卫：默认 deny；prompt 模式非 tty 自动拒绝；CLI `--dangerous` 需第二因子（`--dangerous-confirm`/`DANGEROUS_CONFIRM=1`） | `core/danger_guard.py` + `scan_main.py:774-786` | `TestDangerGuard*` |
| 3 | 工具危险参数（如 sqlmap --os-shell） | 工具+参数级黑名单 + `tool:param` 粒度允许清单 | `DANGEROUS_TOOL_PARAMS` | `test_tool_param_blacklist` |
| 4 | Prompt injection（目标页诱导 LLM） | 三层：8 类信号检测 + `<UNTRUSTED_TOOL_OUTPUT>` 信封（3000 字符上限）+ quarantine 台账（检测失败放行、不阻断扫描） | `core/tool_output_guard.py` | `TestToolOutputTrustBoundary` |
| 5 | MCP 服务被外部访问 | 默认只监听 127.0.0.1；非本机监听强制 token；`hmac.compare_digest` 恒定时间比较；请求体 512KB 上限；鉴权失败统一 401 | `core/mcp_server.py` | 静态核实（详见文件 docstring） |
| 6 | 凭据回显 | 目标账号摘要只暴露角色/用户名，密码打码 | `core/instructions.py` `masked_summary`/`_MASKED` | 代码核实 |
| 7 | 审计可查 | 危险决策全量审计环（op/detail/allowed/mode，上限 200 条）；注入命中落 quarantine JSONL | `danger_guard._audit` / `record_quarantine` | `test_audit_trail_recorded` |
| 8 | 目标解析路径误用 | 本地目标（localhost/127.0.0.1/::1）强制走原生 aiohttp，避免 impersonation 传输层不确定性 | `core/scanner.py` `_is_local_target` | 代码核实 |

## 3. 残余风险（未防护 / 未核实，如实列出）

1. ~~**aiohttp 主路径无 scope 钩子**~~ ✅ **已修复**：`_http_request` 入口已做 `allowed_scope` 硬拦截（E5.1，越界直接 `ScopeGuardError`，不可被 LLM 绕过）；工作流8 又接入出站白名单 / SSRF/DNS-rebinding 检查（`_egress_ssrf_block_reason`，aiohttp 与 requests 路径统一）。
2. **DNS rebinding**：✅ **已缓解（opt-in）**：`http_client.check_ssrf` 记录 host 首次解析 IP，重解析不一致即拒绝，并已接入 aiohttp 主链路（`SSRF_GUARD=1` 启用）。残余：**仅覆盖初始请求 URL，不含重定向链**（见第 8 条）。
3. **私网/云元数据地址无默认黑名单**：✅ **已缓解（opt-in）**：`SSRF_GUARD=1` 时 loopback/private/link-local 一律拒绝，`SSRF_ALLOW_PRIVATE`（CIDR/单 IP）放行内部靶场；默认 off 保持旧行为（兼容）。
4. **命令注入面未全量核实**：`tool_registry` 调用第三方工具的参数拼接方式未逐工具审计（危险参数黑名单只覆盖 4 个工具的高危旗标）。
5. **压缩炸弹 / 超大响应**：✅ **已缓解**：aiohttp 路径 `utils` 有 `MAX_RESPONSE_SIZE` + 流式 `read(N+1)` 截断；httpx 路径 `_read_response_body` 校验 Content-Length 上限与压缩比（`MAX_COMPRESSION_RATIO`）。
6. **报告 HTML 注入**：`render_html` 多处使用 `html_escape`，但未做全字段审计（finding 字段来自目标响应与工具输出）。
7. **凭据全链路脱敏未覆盖日志**：✅ **已缓解**：`core/utils` 凭据脱敏函数 + `logger` 过滤器（日志落盘前脱敏），含正/负例与 fail-open 回归测试。
8. **重定向链未覆盖（工作流8 新增）**：出站白名单 / SSRF 检查只作用于发起请求的 URL；aiohttp/httpx 默认自动跟随重定向，目标 302 → `169.254.169.254` / 内网可绕过 `SSRF_GUARD`。缓解现状：`EGRESS_ALLOWLIST` 为 host 白名单，重定向到白名单外 host 时**下一次请求**会被拦（同一连接内的跟随不复查）。建议：`SSRF_GUARD=1` 时逐跳校验或禁用自动重定向 + 手动逐跳检查。
9. **插件签名强度（工作流8 新增）**：`plugin_signatures.json` 是 SHA256 清单（与插件同机、对称信任），非公钥验签；能写 `plugins_dir` 者可同时改清单与插件。现状：清单内哈希不匹配 → fail-closed 拒绝加载（已实现）；清单缺失 / 插件不在清单 → warning 放行（兼容旧插件）；仅校验 entry 文件，不含插件目录内其他模块。建议：引入公钥验签（需密钥管理产品决策）。

## 4. 复现与回归

```powershell
python -m pytest tests/test_platform_security.py tests/test_supply_chain.py -q --disable-warnings
```

残余风险 1-3、5、7 已缓解（工作流8：脱敏 / 出站白名单 / SSRF&DNS-rebinding / 响应上限，均有离线回归）；剩余 4、6、8、9 待下一轮迭代（每项都有可离线验收的测试形态）。
