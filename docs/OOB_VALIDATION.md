# OOB / interactsh 验证矩阵（OOB VALIDATION）

> D1 交付。严格区分两层：**离线 mock 闭环已真实验证** 与 **真实回连待环境验证**。
> 不得把 mock 结论表述为"OOB 可用"。

## 1. 离线已验证（本地 mock interactsh server，真 HTTP）

验证载体：`tests/test_oob_interactsh_offline.py`（mock server 走真实 HTTP 注册/轮询，
不 mock 函数返回值）+ `tests/test_oob_channel.py`（**44 例全绿**）。

| # | 能力 | 验证方式 | 状态 |
|---|---|---|---|
| 1 | token 注册/申请域名 | mock `POST /register` → 域名+correlation | ✅ |
| 2 | 回调收取并绑定 token | 注入回调 → `wait_for_interaction` 命中 | ✅ |
| 3 | 回调去重 | 同 interaction 重复投递 → 审计链只计一次 | ✅ |
| 4 | 误关联防护（外部域名） | `attacker.example` / 后缀伪装回调一律丢弃 | ✅ |
| 5 | 精确匹配（前缀/大小写） | `tokabc12*` 前缀不命中；大小写归一命中 | ✅ |
| 6 | 无回调有界收敛 | timeout 内返回空，不空转、不产证据 | ✅ |
| 7 | 服务不可用降级 | 5xx → fail-closed，不谎报域名/证据 | ✅ |
| 8 | 通道级熔断 | `mark_channel_down` → 跳过申请；reset 后恢复 | ✅ |
| 9 | 目标级熔断 + 命中解除 | 连续零回调熔断；真实回调到达即解除 | ✅ |
| 10 | 熔断零成本跳过 | 熔断且内存无命中 → 立即返回（<1s，不空等 timeout） | ✅ |
| 11 | 熔断中已收回调不漏报 | 熔断后缓冲/审计已有回调 → 命中并解除（FN 防护） | ✅ |

**本轮修复的 3 个真实 FN 风险**（均由离线测试暴露，已修 + 锁测试）：
1. `wait_for_interaction` 熔断时直接返回空 → 已收到的实锤（注入成功但结果先到）被漏掉；
2. `interactions_for` 的 poll 消费语义 → 并发等待时其它 token 的 poll 会把回调先行取走（只落审计）；
3. `get_interactsh_poll` 熔断分支直接返回空 → 同样的漏报面。

## 2. 真实环境验证清单（未执行，需自部署 interactsh + 授权目标）

**前置**：
```text
1. 自部署 interactsh server（或在授权网络内可用的服务），拿到根域名；
2. .env 配置 OOB_INTERACTSH_SERVER=<origin>（仅 origin，不带路径/凭据）；
3. python scan.py --health 确认 [OOB] 段显示服务与 interactsh-client 路径；
4. 到测试机确认 DNS 可达：nslookup <token>.<domain> <dns-server>
```

**逐协议验证（每项须留存证据记录）**：
```text
DNS : nslookup $(python -c "print('probe123')").<domain>   → interactsh 侧收到 dns 交互
HTTP: curl http://<domain>/probe123                        → 收到 http 交互
LDAP: 由 Log4Shell/Fastjson 盲打链触发（无独立命令）        → 收到 ldap/dns 交互
```

**证据样本格式（每条真实回调必须按此记录）**：
```json
{
  "interaction_id": "...",
  "token": "probe123",
  "protocol": "dns",
  "received_at": "2026-09-13T12:00:00Z",
  "source_ip": "203.0.113.7",
  "request_id": "<扫描内产生的关联 id>",
  "finding_id": "f1-xxxxxxxxxxxxxxxx",
  "latency_ms": 1234
}
```

**必须人工确认的失败场景**（mock 已覆盖逻辑，真实环境需复验）：
token 过期行为 / 回调延迟分布 / 回调服务不可用时的降级 / OOB 轮询超时 /
熔断与恢复窗口 / 跨目标回调不串台。

## 3. 未执行项（如实声明）

- 真实 DNS/HTTP/LDAP 回调收取（无自部署 interactsh 服务）；
- interactsh-client 真实二进制链路（本机有 client 路径但无服务端）；
- Log4Shell/Fastjson/SSRF 的真实外带触发（需 Vulhub 场景，见 §4）；
- 加密回调解析（真实 interactsh 走 AES；mock 用明文 JSON——加密链只能在真实服务端验证）。

## 4. 与 Vulhub 的衔接

场景清单见 `scripts/lab_profiles/vulhub.yaml`（10 场景，revision 待授权环境锁定）；
执行编排 `python scripts/lab_vulhub.py`（默认 dry-run，无 Docker 时 exit 2）。
OOB 类场景（fastjson/log4shell/盲 xxe）的**唯一实锤口径 = 真实回调**，容器启动不算检出。

## 5. 复现

```powershell
python -m pytest tests/test_oob_interactsh_offline.py tests/test_oob_channel.py -q --disable-warnings
python scripts/lab_vulhub.py            # 无 Docker：打印计划 + exit 2
```
