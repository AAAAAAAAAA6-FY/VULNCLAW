# Box 账户 2FA 启用 + 会话刷新备忘

> 用途：VULNCLAW 已认证扫描 app.box.com 的记录与后续维护步骤。
> 创建：2026-08-31

---

## 一、为什么开 2FA

已认证扫描实测到账户配置：
- `authentication.is2FARequired = false`（未启用两步验证）
- `authentication.passwordWasGeneratedAndNotRevealed = false`
- 账户类型为非管理员普通用户

为加固账户安全，建议开启两步验证（Two-step verification / 2FA）。

---

## 二、启用 2FA 的步骤

前置准备：能收 SMS 的手机号，或 Google/Microsoft Authenticator 应用。

1. 登录 Box（Chrome，已登录状态）。
2. 右上角头像 → **Settings（设置）**。
3. 左侧栏 **Security（安全）** → **Two-step verification** → **Enable**。
   - 直达地址（需已登录）：`https://app.box.com/account/security`
4. 选择验证方式：
   - **A. 手机验证（推荐）**：输入手机号 → Send SMS → 手机收 6 位码 → 输入 → 下一步。
   - **B. Authenticator**：扫二维码 → 输入 6 位码 → 下一步。
5. 设置恢复手段（强烈建议）：
   - 备用手机号 / 备用邮箱；
   - 记下一次性备份码（8~10 个），保存在 Bitwarden / 备忘录 / 纸质。
6. Done / Finish 完成。

验证：下次重登 Box 输密码后需验证码，即生效。

---

## 三、重点提醒

- 备份码 + 手机双失 = 账户锁死，需人工联系 Box 客服，务必保管备份码。
- 2FA 开启后，已缓存的会话（`_runtime_cache/cookies/box.com.json` / `app.box.com.json`）会在登录态失效后无法访问认证 API。

---

## 四、2FA 之后：刷新扫描会话（VULNCLAW 已认证扫描）

会话文件位置：
- `_runtime_cache/cookies/box.com.json`（父域，历史导出）
- `_runtime_cache/cookies/app.box.com.json`（目标域名，扫描器优先读取）

刷新流程（任选其一）：

### 方式 A：从浏览器导出 cookie（最快）
1. 在已登录 Box 的 Chrome，按 F12 → Console 执行：
   ```javascript
   copy(document.cookie)
   ```
2. 把得到的 `k1=v1; k2=v2; ...` 粘贴给 VULNCLAW 助手（本会话），转换成 JSON 写入 `_runtime_cache/cookies/app.box.com.json`。

注意：`HttpOnly` 的 cookie（如 `z`）无法用 `document.cookie` 读取，方式 A 可能缺关键 cookie；若 401 请改用方式 B。

### 方式 B：从 Burp 扩展桥流量提取（推荐，完整）
VULNCLAW 的 Burp 扩展把每次经过代理的请求记在：
- `_runtime_cache/burp_bridge/proxy_history.jsonl`

登录一次后刷新几次页面，该文件会包含带完整 `Cookie: ...` 与 `Authorization: Bearer ...` 的请求。从最新一条 `app.box.com/app-api/*` 请求提取请求头，即可还原完整会话写入 cookie 文件（本会话已确认此链路可用，Box 的实际认证入口是 `/app-api/` 前缀，而非 `/api/2.0/`）。

### 方式 C：完整扫描命令（会话有效后）
```bash
python scan.py scan -t https://app.box.com --deep --dangerous --proxy http://127.0.0.1:8080
```
- 不加 `--no-cookie`（该参数已从扫描器移除，默认自动加载 cookie 文件做认证扫描）。
- 扫描器会从 `_runtime_cache/cookies/` 自动加载会话，并把 `Authorization` cookie 提升为 Bearer 请求头。

---

## 五、已修复的相关扫描器缺陷（2026-08-31）

1. `--no-cookie` 参数已删除（`cli.py` / `scan_main.py` / `scan_runner.py` / `start_vulnclaw.sh` / `scripts/run_code_audit.py` / 文档）。
2. Cookie 加载支持父域名回退：目标 `app.box.com` 找不到 `app.box.com.json` 时自动回退到 `box.com.json`（`utils.py` / `scan_runner.py`）。
3. `Authorization` cookie 自动提升为 HTTP `Authorization: Bearer` 请求头（`utils.py`）。
4. 浏览器 Cookie 路径适配新版 Chrome/Edge（`Network/Cookies`，`browser_cookie.py`）。

---

## 六、扫描结果与误报说明（本次 app.box.com 已认证扫描）

- 68 条漏洞中，绝大多数为假阳性，根源：
  - Spa 假 404：所有未授权路径统一返回 index.html（`len≈35~36KB`），导致响应差异/WAF 绕过/盲注类引擎误报。
  - 登录重定向 302 被 WebSocket 引擎误判为 101 握手（实为 `/login?redirect_url=...`）。
- 实测结论：
  - 2FA 绕过 Critical×2 → 假阳性（账户 `is2FARequired=false`，本就不要求 2FA）。
  - F5 WAF 绕过 High×6 → 假阳性（0% 响应差异）。
  - CSWSH High×3 / WS 可访问 Medium×3 → 假阳性（全部 302）。
  - 缓存投毒 → 假阳性（`Cache-Control: no-store` + 0% 差异）。
  - 信息泄露 email → 假阳性（首页/路径无明文 email）。
- 无被证实可用的高危漏洞；建议开启 2FA 属于安全加固，非漏洞利用点。

---

## 七、其他

- Box 公开 REST API `api.box.com/2.0/*` 需要自有 OAuth token（与网页会话不同），网页会话只认证 `/app-api/` 前缀；若需 API 授权请走开发者控制台创建应用拿 Access Token。