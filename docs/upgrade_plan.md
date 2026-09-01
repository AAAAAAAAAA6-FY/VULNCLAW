# 扫描器提升计划 - Agent A：准确率与检出率优化

## 维度 1：准确率提升（治误报）

### ① SPA 假 404 欺骗"响应差异类"引擎

**根因**：`has_response_diff()` 只计算长度+内容差异，SPA 首页天然抖动导致误判\
**方案**：新增 `SpaFingerprintDetector`

* 对随机路径探测，若与首页返回同一 `index.html` 外壳 → 标记 `is_spa`

* 所有依赖响应差异的结论强制降级（盲注只记"疑似"、WAF 不报、缓存投毒只报风险提示）\
  **代码位置**：`src/vulnclaw/core/detectors/spa_detector.py`（需新建）

### ② 302→login 误判为 WebSocket 101（CSWSH）

**根因**：`sess.get` 默认跟随重定向，302 被吃到 `/login` 200 页误判为"WS 端点可访问"\
**方案**：

* 探测一律 `allow_redirects=False`，只认 101 + 校验 `Sec-WebSocket-Accept == 计算值` 才判真实握手

* 之后才用恶意 Origin 做 CSWSH 测试\
  **代码位置**：`src/vulnclaw/core/network/ws_detector.py`（修改 `probe_websocket` 函数）

### ③ WAF 绕过判定缺陷

**根因**：`try_waf_bypass` 只要"检测到 WAF 头 + 有响应差异"就报绕过成功，从不验证经典签名是否被拦\
**方案**：三段式验证

1. 先发经典签名 payload（`' OR '1'='1--` 等），必须观察到 403/拦截页才进入下一步，否则 `waf_type=None` 直接退出
2. 绕过 payload 需同时满足"无拦截特征 + 反射出本次唯一 token / 复现报错 / 延时稳定 A/B 可复现"
3. 纯"有 WAF 头 + 无拦截"一律不报\
   **代码位置**：`src/vulnclaw/core/waf_bypass.py`（重构 `try_waf_bypass` 函数）

### ④ 缓存投毒判定缺陷

**根因**：仅凭 `Cache-Control: public` + 响应差异就报 Medium，从未验证注入值是否真的进入缓存响应\
**方案**：两阶段验证

* 带注入头请求（期望 Miss）→ 同 URL 不带头再请求，仍含注入 token 才算中毒(High)

* 否则仅 Info。启发式结论全部降级\
  **代码位置**：`src/vulnclaw/core/cache_poisoning.py`（修改 `verify_cache_poisoning` 函数）

### ⑤ 2FA 绕过误报

**根因**：只 GET `/dashboard` + 页面 200 + 含 email 关键词就报 Critical，没确认站点是否有 2FA\
**方案**：三前置缺一不报

1. 站点存在 2FA 迹象
2. 匿名访问确实越权（非 SPA 壳）
3. 关键词排除导航/模板常亮词\
   **代码位置**：`src/vulnclaw/core/2fa_bypass.py`（修改 `detect_2fa_bypass` 函数）

## 维度 2：检出率提升（治漏报）

### ⑥ 通用反射证据验证器（核心）✅ 已实现

**方案**：把所有"响应差异类"漏洞（SQLi/WAF/缓存投毒）升级门槛统一为：

* 注入唯一 12 位随机 token → 剥离基线后确认 token 在 body/头/JS 中新出现 → 才可报 High

* 无反射一律降级 → 天然抗 SPA 噪声 + 提高真实检出置信度\
  **实际实现**：

* `src/vulnclaw/core/reflective_validator.py`：`ReflectiveValidator` 类

  * `_generate_unique_token()`：secrets.SystemRandom 生成 12 位唯一 token（去掉易混淆字符）

  * `validate_reflection()`：注入 `payload+token` → 剥离基线 → 检查 body/头/JS 三处"新出现"

  * `validate_injection()`：兼容入口

* 集成点：

  * `src/vulnclaw/engines/web_engines.py` SQLiEngine 布尔盲注（A/B 通过后必须反射才报 High，无反射降 Medium·low）

  * `src/vulnclaw/engines/base.py` `_verify_waf_bypass_success`（反射/报错/A-B延时三通道，统一走反射验证器）

### ⑦ 真 OOB/SSRF 盲打通道 ✅ 已实现

**方案**：扩展为对 url/redirect/file 参数注入 `http://<scanid>.interactsh/`，DNS/HTTP 轮询命中即确认为真 SSRF

* 把 OOB 命中接入 verify 阶段（`_severity_verify_plan` 已有 `do_oob_poll` 钩子）\
  **实际实现**：

* `src/vulnclaw/engines/net_engines.py` SSRFEngine：

  * `OOB_PAYLOADS`：`http://{scan_id}.{domain}/`（DNS/HTTP）、`/ssrf-probe`（HTTP路径）、`:80/?q=1`（带参）、`https://` 变体

  * `_gen_scan_token()`：生成唯一 `sr+6位随机` 前缀域名用于命中配对

  * `_test_ssrf_oob()`：注入 Interactsh 子域 → 短轮询（复用 `get_interactsh_poll`）→ 命中即返回 `oob_confirmed=True` 的 High

  * check() 在常规 payload 循环前优先执行 OOB 盲打（⑦ 第 2.5 步）

* `src/vulnclaw/ai/v100/phases/phases_executor.py`：`engine_name in ("cmdi", "ssrf")` 时向引擎传入 `interactsh_domain`

* `src/vulnclaw/ai/v100/phases/phases_verify.py`：

  * `_severity_verify_plan`：High 级别 `do_oob_poll` 从 False 改为 True

  * OOB 确认条件扩展为 `method in ("oob_dns", "oob_ssrf", "oob_http")`，且支持引擎侧 `oob_confirmed` 直通确认

### ⑧ 参数级三层漏斗（真注入确认）✅ 已实现

**方案**：

1. 布尔/时间探针 → suspect
2. A/B 逆命题 + 稳定性复核 → probable
3. 真实注入确认（OR 返回正常 / AND 返回空或超时 / UNION 列数回显 / 报错关键字 / 反射 token，五选二）→ confirmed\
   **实际实现**：`src/vulnclaw/engines/web_engines.py` SQLiEngine.check()

* 第一层 suspect：快失败探测（布尔/时间探针，`_probe_param` + `sqli_fast_fail`）

* 第二层 probable：`ab_verify`（A/B 逆命题并发验证）+ 重放稳定性复核（RTT/抖动抗性）

* 第三层 confirmed（仅此层进报告）：

  * 报错关键字（`_has_sql_error`）→ High

  * UNION 列数回显（数据库关键词新出现）→ High

  * 时间盲注（A/B 延时可复现，`_verify_time_based`）→ High

  * 布尔盲注（A/B 通过 + 反射 token ⑥）→ High；A/B 通过但无反射 → Medium·low 降级

* 疑似层（仅响应差异，无 A/B 行为确认）一律跳过（杜绝假 404 与抖动噪声）

## 实施优先级

1. 通用反射证据验证器（⑥）- 核心基础
2. SPA 检测器（①）- 解决最常见误报
3. WAF 绕过三段式验证（③）- 关键漏洞判定
4. 缓存投毒两阶段验证（④）- 高危漏洞确认
5. 2FA 绕过三前置（⑤）- 误报消除
6. WebSocket 误判修复（②）- 端点检测优化
7. OOB/SSRF 盲打（⑦）- 检出率提升
8. 三层漏斗验证（⑧）- 真注入确认

