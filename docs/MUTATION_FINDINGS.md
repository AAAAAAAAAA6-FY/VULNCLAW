# 请求侧变异 / 模糊测试发现（Agent-G）

> **范围**：请求侧输入破坏（输入在构造/解析阶段被"破坏"）+ 解析器健壮性 + 基础资源边界。
> **性质**：全离线、确定性（零随机）、不调 AI；靶场为测试内嵌 aiohttp 服务。
> **不做**：响应侧对抗（异常响应 / WAF 拦截页 / 超时 / 重定向）由另一路并行成员负责。

---

## 1. 交付物

| 文件 | 作用 |
| --- | --- |
| `scripts/mutation_probe.py` | 确定性变异生成器 + CLI，7 个变异族共 78 个维度 |
| `tests/test_mutation_fuzzing.py` | 10 个最基础用例：A 解析器健壮性 / B 规则不被简单绕过 / C 资源边界 |
| `docs/MUTATION_FINDINGS.md` | 本文件 |

## 2. 变异维度矩阵

`scripts/mutation_probe.py` 的族与维度（零随机：去重走 dict 插入序，输出逐字节稳定）：

| 族 | 维度数 | 覆盖的破坏形态 |
| --- | --- | --- |
| `url` | 9 | URL 编码 / 双重 / 三重、百分号大小写及混排、空格 `+` 与 `%20`、逐字节全量编码 |
| `unicode` | 9 | NFC/NFD/NFKC、全角、西里尔同形字、`\uXXXX` 转义、零宽字符、BOM、UTF-8 overlong（`%c0%af`） |
| `boundary` | 14 | 空值、超长值、NUL/CR/LF/控制字符、JSON 转义与深层嵌套、CDATA 与闭合破坏、XML 实体递归 |
| `path` | 15 | `../`、`..%2f`（大小写）、`....//`、`..;/`、`%2e%2e`、双重编码、overlong、反斜杠、绝对路径、尾点/尾空格/`%00` 后缀、UNC |
| `case` | 6 | 全大写 / 全小写 / 交换 / 交替（正逆）/ 标题 |
| `query` | 14 | 参数轮转与逆序、重复参数、空值、纯键、`k[]` 与 `k[0]` 数组记法、分号分隔、参数名大小写与全角、超长值 |
| `header` | 12 | 名称大小写、顺序轮转与逆序、重复头、obs-fold（`\r\n ` 续行）、名称尾空格、`_`/`-` 互换、值内 NUL 与 CRLF 注入、超长值 |

CLI：

```powershell
python scripts/mutation_probe.py --list-families
python scripts/mutation_probe.py --input "' OR 1=1--" --family url --pretty
python scripts/mutation_probe.py --input "a=1&b=2" --family query --summary
```

## 3. 实测结果

```powershell
python -m pytest tests/test_mutation_fuzzing.py -q --disable-warnings --durations=0
```

**结果：10 passed / 0 failed**，整文件约 **6.7s**。

| 用例 | 实测耗时 |
| --- | --- |
| `test_mutation_corpus_does_not_break_core_parsers` | 6.06s |
| `test_deep_nested_json_does_not_crash_clean_ai_json` | 0.52s |
| `test_encoded_lfi_variant_still_detected` | 0.02s |
| 其余 7 例 | 均 < 0.02s |

环境无 `pytest-timeout`，耗时上限一律用 `time.monotonic()` 自建断言。

## 4. 发现（真实缺口，已最小修复 + 单测锁死）

### 4.1 解析崩溃：`clean_ai_json` 未捕获 `RecursionError`

* **文件**：`src/vulnclaw/core/utils.py`（`clean_ai_json`）
* **现象**：首个 `try: json.loads(text)` 只 `except json.JSONDecodeError`。但深层嵌套 JSON（如 `"[" * 5000 + "1" + "]" * 5000`）抛的是 `RecursionError`（继承 `RuntimeError`，**不是** `JSONDecodeError`）→ 异常直接冒泡，AI 结构化输出清洗链路整条中断。
* **修复**：改为 `except (json.JSONDecodeError, RecursionError)`（精准捕获，不用 `BaseException` 以免吞掉 Ctrl-C 等）。
* **锁死**：`test_deep_nested_json_does_not_crash_clean_ai_json`（深度 200 / 2000 / 5000，并断言返回值必须是合法 JSON）。

### 4.2 回显剥离不全：HTML 转义回显触发幻影 diff

* **文件**：`src/vulnclaw/engines/base.py`（`BaseEngine.strip_payload_reflection`）
* **现象**：原实现只剥离「原文 / `quote(p, safe="")` / `unquote(p)`」三种形态。绝大多数服务端渲染会把参数 **HTML 转义**后回显（`<` → `&lt;`、`'` → `&#x27;`），这类回显**整体残留**：
  * 正常响应无 payload、攻击响应含转义回显 → 两响应"天然不同"；
  * 以 `LFI` 为例，长度差约 0.35、词集合 Jaccard 差 1.0 → `total_diff ≈ 0.72 > 0.3` → 命中"疑似"档位。
  * 即：**纯回显型目标会被判成文件包含/注入的疑似漏洞**（原始动机正是为 httpbin 这类回显目标做的剥离，但只覆盖了 JSON 回显、漏了 HTML 转义回显）。
* **修复**：剥离形态扩到 6 种并按**长形态优先**剥离（避免短形态先命中导致长形态残留）：
  ```
  quote(quote(p)) → html.escape(p, quote=True) → html.escape(p, quote=False)
  → quote(p) → unquote(p) → p
  ```
* **锁死**：`test_html_escaped_echo_does_not_create_phantom_diff`（标签型 `<script>alert(1)</script>`、引号型 `a'b"c`、模板型、编码型、命令型 5 个 payload，断言 `has_response_diff` 为 False）。
* **风险控制**：`strip_payload_reflection` 仅用于"疑似"档位的 diff 计算；各引擎的真实判定（`_is_file_included` / `_has_cmd_output` / `_has_ssrf_indicator`）都读**未剥离**的原文，故本改动只会减少 diff 误报，不会削弱实锤检出。

## 5. 已知局限（如实记录，**未放宽断言掩盖**）

### 5.1 靶场只模拟两层解码链，三层编码不断言命中

内嵌靶场 `_build_lab_app()` 的语义是「HTTP 层解一次（aiohttp 自动）+ 应用层再解一次（靶场显式 `unquote`）」。因此：

* **断言命中**（编码等价类，共 6 个维度）：`url_encode`、百分号大小写、`..%2f`（大小写）、`%2e%2e%2f` —— 这些在两层解码链下与 `../../../../etc/passwd` 语义等价，引擎必须检出。
* **只断言"不误判 Critical"**：纯三层编码 `"%252e%252e%252f" * 4 + "etc/passwd"`。靶场确实**没读到文件**（解码后是 `%2e%2e%2f…`，不含明文 `../`），故引擎不得判 Critical。
  需要目标自身存在三层解码链时该 payload 才有效 —— 这属于"按目标形态择优"，不是引擎漏检。

### 5.2 `path_traversal_double_encoded` 不能当负向用例

`mutation_probe` 的 `path_traversal_double_encoded` 维度值是 `"%252e%252e%252f" * 4 + "../../../../etc/passwd"` —— **尾部保留了明文相对路径**。这是刻意的（真实攻击串多是这种混合形态），但因此靶场两层解码后**仍含明文 `../` 且以 `etc/passwd` 结尾 → 会读到文件**，引擎报 Critical 属**真实检出**。
本次调试先误用它做负向断言（首轮 `1 failed`），已改为自建纯编码串，属于**断言设计纠错**，非产品缺陷。

### 5.3 `LFIEngine._is_file_param` 恒返回 `True`（准入闸门形同虚设）

`src/vulnclaw/engines/web_engines.py` 中 `_is_file_param` 三条路径都返回 `True`（命中关键字返回 True；异常被吞掉后继续；末尾无条件 `return True`）。于是 `check()` 里那段
`if not await self._is_file_param(...): return None` 的早退**永不会触发**：任何参数名都会跑 LFI 全量 payload 表。

* 影响：请求数被放大（对非文件参数也打全量路径穿越 payload），属于**请求侧无界放大**。
* 未修原因：改动会直接改变 LFI 引擎的请求量与既有测试的命中面，属于产品策略决策（"宁可多测不漏测" vs "省请求"），需产品负责人拍板；已在 `docs/` 记录，不建议在测试冲刺中单方面反转。
* 建议：若确认要修，最小改法是把末尾 `return True` 改为 `return status_ok`（用探测响应判断），并同步调整 LFI 相关测试的请求数上限。

### 5.4 LFI"疑似"档位依赖响应变长

`check()` 第 ⑤ 档要求 `has_diff and len(attack_text) > len(normal_text) * 1.2`。若目标在报错时返回**更短**的响应（如 `not found`），即使 diff 很大也不会进疑似档，仅说明该档位是"放大式"启发，非严格判定。这是既有设计，本次不改。

## 6. 复现

```powershell
# 变异生成器自检（确定性）
python scripts/mutation_probe.py --input "../../../../etc/passwd" --family path --pretty

# 最基础测试组
python -m pytest tests/test_mutation_fuzzing.py -q --disable-warnings --durations=0
```
