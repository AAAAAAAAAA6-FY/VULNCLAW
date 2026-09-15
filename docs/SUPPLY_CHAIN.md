# 供应链安全（SUPPLY CHAIN）

> 口径：**离线优先、可复现、如实呈现**。本项目不引入外部 SBOM/签名工具作为运行时依赖，
> 所有校验只用 stdlib 或项目已有依赖完成（详见 `scripts/sbom.py` / `scripts/verify_tools.py`）。
> 威胁面清单与残余风险见 `docs/THREAT_MODEL.md`。

---

## 1. 来源清单（本项目的全部外部输入）

| 类别 | 来源 | 入库 | 信任级别 | 现状控制 |
| --- | --- | --- | --- | --- |
| Python 依赖 | `pyproject.toml` 的 `dependencies` / `optional-dependencies` | 是（仅声明，非锁定） | 中 | 版本下限约束；`pip install -e .` 由 PyPI + TLS 兜底；SBOM 记录实际装到的版本 |
| 第三方二进制 | `thirdparty/tools.yaml` 登记的 GitHub Release 资产 | **否**（`.gitignore`） | 中 | 官方 checksums 硬校验（部分厂商）+ 本地 SHA256 清单比对（本文件 §3） |
| 插件 | 插件市场（`core/plugin_market.py`，GitHub Releases zip） | 否 | **低（等于远程代码执行）** | SHA256 校验；**无签名校验**（规范草案见 §5） |
| 规则/指纹数据 | `data/**`、`core/vulnspec`、引擎内置信数据驱动签名 | 是 | 中 | 代码评审；外源签名落 `thirdparty/rules/external_sigs.json` |
| OSINT 外发 | crt.sh / OTX / urlscan（可 `OSINT_DISABLE=1` 关闭） | — | 低 | 默认开启但可关；不回写仓库 |

**不入库的东西**（`.gitignore` 显式声明，并附原因注释）：`thirdparty/**/*.exe|dll|so`、
整包第三方仓库（`PentestGPT/`、`OneForAll/`、`sqlmap/`、`dirsearch/`、`testssl.sh/` 等）、
`nuclei-templates/`、`rad_ca.*`。目的：仓库体积可控 + 避免把来源各异的二进制纳入本仓的许可/责任范围。

---

## 2. 生成物与命令（全部离线）

| 生成物 | 生成命令 | 内容 |
| --- | --- | --- |
| `SBOM.json` | `python scripts/sbom.py` | CycloneDX 1.5 风格的组件清单（library 类型，含 purl / 版本 / 许可证 / 依赖范围） |
| `docs/LICENSES.md` | `python scripts/sbom.py --licenses-md docs/LICENSES.md` | 许可证分布 + 逐组件明细（UNKNOWN 如实列出） |
| `thirdparty/tools_integrity.json` | `python scripts/verify_tools.py --update` | 工具名 → executable / SHA256 / size / 相对路径 |

组件来源两路合并：

1. `pyproject.toml` 声明的直接依赖（含 `dev` / `full` 可选组，记 `declared-spec`）；
2. 本机 `importlib.metadata.distributions()` 实际安装的发行包。

依赖范围标注 `vulnclaw:dependency-scope`：
`direct`（声明且已装）/ `transitive`（由直接依赖的基础依赖闭包引入，跳过 optional extra）/
`environment`（本机已装但不在闭包内，多为开发工具）/ `declared-missing`（声明了但未安装，版本留空）。

**可复现性**：设置 `SOURCE_DATE_EPOCH`（秒）可固定 `metadata.timestamp`；
`serialNumber` 用 `uuid5(namespace, vulnclaw/sbom/<name>/<version>)` 派生，天然确定性。
本机基线（2026-09-13）：**组件 328**（direct 28 / transitive 92 / environment 206 / declared-missing 2），
许可证 **UNKNOWN 8 个**（元数据未标注，不推测）。

---

## 3. SHA256 完整性机制

三层，按"下载时 → 安装后 → 事后审计"排列：

1. **下载时（`core/utils.py`）**：对官方发布 `<repo>_<ver>_checksums.txt` 的厂商（projectdiscovery / ffuf）
   做硬校验，**不匹配即拒装**（`raise ValueError`，删除半截归档）；拉不到 checksums 的厂商只软告警。
   下载走"直连 + 镜像"候选源，连接级失败按源标记跳过，全部失败则清理半成品文件。
2. **安装后（`core/utils._record_tool_manifest`）**：把每个成功安装的二进制 SHA256 + 版本写入
   `thirdparty/tool_manifest.json`；同版本重下时哈希变化会打 `⚠️` 告警（防替换/防损坏）。
3. **事后审计（`scripts/verify_tools.py`）**：按 `tools.yaml` 遍历，对本机存在的二进制重新计算 SHA256，
   与 `thirdparty/tools_integrity.json` 比对，并与第 2 层的 `tool_manifest.json` **交叉比对**。

判定与退出码：

| 场景 | 输出 | 退出码 |
| --- | --- | --- |
| 哈希与清单一致 | `OK <name> <sha256前16>… <size>` | 0 |
| 工具缺失（未下载/未入库） | `SKIP <name> 未找到 <exe>（thirdparty/ 与 PATH 均无）` | 0（**fail-open 记录**） |
| 文件小于 100KB（残留/损坏） | `SKIP`（与 `plan_tool_install` 的判据一致） | 0 |
| 哈希与清单不符 | `MISMATCH 期望… 实际… ← 原因` | **2（硬失败）** |
| 存在但清单未登记 | `UNTRACKED`（防"悄悄多出一个二进制"） | 0；`--strict` 时 2 |

设计取舍（刻意为之）：CI 上没有 `thirdparty/`（不入库），若把"缺失"当失败，门禁永远红 ⇒ 失去意义。
因此**缺失 = 显式记录原因并放行**，而**哈希不符 = 立即失败**——这正是"供应链被篡改"最该拦住的信号。
`--update` 采用**合并语义**：只刷新本机可见项，缺失项保留旧记录，避免在 Linux CI 上跑一次
`--update` 就把 Windows 端的哈希记录全部抹掉。

---

## 4. 许可证策略

- 本项目自身：`AGPL-3.0-or-later WITH Classpath-exception-2.0`（见 `LICENSE`）。
- 依赖许可证**一律取自包元数据**：`License-Expression` → `Classifier: License ::` 叶子 → `License` 短标识；
  三者皆无则记 `UNKNOWN`。**不做归一化、不做推测**（例如不把分类器名 `Apache Software License`
  擅自改写成 `Apache-2.0`），清单展示的是上游元数据原文。
- 引入新依赖（进 `dependencies`）的评审要求：
  1. 许可证必须是 OSI 认可且与 AGPL-3.0 兼容（MIT/BSD/Apache-2.0/ISC/PSF 等）；
  2. 许可证为 `UNKNOWN` 或含"仅非商用/研究用途"限制的包，**不得进入直接依赖**；
  3. 强 copyleft（GPL/AGPL 之外的分发条款冲突）需单独说明，避免整体许可被污染。
- 第三方二进制由各自上游许可证约束，本仓只登记"来源 + 哈希"（见 `thirdparty/VERSIONS.md`、
  `thirdparty/LICENSE.md`、`thirdparty/LICENSE.txt`），不再分发其二进制。
- 定期复核：`docs/LICENSES.md` 由 CI 每次流水线重新生成（只生成、不比对，因为不同机器装到的版本不同）。

---

## 5. 工具隔离

- 工具的**唯一注册入口**是 `thirdparty/tools.yaml`（名称 / executable / default_args / timeout / 输出格式）。
- 可用性判定统一走 `core.tool_registry.tool_available`，**禁止 `shutil.which` 作为门禁**
  （thirdparty 下的工具通常不在 PATH 上），历史事故见 `tests/test_tool_wiring_regressions.py`。
- 调用一律走 `core.tool_registry.run_tool`：列表传参（不经 shell 拼接）、显式 timeout、
  输出做信任边界处理（`core/tool_output_guard.py` 包 `<UNTRUSTED_TOOL_OUTPUT>` 信封 + 注入信号检测 + quarantine 台账）。
- 危险参数（`danger_guard.DANGEROUS_TOOL_PARAMS`：sqlmap `--os-shell`、nmap `--script`、curl `--upload-file` 等）
  默认拒绝，需 `DANGEROUS_ALLOW` 按 `工具:参数` 粒度显式放行。
- 工具**不自动执行仓库内脚本**：下载只解压出目标可执行文件（`_tp_extract` 按文件名精确匹配），
  不解压全目录、不执行安装脚本。

---

## 6. 插件签名规范（草案，**仅设计，未实现**）

现状：`core/plugin_market.py` 下载 zip → 用 GitHub API 返回的 `digest` 做 SHA256 比对 → 解压 →
`importlib` 动态导入 `entry` 模块并注册钩子。**即插件在本进程内获得完整权限**（等于任意代码执行），
且哈希期望值与被校验文件来自同一 API 响应，安全性完全等价于"完全信任该 GitHub 账号"。

草案（落地顺序：先 1–3，再 4–6）：

1. **manifest 扩展**（`plugin_manifest.yaml` 增加 `integrity` 段）：
   `integrity: {sha256: <hex>, signature: <base64>, algo: minisign|cosign, publisher: <key-id>}`。
2. **签名算法**：优先 `minisign`（无外部服务、密钥小、纯文件校验），备选 `cosign`/Sigstore（可透明日志）。
3. **信任存储**：`thirdparty/plugins/trusted_keys.json`（`key-id → 公钥 + 允许的 publisher`）；
   仓库内置 keyring 只放**官方发布密钥**，第三方发布者需用户显式 `--allow-publisher <key-id>` 信任。
4. **加载前强校验**：签名通过 + 哈希一致才注册钩子；默认策略是**拒绝一切未签名插件**
   （`PLUGIN_REQUIRE_SIGNATURE=true` 默认开），仅 `--allow-unsigned` 单次降级放行并写审计。
5. **撤销与锁定**：`thirdparty/plugins/revocations.json`（被撤销的 key-id/插件哈希），加载前先查撤销表；
   插件版本写入 `plugins_manifest.json`（含 `installed_at`），卸载时清理目录 + 注销钩子。
6. **权限最小化**（与签名正交，需单独设计）：按 `hooks` 声明能力（只读网络 / 写报告 / 执行工具），
   将插件执行下沉到子进程或沙箱（`core/sandbox_runner.py` 已有进程隔离雏形），禁止插件直接持有危险操作审批权。

---

## 7. 已知缺口与残余风险

| 缺口 | 说明 | 影响 | 处置 |
| --- | --- | --- | --- |
| 无 lock 文件 | 只有版本下限（`>=`），不同机器/时间装到的版本可能不同 | 构建不可复现；新版本可能引入回归或被投毒 | 待定：引入 `uv.lock`/`requirements.txt`（哈希锁定）需先确认依赖管理策略 |
| 插件无签名 | 仅 SHA256，且期望值来自同一响应 | 发布账号/通道被控即等于任意代码执行 | §6 草案（未实现），当前建议只装官方插件 |
| 插件哈希可缺省 | `_verify_sha256` 在期望值为空时**放行**（fail-open） | 无 digest 的 release 未经校验即安装 | 已知；建议后续改为 require digest（需评估对现有下载流程的影响） |
| 工具校验依赖本地清单 | `tools_integrity.json` 首次由本机生成，若首次就是被投毒的二进制，则记下的是坏哈希 | 首次可信引导（bootstrapping）问题 | 官方 checksums 硬校验作第一层缓解；建议从可信机器生成并评审入库 |
| 无 SBOM 变更门禁 | CI 只生成 SBOM，不比对差异 | 新增依赖不会自动触发人工复核 | 待定：可加"依赖清单变化必须人工 approve"的 PR 规则（流程项，非代码） |
| 无漏洞库比对 | 离线环境不引入 OSV/Grype 等扫描器 | 已知 CVE 无法自动发现 | 依赖 Dependabot PR（`pyproject.toml` 内已有对应升级注释） |
