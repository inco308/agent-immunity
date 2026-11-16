# 开发者预览版本支持矩阵

选择接入方式时，请按整行匹配环境。只需要运行本地策略体检或代理，可从核心包安装行开始。需要验证工具发现、文件和 HTTP 行为，可照 Inspector 行复现。需要在编码宿主试装第三方工具并演练回退，请使用 Codex CLI 行。[安装预览包](doctor.md#获取开发者预览包) · [Inspector 复现](interop.md#安装和运行) · [Codex 试点步骤](codex-time-pilot.md#从干净环境复现)

## 已验证组合

网关版本 `0.3.0a1`。验收提交 [`7328ca6`](https://github.com/inco308/agent-immunity/commit/7328ca6949dcade4bbf186c827c3eee9c39fab4e)。

| 使用路径 | CI 环境 | 组件 | 已执行的验收 | 证据 |
| --- | --- | --- | --- | --- |
| 核心包安装 | `ubuntu-latest` · Python 3.10 | wheel 和 sdist | 各自在新环境安装，运行策略体检、基准和代理 ping | [作业记录](https://github.com/inco308/agent-immunity/actions/runs/43694645291/job/132752387738) |
| 核心包安装 | `ubuntu-latest` · Python 3.12 | wheel 和 sdist | 各自在新环境安装，运行策略体检、基准和代理 ping | [作业记录](https://github.com/inco308/agent-immunity/actions/runs/43694645291/job/132752387813) |
| 核心包安装 | `windows-latest` · Python 3.10 | wheel 和 sdist | 各自在新环境安装，运行策略体检、基准和代理 ping | [作业记录](https://github.com/inco308/agent-immunity/actions/runs/43694645291/job/132752387780) |
| 核心包安装 | `windows-latest` · Python 3.12 | wheel 和 sdist | 各自在新环境安装，运行策略体检、基准和代理 ping | [作业记录](https://github.com/inco308/agent-immunity/actions/runs/43694645291/job/132752387809) |
| Inspector 互操作 | `ubuntu-latest` · Python 3.12.16 · Node 24.22.1 | Inspector 2.14.0 · Python SDK 1.30.0 | MCP 2025-06-18 握手、文件读写和回环 HTTP 发布 | [作业记录](https://github.com/inco308/agent-immunity/actions/runs/43694645291/job/132752387637) |
| Inspector 互操作 | `windows-latest` · Python 3.12.10 · Node 24.22.1 | Inspector 2.14.0 · Python SDK 1.30.0 | MCP 2025-06-18 握手、文件读写和回环 HTTP 发布 | [作业记录](https://github.com/inco308/agent-immunity/actions/runs/43694645291/job/132752387752) |
| 编码宿主试点 | `ubuntu-24.04` | Codex CLI 0.167.0-alpha.3.2 · Python SDK 1.30.0 | mcp-server-time 2025.8.4 → 2025.9.25 → 2025.8.4，三阶段时区转换与重复调用拒绝 | [作业记录](https://github.com/inco308/agent-immunity/actions/runs/43694645271/job/132752387413) |

## 双构建故障恢复演练

演练提交 [`895c07a`](https://github.com/inco308/agent-immunity/commit/895c07a4f9763822ce1810dceed5ba4b40fb49e4)。网关按各自的 wheel SHA-256 前缀标识。

| CI 环境与宿主 | 网关构建 | 已执行的故障与恢复验收 | 证据 |
| --- | --- | --- | --- |
| `ubuntu-24.04` · Codex CLI 0.167.0-alpha.3.2 · MCP Python SDK 1.30.0 | 原 [0.3.0a1 · `350a623558e1`](https://github.com/inco308/agent-immunity/actions/runs/43693563690/artifacts/14153586472)（提交 `8568e98`） → 候选 [0.3.0a1 · `b44de0a50ae7`](https://github.com/inco308/agent-immunity/actions/runs/43694645291/artifacts/14153623428)（提交 `7328ca6`） → 原构建 | mcp-server-time 从 2025.8.4 升级到 2025.9.25 时上游程序缺失，候选网关退出 1。恢复 2025.8.4 后完成时区转换并拒绝重复调用 | [作业记录](https://github.com/inco308/agent-immunity/actions/runs/43823960415/job/133153250640) · [恢复报告](https://github.com/inco308/agent-immunity/actions/runs/43823960415/artifacts/14206370054) |

本次恢复演练由指定试点提交手动运行。两个网关包版本号相同，发行元数据不同。恢复时重开 Codex 会话，核对原网关、原策略及宿主注册，并将 UTC 09:00 转换为东京 18:00。表中的运行器和故障类型限定了这条证据的适用范围。

## 如何解读环境

- 核心包的四项作业分别验收了 wheel 和源码包。2026-11-15 的 `ubuntu-latest` 实际为 Ubuntu 26.04.1 x64，使用 CPython 3.10.22、3.12.16。`windows-latest` 实际为 Windows Server 2025 x64，使用 CPython 3.10.11、3.12.10。作业标签会随托管环境更新。[核心与互操作工作流](https://github.com/inco308/agent-immunity/actions/runs/43694645291)
- Inspector 两行使用 `mcpdo` 持久连接客户端和基于官方 Python SDK 的 FastMCP 示例上游。每个平台通过 17 项检查。其中取消检查由 Python SDK 客户端单独发起。[Ubuntu 报告](https://github.com/inco308/agent-immunity/actions/runs/43694645291/artifacts/14153623527) · [Windows 报告](https://github.com/inco308/agent-immunity/actions/runs/43694645291/artifacts/14153787009)
- Codex CLI 使用 App Server 的 stdio 接口。该作业实际使用 Ubuntu 24.04.5 x64、CPython 3.12.16 和 Node 24.22.1，从同一提交单独构建并安装网关 wheel。三个阶段均把 UTC 09:00 转换为东京 18:00，并按原策略拒绝同一会话的第二次调用。变化的是第三方时区上游的版本。[试点作业日志](https://github.com/inco308/agent-immunity/actions/runs/43694645271/job/132752387413) · [三阶段报告](https://github.com/inco308/agent-immunity/actions/runs/43694645271/artifacts/14153399223)

包元数据声明 Python `>=3.10`。这份预览证据仅覆盖表中的组合。macOS、ARM64、其他 Python 系列、Windows 上的 Codex 宿主，以及 Cursor、Claude Code、Copilot 等宿主仍需分别做端到端验收。Codex 试点覆盖线程级工具调用，LLM 的任务完成率另有独立评测。[包元数据](../pyproject.toml) · [LLM 评测范围](llm-evaluation.md)

## 从 CI 复核或更新

在源码仓库根目录使用 Python 3.10+ 和已登录 `github.com`、可读取本仓库 Actions 产物的 GitHub CLI。以下命令只读下载报告，将可复制的 Markdown 表格写到标准输出。

```text
python -X utf8 -m scripts.support_matrix --commit 7328ca6949dcade4bbf186c827c3eee9c39fab4e --verify-run 43694645291 --pilot-run 43694645271
```

更新快照时，选择同一完整 `main` 提交的 `verify` 和 `codex-time-pilot` 两次 push 运行。生成器核对仓库、提交、工作流、作业及关键步骤，再读取两个平台的 Inspector 报告和 Codex 三阶段报告。产物只绑定运行编号，因而生成器要求两次运行都在首次尝试成功。预检、未完成的回退或过期缺失的报告会使命令返回非零。表下方的系统镜像、架构和补丁版本来自原作业日志，更新快照时也应重新核对。[生成器](../scripts/support_matrix.py)

### 重建双构建恢复附表

同时指定演练提交与运行编号，可在原矩阵后生成上面的恢复记录。下面的命令从 GitHub Actions 取证，需要可读取产物的 GitHub CLI 登录。

```bash
python -m scripts.support_matrix --commit 7328ca6949dcade4bbf186c827c3eee9c39fab4e --verify-run 43694645291 --pilot-run 43694645271 --recovery-commit 895c07a4f9763822ce1810dceed5ba4b40fb49e4 --recovery-run 43823960415
```

生成器从指定的首次成功手动运行读取报告和候选进程退出码，核对作业步骤、归档摘要及两份来自 `main` 构建的 wheel。候选 wheel 的来源提交、打包运行编号和版本须匹配主矩阵。缺少产物或校验失败时，命令返回非零。重新取证受三个产物各自的保留期限约束。

### 在产物过期前留存恢复证据

在产物仍可下载时，使用已登录的 GitHub CLI 和下列命令。成功后得到一个 ZIP 文件，标准输出为整包的 SHA-256。把文件存入团队的证据存档，把该摘要另存到有独立访问控制的验收记录中。每次采集使用新的输出文件名。

```text
python -X utf8 -m scripts.recovery_bundle capture --commit 895c07a4f9763822ce1810dceed5ba4b40fb49e4 --run 43823960415 --output artifacts/recovery-43823960415.zip
```

留存包包含三份 GitHub 原始 ZIP（恢复报告及退出码、原网关发行包、候选网关发行包），以及记录作业、产物编号、摘要和采集机 UTC 时间的清单。断网或远端产物过期后，在有本仓库脚本和 Python 的机器上，用保存的摘要替换以下参数值。

```text
python -X utf8 -m scripts.recovery_bundle verify --bundle artifacts/recovery-43823960415.zip --sha256 <采集时独立保存的64位摘要>
```

离线命令重新计算整包、内层归档和两个 wheel 的摘要，核对候选退出码与报告中的实际恢复结果，输出采集时的在线核验时间和恢复附表。它验证留存内容与当时记录的一致性。要确认 GitHub 上当前的状态，需要重新在线取证。清单里的时间来自采集机时钟；若包与独立摘要都被替换，单凭这两份文件无法证明原始来源。

### 核对核心包的安装环境

核心包行有两种证据来源。历史作业的安装验收通过时，行中列出运行器标签和 Python 系列。有独立安装报告的作业，还会列出 wheel 与源码包各自测到的系统、架构和 Python 补丁版本。两份环境相同时合并显示，有差异时按包分别显示。

生成器按作业选择 `macos-15`、`ubuntu-latest` 或 `windows-latest` 对应的环境核对和报告上传步骤。两步均通过后，从同一次 `verify` 运行的 `package-install-<运行器标签>-py<Python系列>` 产物中读取 `package-install.json`。每种包的文件名、安装版本和完整 SHA-256 都须有效，两个包都要通过策略体检和代理 `ping`。报告中的网关版本须与矩阵一致，两个解释器须匹配该作业的 Python 系列。

Ubuntu 行分别列出发行版版本、Linux 内核版本和实测的 `linux-x86_64` 解释器平台。Windows 行列出系统内部版本和 `win-amd64`。生成器对 wheel 和源码包各自检查机器架构和 64 位指针宽度。早期 Ubuntu、Windows 作业仅跳过 macOS 专用步骤时，仍按原作业标签展示。已有适用的报告步骤时，缺失或错配的报告会使生成失败。

组件列中随 wheel、sdist 显示的 12 个十六进制字符是各自报告的 SHA-256 前缀，可在作业产物中核对完整值。生成器核对安装报告中的记录，归档字节的校验由生产该报告的打包作业完成。应有的报告缺失、两种包只通过一种，或不同 Python 系列的报告被调换时，生成命令会报错。安装行的覆盖范围到核心包入口为止。

### 加入原生编码宿主

生成器按该次运行实际包含的作业取证。历史运行只有 `lifecycle` 时，仍只生成 Linux 宿主行。原生作业出现时，生成器读取同一运行中对应的 `report.json`。

| 原生作业 | 运行器标签 | 独立产物 |
| --- | --- | --- |
| `lifecycle-macos-arm64` | `macos-15` | `codex-time-lifecycle-macos-arm64` |
| `lifecycle-windows-x64` | `windows-2025` | `codex-time-lifecycle-windows-x64` |

每个新增的宿主行都需要该作业的架构检查通过。生成器核对实际系统版本、Codex 可执行文件架构、网关和两个上游的 CPython 3.12 观测值，再检查同一报告中的安装、升级、回退、业务转换及策略拒绝。Windows 还要核对三个解释器均为 `win-amd64`。三个补丁版本相同时合并显示，有差异时按角色分别列出。

存在原生作业但产物过期、平台错配或回退验证不完整时，本次生成失败。PR 报告可用于测试生成器，正式快照须等包含这些作业的同一 `main` 提交通过验收后再更新。
