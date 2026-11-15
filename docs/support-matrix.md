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
