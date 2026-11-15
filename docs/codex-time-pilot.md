# 在 Codex 中安装、升级和回退时区工具

本试点把 Codex CLI 的 MCP 宿主连接到已安装的 Agent Immunity wheel，再连接独立维护的 Python 包 `mcp-server-time`。适合在推广第三方工具升级前验证三件事：宿主实际看到了哪些工具、业务结果是否来自所选版本、回退是否能恢复原配置。[上游项目](https://github.com/modelcontextprotocol/servers/tree/850b1542e2a800369f627232f256f1e4ecb15e54/src/time) · [OpenAI 官方 App Server 文档](https://developers.openai.com/codex/app-server/)

## 这次试用的配置

| 组件 | 选择 |
| --- | --- |
| 编码宿主 | Codex CLI 0.167.0-alpha.3.2，App Server stdio 接口 |
| 网关 | 从当前提交构建并安装 0.3.0a1 wheel |
| 上游初始与回退版本 | mcp-server-time 2025.8.4，[发行文件](https://pypi.org/project/mcp-server-time/2025.8.4/) |
| 上游升级版本 | mcp-server-time 2025.9.25，[发行文件](https://pypi.org/project/mcp-server-time/2025.9.25/) |
| 协议与环境 | MCP 2025-06-18，Python 3.12，上游 Python SDK 1.30.0 |

两个版本都能把 UTC 的 09:00 换算为东京 18:00，时差为 +9.0h。新版在源和目的时间上都提供 `day_of_week`，旧版没有该字段。这是本次选择这对历史版本的原因。包版本和业务结果形状共同用来判断实际运行的版本。

本地策略只登记 `convert_time`，并设置每个会话仅允许一次转换，以便检查权限。直接上游还提供 `get_current_time`，宿主通过代理只会发现前者。同一会话内第二次提交相同的、参数合法的转换，应收到 `TRANSITION_DENIED`。时区工具的实际返回值和网关的保留元数据分别用于验收。[试点策略](../pilot/codex_time/policy.json)

## 从干净环境复现

以下命令适用于仓库根目录、Python 3.12 和 Node 24。宿主演练使用独立测试账号或 GitHub 托管 runner。个人账号可先用 `--preflight-only` 检查实际安装的第三方目录与策略，避免自动演练连到已有 MCP 服务。

```bash
python -m pip wheel --no-deps --wheel-dir artifacts/pilot-wheels .
python -X utf8 pilot/codex_time/prepare.py --root artifacts/pilot-env --wheel artifacts/pilot-wheels/agent_immunity-0.3.0a1-py3-none-any.whl
npm ci --prefix pilot/codex_time --ignore-scripts --no-audit --no-fund
python -X utf8 -m pilot.codex_time.run --codex pilot/codex_time/node_modules/.bin/codex --environment artifacts/pilot-env/environment.json --output-dir artifacts/time-pilot-run
```

Windows 的 `--codex` 可指向相同版本的 `codex.exe`。每次演练使用新的输出目录，配置和数据都写入这次的项目。安装程序为网关、旧上游、新上游各建虚拟环境，校验上游 wheel 哈希、依赖一致性和 Python 包实际导入位置。准备失败时，已有的环境描述仍可使用。

运行器先向两个上游采集工具目录，再用已安装的策略检查器核对兼容性。两份检查通过后，运行器确认测试账号的 MCP 注册表为空，在本次演练的 Git 项目创建 `host-project/.codex/config.toml`。文件只有一条 `mcp_servers.time_pilot` 赋值，包含本阶段的网关命令及参数。

每个阶段先把该文件的内容作为单个 `-c` 参数交给 `codex mcp get time_pilot --json`，核对宿主解析出的命令与参数，再把同一赋值传给新启动的 Codex App Server，通过临时线程发现和调用时区工具。配置的生效范围是这两个宿主进程。升级在项目内原子切换上游解释器，回退恢复初始文件字节，三个阶段分别验证业务返回和会话级拒绝。

运行完成后，`report.json` 含各阶段版本、工具名、UTC/东京转换结果、星期字段是否存在、拒绝码、配置摘要和耗时。初始与回退的配置摘要应一致，升级摘要应与它们不同。任一阶段发生异常时，运行器记录 `failed` 和失败类型，恢复最近通过验收的项目配置，并返回非零。如果首次验收就失败，则移除本次尚未通过验收的配置；若恢复本身失败，报告另记 `rollback_error_type`。文件恢复后仍要重新连接进行业务验收。

## 在平时使用的编码宿主中接入

在自己的受信项目里，先确认演练配置中的绝对路径与本机安装一致。若项目尚无 `time_pilot` 登记，将演练生成的 `mcp_servers.time_pilot` 赋值放到项目 `.codex/config.toml` 文件开头、首个 TOML 表头之前。若项目已有同名登记，先保存原配置，再更新该项的 `command` 和 `args`。打开工作区，在 Codex 的 MCP 工具列表确认 `time_pilot.convert_time` 可用，用同一时区转换例子验证返回值。升级后重新连接，回退时恢复旧配置和上一版本的已验证虚拟环境。[Codex MCP 配置说明](https://developers.openai.com/codex/mcp/)

自动验收从宿主的线程级 MCP 接口发起调用，覆盖发现、实际工具连接和策略拒绝。它没有运行模型规划或验证每种 IDE 图形界面，也没有收集外部团队的采用数据。项目的下一阶段需要独立使用者实际走完上述安装和升级流程。

## 在 Apple Silicon 上复现宿主演练

在专用测试账号或干净的 macOS 运行器上，使用原生 arm64 CPython 3.12 和 Node 24.22.1，先按“从干净环境复现”完成 wheel 构建、Python 环境准备和 `npm ci`。然后从仓库根目录运行：

```bash
python -X utf8 -m pilot.codex_time.run --require-macos-arm64 \
  --codex pilot/codex_time/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex \
  --environment artifacts/pilot-env/environment.json --output-dir artifacts/apple-silicon-time-run
```

上述路径指向锁定 npm 包中的原生程序。运行器用 `lipo -archs` 核对该文件只含 arm64，并将同一可执行文件用于三个阶段。网关以及新旧上游的解释器会分别报告自身架构与 Python 补丁版本。这个模式要求完整宿主调用，单独的 `--preflight-only` 仍可用于常规策略体检。

在 `codex-time-pilot` 工作流中选择 `lifecycle-macos-arm64` 作业，下载 `codex-time-lifecycle-macos-arm64` 产物。查看 `report.json` 的 `host_environment`、`codex_version` 和 `stages`，将原生架构与三阶段的工具发现、时区结果、策略拒绝及配置摘要放在一起核对。Ubuntu 作业继续提供其原有的独立报告。
