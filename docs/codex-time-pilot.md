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

运行器先直接向两个上游采集工具目录，再用已安装的策略检查器核对兼容性。两份检查通过后，在本次演练的 Git 项目生成 `host-project/.codex/config.toml`。每次激活都以该文件为输入，通过 Codex 的 `mcp add` 更新独立测试账号的同名注册，用 `mcp get --json` 回读并逐项核对命令和参数，然后在新的临时宿主线程中发现和调用工具。升级原子替换项目配置中的上游解释器，回退恢复原配置字节。三个阶段都检查业务返回及会话级拒绝，演练结束后清理测试账号中的临时注册。

运行完成后，`report.json` 含各阶段版本、工具名、UTC/东京转换结果、星期字段是否存在、拒绝码、配置摘要和耗时。初始与回退的配置摘要应一致，升级摘要应与它们不同。任何阶段失败，演练返回非零并恢复最后通过验证的配置文件。文件恢复后仍要重新连接进行业务验收。

## 在平时使用的编码宿主中接入

在自己的受信项目里，将演练生成的 `[mcp_servers.time_pilot]` 配置段添加到项目的 `.codex/config.toml`，确认绝对路径与本机安装一致，保留项目原有的其他配置。打开该工作区，在 Codex 的 MCP 工具列表确认 `time_pilot.convert_time` 可用。用同一时区转换例子验证返回值。更新前保存当前配置段，升级后重新连接，回退时恢复旧配置段及上一版本的已验证虚拟环境。[Codex MCP 配置说明](https://developers.openai.com/codex/mcp/)

自动验收从宿主的线程级 MCP 接口发起调用，覆盖发现、实际工具连接和策略拒绝。它没有运行模型规划或验证每种 IDE 图形界面，也没有收集外部团队的采用数据。项目的下一阶段需要独立使用者实际走完上述安装和升级流程。
