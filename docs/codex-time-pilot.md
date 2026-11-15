# 在 Codex 中安装、升级和回退时区工具

本试点把 Codex CLI 的 MCP 宿主连接到已安装的 Agent Immunity wheel，再连接独立维护的 Python 包 `mcp-server-time`。适合在推广第三方工具升级前验证三件事：宿主实际看到了哪些工具、业务结果是否来自所选版本、回退是否能恢复原配置。[上游项目](https://github.com/modelcontextprotocol/servers/tree/850b1542e2a800369f627232f256f1e4ecb15e54/src/time) · [OpenAI 官方 App Server 文档](https://developers.openai.com/codex/app-server/)

## 这次试用的配置

| 组件 | 选择 |
| --- | --- |
| 编码宿主 | Codex CLI 0.167.0-alpha.3.2，App Server stdio 接口 |
| 网关 | 默认从当前提交构建 wheel；也可用两个指定的 `main` 构建分别安装原网关和候选网关 |
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

Windows 的 `--codex` 可指向相同版本的 `codex.exe`。每次演练使用新的输出目录，配置和数据都写入这次的项目。以上命令使用一个网关环境和两个上游环境，校验上游 wheel 哈希、依赖一致性和 Python 包实际导入位置。准备失败时，已有的环境描述仍可使用。

### 用两个已核验的网关构建演练回退

要确认回退后加载的是原先选定的网关构建，请从已审阅的 `main` 提交各选一次成功的构建。准备程序使用 GitHub CLI 下载两份预览包并校验收据，各自安装到独立环境。两个上游版本、宿主和策略仍使用上表的配置。需要本机 `gh` 已登录 `github.com` 并能读取仓库的 Actions 产物。[预览包的来源校验和保留期](verified-preview.md)

以下历史实例中的两个网关均为 `0.3.0a1`。逐项比较两个 wheel 的 25 个成员，只有发行元数据 `METADATA` 和校验清单 `RECORD` 的内容不同。这一对构建适合检查版本号相同时是否还原了指定的安装；网关跨版本迁移需要另选两个实际版本。[原构建](https://github.com/inco308/agent-immunity/actions/runs/43693563690) · [候选构建](https://github.com/inco308/agent-immunity/actions/runs/43694645291)

```bash
python -X utf8 -m pilot.codex_time.prepare --root artifacts/verified-pilot --previous-preview 43693563690 8568e98c5d458b8f25dcf68cc3e1361d5675c90d --candidate-preview 43694645291 7328ca6949dcade4bbf186c827c3eee9c39fab4e
npm ci --prefix pilot/codex_time --ignore-scripts --no-audit --no-fund
python -X utf8 -m pilot.codex_time.run --codex pilot/codex_time/node_modules/.bin/codex --environment artifacts/verified-pilot/environment.json --require-verified-gateways --output-dir artifacts/verified-time-run
```

`--require-verified-gateways` 要求环境描述中有两个独立构建的核验信息，误用单网关环境会直接报错。在 GitHub Actions 的 `codex-time-pilot` 手动运行页，可填写 `previous_run`、`previous_commit`、`candidate_run` 和 `candidate_commit` 复现。四个输入全部留空会从运行所在提交构建一个网关。使用历史预览包时须填全两组运行编号和完整提交 SHA。

### 阅读三阶段结果

运行器先向两个上游采集工具目录，再用已安装的策略检查器核对兼容性。两份检查通过后，运行器确认测试账号的 MCP 注册表为空，在本次演练的 Git 项目创建 `host-project/.codex/config.toml`。文件只有一条 `mcp_servers.time_pilot` 赋值，包含本阶段的网关命令及参数。

每个阶段先把该文件的内容作为单个 `-c` 参数交给 `codex mcp get time_pilot --json`，核对宿主解析出的命令与参数，再把同一赋值传给新启动的 Codex App Server，通过临时线程发现和调用时区工具。配置的生效范围是这两个宿主进程。升级在项目内原子切换上游解释器，双网关演练也会切换网关解释器。回退恢复初始文件字节，三个阶段分别验证业务返回和会话级拒绝。

双网关演练在每个阶段的宿主调用前后各核对一次安装。运行后打开 `artifacts/verified-time-run/report.json`，查看 `install`、`upgrade`、`rollback` 三条记录的 `gateway`。其中 `commit`、`run_id` 和 `artifact_id` 标明来源，`wheel_sha256` 标明所选 wheel，`metadata_sha256` 和 `runtime_files` 分别记录已安装的 `METADATA` 摘要和校验通过的运行时文件数量。同阶段还能看到宿主取得的工具、转换结果和 `TRANSITION_DENIED`。在历史实例中，初始与回退的 wheel 摘要均以 `350a6235` 开头，升级阶段以 `b44de0a5` 开头。

收据和安装文件的对照依赖受信的本机解释器、试点目录和 GitHub 构建记录。文件核对覆盖 wheel 中的 `agent_immunity/` 运行文件和发行元数据 `METADATA`，解释器生成的 `__pycache__/*.pyc` 缓存不计入文件数。宿主结果提供调用行为证据。证明调用期间的进程内存完整性需要额外的观测手段。

两种演练的 `report.json` 都含各阶段版本、工具名、UTC/东京转换结果、星期字段是否存在、拒绝码、配置摘要和耗时。初始与回退的配置摘要应一致，升级摘要应与它们不同。任一阶段发生异常时，运行器记录 `failed` 和失败类型，恢复最近通过验收的项目配置，并返回非零。判断恢复到哪个构建时，应核对失败阶段与最近一次成功阶段。如果首次验收就失败，则移除本次尚未通过验收的配置；若恢复本身失败，报告另记 `rollback_error_type`。文件恢复后仍要重新连接进行业务验收。

## 在平时使用的编码宿主中接入

在自己的受信项目里，先确认演练配置中的绝对路径与本机安装一致。若项目尚无 `time_pilot` 登记，将演练生成的 `mcp_servers.time_pilot` 赋值放到项目 `.codex/config.toml` 文件开头、首个 TOML 表头之前。若项目已有同名登记，先保存原配置，再更新该项的 `command` 和 `args`。打开工作区，在 Codex 的 MCP 工具列表确认 `time_pilot.convert_time` 可用，用同一时区转换例子验证返回值。升级后重新连接，回退时恢复旧配置和上一版本的已验证虚拟环境。[Codex MCP 配置说明](https://developers.openai.com/codex/mcp/)

自动验收从宿主的线程级 MCP 接口发起调用，覆盖发现、实际工具连接和策略拒绝。它没有运行模型规划或验证每种 IDE 图形界面，也没有收集外部团队的采用数据。项目的下一阶段需要独立使用者实际走完上述安装和升级流程。
