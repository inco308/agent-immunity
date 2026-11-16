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

两种演练的 `report.json` 都含各阶段版本、工具名、UTC/东京转换结果、星期字段是否存在、拒绝码、配置摘要和耗时。初始与回退的配置摘要应一致，升级摘要应与它们不同。任一阶段发生异常时，运行器记录 `failed` 和失败类型，并尝试写回最近通过验收的项目配置。首次安装未完成时会移除本次配置。写回失败时，报告另记 `rollback_error_type`。

### 候选网关启动失败后的恢复

初装已通过、候选升级出现连接失败或工具发现轮询耗尽时，运行器恢复初装配置，重新读取 Codex 注册，再启动一次新的 App Server 和临时线程。它核对策略、可见工具、一次 UTC 到东京的实际转换，以及同会话重复调用被拒绝的结果。在双预览模式下，还会在业务调用前后核对原构建的安装文件和收据。用户取消、认证问题及其他类型的错误保留各自的失败信息。

可使用前文准备的双预览环境重现。下面的 Bash 命令在新项目内让候选网关读取缺失的策略文件，保存网关的实际退出码，并单独验收恢复结果。两条命令应在同一台机器、同一份工作树中运行。

```bash
status=0
python -X utf8 -m pilot.codex_time.run --codex pilot/codex_time/node_modules/.bin/codex \
  --environment artifacts/verified-pilot/environment.json --require-verified-gateways \
  --output-dir artifacts/recovery-run --simulate-candidate-startup-failure || status=$?
python -X utf8 -m pilot.codex_time.check_recovery --runner-exit-code "$status" \
  --environment artifacts/verified-pilot/environment.json --output-dir artifacts/recovery-run
```

升级失败时，运行器返回 `1`，顶层 `status` 为 `failed`。此次演练还要求候选进程退出码为 `2`，且宿主确实未能连接候选网关。只有原配置、原业务和原策略均复验成功，报告才写入 `recovery.status=passed`。运行器尝试重连一次，重连失败的原因记在 `recovery.error_type`。工作流在 `codex-time-recovery` 产物中保存演练证据。该结果覆盖试点运行器新建会话后的恢复，已有编辑器会话中的在途任务仍需单独验证。

## 升级前审阅候选策略

若升级也会更换策略，将候选模板传给同一演练入口。下面的样例为现有时区服务额外登记了 `get_current_time`。在准备好上述环境后运行：

```bash
python -X utf8 -m pilot.codex_time.run --codex pilot/codex_time/node_modules/.bin/codex --environment artifacts/pilot-env/environment.json --output-dir artifacts/time-pilot-review --candidate-policy-template pilot/codex_time/expanded-policy.json
```

运行器把模板复制为本次输出目录下的 `candidate-policy.json`。相对工作区以这份副本所在目录为基准，旧策略和候选策略可以指向同一个演练工作区。完整演练先安装并验证旧版，再用已安装的检查器比较两份策略和已采集的候选上游目录。

| 退出码 | 实际行为 |
| --- | --- |
| 0 | 比较通过。宿主切换到已检查的候选策略副本和新版上游，完成业务验收，再回退到原配置。可用原 `policy.json` 作候选模板复现。 |
| 2 | 检查器要求审阅。宿主继续使用原注册，重新连接旧版并验证一次允许调用和一次预期拒绝。样例的诊断为 `POLICY_TOOL_ADDED`。 |
| 1 | 检查或业务验收发生错误。查看失败报告。若候选检查器正常返回策略错误，完整演练也会复验旧配置。 |

在 `report.json` 中查看 `policy_comparison` 的诊断码和两份策略的摘要。等待审阅时，`stages` 只有已完成的安装；`retained` 记录旧配置的实际回读、业务结果和拒绝码。重新连接失败时，整轮报告失败。加 `--preflight-only` 可单独检查策略和目录，此模式下没有宿主复验证据。

这里暂停的是宿主注册切换。采集候选目录会启动指定的第三方上游，应在隔离环境中使用受信的安装包。策略比较覆盖新增工具、声明能力、读写目录和允许的网络目标；参数白名单及状态约束变化仍需单独审阅。[策略比较范围](doctor.md)

### 候选策略通过后，验证候选网关故障恢复

在干净宿主准备好上面的双预览环境后，为 `--policy-check-python` 指定安装了当前检查器的独立 Python。历史网关可以使用原有策略体检命令；差异检查由新检查器完成，随后候选网关还须用自己的检查器加载这份策略并核对候选工具目录。两个检查都通过后才切换注册。

```bash
python -m venv artifacts/policy-checker
artifacts/policy-checker/bin/python -m pip install --no-index --no-deps artifacts/pilot-wheels/*.whl
python -c "import json,pathlib; p=pathlib.Path('pilot/codex_time/policy.json'); pathlib.Path('artifacts/equivalent.json').write_text(json.dumps(json.loads(p.read_bytes()),sort_keys=True),encoding='utf-8')"
status=0
python -X utf8 -m pilot.codex_time.run --codex pilot/codex_time/node_modules/.bin/codex --environment artifacts/verified-pilot/environment.json --require-verified-gateways --policy-check-python artifacts/policy-checker/bin/python --candidate-policy-template artifacts/equivalent.json --simulate-candidate-startup-failure --output-dir artifacts/policy-recovery || status=$?
python -X utf8 -m pilot.codex_time.check_recovery --output-dir artifacts/policy-recovery --environment artifacts/verified-pilot/environment.json --runner-exit-code "$status" --candidate-policy-template artifacts/equivalent.json
```

这份等价模板的字节摘要与初始策略不同，因此可以核实恢复阶段究竟采用了哪份文件。模拟故障保留已经检查的候选策略，让候选注册指向缺失的上游程序。预期候选网关和升级运行器都返回 `1`，独立验收器返回 `0`。Windows 使用虚拟环境的 `Scripts/python.exe`，在 PowerShell 中通过 `$LASTEXITCODE` 传入运行器的实际退出码。

验收器核对候选策略、故障注册和候选构建的来源，再检查磁盘上的原始注册、恢复后的网关与策略摘要，以及新宿主会话的业务结果。GitHub Actions 的 `codex-time-policy-recovery` 制品保存这次演练的报告。普通 PR 工作流使用本次构建的一个网关；手动提供两组预览收据可复核不同构建的恢复。

## 在平时使用的编码宿主中接入

在自己的受信项目里，先确认演练配置中的绝对路径与本机安装一致。若项目尚无 `time_pilot` 登记，将演练生成的 `mcp_servers.time_pilot` 赋值放到项目 `.codex/config.toml` 文件开头、首个 TOML 表头之前。若项目已有同名登记，先保存原配置，再更新该项的 `command` 和 `args`。打开工作区，在 Codex 的 MCP 工具列表确认 `time_pilot.convert_time` 可用，用同一时区转换例子验证返回值。升级后重新连接，回退时恢复旧配置和上一版本的已验证虚拟环境。[Codex MCP 配置说明](https://developers.openai.com/codex/mcp/)

自动验收从宿主的线程级 MCP 接口发起调用，覆盖发现、实际工具连接和策略拒绝。它没有运行模型规划或验证每种 IDE 图形界面，也没有收集外部团队的采用数据。项目的下一阶段需要独立使用者实际走完上述安装和升级流程。
