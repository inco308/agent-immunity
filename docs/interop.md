# 官方客户端与独立 SDK 的端到端验证

本场景使用已发布的 MCP Inspector `mcpdo` 客户端，通过 Agent Immunity stdio 代理，连接独立的官方 Python SDK 上游。客户端与上游的协议实现均来自官方依赖；仓库脚本负责准备数据、调用外部命令和核对副作用，不使用自制 JSON-RPC 客户端完成主场景。

该验证覆盖确定性的文档处理工作流，没有调用 LLM。它不衡量模型规划能力或提示注入成功率，也不构成 Claude、Cursor 等其他宿主的兼容性声明。

## 固定的验证组合

| 组件 | 版本与范围 |
| --- | --- |
| 真实客户端 | `@modelcontextprotocol/inspector==2.14.0` 中的 `mcpdo` 持久连接客户端 |
| Node.js | `24.22.1`，验证入口会检查精确版本 |
| 独立上游 | 官方 MCP Python SDK `mcp==1.30.0`，使用 `FastMCP` |
| 互操作 Python 环境 | Python 3.12，使用单独虚拟环境与哈希锁定依赖 |
| 协议 | 通过 `legacy` 协商到代理固定支持的 `2025-06-18` stdio 工具子集 |

核心代理仍支持 Python 3.10+，运行时没有增加 Node 或 MCP SDK 依赖。这些依赖仅用于独立上游示例和互操作验证。当前 SDK 的新主版本是 2.x；这里选择官方仍提供关键缺陷与安全修复的 1.x 维护线，固定验证本项目已有的协议范围，未验证 2.x 上游。[官方版本维护说明](https://github.com/modelcontextprotocol/python-sdk/blob/v1.30.0/README.md)

`mcpdo` 是 Inspector 提供的实验性持久连接客户端。它与执行一次命令就断开的 Inspector CLI 生命周期不同；本例需要在多次调用之间保留同一代理会话中的凭证记录。[官方 mcpdo 文档](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/mcpdo)

## 安装和运行

先准备 Python 3.12 与 Node 24.22.1，在仓库根目录运行。命令只安装到工作区；无需修改全局 MCP 客户端配置。

Windows PowerShell：

~~~powershell
python -m venv artifacts/interop-venv
artifacts/interop-venv/Scripts/python.exe -m pip install --require-hashes -r interop/requirements.lock
npm.cmd ci --prefix interop --ignore-scripts --no-audit --no-fund
artifacts/interop-venv/Scripts/python.exe -X utf8 interop/run_e2e.py
~~~

Linux：

~~~sh
python3.12 -m venv artifacts/interop-venv
artifacts/interop-venv/bin/python -m pip install --require-hashes -r interop/requirements.lock
npm ci --prefix interop --ignore-scripts --no-audit --no-fund
artifacts/interop-venv/bin/python -X utf8 interop/run_e2e.py
~~~

验证入口默认使用 PATH 中的 Node。若 Node 24.22.1 位于独立目录，通过 `--node` 指定它的绝对路径，例如：

~~~powershell
artifacts/interop-venv/Scripts/python.exe -X utf8 interop/run_e2e.py --node "D:/tools/node-v24.22.1-win-x64/node.exe"
~~~

上面的工具路径只是写法示例，需要替换为自己的实际安装位置。不要为了通过检查而修改版本断言或忽略依赖锁。更新依赖应重新运行互操作用例并记录新的验证组合。

脚本为子进程移除继承的 `MCP_*` 配置，创建私有 Inspector storage/daemon 目录，并将 OAuth、secret store 和客户端配置路径限定到该目录，不使用用户的默认连接。结束时执行该私有 daemon 的 `stop`，确认停止后清理临时状态。它还启动一个仅监听 `127.0.0.1` 动态端口的 HTTP 接收器；受限宿主必须允许本地进程通信和回环连接。环境阻断应报告为验证失败，不能计作成功防护。

## 实际业务链

数据在 [fixtures.json](../examples/sdk_workspace/fixtures.json)，本地策略模板在 [policy.template.json](../examples/sdk_workspace/policy.template.json)，独立上游实现在 [server.py](../examples/sdk_workspace/server.py)。

一次运行按以下顺序执行：

1. 创建本次运行工作区，填入项目任务、公开说明和虚构凭证文件，生成绝对路径配置。
2. Inspector 建立命名连接，完成初始化，确认协商版本；发现结果只包含代理登记的工具。
3. 从上游读取项目 JSON，应用确定性汇总函数生成 Markdown 状态报告。
4. 通过工具实际写入报告，再从上游读取，核对返回值及磁盘文件内容。
5. 通过网络工具 POST 报告到本地接收器，核对接收内容和请求数量。
6. 在同一个会话中读取一次虚构凭证，执行越权及敏感流出用例，再发送正常术语说明作为良性对照。
7. 检查普通 SDK 工具错误后的会话可用性，以及代理超时关闭后客户端重新连接的行为；显式观察新会话尚未重新读取凭证时的漏检边界，再重新读取凭证验证阻断恢复。
8. 通过官方 Python SDK 的公开通知接口补充验证取消链，最后关闭所有本次测试资源。

业务汇总由脚本计算，不是预先返回一份“任务已完成”的固定上游结果。报告验证只说明这条确定性应用链完成，不等价于模型自主完成任务。

是否保持同一会话依据上游返回的随机 `session_id` 判断，并结合脱敏调用日志核对。客户端显示的 `connectedAt` 不作为上游会话未变化的证据。

## 拒绝发生在哪一层

| 用例 | 行为 | 预期拒绝来源 |
| --- | --- | --- |
| U01 | 调用未登记的 `admin_action` | 代理先过滤工具列表，Inspector 根据发现缓存返回 `tool_not_found`；这不是一次代理 tools/call 拒绝 |
| P01 | 向工作区外写入 | 代理返回 `ARGUMENTS_DENIED` |
| N01 | 请求未允许的回环端口 | 代理返回 `ARGUMENTS_DENIED` |
| S01、S02 | 发布已读取凭证明文或 Base64 表示 | 代理返回 `SENSITIVE_FLOW` |
| S03 | 在 URL 查询参数中携带已读取凭证 | 代理返回 `SENSITIVE_FLOW` |
| S04 | 把已读取凭证的 Base64 表示写入报告 | 代理返回 `SENSITIVE_FLOW` |

每个拒绝用例都同时核对上游调用日志没有增加、接收器没有额外收到请求；还检查管理标记、越界文件和泄漏文件未产生。报告的 `enforcement_layer` 区分 Inspector 与代理，不能将七个用例统一宣传为“七次网关拦截”。

这些检查不改变已公开的保护范围：上游必须受信，工具能力和参数通道必须准确配置；本程序仍不是恶意上游沙箱，也不能阻止所有凭证编码方式或代理之外的外发。

## 错误、超时与取消

上游 `fail_task` 通过 SDK 返回正常工具错误。验证要求 Inspector 接收到工具错误，并且后续 `session_info` 返回同一个上游会话 ID。

上游 `slow_task` 延迟执行，而配置给代理的请求超时更短。验证核对慢工具确实只进入上游一次、客户端收到明确的代理超时消息、旧上游进程退出、延迟标记未产生，之后的调用由 mcpdo 建立新的上游会话。Inspector 将该错误转换成自己的错误对象，未保留代理原始数字错误码；报告不把 Inspector 的错误码冒充代理错误码。

重连由客户端实现；新会话不继承旧代理的凭证记录，不能称为安全状态自愈，也不能把失败调用的自动重放作为恢复手段。脚本保留了实际边界检查：新会话尚未重新读取凭证时，先前虚构凭证的 Base64 表示可以发送到本地接收器；重新读取凭证后，相同请求再次被拒绝。报告以 `cross_session_tracking_limit_observed` 和 `known_limitation=true` 记录这次漏检。此检查通过代表成功复现已知限制，不代表成功阻止外发；只使用公开的虚构凭证和本地接收器。

取消补充验证位于 `interop/sdk_cancellation.py`。mcp 1.30.0 的本地取消作用域或读取超时不会自动发送协议取消通知；本例从 SDK 公开发送流观察实际请求 ID，再通过公开 `send_notification` 和协议类型发送 `notifications/cancelled`，不猜测请求 ID、不访问 SDK 私有计数器。检查上游工具已开始、代理返回 `-32800`、传输结束、直接上游退出及延迟标记未出现。该检查属于 Python SDK 取消链，不是 Inspector 的取消能力声明。

上述超时和取消证据只针对本例延迟任务，不能推导其他工具已经发生的副作用可以回滚。

## 结果与复核

默认输出位于：

- `artifacts/interop/report.json`：版本、场景检查、执行层、会话证据及运行目录。
- `artifacts/interop/status-report.md`：实际生成的项目报告。
- `artifacts/interop/run-.../`：工作区、`policy.json`、`client.json`、仅包含工具名/会话 ID/PID 的上游日志。
- `cancellation.jsonl`：补充取消链的独立脱敏日志，位于相应运行目录。

`report.json` 的 `scope` 为 `INSPECTOR_SDK_APPLICATION_E2E`。只有全部断言和私有 daemon 清理成功时，最终状态才为 `passed`。Inspector、Node 或 SDK 版本检查不符，以及业务断言失败时会返回非零退出码。可用 `--output` 指定另一报告路径；相应产物位于它的父目录。

本场景不调用模型，也不覆盖整个客户端生态或 OS 隔离。不能将其用例数量与模拟规则基准的攻击分母混合计算。远端 CI 是否通过，应核对对应提交的 [Actions 运行](https://github.com/inco308/agent-immunity/actions/workflows/ci.yml)，不要仅引用本地历史输出。

## 手工使用同一客户端

自动验证结束后，生成的 `client.json` 可以继续用于本地发现和文件工具探索。其 HTTP 端口属于已经关闭的自动测试接收器，不能直接重放旧发布请求；完整发布验证请重新运行脚本。手工发布时需另建本地接收器，并同步修改本地策略的 origin。

下面在**新开的 PowerShell 终端**中运行，以免覆盖正在使用的 Inspector 环境变量。先完成上面的安装和一次自动验证。命令创建全新的私有状态目录，不触及默认 daemon；不要移除这些目录设置后再执行 `daemon stop`。

~~~powershell
$nodePath = (Get-Command node).Source
if ((& $nodePath --version) -ne "v24.22.1") { throw "需要 Node 24.22.1" }
$mcpdo = (Resolve-Path "interop/node_modules/@modelcontextprotocol/inspector/clients/mcpdo/build/mcp-bin.js").Path
$runReport = Get-Content "artifacts/interop/report.json" -Raw | ConvertFrom-Json
$configPath = Join-Path $runReport.run_directory "client.json"
$artifactRoot = (Resolve-Path "artifacts").Path
$manualRoot = Join-Path $artifactRoot ("manual-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $manualRoot | Out-Null

Get-ChildItem Env:MCP_* | ForEach-Object { Remove-Item -LiteralPath ("Env:" + $_.Name) }
$env:MCP_STORAGE_DIR = $manualRoot
$env:MCP_INSPECTOR_DAEMON_DIR = Join-Path $manualRoot "daemon"
$env:MCP_INSPECTOR_OAUTH_STATE_PATH = Join-Path $manualRoot "oauth.json"
$env:MCP_INSPECTOR_SECRET_FILE = Join-Path $manualRoot "secrets.json"
$env:MCP_INSPECTOR_SECRET_STORE = "file"
$env:MCP_CLIENT_CONFIG_PATH = Join-Path $manualRoot "client-config.json"
[System.IO.File]::WriteAllText($env:MCP_CLIENT_CONFIG_PATH, "{}", [System.Text.UTF8Encoding]::new($false))
$env:MCP_AUTO_OPEN_ENABLED = "false"
$env:NO_COLOR = "1"

try {
    & $nodePath $mcpdo --format json connect immunity --config $configPath --era legacy --elicit off
    if ($LASTEXITCODE -ne 0) { throw "连接失败" }
    & $nodePath $mcpdo --format json --connection immunity tools/list
    & $nodePath $mcpdo --format json --connection immunity tools/call session_info
    & $nodePath $mcpdo --format json --connection immunity tools/call read_document path:=project.json
    & $nodePath $mcpdo --format json --connection immunity tools/call write_report path:=manual-report.md content:=公开测试报告
    & $nodePath $mcpdo --format json --connection immunity tools/call read_document path:=manual-report.md
    & $nodePath $mcpdo --format json disconnect immunity
} finally {
    & $nodePath $mcpdo --format json daemon stop
}
~~~

使用独立 Node 路径时，只需将 `$nodePath` 赋值为该可执行文件的绝对路径。这段命令只清理当前新终端中的 `MCP_*` 环境变量，不修改机器或用户级环境设置。`--config` 已指定本次连接配置，不要同时设置 `MCP_CATALOG_PATH`。手工命令的业务结果和错误仍需自行核对；自动入口会对这些行为作完整断言。
