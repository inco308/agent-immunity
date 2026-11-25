# 在接入前核对策略和工具声明

开发者预览包提供 `agent-immunity-check`。本地策略决定代理向客户端展示的参数。若上游升级后增加必填参数，代理可以照常启动，但某些调用会到达上游后才失败。检查器比较两侧公开的输入形状，让这类问题可以在部署 CI 中发现。

只检查本地策略时，在源码仓库根目录运行以下命令。安装 wheel 后可用 `agent-immunity-check` 代替 `python -m agent_immunity.doctor`。

```text
python -m agent_immunity.doctor --policy examples/policy.json
```

要核对上游，将所有分页中的工具名和 `inputSchema` 存为 UTF-8 JSON，传给 `--catalog`。采集器直接连接上游，因为代理返回的列表已经用本地策略替换了输入描述。快照会在已识别的 schema 节点去掉文档注解，包括描述、示例和默认值。

采集需要官方 MCP SDK，核心运行时不需要。安装 wheel 后执行 `python -m pip install 'agent-immunity[interop]'` 即可使用 `agent-immunity-capture`；仓库内也可用 `python -m agent_immunity.capture`，或按 [互操作指南](interop.md) 用哈希锁定依赖。缺少 SDK 时采集器会给出安装提示并以退出码 2 结束。下面的示例从源码仓库运行，示例上游只依赖标准库。

```text
python -m interop.capture_catalog --output artifacts/upstream-tools.json -- python examples/local_tools.py
python -m agent_immunity.doctor --policy examples/policy.json --catalog artifacts/upstream-tools.json --json
```

离线检查本身只读文件。采集命令会启动指定的上游进程，使用固定版本的 stdio 握手和工具发现。上线前请核对命令、工作目录和宿主权限。上游进程启动时就能自行执行代码。快照中的参数名或 schema 常量可能包含内部信息，应在本地保存并审查后分享。

| 退出码 | 状态 | 行动 |
| --- | --- | --- |
| 0 | `pass` | 所选范围的检查通过。仅给策略时范围为 `policy`；提供目录后为 `policy_and_catalog`。 |
| 1 | `error` | 修正无效输入、策略落在声明的可写根内、无法匹配的执行白名单条目、缺少登记工具或输入描述冲突。`POLICY_INVALID` 的 `message` 会指出具体字段或工具（例如"工具 convert_time 含不支持的字段: typo_field"），但**不回显配置取值**——版本号、参数类型、路径、限额和命令行都只报字段名，请对照策略文件自行核对。 |
| 2 | `review` | 上游使用超出自动检查范围的 schema 约束。请审阅原始描述和实现，补真实调用测试。CLI 参数错误也遵循 argparse 的退出码 2。 |

例如，上游接受 number 时，本地只公开 integer 属于合理收窄。上游明确禁止额外属性时，本地多公开一个字段会给出 `FIELD_NOT_ACCEPTED`。上游增加必填字段会给出 `REQUIRED_MISMATCH`。枚举、嵌套对象限制、引用或组合条件会给出 `SCHEMA_REVIEW`。上游另行公开但本地未登记的工具只计入 `hidden_tools`。有限规则检查的是**本地公开输入描述**与上游声明的关系，执行白名单的取值限制另行校验。

报告含本地登记的工具名、字段名和固定诊断码。它不包含参数实值、完整命令或整份目录。通过检查后仍需要验证工具实际使用哪些文件、地址或子进程，以及运行账户能做什么。采集完到实际调用之间的上游变化，需要在升级时重新检查。[上游升级前的验收清单](upgrade-checklist.md)把这项检查连同业务验收与副作用验收固定成步骤，并给出 `scripts/upgrade_drill.py`：它把升级前后的两份目录放在一起比较，因此能报出 doctor 单独运行时不报的变化（例如上游放松必填字段）。

## 获取开发者预览包

在对应提交的 GitHub Actions `verify` 页面下载 `agent-immunity-dist` 并解压。在该目录用 `sha256sum -c SHA256SUMS`，或在 PowerShell 中用 `Get-FileHash -Algorithm SHA256` 核对 wheel 与源码包摘要。在新的虚拟环境执行以下命令即可试用本轮版本。

```text
python -m pip install --no-index --no-deps ./agent_immunity-0.3.0a1-py3-none-any.whl
agent-immunity-check --help
agent-immunity --help
```

wheel 安装只使用本地文件。从源码包安装时需要构建后端。示例策略与上游脚本可在对应提交的 `examples/` 目录获取。工作流产物有保留期限，正式版本、长期下载地址以及签名与来源验证属于发行路线图中的后续工作。SHA-256 用于校验文件内容。[产品路线图](product-roadmap.md)
