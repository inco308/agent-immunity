# 在接入前核对策略和工具声明

开发者预览包提供 `agent-immunity-check`。本地策略决定代理向客户端展示的参数。若上游升级后增加必填参数，代理可以照常启动，但某些调用会到达上游后才失败。检查器比较两侧公开的输入形状，让这类问题可以在部署 CI 中发现。

只检查本地策略时，在源码仓库根目录运行以下命令。安装 wheel 后可用 `agent-immunity-check` 代替 `python -m agent_immunity.doctor`。

```text
python -m agent_immunity.doctor --policy examples/policy.json
```

## 升级前核对新增工具、能力和目录授权

从可信的部署记录取得已验收的策略作为 `--baseline`，把准备上线的策略作为 `--policy`。在能访问两份策略所声明目录的宿主上运行以下命令。检查器只读本地文件，分别以各策略文件的位置解析其工作区，再以工作区解析工具的目录。

```text
agent-immunity-check --policy candidate.json --baseline deployed.json --json
```

例如，旧策略只允许工具 `notes` 读取文件，新策略为它增加写入能力时，报告会给出 `POLICY_CAPABILITIES_ADDED`，并在 `capabilities` 中列出 `write`。首次登记的工具会给出 `POLICY_TOOL_ADDED`，列出它声明的全部能力。只移除工具、撤回能力或调整声明顺序时，不会产生新增项。

如果 `notes` 在两份策略中都保留 `read`，可读范围却从 `reports/daily` 扩大到 `reports`，检查器会给出 `POLICY_FILE_ROOTS_EXPANDED`。对每个这样的工具，报告只给出一条目录诊断，`capabilities` 列出两份策略共同声明的读写能力，具体路径留在本地策略文件中。把授权换到旧范围以外的同级目录也会触发。反向收窄到子目录，或添加已被旧根目录覆盖的子目录，均不会触发目录诊断。

比较依据是检查时宿主解析出的实际目录。迁移工作区后，即使两份策略里的相对路径相同，也可能指向旧范围以外的目录。若符号链接在部署后被改指，仅凭旧策略文件无法还原它当时指向的位置。上线前还需核对网络目标、路径参数、执行参数白名单和状态约束，并用实际宿主验证允许和拒绝的操作。

JSON 中的 `comparison.scope` 为 `added_tools_capabilities_and_file_roots`。两份策略均加载成功时，`comparison.status` 为 `compared`。任一份加载失败时为 `not_compared`，对应诊断的 `policy_role` 为 `candidate` 或 `baseline`。可同时加上 `--catalog`，使用上游快照检查候选策略。基线文件有误时，已加载的候选策略仍接受常规检查。

## 升级后策略加载失败

在发生问题的网关环境中运行 `agent-immunity-check --policy <策略文件> --json`，查看 `findings[].code`。策略的顶层字段 `version` 指定权限配置的格式，目前支持整数 `1`。体检报告的 `schema_version` 指定报告自身的格式。

| 诊断码 | 触发条件 | 处理方式 |
| --- | --- | --- |
| `POLICY_VERSION_UNSUPPORTED` | 文件能按严格 UTF-8 JSON 解析，策略对象声明了当前网关不支持的整数版本。新格式可以包含当前网关不认识的字段。 | 恢复与当前网关配套、最近通过验收的策略，或选择明确支持目标格式的网关。迁移时逐项核对工具权限、参数、目录与状态转换。 |
| `POLICY_INVALID` | 文件无法读取、JSON 截断或有重复键、`version` 缺失或类型错误，以及当前格式下的字段或目录无效等。 | 先确认文件可读并检查完整 UTF-8 JSON，再核对整数版本、策略字段和本地目录。字符串 `"1"`、浮点数 `1.0` 和布尔值 `true` 均不符合版本字段要求。 |

两类错误的体检退出码都是 `1`。代理直接启动时会在创建上游进程前退出，退出码为 `2`，诊断写到 stderr。恢复策略后，用实际部署所用的工具目录再次运行 `--catalog` 检查，并在新会话中验证一次允许调用和一次预期拒绝。

## 核对上游工具目录

要核对上游，将所有分页中的工具名和 `inputSchema` 存为 UTF-8 JSON，传给 `--catalog`。采集器直接连接上游，因为代理返回的列表已经用本地策略替换了输入描述。快照会在已识别的 schema 节点去掉文档注解，包括描述、示例和默认值。下面的示例从源码仓库运行，Python 环境需先按 [互操作指南](interop.md) 安装锁定的 SDK 依赖。示例上游只依赖标准库。

```text
python -m interop.capture_catalog --output artifacts/upstream-tools.json -- python examples/local_tools.py
python -m agent_immunity.doctor --policy examples/policy.json --catalog artifacts/upstream-tools.json --json
```

离线检查本身只读文件。采集命令会启动指定的上游进程，使用固定版本的 stdio 握手和工具发现。上线前请核对命令、工作目录和宿主权限。上游进程启动时就能自行执行代码。快照中的参数名或 schema 常量可能包含内部信息，应在本地保存并审查后分享。

| 退出码 | 状态 | 行动 |
| --- | --- | --- |
| 0 | `pass` | 所选范围的检查通过。仅给策略时范围为 `policy`；提供目录后为 `policy_and_catalog`。 |
| 1 | `error` | 修正无效输入、策略落在声明的可写根内、无法匹配的执行白名单条目、缺少登记工具或输入描述冲突。 |
| 2 | `review` | 审阅新增工具、已有工具新增的能力或扩大的读写目录范围，以及上游超出自动检查范围的 schema 约束。有任何检查错误时优先返回 1。CLI 参数错误也遵循 argparse 的退出码 2。 |

例如，上游接受 number 时，本地只公开 integer 属于合理收窄。上游明确禁止额外属性时，本地多公开一个字段会给出 `FIELD_NOT_ACCEPTED`。上游增加必填字段会给出 `REQUIRED_MISMATCH`。枚举、嵌套对象限制、引用或组合条件会给出 `SCHEMA_REVIEW`。上游另行公开但本地未登记的工具只计入 `hidden_tools`。有限规则检查的是**本地公开输入描述**与上游声明的关系，执行白名单的取值限制另行校验。

报告含本地登记的工具名、字段名和固定诊断码。它不包含参数实值、完整命令或整份目录。通过检查后仍需要验证工具实际使用哪些文件、地址或子进程，以及运行账户能做什么。采集完到实际调用之间的上游变化，需要在升级时重新检查。

## 获取开发者预览包

在对应提交的 GitHub Actions `verify` 页面下载 `agent-immunity-dist` 并解压。在该目录用 `sha256sum -c SHA256SUMS`，或在 PowerShell 中用 `Get-FileHash -Algorithm SHA256` 核对 wheel 与源码包摘要。在新的虚拟环境执行以下命令即可试用本轮版本。

```text
python -m pip install --no-index --no-deps ./agent_immunity-0.3.0a1-py3-none-any.whl
agent-immunity-check --help
agent-immunity --help
```

wheel 安装只使用本地文件。从源码包安装时需要构建后端。示例策略与上游脚本可在对应提交的 `examples/` 目录获取。工作流产物有保留期限，正式版本、长期下载地址以及签名与来源验证属于发行路线图中的后续工作。SHA-256 用于校验文件内容。[产品路线图](product-roadmap.md)
