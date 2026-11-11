# MCP stdio 接入说明

当前代理实现固定 MCP `2025-06-18` 的工具子集，使用一行一个 UTF-8 JSON-RPC 消息的 stdio 通信。它启动并管理一个真实上游进程，向客户端只公开本地策略登记的工具。它并非完整、透明的 MCP 实现，不能据此宣称兼容任意客户端或上游。

协议参考：[生命周期](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle)、[传输](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)、[工具](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)。下面列出的范围以本仓库代码为准。

## 启动

在仓库根目录执行：

```text
python -m agent_immunity.mcp_stdio --policy examples/policy.json -- python ../local_tools.py
```

`--` 之后是受信上游的可执行程序及参数，不经 shell 解析。上游工作目录是策略中的 `workspace`；示例中为 `examples/workspace`，所以 `../local_tools.py` 指向示例脚本。上游继承宿主环境，部署者应在外层提供最小权限账户和合适的环境变量。代理不会创建 OS 沙箱。

`--timeout` 默认 30 秒，范围为大于 0 且不超过 300。用于有在途请求时等待上游响应。进程空闲等待客户端输入时没有该请求超时。客户端必须持续读取代理 stdout：当前下游输出是同步写入，客户端停止读取造成的背压可能阻塞事件循环，超时保证不覆盖这种情况。真实客户端配置建议使用解释器、策略和上游脚本的绝对路径；具体客户端的配置格式需另外核实，本仓库不提供未经验证的客户端适配声明。

若已通过 `python -m pip install .` 安装，可使用等价入口 `agent-immunity --policy ... -- ...`。旧模块名 `python -m agent_immunity.cross_validate.mcp_proxy_demo` 转发到新入口，同样需要策略和上游参数；不再运行预制演示。

## 手工检查协议

终端启动后，先发送一行初始化请求：

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"manual-client","version":"1"}}}
```

等到收到初始化响应，再发送初始化完成通知：

```json
{"jsonrpc":"2.0","method":"notifications/initialized"}
```

随后可发送工具发现请求，收到响应后再调用工具：

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
```

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"sample.txt"}}}
```

固定版本查询使用 `{"name":"python_version","arguments":{}}`。调用 `write_file` 会实际写入示例工作区，请只提供临时文件名和公开内容。

通知不产生响应，因此不要在发送 `notifications/initialized` 后等待一个通知响应。需要等待的是先前的初始化请求。客户端应按响应进行握手，而不是一次性无序发送整套消息。

## 支持范围

| 操作 | 当前行为 |
| --- | --- |
| `initialize` | 校验必要形状；向上游固定请求 2025-06-18，要求上游提供 tools 能力；向客户端返回该版本供其判断兼容性 |
| `notifications/initialized` | 在正确阶段转发，进入就绪状态；不响应通知 |
| `ping` | 由代理本地回复，不能用它证明上游健康 |
| `tools/list` | 转发可选 cursor，仅返回上游列出且本地登记的工具；以本地参数定义替换 inputSchema |
| `tools/call` | 接受 name、arguments 和可选对象类型 _meta；_meta 校验后丢弃，不支持进度输出；单个在途调用；拒绝决定不转发上游 |
| `notifications/cancelled` | ID 匹配在途请求时关闭整个会话并终止直接上游；不保证取消通知先于终止被上游处理 |
| `notifications/tools/list_changed` | 就绪后转发不含额外载荷的通知 |
| 工具结果 | 支持 text 内容列表及可选对象类型 structuredContent；不支持图片、音频、资源链接或嵌入资源 |
| 其他能力 | 不代理 HTTP/SSE、resources、prompts、sampling、elicitation、roots 回调、批量请求或并行工具调用 |

请求参数中的 `_meta` 仅接受对象，校验后丢弃，不向上游传递进度令牌等内容；客户端不应等待进度通知。代理不向上游宣告客户端回调能力；收到服务端请求时返回方法不支持。工具描述可以从上游保留，因此它仍应当作不可信输入处理。当前没有描述清洗或提示注入文本检测保证。

请求 ID 仅允许字符串或整数。在途时新请求通常返回忙；不同 ID 的 ping 可本地响应。与在途请求重复的 ID 会终止会话。当前代理不维护跨整个会话的历史 ID 集合，客户端仍应自行使用唯一 ID。

## 拒绝与异常

策略拒绝返回工具层错误结果，而不是把它伪装成执行成功：

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "content": [{"type": "text", "text": "工具未在本地策略登记"}],
    "isError": true,
    "_meta": {
      "agent_immunity": {
        "decision": "DENY",
        "code": "UNKNOWN_TOOL"
      }
    }
  }
}
```

常用策略码包括 `UNKNOWN_TOOL`、`ARGUMENTS_DENIED`、`TRANSITION_DENIED`、`SENSITIVE_FLOW`、`SESSION_BUSY` 和 `SESSION_CLOSED`。结果无法跟踪时返回 `RESULT_REJECTED` 并关闭会话。仅看 `isError` 无法区分上游工具错误与代理拒绝，应结合代理保留元数据和调用上下文处理。上游结果的 `_meta` 必须是对象，其中 `agent_immunity` 命名空间会被移除，防止上游冒充代理决定；其他上游元数据仍按不可信数据处理。

无效参数、未支持方法、解析失败等使用 JSON-RPC 错误。上游响应超时、非 JSON 输出、错误响应 ID、结果形状不支持、通信结束或结果超限会关闭会话。正常工具错误可以继续会话，但不会更新成功状态。

stdout 只传输协议消息。上游 stderr 被持续读取并丢弃，避免阻塞及把潜在凭证写进代理日志；因此它不是上游调试日志或审计存档。客户端断开时代理终止直接上游进程；不能由此推断所有子孙进程都已停止。

任何关闭或取消都不保证回滚：上游可能已经写文件或发出请求。发生结果不确定时，应由受信宿主核查真实副作用，不能盲目自动重试有副作用的调用。
