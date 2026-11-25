# 定位重合的项目与产品

2026-11-21。本文件记录与本项目（本地 MCP stdio 工具策略检查）定位重合的公开工作，以及逐项核对的结果。目的不是排名，而是回答两个问题：**我们的差异点是否真实存在**，以及**哪些能力已经被别人做得更完整**。

证据等级在每一行标注：

- **源码**：本地克隆并读过实现与威胁模型，结论可复核。
- **官方文档**：只依据项目自述、README 或官方文档，未读实现。
- **未核实**：仅见于搜索摘要，未打开原文。

## 四层分工

公开工作可以落在四个不同的层，混在一起比较会得出错误结论：

| 层 | 做什么 | 代表 |
| --- | --- | --- |
| 扫描/体检 | 发现组件、报告注入与配置风险，不参与运行时 | [Snyk Agent Scan](https://github.com/snyk/agent-scan) |
| 决策服务 | 对一次操作出允许/拒绝，执行由集成方自己保证 | [SecAI-Hub/mcp-firewall](https://github.com/SecAI-Hub/mcp-firewall)、[Progent](http://export.arxiv.org/abs/2504.11703) |
| 执行体 | 真正经手调用，能保证"拒绝即未发生" | [Docker MCP Gateway](https://www.docker.com/blog/docker-mcp-gateway-secure-infrastructure-for-agentic-ai/)、[IBM ContextForge](https://github.com/IBM/mcp-context-forge)、本项目 stdio 代理 |
| 模型侧护栏 | 在模型输入输出层做语义检测 | [Meta LlamaFirewall](https://github.com/meta-llama/PurpleLlama)、[NVIDIA NeMo Guardrails](https://docs.nvidia.com/nemo/guardrails/v0.24.0/configure-guardrails/guardrail-catalog/tool-calling) |

本项目的特殊之处是**决策与执行合一**：它在同一个进程里既做判断又把调用转发给真实上游，因此"拒绝"等价于"副作用没有发生"。这一点在下一节的对照里是唯一站得住的差异化，也是最容易被误读成"比别的项目更安全"的地方——它不是更强的防护，只是**责任边界更清楚**。

## 与最接近的实现逐项对照

`SecAI-Hub/mcp-firewall` 是定位最接近的项目：默认拒绝 + 版本化策略 + 会话污点。下列结论来自本地克隆后阅读 `README.md`、`THREAT_MODEL.md`、`taint.go`、`redact.go`、`policies/default-policy.yaml`（Go，生产代码约 4423 行，测试约 2862 行）。

| 维度 | 本项目 | mcp-firewall | 优劣 |
| --- | --- | --- | --- |
| 部署形态 | 单机 stdio 代理，Python 标准库 | 本机回环 HTTP 守护进程，Go | 对方可多客户端共享；本项目零依赖但只能单上游 |
| 默认拒绝 | 未登记工具拒绝 | 未登记 server/tool/resource/method 拒绝 | 对方覆盖的标识维度更多 |
| 策略表达 | 工具、参数类型、路径根、origin、精确执行参数 | server/tool/arg 规则、正则、长度上限、路径限制、限速 | 相当；对方多限速与 trust_level |
| 谁保证拒绝被执行 | 自己代理上游，拒绝即不转发 | 明确声明只做决策，**执行由集成方保证** | **本项目更可靠**；对方在威胁模型里把"调用方可以忽略决策"列为残余风险 |
| 凭证值跟踪 | 从工具结果提取凭证值，在后续汇聚点比对（含有限编码表示） | 未跟踪凭证值；只有会话/身份级标签（如 `fs-read`）与审计日志正则脱敏 | **本项目更细**；对方粒度是"这次会话读过东西" |
| 污点持久性 | 会话内存，进程结束即失效 | 身份级标签跨连接持久，重启后从审计链恢复，24 小时 TTL | **对方明显更强** |
| 容量与失效 | 凭证数、字节数上限，耗尽即结束会话 | 标签数与会话数上限，耗尽置 `unavailable` 并拒绝后续评估 | 都采用失败关闭，对方覆盖面更广 |
| 审计与可追溯 | 有界内存事件队列；可选追加写 JSONL（无哈希链、无签名、不 fsync） | SHA-256 链式审计日志、Ed25519 决策回执、nonce 一次性消费 | **对方明显更强**；本项目的追加写日志只能支撑本机事后核对 |
| 身份与角色 | 无 | 文件落盘凭证 + evaluator/observer/administrator 角色 | 对方有；本项目定位为单用户本机 |
| 注入检测 | 不声称有此能力 | 有正则检测，并自行声明"正则无法证明语义安全" | 都承认做不到 |
| 评测证据 | 规则基准 + 真实模型 16 条轨迹 + 零分母披露 | 未在本文件核对范围内 | 本项目在**评测透明度**上更明确，但样本极小 |

结论：**在"决定是否放行"这件事上，本项目略细；在"让决策可信、可追溯、可持久"这件事上，本项目全面落后。**把两者说成同一档产品是不诚实的。

## 学术来源

这三个方向的原始想法都不属于本项目：

| 工作 | 核心主张 | 与本项目的关系 |
| --- | --- | --- |
| [Progent](http://export.arxiv.org/abs/2504.11703) | 对工具调用施加可编程最小权限策略，动态收窄 | 本项目的 `Policy` 基本是它的工程简化版 |
| [CaMeL](https://arxiv.org/html/2503.18813v2) | 用 capability 与数据流隔离阻断注入对控制流的影响 | 本项目的凭证跟踪是它的极简影子；正解是把标签绑到值上，本项目做的是文本匹配 |
| [IsolateGPT](https://www.ndss-symposium.org/wp-content/uploads/6A-f1131-Wu.pdf) | Hub-and-Spoke 执行隔离，按最小权限分域 | 本项目 `SECURITY.md` 明确声明"不是 OS 沙箱"，它做的正是这个 |
| [AgentDojo](https://scholar.google.fr/citations?view_op=view_citation&hl=zh-CN&user=L-XVbBAAAAAJ&citation_for_view=L-XVbBAAAAAJ:IWHjjKOFINEC) | 动态注入评测环境 | 本项目为 8 个固定场景，量级差两个数量级 |

因此"意图图谱约束工具调用""凭证污点追踪"不应作为创新点写进项目说明，它们是这条研究线的成熟做法。本项目可主张的是工程取舍与证据纪律，不是新机制。

## 已被验证的行业教训

[IBM 关于 ContextForge MCP Gateway 的安全公告](https://www.ibm.com/support/pages/node/7285720)记录了一次**通过嵌套载荷结构绕过安全过滤器**的缺陷。这与本项目在 `A14` 之后仍保留的"未识别秘密/嵌套绕过节"属同一类失败点，说明：

- 参数结构处理是这类产品的真实打穿位置，本项目拒绝额外字段、限制嵌套深度的选择是必要的而非过度设计；
- 大厂网关也会栽在这里，所以"我们做了类型与结构校验"不能当作安全保证来宣传。

## 定位建议

**不建议**把"Agent 运行时安全边界"作为主定位。该表述会立即被与 Docker MCP Gateway、ContextForge、mcp-firewall 比较，而本项目在审计、身份、持久化、并发上都不占优。

**建议**把主定位收窄到本项目已经具备、且在上表里无人占据的位置：

> 在升级 MCP 上游之后、交付给同事之前，用离线检查发现策略失配（工具名、必填参数、类型漂移），并用副作用验收确认被拒绝的调用确实没有写文件或发请求。

支撑这个定位的已有部件：`agent_immunity/doctor.py` 的离线体检、`scripts/check_dist.py` 的发行检查、[编码宿主试点](codex-time-pilot.md)记录的实机升级/回退试点。运行时拦截降级为配套能力，不再作为卖点。

## 未核实与复核方法

本文件下列内容**未经**独立核实，正式对外引用前需要补做：

- Docker MCP Gateway 与 IBM ContextForge 的能力描述仅取自官方文档与项目自述，未安装运行；
- Progent、CaMeL、IsolateGPT 只读摘要级信息，未核对实验设置与适用边界；
- Snyk Agent Scan 只读 README，未评估其检出率；
- mcp-firewall 的运行时行为未做黑盒测试，上表结论来自静态阅读。

建议的复核动作：用同一组夹具（本仓库 `agent_immunity/dataset/cases.json` 的 24 条攻击调用）分别向 mcp-firewall 的 `/v1/evaluate` 与本项目 `DynamicImmunityEngine.check_call` 投递，比较决策差异。这需要为每个项目写一层薄适配器，结果应记录在单独文件，不与本项目成绩合并。

## 检索噪音

搜索 `mcp firewall`、`agent firewall` 会命中大量同名包（`agentguard-mcp`、`agentgate-firewall`、`agentfirewall`、`agentsec-firewall`、`cpex-lasso`，以及 npm 上的 `@vikingowl/mcp-firewall`、`@zhiwansi/mcp-firewall` 等），普遍只有 `0.1.0a1` 级版本号、无公开仓库、无文档。这些**不建议**计入竞品清单，也不建议在其上做技术判断。
