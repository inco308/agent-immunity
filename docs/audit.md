# 判定审计

代理可以可选地把每次判定追加写入本地 JSONL：

```text
agent-immunity --policy policy.json --audit artifacts/audit.jsonl -- python upstream.py
```

默认关闭。启用后，`--audit-max-bytes`（默认 8 MiB）与 `--audit-max-records`（默认 100000）限制文件增长。

## 记录什么

每行一个 JSON 对象，字段固定：

```json
{"v": 1, "seq": 1, "ts": 1795617565.479583, "event": "completion",
 "tool": "python_version", "code": "COMPLETED", "completed": true}
```

| 字段 | 含义 |
| --- | --- |
| `v` | 记录格式版本，当前为 1 |
| `seq` | 序号，重启后从文件尾续接 |
| `ts` | Unix 时间戳 |
| `event` | `decision`（拒绝）、`completion`（完成）、`abort`（中止） |
| `tool` | 策略登记的工具名；未登记的工具记为 `<unregistered>` |
| `code` | 固定诊断码，例如 `ALLOW`、`UNKNOWN_TOOL`、`SENSITIVE_FLOW`、`TOOL_ERROR` |
| `completed` | 该工具调用是否成功完成 |

**不记录**：工具参数、工具返回值、用户目标、策略里的路径与 origin、上游 stderr。字段是白名单，多余内容不会被写进去。凭证候选本身也不会落盘——被 `SENSITIVE_FLOW` 拒绝的调用只留诊断码。

## 写不进去时怎么办

按失败关闭处理：

| 情况 | 行为 |
| --- | --- |
| 启动时打不开文件（目录不存在、无权限） | 拒绝启动，退出码 2，并说明原因 |
| 运行中写入失败（磁盘满、句柄失效） | 拒绝该次调用（`AUDIT_UNAVAILABLE`）并结束会话；后续调用返回 `SESSION_CLOSED` |
| 达到大小或条数上限 | 同上 |

理由：日志出现缺口之后，事后核对就无法区分"没发生"与"没记下来"。如果更希望"审计失败也不要中断业务"，就不要开启这个选项——目前没有降级模式。

## 边界（不要当成合规审计）

- **不防篡改**：没有哈希链、没有签名、没有远程汇聚。能写文件的人也能改日志。
- **不保证不丢**：每行只 `flush`、不 `fsync`，掉电或强杀可能丢尾部若干行。
- **不是完整取证**：只记判定，不记参数与结果。要还原"它到底写了什么文件"，需要另配宿主侧日志或文件系统审计。
- **单进程单文件**：不做并发写入协调，不支持多实例共用同一文件。
- **不覆盖上游自身行为**：上游在被调用内部执行的读写、联网不在判定日志范围内。

需要链式审计与决策回执的场景，应选择专门做决策服务的实现——对照见[定位重合的项目与产品](competitive-landscape.md)。

## 与内存事件的关系

引擎内部本来就有有界内存事件队列（`policy.max_events`），用于运行期自检。审计是同一批字段的持久化副本，不改变任何判定逻辑：开启审计不会放行或拒绝任何原本不会被放行或拒绝的调用，唯一影响是审计不可用时的失败关闭。

## 核对方法

```text
# 某次会话里被拒绝了哪些调用、以什么码
grep '"event": "decision"' artifacts/audit.jsonl

# 出现过的诊断码分布
python -c "import json,sys,collections; print(collections.Counter(json.loads(l)['code'] for l in open('artifacts/audit.jsonl')))"
```

日志里没有参数值，所以它能回答"谁被拒、为什么拒"，不能回答"它想写哪个文件"。后者需要你去核对上游或宿主的日志，或用 `agent-immunity-probe --watch` 做会话前后的文件快照，见[升级前验收清单](upgrade-checklist.md)第 7 步。
