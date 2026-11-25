# 上游升级前的验收清单

升级一个 MCP 上游（换版本、换发行源、改依赖）之后，把工具交给同事之前，用这份清单确认三件事：**本地策略对新版本仍然成立**、**业务结果确实由新版本产生**、**被拒绝的调用确实没有发生**。

清单里的命令在本仓库根目录可直接运行，实测记录见文末。工具能力与退出码见[体检与安全预检](doctor.md)。

## 何时使用

适用：上游是受信包、你通过 stdio 代理接入、升级前有可复现的固定版本。

不适用：需要 OS 隔离或恶意上游防护（见 [SECURITY.md](../SECURITY.md)）；上游工具集每次启动都变；你想用它替代真实业务验收——**它只比较输入描述，判断不了行为是否正确**。

## 清单

### 1. 固定升级前后的版本

记录**两个**版本号与发行文件来源，不要用浮动版本。目录检查只有在"旧版确定、新版确定"时才有意义。

```text
上游        mcp-server-time
升级前      2025.9.25
升级后      2026.11.18
协议/SDK    MCP 2025-06-18；采集目录用 mcp 1.30.0 或 2.3.0 均可
```

### 2. 采集升级前的完整工具目录

采集需要官方 MCP SDK，演练工具本身只读文件、不依赖 SDK。安装发行包后执行 `python -m pip install 'agent-immunity[interop]'` 即可使用 `agent-immunity-capture`；在仓库内也可以用 `python -m interop.capture_catalog`（环境见 [interop/requirements.lock](../interop/requirements.lock)）：

```text
agent-immunity-capture --output artifacts/catalog-before.json -- <升级前上游命令>
```

目录必须是完整 `tools/list`：包含全部工具，且没有后续分页（带 `nextCursor` 的快照会被拒绝）。采集器会在已知 schema 节点去掉描述、示例、默认值等注解，因此纯文档改动不会制造差异噪音。

### 3. 跑一次升级前的策略体检

```text
python -m agent_immunity.doctor --policy <你的策略>.json --catalog <升级前目录>.json --json
```

期望 `status` 为 `pass`。**如果不是**：先把策略修好再升级，否则升级后会分不清是新版本的问题还是旧策略本来就有问题。

### 4. 执行升级

按上游自己的方式升级（`pip install`、`npx`、容器镜像替换），并记录实际安装版本。旧版本保留到回滚验证完成为止。

### 5. 采集升级后的目录并跑漂移演练

```text
agent-immunity-capture --output artifacts/catalog-after.json -- <升级后上游命令>
agent-immunity-drill \
  --policy <你的策略>.json \
  --old-catalog artifacts/catalog-before.json \
  --new-catalog artifacts/catalog-after.json \
  --output artifacts/upgrade-drill.json
```

退出码：`0` 通过，`2` 需要人工复核，`1` 存在错误。判定依据是三样东西的并集——升级前的体检结果、升级后的体检结果、两个目录之间的差异。

出现 `1` 时不要继续：`TOOL_MISSING` 表示策略登记的工具已不存在，`REQUIRED_MISMATCH` 表示上游新增了必填字段而策略没有声明。

出现 `2` 时逐条核对 `changes`：

| 变化 | 含义 | 需要做什么 |
| --- | --- | --- |
| `TOOL_ADDED` | 上游新增工具 | 确认是否要登记；代理默认不会向宿主暴露它 |
| `TOOL_REMOVED` | 工具消失 | 通常已由 doctor 判错；否则说明策略未登记该工具 |
| `REQUIRED_STRICTENED` | 上游新增必填 | doctor 会判错，按报错修策略 |
| `REQUIRED_LOOSENED` | 上游不再要求某字段 | **doctor 不报错**，但服务端可能开始使用默认值，必须走第 6 步 |
| `PROPERTY_ADDED` / `PROPERTY_REMOVED` | 参数增删 | 确认策略公开的字段与上游一致 |
| `TYPE_CHANGED` | 参数类型变了 | 核对实际取值，必要时改策略类型 |

### 6. 业务验收（不能省略）

目录检查看不出行为变化，所以要用**同一组固定输入**在升级前后各跑一次真实调用。这一步可以自动化：把调用写进清单，分别采集两份观测，再交给演练工具比较。

调用清单 `calls.json`：

```json
{"version": 1, "calls": [
  {"id": "convert-tokyo", "tool": "convert_time",
   "arguments": {"source_timezone": "UTC", "time": "09:00", "target_timezone": "Asia/Tokyo"}}]}
```

分别采集观测（需要 SDK，见第 2 步的环境说明）：

```text
agent-immunity-probe --calls calls.json --output artifacts/obs-before.json -- <升级前上游命令>
agent-immunity-probe --calls calls.json --output artifacts/obs-after.json  -- <升级后上游命令>
```

断言文件 `expectations.json` 写"必须保持不变的值"和"随运行变化的路径"：

```json
{"version": 1,
 "ignore": ["source.datetime", "target.datetime"],
 "expect": [
   {"id": "convert-tokyo", "path": "time_difference", "equals": "+9.0h"},
   {"id": "convert-tokyo", "contains": "T18:00:00+09:00"}]}
```

再跑一次演练，把观测接进同一份报告：

```text
agent-immunity-drill \
  --policy <你的策略>.json \
  --old-catalog artifacts/catalog-before.json \
  --new-catalog artifacts/catalog-after.json \
  --old-observations artifacts/obs-before.json \
  --new-observations artifacts/obs-after.json \
  --expect expectations.json \
  --output artifacts/upgrade-drill.json
```

判定分三种：**断言失败**直接判错（退出码 1）；字段增删、类型或取值变化判 `review`（退出码 2），需要人确认是否可接受；两者都没有才是 `pass`。观测文件可能包含上游返回的真实数据，按敏感材料保存。

`ignore` 只对路径生效（前缀匹配也生效），用来排除时间戳、随机 id 之类每次都会变的值。断言不写"哪些字段必须存在"，只写"必须成立的值"，这样上游新增字段不会把断言弄坏——新增字段由字段差异单独报出来。

人工仍要确认的是**语义**：字段没变、断言也通过，不代表业务含义没变（例如时区名从 IANA 改成别名、排序规则变化）。

### 7. 副作用验收

拒绝必须等价于没发生。确认被策略拒绝的调用**没有**产生文件、没有发出请求：

- 文件：检查工作区与上游声明的根目录之外是否有新文件；
- 网络：用本地接收器而不是外网地址，记录升级前后的请求数；
- 记录真实拒绝码（如 `TRANSITION_DENIED`），而不是只看客户端有没有报错。

### 8. 记录与回滚

保存：两个版本号、两份目录快照、演练报告、业务验收的输出、回滚后的复验结果。回滚后必须重新连接并**再跑一次业务验收**，因为恢复文件不等于恢复运行状态。

## 接入 CI

把演练作为升级 PR 的必过项，只在目录变化时报红：

```yaml
- name: 升级漂移演练
  run: |
    python -m scripts.upgrade_drill \
      --policy policy.json \
      --old-catalog fixtures/catalog-before.json \
      --new-catalog fixtures/catalog-after.json \
      --output artifacts/upgrade-drill.json --json
```

退出码 `2`（需要复核）在 CI 里等价于失败：它要求人在合并前看一眼 `changes`。若团队接受自动放行 `review`，请在同一份报告里保留变化清单，不要只把退出码当结论。

## 实测记录

2026-11-21，本机 Linux（WSL2）、Python 3.14.4。两个版本都从 PyPI 安装到独立虚拟环境，用 `interop.capture_catalog` 实际采集 `tools/list`，再跑上面的第 5 步。夹具保存在 `tests/fixtures/upgrade/`，回归见 `tests/test_upgrade_drill.py`。

| 升级 | 目录变化 | 观测变化 | 体检（doctor） | 演练判定 |
| --- | --- | --- | --- | --- |
| 2025.8.4 → 2025.9.25 | 无（工具与参数完全一致） | `source.day_of_week`、`target.day_of_week` 新增 | 两次 `pass` | `review`（退出码 2） |
| 2025.9.25 → 2026.11.18 | 新增 `get_time_ago`；`convert_time` 必填由 3 项降为 1 项；`get_current_time` 变为无必填 | `later_occurrence` 新增、开始提供 `structuredContent` | 两次 `pass`，`hidden_tools` 由 1 变 2 | `review`（退出码 2） |

两行都说明同一件事：**doctor 单独跑两次都是 `pass`**。第一行更极端——目录完全一致，只有观测比较才能看出输出多了字段；只看目录会得出"升级无影响"的错误结论。

两次演练的断言（`time_difference == "+9.0h"`、返回含 `T18:00:00+09:00`）在三个版本上全部通过，说明这些关键业务值没有退化。夹具与回归见 `tests/fixtures/upgrade/`、`tests/test_observation_diff.py`。

一个环境细节：`mcp-server-time 2025.8.4` 在 `mcp 2.3.0` 下直接 `ImportError`（它 import 的是旧名 `McpError`，2.x 改名为 `MCPError`）。想让旧版跑起来，采集环境要固定在 `mcp 1.30.0`。这类"旧上游在新 SDK 下起不来"属于升级链自身的风险，清单第 3 步的基线体检能提前暴露它。

## 已知覆盖不到的变化

目录比较看不出行为；观测比较能看出字段增删、类型与取值变化，但以下仍然看不出来：

- 字段没变、取值也在断言范围内，但**语义**变了（时区名从 IANA 改为别名、排序规则变化、单位换算口径变化）；
- 上游放宽约束后悄悄启用的默认值（能看出必填放松，看不出默认值取得合不合理）；
- 同名工具在同名参数上改变行为，且本次调用没有覆盖到；
- 上游在运行期动态注册工具，或以不同名提供同一能力；
- 上游在调用内部产生副作用（写文件、发请求），这属于第 7 步。
