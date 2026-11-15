# 在 Linux Docker 中运行本地文件工具

这个样例允许客户端从指定目录读取一份公开资料，将结果写入专用输出目录，并在宿主上核对文件内容。容器内运行 Agent Immunity 和仓库的受信上游 `local_tools.py`。客户端通过标准输入输出连接代理，策略只登记 `read_file` 和 `write_file`。Docker 限制这两个进程可以改写的业务文件和使用的网络接口。

## 构建和验收

在 Linux/amd64 的仓库根目录执行以下命令。宿主需要 Python 3.12，以及有权访问本地 `/var/run/docker.sock` 的账户。构建和验收使用同一个以 root 身份运行的 Docker Engine。验收客户端使用锁定在宿主虚拟环境中的官方 MCP Python SDK 1.30.0。容器内的代理从当前提交构建的 wheel 安装。[验收依赖锁](../interop/requirements.lock)

```sh
python3.12 -m venv artifacts/container-venv
. artifacts/container-venv/bin/activate
unset DOCKER_CONTEXT
export DOCKER_HOST=unix:///var/run/docker.sock
python -m pip install --require-hashes -r interop/requirements.lock
python -m pip wheel --no-deps --wheel-dir artifacts/container-wheels .
python deploy/container/build_context.py \
  --wheel artifacts/container-wheels/agent_immunity-*.whl \
  --output artifacts/container-build
docker --host unix:///var/run/docker.sock build --network=none --platform linux/amd64 -t agent-immunity-pilot:local artifacts/container-build
python deploy/container/verify_deployment.py \
  --image agent-immunity-pilot:local \
  --output artifacts/container-e2e/report.json
```

构建脚本核对 wheel 内的运行时代码与当前工作树，并将 wheel、Dockerfile、策略和受信上游脚本复制到新目录。Dockerfile 按摘要固定 Linux/amd64 基础镜像，从上下文中的 wheel 离线安装代理。首次安装宿主依赖和拉取基础镜像可能需要网络。重复运行时，为构建上下文和验收报告选择新的输出目录。[构建脚本](../deploy/container/build_context.py) · [镜像定义](../deploy/container/Dockerfile)

## 哪些目录可用

| 容器内的位置 | Docker 设置 | 在这个工作流中的用途 |
| --- | --- | --- |
| 镜像根文件系统 | 只读 | 保存解释器、程序和策略。 |
| `/workspace/input` | 只读绑定挂载 | 客户端按 `input/source.txt` 读取宿主提供的文件。 |
| `/workspace/output` | 可写绑定挂载 | 客户端写入后可读回 `output/report.txt`，宿主从该专用目录取得结果。 |

容器以非 root 身份运行，移除所有 Linux capabilities，并启用 `no-new-privileges`。内存、CPU 和进程数上限分别为 128 MiB、1 个 CPU 和 32 个进程，swap 使用 Docker 默认设置。`--network none` 保留容器内的回环接口。绑定挂载在 Docker 引擎所在的主机上解析，默认可写，因此输入目录须显式指定 `readonly`。选用独立的普通目录，避免把在用的仓库、用户主目录、Docker 套接字或含其他挂载的目录交给容器。[Docker 网络设置](https://docs.docker.com/engine/network/drivers/none/) · [Docker 绑定挂载](https://docs.docker.com/engine/storage/bind-mounts/) · [容器运行参数](https://docs.docker.com/reference/cli/docker/container/run/)

## 手工启动

以下命令供 UID、主 GID 均非零的普通 Linux 用户从仓库根目录运行。输入和输出属于当前用户，容器使用相同的 UID/GID。自动验收由 root 启动时使用 65532 替代零值，并调整本次专用挂载的属主。输入、输出应放在支持 Linux 文件权限的文件系统上。

```sh
mkdir -p artifacts
pilot_dir=$(mktemp -d "$(pwd)/artifacts/container-manual.XXXXXX")
mkdir "$pilot_dir/input" "$pilot_dir/output"
printf '%s\n' '公开资料：本轮仅处理这一份输入。' > "$pilot_dir/input/source.txt"
docker --host unix:///var/run/docker.sock run --rm -i --pull=never \
  --user "$(id -u):$(id -g)" --read-only \
  --network none --cap-drop ALL --security-opt no-new-privileges \
  --memory 128m --cpus 1 --pids-limit 32 \
  --mount "type=bind,src=$pilot_dir/input,dst=/workspace/input,readonly" \
  --mount "type=bind,src=$pilot_dir/output,dst=/workspace/output" \
  agent-immunity-pilot:local
```

最后一条命令可作为 stdio 客户端的服务端命令。直接从终端启动时，它会等待协议初始化。客户端配置若分开填写命令与参数，请使用 `docker` 作命令，并将 UID/GID 和两个挂载的宿主路径替换为实际值。[MCP 协议输入示例](mcp_integration.md#手工检查协议) · [容器内的工具策略](../deploy/container/policy.json)

## 读验收报告

验收程序用官方 SDK 连接容器，协商 MCP `2025-06-18`，要求工具列表恰为 `read_file` 和 `write_file`。同一会话先读取 `input/source.txt`，给返回的文本加上 `checked=` 前缀，写入 `output/report.txt`，再核对上游读回的内容与宿主文件。请求改写输入应得到 `ARGUMENTS_DENIED`，原文件内容保持完整。另一次调用直接请求受信上游确实实现、但本地策略未登记的 `python_version`，应得到 `UNKNOWN_TOOL`。

在 `report.json` 的 `docker_inspect` 中可以核对实际挂载和资源配置。`os_probe` 来自同一容器内通过 `docker exec` 启动的独立进程，记录进程的 UID/GID、有效 capabilities、`NoNewPrivs`、仅有的 `lo` 接口、Docker 套接字是否存在及挂载标志。进程还尝试在根文件系统的 `/tmp` 和只读输入目录创建文件，并在输出目录创建对照文件。这些观测与代理返回的策略拒绝分别记录。[验收程序](../deploy/container/verify_deployment.py)

报告的 `scope` 为 `LINUX_DOCKER_MCP_DEPLOYMENT`。`run_directory` 指向报告同级的本次运行目录，可直接查看输入文件、业务输出及探针对照文件。退出码为零、`status` 为 `passed`、`cleanup.container_remaining` 为 `false` 表示本次验收和容器清理成功。如果容器无法启动，先确认 Docker 引擎和账户访问权限。如果允许的输出写入失败，检查宿主专用输出目录的属主、权限及挂载方式。

本例的结论限于上述 Linux 引擎、启动参数、两个受信工具和实际受测的路径。持有 Docker 管理权限的宿主、代理以外的客户端连接、工具在已授权目录内的操作仍有各自的权限边界。其他 Agent、rootless Docker、用户命名空间重新映射、额外的 SELinux 策略和生产部署需要单独验收。此流程只在本地构建镜像，不向 PyPI 或镜像仓库发布。[项目威胁模型](../SECURITY.md)
