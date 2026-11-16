# 按提交下载并校验开发者预览包

先从你已审阅的 `main` 提交取得完整 SHA，再到 `verify` 工作流选择该提交对应的运行。下载命令要求同时给出这两个值，便于确认手里的 wheel 和源码分发包来自预期构建。[提交记录](https://github.com/inco308/agent-immunity/commits/main/) · [verify 工作流](https://github.com/inco308/agent-immunity/actions/workflows/ci.yml)

## 下载

使用 Python 3.10 或更高版本，在包含本下载脚本的源码仓库根目录运行。需要安装 GitHub CLI，且 `gh` 已登录 `github.com` 并能读取该仓库的 Actions 产物。命令适用于 PowerShell 和 Linux shell。[gh api 参数](https://cli.github.com/manual/gh_api)

```text
python -m scripts.fetch_verified_dist --commit <40位小写SHA> --run-id <正整数> --output <新目录>
```

将尖括号及其中的文字替换为实际值。运行编号是 Actions 运行页面 URL 中 `/actions/runs/` 之后的数字。输出目录必须尚不存在。下面的历史示例选择提交 `7328ca6`，产物可下载的时间取决于仓库保留策略。[示例提交](https://github.com/inco308/agent-immunity/commit/7328ca6949dcade4bbf186c827c3eee9c39fab4e) · [示例运行](https://github.com/inco308/agent-immunity/actions/runs/43694645291)

```text
python -m scripts.fetch_verified_dist --commit 7328ca6949dcade4bbf186c827c3eee9c39fab4e --run-id 43694645291 --output preview-43694645291
```

## 核对结果

成功后打开 `<新目录>/verified/`。这里保存同一版本的 `.whl` 和 `.tar.gz`、原始 `SHA256SUMS` 以及本地生成的 `receipt.json`。下载过程不会安装或执行包，外层 ZIP 只用于校验，不保留在结果中。

| 核对项 | 成功的条件 |
| --- | --- |
| 构建来源 | GitHub 记录属于 `inco308/agent-immunity` 的 `.github/workflows/ci.yml`，事件为推送到 `main`，首次运行已成功完成，`head_sha` 与输入完整相同。重跑会沿用运行编号，因此只接受 `run_attempt=1`。 |
| 外层归档 | 运行中恰有一个名为 `agent-immunity-dist` 的产物，且仍在保留期内。下载的完整 ZIP 的长度和 SHA-256 与 GitHub 为该 artifact ID 提供的记录相同。 |
| 两个分发包 | ZIP 根目录恰有同版本 wheel、源码包和校验清单。逐个计算包的 SHA-256，结果分别与清单中的对应行相同。 |

在收据中，`commit`、`run_url` 和 `artifact_id` 可定位到提交、运行和产物。`archive_digest` 是与 GitHub 记录比对过的 ZIP 摘要。`files` 按文件名记录 wheel 和源码包各自的实测 SHA-256。日后复核本地副本时，可在 `verified/` 中运行 `sha256sum -c SHA256SUMS`。PowerShell 可使用 `Get-FileHash -Algorithm SHA256 -Path *.whl,*.tar.gz`，按文件名与清单比较。[GitHub 运行记录字段](https://docs.github.com/en/rest/actions/workflow-runs#get-a-workflow-run) · [GitHub 产物字段](https://docs.github.com/en/rest/actions/artifacts#list-workflow-run-artifacts)

要在真实宿主中验证升级和回退，可向 Codex 时区工具试点提交两组运行编号与 SHA。准备程序会为原网关和候选网关分别下载、核验和安装 wheel。演练报告将每次实际使用的安装环境与对应收据、业务结果和策略拒绝关联起来。[用两个已核验的网关构建演练回退](codex-time-pilot.md#用两个已核验的网关构建演练回退)

## 下载失败时

- 登录或访问失败时，用 `gh auth status --hostname github.com` 检查当前账号及其读取权限。
- 运行编号与提交不符、运行来自 PR、尚未成功或已重跑时，重新核对运行页的事件、分支、提交和运行次数。
- 产物过期或被删除后，该运行可能仍可查看，归档已经无法下载。若必须复核这一提交，应保留这一限制。若可改用其他版本，请另选已审阅的提交及相应成功运行。GitHub 默认保存工作流产物 90 天，仓库可调整期限。[GitHub 产物保留期](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts)
- 摘要缺失、内容不符或归档结构异常时，当次下载不能作为已核验包使用。复核该提交的构建工作流和运行记录后，在新的输出目录重试。

这次校验依赖本机的 GitHub CLI 及其配置、TLS、GitHub 返回的元数据，以及该提交使用的工作流与构建依赖。收据记录本次比对的结果，包内清单和归档摘要来自同一套 GitHub 构建与存储流程。独立发行签名、可单独验证的构建证明和软件物料清单（SBOM）仍属后续工作。[GitHub 构建证明](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
