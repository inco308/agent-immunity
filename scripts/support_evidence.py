"""读取 main 支持矩阵证据及按独立提交取证的双构建恢复演练。"""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import zipfile


REPOSITORY = "inco308/agent-immunity"
REPOSITORY_ID = 1381124176
RUNS_API = f"repos/{REPOSITORY}/actions/runs"
RECOVERY_ARTIFACT = "codex-time-policy-recovery"
RECOVERY_CHECK_STEP = "验证通过检查的候选策略在网关启动失败后恢复"
RECOVERY_STEPS = (
    "从两次指定的成功构建下载并安装已核验网关",
    RECOVERY_CHECK_STEP,
    "保存策略检查和故障恢复的组合报告",
)
ARCHIVE_LIMIT = 32 * 1024 * 1024
PLATFORMS = ("ubuntu-latest", "windows-latest")
PACKAGE_JOB = re.compile(r"test \(((?:ubuntu|windows|macos)-[a-z0-9.]+), ([0-9]+\.[0-9]+)\)")
PACKAGE_REPORT_CONTRACTS = (
    (("macos-15",), ("核对两个安装环境的 macOS、架构和 Python 系列", "保存 macOS 安装验收报告")),
    (("ubuntu-latest", "windows-latest"), ("核对两个安装环境的 x64 系统、架构和 Python 系列", "保存 x64 安装验收报告")),
)
NATIVE_TARGETS = {
    "lifecycle-macos-arm64": ("macos-15", "codex-time-lifecycle-macos-arm64"),
    "lifecycle-windows-x64": ("windows-2025", "codex-time-lifecycle-windows-x64"),
}


REPO_URL = f"https://github.com/{REPOSITORY}"


def version(value):
    # 只将版本号放入表格，避免把报告中的自由文本或 Markdown 当成证据发布。
    if not isinstance(value, str) or not re.fullmatch(r"[0-9][0-9A-Za-z.+!-]{0,63}", value):
        raise ValueError("报告中的版本号无效")
    return value


def by_name(items):
    indexed = {item["name"]: item for item in items}
    if len(indexed) != len(items):
        raise ValueError("证据中存在重名项目")
    return indexed


def job_link(job, run, os_label, *required_steps):
    if (job["status"] != "completed" or job["conclusion"] != "success"
            or type(job["run_id"]) is not int or job["run_id"] != run
            or os_label not in job["labels"] or type(job["id"]) is not int or job["id"] <= 0):
        raise ValueError("作业运行编号、平台或成功状态不符")
    steps = by_name([step for step in job["steps"] if step["name"] in required_steps])
    for name in required_steps:
        step = steps.get(name, {})
        if step.get("status") != "completed" or step.get("conclusion") != "success":
            raise ValueError(f"缺少成功的验收步骤：{name}")
    return f"[作业记录]({REPO_URL}/actions/runs/{run}/job/{job['id']})"


class _NetworkError(ValueError):
    """可安全重试的只读请求失败。"""


def _gh(args):
    try:
        result = subprocess.run(
            ["gh", *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "GH_PROMPT_DISABLED": "1"}, timeout=60,
        )
    except subprocess.TimeoutExpired:
        raise _NetworkError("读取 GitHub 证据超时") from None
    except OSError:
        raise ValueError("无法启动 GitHub CLI，请确认已安装 gh") from None
    if result.returncode:
        # 错误流可能含短时下载链接或本机路径，仅用来识别临时网络故障。
        message = result.stderr.lower()
        if any(fragment in message for fragment in (
            b"timeout", b"connection reset", b"connection refused", b"unexpected eof",
            b"http 502", b"http 503", b"http 504", b"temporary failure",
        )):
            raise _NetworkError("读取 GitHub 证据时网络暂不可用")
        raise ValueError("读取 GitHub 证据失败，请核对 gh 登录、Actions 读取权限和产物保留期")
    return result.stdout


def _retry(read):
    try:
        return read()
    except _NetworkError:
        return read()


def _api(endpoint, *, pages=False):
    options = ["--paginate", "--slurp"] if pages else []
    return json.loads(_retry(lambda: _gh(["api", "--hostname", "github.com", *options, endpoint])))


def _matches(record, fields):
    return isinstance(record, dict) and all(
        type(record.get(key)) is type(value) and record[key] == value for key, value in fields.items()
    )


def _verify_run(commit, run_id, workflow, *, dispatch=False):
    run = _api(f"{RUNS_API}/{run_id}")
    required = {"id": run_id, "head_sha": commit, "event": "workflow_dispatch" if dispatch else "push",
                "status": "completed", "conclusion": "success", "run_attempt": 1,
                "path": f".github/workflows/{workflow}.yml"}
    if not dispatch:
        required["head_branch"] = "main"
    repo = {"id": REPOSITORY_ID, "full_name": REPOSITORY}
    if (not _matches(run, required)
            or not all(_matches(run.get(key), repo) for key in ("repository", "head_repository"))):
        raise ValueError("证据的提交、仓库、工作流、触发方式或首次运行的成功状态不符")


def _jobs(commit, run_id):
    pages = _api(f"{RUNS_API}/{run_id}/attempts/1/jobs?per_page=100", pages=True)
    if not isinstance(pages, list) or not pages or not all(
        isinstance(page, dict) and isinstance(page.get("jobs"), list) for page in pages
    ):
        raise ValueError("作业列表格式错误")
    jobs = [job for page in pages for job in page["jobs"]]
    identity = {"run_id": run_id, "run_attempt": 1, "head_sha": commit}
    if (not jobs or not all(_matches(page, {"total_count": len(jobs)}) for page in pages)
            or not all(_matches(job, identity) and type(job.get("id")) is int and job["id"] > 0 for job in jobs)
            or len({job["id"] for job in jobs}) != len(jobs)):
        raise ValueError("作业列表不完整、重复或绑定到了其他构建")
    return jobs


def package_artifact_name(job):
    """返回本打包作业应当发布的安装报告产物名；历史作业仍可使用原有证据。"""
    name = job.get("name")
    axis = PACKAGE_JOB.fullmatch(name) if isinstance(name, str) else None
    if axis is None:
        return None
    system, python = axis.groups()
    all_steps = job.get("steps")
    if not isinstance(all_steps, list) or not all(isinstance(s, dict) and isinstance(s.get("name"), str) for s in all_steps):
        raise ValueError("打包作业缺少有效的步骤列表")
    requires_report = False
    for runners, expected_steps in PACKAGE_REPORT_CONTRACTS:
        steps = [s for s in all_steps if s["name"] in expected_steps]
        if not steps:
            continue
        if sorted(s["name"] for s in steps) != sorted(expected_steps):
            raise ValueError("安装报告核对或上传步骤缺失或重复")
        applicable = system in runners
        conclusion = "success" if applicable else "skipped"
        if not all(_matches(s, {"status": "completed", "conclusion": conclusion}) for s in steps):
            raise ValueError("安装报告步骤状态与打包作业平台不符")
        requires_report = requires_report or applicable
    if not requires_report:
        return None
    labels = job.get("labels")
    if not isinstance(labels, list) or [label for label in labels if isinstance(label, str)
                                        and label.startswith(("macos-", "ubuntu-", "windows-"))] != [system]:
        raise ValueError("安装报告作业的运行器标签不符")
    if not _matches(job, {"status": "completed", "conclusion": "success"}):
        raise ValueError("打包作业未成功完成")
    return f"package-install-{system}-py{python}"


def _report(run_id, name, filename="report.json"):
    if filename not in ("report.json", "package-install.json"):
        raise ValueError("未知的构建报告文件名")

    def download():
        # 为每次尝试创建独占新目录，读取的报告不能来自先前中断的下载。
        with tempfile.TemporaryDirectory(prefix="support-evidence-") as work:
            _gh(["run", "download", str(run_id), "--repo", f"github.com/{REPOSITORY}",
                 "--name", name, "--dir", work])
            path = Path(work) / filename
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"构建产物缺少常规文件 {filename}")
            with path.open("rb") as stream:
                data = stream.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise ValueError("构建报告超过 1 MiB")
            report = json.loads(data)
            if not isinstance(report, dict):
                raise ValueError("构建报告必须为 JSON 对象")
            return report

    return _retry(download)


def fetch_evidence(commit, verify_run, pilot_run):
    """按输入的完整提交和运行编号读取 verify 作业、两份互操作报告及 Codex 作业和报告。"""
    if (not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or not all(type(run_id) is int and run_id > 0 for run_id in (verify_run, pilot_run))
            or verify_run == pilot_run):
        raise ValueError("需提供完整的 40 位小写提交 SHA 和两个不同的正整数运行编号")
    workflows = ((verify_run, "ci"), (pilot_run, "codex-time-pilot"))
    for run_id, workflow in workflows:
        _verify_run(commit, run_id, workflow)
    verify_jobs = _jobs(commit, verify_run)
    pilot_jobs = {}
    for job in _jobs(commit, pilot_run):
        name = job.get("name")
        if not isinstance(name, str) or (name != "lifecycle" and name not in NATIVE_TARGETS):
            continue
        if name in pilot_jobs or not _matches(job, {"status": "completed", "conclusion": "success"}):
            raise ValueError(f"Codex 试点需要唯一且成功的 {name} 作业")
        pilot_jobs[name] = job
    if "lifecycle" not in pilot_jobs:
        raise ValueError("Codex 试点缺少 lifecycle 作业")
    artifacts = [package_artifact_name(job) for job in verify_jobs]
    expected = [name for name in artifacts if name is not None]
    if len(set(expected)) != len(expected):
        raise ValueError("多个打包作业对应同一个安装报告")
    verify_jobs = [
        job if name is None else {**job, "package_install_report": _report(verify_run, name, "package-install.json")}
        for job, name in zip(verify_jobs, artifacts)
    ]
    interop = {platform: _report(verify_run, f"interop-{platform}") for platform in PLATFORMS}
    pilot = _report(pilot_run, "codex-time-lifecycle")
    native_pilots = [(pilot_jobs[name], _report(pilot_run, artifact))
                     for name, (_, artifact) in NATIVE_TARGETS.items() if name in pilot_jobs]
    # 产物绑定运行编号。下载期间若已开始重跑，不能把它归入曾成功的第一次尝试。
    for run_id, workflow in workflows:
        _verify_run(commit, run_id, workflow)
    return verify_jobs, interop, pilot_jobs["lifecycle"], pilot, native_pilots


def _download_artifact(commit, run_id, name, *, expected_id=None):
    """按不可复用的产物编号下载，并与 GitHub 的归档摘要核对。"""
    payload = _api(f"{RUNS_API}/{run_id}/artifacts?name={name}&per_page=100")
    if (not _matches(payload, {"total_count": 1}) or not isinstance(payload.get("artifacts"), list)
            or len(payload["artifacts"]) != 1):
        raise ValueError("指定运行缺少唯一的同名产物")
    item = payload["artifacts"][0]
    source = {"id": run_id, "head_sha": commit, "repository_id": REPOSITORY_ID, "head_repository_id": REPOSITORY_ID}
    if not _matches(item, {"name": name, "expired": False}) or not _matches(item.get("workflow_run"), source):
        raise ValueError("构建产物的名称、运行、提交、来源仓库或有效期不符")
    number = item.get("id")
    size = item.get("size_in_bytes")
    if (type(number) is not int or number <= 0 or (expected_id is not None and number != expected_id)
            or type(size) is not int or not 0 < size <= ARCHIVE_LIMIT):
        raise ValueError("构建产物编号与收据不一致或归档大小无效")
    data = _retry(lambda: _gh(["api", "--hostname", "github.com", f"repos/{REPOSITORY}/actions/artifacts/{number}/zip"]))
    checksum = hashlib.sha256(data).hexdigest()
    if len(data) != size or item.get("digest") != "sha256:" + checksum:
        raise ValueError("下载的产物归档与 GitHub 元数据不符")
    return {"id": number, "sha256": checksum, "data": data}


def read_artifact_files(data, limits, *, exact=False):
    """按各成员长度上限读取 ZIP；留存包可要求成员集合完全匹配。"""
    files = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                if member.filename not in limits:
                    if exact:
                        raise ValueError("归档包含额外成员")
                    continue
                if (member.filename in files or member.is_dir()
                        or stat.S_IFMT(member.external_attr >> 16) not in (0, stat.S_IFREG)
                        or member.file_size > limits[member.filename]):
                    raise ValueError("归档成员重复、不是常规文件或长度超限")
                files[member.filename] = archive.read(member)
    except (zipfile.BadZipFile, RuntimeError) as exc:
        raise ValueError("无法读取构建产物归档") from exc
    if files.keys() != limits.keys():
        raise ValueError("构建产物缺少所需文件")
    return files


def _verify_wheel(receipt):
    commit, run_id, number = receipt["commit"], receipt["run_id"], receipt["artifact_id"]
    if (not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or any(type(n) is not int or n <= 0 for n in (run_id, number))):
        raise ValueError("网关构建收据无效")
    _verify_run(commit, run_id, "ci")
    wheel = f"agent_immunity-{version(receipt['version'])}-py3-none-any.whl"
    archive = _download_artifact(commit, run_id, "agent-immunity-dist", expected_id=number)
    files = read_artifact_files(archive["data"], {wheel: ARCHIVE_LIMIT})
    if hashlib.sha256(files[wheel]).hexdigest() != receipt["wheel_sha256"]:
        raise ValueError("来源构建中的 wheel 字节与恢复报告的摘要不符")
    _verify_run(commit, run_id, "ci")
    return archive


def fetch_recovery_evidence(recovery_commit, recovery_run, *, archives=None):
    """核对双构建演练及两个 main 来源；可在全部核验完成后取回三份原始归档。"""
    if (not isinstance(recovery_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", recovery_commit)
            or type(recovery_run) is not int or recovery_run <= 0):
        raise ValueError("需要恢复演练的完整提交 SHA 和正整数运行编号")
    _verify_run(recovery_commit, recovery_run, "codex-time-pilot", dispatch=True)
    jobs = [j for j in _jobs(recovery_commit, recovery_run) if j.get("name") == "lifecycle"]
    if len(jobs) != 1:
        raise ValueError("需要唯一且成功的恢复演练作业")
    job = jobs[0]
    if job.get("labels") != ["ubuntu-24.04"]:
        raise ValueError("恢复演练的作业标签不符")
    try:
        job_link(job, recovery_run, "ubuntu-24.04", *RECOVERY_STEPS)
    except (KeyError, TypeError) as exc:
        raise ValueError("恢复演练作业缺少有效的步骤") from exc
    recovery = _download_artifact(recovery_commit, recovery_run, RECOVERY_ARTIFACT)
    files = read_artifact_files(recovery["data"], {"report.json": 1024 * 1024, "candidate-exit.txt": 3})
    if files["candidate-exit.txt"] not in (b"1\n", b"1\r\n"):
        raise ValueError("候选网关实际退出码与缺失上游的验收不符")
    report = json.loads(files["report.json"])
    if not _matches(report, {"schema_version": 2, "gateway_mode": "verified_previews"}):
        raise ValueError("恢复记录需要两份已核验的网关构建")
    retained = {"recovery": recovery} if archives is not None else None
    try:
        previous, candidate = (report["upstreams"][slot]["gateway"] for slot in ("previous", "candidate"))
        if any(previous[k] == candidate[k] for k in ("commit", "run_id", "artifact_id", "wheel_sha256")):
            raise ValueError("恢复记录没有使用两个独立构建")
        for slot, receipt in (("previous", previous), ("candidate", candidate)):
            archive = _verify_wheel(receipt)
            if retained is not None:
                retained[slot] = archive
    except (TypeError, KeyError) as exc:
        raise ValueError("恢复报告的网关来源收据不完整") from exc
    _verify_run(recovery_commit, recovery_run, "codex-time-pilot", dispatch=True)
    if archives is not None:
        archives.update(retained)
    return job, report, recovery["id"]
