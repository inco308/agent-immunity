"""从指定 main 提交的两次成功 CI 运行读取版本矩阵证据。"""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


REPOSITORY = "inco308/agent-immunity"
REPOSITORY_ID = 1381124176
RUNS_API = f"repos/{REPOSITORY}/actions/runs"
PLATFORMS = ("ubuntu-latest", "windows-latest")
PACKAGE_JOB = re.compile(r"test \(((?:ubuntu|windows|macos)-[a-z0-9.]+), ([0-9]+\.[0-9]+)\)")
PACKAGE_REPORT_STEPS = ("核对两个安装环境的 macOS、架构和 Python 系列", "保存 macOS 安装验收报告")
NATIVE_TARGETS = {
    "lifecycle-macos-arm64": ("macos-15", "codex-time-lifecycle-macos-arm64"),
    "lifecycle-windows-x64": ("windows-2025", "codex-time-lifecycle-windows-x64"),
}


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


def _verify_run(commit, run_id, workflow):
    run = _api(f"{RUNS_API}/{run_id}")
    required = {"id": run_id, "head_sha": commit, "event": "push", "head_branch": "main",
                "status": "completed", "conclusion": "success", "run_attempt": 1,
                "path": f".github/workflows/{workflow}.yml"}
    repo = {"id": REPOSITORY_ID, "full_name": REPOSITORY}
    if (not _matches(run, required)
            or not all(_matches(run.get(key), repo) for key in ("repository", "head_repository"))):
        raise ValueError("证据必须来自本仓库指定提交、指定工作流的首次成功 main 推送")


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
    steps = [s for s in all_steps if s["name"] in PACKAGE_REPORT_STEPS]
    if not steps:
        return None
    if sorted(s["name"] for s in steps) != sorted(PACKAGE_REPORT_STEPS):
        raise ValueError("安装报告核对或上传步骤缺失或重复")
    if system != "macos-15":
        if all(_matches(s, {"status": "completed", "conclusion": "skipped"}) for s in steps):
            return None
        raise ValueError("macOS 安装报告步骤与打包作业平台不符")
    labels = job.get("labels")
    if not isinstance(labels, list) or [label for label in labels if isinstance(label, str)
                                        and label.startswith(("macos-", "ubuntu-", "windows-"))] != [system]:
        raise ValueError("macOS 安装报告作业的运行器标签不符")
    passed = {"status": "completed", "conclusion": "success"}
    if not _matches(job, passed) or not all(_matches(s, passed) for s in steps):
        raise ValueError("macOS 打包作业及两个安装报告步骤需全部成功")
    return f"package-install-macos-15-py{python}"


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
