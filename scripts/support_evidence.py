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


def _report(run_id, name):
    def download():
        # 为每次尝试创建独占新目录，读取的报告不能来自先前中断的下载。
        with tempfile.TemporaryDirectory(prefix="support-evidence-") as work:
            _gh(["run", "download", str(run_id), "--repo", f"github.com/{REPOSITORY}",
                 "--name", name, "--dir", work])
            path = Path(work) / "report.json"
            if path.is_symlink() or not path.is_file():
                raise ValueError("构建产物缺少常规文件 report.json")
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
    pilot_jobs = [job for job in _jobs(commit, pilot_run) if job.get("name") == "lifecycle"]
    if len(pilot_jobs) != 1 or not _matches(pilot_jobs[0], {"status": "completed", "conclusion": "success"}):
        raise ValueError("Codex 试点缺少唯一成功的 lifecycle 作业")
    interop = {platform: _report(verify_run, f"interop-{platform}") for platform in PLATFORMS}
    pilot = _report(pilot_run, "codex-time-lifecycle")
    # 产物绑定运行编号。下载期间若已开始重跑，不能把它归入曾成功的第一次尝试。
    for run_id, workflow in workflows:
        _verify_run(commit, run_id, workflow)
    return verify_jobs, interop, pilot_jobs[0], pilot
