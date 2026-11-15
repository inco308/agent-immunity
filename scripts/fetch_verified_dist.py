"""从已知的主分支 CI 运行取得发行包，核对来源和摘要后生成查验记录。"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading

from .preview_archive import verify_archive


REPOSITORY = "inco308/agent-immunity"
REPOSITORY_ID = 1381124176
WORKFLOW = ".github/workflows/ci.yml"
ARTIFACT = "agent-immunity-dist"
METADATA_LIMIT = 1024 * 1024
ARCHIVE_LIMIT = 32 * 1024 * 1024
API = f"repos/{REPOSITORY}/actions"


def _positive_id(value):
    return type(value) is int and value > 0


def _matches(record, fields):
    """区分 JSON 布尔值与整数，缺失字段同样不能通过。"""
    return isinstance(record, dict) and all(
        type(record.get(key)) is type(value) and record[key] == value for key, value in fields.items()
    )


def verify_run(run, expected_sha, run_id, repository_id):
    expected = {
        "id": run_id, "path": WORKFLOW, "head_sha": expected_sha, "head_branch": "main",
        "event": "push", "status": "completed", "conclusion": "success", "run_attempt": 1,
    }
    if not _matches(run, expected):
        raise ValueError("运行必须是指定提交在 main 上的成功 push CI，且首次尝试即成功")
    repository = {"id": repository_id, "full_name": REPOSITORY}
    if not all(_matches(run.get(key), repository) for key in ("repository", "head_repository")):
        raise ValueError("工作流或提交的来源仓库不符")


def select_artifact(payload, run_id, expected_sha, repository_id):
    items = payload.get("artifacts") if isinstance(payload, dict) else None
    if not isinstance(items, list) or not _matches(payload, {"total_count": len(items)}):
        raise ValueError("未取得完整的同名产物列表")
    matches = [item for item in items if _matches(item, {"name": ARTIFACT})]
    if len(matches) != 1:
        raise ValueError("找不到唯一的 agent-immunity-dist 产物")
    item = matches[0]
    source = {"id": run_id, "head_sha": expected_sha, "head_branch": "main",
              "repository_id": repository_id, "head_repository_id": repository_id}
    if not _matches(item.get("workflow_run"), source):
        raise ValueError("产物的运行、仓库或提交与指定来源不一致")
    if not _positive_id(item.get("id")) or item.get("expired") is not False:
        raise ValueError("产物已过期或缺少有效编号")
    size = item.get("size_in_bytes")
    if not _positive_id(size) or size > ARCHIVE_LIMIT:
        raise ValueError("产物大小无效或超过 32 MiB")
    digest = item.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("产物缺少有效的 GitHub SHA-256 摘要")
    return item


def _api_bytes(endpoint, limit):
    # 仅由本模块构造相对端点。gh 管理鉴权和短时重定向，二进制响应始终进入管道。
    args = ["gh", "api", "--hostname", "github.com", "--method", "GET", endpoint]
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env={**os.environ, "GH_PROMPT_DISABLED": "1"}) as proc:
        timer = threading.Timer(90, proc.kill)
        timer.start()
        try:
            response = proc.stdout.read(limit + 1)
            if len(response) > limit:
                raise ValueError("GitHub 响应超出大小限制")
            if proc.wait() != 0:
                raise ValueError("GitHub 请求失败，请核对 gh 登录、Actions 读取权限、网络和产物保留期限")
            return response
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()


def fetch_verified(run_id, expected_sha, output):
    if not _positive_id(run_id) or not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise ValueError("需提供正整数运行编号和完整的 40 位小写提交 SHA")
    output = Path(output)
    if os.path.lexists(output):
        raise FileExistsError(f"输出目录已存在：{output}")
    run_path = f"{API}/runs/{run_id}"
    run = json.loads(_api_bytes(run_path, METADATA_LIMIT))
    verify_run(run, expected_sha, run_id, REPOSITORY_ID)
    listing = json.loads(_api_bytes(f"{run_path}/artifacts?name={ARTIFACT}&per_page=100", METADATA_LIMIT))
    artifact = select_artifact(listing, run_id, expected_sha, REPOSITORY_ID)
    data = _api_bytes(f"{API}/artifacts/{artifact['id']}/zip", artifact["size_in_bytes"])
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if len(data) != artifact["size_in_bytes"] or digest != artifact["digest"]:
        raise ValueError("原始 ZIP 的长度或 SHA-256 与 GitHub 的记录不符")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent, prefix=".preview-") as temp:
        work = Path(temp)
        archive = work / "artifact.zip"
        archive.write_bytes(data)
        staging = work / "verified"
        staging.mkdir()
        packages = verify_archive(archive, staging)
        receipt = {
            "repository": REPOSITORY, "repository_id": REPOSITORY_ID, "workflow": WORKFLOW,
            "event": run["event"], "branch": run["head_branch"], "commit": expected_sha,
            "run_id": run_id, "run_attempt": run["run_attempt"], "conclusion": run["conclusion"],
            "run_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
            "artifact_name": ARTIFACT, "artifact_id": artifact["id"], "archive_size": len(data),
            "archive_digest": digest, **packages,
        }
        (staging / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        # 独占创建外层目录，以免覆盖并发下载。整个校验结果在同一文件系统一次移入。
        output.mkdir()
        try:
            staging.rename(output / "verified")
        except OSError:
            output.rmdir()
            raise
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, type=int, help="GitHub Actions 运行编号")
    parser.add_argument("--commit", required=True, help="独立选定的完整 40 位小写 main 提交 SHA")
    parser.add_argument("--output", required=True, type=Path, help="使用一个新目录保存校验结果")
    args = parser.parse_args()
    try:
        receipt = fetch_verified(args.run_id, args.commit, args.output)
    except (OSError, ValueError) as exc:
        print(f"校验失败：{exc}", file=sys.stderr)
        return 1
    print(f"已核验 {receipt['version']}，记录保存于 {args.output / 'verified' / 'receipt.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
