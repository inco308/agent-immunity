"""将本地预览 wheel 和源码包与指定 CI 作业上传的发行文件及安装收据比对。"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from .support_evidence import ARCHIVE_LIMIT, REPOSITORY, fetch_preview_pair, validate_preview_checksums


def read_regular_file(path, limit):
    """核对读取的文件本身，拒绝链接、特殊节点及读取过程中发生的替换。"""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError(f"{path.name} 必须是普通文件")
    if before.st_size > limit:
        raise ValueError(f"{path.name} 超出预览文件大小上限")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        opened = os.fstat(source.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ValueError(f"{path.name} 在打开时发生变化")
        data = source.read(limit + 1)
        after = path.lstat()
        if (len(data) != before.st_size or len(data) > limit or not os.path.samestat(opened, after)
                or after.st_size != before.st_size or after.st_mtime_ns != before.st_mtime_ns):
            raise ValueError(f"{path.name} 在核验时发生变化")
    return data


def verify_pair_with_wheel(directory, commit, run_id, branch="main"):
    """核对两个归档，供准备流程直接使用此次校验所读的 wheel 字节。"""
    directory = Path(directory)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("请选择解压后的常规目录")
    job, report, dist_id, receipt_id = fetch_preview_pair(commit, run_id, branch)
    records = report["packages"]
    names = {p["filename"] for p in records}
    found = {p.name for p in directory.iterdir()
             if p.name.lower().startswith(("agent_immunity-", "agent-immunity-", "agent.immunity-"))
             and p.name.lower().endswith((".whl", ".tar.gz"))}
    if found != names:
        raise ValueError("目录中需要收据列出的同一构建的 wheel 和源码包，请核对包名和数量")
    wheel_bytes = None
    for item in records:
        data = read_regular_file(directory / item["filename"], ARCHIVE_LIMIT)
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError(f"{item['kind']} 的实际 SHA-256 与指定作业的安装收据不符")
        if item["kind"] == "wheel":
            wheel_bytes = data
    sums = directory / "SHA256SUMS"
    has_manifest = os.path.lexists(sums)
    if has_manifest:
        validate_preview_checksums(read_regular_file(sums, 4096), report)
    if wheel_bytes is None:
        raise ValueError("安装收据缺少 wheel")
    receipt = {
        "schema_version": 1, "scope": "LOCAL_PREVIEW_PAIR", "status": "passed",
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "repository": REPOSITORY, "branch": branch, "commit": commit, "run_id": run_id,
        "job": job["name"], "job_id": job["id"], "dist_artifact_id": dist_id,
        "receipt_artifact_id": receipt_id, "local_checksums_verified": has_manifest,
        "packages": [{key: item[key] for key in ("kind", "filename", "installed_version", "sha256", "protocol_version")}
                     for item in records],
    }
    return receipt, wheel_bytes


def verify_pair(directory, commit, run_id, branch="main"):
    receipt, _ = verify_pair_with_wheel(directory, commit, run_id, branch)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", required=True, type=Path, help="已下载并解压的预览发行文件目录")
    parser.add_argument("--commit", required=True, help="预期构建来源的完整提交 SHA")
    parser.add_argument("--run", type=int, required=True, help="同仓库成功的 verify 推送运行编号")
    parser.add_argument("--branch", default="main", help="预期分支，默认 main；验证在审构建时请指定其分支")
    args = parser.parse_args(argv)
    try:
        result = verify_pair(args.dist, args.commit, args.run, args.branch)
    except (ValueError, OSError) as exc:
        print(f"预览发行文件核验失败：{exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
