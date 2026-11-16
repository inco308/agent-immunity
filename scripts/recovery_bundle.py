"""在线留存一次双构建演练的原始归档，或凭独立保存的 SHA-256 离线复核。"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import zipfile

from .recovery_matrix import digest, render_recovery
from .support_evidence import (
    ARCHIVE_LIMIT, RECOVERY_STEPS, REPOSITORY, fetch_recovery_evidence, read_artifact_files, version,
)


ROLES = ("recovery", "previous", "candidate")
MANIFEST_LIMIT = 64 * 1024
BUNDLE_LIMIT = 3 * ARCHIVE_LIMIT + MANIFEST_LIMIT + 4096


def _summary(manifest, contents):
    """验证归档内部的运行、构建和业务关联，生成与在线矩阵相同的恢复附表。"""
    if (type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
            or manifest["repository"] != REPOSITORY or set(manifest["artifacts"]) != set(ROLES)):
        raise ValueError("留存包的版本、仓库或产物集合不符")
    timestamp = manifest["verified_at"]
    instant = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    if instant.isoformat(timespec="seconds") + "Z" != timestamp:
        raise ValueError("缺少规范的 UTC 在线核验时间")

    receipts = manifest["artifacts"]
    for role in ROLES:
        if (type(receipts[role]["id"]) is not int or receipts[role]["id"] <= 0
                or hashlib.sha256(contents[role]).hexdigest() != receipts[role]["sha256"]):
            raise ValueError(f"{role} 归档编号或 SHA-256 不符")
    files = read_artifact_files(contents["recovery"], {"report.json": 1024 * 1024, "candidate-exit.txt": 3})
    if files["candidate-exit.txt"] not in (b"1\n", b"1\r\n"):
        raise ValueError("候选网关的实际退出码不符")
    report = json.loads(files["report.json"])
    for role in ("previous", "candidate"):
        build = report["upstreams"][role]["gateway"]
        wheel = f"agent_immunity-{version(build['version'])}-py3-none-any.whl"
        payload = read_artifact_files(contents[role], {wheel: ARCHIVE_LIMIT})
        if build["artifact_id"] != receipts[role]["id"] or hashlib.sha256(payload[wheel]).hexdigest() != build["wheel_sha256"]:
            raise ValueError(f"{role} 的 wheel 与恢复报告收据不符")

    candidate = report["upstreams"]["candidate"]["gateway"]
    table = render_recovery(manifest["recovery_commit"], manifest["recovery_run"], manifest["job"], report,
                            receipts["recovery"]["id"], matrix_commit=candidate["commit"],
                            verify_run=candidate["run_id"], gateway_version=candidate["version"])
    return f"上次在线核验时间（采集机 UTC）为 {timestamp}。\n\n{table}"


def capture(commit, run, dest):
    dest = Path(dest)
    if os.path.lexists(dest):
        raise FileExistsError("目标已存在，请为本次留存选择新文件")
    archives = {}
    job, _, artifact_id = fetch_recovery_evidence(commit, run, archives=archives)
    if artifact_id != archives["recovery"]["id"]:
        raise ValueError("留存归档与已在线核验的恢复运行不符")
    selected_job = {k: job[k] for k in ("id", "name", "run_id", "run_attempt", "head_sha", "labels", "status", "conclusion")}
    selected_job["steps"] = [{k: step[k] for k in ("name", "status", "conclusion")}
                             for step in job["steps"] if step["name"] in RECOVERY_STEPS]
    manifest = {
        "schema_version": 1, "repository": REPOSITORY, "recovery_commit": commit, "recovery_run": run,
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "job": selected_job,
        "artifacts": {role: {"id": item["id"], "sha256": item["sha256"]} for role, item in archives.items()},
    }
    contents = {role: item["data"] for role, item in archives.items()}
    _summary(manifest, contents)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=dest.parent, delete=False) as stream:
        temporary = Path(stream.name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as bundle:
            bundle.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode("utf-8"))
            for role in ROLES:
                bundle.writestr(role + ".zip", contents[role])
        checksum = hashlib.sha256(temporary.read_bytes()).hexdigest()
        # 同目录原子发布：同名文件被其他采集进程抢先创建时，保留先完成的结果。
        if os.name == "nt":
            # Windows 的 rename 拒绝覆盖已有文件，也适用于不支持硬链接的卷。
            os.rename(temporary, dest)
        else:
            os.link(temporary, dest)
    finally:
        temporary.unlink(missing_ok=True)
    return checksum


def verify(dest, expected_sha256):
    checksum = digest(expected_sha256.lower())
    dest = Path(dest)
    if not dest.is_file():
        raise ValueError("请选择常规 ZIP 文件")
    with dest.open("rb") as stream:
        data = stream.read(BUNDLE_LIMIT + 1)
    if len(data) > BUNDLE_LIMIT or hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError("留存包过大或与独立保存的 SHA-256 不符")
    limits = {"manifest.json": MANIFEST_LIMIT, **{role + ".zip": ARCHIVE_LIMIT for role in ROLES}}
    members = read_artifact_files(data, limits, exact=True)
    try:
        manifest = json.loads(members["manifest.json"])
        return _summary(manifest, {role: members[role + ".zip"] for role in ROLES})
    except (KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise ValueError("留存包清单或报告字段无效") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    collect = modes.add_parser("capture", help="从 GitHub 在线核验并保存三份原始产物")
    collect.add_argument("--commit", required=True, help="演练的完整提交 SHA")
    collect.add_argument("--run", required=True, type=int, help="双构建手动演练的运行编号")
    collect.add_argument("--output", required=True, type=Path, help="新建的本地 ZIP 路径")
    offline = modes.add_parser("verify", help="复核本地留存包并显示在线核验时间")
    offline.add_argument("--bundle", required=True, type=Path)
    offline.add_argument("--sha256", required=True, help="留存时单独记录的整个包的 SHA-256")
    args = parser.parse_args(argv)
    try:
        if args.mode == "capture":
            print(capture(args.commit, args.run, args.output))
        else:
            print(verify(args.bundle, args.sha256), end="")
    except (ValueError, OSError) as exc:
        print(f"恢复证据核验失败：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
