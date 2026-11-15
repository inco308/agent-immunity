"""通过真实 MCP 会话和同容器 Linux 进程验收本地 Docker 部署。"""
import argparse
import errno
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid


DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]
OWNER_LABEL = "io.agent-immunity.deployment-check"
MEMORY = 128 * 1024 * 1024
NANO_CPUS = 1_000_000_000
PIDS = 32
CONTAINER_INPUT = "/workspace/input"
CONTAINER_OUTPUT = "/workspace/output"

# 此进程与代理共享容器配置和用户身份，使用操作系统接口独立观测实际权限。
PROBE = """
import json, os, sys
from pathlib import Path
name = "probe-" + sys.argv[1]
def try_create(directory):
    try:
        with (directory / name).open("xb") as target:
            target.write(b"direct-process-check")
    except OSError as exc:
        return exc.errno
    return 0
status = {}
for line in Path("/proc/self/status").read_text().splitlines():
    key, _, value = line.partition(":")
    if key in ("CapEff", "NoNewPrivs"):
        status[key] = int(value.strip(), 16 if key == "CapEff" else 10)
print(json.dumps({
    "uid": os.geteuid(), "gid": os.getegid(),
    "cap_eff": status["CapEff"], "no_new_privs": status["NoNewPrivs"],
    "interfaces": sorted(p.name for p in Path("/sys/class/net").iterdir()),
    "docker_socket_absent": not Path("/var/run/docker.sock").exists(),
    "root_read_only": bool(os.statvfs("/").f_flag & os.ST_RDONLY),
    "input_read_only": bool(os.statvfs("/workspace/input").f_flag & os.ST_RDONLY),
    "output_read_only": bool(os.statvfs("/workspace/output").f_flag & os.ST_RDONLY),
    "root_create_errno": try_create(Path("/tmp")),
    "input_create_errno": try_create(Path("/workspace/input")),
    "output_create_errno": try_create(Path("/workspace/output")),
}))
"""


class VerificationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def docker(args, *, stdin=None, timeout=20):
    result = subprocess.run([*DOCKER, *args], input=stdin, capture_output=True,
                            encoding="utf-8", timeout=timeout, check=False)
    require(result.returncode == 0, f"Docker {args[0]} 调用失败（退出码 {result.returncode}）")
    return result.stdout.strip()


def owned_containers(token):
    text = docker(["container", "ls", "-aq", "--no-trunc", "--filter", f"label={OWNER_LABEL}={token}"])
    ids = text.splitlines()
    require(all(re.fullmatch("[0-9a-f]{64}", cid) for cid in ids), "Docker 返回了无效容器 ID")
    require(len(ids) <= 1, "本次唯一标签匹配到多个容器")
    return ids


def cleanup_owned(token, created_id):
    ids = owned_containers(token)
    if ids:
        require(created_id is None or ids == [created_id], "标签与本次创建的容器不一致")
        docker(["container", "rm", "-f", ids[0]])
    require(not owned_containers(token), "本次容器清理未完成")


def prepare_mounts(directory, token):
    inputs = directory / "input"
    outputs = directory / "output"
    inputs.mkdir(mode=0o700)
    outputs.mkdir(mode=0o700)
    source = inputs / "source.txt"
    source.write_text(token, encoding="utf-8")
    uid, gid = os.geteuid(), os.getegid() or 65532
    if uid == 0:
        uid, gid = 65532, 65532
        for path in (inputs, outputs, source):
            os.chown(path, uid, gid)
    for path in (inputs, outputs):
        require((path.stat().st_mode & 0o777) == 0o700, "请将本次输出设在支持 Linux 目录权限的文件系统")
    return inputs, outputs, uid, gid


def bind_mount(source, destination, readonly=False):
    # Docker --mount 使用 CSV 分隔，拒绝不能直接嵌入的源路径。
    require(not any(c in str(source) for c in ',\n\r"'), "绑定目录名含不支持的 CSV 字符")
    return f"type=bind,src={source},dst={destination}" + (",readonly" if readonly else "")


def inspect_settings(container, uid, gid):
    # 精确选择所需字段，避免采集容器环境、完整命令等内容。
    fields = ("Privileged", "ReadonlyRootfs", "NetworkMode", "CapDrop", "CapAdd", "SecurityOpt",
              "Memory", "NanoCpus", "PidsLimit")
    selectors = [*(".HostConfig." + key for key in fields), ".Mounts", ".Config.User", ".State.Running"]
    fmt = "\n".join("{{json " + field + "}}" for field in selectors)
    values = [json.loads(v) for v in docker(["inspect", "--format", fmt, container]).splitlines()]
    require(len(values) == len(selectors), "Docker inspect 返回字段数量不符")
    host = dict(zip(fields, values))
    mounts, user, running = values[-3:]
    require(running is True and user == f"{uid}:{gid}", "运行状态或用户配置不符")
    require(host["Privileged"] is False and host["ReadonlyRootfs"] is True, "特权或根文件系统配置不符")
    require(host["NetworkMode"] == "none" and set(host.get("CapDrop") or []) == {"ALL"}
            and not host.get("CapAdd"), "容器网络或 capability 配置不符")
    require(any(option in {"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"}
                for option in (host["SecurityOpt"] or [])), "缺少 no-new-privileges")
    require((host["Memory"], host["NanoCpus"], host["PidsLimit"]) == (MEMORY, NANO_CPUS, PIDS),
            "容器资源限额不符")
    expected = {CONTAINER_INPUT: False, CONTAINER_OUTPUT: True}
    require(len(mounts) == 2 and all(m["Type"] == "bind" for m in mounts)
            and {m["Destination"]: m["RW"] for m in mounts} == expected, "绑定目录范围或读写模式不符")
    return {"user": user, "read_only_rootfs": host["ReadonlyRootfs"], "privileged": host["Privileged"],
            "network_mode": host["NetworkMode"], "cap_drop": host["CapDrop"], "cap_add": host["CapAdd"] or [],
            "security_options": host["SecurityOpt"], "pids_limit": host["PidsLimit"], "memory_bytes": host["Memory"],
            "nano_cpus": host["NanoCpus"], "mounts": [{"destination": m["Destination"], "rw": m["RW"],
                                                     "type": m["Type"]} for m in mounts]}


def verify_os(container, uid, gid, token, inputs, outputs):
    # 不指定 exec --user，让新进程使用被测容器的实际用户。
    evidence = json.loads(docker(["exec", "-i", container, "python", "-I", "-X", "utf8", "-", token], stdin=PROBE))
    require(evidence["uid"] == uid and evidence["gid"] == gid and uid != 0, "容器进程实际身份不符")
    require(evidence["cap_eff"] == 0 and evidence["no_new_privs"] == 1, "实际进程权限不符")
    require(evidence["interfaces"] == ["lo"], "发现非回环网络接口")
    require(evidence["docker_socket_absent"], "容器内的默认 Docker socket 仍可见")
    require(evidence["root_read_only"] and evidence["input_read_only"] and not evidence["output_read_only"],
            "容器内实际挂载标志不符")
    for location in ("root", "input"):
        require(evidence[location + "_create_errno"] in (errno.EROFS, errno.EACCES, errno.EPERM),
                "容器进程对只读目录的写入未得到预期拒绝")
    name = "probe-" + token
    require(evidence["output_create_errno"] == 0 and (outputs / name).read_bytes() == b"direct-process-check",
            "容器进程未能写到本次宿主输出目录")
    require(not (inputs / name).exists(), "只读输入目录出现探针写入")
    return evidence


async def verify_session(container, uid, gid, token, inputs, outputs, report):
    import anyio
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    parameters = StdioServerParameters(command=DOCKER[0], args=[*DOCKER[1:], "start", "-ai", container])
    with open(os.devnull, "w") as errors:
        async with stdio_client(parameters, errlog=errors) as (read, write):
            async with ClientSession(read, write) as session:
                with anyio.fail_after(65):
                    initialized = await session.initialize()
                    require(initialized.protocolVersion == "2025-06-18", "MCP 协商版本不符")
                    report["docker_inspect"] = await anyio.to_thread.run_sync(inspect_settings, container, uid, gid)
                    report["os_probe"] = await anyio.to_thread.run_sync(
                        verify_os, container, uid, gid, token, inputs, outputs)
                    listing = await session.list_tools()
                    names = [tool.name for tool in listing.tools]
                    require(sorted(names) == ["read_file", "write_file"],
                            "MCP 工具发现结果不符")
                    original = await session.call_tool("read_file", {"path": "input/source.txt"})
                    require(not original.isError and len(original.content) == 1
                            and original.content[0].type == "text" and original.content[0].text == token,
                            "输入绑定文件的读取结果不符")
                    content = "checked=" + original.content[0].text
                    written = await session.call_tool("write_file", {"path": "output/report.txt", "content": content})
                    require(not written.isError, "MCP 写报告失败")
                    reread = await session.call_tool("read_file", {"path": "output/report.txt"})
                    require(not reread.isError and len(reread.content) == 1 and reread.content[0].type == "text"
                            and reread.content[0].text == content and (outputs / "report.txt").read_bytes() == content.encode(),
                            "容器读回值或宿主报告不符")
                    denials = {}
                    for tool, arguments, expected in (
                        ("write_file", {"path": "input/source.txt", "content": "unexpected"}, "ARGUMENTS_DENIED"),
                        ("python_version", {}, "UNKNOWN_TOOL"),
                    ):
                        denied = await session.call_tool(tool, arguments)
                        meta = denied.model_dump(mode="json", by_alias=True).get("_meta") or {}
                        decision = meta.get("agent_immunity", {})
                        require(denied.isError and decision.get("decision") == "DENY"
                                and decision.get("code") == expected, "调用未得到预期的代理策略拒绝")
                        denials[tool] = expected
                    require((inputs / "source.txt").read_text(encoding="utf-8") == token, "种子输入被更改")
                    report["mcp"] = {"protocol_version": initialized.protocolVersion, "visible_tools": sorted(names),
                                     "input_read": True, "report_read_back": True, "host_report_matches": True,
                                     "input_unchanged": True, "denial_codes": denials}


def safe_error(error):
    if isinstance(error, VerificationError):
        return str(error)
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return "等待 Docker 或 MCP 操作超时"
    for inner in getattr(error, "exceptions", ()):
        reason = safe_error(inner)
        if reason:
            return reason
    return None


def run(image, output):
    from importlib.metadata import PackageNotFoundError, version

    token = uuid.uuid4().hex
    run_dir = output.parent / ("run-" + token)
    run_dir.mkdir(mode=0o700)
    report = {"schema_version": 1, "scope": "LINUX_DOCKER_MCP_DEPLOYMENT",
              "status": "failed", "run_directory": run_dir.name,
              "limits": ["单次本地 Linux 容器部署", "通过挂载标志和写入错误核对只读性",
                         "网络证据为接口列表和 Docker 配置，仅观测当前容器网络命名空间"]}
    create_attempted, container = False, None
    try:
        require(sys.platform == "linux", "验收须在 Linux 宿主上运行")
        try:
            sdk_version = version("mcp")
        except PackageNotFoundError:
            sdk_version = None
        require(sdk_version == "1.30.0", "请安装 interop/requirements.lock 中固定的 MCP SDK")
        import anyio
        report["sdk_version"] = sdk_version
        report["stage"] = "prepare"
        image_id = docker(["image", "inspect", "--format", "{{.Id}}", "--", image])
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "需要本地存在的 Docker 镜像")
        inputs, outputs, uid, gid = prepare_mounts(run_dir, token)
        report["image_id"] = image_id
        report["stage"] = "create"
        create_attempted = True
        container = docker([
            "create", "-i", "--pull=never", "--name", "aimcp-verify-" + token, "--label", f"{OWNER_LABEL}={token}",
            "--user", f"{uid}:{gid}", "--read-only", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", str(PIDS), "--memory", str(MEMORY),
            "--cpus", "1", "--mount", bind_mount(inputs, CONTAINER_INPUT, True),
            "--mount", bind_mount(outputs, CONTAINER_OUTPUT), image_id,
        ])
        require(re.fullmatch(r"[0-9a-f]{64}", container), "Docker create 返回了无效容器 ID")
        report["stage"] = "session"
        anyio.run(verify_session, container, uid, gid, token, inputs, outputs, report)
        report["status"] = "passed"
    except Exception as error:
        report["error"] = safe_error(error) or type(error).__name__
    finally:
        try:
            if create_attempted:
                cleanup_owned(token, container)
            report["cleanup"] = {"container_remaining": False, "create_attempted": create_attempted}
        except Exception as error:
            report["status"] = "failed"
            report["cleanup"] = {"error": safe_error(error) or type(error).__name__}
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{report['status']}: {output}")
    if report["status"] != "passed":
        print(report.get("error") or report["cleanup"].get("error"), file=sys.stderr)
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="本地已构建的 Linux 镜像")
    parser.add_argument("--output", type=Path, required=True, help="此前不存在的结果目录下的 JSON 文件路径")
    args = parser.parse_args()
    output = args.output.absolute()
    try:
        output.parent.mkdir(parents=True, exist_ok=False, mode=0o700)
    except OSError:
        parser.error("请为 --output 指定新目录中的报告路径")
    return run(args.image, output)


if __name__ == "__main__":
    raise SystemExit(main())
