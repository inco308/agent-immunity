"""主动关闭 stdio 客户端，核对待确认审计指针并在新 SDK 会话中只读核对流水。"""
import argparse
from importlib.metadata import version
import json
from pathlib import Path
import shutil
import sys
import tempfile
import uuid

import anyio
from anyio.streams.buffered import BufferedByteReceiveStream
from mcp import StdioServerParameters
from mcp.client.stdio import get_default_environment

from .capture_catalog import write_atomic
from .sdk_cancellation import process_is_running
from .uncertain_call import FIXTURES, REPO, connect, query


async def send(process, method, params, request_id=None):
    message = {"jsonrpc": "2.0", "method": method, "params": params}
    if request_id is not None:
        message["id"] = request_id
    await process.stdin.send((json.dumps(message) + "\n").encode())


async def read_result(reader, request_id):
    reply = json.loads(await reader.receive_until(b"\n", 256 * 1024))
    if reply.get("jsonrpc") != "2.0" or reply.get("id") != request_id or not isinstance(reply.get("result"), dict):
        raise ValueError("未收到指定请求的有效结果")
    return reply["result"]


async def disconnect_after_commit(parameters, root, arguments, private_id, errors):
    signal = root / "committed.pid"
    command = [parameters.command, *parameters.args, "--hold-after-commit", str(signal)]
    # open_process 的上下文正常退出时关闭两条客户端管道并等待子进程退出。
    # 只在超时失败时强制清理；强制清理不能计为代理自行完成了断线处理。
    with anyio.fail_after(25):
        async with await anyio.open_process(command, cwd=REPO, env=get_default_environment(), stderr=errors) as process:
            reader = BufferedByteReceiveStream(process.stdout)
            await send(process, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "disconnect-fixture", "version": "1"}}, 1)
            if (await read_result(reader, 1)).get("protocolVersion") != "2025-06-18":
                raise ValueError("客户端未协商到预期协议")
            await send(process, "notifications/initialized", {})
            await send(process, "tools/call", {"name": "query_operation", "arguments": arguments}, 2)
            prior = await read_result(reader, 2)
            data = prior["structuredContent"]
            if (prior.get("isError") or data["operation_id"] != arguments["operation_id"]
                    or type(data["count"]) is not int or data["count"] != 0
                    or not isinstance(data["session_id"], str) or not data["session_id"]):
                raise ValueError("初始只读查询未确认旧会话与空流水")
            await send(process, "tools/call", {"name": "append_operation", "arguments": arguments}, private_id)
            while not signal.exists() or not signal.read_bytes():
                await anyio.sleep(0.025)
            pid = int(signal.read_bytes())
            if not process_is_running(pid) or process.returncode is not None or list((root / "audit").glob("*.unconfirmed.json")):
                raise ValueError("在客户端主动断线前，代理、上游或审计状态不符")
        if process.returncode != 0 or process_is_running(pid):
            raise ValueError("客户端正常断线后，代理未正常结束并回收直接上游")
    return data


def check_pointer(audit, policy):
    markers = list(audit.glob("*.unconfirmed.json"))
    if len(markers) != 1:
        raise ValueError("断线会话需要恰好一个待确认指针")
    marker = json.loads(markers[0].read_bytes())
    fields = {"schema_version", "utc", "session_id", "decision_sequence", "reason"}
    if (set(marker) != fields or type(marker["schema_version"]) is not int or marker["schema_version"] != 1
            or marker["session_id"] != markers[0].name.removesuffix(".unconfirmed.json")
            or marker["reason"] != "upstream_result_unknown"):
        raise ValueError("待确认记录的字段、会话名或原因不符")
    log, = audit.glob("*.jsonl")
    rows = [json.loads(line) for line in log.read_bytes().splitlines()]
    names = sorted(json.loads(policy.read_bytes())["tools"])
    if (log.stem != marker["session_id"] or len(rows) != 2
            or type(marker["decision_sequence"]) is not int or marker["decision_sequence"] != 2):
        raise ValueError("待确认指针未定位断线会话的第二条判定")
    for seq, (row, tool) in enumerate(zip(rows, ("query_operation", "append_operation")), 1):
        if (row["schema_version"] != 1 or row["session_id"] != log.stem or row["sequence"] != seq
                or row["decision_code"] != "ALLOW" or row["tool_index"] != names.index(tool) + 1):
            raise ValueError("指针关联的转发前判定与客户端调用顺序不符")
    return markers[0], marker


async def verify(root, report):
    workspace = root / "workspace"
    workspace.mkdir()
    ledger = workspace / "operations.jsonl"
    ledger.touch()
    audit = root / "audit"
    audit.mkdir()
    policy = root / "policy.json"
    shutil.copyfile(FIXTURES / "uncertain_policy.json", policy)
    parameters = StdioServerParameters(command=sys.executable, cwd=REPO, args=[
        "-X", "utf8", "-m", "agent_immunity.mcp_stdio", "--policy", str(policy),
        "--audit-dir", str(audit), "--timeout", "40", "--",
        sys.executable, "-I", "-X", "utf8", str(FIXTURES / "uncertain_upstream.py"), str(ledger),
    ])
    arguments = {"path": ledger.name, "operation_id": uuid.uuid4().hex}
    private_id = "private-call-" + uuid.uuid4().hex
    diagnostics = root / "diagnostics.txt"
    report["step"] = "disconnect_after_fsync"
    with diagnostics.open("w", encoding="utf-8") as errors:
        before = await disconnect_after_commit(parameters, root, arguments, private_id, errors)
        committed = ledger.read_bytes()
        rows = [json.loads(line) for line in committed.splitlines()]
        if rows != [{"operation_id": arguments["operation_id"], "writer_session": before["session_id"]}]:
            raise ValueError("断线后磁盘上需要恰好一条由原上游写入的操作")
        report["step"] = "resolve_audit_pointer"
        marker_path, marker = check_pointer(audit, policy)
        marker_bytes = marker_path.read_bytes()
        report["step"] = "reconcile_read_only"
        async with connect(parameters, errlog=errors) as second:
            after = await query(second, arguments, 1)
    if (before["session_id"] == after["session_id"] or ledger.read_bytes() != committed
            or len(list(audit.glob("*.jsonl"))) != 2 or list(audit.glob("*.unconfirmed.json")) != [marker_path]
            or marker_path.read_bytes() != marker_bytes):
        raise ValueError("只读重连未保留原流水、独立会话或唯一待确认记录")
    observed = diagnostics.read_bytes() + b"".join(p.read_bytes() for p in audit.iterdir())
    private_values = (arguments["operation_id"], private_id, ledger.name, before["session_id"], after["session_id"],
                      "append_operation", "query_operation")
    if any(value.encode() in observed for value in private_values):
        raise ValueError("审计文件或代理诊断含有本次私有调用信息")
    report.update(decision_sequence=marker["decision_sequence"], reason=marker["reason"],
                  records_before_write=before["count"], records_after_disconnect=len(rows),
                  records_after_reconnect=after["count"], new_upstream_session=True, marker_count=1,
                  ledger_unchanged_after_reconnect=True, private_markers_absent=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=REPO / "artifacts/interop/client-disconnect-audit.json")
    output = parser.parse_args().output.resolve()
    report = {"schema_version": 1, "scope": "CLIENT_DISCONNECT_AUDIT", "status": "running", "sdk_version": version("mcp")}

    def save():
        write_atomic(output, (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode())

    save()
    try:
        if report["sdk_version"] != "1.30.0":
            raise ValueError("请使用互操作环境锁定的 MCP SDK")
        with tempfile.TemporaryDirectory(prefix="lost-client-", dir=output.parent) as temporary:
            anyio.run(verify, Path(temporary), report)
    except Exception as exc:
        report.update(status="failed", error_type=type(exc).__name__)
        raise
    else:
        report.pop("step")
        report["status"] = "passed"
    finally:
        save()
    print(f"已核对断线调用的脱敏审计和实际流水：{output}")


if __name__ == "__main__":
    main()
