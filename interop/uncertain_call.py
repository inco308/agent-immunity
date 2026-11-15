"""用官方 SDK 实测写入后断线，重新连接并只读核对同一业务操作。"""
import argparse
from contextlib import asynccontextmanager
from datetime import timedelta
from importlib.metadata import version
import json
from pathlib import Path
import shutil
import sys
import tempfile
import uuid

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError

from .capture_catalog import write_atomic


REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
EXPECTED_DATA = {"agent_immunity": {"outcome": "unknown", "automatic_retry": False}}


@asynccontextmanager
async def connect(parameters, *, errlog=sys.stderr):
    async with stdio_client(parameters, errlog=errlog) as (reader, writer):
        async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=20)) as session:
            initialized = await session.initialize()
            if initialized.protocolVersion != "2025-06-18":
                raise ValueError("未协商到代理支持的 MCP 协议版本")
            yield session


async def query(session, arguments, expected_count):
    result = await session.call_tool("query_operation", arguments)
    value = result.structuredContent
    if (result.isError or not isinstance(value, dict) or value.get("operation_id") != arguments["operation_id"]
            or type(value.get("count")) is not int or value["count"] != expected_count
            or not isinstance(value.get("session_id"), str) or not value["session_id"]):
        raise ValueError("只读核对的操作、条数或上游会话标识不符")
    return value


async def verify(root, report):
    workspace = root / "workspace"
    workspace.mkdir()
    ledger = workspace / "operations.jsonl"
    ledger.touch(exist_ok=False)
    policy = root / "policy.json"
    shutil.copyfile(FIXTURES / "uncertain_policy.json", policy)
    parameters = StdioServerParameters(
        command=sys.executable, cwd=REPO,
        args=["-X", "utf8", "-m", "agent_immunity.mcp_stdio", "--policy", str(policy), "--timeout", "10", "--",
              sys.executable, "-I", "-X", "utf8", str(FIXTURES / "uncertain_upstream.py"), str(ledger)],
    )
    arguments = {"path": ledger.name, "operation_id": uuid.uuid4().hex}
    report["step"] = "append_then_disconnect"
    async with connect(parameters) as first:
        before = await query(first, arguments, 0)
        try:
            await first.call_tool("append_operation", arguments)
        except McpError as exc:
            if (exc.error.code != -32003 or exc.error.data != EXPECTED_DATA
                    or exc.error.data["agent_immunity"]["automatic_retry"] is not False):
                raise ValueError("客户端没有取得上游 EOF 和禁止自动重试的结果未知标记") from exc
            report["client_error"] = {"code": exc.error.code, "data": exc.error.data}
        else:
            raise ValueError("已断线的写调用意外取得了工具结果")

    report["step"] = "observe_side_effect"
    committed = ledger.read_bytes()
    expected = {"operation_id": arguments["operation_id"], "writer_session": before["session_id"]}
    rows = [json.loads(line) for line in committed.splitlines()]
    if rows != [expected]:
        raise ValueError("磁盘流水中未恰好记录一次本会话的目标操作")
    report["records_after_disconnect"] = len(rows)

    report["step"] = "read_only_reconciliation"
    # 新 SDK 客户端启动另一代理进程，唯一的工具调用是按同一业务编号查询。
    async with connect(parameters) as second:
        after = await query(second, arguments, 1)
        if after["session_id"] == before["session_id"]:
            raise ValueError("重连没有建立新的上游会话")
    if ledger.read_bytes() != committed:
        raise ValueError("重新连接及只读核对期间流水发生变化")
    report.update(
        new_upstream_session=True, records_before_write=before["count"],
        records_after_reconnect=after["count"], ledger_unchanged_after_reconnect=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=REPO / "artifacts" / "interop" / "uncertain-call.json")
    output = parser.parse_args().output.resolve()
    report = {"schema_version": 1, "scope": "SDK_WRITE_DISCONNECT_RECONCILIATION", "status": "running",
              "sdk_version": version("mcp")}

    def save():
        write_atomic(output, (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))

    save()
    try:
        if report["sdk_version"] != "1.30.0":
            raise ValueError("请使用 interop/requirements.lock 中锁定的 MCP SDK")
        with tempfile.TemporaryDirectory(prefix="uncertain-", dir=output.parent) as temporary:
            anyio.run(verify, Path(temporary), report)
    except Exception as exc:
        report.update(status="failed", error_type=type(exc).__name__)
        raise
    else:
        report.pop("step")
        report["status"] = "passed"
    finally:
        save()
    print(f"已验证写入后断线和只读重连，报告位于 {output}")


if __name__ == "__main__":
    main()
