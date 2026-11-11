"""通过官方 Python SDK 的公开通知接口验证真实 stdio 取消链。"""
import ctypes
from datetime import timedelta
from importlib.metadata import version
import json
import os
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError


def process_is_running(pid: int) -> bool:
    """只查询已知上游 PID，不向 Windows 进程发送 os.kill(pid, 0)。"""
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        kernel.WaitForSingleObject.restype = ctypes.c_ulong
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        handle = kernel.OpenProcess(0x00100000, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:
                return False
            raise OSError(error, "无法查询上游进程状态")
        try:
            status = kernel.WaitForSingleObject(handle, 0)
            if status == 0:
                return False
            if status == 258:
                return True
            raise OSError("上游进程等待状态异常")
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _tool_entered(journal: Path, session_id: str) -> bool:
    if not journal.exists():
        return False
    try:
        rows = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()]
    except json.JSONDecodeError:
        # 日志的最后一行可能还在写入，下一轮再读；整体等待有上限。
        return False
    return any(row.get("tool") == "slow_task" and row.get("session_id") == session_id for row in rows)


async def verify_cancellation(
    python: str,
    repo: Path,
    policy: Path,
    server: Path,
    workspace: Path,
    journal: Path,
) -> dict:
    """验证取消响应、传输 EOF、直接上游退出及延迟写入未发生。"""
    repo, policy, server, workspace, journal = [
        Path(path).resolve() for path in (repo, policy, server, workspace, journal)
    ]
    marker = workspace / "slow-marker.txt"
    if marker.exists():
        raise AssertionError("取消验证要求没有既存的 slow-marker.txt")
    parameters = StdioServerParameters(
        command=str(python),
        args=[
            "-X", "utf8", "-m", "agent_immunity.mcp_stdio",
            "--policy", str(policy), "--timeout", "10", "--",
            str(python), "-X", "utf8", str(server),
            "--workspace", str(workspace), "--journal", str(journal),
        ],
        cwd=repo,
    )
    observed_request = {}
    request_seen = anyio.Event()
    call_finished = anyio.Event()
    transport_closed = anyio.Event()
    call_outcome = {}

    with open(os.devnull, "w", encoding="utf-8") as errlog:
        async with stdio_client(parameters, errlog=errlog) as (transport_read, transport_write):
            client_write, outgoing = anyio.create_memory_object_stream(0)
            incoming, client_read = anyio.create_memory_object_stream(0)

            async def relay_outgoing():
                async with outgoing:
                    async for message in outgoing:
                        request = message.message.root
                        if (
                            isinstance(request, types.JSONRPCRequest)
                            and request.method == "tools/call"
                            and isinstance(request.params, dict)
                            and request.params.get("name") == "slow_task"
                        ):
                            # 观察 SDK 生成的真实请求 ID，不读取 SDK 私有计数器或改写消息。
                            observed_request["id"] = request.id
                            request_seen.set()
                        await transport_write.send(message)

            async def relay_incoming():
                async with incoming:
                    async for message in transport_read:
                        await incoming.send(message)
                # 只在真实传输 EOF 时置位；取消转发任务不会伪造 EOF 证据。
                transport_closed.set()

            async with anyio.create_task_group() as relays:
                relays.start_soon(relay_outgoing)
                relays.start_soon(relay_incoming)
                try:
                    async with ClientSession(
                        client_read, client_write, read_timeout_seconds=timedelta(seconds=15)
                    ) as session:
                        initialized = await session.initialize()
                        if initialized.protocolVersion != "2025-06-18":
                            raise AssertionError("未协商到代理支持的协议版本")
                        info = await session.call_tool("session_info", {})
                        if info.isError or not isinstance(info.structuredContent, dict):
                            raise AssertionError("SDK 会话信息调用失败")
                        session_id = info.structuredContent.get("session_id")
                        pid = info.structuredContent.get("pid")
                        if not isinstance(session_id, str) or not session_id or type(pid) is not int:
                            raise AssertionError("SDK 上游未返回有效会话和进程标识")

                        async def call_slow():
                            try:
                                await session.call_tool("slow_task", {})
                            except McpError as exc:
                                call_outcome["code"] = exc.error.code
                            else:
                                call_outcome["code"] = "unexpected_success"
                            finally:
                                call_finished.set()

                        async with anyio.create_task_group() as calls:
                            calls.start_soon(call_slow)
                            with anyio.fail_after(8):
                                await request_seen.wait()
                                while not _tool_entered(journal, session_id):
                                    await anyio.sleep(0.05)
                            # mcp 1.30 的本地取消/读取超时不会自动发出协议取消通知。
                            # 使用公开 API 和公开协议类型显式取消已观察到的在途请求。
                            with anyio.fail_after(5):
                                await session.send_notification(
                                    types.ClientNotification(
                                        types.CancelledNotification(
                                            params=types.CancelledNotificationParams(
                                                requestId=observed_request["id"],
                                                reason="interop cancellation verification",
                                            )
                                        )
                                    )
                                )
                            with anyio.fail_after(5):
                                await call_finished.wait()
                                await transport_closed.wait()
                            if call_outcome.get("code") != -32800:
                                raise AssertionError(f"未收到代理取消错误：{call_outcome.get('code')}")
                finally:
                    relays.cancel_scope.cancel()

    with anyio.fail_after(5):
        while process_is_running(pid):
            await anyio.sleep(0.05)
    if marker.exists():
        raise AssertionError("已取消的延迟任务仍产生标记文件")
    return {
        "client": "official-python-sdk",
        "sdk_version": version("mcp"),
        "method": "public_send_notification_with_observed_request_id",
        "session_id": session_id,
        "request_id": observed_request["id"],
        "tool_entered": True,
        "response_code": call_outcome["code"],
        "transport_eof": transport_closed.is_set(),
        "upstream_exited": True,
        "late_marker_absent": True,
    }
