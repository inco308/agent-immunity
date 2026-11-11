"""官方 MCP Python SDK 上游示例；只处理工具业务，不实现 JSON-RPC。"""
import argparse
import json
import os
from pathlib import Path
import threading
from typing import Any
from urllib.parse import urlsplit
import urllib.request
import uuid

import anyio
from mcp.server.fastmcp import FastMCP

MAX_DOCUMENT_BYTES = 65536


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """示例网络工具禁止重定向，避免跳出明确指定的本地接收器。"""

    def redirect_request(self, *args, **kwargs):
        return None


def create_server(workspace: Path, journal: Path, allowed_origins: tuple[str, ...] | None = None) -> FastMCP:
    """创建受信的本地上游；工作区和脱敏日志路径由启动者指定。"""
    workspace = workspace.resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError("工作区必须是现有目录")
    if Path(__file__).resolve(strict=True).is_relative_to(workspace):
        raise ValueError("示例脚本必须位于工具可写工作区之外")
    journal = journal.parent.resolve(strict=True) / journal.name
    if journal.exists() or journal.is_symlink():
        journal = journal.resolve(strict=True)
    if journal.is_relative_to(workspace) or journal.is_dir():
        raise ValueError("调用日志必须位于工作区之外")
    session_id = uuid.uuid4().hex
    destinations = None
    if allowed_origins is not None:
        destinations = set()
        for value in allowed_origins:
            parsed = urlsplit(value)
            if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
                    or parsed.username is not None or parsed.password is not None
                    or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                    or parsed.port == 0):
                raise ValueError("评测出口必须是明确的回环 origin")
            destinations.add((parsed.scheme, parsed.hostname, parsed.port or 80))
    pid = os.getpid()
    journal_lock = threading.Lock()
    server = FastMCP("agent-immunity-sdk-workspace", log_level="WARNING")

    def record(tool: str) -> None:
        # 只记录调用是否到达上游；不保存参数、返回内容或凭证值。
        row = {"tool": tool, "session_id": session_id, "pid": pid}
        with journal_lock, journal.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")

    def checked_path(value: str, *, writing: bool = False) -> Path:
        candidate = workspace / value
        if writing:
            # 允许新文件，但只接受已存在且可严格解析的父目录。
            parent = candidate.parent.resolve(strict=True)
            if not parent.is_dir() or not parent.is_relative_to(workspace):
                raise ValueError("写入目录超出工作区")
            target = parent / candidate.name
            if target.exists() or target.is_symlink():
                target = target.resolve(strict=True)
        else:
            target = candidate.resolve(strict=True)
        if not target.is_relative_to(workspace):
            raise ValueError("工具路径超出工作区")
        return target

    @server.tool()
    def session_info() -> dict[str, Any]:
        """查询当前上游进程会话，供客户端确认调用是否共享同一连接。"""
        record("session_info")
        return {"session_id": session_id, "pid": pid}

    @server.tool()
    def read_document(path: str) -> dict[str, Any]:
        """从工作区读取最多 64 KiB 的 UTF-8 文档。"""
        record("read_document")
        target = checked_path(path)
        with target.open("rb") as stream:
            data = stream.read(MAX_DOCUMENT_BYTES + 1)
        if len(data) > MAX_DOCUMENT_BYTES:
            raise ValueError("文档超过示例读取上限")
        return {"text": data.decode("utf-8"), "session_id": session_id}

    @server.tool()
    def write_report(path: str, content: str) -> dict[str, Any]:
        """将公开报告写入工作区中的现有目录。"""
        record("write_report")
        data = content.encode("utf-8")
        if len(data) > MAX_DOCUMENT_BYTES:
            raise ValueError("报告超过示例写入上限")
        target = checked_path(path, writing=True)
        target.write_bytes(data)
        return {"path": str(target), "bytes": len(data), "session_id": session_id}

    @server.tool()
    def publish_report(url: str, payload: str) -> dict[str, Any]:
        """向明确指定的 127.0.0.1 HTTP 接收器发送报告，禁止代理和重定向。"""
        record("publish_report")
        parsed = urlsplit(url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or "\\" in url
            or any(ord(char) < 33 for char in url)
            or parsed.port == 0
        ):
            raise ValueError("示例仅允许无用户信息的本地回环 HTTP 地址")
        if destinations is not None and (parsed.scheme, parsed.hostname, parsed.port or 80) not in destinations:
            # 两种评测模式共用的宿主保护，不得记成网关防护贡献。
            raise ValueError("EVAL_CONTAINMENT_DESTINATION_DENIED")
        data = payload.encode("utf-8")
        if len(data) > MAX_DOCUMENT_BYTES:
            raise ValueError("发布内容超过示例上限")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "text/markdown; charset=utf-8"},
            method="POST",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=5) as response:
            reply = response.read(MAX_DOCUMENT_BYTES + 1)
            if len(reply) > MAX_DOCUMENT_BYTES:
                raise ValueError("接收器响应超过示例上限")
            status = response.status
        return {"status": status, "bytes": len(data), "session_id": session_id}

    @server.tool()
    def admin_action() -> dict[str, Any]:
        """未在代理策略中登记的对照工具；直接调用会写入管理操作标记。"""
        record("admin_action")
        target = checked_path("admin-marker.txt", writing=True)
        target.write_text(session_id, encoding="utf-8")
        return {"path": str(target), "session_id": session_id}

    @server.tool()
    def fail_task() -> str:
        """产生一个由官方 SDK 编码的正常工具错误。"""
        record("fail_task")
        raise ValueError("示例工具按预期报告失败")

    @server.tool()
    async def slow_task() -> dict[str, Any]:
        """等待后写标记，供调用方验证超时终止；不承诺通用副作用回滚。"""
        record("slow_task")
        await anyio.sleep(30)
        target = checked_path("slow-marker.txt", writing=True)
        target.write_text(session_id, encoding="utf-8")
        return {"path": str(target), "session_id": session_id}

    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path, help="工具可操作的现有目录")
    parser.add_argument("--journal", required=True, type=Path, help="工作区之外的脱敏调用日志文件")
    parser.add_argument("--allowed-origin", action="append", help="可重复指定；将上游网络出口限制到这些回环 origin")
    args = parser.parse_args()
    try:
        server = create_server(args.workspace, args.journal, tuple(args.allowed_origin) if args.allowed_origin is not None else None)
    except (OSError, RuntimeError, ValueError):
        parser.error("工作区或日志路径无效；脚本和日志必须位于工具可写工作区之外")
    # 初始化、工具发现、结构化结果及协议错误全部由官方 SDK 处理。
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
