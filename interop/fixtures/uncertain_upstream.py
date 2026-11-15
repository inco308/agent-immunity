"""真实 MCP SDK 上游夹具。在私有流水文件中追加一条操作，随即退出。"""
import json
import os
from pathlib import Path
import sys
from typing import Any
import uuid

from mcp.server.fastmcp import FastMCP


def serve(ledger):
    session_id = uuid.uuid4().hex
    server = FastMCP("uncertain-call-fixture", log_level="WARNING")

    def check_path(path):
        if Path(path).resolve(strict=True) != ledger:
            raise ValueError("只接受本次演练的流水文件")

    @server.tool()
    def append_operation(path: str, operation_id: str) -> str:
        check_path(path)
        row = {"operation_id": operation_id, "writer_session": session_id}
        with ledger.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        # 此时记录已落盘，终止这个独立子进程，让连接在工具结果发送前结束。
        os._exit(17)

    @server.tool()
    def query_operation(path: str, operation_id: str) -> dict[str, Any]:
        check_path(path)
        with ledger.open(encoding="utf-8") as stream:
            count = sum(json.loads(line)["operation_id"] == operation_id for line in stream)
        return {"operation_id": operation_id, "count": count, "session_id": session_id}

    server.run(transport="stdio")


if __name__ == "__main__":
    serve(Path(sys.argv[1]).resolve(strict=True))
