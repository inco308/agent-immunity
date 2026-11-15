"""真实 MCP SDK 上游夹具。在私有流水文件中追加一条操作后模拟连接中断。"""
import argparse
import json
import os
from pathlib import Path
import time
from typing import Any
import uuid

from mcp.server.fastmcp import FastMCP


def serve(ledger, commit_signal=None):
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
        if commit_signal is not None:
            # 父进程见到标记时 fsync 已完成。等待客户端先断线，代理负责回收本进程。
            commit_signal.write_text(str(os.getpid()), encoding="ascii")
            time.sleep(60)
            raise RuntimeError("演练超过等待期限")
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--hold-after-commit", type=Path, metavar="SIGNAL")
    args = parser.parse_args()
    serve(args.ledger.resolve(strict=True), args.hold_after_commit)
