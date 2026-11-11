"""受信上游示例：仅操作启动工作区，且仅执行固定的 Python 版本查询。"""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path.cwd().resolve()
TOOLS = ("read_file", "write_file", "python_version")

def local_path(value):
    target = (ROOT / value).resolve()
    if not target.is_relative_to(ROOT):
        raise ValueError("路径越界")
    return target

def invoke(name, arguments):
    if name == "read_file":
        with local_path(arguments["path"]).open("rb") as stream:
            data = stream.read(65537)
        if len(data) > 65536:
            raise ValueError("示例读取上限为 64 KiB")
        return data.decode("utf-8")
    if name == "write_file":
        text = arguments["content"]
        if len(text.encode("utf-8")) > 65536:
            raise ValueError("示例写入上限为 64 KiB")
        local_path(arguments["path"]).write_text(text, encoding="utf-8")
        return "written"
    if name == "python_version" and arguments == {}:
        completed = subprocess.run([sys.executable, "--version"], capture_output=True, text=True, timeout=5, check=True)
        return completed.stdout.strip()
    raise ValueError("工具不支持")

def main():
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request.get("method")
        response = {"jsonrpc": "2.0", "id": request["id"]}
        if method == "initialize":
            response["result"] = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "local-tools-example", "version": "0.2.0"}}
        elif method == "tools/list":
            response["result"] = {"tools": [{"name": name, "description": "本地示例工具；参数由代理的本地策略定义。", "inputSchema": {"type": "object"}} for name in TOOLS]}
        elif method == "tools/call":
            try:
                text = invoke(request["params"]["name"], request["params"].get("arguments", {}))
                response["result"] = {"content": [{"type": "text", "text": text}], "isError": False}
            except Exception:
                response["result"] = {"content": [{"type": "text", "text": "示例工具执行失败"}], "isError": True}
        elif method == "ping":
            response["result"] = {}
        else:
            response["error"] = {"code": -32601, "message": "unsupported"}
        print(json.dumps(response, ensure_ascii=True), flush=True)

if __name__ == "__main__":
    main()
