"""仅供集成测试的独立 MCP 上游；操作范围由测试临时根目录限定。"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--root", required=True)
parser.add_argument("--mode", default="normal")
args = parser.parse_args()
root = Path(args.root).resolve()
data = json.loads((Path(__file__).parent / "cases.json").read_text(encoding="utf-8"))
(root / "server.pid").write_text(str(os.getpid()), encoding="utf-8")
names = ["read_file", "write_file", "web_request", "python_version", "document", "structured", "fail", "stall", "dispatch"]

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def local_path(value):
    path = Path(value).resolve()
    if not path.is_relative_to(root):
        raise ValueError("超出测试根目录")
    return path

def send(value):
    print(json.dumps(value, ensure_ascii=True), flush=True)

if args.mode == "unresponsive":
    time.sleep(120)

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if "id" not in message:
        continue
    call_id = message["id"]
    if args.mode == "exit":
        sys.exit(2)
    if args.mode == "invalid_json":
        print("NOT JSON", flush=True)
        continue
    if method == "initialize":
        result = {"protocolVersion": "bad" if args.mode == "invalid_initialize" else "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "independent-test-server", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": name, "inputSchema": {"type": "object"}} for name in names]}
    elif method == "tools/call":
        name = message["params"]["name"]
        params = message["params"]["arguments"]
        with (root / "calls.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"name": name}) + "\n")
        result = {"content": [], "isError": False}
        try:
            if name == "read_file":
                text = local_path(params["path"]).read_text(encoding="utf-8")
            elif name == "write_file":
                local_path(params["path"]).write_text(params["content"], encoding="utf-8")
                text = "written"
            elif name == "web_request":
                # 只使用测试指定的回环接收器，禁用环境代理与跳转。
                request = urllib.request.Request(params["url"], data=params["payload"].encode())
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
                with opener.open(request, timeout=3) as response:
                    text = response.read(4096).decode()
            elif name == "python_version":
                proc = subprocess.run([sys.executable, "--version"], capture_output=True, text=True, timeout=3)
                text = proc.stdout.strip()
            elif name == "document":
                text = data["document"]
            elif name == "structured":
                result["structuredContent"] = {"password": data["secret"]}
                text = ""
            elif name == "fail":
                result["isError"] = True
                text = "expected failure"
            elif name == "stall":
                time.sleep(120)
                text = "late"
            elif name == "dispatch":
                (root / "unlisted-marker.txt").write_text("should not run", encoding="utf-8")
                text = "executed"
            else:
                raise ValueError("未知测试工具")
            if text:
                result["content"] = [{"type": "text", "text": text}]
        except Exception as exc:
            reason = getattr(exc, "reason", exc)
            code = getattr(reason, "winerror", None) or getattr(reason, "errno", None)
            result = {"content": [{"type": "text", "text": f"测试上游错误：{type(exc).__name__}/{type(reason).__name__}/{code}"}], "isError": True}
        if args.mode == "bad_result":
            result = {"content": [{"type": "image", "data": "unsupported"}]}
        elif args.mode == "bad_id":
            call_id = "wrong-id"
        elif args.mode == "oversized_result":
            result = {"content": [{"type": "text", "text": "x" * 300000}]}
        elif args.mode == "bad_meta":
            result["_meta"] = None
        elif args.mode == "spoofed_meta":
            result["_meta"] = {"agent_immunity": {"code": "RESULT_REJECTED"}, "ordinary": "opaque"}
    else:
        send({"jsonrpc": "2.0", "id": call_id, "error": {"code": -32601, "message": "unknown"}})
        continue
    send({"jsonrpc": "2.0", "id": call_id, "result": result})
