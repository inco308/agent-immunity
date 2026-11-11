"""固定 MCP 2025-06-18 工具子集的 stdio 策略代理。"""
import argparse
import queue
import subprocess
import sys
import threading
import time
from . import DynamicImmunityEngine, Policy, ToolCall, ToolResult
from .core.policy import canonical, strict_json

VERSION = "2025-06-18"

def valid_id(value):
    return type(value) in (str, int)

def error(call_id, code, message):
    return {"jsonrpc": "2.0", "id": call_id, "error": {"code": code, "message": message}}

class StdioProxy:
    def __init__(self, policy, command, timeout=30, input_stream=None, output_stream=None):
        self.policy = policy
        self.command = command
        self.timeout = timeout
        # 后台线程可能仍等待客户端输入；避免解释器退出时争抢缓冲读取锁。
        self.input = input_stream or sys.stdin.buffer.raw
        self.output = output_stream or sys.stdout.buffer
        self.engine = DynamicImmunityEngine(policy)
        self.messages = queue.Queue(maxsize=64)
        self.outgoing = queue.Queue(maxsize=64)
        self.process = None
        self.pending = None
        self.phase = "NEW"
        self.running = True
        self.exit_code = 0

    def emit(self, message):
        self.output.write((canonical(message) + "\n").encode("utf-8"))
        self.output.flush()

    def send(self, message):
        encoded = (canonical(message) + "\n").encode("utf-8")
        if len(encoded) > self.policy.max_bytes:
            raise ValueError("转发帧超过上限")
        try:
            self.outgoing.put_nowait(encoded)
        except queue.Full as exc:
            raise ValueError("上游发送队列已满") from exc

    def writer(self):
        # 将阻塞写入移出事件循环，保证上游不读取时仍可处理超时和取消。
        try:
            while True:
                remaining = memoryview(self.outgoing.get())
                while remaining:
                    size = self.process.stdin.write(remaining)
                    if not size:
                        raise OSError("写入中断")
                    remaining = remaining[size:]
        except (OSError, ValueError):
            self.messages.put(("upstream", ValueError("发送中断")))

    def reader(self, source, stream):
        try:
            buffered = bytearray()
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    self.messages.put((source, ValueError("不完整通信帧") if buffered else None))
                    return
                buffered.extend(chunk)
                while b"\n" in buffered:
                    end = buffered.index(b"\n") + 1
                    if end > self.policy.max_bytes:
                        self.messages.put((source, ValueError("通信帧过长")))
                        return
                    self.messages.put((source, bytes(buffered[:end])))
                    del buffered[:end]
                if len(buffered) >= self.policy.max_bytes:
                    self.messages.put((source, ValueError("通信帧过长")))
                    return
        except (OSError, ValueError):
            self.messages.put((source, ValueError("通信流中断")))

    def discard_stderr(self):
        # 持续排空，防止上游阻塞；不把可能含凭证的上游日志写入代理审计。
        try:
            while self.process.stderr.read(4096):
                pass
        except (OSError, ValueError):
            pass

    def fail(self, code, message):
        if self.pending:
            self.emit(error(self.pending["id"], code, message))
        self.engine.abort()
        self.pending = None
        self.running = False
        self.exit_code = 1

    def dispatch(self, message, call=None):
        self.pending = {"id": message["id"], "method": message["method"], "call": call, "deadline": time.monotonic() + self.timeout}
        self.send(message)

    def client_message(self, req):
        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or not isinstance(req.get("method"), str):
            self.emit(error(None, -32600, "无效 JSON-RPC 请求"))
            return
        method = req["method"]
        params = req.get("params", {})
        if "id" not in req:
            # 不响应通知，且不将 tools/call 通知当作可执行请求。
            if method == "notifications/initialized" and self.phase == "INITIALIZED" and params == {}:
                self.send(req)
                self.phase = "READY"
            elif method == "notifications/cancelled" and isinstance(params, dict) and self.pending:
                cancelled = params.get("requestId")
                if type(cancelled) is type(self.pending["id"]) and cancelled == self.pending["id"]:
                    self.send(req)
                    # 终止整个上游会话；取消不等于回滚已发生的副作用。
                    self.fail(-32800, "请求已取消，会话关闭；已发生的副作用不保证回滚")
            return
        call_id = req["id"]
        if not valid_id(call_id):
            self.emit(error(None, -32600, "请求 ID 必须为字符串或整数"))
            return
        if not isinstance(params, dict):
            self.emit(error(call_id, -32602, "params 必须为对象"))
            return
        if "_meta" in params and not isinstance(params["_meta"], dict):
            self.emit(error(call_id, -32602, "请求元数据必须为对象"))
            return
        if self.pending and type(call_id) is type(self.pending["id"]) and call_id == self.pending["id"]:
            self.fail(-32600, "重复的在途请求 ID")
            return
        if method == "ping":
            self.emit({"jsonrpc": "2.0", "id": call_id, "result": {}})
            return
        if self.pending:
            self.emit(error(call_id, -32000, "会话忙，请等待前一个请求完成"))
            return
        if method == "initialize":
            info = params.get("clientInfo")
            if self.phase != "NEW" or not isinstance(params.get("protocolVersion"), str) or not isinstance(params.get("capabilities"), dict) or not isinstance(info, dict) or not all(isinstance(info.get(k), str) for k in ("name", "version")):
                self.emit(error(call_id, -32602, "无效或重复初始化"))
                return
            # 固定代理子集，不向上游宣告客户端回调、采样等未代理能力。
            forwarded = {"jsonrpc": "2.0", "id": call_id, "method": method, "params": {"protocolVersion": VERSION, "capabilities": {}, "clientInfo": {"name": "agent-immunity", "version": "0.2.0"}}}
            self.phase = "INITIALIZING"
            self.dispatch(forwarded)
            return
        if self.phase != "READY":
            self.emit(error(call_id, -32002, "尚未完成 MCP 初始化"))
            return
        if method == "tools/list":
            if set(params) - {"cursor", "_meta"} or ("cursor" in params and not isinstance(params["cursor"], str)):
                self.emit(error(call_id, -32602, "无效分页参数"))
                return
            # 接受客户端元数据，但不向上游协商或转发未支持的进度能力。
            self.dispatch({"jsonrpc": "2.0", "id": call_id, "method": method, "params": {k: v for k, v in params.items() if k != "_meta"}})
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or not name or not isinstance(arguments, dict) or set(params) - {"name", "arguments", "_meta"}:
                self.emit(error(call_id, -32602, "无效工具调用参数"))
                return
            call = ToolCall(str(call_id), name, arguments)
            decision = self.engine.begin(call)
            if not decision.allowed:
                result = self.engine.rejected(decision.code, decision.reason)
                self.emit({"jsonrpc": "2.0", "id": call_id, "result": result.output})
                return
            self.dispatch({"jsonrpc": "2.0", "id": call_id, "method": method, "params": {"name": name, "arguments": decision.arguments}}, call)
        else:
            self.emit(error(call_id, -32601, "本代理仅支持 initialize、ping、tools/list 和 tools/call"))

    def upstream_message(self, response):
        if not isinstance(response, dict) or response.get("jsonrpc") != "2.0":
            raise ValueError("无效上游消息")
        if "method" in response:
            if "id" in response:
                if not valid_id(response["id"]):
                    raise ValueError("无效服务端请求 ID")
                self.send(error(response["id"], -32601, "未协商服务端回调能力"))
            elif response.get("method") == "notifications/tools/list_changed" and self.phase == "READY":
                self.emit({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
            return
        if not self.pending or type(response.get("id")) is not type(self.pending["id"]) or response.get("id") != self.pending["id"]:
            raise ValueError("上游响应 ID 不匹配")
        if ("result" in response) == ("error" in response):
            raise ValueError("响应必须且只能包含 result 或 error")
        pending = self.pending
        if "error" in response:
            # 协议错误意味着执行结果不确定，终止会话而不继续积累不完整来源。
            self.fail(-32603, "上游返回协议错误，会话已关闭")
            return
        result = response["result"]
        if not isinstance(result, dict):
            raise ValueError("上游 result 需要对象")
        method = pending["method"]
        if method == "initialize":
            if result.get("protocolVersion") != VERSION or not isinstance(result.get("capabilities"), dict) or not isinstance(result["capabilities"].get("tools"), dict) or not isinstance(result.get("serverInfo"), dict) or not all(isinstance(result["serverInfo"].get(k), str) for k in ("name", "version")):
                raise ValueError("上游不支持所需工具协议")
            result = {"protocolVersion": VERSION, "serverInfo": result["serverInfo"], "capabilities": {"tools": {"listChanged": True}}}
            self.phase = "INITIALIZED"
        elif method == "tools/list":
            if not isinstance(result.get("tools"), list) or ("nextCursor" in result and not isinstance(result["nextCursor"], str)):
                raise ValueError("无效工具列表")
            listed = []
            names = set()
            for tool in result["tools"]:
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or tool["name"] in names:
                    raise ValueError("无效或重复工具描述")
                names.add(tool["name"])
                spec = self.policy.tools.get(tool["name"])
                if spec:
                    item = {"name": tool["name"], "inputSchema": spec.input_schema()}
                    if isinstance(tool.get("description"), str):
                        item["description"] = tool["description"]
                    listed.append(item)
            result = {"tools": listed, **({"nextCursor": result["nextCursor"]} if "nextCursor" in result else {})}
        elif method == "tools/call":
            content = result.get("content")
            if not isinstance(content, list) or any(not isinstance(item, dict) or item.get("type") != "text" or not isinstance(item.get("text"), str) for item in content) or type(result.get("isError", False)) is not bool or ("structuredContent" in result and not isinstance(result["structuredContent"], dict)) or ("_meta" in result and not isinstance(result["_meta"], dict)):
                raise ValueError("仅支持文本和结构化 JSON 工具结果")
            if "_meta" in result:
                # 保留普通上游元数据，但代理决策命名空间只能由本代理产生。
                result["_meta"] = {key: value for key, value in result["_meta"].items() if key != "agent_immunity"}
            completed = self.engine.complete(pending["call"].call_id, ToolResult(result, result.get("isError", False)))
            result = completed.output
            if self.engine.closed:
                self.running = False
                self.exit_code = 1
        self.emit({"jsonrpc": "2.0", "id": pending["id"], "result": result})
        self.pending = None

    def run(self):
        try:
            self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.policy.workspace, shell=False, bufsize=0, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for source, stream in (("client", self.input), ("upstream", self.process.stdout)):
                threading.Thread(target=self.reader, args=(source, stream), daemon=True).start()
            threading.Thread(target=self.discard_stderr, daemon=True).start()
            threading.Thread(target=self.writer, daemon=True).start()
            while self.running:
                if self.pending and time.monotonic() >= self.pending["deadline"]:
                    self.fail(-32001, "上游响应超时，会话已关闭")
                    break
                try:
                    source, data = self.messages.get(timeout=0.05)
                except queue.Empty:
                    continue
                if data is None:
                    if source == "upstream":
                        self.fail(-32003, "上游通信结束")
                    else:
                        self.running = False
                    continue
                if isinstance(data, Exception):
                    self.fail(-32600, "通信流超限或中断")
                    continue
                try:
                    message = strict_json(data.decode("utf-8"))
                except (ValueError, UnicodeError, RecursionError):
                    if source == "client":
                        self.emit(error(None, -32700, "JSON 解析失败"))
                    else:
                        self.fail(-32603, "上游输出不是有效 JSON")
                    continue
                try:
                    if source == "client":
                        self.client_message(message)
                    else:
                        self.upstream_message(message)
                except (ValueError, TypeError, KeyError, RecursionError, OSError):
                    self.fail(-32603, "协议或上游通信错误，会话已关闭")
        except (OSError, BrokenPipeError):
            print("无法启动或维持上游进程通信", file=sys.stderr)
            self.exit_code = 1
        finally:
            self.engine.close()
            if self.process:
                if self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=2)
                for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass
        return self.exit_code

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, help="受信本地 JSON 策略")
    parser.add_argument("--timeout", type=float, default=30, help="每次上游请求超时秒数")
    parser.add_argument("upstream", nargs=argparse.REMAINDER, help="-- 之后指定受信上游命令")
    args = parser.parse_args()
    command = args.upstream[1:] if args.upstream[:1] == ["--"] else args.upstream
    if not command or not 0 < args.timeout <= 300:
        parser.error("需要上游命令，timeout 必须介于 0 和 300 秒")
    try:
        policy = Policy.load(args.policy)
    except (OSError, ValueError, TypeError, RecursionError):
        parser.error("无法加载有效的本地策略")
    return StdioProxy(policy, command, args.timeout).run()

if __name__ == "__main__":
    raise SystemExit(main())
