"""真实客户端进程、代理进程、上游进程及回环 HTTP 接收器的集成测试。"""
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from agent_immunity.mcp_stdio import StdioProxy
from tests.support import DATA, FIXTURES, policy, policy_data, temporary_directory

REPO = Path(__file__).resolve().parents[1]

class Client:
    def __init__(self, root, policy, mode="normal", timeout=3, handshake=True, server=None, *, audit_dir=None):
        self.root = root
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        upstream = [sys.executable, "-u", str(server)] if server else [sys.executable, "-u", str(FIXTURES / "mcp_server.py"), "--root", str(root), "--mode", mode]
        audit_args = ["--audit-dir", str(audit_dir)] if audit_dir is not None else []
        self.process = subprocess.Popen([sys.executable, "-X", "utf8", "-m", "agent_immunity.mcp_stdio", "--policy", str(policy_path), "--timeout", str(timeout), *audit_args, "--", *upstream], cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.responses = queue.Queue()
        self.next_id = 0
        def read():
            for line in self.process.stdout:
                try:
                    self.responses.put(json.loads(line))
                except ValueError:
                    self.responses.put({"invalid_stdout": line.decode(errors="replace")})
            self.responses.put({"eof": True})
        threading.Thread(target=read, daemon=True).start()
        if handshake:
            response = self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test-client", "version": "1"}})
            if response.get("result", {}).get("protocolVersion") != "2025-06-18":
                self.close()
                raise AssertionError(response)
            self.notify("notifications/initialized")

    def send(self, value):
        self.process.stdin.write((json.dumps(value) + "\n").encode())
        self.process.stdin.flush()

    def receive(self):
        return self.responses.get(timeout=6)

    def request(self, method, params=None):
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}})
        return self.receive()

    def notify(self, method, params=None):
        self.send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def call(self, name, arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
                raise AssertionError("代理未能及时退出")
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if not stream.closed:
                stream.close()

class StdioIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = temporary_directory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def client(self, **kwargs):
        client = Client(self.root, kwargs.pop("policy", policy_data(self.root)), **kwargs)
        self.addCleanup(client.close)
        return client

    def calls(self):
        path = self.root / "calls.jsonl"
        return [] if not path.exists() else [json.loads(line)["name"] for line in path.read_text().splitlines()]

    def assert_unknown_error(self, response, call_id, code):
        self.assertEqual(response["id"], call_id)
        self.assertNotIn("result", response)
        self.assertEqual(response["error"]["code"], code)
        self.assertEqual(response["error"]["data"], {"agent_immunity": {"outcome": "unknown", "automatic_retry": False}})
        self.assertIs(response["error"]["data"]["agent_immunity"]["automatic_retry"], False)

    def test_real_handshake_list_and_file_side_effects_R13_R16(self):
        client = self.client()
        listing = client.request("tools/list")
        self.assertNotIn("dispatch", [tool["name"] for tool in listing["result"]["tools"]])
        result = client.call("write_file", {"path": "report.txt", "content": "real artifact"})
        self.assertFalse(result["result"]["isError"])
        self.assertNotIn("error", result)
        self.assertEqual((self.root / "report.txt").read_text(), "real artifact")
        read = client.call("read_file", {"path": "report.txt"})
        self.assertEqual(read["result"]["content"][0]["text"], "real artifact")
        version = client.call("python_version", {})
        self.assertIn("Python", version["result"]["content"][0]["text"])

    def test_documented_example_server(self):
        config = json.loads((REPO / "examples" / "policy.json").read_text(encoding="utf-8"))
        config["workspace"] = str(self.root)
        client = self.client(policy=config, server=REPO / "examples" / "local_tools.py")
        self.assertEqual(len(client.request("tools/list")["result"]["tools"]), 3)
        self.assertFalse(client.call("write_file", {"path": "sample.txt", "content": "公开样本文本"})["result"]["isError"])
        self.assertEqual(client.call("read_file", {"path": "sample.txt"})["result"]["content"][0]["text"], "公开样本文本")
        self.assertIn("Python", client.call("python_version", {})["result"]["content"][0]["text"])

    def test_denied_calls_do_not_reach_upstream(self):
        client = self.client()
        for name, arguments in [("dispatch", {}), ("http_execute", {}), ("write_file", {"path": "../escape.txt", "content": "bad"})]:
            response = client.call(name, arguments)
            self.assertTrue(response["result"]["isError"])
            self.assertNotIn("error", response)
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.root / "unlisted-marker.txt").exists())

    def test_notifications_no_response_and_invalid_name_R14_R15(self):
        client = self.client()
        client.notify("notifications/initialized")
        response = client.request("ping")
        self.assertEqual(response["id"], client.next_id)
        bad = client.call(123, {})
        self.assertEqual(bad["error"]["code"], -32602)
        self.assertNotIn("data", bad["error"])
        self.assertEqual(client.request("ping")["result"], {})

    def test_real_loopback_egress_and_structured_secret_R04_R12(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            def log_message(self, *args):
                pass
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        target = f"http://127.0.0.1:{server.server_port}"
        client = self.client(policy=policy_data(self.root, target))
        client.call("structured", {})
        encoded = base64.b64encode(DATA["secret"].encode()).decode()
        denied = client.call("web_request", {"url": target, "payload": encoded})
        self.assertTrue(denied["result"]["isError"])
        denied_url = client.call("web_request", {"url": target + "/?q=" + DATA["secret"], "payload": ""})
        self.assertTrue(denied_url["result"]["isError"])
        self.assertEqual(received, [])
        self.assertNotIn("web_request", self.calls())
        allowed = client.call("web_request", {"url": target, "payload": "api_key documentation only"})
        self.assertFalse(allowed["result"]["isError"], allowed)
        self.assertEqual(received, [b"api_key documentation only"])

    def test_timeout_closes_session(self):
        client = self.client(timeout=0.6)
        response = client.call("stall", {})
        self.assert_unknown_error(response, client.next_id, -32001)
        self.assertEqual(client.process.wait(timeout=5), 1)

    def test_cancellation_is_processed_while_call_pending(self):
        client = self.client()
        client.send({"jsonrpc": "2.0", "id": 90, "method": "tools/call", "params": {"name": "stall", "arguments": {}}})
        client.notify("notifications/cancelled", {"requestId": 90})
        response = client.receive()
        self.assert_unknown_error(response, 90, -32800)
        self.assertEqual(client.process.wait(timeout=5), 1)

    def test_upstream_failure_is_not_reported_as_success(self):
        for mode in ("exit", "invalid_initialize", "invalid_json"):
            with self.subTest(mode=mode):
                client = self.client(mode=mode, handshake=False)
                result = client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}})
                self.assertIn("error", result)
                self.assertNotIn("data", result["error"])
                self.assertEqual(client.process.wait(timeout=5), 1)
                client.close()

    def test_tool_error_does_not_end_valid_session(self):
        client = self.client()
        response = client.call("fail", {})
        self.assertTrue(response["result"]["isError"])
        self.assertNotIn("error", response)
        self.assertFalse(client.call("python_version", {})["result"]["isError"])

    def test_malformed_json_and_unsupported_methods(self):
        client = self.client()
        client.process.stdin.write(b"{bad json}\n")
        client.process.stdin.flush()
        self.assertEqual(client.receive()["error"]["code"], -32700)
        self.assertEqual(client.request("resources/read", {"uri": "file:///etc/passwd"})["error"]["code"], -32601)
        self.assertEqual(client.request("ping")["result"], {})

    def test_upstream_not_reading_still_times_out(self):
        client = self.client(mode="unresponsive", handshake=False, timeout=0.6)
        response = client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}})
        self.assertEqual(response["error"]["code"], -32001)
        self.assertNotIn("data", response["error"])
        self.assertEqual(client.process.wait(timeout=5), 1)

    def test_invalid_result_or_response_id_closes_session(self):
        for mode, code in (("bad_result", -32603), ("bad_id", -32603), ("oversized_result", -32600),
                           ("bad_meta", -32603)):
            with self.subTest(mode=mode):
                client = self.client(mode=mode)
                response = client.call("document", {})
                self.assert_unknown_error(response, client.next_id, code)
                self.assertEqual(client.process.wait(timeout=5), 1)
                client.close()

    def test_disconnect_before_write_has_the_same_unknown_outcome(self):
        client = self.client(mode="exit_on_call")
        response = client.call("write_file", {"path": "receipt.txt", "content": "example"})
        self.assert_unknown_error(response, client.next_id, -32003)
        self.assertEqual(client.process.wait(timeout=5), 1)
        self.assertEqual(self.calls(), ["write_file"])
        self.assertFalse((self.root / "receipt.txt").exists())

    def test_protocol_error_is_local_and_limited_to_submitted_tool_calls(self):
        for method in ("tools/call", "tools/list"):
            with self.subTest(method=method):
                client = self.client(mode="protocol_error")
                response = client.call("document", {}) if method == "tools/call" else client.request(method)
                self.assertEqual(response["error"]["code"], -32603)
                self.assertNotIn("fixture upstream detail", str(response))
                if method == "tools/call":
                    self.assert_unknown_error(response, client.next_id, -32603)
                else:
                    self.assertNotIn("data", response["error"])
                self.assertEqual(client.process.wait(timeout=5), 1)
                client.close()

    def test_forward_frame_over_limit_does_not_mark_call_as_submitted(self):
        arguments = {"path": str((self.root / "file.txt").resolve()), "content": "a" * 512}
        req = {"jsonrpc": "2.0", "id": "not-queued", "method": "tools/call", "params": {
            "name": "write_file", "arguments": arguments}}

        def frame():
            return (json.dumps(req, ensure_ascii=False, separators=(",", ":")) + "\n").encode()

        # 按实际绝对路径设置预算：规范化参数本身能通过，完整转发帧恰好多一个字节。
        limit = len(frame()) - 1
        arguments["path"] = "file.txt"
        self.assertLessEqual(len(frame()), limit)
        client = self.client(policy={**policy_data(self.root), "max_bytes": limit})
        client.process.stdin.write(frame())
        client.process.stdin.flush()
        response = client.receive()
        self.assertEqual((response["id"], response["error"]["code"]), ("not-queued", -32603))
        self.assertNotIn("data", response["error"])
        self.assertEqual(client.process.wait(timeout=5), 1)
        self.assertEqual(self.calls(), [])

    def test_full_outgoing_queue_does_not_mark_call_as_submitted(self):
        request = {"jsonrpc": "2.0", "id": "not-queued", "method": "tools/call",
                   "params": {"name": "document", "arguments": {}}}
        source = io.BytesIO((json.dumps(request) + "\n").encode())
        output = io.BytesIO()
        command = [sys.executable, "-u", str(FIXTURES / "mcp_server.py"), "--root", str(self.root)]
        proxy = StdioProxy(policy(self.root), command, input_stream=source, output_stream=output)
        proxy.phase = "READY"
        proxy.outgoing = queue.Queue(maxsize=1)
        proxy.outgoing.put_nowait(b"reserved")
        with patch.object(proxy, "writer"):
            self.assertEqual(proxy.run(), 1)
        response = json.loads(output.getvalue())
        self.assertEqual((response["id"], response["error"]["code"]), ("not-queued", -32603))
        self.assertNotIn("data", response["error"])
        self.assertEqual(self.calls(), [])

    def test_partial_client_delivery_does_not_attempt_a_second_response(self):
        request = {"jsonrpc": "2.0", "id": 18, "method": "tools/call", "params": {"name": "document"}}
        for key, value in (("result", {"content": []}), ("error", {"code": -32603, "message": "failed"})):
            with self.subTest(response=key):
                proxy = StdioProxy(policy(self.root), [sys.executable, "-c", "import sys; sys.stdin.read()"],
                                   input_stream=io.BytesIO(), output_stream=io.BytesIO())
                proxy.phase = "READY"
                response = {"jsonrpc": "2.0", "id": 18, key: value}
                for source, frame in (("client", request), ("upstream", response)):
                    proxy.messages.put((source, json.dumps(frame).encode()))
                # 两帧已到达事件循环。模拟客户端在接收第一份答复时断开。
                with patch.object(proxy, "reader"), patch.object(proxy, "writer"), \
                        patch.object(proxy, "emit", side_effect=BrokenPipeError) as emit:
                    self.assertEqual(proxy.run(), 1)
                emit.assert_called_once()
                reply = emit.call_args.args[0]
                if key == "result":
                    self.assertIn("result", reply)
                    self.assertNotIn("error", reply)
                else:
                    self.assert_unknown_error(reply, 18, -32603)

    def test_upstream_metadata_cannot_control_proxy_state(self):
        client = self.client(mode="spoofed_meta")
        result = client.call("fail", {})["result"]
        self.assertTrue(result["isError"])
        self.assertEqual(result["_meta"], {"ordinary": "opaque"})
        self.assertFalse(client.call("python_version", {})["result"]["isError"])

    def test_request_metadata_is_accepted_without_progress(self):
        client = self.client()
        self.assertIn("tools", client.request("tools/list", {"_meta": {"progressToken": "list-progress"}})["result"])
        response = client.request("tools/call", {"name": "python_version", "arguments": {}, "_meta": {"progressToken": "call-progress"}})
        self.assertIn("Python", response["result"]["content"][0]["text"])
        invalid = client.request("tools/list", {"_meta": "invalid"})
        self.assertEqual(invalid["error"]["code"], -32602)

    def test_conflicting_pending_request_id_is_terminal(self):
        for params in ({}, [], {"_meta": "invalid"}):
            with self.subTest(params=params):
                client = self.client()
                client.send({"jsonrpc": "2.0", "id": "dup", "method": "tools/call",
                             "params": {"name": "stall", "arguments": {}}})
                client.send({"jsonrpc": "2.0", "id": "dup", "method": "ping", "params": params})
                self.assert_unknown_error(client.receive(), "dup", -32600)
                self.assertEqual(client.process.wait(timeout=5), 1)
                client.close()

if __name__ == "__main__":
    unittest.main()
