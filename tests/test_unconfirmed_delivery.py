"""按可控事件顺序验证断线时的审计指针及输出通道的交付边界。"""
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import queue
import sys
import unittest
from unittest.mock import Mock, patch

from agent_immunity.mcp_stdio import StdioProxy
from tests.support import policy, temporary_directory


REQUEST_ID = "private-request-id"
ARGUMENT = "private-operation-content"
REQUEST = {"jsonrpc": "2.0", "id": REQUEST_ID, "method": "tools/call", "params": {
    "name": "write_file", "arguments": {"path": "out.txt", "content": ARGUMENT},
}}
CLIENT_CALL = ("client", REQUEST)
CLIENT_EOF = ("client", None)
UPSTREAM_EOF = ("upstream", None)


def tool_reply(is_error=False):
    return ("upstream", {"jsonrpc": "2.0", "id": REQUEST_ID,
                         "result": {"content": [], "isError": is_error}})


class UnconfirmedDeliveryTests(unittest.TestCase):
    def setUp(self):
        tmp = temporary_directory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.audit = Mock()
        self.audit.record.return_value = 42

    def proxy(self, **options):
        options.setdefault("audit", self.audit)
        options.setdefault("output_stream", io.BytesIO())
        proxy = StdioProxy(policy(self.root), [sys.executable, "-c", "import sys; sys.stdin.read()"],
                           input_stream=io.BytesIO(), **options)
        proxy.phase = "READY"
        return proxy

    def drive(self, proxy, *events):
        # 消息先进入真实事件循环，副作用交给独立的端到端演练核对。
        for source, message in events:
            frame = None if message is None else json.dumps(message).encode()
            proxy.messages.put((source, frame))
        with patch.object(proxy, "reader"), patch.object(proxy, "writer"):
            status = proxy.run()
        self.assertTrue(proxy.engine.closed)
        self.assertIsNotNone(proxy.process.poll(), "直接上游必须已被回收")
        return status

    def test_unknown_result_marker_uses_the_allow_sequence(self):
        for terminal, code in ((CLIENT_EOF, None), (UPSTREAM_EOF, -32003), (None, -32001)):
            with self.subTest(terminal=terminal):
                self.audit.reset_mock()
                proxy = self.proxy(timeout=0.05 if terminal is None else 3)
                events = (CLIENT_CALL,) if terminal is None else (CLIENT_CALL, terminal)
                self.drive(proxy, *events)
                self.audit.record.assert_called_once_with("write_file", "ALLOW")
                self.audit.record_unconfirmed.assert_called_once_with(42, "upstream_result_unknown")
                if code is None:
                    self.assertEqual(proxy.output.getvalue(), b"")
                else:
                    reply = json.loads(proxy.output.getvalue())
                    self.assertEqual((reply["id"], reply["error"]["code"]), (REQUEST_ID, code))
                    self.assertEqual(reply["error"]["data"], {
                        "agent_immunity": {"outcome": "unknown", "automatic_retry": False},
                    })

    def test_result_observed_but_write_or_flush_did_not_complete(self):
        for failed_method in ("write", "flush"):
            with self.subTest(failed_method=failed_method):
                self.audit.reset_mock()
                output = Mock(wraps=io.BytesIO())
                getattr(output, failed_method).side_effect = BrokenPipeError()
                proxy = self.proxy(output_stream=output)
                self.assertEqual(self.drive(proxy, CLIENT_CALL, tool_reply(failed_method == "flush"), CLIENT_EOF), 1)
                self.audit.record_unconfirmed.assert_called_once_with(42, "client_delivery_unconfirmed")
                self.assertEqual(output.write.call_count, 1, "写出中断后不能再发送其他响应")

    def test_partial_writes_must_finish_the_same_result_frame(self):
        for terminal in ("finish", 0, None):
            with self.subTest(terminal=terminal):
                self.audit.reset_mock()
                captured = io.BytesIO()
                output = Mock(wraps=captured)

                def short_write(chunk):
                    if captured.tell() and terminal != "finish":
                        return terminal
                    return captured.write(chunk[:5])

                output.write.side_effect = short_write
                proxy = self.proxy(output_stream=output)
                status = self.drive(proxy, CLIENT_CALL, tool_reply(), CLIENT_EOF)
                if terminal == "finish":
                    self.assertEqual(status, 0)
                    self.assertEqual(json.loads(captured.getvalue())["id"], REQUEST_ID)
                    self.audit.record_unconfirmed.assert_not_called()
                else:
                    self.assertEqual(status, 1)
                    self.assertEqual(output.write.call_count, 2)
                    self.assertEqual(len(captured.getvalue()), 5)
                    self.audit.record_unconfirmed.assert_called_once_with(42, "client_delivery_unconfirmed")

    def test_ping_does_not_confirm_an_unrelated_second_call(self):
        self.audit.record.side_effect = [41, 42]
        second = ("client", {**REQUEST, "id": 2})
        ping = ("client", {"jsonrpc": "2.0", "method": "ping", "id": 3})
        proxy = self.proxy()
        self.drive(proxy, CLIENT_CALL, tool_reply(), second, ping, CLIENT_EOF)
        delivered = [json.loads(line)["id"] for line in proxy.output.getvalue().splitlines()]
        self.assertEqual(delivered, [REQUEST_ID, 3])
        self.audit.record_unconfirmed.assert_called_once_with(42, "upstream_result_unknown")

    def test_successful_handoff_and_a_local_denial_need_no_marker(self):
        denied = ("client", {**REQUEST, "params": {"name": "missing", "arguments": {}}})
        for events in ((CLIENT_EOF,), (denied, CLIENT_EOF),
                       (CLIENT_CALL, tool_reply(), CLIENT_EOF), (CLIENT_CALL, tool_reply(True), CLIENT_EOF)):
            with self.subTest(events=events):
                self.audit.reset_mock()
                self.assertEqual(self.drive(self.proxy(), *events), 0)
                self.audit.record_unconfirmed.assert_not_called()

    def test_an_allow_that_never_entered_the_queue_gets_no_marker(self):
        proxy = self.proxy()
        proxy.outgoing = queue.Queue(maxsize=1)
        proxy.outgoing.put_nowait(b"occupied")
        self.assertEqual(self.drive(proxy, CLIENT_CALL, CLIENT_EOF), 1)
        self.audit.record.assert_called_once_with("write_file", "ALLOW")
        self.audit.record_unconfirmed.assert_not_called()
        error = json.loads(proxy.output.getvalue())["error"]
        self.assertEqual(error["code"], -32603)
        self.assertNotIn("data", error)

    def test_marker_failure_leaves_original_reply_and_reaps_upstream(self):
        private_diagnostic = "private-storage-error"
        self.audit.record_unconfirmed.side_effect = OSError(private_diagnostic)
        for ending in (UPSTREAM_EOF, CLIENT_EOF):
            with self.subTest(ending=ending):
                self.audit.reset_mock()
                proxy = self.proxy()
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(self.drive(proxy, CLIENT_CALL, ending), 1)
                self.audit.record_unconfirmed.assert_called_once_with(42, "upstream_result_unknown")
                wire = proxy.output.getvalue().decode()
                if ending == CLIENT_EOF:
                    self.assertEqual(wire, "")
                else:
                    self.assertEqual(len(wire.splitlines()), 1)
                    error = json.loads(wire)["error"]
                    self.assertEqual(error["code"], -32003)
                    self.assertIs(error["data"]["agent_immunity"]["automatic_retry"], False)
                self.assertTrue(stderr.getvalue(), "存储失败需要留下固定诊断")
                self.assertNotIn(REQUEST_ID, stderr.getvalue())
                for private in (ARGUMENT, private_diagnostic):
                    self.assertNotIn(private, wire + stderr.getvalue())

    def test_disabled_audit_preserves_the_wire_error(self):
        proxy = self.proxy(audit=None)
        self.assertEqual(self.drive(proxy, CLIENT_CALL, UPSTREAM_EOF), 1)
        self.assertEqual(self.audit.mock_calls, [])
        reply = json.loads(proxy.output.getvalue())
        self.assertEqual((reply["id"], reply["error"]["code"]), (REQUEST_ID, -32003))
        self.assertIs(reply["error"]["data"]["agent_immunity"]["automatic_retry"], False)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_legacy_decision_only_sink_can_still_observe_calls(self):
        audit = Mock(spec=["record"])
        audit.record.return_value = None
        proxy = self.proxy(audit=audit)
        self.assertEqual(self.drive(proxy, CLIENT_CALL, CLIENT_EOF), 0)
        audit.record.assert_called_once_with("write_file", "ALLOW")
