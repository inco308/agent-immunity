"""用审计文件、独立上游调用记录和实际文件核对代理决策。"""

from contextlib import redirect_stderr
from datetime import datetime, timedelta
import io
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

from agent_immunity import Policy
from agent_immunity import decision_audit, mcp_stdio
from agent_immunity.decision_audit import AuditError, DecisionAudit
from agent_immunity.mcp_stdio import StdioProxy
from tests.support import DATA, policy_data, temporary_directory
from tests.test_mcp_stdio import Client


FIELDS = {"schema_version", "utc", "session_id", "sequence", "tool_index", "decision_code"}
REQUEST_MARKER = "AuditTestPrivateRequestId"
UNKNOWN_MARKER = "AuditTestUnregisteredName"
ARGUMENT_MARKER = "AuditTestPrivateArgument"
RESULT_MARKER = "AuditTestPrivateResult"


def read_rows(path):
    data = path.read_bytes()
    if data and not data.endswith(b"\n"):
        raise AssertionError("审计日志末尾存在不完整行")
    return [json.loads(line) for line in data.splitlines()]


class DecisionAuditTests(unittest.TestCase):
    def setUp(self):
        directory = temporary_directory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.workspace = self.root / "workspace"
        self.work = self.workspace / "work"
        self.work.mkdir(parents=True)
        self.logs = self.root / "audit"
        self.logs.mkdir()
        self.spec = policy_data(self.workspace)
        for tool in self.spec["tools"].values():
            if tool.get("path_fields"):
                tool["roots"] = ["work"]
        self.policy = Policy.from_dict(self.spec)

    def start_client(self, directory, handshake=True):
        client = Client(self.workspace, self.spec, audit_dir=directory, handshake=handshake)
        self.addCleanup(client.close)
        return client

    def test_live_decisions_match_upstream_effects_and_exclude_private_fields(self):
        # 这个值只出现在上游读取结果中，不会随工具调用参数发送。
        (self.work / "input.txt").write_text(RESULT_MARKER, encoding="utf-8")
        client = self.start_client(self.logs)
        self.assertTrue((self.workspace / "server.pid").is_file())
        self.assertIn("tools", client.request("tools/list")["result"])
        self.assertEqual(client.request("ping")["result"], {})
        self.assertEqual(client.call(123, {})["error"]["code"], -32602)
        client.notify("tools/call", {"name": "fail", "arguments": {}})

        client.send({"jsonrpc": "2.0", "id": REQUEST_MARKER, "method": "tools/call", "params": {
            "name": "write_file", "arguments": {"path": "work/report.txt", "content": ARGUMENT_MARKER},
        }})
        written = client.receive()
        self.assertEqual(written["id"], REQUEST_MARKER)
        self.assertFalse(written["result"]["isError"])
        self.assertEqual((self.work / "report.txt").read_text(encoding="utf-8"), ARGUMENT_MARKER)
        self.assertEqual(client.call("read_file", {"path": "work/input.txt"})["result"]["content"][0]["text"],
                         RESULT_MARKER)

        unknown = client.call(UNKNOWN_MARKER, {})["result"]
        self.assertEqual(unknown["_meta"]["agent_immunity"]["code"], "UNKNOWN_TOOL")
        source = client.call("structured", {})["result"]
        self.assertEqual(source["structuredContent"]["password"], DATA["secret"])
        denied = client.call("write_file", {"path": "work/denied.txt", "content": DATA["secret"]})["result"]
        self.assertEqual(denied["_meta"]["agent_immunity"]["code"], "SENSITIVE_FLOW")
        self.assertFalse((self.work / "denied.txt").exists())
        self.assertTrue(client.call("fail", {})["result"]["isError"])

        upstream = read_rows(self.workspace / "calls.jsonl")
        self.assertEqual([row["name"] for row in upstream], ["write_file", "read_file", "structured", "fail"])
        paths = list(self.logs.glob("*.jsonl"))
        self.assertEqual(len(paths), 1)
        records = read_rows(paths[0])
        indices = {name: index for index, name in enumerate(sorted(self.spec["tools"]), 1)}
        expected = [(indices["write_file"], "ALLOW"), (indices["read_file"], "ALLOW"), (0, "UNKNOWN_TOOL"),
                    (indices["structured"], "ALLOW"), (indices["write_file"], "SENSITIVE_FLOW"),
                    (indices["fail"], "ALLOW")]
        self.assertEqual([(row["tool_index"], row["decision_code"]) for row in records], expected)
        self.assertEqual([row["sequence"] for row in records], list(range(1, len(expected) + 1)))
        for row in records:
            self.assertEqual(set(row), FIELDS)
            self.assertIs(type(row["schema_version"]), int)
            self.assertEqual(row["schema_version"], 1)
            self.assertIs(type(row["tool_index"]), int)
            self.assertIs(type(row["sequence"]), int)
            self.assertIsInstance(row["session_id"], str)
            self.assertTrue(row["session_id"])
            self.assertEqual(row["session_id"], records[0]["session_id"])
            timestamp = datetime.fromisoformat(row["utc"].replace("Z", "+00:00"))
            self.assertEqual(timestamp.utcoffset(), timedelta(0))
        text = paths[0].read_text(encoding="utf-8")
        for marker in (REQUEST_MARKER, UNKNOWN_MARKER, ARGUMENT_MARKER, RESULT_MARKER,
                       DATA["secret"], "work/report.txt", "expected failure", *self.spec["tools"]):
            self.assertNotIn(marker, text)

    def test_concurrent_sessions_create_independent_files_and_preserve_existing_data(self):
        existing = self.logs / "existing.jsonl"
        existing.write_bytes(b'{"previous_session":true}\n')
        first = DecisionAudit.open(self.logs, self.policy)
        try:
            second = DecisionAudit.open(self.logs, self.policy)
            try:
                first.record("document", "ALLOW")
                second.record(UNKNOWN_MARKER, "UNKNOWN_TOOL")
                first.record(UNKNOWN_MARKER, "UNKNOWN_TOOL")
            finally:
                second.close()
        finally:
            first.close()
        self.assertEqual(existing.read_bytes(), b'{"previous_session":true}\n')
        files = set(self.logs.glob("*.jsonl")) - {existing}
        self.assertEqual(len(files), 2)
        sessions = sorted((read_rows(path) for path in files), key=len)
        self.assertEqual([[row["sequence"] for row in session] for session in sessions], [[1], [1, 2]])
        self.assertNotEqual(sessions[0][0]["session_id"], sessions[1][0]["session_id"])
        self.assertEqual(sessions[1][0]["session_id"], sessions[1][1]["session_id"])
        if os.name == "posix":
            for path in files:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)

    def test_startup_rejects_unusable_or_tool_writable_directory_before_upstream(self):
        not_directory = self.root / "sentinel"
        not_directory.write_bytes(b"original")
        nested = self.work / "audit"
        nested.mkdir()
        absent = self.root / "missing-audit"
        for path in (absent, not_directory, self.work, nested):
            with self.subTest(kind=path.name):
                client = self.start_client(path, handshake=False)
                self.assertNotEqual(client.process.wait(timeout=6), 0)
                self.assertFalse((self.workspace / "server.pid").exists())
                self.assertFalse((self.workspace / "calls.jsonl").exists())
                client.close()
        self.assertFalse(absent.exists())
        self.assertEqual(not_directory.read_bytes(), b"original")
        self.assertEqual(list(self.work.rglob("*.jsonl")), [])

    def test_symlink_into_tool_writable_tree_cannot_receive_audit_files(self):
        target = self.work / "logs"
        target.mkdir()
        alias = self.root / "external-alias"
        through_writable = self.root / "nested-alias"
        try:
            alias.symlink_to(self.work, target_is_directory=True)
            (self.work / "redirect").symlink_to(self.logs, target_is_directory=True)
            through_writable.symlink_to(self.work / "redirect", target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("当前宿主不允许创建目录符号链接")
        for chosen in (alias, alias / "logs", through_writable):
            with self.subTest(path=chosen), self.assertRaises(AuditError):
                DecisionAudit.open(chosen, self.policy)
        self.assertEqual(list(self.work.rglob("*.jsonl")), [])
        self.assertEqual(list(self.logs.iterdir()), [])

    def test_exclusive_creation_failure_blocks_startup_without_touching_existing_file(self):
        fixed = UUID("de82e0e8-ea51-4dc5-b48c-bb53e0e73d82")
        old = self.logs / f"{fixed.hex}.jsonl"
        old.write_bytes(b"previous session evidence\n")
        policy_path = self.root / "policy.json"
        policy_path.write_text(json.dumps(self.spec), encoding="utf-8")
        args = ["proxy", "--policy", str(policy_path), "--audit-dir", str(self.logs), "--", "synthetic-upstream"]
        with patch.object(decision_audit.uuid, "uuid4", return_value=fixed), patch.object(sys, "argv", args), \
                patch.object(StdioProxy, "run") as start, redirect_stderr(io.StringIO()):
            self.assertNotEqual(mcp_stdio.main(), 0)
        start.assert_not_called()
        self.assertEqual(old.read_bytes(), b"previous session evidence\n")

    def test_capacity_rejection_does_not_corrupt_or_grow_existing_records(self):
        self.assertEqual(decision_audit.MAX_AUDIT_BYTES, 4 * 1024 * 1024)
        with patch.object(decision_audit, "MAX_AUDIT_BYTES", 1024):
            sink = DecisionAudit.open(self.logs, self.policy)
            try:
                written = 0
                with self.assertRaises(AuditError):
                    for _ in range(64):
                        sink.record("document", "ALLOW")
                        written += 1
            finally:
                sink.close()
        self.assertGreater(written, 0)
        paths = list(self.logs.glob("*.jsonl"))
        self.assertEqual(len(paths), 1)
        self.assertLessEqual(paths[0].stat().st_size, 1024)
        self.assertEqual([r["sequence"] for r in read_rows(paths[0])], list(range(1, written + 1)))

    def test_record_failure_replies_to_current_id_and_stops_before_dispatch(self):
        for name, arguments, expected in (
            ("write_file", {"path": "work/out.txt", "content": ARGUMENT_MARKER}, "ALLOW"),
            (UNKNOWN_MARKER, {}, "UNKNOWN_TOOL"),
        ):
            with self.subTest(decision=expected):
                failing_audit = Mock(spec=DecisionAudit)
                failing_audit.record.side_effect = AuditError(RESULT_MARKER)
                output = io.BytesIO()
                proxy = StdioProxy(self.policy, [], input_stream=io.BytesIO(), output_stream=output, audit=failing_audit)
                proxy.phase = "READY"
                with patch.object(proxy, "dispatch") as dispatch:
                    proxy.client_message({"jsonrpc": "2.0", "id": REQUEST_MARKER, "method": "tools/call",
                                          "params": {"name": name, "arguments": arguments}})
                dispatch.assert_not_called()
                failing_audit.record.assert_called_once_with(name, expected)
                reply = json.loads(output.getvalue())
                self.assertEqual(reply["id"], REQUEST_MARKER)
                self.assertEqual(reply["error"]["code"], -32603)
                self.assertNotIn("data", reply["error"])
                self.assertNotIn(RESULT_MARKER, json.dumps(reply))
                self.assertFalse(proxy.running)
                self.assertNotEqual(proxy.exit_code, 0)
                self.assertTrue(proxy.engine.closed)
                self.assertFalse((self.work / "out.txt").exists())

    def test_short_write_preserves_completed_lines_and_disables_further_records(self):
        actual_write = os.write

        def write_prefix(fd, data):
            return actual_write(fd, data[:len(data) // 2])

        sink = DecisionAudit.open(self.logs, self.policy)
        try:
            sink.record("document", "ALLOW")
            path, = self.logs.glob("*.jsonl")
            complete = path.read_bytes()
            with patch.object(decision_audit.os, "write", side_effect=write_prefix):
                with self.assertRaises(AuditError) as failed:
                    sink.record(UNKNOWN_MARKER, "UNKNOWN_TOOL")
            self.assertNotIn(UNKNOWN_MARKER, str(failed.exception))
            with self.assertRaises(AuditError):
                sink.record("document", "ALLOW")
            self.assertEqual(path.read_bytes(), complete)
            self.assertEqual([r["sequence"] for r in read_rows(path)], [1])
        finally:
            sink.close()

    def test_unknown_decision_code_cannot_enter_log_or_exception(self):
        sink = DecisionAudit.open(self.logs, self.policy)
        try:
            sink.record("document", "ALLOW")
            path, = self.logs.glob("*.jsonl")
            complete = path.read_bytes()
            with self.assertRaises(AuditError) as failed:
                sink.record("document", DATA["secret"])
            self.assertNotIn(DATA["secret"], str(failed.exception))
            with self.assertRaises(AuditError) as disabled:
                sink.record("document", "ALLOW")
            self.assertNotIn(DATA["secret"], str(disabled.exception))
            self.assertEqual(path.read_bytes(), complete)
            self.assertEqual([r["sequence"] for r in read_rows(path)], [1])
        finally:
            sink.close()


if __name__ == "__main__":
    unittest.main()
