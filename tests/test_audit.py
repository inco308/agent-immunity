"""判定审计的回归：记录什么、不记录什么、写不进去时怎么办。

审计日志的价值在于事后能核对"哪次调用被拒、以什么码"，因此这些用例除了
正常写入，还固定了两条边界：**参数与返回值绝不落盘**，以及**写入失败必须
失败关闭**（否则日志缺口会让事后核对变成猜测）。
"""
import json
from pathlib import Path
import unittest
from unittest import mock

from agent_immunity import DynamicImmunityEngine, Policy, ToolCall, ToolResult
from agent_immunity.audit import AuditError, AuditLog
from tests.support import policy, temporary_directory

SECRET = "AUDIT-MUST-NOT-LEAK-0123456789"
# 同时验证带凭证模式的串也不会落盘
SECRET_LIKE = "sk-live-AUDIT-MUST-NOT-LEAK-0123456789"


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        self.directory = temporary_directory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "audit.jsonl"

    def read(self):
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()]

    def test_records_use_a_fixed_field_whitelist(self):
        log = AuditLog(self.path)
        self.addCleanup(log.close)
        log.write("decision", "read_file", "ALLOW", False)
        log.write("completion", "read_file", "COMPLETED", True)
        records = self.read()
        self.assertEqual([record["seq"] for record in records], [1, 2])
        self.assertEqual(set(records[0]), {"v", "seq", "ts", "event", "tool", "code", "completed"})
        self.assertEqual(records[0]["event"], "decision")
        self.assertTrue(records[1]["completed"])

    def test_unknown_event_and_bad_types_are_rejected(self):
        log = AuditLog(self.path)
        self.addCleanup(log.close)
        for event, tool, code, completed in (
                ("started", "read_file", "ALLOW", False),
                ("decision", 1, "ALLOW", False),
                ("decision", "read_file", None, False),
                ("decision", "read_file", "ALLOW", "no")):
            with self.subTest(event=event), self.assertRaises(ValueError):
                log.write(event, tool, code, completed)

    def test_appends_to_existing_file(self):
        first = AuditLog(self.path)
        first.write("decision", "a", "ALLOW", False)
        first.close()
        second = AuditLog(self.path)
        self.addCleanup(second.close)
        second.write("decision", "b", "UNKNOWN_TOOL", False)
        self.assertEqual([record["tool"] for record in self.read()], ["a", "b"])
        self.assertEqual([record["seq"] for record in self.read()], [1, 2])

    def test_record_capacity_is_enforced(self):
        log = AuditLog(self.path, max_records=1)
        self.addCleanup(log.close)
        log.write("decision", "a", "ALLOW", False)
        with self.assertRaises(AuditError):
            log.write("decision", "b", "ALLOW", False)

    def test_byte_capacity_is_enforced(self):
        log = AuditLog(self.path, max_bytes=1024)
        self.addCleanup(log.close)
        written = 0
        with self.assertRaises(AuditError):
            for index in range(100):
                log.write("decision", f"tool_{index}", "ALLOW", False)
                written += 1
        self.assertLess(written, 100)

    def test_limits_are_validated(self):
        for kwargs in ({"max_bytes": 10}, {"max_bytes": "big"}, {"max_records": 0},
                       {"max_records": "many"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                AuditLog(self.path, **kwargs)

    def test_unwritable_path_fails_at_construction(self):
        with self.assertRaises(AuditError):
            AuditLog(Path(self.directory.name) / "missing-dir" / "audit.jsonl")

    def test_close_is_idempotent_and_blocks_further_writes(self):
        log = AuditLog(self.path)
        log.write("decision", "a", "ALLOW", False)
        log.close()
        log.close()
        with self.assertRaises(AuditError):
            log.write("decision", "b", "ALLOW", False)


class EngineAuditTests(unittest.TestCase):
    def setUp(self):
        self.directory = temporary_directory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / "audit.jsonl"

    def engine(self, **kwargs):
        audit = AuditLog(self.path, **kwargs)
        engine = DynamicImmunityEngine(policy(self.root), audit=audit)
        self.addCleanup(engine.close)
        return engine

    def read(self):
        text = self.path.read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines()], text

    def test_allowed_and_completed_calls_are_recorded(self):
        engine = self.engine()
        self.assertTrue(engine.begin(ToolCall("1", "read_file", {"path": "doc.txt"})).allowed)
        engine.complete("1", ToolResult({"content": [{"type": "text", "text": "ok"}]}))
        records, _ = self.read()
        self.assertEqual([(record["event"], record["code"]) for record in records],
                         [("completion", "COMPLETED")])

    def test_denials_are_recorded_with_their_code(self):
        engine = self.engine()
        engine.begin(ToolCall("1", "unregistered_tool", {}))
        engine.begin(ToolCall("2", "read_file", {"path": "../escape.txt"}))
        records, _ = self.read()
        self.assertEqual([record["code"] for record in records], ["UNKNOWN_TOOL", "ARGUMENTS_DENIED"])
        self.assertEqual(records[0]["tool"], "<unregistered>")

    def test_arguments_and_results_never_reach_the_log(self):
        engine = self.engine()
        engine.begin(ToolCall("1", "write_file", {"path": "out.txt", "content": SECRET}))
        engine.complete("1", ToolResult({"content": [{"type": "text", "text": SECRET}]}))
        _, text = self.read()
        self.assertNotIn("AUDIT-MUST-NOT-LEAK", text)
        self.assertNotIn("out.txt", text)
        self.assertNotIn(SECRET, text)

    def test_credential_like_content_is_not_recorded_even_when_denied(self):
        engine = self.engine()
        decision = engine.begin(ToolCall("1", "write_file", {"path": "out.txt", "content": SECRET_LIKE}))
        self.assertEqual(decision.code, "SENSITIVE_FLOW")
        records, text = self.read()
        self.assertEqual([record["code"] for record in records], ["SENSITIVE_FLOW"])
        self.assertNotIn("AUDIT-MUST-NOT-LEAK", text)

    def test_user_goal_is_not_recorded(self):
        audit = AuditLog(self.path)
        engine = DynamicImmunityEngine(policy(self.root), user_goal=SECRET, audit=audit)
        self.addCleanup(engine.close)
        engine.begin(ToolCall("1", "unread_tool", {}))
        _, text = self.read()
        self.assertNotIn("AUDIT-MUST-NOT-LEAK", text)

    def test_capacity_exhaustion_denies_and_closes_session(self):
        engine = self.engine(max_records=1)
        engine.begin(ToolCall("1", "unread_tool", {}))
        decision = engine.begin(ToolCall("2", "unread_tool", {}))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "AUDIT_UNAVAILABLE")
        self.assertTrue(engine.closed)
        self.assertEqual(engine.begin(ToolCall("3", "read_file", {"path": "doc.txt"})).code, "SESSION_CLOSED")

    def test_write_failure_denies_the_call(self):
        engine = self.engine()
        with mock.patch.object(AuditLog, "write", side_effect=AuditError("disk full")):
            decision = engine.begin(ToolCall("1", "unread_tool", {}))
        self.assertEqual(decision.code, "AUDIT_UNAVAILABLE")
        self.assertTrue(engine.closed)

    def test_completion_write_failure_closes_session_and_marks_result(self):
        engine = self.engine()
        self.assertTrue(engine.begin(ToolCall("1", "read_file", {"path": "doc.txt"})).allowed)
        with mock.patch.object(AuditLog, "write", side_effect=AuditError("disk full")):
            result = engine.complete("1", ToolResult({"content": [{"type": "text", "text": "ok"}]}))
        self.assertTrue(result.is_error)
        self.assertEqual(result.output["_meta"]["agent_immunity"]["code"], "AUDIT_UNAVAILABLE")
        self.assertTrue(engine.closed)

    def test_engine_close_closes_the_log(self):
        engine = self.engine()
        self.assertTrue(engine.begin(ToolCall("1", "read_file", {"path": "doc.txt"})).allowed)
        engine.close()
        with self.assertRaises(AuditError):
            engine.audit.write("decision", "a", "ALLOW", False)

    def test_audit_must_be_an_audit_log(self):
        with self.assertRaises(TypeError):
            DynamicImmunityEngine(policy(self.root), audit="path")


if __name__ == "__main__":
    unittest.main()
