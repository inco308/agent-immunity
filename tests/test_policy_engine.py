"""对应上一轮审查的安全属性回归与正常业务对照。"""
import base64
import copy
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from agent_immunity import DynamicImmunityEngine, Policy, PolicyError, ToolCall, ToolResult
from agent_immunity.core.agent_runtime import CausalActionDAG
from agent_immunity.core.policy import strict_json
from tests.support import DATA, policy, policy_data, temporary_directory

class PolicyEngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = temporary_directory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.engine = DynamicImmunityEngine(policy(self.root))

    def seed(self, engine=None):
        engine = engine or self.engine
        return engine.execute(ToolCall("source", "structured", {}), lambda *_: ToolResult({"content": [], "structuredContent": {"password": DATA["secret"]}}))

    def test_data_driven_review_regressions(self):
        for case in DATA["cases"]:
            with self.subTest(id=case["id"], description=case["description"]):
                engine = DynamicImmunityEngine(policy(self.root), user_goal=case.get("goal", ""))
                if case.get("seed"):
                    self.seed(engine)
                secret = DATA["secret"]
                encoding = case.get("encoding")
                if encoding == "base64":
                    secret = base64.b64encode(secret.encode()).decode()
                elif encoding == "percent":
                    secret = "".join("%%%02X" % x for x in secret.encode())
                elif encoding == "hex":
                    secret = secret.encode().hex()
                arguments = json.loads(json.dumps(case["args"]).replace("$SECRET", secret))
                decision = engine.begin(ToolCall("check", case["tool"], arguments))
                self.assertEqual(decision.code, case["code"])

    def test_untrusted_and_sensitive_labels_coexist_R07_R12(self):
        result = self.seed()
        self.assertTrue(result.taint_tag.untrusted)
        self.assertTrue(result.taint_tag.sensitive)
        self.assertEqual(self.engine.taint_tracker.secret_count, 1)

    def test_credentials_block_all_sink_capabilities_without_state_commit_R08_R10(self):
        data = policy_data(self.root)
        data["tools"]["export"] = {"capabilities": ["execute"], "parameters": {"value": "string"}, "allowed_arguments": [{"value": DATA["secret"]}]}
        engine = DynamicImmunityEngine(Policy.from_dict(data))
        self.seed(engine)
        previous = engine.state.current
        calls = [
            ToolCall("write", "write_file", {"path": "out.txt", "content": DATA["secret"]}),
            ToolCall("network", "web_request", {"url": "https://example.invalid/", "payload": DATA["secret"]}),
            ToolCall("execute", "export", {"value": DATA["secret"]}),
        ]
        for call in calls:
            with self.subTest(tool=call.tool_name):
                self.assertEqual(engine.begin(call).code, "SENSITIVE_FLOW")
                self.assertEqual(engine.state.current, previous)
                self.assertEqual(engine.state.completed_count, 1)

    def test_authorized_command_after_document_R06(self):
        for text in ["Public reference material.", DATA["document"]]:
            with self.subTest(text=text):
                engine = DynamicImmunityEngine(policy(self.root))
                engine.execute(ToolCall("read", "document", {}), lambda *_: ToolResult({"content": [{"type": "text", "text": text}]}))
                self.assertTrue(engine.check_call(ToolCall("run", "python_version", {})).allowed)

    def test_denied_and_failed_actions_do_not_commit_R08(self):
        denied = self.engine.begin(ToolCall("deny", "dispatch", {}))
        self.assertFalse(denied.allowed)
        self.assertEqual(self.engine.state.current, "START")
        call = ToolCall("fail", "fail", {})
        self.engine.begin(call)
        self.assertEqual(self.engine.state.current, "START")
        self.engine.complete(call.call_id, ToolResult({"message": "failed"}, is_error=True))
        self.assertEqual(self.engine.state.completed_count, 0)
        self.seed()
        self.assertEqual(self.engine.state.completed_count, 1)

    def test_synchronous_handler_never_runs_for_denial(self):
        called = []
        result = self.engine.execute(ToolCall("1", "dispatch", {}), lambda *_: called.append(True))
        self.assertTrue(result.is_error)
        self.assertEqual(called, [])

    def test_state_policy_is_explicit(self):
        data = policy_data(self.root)
        data["transitions"] = {"START": ["document"], "document": ["python_version"]}
        engine = DynamicImmunityEngine(Policy.from_dict(data))
        self.assertEqual(engine.begin(ToolCall("1", "python_version", {})).code, "TRANSITION_DENIED")
        engine.execute(ToolCall("2", "document", {}), lambda *_: ToolResult("doc"))
        self.assertTrue(engine.begin(ToolCall("3", "python_version", {})).allowed)

    def test_only_one_pending_call(self):
        self.assertTrue(self.engine.begin(ToolCall("1", "document", {})).allowed)
        self.assertEqual(self.engine.begin(ToolCall("2", "document", {})).code, "SESSION_BUSY")
        self.engine.abort()
        self.assertEqual(self.engine.begin(ToolCall("3", "document", {})).code, "SESSION_CLOSED")

    def test_result_capacity_fail_closed(self):
        data = policy_data(self.root)
        data["max_secrets"] = 1
        engine = DynamicImmunityEngine(Policy.from_dict(data))
        self.seed(engine)
        result = engine.execute(ToolCall("2", "structured", {}), lambda *_: ToolResult({"password": "second_canary"}))
        self.assertTrue(result.is_error)
        self.assertEqual(engine.state.completed_count, 1)
        self.assertEqual(engine.begin(ToolCall("3", "document", {})).code, "SESSION_CLOSED")

    def test_long_text_credential_is_rejected_without_truncation(self):
        result = self.engine.execute(ToolCall("1", "document", {}), lambda *_: ToolResult("password=" + "A" * 4097))
        self.assertTrue(result.is_error)
        self.assertTrue(self.engine.closed)
        self.assertEqual(self.engine.state.completed_count, 0)
        self.assertEqual(self.engine.taint_tracker.secret_count, 0)

    def test_events_bounded_and_redacted(self):
        data = policy_data(self.root)
        data["max_events"] = 3
        engine = DynamicImmunityEngine(Policy.from_dict(data))
        self.seed(engine)
        for i in range(5):
            engine.begin(ToolCall(str(i), "web_request", {"url": "https://example.invalid/", "payload": DATA["secret"]}))
        self.assertEqual(len(engine.events), 3)
        self.assertNotIn(DATA["secret"], repr(engine.events))

    def test_check_copies_and_normalizes_path(self):
        arguments = {"path": "out.txt", "content": "ok"}
        decision = self.engine.begin(ToolCall("1", "write_file", arguments))
        arguments["content"] = "changed"
        self.assertEqual(decision.arguments["content"], "ok")
        self.assertEqual(decision.arguments["path"], str(self.root / "out.txt"))

    def test_absolute_path_outside_workspace(self):
        decision = self.engine.check_call(ToolCall("1", "write_file", {"path": str(self.root.parent / "outside.txt"), "content": "ok"}))
        self.assertFalse(decision.allowed)

    def test_existing_symlink_escape(self):
        with temporary_directory() as outside:
            link = self.root / "link"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("当前宿主不允许创建符号链接")
            decision = self.engine.check_call(ToolCall("1", "write_file", {"path": str(link / "out.txt"), "content": "ok"}))
            self.assertFalse(decision.allowed)
            loop = self.root / "loop"
            loop.symlink_to(loop, target_is_directory=True)
            self.assertEqual(self.engine.check_call(ToolCall("2", "write_file", {"path": str(loop / "out.txt"), "content": "ok"})).code, "ARGUMENTS_DENIED")

    def test_ambiguous_paths_and_zero_port_are_denied(self):
        for path in ["C:relative.txt", "NUL", "CON.txt", "foo. ", "file.txt:stream", "out\x01.txt"]:
            with self.subTest(path=path):
                self.assertFalse(self.engine.check_call(ToolCall("1", "write_file", {"path": path, "content": "ok"})).allowed)
        self.assertFalse(self.engine.check_call(ToolCall("1", "web_request", {"url": "https://example.invalid:0/", "payload": "ok"})).allowed)

    def test_path_resolution_failure_is_a_denial(self):
        with patch.object(Path, "resolve", side_effect=RuntimeError("symlink loop")):
            decision = self.engine.check_call(ToolCall("1", "write_file", {"path": "loop", "content": "ok"}))
            self.assertEqual(decision.code, "ARGUMENTS_DENIED")
            with self.assertRaises(PolicyError):
                Policy.from_dict(policy_data(self.root))
            with self.assertRaises(PolicyError):
                Policy.load("loop")

    def test_json_text_credentials_and_unknown_name_redaction(self):
        self.engine.execute(ToolCall("1", "document", {}), lambda *_: ToolResult(json.dumps({"password": DATA["secret"]})))
        self.assertEqual(self.engine.check_call(ToolCall("2", "write_file", {"path": "out", "content": DATA["secret"]})).code, "SENSITIVE_FLOW")
        self.engine.begin(ToolCall("3", DATA["secret"], {}))
        self.assertNotIn(DATA["secret"], repr(self.engine.events))

    def test_invalid_result_flags_end_session(self):
        result = self.engine.execute(ToolCall("1", "document", {}), lambda *_: ToolResult("ok", is_error="false"))
        self.assertTrue(result.is_error)
        self.assertEqual(self.engine.state.completed_count, 0)

    def test_policy_rejects_missing_restrictions_and_typos(self):
        for key in ["roots", "path_fields"]:
            data = policy_data(self.root)
            del data["tools"]["write_file"][key]
            with self.subTest(field=key), self.assertRaises(PolicyError):
                Policy.from_dict(data)
        data = policy_data(self.root)
        data["tools"]["python_version"]["allowed_arguments"] = []
        with self.assertRaises(PolicyError):
            Policy.from_dict(data)
        data = policy_data(self.root)
        data["tools"]["python_version"]["capabilites"] = ["network"]
        with self.assertRaises(PolicyError):
            Policy.from_dict(data)

    def test_invalid_json_and_types(self):
        for text in ['{"version":1,"version":1}', '{"value":NaN}']:
            with self.assertRaises(ValueError):
                strict_json(text)
        decision = self.engine.check_call(ToolCall("1", "write_file", {"path": 1, "content": "ok"}))
        self.assertFalse(decision.allowed)
        self.assertEqual(self.engine.check_call(ToolCall("1", 123, {})).code, "INVALID_CALL")

    def test_handler_exception_closes_session(self):
        def broken(*_):
            raise RuntimeError(DATA["secret"])
        result = self.engine.execute(ToolCall("1", "document", {}), broken)
        self.assertTrue(result.is_error)
        self.assertNotIn(DATA["secret"], repr(result))
        self.assertEqual(self.engine.check_call(ToolCall("2", "document", {})).code, "SESSION_CLOSED")

    def test_explicit_dag_prunes_only_dependents(self):
        dag = CausalActionDAG()
        dag.add_node("source")
        dag.add_node("blocked", ["source"])
        dag.add_node("dependent", ["blocked"])
        dag.add_node("normal", ["source"])
        self.assertEqual(dag.prune({"blocked"}, ["dependent", "normal"]), ["normal"])
        with self.assertRaises(ValueError):
            dag.add_node("future", ["missing"])

if __name__ == "__main__":
    unittest.main()
