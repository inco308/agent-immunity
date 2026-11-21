"""凭证编码表示回归：归一化与有界多层解码覆盖的变换，以及必须保持放行的良性载荷。

全部数据为虚构值，用例清单见 tests/fixtures/encoding_cases.json。
未覆盖的变换（任意替换密码、加密、分割传输、模型改写）仍是已知局限，
这里只断言清单内的行为，不声称任意变换都能识别。
"""
import json
import unittest

from agent_immunity import DynamicImmunityEngine, Policy, ToolCall, ToolResult
from tests.support import FIXTURES, policy_data, temporary_directory

CASES = json.loads((FIXTURES / "encoding_cases.json").read_text(encoding="utf-8"))
ORIGIN = "https://example.invalid"


class CredentialEncodingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = temporary_directory()
        self.addCleanup(self.temporary.cleanup)

    def seeded_engine(self):
        """先把虚构凭证写进会话污点库，再返回引擎。"""
        engine = DynamicImmunityEngine(
            Policy.from_dict(policy_data(self.temporary.name, origin=ORIGIN)))
        decision = engine.begin(ToolCall("seed-1", "read_file", {"path": "secret.txt"}))
        self.assertTrue(decision.allowed, decision)
        engine.complete("seed-1", ToolResult({"content": [
            {"type": "text", "text": "api_key=" + CASES["secret"]}]}))
        self.assertEqual(engine.taint_tracker.secret_count, 1)
        return engine

    def sink_decision(self, case):
        engine = self.seeded_engine()
        return engine.begin(ToolCall(
            "sink-1", "web_request", {"url": case["url"], **case["arguments"]}))

    def test_blocked_encodings_are_denied(self):
        for case in CASES["blocked"]:
            with self.subTest(case=case["id"]):
                decision = self.sink_decision(case)
                self.assertFalse(decision.allowed, case["id"])
                self.assertEqual(decision.code, "SENSITIVE_FLOW")

    def test_allowed_payloads_still_pass(self):
        for case in CASES["allowed"]:
            with self.subTest(case=case["id"]):
                decision = self.sink_decision(case)
                self.assertTrue(decision.allowed, f"{case['id']}: {decision.code}")

    def test_no_tracked_secret_means_no_credential_denial(self):
        """未跟踪到凭证时，编码表示本身不应被拒；只有明文形态例外。"""
        recognized = set(CASES["pattern_recognized"])
        for case in CASES["blocked"]:
            if case["id"] in recognized:
                continue
            with self.subTest(case=case["id"]):
                engine = DynamicImmunityEngine(
                    Policy.from_dict(policy_data(self.temporary.name, origin=ORIGIN)))
                decision = engine.begin(ToolCall(
                    "sink-1", "web_request", {"url": case["url"], **case["arguments"]}))
                self.assertTrue(decision.allowed, f"{case['id']}: {decision.code}")


if __name__ == "__main__":
    unittest.main()
