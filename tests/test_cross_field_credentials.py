"""跨字段凭证拆分回归。

只把同一个已知凭证拆到相邻参数、不做任何编码变换，连接参数值后才构成凭证。
用例清单见 tests/fixtures/cross_field_cases.json；顺序相反或不相关字段必须放行。
"""
import json
import unittest

from agent_immunity import DynamicImmunityEngine, Policy, ToolCall, ToolResult
from tests.support import FIXTURES, policy_data, temporary_directory

CASES = json.loads((FIXTURES / "cross_field_cases.json").read_text(encoding="utf-8"))
ORIGIN = "https://example.invalid"


class CrossFieldCredentialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = temporary_directory()
        self.addCleanup(self.temporary.cleanup)

    def seeded_engine(self):
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

    def test_split_secret_is_denied(self):
        for case in CASES["blocked"]:
            with self.subTest(case=case["id"]):
                decision = self.sink_decision(case)
                self.assertFalse(decision.allowed, case["id"])
                self.assertEqual(decision.code, "SENSITIVE_FLOW")

    def test_reordered_or_unrelated_fields_still_pass(self):
        for case in CASES["allowed"]:
            with self.subTest(case=case["id"]):
                decision = self.sink_decision(case)
                self.assertTrue(decision.allowed, f"{case['id']}: {decision.code}")


if __name__ == "__main__":
    unittest.main()
