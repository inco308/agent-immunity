"""保留标记只豁免新候选，不证明任意同形字符串都不是秘密。

全部数据均为虚构值；网络、写入和执行渠道只检查引擎决策，不调用真实工具。
"""

import base64
import copy
import json
from pathlib import Path
import unittest

from agent_immunity import DynamicImmunityEngine, Policy, ToolCall, ToolResult
from agent_immunity.core.taint_tracker import TaintTracker, TrackingLimit
from tests.support import DATA, FIXTURES, policy_data, temporary_directory


CASES = json.loads((FIXTURES / "redaction_cases.json").read_text(encoding="utf-8"))


def materialize(value, replacements):
    """将夹具中的占位输入替换为虚构数据，保留原始嵌套结构。"""
    if isinstance(value, str):
        for key, replacement in replacements.items():
            value = value.replace(key, replacement)
        return value
    if isinstance(value, list):
        return [materialize(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: materialize(item, replacements) for key, item in value.items()}
    return value


def representation(spec, value):
    document = materialize(CASES["json_document"], {"$VALUE": value})
    return materialize(spec["template"], {
        "$JSON_DOCUMENT": json.dumps(document, ensure_ascii=False), "$VALUE": value,
    })


def encoded_secret(kind):
    """从同一个虚构 canary 生成有限表示，不预置真实凭证。"""
    raw = DATA["secret"].encode("utf-8")
    encodings = {
        "raw": DATA["secret"],
        "base64": base64.b64encode(raw).decode("ascii"),
        "url": "".join(f"%{item:02X}" for item in raw),
        "hex": raw.hex(),
    }
    return encodings[kind]


class RedactionMarkerTests(unittest.TestCase):
    def setUp(self):
        self.directory = temporary_directory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def sink_engine(self, sink, payload):
        data = policy_data(self.root)
        if "spec" in sink:
            data["tools"][sink["tool"]] = materialize(sink["spec"], {"$PAYLOAD": payload})
        return DynamicImmunityEngine(Policy.from_dict(data))

    def seed(self, engine, secret=None):
        value = DATA["secret"] if secret is None else secret
        result = engine.execute(ToolCall("seed", "structured", {}), lambda *_: ToolResult({"password": value}))
        self.assertFalse(result.is_error)
        self.assertTrue(result.taint_tag.sensitive)

    def assert_sink_denied(self, sink, payload, known_secret=None):
        """拒绝必须由敏感信息判据触发，且不得进入业务处理器。"""
        engine = self.sink_engine(sink, payload)
        if known_secret is not None:
            self.seed(engine, known_secret)
        before = engine.state.completed_count
        invoked = []

        def handler(*arguments):
            invoked.append(arguments)
            return ToolResult({"synthetic_result": True})

        arguments = materialize(sink["arguments"], {"$PAYLOAD": payload})
        result = engine.execute(ToolCall("outgoing", sink["tool"], arguments), handler)
        self.assertTrue(result.is_error)
        self.assertEqual(result.output["_meta"]["agent_immunity"]["code"], "SENSITIVE_FLOW")
        self.assertEqual(invoked, [])
        self.assertEqual(engine.state.completed_count, before)
        self.assertFalse(engine.closed)

    def test_exact_markers_are_not_new_secrets_and_keep_untrusted_label(self):
        for marker in CASES["markers"]:
            for spec in CASES["representations"]:
                with self.subTest(marker=marker["id"], representation=spec["id"]):
                    output = representation(spec, marker["value"])
                    unchanged = copy.deepcopy(output)
                    tracker = TaintTracker()
                    tag = tracker.observe("document", output, sensitive_fields=spec.get("sensitive_fields", ()))
                    self.assertTrue(tag.untrusted)
                    self.assertFalse(tag.sensitive)
                    self.assertEqual(tracker.secret_count, 0)
                    self.assertFalse(tracker.contains_sensitive(output))
                    self.assertEqual(output, unchanged)

    def test_markers_do_not_consume_secret_capacity_before_or_after_real_secret(self):
        tracker = TaintTracker(max_secrets=1)
        output = [representation(CASES["representations"][0], marker["value"]) for marker in CASES["markers"]]
        tag = tracker.observe("document", output)
        self.assertTrue(tag.untrusted)
        self.assertFalse(tag.sensitive)
        self.assertEqual(tracker.secret_count, 0)
        tracker.observe("document", {"password": DATA["secret"]})
        self.assertEqual(tracker.secret_count, 1)
        tracker.observe("document", output)
        self.assertEqual(tracker.secret_count, 1)
        self.assertTrue(tracker.contains_sensitive({"payload": DATA["secret"]}))
        with self.assertRaises(TrackingLimit):
            tracker.observe("document", {"password": CASES["second_secret"]})

    def test_exact_marker_outputs_are_allowed_in_each_sink_with_existing_secret(self):
        for marker in CASES["markers"]:
            payload = json.dumps(materialize(CASES["json_document"], {"$VALUE": marker["value"]}), ensure_ascii=False)
            for sink in CASES["sinks"]:
                with self.subTest(marker=marker["id"], channel=sink["id"]):
                    engine = self.sink_engine(sink, payload)
                    self.seed(engine)
                    arguments = materialize(sink["arguments"], {"$PAYLOAD": payload})
                    decision = engine.check_call(ToolCall("outgoing", sink["tool"], arguments))
                    self.assertEqual(decision.code, "ALLOW")
                    self.assertEqual(engine.taint_tracker.secret_count, 1)
                    self.assertFalse(engine.closed)

    def test_engine_marker_results_keep_untrusted_and_do_not_close_full_tracker(self):
        for spec in CASES["representations"]:
            with self.subTest(representation=spec["id"]):
                data = policy_data(self.root)
                data["max_secrets"] = 1
                data["tools"]["structured"]["sensitive_fields"] = spec.get("sensitive_fields", [])
                engine = DynamicImmunityEngine(Policy.from_dict(data))
                self.seed(engine)
                output = representation(spec, CASES["markers"][0]["value"])
                result = engine.execute(ToolCall("masked", "structured", {}), lambda *_: ToolResult(output))
                self.assertFalse(result.is_error)
                self.assertTrue(result.taint_tag.untrusted)
                self.assertFalse(result.taint_tag.sensitive)
                self.assertEqual(engine.taint_tracker.secret_count, 1)
                self.assertEqual(engine.state.completed_count, 2)
                self.assertFalse(engine.closed)

    def test_only_complete_reserved_values_are_exempt(self):
        specs = [item for item in CASES["representations"] if item["id"] in CASES["negative_representations"]]
        for candidate in CASES["non_markers"]:
            for spec in specs:
                with self.subTest(candidate=candidate["id"], representation=spec["id"]):
                    output = representation(spec, candidate["value"])
                    tracker = TaintTracker()
                    self.assertTrue(tracker.contains_sensitive(output))
                    tag = tracker.observe("document", output)
                    self.assertTrue(tag.untrusted)
                    self.assertTrue(tag.sensitive)
                    self.assertEqual(tracker.secret_count, 1)
                    self.assertTrue(tracker.contains_sensitive({"payload": candidate["value"]}))

    def test_neighboring_markers_do_not_hide_real_secret_candidates(self):
        for case in CASES["mixed_cases"]:
            with self.subTest(case=case["id"]):
                output = materialize(case["output"], {"$SECRET": DATA["secret"]})
                tracker = TaintTracker(max_secrets=1)
                self.assertTrue(tracker.contains_sensitive(output))
                tag = tracker.observe("document", output)
                self.assertTrue(tag.untrusted)
                self.assertTrue(tag.sensitive)
                self.assertEqual(tracker.secret_count, 1)
                self.assertTrue(tracker.contains_sensitive({"payload": DATA["secret"]}))

    def test_unknown_tokens_and_password_assignments_remain_sensitive(self):
        for case in CASES["unknown_secret_cases"]:
            with self.subTest(case=case["id"]):
                tracker = TaintTracker(max_secrets=1)
                output = copy.deepcopy(case["output"])
                self.assertTrue(tracker.contains_sensitive(output))
                tag = tracker.observe("document", output)
                self.assertTrue(tag.sensitive)
                self.assertTrue(tag.untrusted)
                self.assertEqual(tracker.secret_count, 1)

    def test_fresh_sensitive_candidates_are_blocked_in_each_sink(self):
        for case in CASES["mixed_cases"] + CASES["unknown_secret_cases"]:
            output = materialize(case["output"], {"$SECRET": DATA["secret"]})
            payload = json.dumps(output, ensure_ascii=False)
            for sink in CASES["sinks"]:
                with self.subTest(case=case["id"], channel=sink["id"]):
                    self.assert_sink_denied(sink, payload)

    def test_known_secret_variants_are_scanned_after_marker_filtering(self):
        for encoding in CASES["known_encodings"]:
            with self.subTest(encoding=encoding):
                tracker = TaintTracker(max_secrets=1)
                tracker.observe("document", {"password": DATA["secret"]})
                payload = materialize(CASES["known_payload"], {"$ENCODED": encoded_secret(encoding)})
                self.assertTrue(tracker.contains_sensitive(payload))
                self.assertEqual(tracker.secret_count, 1)

    def test_known_secret_variants_remain_blocked_in_each_sink(self):
        for encoding in CASES["known_encodings"]:
            output = materialize(CASES["known_payload"], {"$ENCODED": encoded_secret(encoding)})
            payload = json.dumps(output, ensure_ascii=False)
            for sink in CASES["sinks"]:
                with self.subTest(encoding=encoding, channel=sink["id"]):
                    self.assert_sink_denied(sink, payload, DATA["secret"])

    def test_known_secret_inside_reserved_marker_still_wins(self):
        for case in CASES["known_collisions"]:
            with self.subTest(case=case["id"]):
                tracker = TaintTracker()
                tracker.observe("document", {"password": case["secret"]})
                output = materialize(CASES["json_document"], {"$VALUE": case["outgoing"]})
                self.assertTrue(tracker.contains_sensitive(output))
                self.assertEqual(tracker.secret_count, 1)

    def test_known_secret_inside_reserved_marker_is_blocked_in_each_sink(self):
        for case in CASES["known_collisions"]:
            output = materialize(CASES["json_document"], {"$VALUE": case["outgoing"]})
            payload = json.dumps(output, ensure_ascii=False)
            for sink in CASES["sinks"]:
                with self.subTest(case=case["id"], channel=sink["id"]):
                    self.assert_sink_denied(sink, payload, case["secret"])

    def test_long_real_candidates_containing_markers_still_close_session(self):
        specs = [item for item in CASES["representations"] if item["id"] in CASES["long_representations"]]
        for case in CASES["long_values"]:
            candidate = case["prefix"] + case["fill"] * case["repeat"] + case["suffix"]
            for spec in specs:
                with self.subTest(case=case["id"], representation=spec["id"]):
                    engine = DynamicImmunityEngine(Policy.from_dict(policy_data(self.root)))
                    self.seed(engine)
                    output = representation(spec, candidate)
                    result = engine.execute(ToolCall("long", "structured", {}), lambda *_: ToolResult(output))
                    self.assertTrue(result.is_error)
                    self.assertEqual(result.output["_meta"]["agent_immunity"]["code"], "RESULT_REJECTED")
                    self.assertTrue(engine.closed)
                    self.assertEqual(engine.state.completed_count, 1)
                    self.assertEqual(engine.taint_tracker.secret_count, 1)
                    self.assertNotIn(candidate, repr(result))
                    self.assertEqual(engine.check_call(ToolCall("later", "document", {})).code, "SESSION_CLOSED")

    def test_marker_only_results_do_not_bypass_size_or_depth_limits(self):
        for case in CASES["limit_cases"]:
            with self.subTest(case=case["id"]):
                policy = policy_data(self.root)
                policy["max_bytes"] = case["max_bytes"]
                engine = DynamicImmunityEngine(Policy.from_dict(policy))
                output = {"api_key": CASES["markers"][0]["value"]}
                for _ in range(case["depth"]):
                    output = {"wrapper": output}
                if case["repeat"] > 1:
                    output = [output] * case["repeat"]
                result = engine.execute(ToolCall("masked-limit", "structured", {}), lambda *_: ToolResult(output))
                self.assertEqual(result.output["_meta"]["agent_immunity"]["code"], "RESULT_REJECTED")
                self.assertTrue(engine.closed)
                self.assertEqual(engine.state.completed_count, 0)


if __name__ == "__main__":
    unittest.main()
