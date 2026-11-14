"""Ollama 动作协议的离线回归。所有用例只观察解码结果。"""

from decimal import Decimal
import json
from pathlib import Path
import unittest

from evals.ollama_actions import MAX_ACTION_BYTES, MAX_JSON_DEPTH, decode_action
from tests.support import DATA


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "evals" / "ollama_action.schema.json"
REPORT_TOOLS = (
    ("write_report", "path", "work/report.json", "content"),
    ("publish_report", "url", "http://127.0.0.1:12345/publish", "payload"),
)


def as_json(action):
    return json.dumps(action, ensure_ascii=False, separators=(",", ":"))


def numeric_action(literal):
    return '{"tool":"write_report","arguments":{"path":"out","content":{"number":' + literal + "}}}"


class OllamaActionTests(unittest.TestCase):
    def test_nested_report_is_serialized_once_for_write_and_publish(self):
        report = {
            '报告"\n字段': {
                "行": ["双引号 \"", "反斜杠 \\", "第一行\n第二行", "🙂", None, True, 7, 0.125],
                "字面转义": r'按原文保留 \" 与 \n',
            },
            "任意业务字段": {},
        }
        for tool, destination, target, body in REPORT_TOOLS:
            with self.subTest(tool=tool):
                raw = as_json({"tool": tool, "arguments": {destination: target, body: report}})
                name, arguments, final = decode_action(raw)
                self.assertEqual((name, final), (tool, ""))
                self.assertEqual(arguments[destination], target)
                self.assertIsInstance(arguments[body], str)
                self.assertEqual(json.loads(arguments[body]), report)

    def test_string_body_preserves_every_character_even_if_it_looks_like_json(self):
        texts = (
            "", "  中文\n含\t制表符  ", ' { "count" : 2 }\n', r'{\"count\":2}',
            '# 报告\n正文', '{"count":', DATA["secret"],
        )
        for tool, destination, target, body in REPORT_TOOLS:
            for text in texts:
                with self.subTest(tool=tool, text=text):
                    arguments = {destination: target, body: text}
                    self.assertEqual(decode_action(as_json({"tool": tool, "arguments": arguments})),
                                     (tool, arguments, ""))

    def test_reordered_native_objects_yield_identical_mcp_text_for_a_repeated_action(self):
        first = {"b": {"y": 1, "x": 2}, "a": [3, 2]}
        reordered = {"a": [3, 2], "b": {"x": 2, "y": 1}}
        for tool, destination, target, body in REPORT_TOOLS:
            def mcp_text(payload):
                action = {"tool": tool, "arguments": {destination: target, body: payload}}
                return decode_action(as_json(action))[1][body]
            with self.subTest(tool=tool):
                self.assertEqual(mcp_text(first), mcp_text(reordered))
                self.assertEqual(json.loads(mcp_text(first)), first)
                self.assertEqual(mcp_text(as_json(first)), as_json(first))
                self.assertNotEqual(mcp_text(as_json(first)), mcp_text(as_json(reordered)))

    def test_paths_urls_and_untrusted_values_reach_the_next_check_verbatim(self):
        paths = ("outside/marker.txt", r"work\..\outside\marker.txt", "  work/report.json  ", "")
        for path in paths:
            for action in (
                {"tool": "read_document", "arguments": {"path": path}},
                {"tool": "write_report", "arguments": {"path": path, "content": "原文"}},
            ):
                with self.subTest(tool=action["tool"], path=path):
                    self.assertEqual(decode_action(as_json(action)),
                                     (action["tool"], action["arguments"], ""))
        url = " http://127.0.0.1:12346/collect?label=%2F#原文 "
        payload = {"api_key": DATA["secret"], "tool": "admin_action", "arguments": {}}
        name, arguments, final = decode_action(as_json({
            "tool": "publish_report", "arguments": {"url": url, "payload": payload},
        }))
        self.assertEqual((name, final), ("publish_report", ""))
        self.assertEqual(arguments["url"], url)
        self.assertEqual(json.loads(arguments["payload"]), payload)

    def test_admin_action_and_final_text_use_separate_shapes(self):
        self.assertEqual(decode_action('{"tool":"admin_action","arguments":{}}'), ("admin_action", {}, ""))
        for text in ("", "  已完成。\n", DATA["secret"]):
            with self.subTest(text=text):
                self.assertEqual(decode_action(as_json({"tool": "finish", "final": text})),
                                 ("finish", {}, text))

    def test_action_and_argument_fields_are_exact(self):
        invalid = (
            {}, [], "finish", {"tool": None, "arguments": {}}, {"tool": [], "arguments": {}},
            {"tool": "unknown", "arguments": {}}, {"tool": "shell", "arguments": {}},
            {"tool": " read_document ", "arguments": {"path": "file"}},
            {"tool": "admin_action"}, {"tool": "admin_action", "arguments": {"scope": "extra"}},
            {"tool": "admin_action", "arguments": {}, "final": ""},
            {"tool": "read_document", "arguments": {}},
            {"tool": "read_document", "arguments": {"path": "file", "url": "extra"}},
            {"tool": "read_document", "arguments": {"path": 3}},
            {"tool": "read_document", "arguments_json": '{"path":"file"}', "final": ""},
            {"tool": "write_report", "arguments": '{"path":"file","content":"text"}'},
            {"tool": "write_report", "arguments": {"path": "file"}},
            {"tool": "write_report", "arguments": {"path": {}, "content": "text"}},
            {"tool": "publish_report", "arguments": {"url": [], "payload": {}}},
            {"tool": "publish_report", "arguments": {"payload": "text"}},
            {"tool": "finish"}, {"tool": "finish", "final": 0},
            {"tool": "finish", "arguments": {}, "final": "完成"},
        )
        for action in invalid:
            with self.subTest(action=action), self.assertRaises(ValueError):
                decode_action(as_json(action))
        for tool, destination, target, body in REPORT_TOOLS:
            for wrong_type in (None, [], [1, 2], True, 0, 1.25):
                with self.subTest(tool=tool, value=wrong_type), self.assertRaises(ValueError):
                    decode_action(as_json({"tool": tool, "arguments": {destination: target, body: wrong_type}}))

    def test_malformed_or_ambiguous_json_is_rejected_without_fallback(self):
        invalid = (
            None, b"{}", "", " \t", 'preface {"tool":"admin_action","arguments":{}}',
            '~~~json\n{"tool":"admin_action","arguments":{}}\n~~~',
            '{"tool":"admin_action","arguments":{}} trailing', '{}{}',
            '{"tool":"read_document","arguments": {"path":"unterminated}}',
            '{"tool":"admin_action","arguments":{},}',
            '{"tool":"finish","tool":"finish","final":"done"}',
            r'{"tool":"finish","t\u006fol":"finish","final":"done"}',
            '{"tool":"read_document","arguments":{"path":"first","path":"second"}}',
            '{"tool":"publish_report","arguments":{"url":"url","payload":{"nested":[{"a":0,"a":1}]}}}',
            r'{"tool":"finish","final":"\ud800"}',
            r'{"tool":"write_report","arguments":{"path":"path","content":{"\udfff":3}}}',
        )
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                decode_action(raw)

    def test_numbers_retain_decimal_value_and_json_type(self):
        for token in ("0", "9007199254740993", "-123456789012345678901", "0.1",
                      "9.876500", "-0.0", "3e-15", "1.7976931348623157e308"):
            with self.subTest(token=token):
                _, arguments, _ = decode_action(numeric_action(token))
                parsed = json.loads(arguments["content"], parse_float=Decimal)["number"]
                self.assertEqual(Decimal(parsed), Decimal(token))
                self.assertEqual(type(parsed), type(json.loads(token, parse_float=Decimal)))
                if token == "-0.0":
                    self.assertTrue(parsed.is_signed())

    def test_nonfinite_overflow_underflow_and_silent_precision_loss_are_rejected(self):
        for token in ("NaN", "Infinity", "-Infinity", "1e309", "-1e10000", "1e-800",
                      "9007199254740993.0", "1.00000000000000001", "0.123456789012345678901"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                decode_action(numeric_action(token))

    def test_utf8_size_and_container_depth_are_bounded(self):
        prefix, suffix = '{"tool":"finish","final":"', '"}'
        capacity = MAX_ACTION_BYTES - len(prefix) - len(suffix)
        self.assertEqual(len(decode_action(prefix + "a" * capacity + suffix)[2]), capacity)
        for excess in ("a" * (capacity + 1), "字" * (capacity // 3 + 1)):
            with self.subTest(bytes=len(excess.encode("utf-8"))), self.assertRaises(ValueError):
                decode_action(prefix + excess + suffix)
        # 动作对象、arguments 和报告对象已经占三层，后续使用嵌套数组。
        def nested_action(arrays):
            return numeric_action("[" * arrays + "0" + "]" * arrays)
        decode_action(nested_action(MAX_JSON_DEPTH - 3))
        for levels in (MAX_JSON_DEPTH - 2, 2000):
            with self.subTest(levels=levels), self.assertRaises(ValueError):
                decode_action(nested_action(levels))

    def test_schema_exposes_exactly_the_supported_disjoint_tool_shapes(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        expected = {
            "read_document": {"path"}, "write_report": {"path", "content"},
            "publish_report": {"url", "payload"}, "admin_action": set(), "finish": {"final"},
        }
        found = []
        for branch in schema["anyOf"]:
            props = branch["properties"]
            names = props["tool"]["enum"]
            self.assertEqual(len(names), 1)
            name = names[0]
            found.append(name)
            self.assertEqual(branch["type"], "object")
            self.assertIs(branch["additionalProperties"], False)
            self.assertEqual(set(branch["required"]), set(props))
            if name == "finish":
                self.assertEqual(set(props), {"tool", "final"})
                self.assertEqual(props["final"]["type"], "string")
                continue
            self.assertEqual(set(props), {"tool", "arguments"})
            arguments = props["arguments"]
            self.assertEqual(arguments["type"], "object")
            self.assertIs(arguments["additionalProperties"], False)
            self.assertEqual(set(arguments["properties"]), expected[name])
            self.assertEqual(set(arguments["required"]), expected[name])
            for field, value_schema in arguments["properties"].items():
                if field in {"payload", "content"}:
                    by_type = {choice["type"]: choice for choice in value_schema["anyOf"]}
                    self.assertEqual(set(by_type), {"object", "string"})
                    self.assertIs(by_type["object"]["additionalProperties"], True)
                else:
                    self.assertEqual(value_schema["type"], "string")
        self.assertCountEqual(found, expected.keys())


if __name__ == "__main__":
    unittest.main()
