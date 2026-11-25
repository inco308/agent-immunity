"""观测采集的输入校验与结果整理；这些用例不需要 MCP SDK。"""
import json
from pathlib import Path
import tempfile
import unittest

from agent_immunity import probe


class CallListTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def load(self, payload):
        path = self.root / "calls.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return probe.load_calls(path)

    def test_valid_list_is_returned_unchanged(self):
        calls = [{"id": "a", "tool": "t", "arguments": {"x": 1}}]
        self.assertEqual(self.load({"version": 1, "calls": calls}), calls)

    def test_arguments_default_to_empty_object(self):
        self.assertEqual(self.load({"version": 1, "calls": [{"id": "a", "tool": "t"}]}),
                         [{"id": "a", "tool": "t"}])

    def test_invalid_lists_are_rejected(self):
        samples = [
            {}, {"version": 2, "calls": []}, {"version": 1},
            {"version": 1, "calls": []},
            {"version": 1, "calls": [{"tool": "t"}]},
            {"version": 1, "calls": [{"id": "a"}]},
            {"version": 1, "calls": [{"id": "", "tool": "t"}]},
            {"version": 1, "calls": [{"id": "a", "tool": "t"}, {"id": "a", "tool": "t"}]},
            {"version": 1, "calls": [{"id": "a", "tool": "t", "extra": 1}]},
            {"version": 1, "calls": [{"id": "a", "tool": "t", "arguments": []}]},
        ]
        for payload in samples:
            with self.subTest(payload=payload), self.assertRaises(probe.ProbeError):
                self.load(payload)

    def test_missing_file_is_a_probe_error(self):
        with self.assertRaises(probe.ProbeError):
            probe.load_calls(self.root / "absent.json")


class SummarizeTests(unittest.TestCase):
    def test_json_text_is_parsed_and_flattened(self):
        observed = probe.summarize(False, ['{"a": 1, "b": {"c": true}}'], None)
        self.assertEqual(observed["json"], {"a": 1, "b": {"c": True}})
        self.assertEqual(observed["shape"], {"a": "number", "b": "object", "b.c": "boolean"})

    def test_plain_text_has_single_text_leaf(self):
        observed = probe.summarize(False, ["hello"], None)
        self.assertIsNone(observed["json"])
        self.assertEqual(observed["shape"], {"text": "string"})

    def test_multiple_blocks_are_joined_and_flags_kept(self):
        observed = probe.summarize(True, ["a", "b"], {"k": 1})
        self.assertEqual(observed["text"], "a\nb")
        self.assertTrue(observed["is_error"])
        self.assertEqual(observed["structured"], {"k": 1})

    def test_arrays_and_null_are_flattened_with_indices(self):
        self.assertEqual(probe.flatten({"items": [None, "x"]}),
                         {"items": "array", "items.0": "null", "items.1": "string"})

    def test_long_text_is_truncated(self):
        observed = probe.summarize(False, ["x" * (probe.MAX_TEXT + 100)], None)
        self.assertEqual(len(observed["text"]), probe.MAX_TEXT)


if __name__ == "__main__":
    unittest.main()
