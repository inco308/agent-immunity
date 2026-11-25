"""调用观测的比较与业务断言回归。

夹具里的观测是真实采集的（mcp-server-time 2025.8.4 / 2025.9.25 / 2026.11.18），
因此这里固定的不只是代码行为，还有"目录完全一致但输出变了"这个具体案例。
"""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from agent_immunity import drill as upgrade_drill

FIXTURES = Path(__file__).parent / "fixtures" / "upgrade"
POLICY = FIXTURES / "policy.json"
EXPECT = FIXTURES / "expectations.json"


def fixture(name):
    return FIXTURES / name


def observation(call_id, shape=None, json_value=None, text="", is_error=False, structured=None):
    return {"id": call_id, "tool": "t", "arguments": {},
            "is_error": is_error, "text": text, "json": json_value,
            "structured": structured, "shape": shape or {}}


class ObservationChangeTests(unittest.TestCase):
    def changes(self, before, after, ignore=()):
        return upgrade_drill.observation_changes(
            {entry["id"]: entry for entry in before},
            {entry["id"]: entry for entry in after}, ignore)

    def kinds(self, changes):
        return sorted((change["kind"], change.get("path")) for change in changes)

    def test_field_added_and_removed_are_reported(self):
        before = [observation("c", {"a": "string"})]
        after = [observation("c", {"b": "string"})]
        self.assertEqual(self.kinds(self.changes(before, after)),
                         [("FIELD_ADDED", "b"), ("FIELD_REMOVED", "a")])

    def test_nested_paths_use_dots_and_indices(self):
        before = [observation("c", {"items": "array", "items.0.name": "string"})]
        after = [observation("c", {"items": "array", "items.0.name": "string", "items.0.id": "number"})]
        self.assertEqual(self.kinds(self.changes(before, after)), [("FIELD_ADDED", "items.0.id")])

    def test_type_change_is_distinguished_from_value_change(self):
        before = [observation("c", {"flag": "boolean"}, {"flag": True})]
        after = [observation("c", {"flag": "string"}, {"flag": "true"})]
        self.assertEqual(self.kinds(self.changes(before, after)), [("OBSERVATION_TYPE_CHANGED", "flag")])
        before = [observation("c", {"n": "number"}, {"n": 1})]
        after = [observation("c", {"n": "number"}, {"n": 2})]
        self.assertEqual(self.kinds(self.changes(before, after)), [("VALUE_CHANGED", "n")])
        self.assertEqual(self.changes(before, after)[0]["before"], "1")

    def test_text_and_json_are_not_compared_as_values(self):
        before = [observation("c", {"a": "string"}, {"a": "x"})]
        after = [observation("c", {"text": "string"}, None, text="x")]
        # JSON 与纯文本的差异表现为字段增删，不额外引入格式码。
        self.assertEqual(self.kinds(self.changes(before, after)),
                         [("FIELD_ADDED", "text"), ("FIELD_REMOVED", "a")])

    def test_error_and_structured_state_changes_are_reported(self):
        before = [observation("c", {"a": "string"}, {"a": "x"})]
        after = [observation("c", {"a": "string"}, {"a": "x"}, is_error=True,
                             structured={"a": "x"})]
        self.assertEqual(self.kinds(self.changes(before, after)),
                         [("ERROR_CHANGED", None), ("STRUCTURED_ADDED", None)])

    def test_missing_call_is_reported(self):
        self.assertEqual(self.kinds(self.changes([observation("a")], [observation("b")])),
                         [("CALL_MISSING", None), ("CALL_MISSING", None)])

    def test_ignore_matches_exact_paths_and_prefixes(self):
        before = [observation("c", {"report": "object", "report.date": "string", "report.id": "number"})]
        after = [observation("c", {"report": "object", "report.id": "number"})]
        self.assertEqual(self.kinds(self.changes(before, after)), [("FIELD_REMOVED", "report.date")])
        self.assertEqual(self.changes(before, after, ["report"]), [])
        self.assertEqual(self.changes(before, after, ["report.date"]), [])
        # 只忽略精确路径，兄弟字段仍要报出来
        other = [observation("c", {"report": "object", "report.id": "number", "report.time": "string"})]
        self.assertEqual(self.kinds(self.changes(before, other, ["report.date"])),
                         [("FIELD_ADDED", "report.time")])


class ObservationLoadingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name, payload):
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_observations_are_indexed_by_call_id(self):
        path = self.write("o.json", {"schema_version": 1, "calls": [observation("a"), observation("b")]})
        self.assertEqual(sorted(upgrade_drill.load_observations(path)), ["a", "b"])

    def test_invalid_observation_files_are_rejected(self):
        for payload in ({}, {"schema_version": 2, "calls": []}, {"schema_version": 1, "calls": [{}]},
                        {"schema_version": 1}):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    upgrade_drill.load_observations(self.write("bad.json", payload))


class ExpectationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.calls = {"c": observation("c", {"time_difference": "string"}, {"time_difference": "+9.0h"},
                                       text='{"time_difference": "+9.0h"}')}

    def check(self, expect):
        return upgrade_drill.check_expectations(self.calls, expect)

    def test_equals_and_contains_pass(self):
        self.assertEqual(self.check([
            {"id": "c", "path": "time_difference", "equals": "+9.0h"},
            {"id": "c", "contains": "+9.0h"},
        ]), [])

    def test_mismatch_reports_expected_and_actual(self):
        failures = self.check([{"id": "c", "path": "time_difference", "equals": "+8.0h"}])
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["expected"], "+8.0h")
        self.assertEqual(failures[0]["actual"], "+9.0h")

    def test_missing_call_or_path_fails(self):
        self.assertIn("观测里没有这个调用", self.check([{"id": "nope", "path": "x", "equals": 1}])[0]["reason"])
        self.assertIn("返回里没有该路径", self.check([{"id": "c", "path": "ghost", "equals": 1}])[0]["reason"])
        self.assertIn("不含期望片段", self.check([{"id": "c", "contains": "nope"}])[0]["reason"])

    def test_expectation_file_validation(self):
        good = {"version": 1, "ignore": ["a.b"], "expect": [{"id": "c", "path": "p", "equals": 1}]}
        path = self.root / "good.json"
        path.write_text(json.dumps(good), encoding="utf-8")
        self.assertEqual(upgrade_drill.load_expectations(path)["ignore"], ["a.b"])
        for bad in ({"version": 2}, {"version": 1, "extra": 1},
                    {"version": 1, "ignore": [1]},
                    {"version": 1, "expect": [{}]},
                    {"version": 1, "expect": [{"id": "c"}]},
                    {"version": 1, "expect": [{"id": "c", "path": "p"}]},
                    {"version": 1, "expect": [{"id": "c", "contains": 1}]}):
            with self.subTest(bad=bad):
                path = self.root / "bad.json"
                path.write_text(json.dumps(bad), encoding="utf-8")
                with self.assertRaises(ValueError):
                    upgrade_drill.load_expectations(path)


class RealUpgradePairTests(unittest.TestCase):
    """真实版本对：目录一致但输出变了。"""

    def run_pair(self, old, new, **options):
        return upgrade_drill.run(
            POLICY, fixture(f"catalog-{old}.json"), fixture(f"catalog-{new}.json"),
            fixture(f"observations-{old}.json"), fixture(f"observations-{new}.json"),
            upgrade_drill.load_expectations(EXPECT) if options.get("expect") else None)

    def test_catalog_is_identical_but_observation_differs(self):
        report = self.run_pair("2025.8.4", "2025.9.25")
        self.assertEqual(report["baseline"]["status"], "pass")
        self.assertEqual(report["upgraded"]["status"], "pass")
        # 目录层面没有任何变化
        self.assertEqual([c for c in report["changes"] if "tool" in c], [])
        # 观测层面报出新增字段，这正是目录比较看不到的部分
        paths = sorted(change["path"] for change in report["changes"] if change["kind"] == "FIELD_ADDED")
        self.assertEqual(paths, ["source.day_of_week", "target.day_of_week"])
        self.assertEqual(report["status"], "review")

    def test_expectations_hold_across_all_three_versions(self):
        expectations = upgrade_drill.load_expectations(EXPECT)
        for old, new in (("2025.8.4", "2025.9.25"), ("2025.9.25", "2026.11.18")):
            with self.subTest(pair=f"{old}->{new}"):
                report = upgrade_drill.run(
                    POLICY, fixture(f"catalog-{old}.json"), fixture(f"catalog-{new}.json"),
                    fixture(f"observations-{old}.json"), fixture(f"observations-{new}.json"),
                    expectations)
                self.assertEqual(report["observations"]["expectation_failures"], [])
                self.assertNotEqual(report["status"], "error")

    def test_latest_pair_reports_catalog_and_observation_changes(self):
        report = self.run_pair("2025.9.25", "2026.11.18")
        kinds = sorted({change["kind"] for change in report["changes"]})
        for expected in ("TOOL_ADDED", "REQUIRED_LOOSENED", "STRUCTURED_ADDED", "FIELD_ADDED"):
            self.assertIn(expected, kinds)

    def test_failed_expectation_turns_status_into_error(self):
        report = upgrade_drill.run(
            POLICY, fixture("catalog-2025.8.4.json"), fixture("catalog-2025.9.25.json"),
            fixture("observations-2025.8.4.json"), fixture("observations-2025.9.25.json"),
            {"ignore": [], "expect": [{"id": "convert-tokyo", "path": "time_difference", "equals": "+8.0h"}]})
        self.assertEqual(report["status"], "error")
        self.assertEqual(upgrade_drill.EXIT_CODES["error"], 1)

    def test_not_measured_hides_output_when_observations_given(self):
        with_obs = self.run_pair("2025.8.4", "2025.9.25")
        self.assertNotIn("输出结构变化", with_obs["not_measured"])
        without = upgrade_drill.run(POLICY, fixture("catalog-2025.8.4.json"),
                                    fixture("catalog-2025.9.25.json"))
        self.assertIn("输出结构变化", without["not_measured"])


class CliObservationTests(unittest.TestCase):
    def main(self, argv):
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            return upgrade_drill.main(argv)

    def base(self):
        return ["--policy", str(POLICY),
                "--old-catalog", str(fixture("catalog-2025.8.4.json")),
                "--new-catalog", str(fixture("catalog-2025.9.25.json"))]

    def test_cli_reports_review_and_prints_observation_summary(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = upgrade_drill.main(self.base() + [
                "--old-observations", str(fixture("observations-2025.8.4.json")),
                "--new-observations", str(fixture("observations-2025.9.25.json")),
                "--expect", str(EXPECT)])
        self.assertEqual(code, 2)
        self.assertIn("断言失败 0 条", stdout.getvalue())

    def test_observation_flags_must_be_paired(self):
        with self.assertRaises(SystemExit):
            self.main(self.base() + ["--old-observations",
                                     str(fixture("observations-2025.8.4.json"))])

    def test_expect_requires_observations(self):
        with self.assertRaises(SystemExit):
            self.main(self.base() + ["--expect", str(EXPECT)])

    def test_invalid_expectation_file_is_rejected(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "bad.json"
        path.write_text(json.dumps({"version": 1, "extra": 1}), encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.main(self.base() + [
                "--old-observations", str(fixture("observations-2025.8.4.json")),
                "--new-observations", str(fixture("observations-2025.9.25.json")),
                "--expect", str(path)])


if __name__ == "__main__":
    unittest.main()
