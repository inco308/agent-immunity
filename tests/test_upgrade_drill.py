"""升级漂移演练的回归。

`catalog-2025.9.25.json` 与 `catalog-2026.11.18.json` 是从真实 PyPI 发行版采集的
tools/list 快照（mcp-server-time 2025.9.25 与 2026.11.18，mcp SDK 1.30.0 / 2.3.0），
只保留 name 与 inputSchema。带 `synthetic` 的目录是为了覆盖 doctor 报错分支
而人工构造的，不代表任何真实上游版本。

这些用例的价值不只是"能不能报错"，还固定了一个已知边界：
doctor 单独运行时对这对真实版本都判 pass，只有当上游变严时才会自己报错。
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


def fixture(name):
    return FIXTURES / name


class CatalogDriftTests(unittest.TestCase):
    def drift(self, before, after):
        return upgrade_drill.catalog_drift(
            upgrade_drill.doctor.read_catalog(fixture(before)),
            upgrade_drill.doctor.read_catalog(fixture(after)))

    def test_real_version_pair_reports_added_tool_and_loosened_required(self):
        changes = self.drift("catalog-2025.9.25.json", "catalog-2026.11.18.json")
        kinds = sorted((change["kind"], change["tool"], change.get("field")) for change in changes)
        self.assertEqual(kinds, [
            ("REQUIRED_LOOSENED", "convert_time", "source_timezone"),
            ("REQUIRED_LOOSENED", "convert_time", "target_timezone"),
            ("REQUIRED_LOOSENED", "get_current_time", "timezone"),
            ("TOOL_ADDED", "get_time_ago", None),
        ])
        for change in changes:
            self.assertIn("message", change)

    def test_identical_catalog_has_no_drift(self):
        self.assertEqual(self.drift("catalog-2025.9.25.json", "catalog-2025.9.25.json"), [])

    def test_tool_removal_and_strictened_required_are_reported(self):
        removed = self.drift("catalog-2025.9.25.json", "catalog-synthetic-tool-removed.json")
        self.assertEqual([(c["kind"], c["tool"]) for c in removed], [("TOOL_REMOVED", "convert_time")])
        strictened = self.drift("catalog-2025.9.25.json", "catalog-synthetic-strictened.json")
        self.assertIn(("REQUIRED_STRICTENED", "convert_time", "locale"),
                      [(c["kind"], c["tool"], c.get("field")) for c in strictened])


class DrillReportTests(unittest.TestCase):
    def run_drill(self, before, after):
        return upgrade_drill.run(POLICY, fixture(before), fixture(after))

    def test_real_drift_is_review_even_though_doctor_passes_both(self):
        report = self.run_drill("catalog-2025.9.25.json", "catalog-2026.11.18.json")
        # 这是本工具存在的理由：doctor 单独运行时两次都是 pass。
        self.assertEqual(report["baseline"]["status"], "pass")
        self.assertEqual(report["upgraded"]["status"], "pass")
        self.assertEqual(report["status"], "review")
        self.assertEqual(upgrade_drill.EXIT_CODES[report["status"]], 2)
        self.assertEqual(report["upgraded"]["hidden_tools"], 2)
        self.assertEqual(report["baseline"]["hidden_tools"], 1)

    def test_same_catalog_passes(self):
        report = self.run_drill("catalog-2025.9.25.json", "catalog-2025.9.25.json")
        self.assertEqual(report["status"], "pass")
        self.assertEqual(upgrade_drill.EXIT_CODES[report["status"]], 0)

    def test_upstream_strictening_is_an_error(self):
        report = self.run_drill("catalog-2025.9.25.json", "catalog-synthetic-strictened.json")
        self.assertEqual(report["status"], "error")
        self.assertEqual(upgrade_drill.EXIT_CODES[report["status"]], 1)
        self.assertIn("REQUIRED_MISMATCH",
                      [finding["code"] for finding in report["upgraded"]["findings"]])

    def test_upstream_tool_removal_is_an_error(self):
        report = self.run_drill("catalog-2025.9.25.json", "catalog-synthetic-tool-removed.json")
        self.assertEqual(report["status"], "error")
        self.assertIn("TOOL_MISSING",
                      [finding["code"] for finding in report["upgraded"]["findings"]])

    def test_report_declares_what_it_does_not_measure(self):
        report = self.run_drill("catalog-2025.9.25.json", "catalog-2026.11.18.json")
        self.assertEqual(report["scope"], "UPGRADE_DRIFT")
        self.assertIn("输出结构变化", report["not_measured"])
        self.assertIn("副作用是否发生", report["not_measured"])


class CliTests(unittest.TestCase):
    def main(self, argv):
        # argparse 的用法提示与报告输出都走标准流，测试里保持输出干净。
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            return upgrade_drill.main(argv)

    def test_cli_exit_code_matches_status(self):
        self.assertEqual(self.main([
            "--policy", str(POLICY),
            "--old-catalog", str(fixture("catalog-2025.9.25.json")),
            "--new-catalog", str(fixture("catalog-2026.11.18.json")),
            "--json",
        ]), 2)

    def test_cli_writes_report_file(self):
        # 3.10 没有 TestCase.enterContext，用 addCleanup 收尾。
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        target = Path(temporary.name) / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = upgrade_drill.main([
                "--policy", str(POLICY),
                "--old-catalog", str(fixture("catalog-2025.9.25.json")),
                "--new-catalog", str(fixture("catalog-2026.11.18.json")),
                "--output", str(target),
            ])
        self.assertEqual(code, 2)
        report = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(report["scope"], "UPGRADE_DRIFT")
        self.assertEqual(len(report["changes"]), 4)

    def test_catalogs_are_required(self):
        with self.assertRaises(SystemExit):
            self.main(["--policy", str(POLICY),
                       "--old-catalog", str(fixture("catalog-2025.9.25.json"))])


if __name__ == "__main__":
    unittest.main()
