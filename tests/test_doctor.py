"""通过命令行检验离线策略体检、诊断分级及报告脱敏。"""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from agent_immunity.doctor import main
from tests.support import temporary_directory


PRIVATE_TEXT = "SYNTHETIC_DOCTOR_DESCRIPTION_831"
PRIVATE_VALUE = "SYNTHETIC_DOCTOR_ARGUMENT_917"
PRIVATE_URL = "https://doctor-value.example.invalid"
PRIVATE_LIMIT = 192731


def catalog_entry(properties, required=(), *, name="summarize", accepts_extra=False):
    return {
        "name": name,
        "description": PRIVATE_TEXT,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": list(required),
            "additionalProperties": accepts_extra,
        },
    }


class DoctorCliTests(unittest.TestCase):
    def setUp(self):
        fixture = temporary_directory()
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.policy_file = self.root / "policy.json"
        self.catalog_file = self.root / "catalog.json"
        self.policy = {
            "version": 1, "workspace": str(self.workspace),
            "tools": {"summarize": {"capabilities": ["compute"], "parameters": {"count": "integer"}}},
        }

    def invoke(self, *, catalog=None, policy_path=None, forbid_external_io=False):
        policy_path = policy_path or self.policy_file
        policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
        args = ["--policy", str(policy_path), "--json"]
        if catalog is not None:
            self.catalog_file.write_text(json.dumps(catalog), encoding="utf-8")
            args.extend(["--catalog", str(self.catalog_file)])
        return self.run_command(args, forbid_external_io)

    def run_command(self, args, forbid_external_io=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            if forbid_external_io:
                with patch("socket.socket", side_effect=AssertionError("离线体检不应建立连接")), \
                        patch("socket.getaddrinfo", side_effect=AssertionError("离线体检不应查询 DNS")), \
                        patch("subprocess.Popen", side_effect=AssertionError("离线体检不应启动上游")):
                    exit_code = main(args)
            else:
                exit_code = main(args)
        output = stdout.getvalue()
        for value in (PRIVATE_TEXT, PRIVATE_VALUE, PRIVATE_URL, str(PRIVATE_LIMIT)):
            self.assertNotIn(value, output + stderr.getvalue())
        report = json.loads(output)
        self.assertIs(type(report["schema_version"]), int)
        self.assertEqual(report["schema_version"], 1)
        self.assertIsInstance(report["findings"], list)
        for finding in report["findings"]:
            self.assertIsInstance(finding, dict)
            self.assertIsInstance(finding["code"], str)
            self.assertIsInstance(finding["severity"], str)
            self.assertTrue(finding["code"] and finding["severity"])
        return exit_code, report

    def assert_outcome(self, response, *, status, scope="policy_and_catalog", codes=()):
        exit_code, report = response
        self.assertEqual(report["status"], status, report["findings"])
        self.assertEqual(exit_code, {"pass": 0, "error": 1, "review": 2}[status])
        self.assertEqual(report["scope"], scope)
        found = {item["code"] for item in report["findings"]}
        self.assertTrue(set(codes) <= found, f"需要 {codes}，得到 {found}")
        return report

    def test_policy_only_offline_checks_neither_contact_nor_execute_tools(self):
        self.policy["tools"] = {
            "send": {"capabilities": ["network"], "parameters": {"url": "string"},
                     "url_fields": ["url"], "origins": [PRIVATE_URL]},
            "run": {"capabilities": ["execute"], "parameters": {"value": "string"},
                    "allowed_arguments": [{"value": PRIVATE_VALUE}]},
        }
        self.policy["max_bytes"] = PRIVATE_LIMIT
        self.assert_outcome(self.invoke(forbid_external_io=True), status="pass", scope="policy")
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_compatible_catalog_counts_and_hides_unregistered_tools(self):
        hidden_name = "unregistered_private_tool_924"
        catalog = {"tools": [
            catalog_entry({"count": {"type": "number"}, "label": {"type": "string"}}, ["count"]),
            catalog_entry({}, name=hidden_name),
        ]}
        report = self.assert_outcome(self.invoke(catalog=catalog, forbid_external_io=True), status="pass")
        self.assertIs(type(report["hidden_tools"]), int)
        self.assertEqual(report["hidden_tools"], 1)
        self.assertNotIn(hidden_name, json.dumps(report))

    def test_catalog_without_policy_tool_is_an_error(self):
        self.assert_outcome(self.invoke(catalog={"tools": []}), status="error", codes=["TOOL_MISSING"])

    def test_required_upstream_field_must_be_guaranteed_by_local_calls(self):
        entry = catalog_entry({"count": {"type": "integer"}, "label": {"type": "string"}}, ["count", "label"])
        for local_has_optional_label in (False, True):
            with self.subTest(local_has_optional_label=local_has_optional_label):
                if local_has_optional_label:
                    tool = self.policy["tools"]["summarize"]
                    tool["parameters"]["label"] = "string"
                    tool["required"] = ["count"]
                self.assert_outcome(self.invoke(catalog={"tools": [entry]}), status="error",
                                    codes=["REQUIRED_MISMATCH"])

    def test_local_optional_field_cannot_target_closed_upstream_object(self):
        tool = self.policy["tools"]["summarize"]
        tool["parameters"]["label"] = "string"
        tool["required"] = ["count"]
        entry = catalog_entry({"count": {"type": "integer"}}, ["count"])
        self.assert_outcome(self.invoke(catalog={"tools": [entry]}), status="error", codes=["FIELD_NOT_ACCEPTED"])
        entry["inputSchema"]["additionalProperties"] = True
        self.assert_outcome(self.invoke(catalog={"tools": [entry]}), status="pass")

    def test_local_number_can_produce_values_upstream_integer_rejects(self):
        self.policy["tools"]["summarize"]["parameters"]["count"] = "number"
        entry = catalog_entry({"count": {"type": "integer"}}, ["count"])
        self.assert_outcome(self.invoke(catalog={"tools": [entry]}), status="error", codes=["TYPE_MISMATCH"])

    def test_enum_numeric_bounds_and_nested_constraints_need_review(self):
        constraints = (
            ("string", {"type": "string", "enum": [PRIVATE_VALUE]}),
            ("integer", {"type": "integer", "maximum": PRIVATE_LIMIT}),
            ("object", {"type": "object", "required": ["value"],
                        "properties": {"value": {"type": "string", "pattern": PRIVATE_VALUE}}}),
            ("array", {"type": "array", "items": {"type": "string", "enum": [PRIVATE_VALUE]}}),
        )
        for local_type, upstream in constraints:
            with self.subTest(local_type=local_type):
                self.policy["tools"]["summarize"]["parameters"]["count"] = local_type
                entry = catalog_entry({"count": upstream}, ["count"])
                self.assert_outcome(self.invoke(catalog={"tools": [entry]}), status="review", codes=["SCHEMA_REVIEW"])

    def test_proven_incompatibility_takes_precedence_over_catalog_review(self):
        self.policy["tools"]["missing"] = {"capabilities": ["compute"], "parameters": {}}
        entry = catalog_entry({"count": {"type": "integer", "maximum": PRIVATE_LIMIT}}, ["count"])
        self.assert_outcome(self.invoke(catalog={"tools": [entry]}), status="error", codes=["TOOL_MISSING"])

    def test_complex_siblings_preserve_proven_conflicts(self):
        self.policy["tools"]["summarize"]["parameters"]["count"] = "number"
        entry = catalog_entry({"count": {"type": "integer", "enum": [1]}}, ["also_required"])
        entry["inputSchema"]["allOf"] = [{"minProperties": 1}]
        self.assert_outcome(self.invoke(catalog={"tools": [entry]}), status="error",
                            codes=["REQUIRED_MISMATCH", "TYPE_MISMATCH", "SCHEMA_REVIEW"])
        entry = catalog_entry({}, accepts_extra=False)
        entry["inputSchema"]["patternProperties"] = {"^count$": {"type": "number"}}
        self.assert_outcome(self.invoke(catalog={"tools": [entry]}), status="review", codes=["SCHEMA_REVIEW"])

    def test_writable_policy_detected_only_within_the_actual_write_root(self):
        reports = self.workspace / "reports"
        sibling = self.workspace / "reports-archive"
        reports.mkdir()
        sibling.mkdir()
        self.policy["tools"] = {
            "write": {"capabilities": ["write"], "parameters": {"path": "string"},
                      "path_fields": ["path"], "roots": ["reports"]},
        }
        self.assert_outcome(self.invoke(policy_path=reports / "policy.json"), status="error",
                            scope="policy", codes=["POLICY_WRITABLE"])
        self.assert_outcome(self.invoke(policy_path=sibling / "policy.json"), status="pass", scope="policy")

    def test_invalid_execute_allowlist_entry_is_rejected_without_printing_its_value(self):
        self.policy["tools"] = {"run": {"capabilities": ["execute"], "parameters": {"count": "integer"},
                                        "allowed_arguments": [{"count": 1}, {"count": PRIVATE_VALUE}]}}
        self.assert_outcome(self.invoke(), status="error", scope="policy", codes=["EXEC_ARGUMENTS_INVALID"])

    def test_duplicate_malformed_and_unconsumed_catalogs_are_errors(self):
        entry = catalog_entry({"count": {"type": "integer"}}, ["count"])
        malformed = (
            ("wrong_tools_type", {"tools": {}}),
            ("missing_name", {"tools": [{"inputSchema": {}}]}),
            ("invalid_schema_type", {"tools": [{"name": "summarize", "inputSchema": PRIVATE_VALUE}]}),
            ("duplicate", {"tools": [entry, entry]}),
            ("partial_page", {"tools": [entry], "nextCursor": PRIVATE_VALUE}),
        )
        for label, catalog in malformed:
            with self.subTest(case=label):
                self.assert_outcome(self.invoke(catalog=catalog), status="error", codes=["CATALOG_INVALID"])

    def test_unreadable_or_invalid_policy_produces_json_error(self):
        for label, data in (("missing", None), ("broken_json", "{"),
                            ("bad_version", json.dumps({**self.policy, "version": PRIVATE_VALUE}))):
            with self.subTest(case=label):
                path = self.root / f"{label}.json"
                if data is not None:
                    path.write_text(data, encoding="utf-8")
                self.assert_outcome(self.run_command(["--policy", str(path), "--json"]), status="error",
                                    scope="policy", codes=["POLICY_INVALID"])

    def test_unsupported_version_is_actionable_and_private_in_both_cli_formats(self):
        path = self.root / (PRIVATE_TEXT + ".json")
        data = {"version": PRIVATE_LIMIT, "workspace": str(self.root / PRIVATE_VALUE), PRIVATE_TEXT: PRIVATE_URL}
        original = json.dumps(data).encode()
        path.write_bytes(original)
        args = ["--policy", str(path), "--catalog", str(self.catalog_file)]
        with patch("agent_immunity.doctor.read_catalog", side_effect=AssertionError("无效策略不应触发目录读取")):
            report = self.assert_outcome(self.run_command([*args, "--json"], forbid_external_io=True), status="error")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(main(args), 1)
        finding, = report["findings"]
        self.assertEqual((finding["code"], finding["severity"], finding.get("field")),
                         ("POLICY_VERSION_UNSUPPORTED", "error", "version"))
        self.assertEqual(report["registered_tools"], 0)
        self.assertIsNone(report["hidden_tools"])
        self.assertIn("version=1", finding["message"])
        self.assertIn("恢复", finding["message"])
        self.assertIn("网关", finding["message"])
        self.assertIn(finding["code"], out.getvalue())
        self.assertIn(finding["message"], out.getvalue())
        for marker in (PRIVATE_TEXT, PRIVATE_VALUE, PRIVATE_URL, str(PRIVATE_LIMIT)):
            self.assertNotIn(marker, out.getvalue() + err.getvalue())
        self.assertEqual(path.read_bytes(), original)

    def test_malformed_policy_and_non_integer_versions_remain_generic_errors(self):
        documents = [b'{"version":2', b'{"version":1,"version":2}', b'{"version":2,"version":1}',
                     b'{"version":2,"future":{"x":1,"x":2}}', b'{"version":2,"x":NaN}',
                     b'{"version":2,"x":"\xff"}', b'[]']
        documents.extend(json.dumps({**self.policy, "version": value}).encode()
                         for value in (True, False, 1.0, 2.0, "2", None))
        documents.append(json.dumps({k: v for k, v in self.policy.items() if k != "version"}).encode())
        documents.append(json.dumps({**self.policy, PRIVATE_TEXT: PRIVATE_VALUE}).encode())
        with patch("agent_immunity.doctor.read_catalog", side_effect=AssertionError("无效策略不应触发目录读取")):
            for data in documents:
                with self.subTest(document=data):
                    self.policy_file.write_bytes(data)
                    report = self.assert_outcome(self.run_command(["--policy", str(self.policy_file), "--catalog",
                                                                  str(self.catalog_file), "--json"]), status="error")
                    self.assertEqual([f["code"] for f in report["findings"]], ["POLICY_INVALID"])

    def test_restoring_accepted_policy_rechecks_catalog(self):
        catalog = {"tools": [catalog_entry({"count": {"type": "integer"}}, ["count"])]}
        self.assert_outcome(self.invoke(catalog=catalog), status="pass")
        previous = self.policy_file.read_bytes()
        args = ["--policy", str(self.policy_file), "--catalog", str(self.catalog_file), "--json"]
        self.policy_file.write_text(json.dumps({**self.policy, "version": 2}), encoding="utf-8")
        self.assert_outcome(self.run_command(args), status="error", codes=["POLICY_VERSION_UNSUPPORTED"])
        self.policy_file.write_bytes(previous)
        self.assert_outcome(self.run_command(args), status="pass")
        catalog["tools"][0]["inputSchema"]["properties"]["count"] = {"type": "string"}
        self.catalog_file.write_text(json.dumps(catalog), encoding="utf-8")
        self.assert_outcome(self.run_command(args), status="error", codes=["TYPE_MISMATCH"])


if __name__ == "__main__":
    unittest.main()
