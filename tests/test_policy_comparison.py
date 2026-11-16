"""从命令行验证离线升级对比的方向、输出边界及错误优先级。"""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from agent_immunity.doctor import main
from tests.support import temporary_directory


PRIVATE_TOOL = "removed_private_tool_713"
PRIVATE_VALUE = "SYNTHETIC_PRIVATE_ARGUMENT_814"
PRIVATE_URL = "https://private-comparison.example.invalid"
PRIVATE_DIR = "private_docs_405"
SCOPE = "added_tools_capabilities_file_roots_and_network_origins"


def file_tool(*capabilities, roots=(".",)):
    return {"capabilities": list(capabilities), "parameters": {"path": "string"},
            "path_fields": ["path"], "roots": list(roots)}


def network_tool(*origins, capabilities=("network",)):
    return {"capabilities": list(capabilities), "parameters": {"url": "string"},
            "url_fields": ["url"], "origins": list(origins)}


class PolicyComparisonTests(unittest.TestCase):
    def setUp(self):
        fixture = temporary_directory()
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name)
        self.baseline = self.root / "installed" / "policy.json"
        self.candidate = self.root / "upgrade" / "policy.json"
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        for path in (self.baseline, self.candidate):
            path.parent.mkdir()

    def write_policy(self, path, tools, workspace="../workspace"):
        policy = {"version": 1, "workspace": workspace, "tools": tools}
        path.write_text(json.dumps(policy), encoding="utf-8")

    def invoke(self, *extra, compare=True, as_json=True):
        args = ["--policy", str(self.candidate)]
        if compare:
            args.extend(["--baseline", str(self.baseline)])
        if as_json:
            args.append("--json")
        stdout, stderr = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))
            for target in ("socket.socket", "socket.getaddrinfo", "subprocess.Popen"):
                stack.enter_context(patch(target, side_effect=AssertionError("策略对比必须离线运行")))
            code = main(args + list(extra))
        for private in (PRIVATE_TOOL, PRIVATE_URL, PRIVATE_VALUE, PRIVATE_DIR, self.root.name,
                        ".invalid", "192.0.2.17", "51029"):
            self.assertNotIn(private, stdout.getvalue() + stderr.getvalue())
        return code, json.loads(stdout.getvalue()) if as_json else stdout.getvalue()

    def test_only_candidate_additions_are_reported_in_sorted_order(self):
        new_name = "a-new\nline\x1b"
        self.write_policy(self.baseline, {
            PRIVATE_TOOL: {"capabilities": ["compute"]},
            "storage": file_tool("compute", "read"),
        })
        self.write_policy(self.candidate, {
            "storage": file_tool("write", "read"),
            new_name: {"capabilities": ["network", "compute"], "parameters": {"url": "string"},
                       "url_fields": ["url"], "origins": [PRIVATE_URL]},
        })
        inputs = {path: path.read_bytes() for path in (self.baseline, self.candidate)}
        code, report = self.invoke()
        self.assertEqual((code, report["status"]), (2, "review"))
        self.assertEqual(report["comparison"], {"scope": SCOPE, "status": "compared"})
        self.assertEqual(
            [(f["tool"], f["code"], f["capabilities"], f["severity"]) for f in report["findings"]],
            [(new_name, "POLICY_TOOL_ADDED", ["compute", "network"], "review"),
             ("storage", "POLICY_CAPABILITIES_ADDED", ["write"], "review")],
        )
        code, output = self.invoke(as_json=False)
        self.assertEqual(code, 2)
        self.assertIn(json.dumps(new_name), output)
        self.assertNotIn(new_name, output)
        for path, content in inputs.items():
            self.assertEqual(path.read_bytes(), content)

    def test_unchanged_reordered_reduced_or_out_of_scope_changes_pass(self):
        def execute_tool(value):
            return {"capabilities": ["execute"], "parameters": {"value": "string"},
                    "allowed_arguments": [{"value": value}]}

        self.write_policy(self.baseline, {
            PRIVATE_TOOL: {"capabilities": ["compute"]}, "ordered": file_tool("write", "read"),
            "unchanged": file_tool("read"), "reduce": file_tool("compute", "read"),
            "run": execute_tool("old"),
        })
        self.write_policy(self.candidate, {
            "ordered": file_tool("read", "write"), "unchanged": file_tool("read"),
            "reduce": file_tool("read"), "run": execute_tool(PRIVATE_VALUE),
        })
        code, report = self.invoke()
        self.assertEqual((code, report["status"], report["findings"]), (0, "pass", []))
        self.assertEqual(report["comparison"], {"scope": SCOPE, "status": "compared"})
        code, single = self.invoke(compare=False)
        self.assertEqual(code, 0)
        self.assertEqual(single, {"schema_version": 1, "scope": "policy", "status": "pass",
                                  "registered_tools": 4, "hidden_tools": None, "findings": []})

    def test_expansion_compares_directory_trees_for_each_retained_file_capability(self):
        child = PRIVATE_DIR + "/child"
        sibling = PRIVATE_DIR + "-archive"
        for name in (child, sibling):
            (self.workspace / name).mkdir(parents=True)
        for old, new, expanded in (
            ([child], [PRIVATE_DIR], True),
            ([PRIVATE_DIR], [child, sibling], True),
            ([child, sibling], [PRIVATE_DIR, "."], True),
            ([PRIVATE_DIR, sibling], [sibling, child], False),
            ([PRIVATE_DIR], [child, PRIVATE_DIR], False),
        ):
            with self.subTest(old=old, new=new):
                self.write_policy(self.baseline, {"docs": file_tool("compute", "read", "write", roots=old)})
                self.write_policy(self.candidate, {"docs": file_tool("write", "compute", "read", roots=new)})
                code, report = self.invoke()
                self.assertEqual((code, report["status"]), (2, "review") if expanded else (0, "pass"))
                self.assertEqual([(f["code"], f["tool"], f["capabilities"]) for f in report["findings"]],
                                 [("POLICY_FILE_ROOTS_EXPANDED", "docs", ["read", "write"])] if expanded else [])
                if expanded:
                    code, output = self.invoke(as_json=False)
                    self.assertEqual(code, 2)
                    self.assertIn("POLICY_FILE_ROOTS_EXPANDED", output)

    def test_directory_alias_and_its_target_cover_the_same_files(self):
        target = self.workspace / PRIVATE_DIR
        target.mkdir()
        alias = self.workspace / "local-alias"
        try:
            alias.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("当前宿主不允许创建符号链接")
        self.write_policy(self.baseline, {"docs": file_tool("read", roots=[target.name])})
        self.write_policy(self.candidate, {"docs": file_tool("read", roots=[alias.name])})
        code, report = self.invoke()
        self.assertEqual((code, report["status"], report["findings"]), (0, "pass", []))

    def test_identical_relative_roots_in_different_workspaces_require_review(self):
        for path in (self.baseline, self.candidate):
            (path.parent / PRIVATE_DIR).mkdir()
            self.write_policy(path, {"docs": file_tool("write")}, workspace=PRIVATE_DIR)
        catalog = self.root / "catalog.json"
        catalog.write_text('{"tools":[]}', encoding="utf-8")
        code, report = self.invoke("--catalog", str(catalog))
        self.assertEqual((code, report["status"]), (1, "error"))
        self.assertEqual([(f["code"], f["severity"], f.get("capabilities")) for f in report["findings"]],
                         [("POLICY_FILE_ROOTS_EXPANDED", "review", ["write"]), ("TOOL_MISSING", "error", None)])

    def test_new_file_capabilities_are_separate_from_changes_to_retained_roots(self):
        (self.workspace / PRIVATE_DIR).mkdir()
        self.write_policy(self.baseline, {
            "docs": file_tool("read", roots=[PRIVATE_DIR]), "worker": {"capabilities": ["compute"]},
        })
        self.write_policy(self.candidate, {
            "docs": file_tool("read", "write"), "worker": file_tool("compute", "read"),
            "new": file_tool("write"),
        })
        code, report = self.invoke()
        self.assertEqual((code, report["status"]), (2, "review"))
        self.assertCountEqual([(f["code"], f["tool"], f["capabilities"]) for f in report["findings"]], [
            ("POLICY_CAPABILITIES_ADDED", "docs", ["write"]), ("POLICY_FILE_ROOTS_EXPANDED", "docs", ["read"]),
            ("POLICY_CAPABILITIES_ADDED", "worker", ["read"]), ("POLICY_TOOL_ADDED", "new", ["write"]),
        ])

    def test_network_comparison_uses_runtime_origin_identity(self):
        ip = "https://192.0.2.17"
        host = "https://bücher.example.invalid"
        for old, new, expanded in (
            ([host], [host, ip, PRIVATE_URL], True),
            ([host], [ip], True),
            ([ip], ["http://192.0.2.17:443"], True),
            ([ip], [ip + ":51029"], True),
            ([host, ip], [host], False),
            ([host, ip], [ip, "https://XN--BCHER-KVA.EXAMPLE.INVALID:443/"], False),
        ):
            with self.subTest(old=old, new=new):
                self.write_policy(self.baseline, {"fetch": network_tool(*old)})
                self.write_policy(self.candidate, {"fetch": network_tool(*new)})
                code, report = self.invoke()
                self.assertEqual((code, report["status"]), (2, "review") if expanded else (0, "pass"))
                self.assertEqual([(f["code"], f["tool"], f["capabilities"], f["severity"]) for f in report["findings"]],
                                 [("POLICY_NETWORK_ORIGINS_EXPANDED", "fetch", ["network"], "review")] if expanded else [])
                if expanded:
                    code, output = self.invoke(as_json=False)
                    self.assertEqual(code, 2)
                    self.assertIn("POLICY_NETWORK_ORIGINS_EXPANDED", output)

    def test_only_retained_network_capability_gets_an_origin_finding(self):
        ip = "https://192.0.2.17:51029"
        self.write_policy(self.baseline, {
            "fetch": network_tool(PRIVATE_URL), "worker": {"capabilities": ["compute"]},
            "parse": network_tool(PRIVATE_URL, capabilities=("compute",)),
        })
        self.write_policy(self.candidate, {
            "fetch": network_tool(ip), "worker": network_tool(ip, capabilities=("compute", "network")),
            "new": network_tool(ip), "parse": network_tool(ip, capabilities=("compute",)),
        })
        catalog = self.root / "catalog.json"
        catalog.write_text('{"tools":[]}', encoding="utf-8")
        code, report = self.invoke("--catalog", str(catalog))
        self.assertEqual((code, report["status"]), (1, "error"))
        self.assertCountEqual([(f["code"], f["tool"], f["capabilities"]) for f in report["findings"]
                               if f["severity"] == "review"], [
            ("POLICY_NETWORK_ORIGINS_EXPANDED", "fetch", ["network"]),
            ("POLICY_CAPABILITIES_ADDED", "worker", ["network"]),
            ("POLICY_TOOL_ADDED", "new", ["network"]),
        ])
        self.assertIn("TOOL_MISSING", [f["code"] for f in report["findings"]])

    def test_unreadable_or_unsupported_policy_identifies_its_role_without_partial_diff(self):
        malformed = b'{"tools":'
        unsupported = json.dumps({"version": 2, PRIVATE_VALUE: True}).encode()
        for candidate, baseline, role, issue in (
            (None, malformed, "baseline", "POLICY_INVALID"),
            (None, unsupported, "baseline", "POLICY_VERSION_UNSUPPORTED"),
            (malformed, None, "candidate", "POLICY_INVALID"),
            (unsupported, malformed, "candidate", "POLICY_VERSION_UNSUPPORTED"),
        ):
            with self.subTest(role=role, issue=issue):
                self.write_policy(self.candidate, {"new": {"capabilities": ["compute"]}})
                self.write_policy(self.baseline, {})
                for path, data in ((self.candidate, candidate), (self.baseline, baseline)):
                    if data is not None:
                        path.write_bytes(data)
                code, report = self.invoke()
                self.assertEqual((code, report["status"]), (1, "error"))
                self.assertEqual(report["comparison"], {"scope": SCOPE, "status": "not_compared"})
                self.assertEqual([(f["code"], f["policy_role"], f["severity"]) for f in report["findings"]],
                                 [(issue, role, "error")])

    def test_invalid_baseline_preserves_catalog_findings_for_valid_candidate(self):
        self.write_policy(self.candidate, {"lookup": {"capabilities": ["compute"]}})
        self.baseline.write_text("{}", encoding="utf-8")
        catalog = self.root / "catalog.json"
        catalog.write_text('{"tools":[]}', encoding="utf-8")
        code, report = self.invoke("--catalog", str(catalog))
        self.assertEqual((code, report["status"]), (1, "error"))
        self.assertEqual(report["comparison"], {"scope": SCOPE, "status": "not_compared"})
        self.assertEqual({f["code"] for f in report["findings"]}, {"POLICY_INVALID", "TOOL_MISSING"})
        for finding in report["findings"]:
            self.assertEqual(finding["severity"], "error")
            if finding["code"] == "POLICY_INVALID":
                self.assertEqual(finding["policy_role"], "baseline")
            else:
                self.assertEqual(finding["tool"], "lookup")

    def test_candidate_static_and_catalog_errors_take_priority_over_additions(self):
        self.write_policy(self.baseline, {})
        self.write_policy(self.candidate, {"run": {
            "capabilities": ["execute"], "parameters": {"count": "integer"},
            "allowed_arguments": [{"count": PRIVATE_VALUE}],
        }})
        catalog = self.root / "catalog.json"
        catalog.write_text('{"tools":[]}', encoding="utf-8")
        code, report = self.invoke("--catalog", str(catalog))
        self.assertEqual((code, report["status"]), (1, "error"))
        self.assertEqual(report["comparison"], {"scope": SCOPE, "status": "compared"})
        self.assertEqual({(f["code"], f["severity"]) for f in report["findings"]},
                         {("EXEC_ARGUMENTS_INVALID", "error"), ("TOOL_MISSING", "error"),
                          ("POLICY_TOOL_ADDED", "review")})
