"""策略加载的错误契约与可诊断性回归。

两个目标：
1. `Policy.load` 对任何失败都只抛 `PolicyError`，调用方不需要额外捕获 OSError/ValueError。
2. 错误信息要说清**哪一处**配置有问题（字段名、工具名、状态名），
   但不能回显参数实值——`allowed_arguments` 里可能放的是完整命令行。
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from agent_immunity import Policy, PolicyError
from agent_immunity import doctor
from agent_immunity import mcp_stdio
from tests.support import temporary_directory

BASE_POLICY = {
    "version": 1,
    "workspace": ".",
    "tools": {"convert_time": {"capabilities": ["compute"], "parameters": {"time": "string"}}},
}


def policy_dict(**overrides):
    data = json.loads(json.dumps(BASE_POLICY))
    data.update(overrides)
    return data


class LoadContractTests(unittest.TestCase):
    """文件层面的失败也必须收敛成 PolicyError。"""

    def setUp(self):
        self.directory = temporary_directory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def load_text(self, text, name="policy.json"):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return Policy.load(path)

    def test_missing_file_raises_policy_error(self):
        with self.assertRaises(PolicyError) as caught:
            Policy.load(self.root / "absent.json")
        self.assertIn("无法读取", str(caught.exception))

    def test_invalid_json_raises_policy_error_not_value_error(self):
        with self.assertRaises(PolicyError) as caught:
            self.load_text("{not json")
        self.assertIn("JSON", str(caught.exception))

    def test_non_object_json_raises_policy_error(self):
        with self.assertRaises(PolicyError) as caught:
            self.load_text("[1, 2, 3]")
        self.assertIn("JSON 对象", str(caught.exception))

    def test_missing_workspace_directory_raises_policy_error_not_oserror(self):
        with self.assertRaises(PolicyError) as caught:
            self.load_text(json.dumps(policy_dict(workspace="no-such-dir")))
        message = str(caught.exception)
        self.assertIn("workspace 目录不存在", message)
        self.assertNotIn("no-such-dir", message)

    def test_oversized_file_raises_policy_error(self):
        with self.assertRaises(PolicyError) as caught:
            self.load_text(" " * (1048576 + 1))
        self.assertIn("过大", str(caught.exception))


class MessageSpecificityTests(unittest.TestCase):
    """每种配置错误都要点出具体位置。"""

    def setUp(self):
        self.directory = temporary_directory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def reason(self, data):
        with self.assertRaises(PolicyError) as caught:
            Policy.from_dict(data, self.root)
        return str(caught.exception)

    def assert_reason(self, data, *expected):
        message = self.reason(data)
        for fragment in expected:
            self.assertIn(fragment, message)
        return message

    def test_unknown_top_level_field_is_named(self):
        self.assert_reason(policy_dict(extra_field=1), "不支持的顶层字段", "extra_field")

    def test_unsupported_version_names_field_without_echoing_value(self):
        message = self.assert_reason(policy_dict(version=2), "version=1")
        self.assertNotIn("当前为", message)

    def test_missing_workspace_is_named(self):
        data = policy_dict()
        data.pop("workspace")
        self.assert_reason(data, "workspace")

    def test_unknown_tool_field_is_named_with_tool(self):
        data = policy_dict()
        data["tools"]["convert_time"]["typo_field"] = 1
        self.assert_reason(data, "convert_time", "typo_field")

    def test_missing_capabilities_names_tool(self):
        self.assert_reason(policy_dict(tools={"read_file": {"parameters": {}}, "x": {}}), "read_file")

    def test_unsupported_capability_is_named(self):
        data = policy_dict()
        data["tools"]["convert_time"]["capabilities"] = ["compute", "teleport"]
        self.assert_reason(data, "convert_time", "teleport")

    def test_parameter_type_names_tool_and_parameter_without_echoing_type(self):
        data = policy_dict()
        data["tools"]["convert_time"]["parameters"] = {"time": "datetime"}
        message = self.assert_reason(data, "convert_time", "time", "可用类型")
        self.assertNotIn("datetime", message)

    def test_required_not_declared_is_named(self):
        data = policy_dict()
        data["tools"]["convert_time"]["required"] = ["time", "ghost"]
        self.assert_reason(data, "convert_time", "ghost")

    def test_path_field_must_be_required_string(self):
        data = policy_dict(tools={"write_file": {
            "capabilities": ["write"], "parameters": {"path": "integer"},
            "path_fields": ["path"], "roots": ["."]}})
        self.assert_reason(data, "write_file", "path", "string")

    def test_path_field_must_be_in_required(self):
        data = policy_dict(tools={"write_file": {
            "capabilities": ["write"], "parameters": {"path": "string", "other": "string"},
            "required": ["other"], "path_fields": ["path"], "roots": ["."]}})
        self.assert_reason(data, "write_file", "path", "必填")

    def test_missing_root_names_tool(self):
        data = policy_dict(tools={"write_file": {
            "capabilities": ["write"], "parameters": {"path": "string"},
            "path_fields": ["path"], "roots": ["no-such-root"]}})
        self.assert_reason(data, "write_file", "roots")

    def test_network_without_origins_names_tool(self):
        data = policy_dict(tools={"post": {
            "capabilities": ["network"], "parameters": {"url": "string"},
            "url_fields": ["url"]}})
        self.assert_reason(data, "post", "network")

    def test_origin_with_path_names_tool(self):
        data = policy_dict(tools={"post": {
            "capabilities": ["network"], "parameters": {"url": "string"},
            "url_fields": ["url"], "origins": ["https://example.invalid/a"]}})
        self.assert_reason(data, "post", "origins")

    def test_execute_requires_allowed_arguments(self):
        data = policy_dict(tools={"run": {"capabilities": ["execute"], "parameters": {}}})
        self.assert_reason(data, "run", "allowed_arguments")

    def test_bad_state_names_tool(self):
        data = policy_dict()
        data["tools"]["convert_time"]["state"] = "START"
        self.assert_reason(data, "convert_time", "state")

    def test_undefined_transition_state_is_named(self):
        self.assert_reason(policy_dict(transitions={"NOWHERE": ["converted"]}), "NOWHERE")

    def test_undefined_transition_target_is_named(self):
        self.assert_reason(policy_dict(transitions={"START": ["missing_state"]}), "missing_state")

    def test_limit_out_of_range_names_key(self):
        self.assert_reason(policy_dict(max_secrets=0), "max_secrets")

    def test_allowed_arguments_error_does_not_echo_values(self):
        secret = "curl -H 'Authorization: Bearer sk-live-SHOULD-NOT-APPEAR'"
        data = policy_dict(tools={"run": {
            "capabilities": ["execute"], "parameters": {}, "allowed_arguments": [secret]}})
        message = self.reason(data)
        self.assertIn("allowed_arguments", message)
        self.assertNotIn("SHOULD-NOT-APPEAR", message)
        self.assertNotIn(secret, message)

    def test_long_names_are_truncated(self):
        data = policy_dict()
        data["tools"]["t" * 500] = {"capabilities": ["compute"], "parameters": {}}
        data["tools"]["t" * 500]["typo_field"] = 1
        message = self.reason(data)
        self.assertLessEqual(len(message), 200)


class DoctorSurfacingTests(unittest.TestCase):
    """doctor 保留固定诊断码，同时把具体原因放进 message。"""

    def setUp(self):
        self.directory = temporary_directory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write_policy(self, data):
        path = self.root / "policy.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_policy_invalid_carries_specific_reason(self):
        data = policy_dict()
        data["tools"]["convert_time"]["typo_field"] = 1
        report = doctor.check(self.write_policy(data))
        self.assertEqual(report["status"], "error")
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual(finding["code"], "POLICY_INVALID")
        self.assertNotEqual(finding["message"], doctor.MESSAGES["POLICY_INVALID"])
        self.assertIn("typo_field", finding["message"])

    def test_unreadable_policy_keeps_generic_message_and_error_status(self):
        report = doctor.check(self.root / "absent.json")
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["findings"][0]["code"], "POLICY_INVALID")

    def test_cli_exit_code_stays_one(self):
        data = policy_dict(extra_field=1)
        with contextlib.redirect_stdout(io.StringIO()):
            code = doctor.main(["--policy", str(self.write_policy(data)), "--json"])
        self.assertEqual(code, 1)


class ProxyStartupTests(unittest.TestCase):
    """代理启动失败时也要给出具体原因。"""

    def test_proxy_reports_reason_and_exits_two(self):
        directory = temporary_directory()
        self.addCleanup(directory.cleanup)
        data = policy_dict()
        data["tools"]["convert_time"]["typo_field"] = 1
        path = Path(directory.name) / "policy.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        stderr = io.StringIO()
        argv = ["agent-immunity", "--policy", str(path), "--", "/bin/true"]
        with contextlib.redirect_stderr(stderr), mock.patch.object(sys, "argv", argv), \
                self.assertRaises(SystemExit) as caught:
            mcp_stdio.main()
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("typo_field", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
