"""用真实临时配置和报告验证宿主演练的阶段切换与失败回退。"""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
from pathlib import Path
import re
from subprocess import CompletedProcess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_immunity import doctor
from pilot.codex_time import host, run as pilot
from tests.support import temporary_directory


def checksum(data):
    return sha256(data).hexdigest()


class CodexPilotLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.output = root / "trial"
        self.active = self.output / "host-project" / ".codex" / "config.toml"
        self.policy_path = self.output / "policy.json"
        self.report_path = self.output / "report.json"
        self.environment = {slot: str(root / f"{slot}-python") for slot in ("gateway", "previous", "candidate")}
        self.environment.update({
            "schema_version": 1, "scope": "CODEX_TIME_PILOT_ENVIRONMENT",
            "versions": {"gateway": "0.3.0a1", "mcp": "1.30.0", **pilot.VERSIONS},
            "gateway_wheel_sha256": checksum(b"synthetic-pilot-wheel"),
        })
        env_file = root / "environment.json"
        env_file.write_text(json.dumps(self.environment), encoding="utf-8")
        self.args = SimpleNamespace(environment=env_file, output_dir=self.output,
                                    codex="pilot-test-codex", preflight_only=False)
        self.observations = []
        self.failure = None
        self.readbacks = []
        self.account_writes = []
        self.account = root / "simulated-account.json"
        self.sentinel = b'{"time_pilot":{"owner":"other-client","command":"keep-me"}}\n'
        self.account.write_bytes(b"{}\n")
        self.race_after_list = False

        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(pilot, "validate_clean_account", create=True))
        stack.enter_context(patch.object(pilot.shutil, "which", return_value=str(root / "pilot-test-codex")))
        self.preflight = stack.enter_context(patch.object(pilot, "preflight", side_effect=self.mock_preflight))
        self.command = stack.enter_context(patch.object(pilot, "run_command", side_effect=self.mock_command))
        self.host = stack.enter_context(patch.object(pilot, "host_stage", side_effect=self.inspect_active_config))

    def mock_preflight(self, environment, slot, output, policy, *, catalog_only=False):
        self.assertEqual(environment[slot], self.environment[slot])
        self.assertEqual(output, self.output)
        if not catalog_only:
            self.assertEqual(policy, self.policy_path)
            catalog_hash = checksum(slot.encode())
        else:
            self.assertEqual(slot, "candidate")
            catalog = {"tools": [{"name": name, "inputSchema": {"type": "object"}}
                                 for name in ("convert_time", "get_current_time")]}
            snapshot = json.dumps(catalog).encode()
            (output / "candidate-tools.json").write_bytes(snapshot)
            catalog_hash = checksum(snapshot)
        return {"installed_version": pilot.VERSIONS[slot], "raw_tools": ["convert_time", "get_current_time"],
                "catalog_sha256": catalog_hash}

    def mock_command(self, argv, cwd):
        if argv[1:] == ["--version"]:
            return f"codex-cli {pilot.HOST_VERSION}\n"
        if argv == ["git", "init", "--quiet"]:
            return ""
        if argv[1:] == ["mcp", "list", "--json"]:
            account = json.loads(self.account.read_bytes())
            if self.race_after_list:
                # 另一个客户端在空列表快照之后登记同名服务。
                self.account.write_bytes(self.sentinel)
            return json.dumps([{"name": name, **data} for name, data in account.items()])
        if argv[1] == "-c" and argv[3:] == ["mcp", "get", "time_pilot", "--json"]:
            self.assertEqual(cwd, self.active.parent.parent)
            override = argv[2]
            self.assertEqual(self.active.read_bytes().decode("utf-8").rstrip("\r\n"), override)
            # 此处解析试点约定的单行 TOML 格式，兼容 Python 3.10 测试环境。
            match = re.fullmatch(r"mcp_servers\.time_pilot\s*=\s*\{\s*command\s*=\s*(.+?),\s*args\s*=\s*(\[.*\])\s*\}", override)
            self.assertIsNotNone(match, "回读应使用项目文件中的单个 dotted 赋值")
            command, arguments = (json.loads(value) for value in match.groups())
            self.readbacks.append(override)
            return json.dumps({"transport": {"type": "stdio", "command": command, "args": arguments}, "enabled": True})
        if "mcp" in argv and any(verb in argv for verb in ("add", "remove")):
            self.account_writes.append(list(argv))
            self.fail("试点不得修改共享账号同名注册")
        self.fail(f"非预期的外部命令类型：{Path(argv[0]).name}")

    def inspect_active_config(self, _executable, project, *, expect_weekday):
        self.assertEqual(project, self.output / "host-project")
        config = self.active.read_bytes()
        self.assertEqual(len(self.readbacks), len(self.observations) + 1)
        self.assertEqual(config.decode("utf-8").rstrip("\r\n"), self.readbacks[-1])
        # 捕获真实 host_stage 准备启动的命令，在启动外部进程之前终止。
        class CaptureStartup(Exception):
            pass

        with patch.object(host, "_JsonProcess", side_effect=CaptureStartup) as spawn:
            with self.assertRaises(CaptureStartup):
                host.host_stage(_executable, project, expect_weekday=expect_weekday)
        startup, startup_cwd = spawn.call_args.args[:2]
        self.assertEqual(startup_cwd, project)
        self.assertEqual(startup, [str(_executable), "-c", self.readbacks[-1],
                                   "--no-daemon", "app-server", "--listen", "stdio://"])
        slot, other = ("candidate", "previous") if expect_weekday else ("previous", "candidate")
        # 在每次宿主验收时读取活动文件，核对它指向本次策略和正确的上游。
        policy_path = self.policy_path
        if expect_weekday and getattr(self.args, "candidate_policy_template", None):
            policy_path = self.output / "candidate-policy.json"
        for value in (self.environment["gateway"], self.environment[slot], str(policy_path)):
            self.assertIn(json.dumps(value, ensure_ascii=False).encode("utf-8"), config)
        self.assertNotIn(json.dumps(self.environment[other], ensure_ascii=False).encode("utf-8"), config)
        self.observations.append((slot, config, checksum(policy_path.read_bytes())))
        if expect_weekday:
            if self.failure == "runtime_error":
                raise RuntimeError("合成候选版本未通过宿主验收")
            if self.failure == "type_error":
                raise TypeError("候选宿主响应形状异常")
            if self.failure == "not_mapping":
                return []
        return {"weekday_field": expect_weekday}

    def run_trial(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return pilot.run(self.args)

    def read_report(self):
        return json.loads(self.report_path.read_text(encoding="utf-8"))

    def check_candidate_template(self, data, expected_code):
        template = self.output.parent / "input-template.json"
        template.write_bytes(data)
        self.args.candidate_policy_template = template
        baseline = (pilot.HERE / "policy.json").read_bytes()
        candidate = self.output / "candidate-policy.json"

        def installed_doctor(argv, **_options):
            self.assertEqual(argv[:4], [self.environment["gateway"], "-I", "-m", "agent_immunity.doctor"])
            options = argv[4:]
            self.assertEqual(Path(options[options.index("--policy") + 1]), candidate)
            self.assertEqual(Path(options[options.index("--baseline") + 1]), self.policy_path)
            self.assertEqual(Path(options[options.index("--catalog") + 1]), self.output / "candidate-tools.json")
            self.assertIn("--json", options)
            self.assertEqual(candidate.read_bytes(), data)
            self.assertEqual(self.policy_path.read_bytes(), baseline)
            if not self.args.preflight_only:
                self.assertEqual([slot for slot, _, _ in self.observations], ["previous"])
                self.assertEqual(self.active.read_bytes(), self.observations[0][1])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = doctor.main(options)
            return CompletedProcess(argv, code, stdout.getvalue(), "")

        with patch.object(pilot.subprocess, "run", side_effect=installed_doctor) as doctor_call, \
                patch.object(pilot, "atomic_write", wraps=pilot.atomic_write) as writes:
            self.assertEqual(self.run_trial(), expected_code)
        doctor_call.assert_called_once()
        self.assertEqual(template.read_bytes(), data)
        self.assertEqual(self.policy_path.read_bytes(), baseline)
        report = self.read_report()
        self.assertEqual(report["policy_comparison"]["candidate_policy_sha256"], checksum(data))
        self.assertEqual(report["policy_comparison"]["baseline_policy_sha256"], checksum(baseline))
        return report, [call.args[1] for call in writes.call_args_list if call.args[0] == self.active]

    def test_installed_candidate_with_reformatted_policy_rolls_back_to_original_policy(self):
        data = json.dumps(json.loads((pilot.HERE / "policy.json").read_bytes())).encode()
        report, writes = self.check_candidate_template(data, 0)
        self.assertEqual((report["status"], report["policy_comparison"]["status"]), ("passed", "pass"))
        original = self.observations[0][1]
        self.assertEqual(writes, [original, self.observations[1][1], original])
        self.assertEqual([slot for slot, _, _ in self.observations], ["previous", "candidate", "previous"])
        self.assertEqual(self.active.read_bytes(), original)
        self.assertEqual(self.observations[1][2], checksum(data))

    def check_held_candidate(self, data, code, status, finding):
        report, writes = self.check_candidate_template(data, code)
        self.assertEqual(report["status"], "review" if code == 2 else "failed")
        self.assertEqual(report["policy_comparison"]["status"], status)
        self.assertIn(finding, report["policy_comparison"]["codes"])
        self.assertEqual([entry["phase"] for entry in report["stages"]], ["install"])
        self.assertEqual([slot for slot, _, _ in self.observations], ["previous", "previous"])
        original = self.observations[0][1]
        self.assertEqual(writes, [original])
        self.assertEqual(self.observations[0], self.observations[1])
        self.assertEqual(self.active.read_bytes(), original)
        self.assertEqual(report["retained"]["config_sha256"], checksum(original))
        self.assertEqual(report["retained"]["version"], pilot.VERSIONS["previous"])

    def test_new_registered_tool_holds_candidate_and_rechecks_existing_host(self):
        policy = json.loads((pilot.HERE / "policy.json").read_bytes())
        policy["tools"]["get_current_time"] = {"capabilities": ["compute"]}
        self.check_held_candidate(json.dumps(policy).encode(), 2, "review", "POLICY_TOOL_ADDED")

    def test_invalid_candidate_retains_original_and_returns_error(self):
        self.check_held_candidate(b'{"version":2}', 1, "error", "POLICY_VERSION_UNSUPPORTED")

    def test_preflight_only_reports_review_without_starting_or_claiming_host_recheck(self):
        self.args.preflight_only = True
        policy = json.loads((pilot.HERE / "policy.json").read_bytes())
        policy["tools"]["get_current_time"] = {"capabilities": ["compute"]}
        report, writes = self.check_candidate_template(json.dumps(policy).encode(), 2)
        self.assertEqual((report["status"], report["stages"], writes), ("review", [], []))
        self.assertNotIn("retained", report)
        self.host.assert_not_called()
        self.assertFalse(self.active.exists())

    def check_candidate_failure(self, failure):
        self.failure = failure
        self.assertEqual(self.run_trial(), 1)
        report = self.read_report()
        self.assertEqual(report["status"], "failed")
        self.assertEqual([entry["phase"] for entry in report["stages"]], ["install"])
        self.assertEqual([slot for slot, _, _ in self.observations], ["previous", "candidate"])
        installed, candidate = (config for _, config, _ in self.observations)
        self.assertNotEqual(installed, candidate)
        self.assertEqual(self.active.read_bytes(), installed)
        self.assertEqual(report["restored_verified_config_sha256"], checksum(installed))
        self.assertEqual(report["stages"][0]["config_sha256"], checksum(installed))
        self.assertEqual(self.account_writes, [])

    def test_failed_candidate_restores_verified_file_and_records_install_only(self):
        self.check_candidate_failure("runtime_error")

    def test_candidate_response_type_error_restores_verified_file(self):
        self.check_candidate_failure("type_error")

    def test_returning_a_malformed_stage_result_cannot_promote_candidate_to_verified(self):
        self.check_candidate_failure("not_mapping")

    def test_three_stages_switch_upstream_and_keep_one_policy(self):
        self.assertEqual(self.run_trial(), 0)
        report = self.read_report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual([call.args[1] for call in self.preflight.call_args_list], ["previous", "candidate"])
        self.assertEqual([slot for slot, _, _ in self.observations], ["previous", "candidate", "previous"])
        self.assertEqual([stage["phase"] for stage in report["stages"]], ["install", "upgrade", "rollback"])
        self.assertEqual([stage["version"] for stage in report["stages"]],
                         [pilot.VERSIONS[slot] for slot, _, _ in self.observations])
        observed_hashes = [checksum(config) for _, config, _ in self.observations]
        self.assertEqual([stage["config_sha256"] for stage in report["stages"]], observed_hashes)
        self.assertEqual(observed_hashes[0], observed_hashes[2])
        self.assertNotEqual(observed_hashes[0], observed_hashes[1])
        self.assertEqual(self.active.read_bytes(), self.observations[0][1])
        expected_policy_sha = checksum((pilot.HERE / "policy.json").read_bytes())
        self.assertEqual([policy_sha for _, _, policy_sha in self.observations], [expected_policy_sha] * 3)
        self.assertEqual(checksum(self.policy_path.read_bytes()), expected_policy_sha)
        self.assertEqual(report["policy_sha256"], expected_policy_sha)
        self.assertEqual(self.account_writes, [])

    def test_competing_client_registration_after_empty_list_survives_success(self):
        self.race_after_list = True
        self.assertEqual(self.run_trial(), 0)
        self.assertEqual(len(self.readbacks), 3)
        self.assertEqual(self.account.read_bytes(), self.sentinel)
        self.assertEqual(self.account_writes, [])

    def test_existing_account_registration_is_preserved_before_any_stage(self):
        self.account.write_bytes(self.sentinel)
        self.assertEqual(self.run_trial(), 1)
        report = self.read_report()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["stages"], [])
        self.assertEqual(self.readbacks, [])
        self.host.assert_not_called()
        self.assertFalse(self.active.exists())
        self.assertEqual(self.account.read_bytes(), self.sentinel)
        self.assertEqual(self.account_writes, [])

    def test_preexisting_output_directory_preserves_user_files(self):
        self.active.parent.mkdir(parents=True)
        self.active.write_bytes(b"# user's existing project registration\r\n")
        self.report_path.write_bytes(b'{"existing": true}\n')
        existing = {path.relative_to(self.output): path.read_bytes()
                    for path in self.output.rglob("*") if path.is_file()}
        try:
            status = self.run_trial()
        except FileExistsError:
            pass
        else:
            self.assertNotEqual(status, 0)
        after = {path.relative_to(self.output): path.read_bytes()
                 for path in self.output.rglob("*") if path.is_file()}
        self.assertEqual(after, existing)
        self.preflight.assert_not_called()
        self.command.assert_not_called()
        self.host.assert_not_called()


if __name__ == "__main__":
    unittest.main()
