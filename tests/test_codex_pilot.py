"""用真实临时配置和报告验证宿主演练的阶段切换与失败回退。"""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pilot.codex_time import run as pilot
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
        self.fail_upgrade = False

        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(pilot, "validate_clean_account"))
        stack.enter_context(patch.object(pilot.shutil, "which", return_value=str(root / "pilot-test-codex")))
        self.preflight = stack.enter_context(patch.object(pilot, "preflight", side_effect=self.mock_preflight))
        self.command = stack.enter_context(patch.object(pilot, "run_command", side_effect=self.mock_command))
        self.host = stack.enter_context(patch.object(pilot, "host_stage", side_effect=self.inspect_active_config))

    def mock_preflight(self, environment, slot, output, policy):
        self.assertEqual(environment[slot], self.environment[slot])
        self.assertEqual((output, policy), (self.output, self.policy_path))
        return {"installed_version": pilot.VERSIONS[slot], "raw_tools": ["convert_time", "get_current_time"],
                "policy_check": "pass", "catalog_sha256": checksum(slot.encode())}

    def mock_command(self, argv, cwd):
        if argv[1:] == ["--version"]:
            return f"codex-cli {pilot.HOST_VERSION}\n"
        if argv == ["git", "init", "--quiet"]:
            return ""
        self.fail(f"非预期的外部命令类型：{Path(argv[0]).name}")

    def inspect_active_config(self, _executable, project, *, expect_weekday):
        self.assertEqual(project, self.output / "host-project")
        config = self.active.read_bytes()
        slot, other = ("candidate", "previous") if expect_weekday else ("previous", "candidate")
        # 在每次宿主验收时读取活动文件，核对它指向本次策略和正确的上游。
        for value in (self.environment["gateway"], self.environment[slot], str(self.policy_path)):
            self.assertIn(json.dumps(value, ensure_ascii=False).encode("utf-8"), config)
        self.assertNotIn(json.dumps(self.environment[other], ensure_ascii=False).encode("utf-8"), config)
        self.observations.append((slot, config, checksum(self.policy_path.read_bytes())))
        if expect_weekday and self.fail_upgrade:
            raise RuntimeError("合成候选版本未通过宿主验收")
        return {"weekday_field": expect_weekday}

    def run_trial(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return pilot.run(self.args)

    def read_report(self):
        return json.loads(self.report_path.read_text(encoding="utf-8"))

    def test_failed_candidate_restores_verified_file_and_records_install_only(self):
        self.fail_upgrade = True
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
