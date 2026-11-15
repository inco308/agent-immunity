"""用真实临时配置和报告验证宿主演练的阶段切换与失败回退。"""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch

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
        self.identity_checks = []
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

    def mock_preflight(self, environment, slot, output, policy):
        self.assertEqual(environment[slot], self.environment[slot])
        if "gateway_slots" in self.environment:
            self.assertEqual(environment["gateway"], self.environment["gateway_slots"][slot]["python"])
        self.assertEqual((output, policy), (self.output, self.policy_path))
        return {"installed_version": pilot.VERSIONS[slot], "raw_tools": ["convert_time", "get_current_time"],
                "policy_check": "pass", "catalog_sha256": checksum(slot.encode())}

    def mock_command(self, argv, cwd):
        if len(argv) > 4 and Path(argv[4]).name == "wheel_identity.py":
            slots = self.environment["gateway_slots"]
            slot = next(name for name, entry in slots.items() if entry["python"] == argv[0])
            entry = slots[slot]
            self.assertEqual(cwd, self.output)
            self.assertEqual(argv[1:], ["-I", "-X", "utf8", str(pilot.HERE / "wheel_identity.py"),
                                        "--wheel", entry["wheel"], "--version", entry["version"],
                                        "--sha256", entry["wheel_sha256"]])
            self.identity_checks.append((slot, len(self.observations)))
            metadata = checksum(f"{slot} metadata".encode())
            if slot == "candidate" and len(self.observations) == 1 and self.failure == "candidate_identity":
                raise ValueError("候选网关安装核验失败")
            if slot == "candidate" and len(self.observations) == 2 and self.failure == "metadata_changed":
                metadata = checksum(b"modified after call")
            return json.dumps({"version": entry["version"], "wheel_sha256": entry["wheel_sha256"],
                               "runtime_files": 8, "metadata_sha256": metadata})
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
        gateway = self.environment["gateway"]
        if "gateway_slots" in self.environment:
            gateway = self.environment["gateway_slots"][slot]["python"]
            other_gateway = self.environment["gateway_slots"][other]["python"]
            self.assertNotIn(json.dumps(other_gateway, ensure_ascii=False).encode("utf-8"), config)
        for value in (gateway, self.environment[slot], str(self.policy_path)):
            self.assertIn(json.dumps(value, ensure_ascii=False).encode("utf-8"), config)
        self.assertNotIn(json.dumps(self.environment[other], ensure_ascii=False).encode("utf-8"), config)
        self.observations.append((slot, config, checksum(self.policy_path.read_bytes())))
        if expect_weekday:
            if self.failure == "runtime_error":
                raise RuntimeError("合成候选版本未通过宿主验收")
            if self.failure == "type_error":
                raise TypeError("候选宿主响应形状异常")
            if self.failure == "not_mapping":
                return []
        return {"visible_tools": ["convert_time"], "source": "UTC 09:00", "target": "Asia/Tokyo 18:00",
                "difference": "+9.0h", "weekday_field": expect_weekday, "denial": "TRANSITION_DENIED"}

    def run_trial(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return pilot.run(self.args)

    def read_report(self):
        return json.loads(self.report_path.read_text(encoding="utf-8"))

    def enable_verified_previews(self):
        root = self.args.environment.parent
        slots = {}
        for index, name in enumerate(("previous", "candidate"), start=1):
            slots[name] = {
                "version": "0.3.0a1", "python": str(root / f"gateway-{name}-python"),
                "wheel": str(root / name / "agent_immunity-0.3.0a1-py3-none-any.whl"),
                "run_id": index, "artifact_id": index + 10, "commit": str(index) * 40,
                "wheel_sha256": checksum(f"{name} wheel".encode()),
            }
            slot = slots[name]
            wheel = Path(slot["wheel"])
            wheel.parent.mkdir()
            receipt = {key: slot[key] for key in ("version", "commit", "run_id", "artifact_id")}
            receipt["files"] = {wheel.name: slot["wheel_sha256"]}
            (wheel.parent / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        self.environment.update(schema_version=2, gateway_slots=slots, gateway=slots["previous"]["python"],
                                gateway_wheel_sha256=slots["previous"]["wheel_sha256"])
        self.args.environment.write_text(json.dumps(self.environment), encoding="utf-8")
        self.args.require_verified_gateways = True
        return slots

    def test_two_same_version_builds_follow_host_and_upstream_through_rollback(self):
        slots = self.enable_verified_previews()
        self.assertEqual(self.run_trial(), 0)
        report = self.read_report()
        self.assertEqual(report["gateway_mode"], "verified_previews")
        self.assertEqual(report["status"], "passed")
        stages = report["stages"]
        self.assertEqual([item["phase"] for item in stages], ["install", "upgrade", "rollback"])
        for item, slot in zip(stages, ("previous", "candidate", "previous")):
            original = slots[slot]
            self.assertEqual(item["gateway"], {
                **{key: original[key] for key in ("commit", "artifact_id", "run_id", "version", "wheel_sha256")},
                "metadata_sha256": checksum(f"{slot} metadata".encode()), "runtime_files": 8,
            })
            self.assertEqual(item["version"], pilot.VERSIONS[slot])
            self.assertEqual(item["weekday_field"], slot == "candidate")
            self.assertEqual(item["denial"], "TRANSITION_DENIED")
        self.assertEqual(self.identity_checks, [
            ("previous", 0), ("candidate", 0),  # 预检两个环境
            ("previous", 0), ("previous", 1), ("candidate", 1), ("candidate", 2),
            ("previous", 2), ("previous", 3),  # 每次调用前后均按活动解释器核验
        ])
        self.assertEqual(self.active.read_bytes(), self.observations[0][1])

    def test_failed_candidate_identity_preserves_previous_registration_before_switch(self):
        self.enable_verified_previews()
        self.failure = "candidate_identity"
        self.assertEqual(self.run_trial(), 1)
        report = self.read_report()
        self.assertEqual(report["attempted_phase"], "upgrade")
        self.assertEqual([stage["phase"] for stage in report["stages"]], ["install"])
        self.assertEqual([slot for slot, _, _ in self.observations], ["previous"])
        self.assertEqual(len(self.readbacks), 1)
        self.assertEqual(self.active.read_bytes(), self.observations[0][1])
        self.assertEqual(report["restored_verified_config_sha256"], report["stages"][0]["config_sha256"])

    def test_changed_candidate_identity_after_host_call_restores_previous_config(self):
        self.enable_verified_previews()
        self.check_candidate_failure("metadata_changed")

    def test_required_verified_mode_rejects_legacy_descriptor(self):
        self.args.require_verified_gateways = True
        self.assertEqual(self.run_trial(), 1)
        self.assertEqual(self.read_report()["stages"], [])
        self.preflight.assert_not_called()
        self.host.assert_not_called()
        self.assertFalse(self.active.exists())

    def test_missing_candidate_slot_cannot_fall_back_to_legacy_gateway(self):
        slots = self.enable_verified_previews()
        del slots["candidate"]
        self.args.require_verified_gateways = False
        self.args.environment.write_text(json.dumps(self.environment), encoding="utf-8")
        self.assertEqual(self.run_trial(), 1)
        self.assertEqual(self.read_report()["stages"], [])
        self.preflight.assert_not_called()
        self.host.assert_not_called()
        self.assertFalse(self.active.exists())

    def test_receipt_commit_mismatch_stops_before_any_host_stage(self):
        slots = self.enable_verified_previews()
        receipt = Path(slots["previous"]["wheel"]).with_name("receipt.json")
        source = json.loads(receipt.read_bytes())
        source["commit"] = "f" * 40
        receipt.write_text(json.dumps(source), encoding="utf-8")
        self.assertEqual(self.run_trial(), 1)
        self.assertEqual(self.read_report()["stages"], [])
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

    def fail_candidate_startup(self, state="failed", on_candidate=None, on_recovery=None):
        """让宿主在实际读取候选配置后报错，保留后续连接独立的观察记录。"""
        def observe(binary, project, *, expect_weekday):
            result = self.inspect_active_config(binary, project, expect_weekday=expect_weekday)
            if expect_weekday:
                if on_candidate:
                    on_candidate()
                raise pilot.GatewayStartupError(state)
            if len(self.observations) == 3 and on_recovery:
                on_recovery()
            return result

        self.host.side_effect = observe

    def test_candidate_startup_failure_reconnects_and_checks_verified_original(self):
        self.enable_verified_previews()
        self.fail_candidate_startup()
        self.assertEqual(self.run_trial(), 1)
        report = self.read_report()
        self.assertEqual((report["status"], report["attempted_phase"], report["failure_type"]),
                         ("failed", "upgrade", "GatewayStartupError"))
        self.assertEqual([s["phase"] for s in report["stages"]], ["install"])
        self.assertEqual([s for s, _, _ in self.observations], ["previous", "candidate", "previous"])
        self.assertEqual(self.observations[0], self.observations[2])
        self.assertEqual(self.active.read_bytes(), self.observations[0][1])
        self.assertEqual(self.identity_checks[-2:], [("previous", 2), ("previous", 3)])
        first = report["stages"][0]
        recovery = report["recovery"]
        self.assertEqual((recovery["phase"], recovery["status"]), ("recovery", "passed"))
        for key in ("config_sha256", "gateway", "version", "visible_tools", "source", "target",
                    "difference", "weekday_field", "denial"):
            self.assertEqual(recovery[key], first[key], key)
        self.assertEqual(report["restored_verified_config_sha256"], checksum(self.active.read_bytes()))
        self.assertEqual(self.account_writes, [])
        self.assertNotIn("fault", report)

    def test_recovery_host_failure_preserves_original_failure_and_does_not_retry(self):
        def no_reconnection():
            raise ConnectionError("恢复宿主连接失败")

        self.fail_candidate_startup("discovery_timeout", on_recovery=no_reconnection)
        self.assertEqual(self.run_trial(), 1)
        report = self.read_report()
        self.assertEqual((report["status"], report["failure_type"], report["host_startup_state"]),
                         ("failed", "GatewayStartupError", "discovery_timeout"))
        self.assertEqual((report["recovery"]["status"], report["recovery"]["error_type"]),
                         ("failed", "ConnectionError"))
        self.assertEqual(self.host.call_count, 3)
        self.assertEqual(self.active.read_bytes(), self.observations[0][1])

    def test_changed_original_install_is_rejected_before_recovery_connection(self):
        slots = self.enable_verified_previews()
        self.fail_candidate_startup()
        inspect = pilot.gateway_identity

        def changed_install(entry, root):
            identity = inspect(entry, root)
            if entry == slots["previous"] and len(self.observations) >= 2:
                identity["metadata_sha256"] = checksum(b"replacement metadata")
            return identity

        with patch.object(pilot, "gateway_identity", side_effect=changed_install):
            self.assertEqual(self.run_trial(), 1)
        report = self.read_report()
        self.assertEqual(report["recovery"]["status"], "failed")
        self.assertEqual(self.host.call_count, 2)

    def test_policy_drift_before_recovery_prevents_new_host_connection(self):
        self.fail_candidate_startup(on_candidate=lambda: self.policy_path.write_bytes(b"{}"))
        self.assertEqual(self.run_trial(), 1)
        report = self.read_report()
        self.assertEqual(report["recovery"]["status"], "failed")
        self.assertEqual(self.host.call_count, 2)

    def test_policy_drift_during_reconnection_cannot_report_service_recovered(self):
        self.fail_candidate_startup(on_recovery=lambda: self.policy_path.write_bytes(b"{}"))
        self.assertEqual(self.run_trial(), 1)
        report = self.read_report()
        self.assertEqual(report["recovery"]["status"], "failed")
        self.assertEqual(self.host.call_count, 3)

    def test_interrupted_upgrade_restores_configuration_without_reconnecting(self):
        def stop():
            raise KeyboardInterrupt()

        self.fail_candidate_startup(on_candidate=stop)
        with self.assertRaises(KeyboardInterrupt):
            self.run_trial()
        report = self.read_report()
        self.assertEqual(report["failure_type"], "KeyboardInterrupt")
        self.assertEqual(self.host.call_count, 2)
        self.assertEqual(self.active.read_bytes(), self.observations[0][1])

    def test_first_startup_failure_has_no_verified_service_to_reconnect(self):
        self.host.side_effect = pilot.GatewayStartupError("failed")
        self.assertEqual(self.run_trial(), 1)
        self.assertEqual(self.host.call_count, 1)
        self.assertEqual(self.read_report()["stages"], [])
        self.assertFalse(self.active.exists())

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
