"""核验故障演练 CI 的通过条件，包括宿主行为、磁盘证据和两个收据。"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest

from pilot.codex_time import check_recovery as check
from tests.support import temporary_directory


class RecoveryEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = temporary_directory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.policy = self.root / "policy.json"
        self.policy.write_bytes((check.HERE / self.policy.name).read_bytes())
        self.env = {"schema_version": 1, "gateway": "python-previous", "previous": "upstream-previous", "candidate": "upstream-candidate",
                    "versions": {"gateway": "0.3.0a1"}, "gateway_wheel_sha256": "2" * 64}
        config = check.config_bytes(check.registration(self.env["gateway"], self.policy, self.env["previous"]))
        self.active = self.root / "host-project/.codex/config.toml"
        self.active.parent.mkdir(parents=True)
        self.active.write_bytes(config)
        digest = hashlib.sha256(config).hexdigest()
        self.marker = self.root / "candidate-exit.txt"
        self.marker.write_bytes(b"2\n")
        stage = {"phase": "install", "version": check.VERSIONS["previous"], "config_sha256": digest,
                 "visible_tools": ["convert_time"], "source": "UTC 09:00", "target": "Asia/Tokyo 18:00",
                 "difference": "+9.0h", "weekday_field": False, "denial": "TRANSITION_DENIED"}
        self.report = {
            "scope": "CODEX_MCP_LIFECYCLE", "schema_version": 1, "attempted_phase": "upgrade",
            "status": "failed", "failure_type": "GatewayStartupError", "host_startup_state": "failed",
            "fault": {"kind": "missing_candidate_policy", "exit_code": 2, "config_sha256": self.fault_sha(self.env["gateway"])},
            "stages": [stage], "recovery": {**stage, "phase": "recovery", "status": "passed"},
            "policy_sha256": hashlib.sha256(self.policy.read_bytes()).hexdigest(),
            "restored_verified_config_sha256": digest,
            "gateway_wheel_sha256": self.env["gateway_wheel_sha256"], "gateway_version": self.env["versions"]["gateway"],
        }

    def fault_sha(self, gateway):
        target = check.startup_fault_registration(gateway, self.root, self.env["candidate"])
        return hashlib.sha256(check.config_bytes(target)).hexdigest()

    def verify(self, report=None, status=1):
        environment = self.root / "environment.json"
        environment.write_text(json.dumps(self.env), encoding="utf-8")
        (self.root / "report.json").write_text(json.dumps(self.report if report is None else report), encoding="utf-8")
        check.validate(self.root, environment, status)

    def test_only_the_injected_failure_and_reconnected_business_count(self):
        self.verify()
        for section, key, value in (
            (None, "status", "passed"), (None, "attempted_phase", "install"), (None, "host_startup_state", "unknown"),
            ("fault", "exit_code", 1), ("fault", "config_sha256", "3" * 64),
            ("recovery", "status", "failed"), ("recovery", "version", "2025.9.25"),
            ("recovery", "target", "Asia/Tokyo 13:00"), ("recovery", "denial", "unexpected"),
        ):
            changed = deepcopy(self.report)
            (changed if section is None else changed[section])[key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                self.verify(changed)
        with self.assertRaises(ValueError):
            self.verify(status=0)
        changed = dict(self.report)
        del changed["recovery"]
        with self.assertRaises(KeyError):
            self.verify(changed)

    def test_disk_config_and_exit_marker_are_required(self):
        self.marker.write_bytes(b"0\n")
        with self.assertRaises(ValueError):
            self.verify()
        self.marker.write_bytes(b"2\r\n")
        self.active.write_bytes(b"different config")
        with self.assertRaises(ValueError):
            self.verify()

    def test_dual_receipt_requires_previous_build_at_recovery(self):
        origin = {"version": "0.3.0a1", "commit": "a" * 40, "run_id": 123, "artifact_id": 456, "wheel_sha256": "2" * 64}
        self.env.update(schema_version=2, gateway_slots={"previous": {**origin, "python": self.env["gateway"]},
                                                         "candidate": {"python": "python-candidate"}})
        identity = {**origin, "runtime_files": 19, "metadata_sha256": "5" * 64}
        self.report.update(schema_version=2, gateway_mode="verified_previews", upstreams={"previous": {"gateway": identity}})
        self.report["stages"][0]["gateway"] = identity
        self.report["recovery"]["gateway"] = identity
        # 单网关模式的故障注册缺少候选解释器，虽然摘要合法，也不能用于双收据演练。
        with self.assertRaises(ValueError):
            self.verify()
        self.report["fault"]["config_sha256"] = self.fault_sha("python-candidate")
        self.verify()
        self.report["recovery"]["gateway"] = {**identity, "wheel_sha256": "4" * 64}
        with self.assertRaises(ValueError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
