"""校验矩阵附表只发布完整的双构建恢复证据。"""
from copy import deepcopy
import unittest

from scripts.recovery_matrix import render_recovery
from scripts.support_evidence import RECOVERY_STEPS
from tests.test_support_matrix import COMMIT, job, pilot_report


PILOT_COMMIT = "21" * 20
RUN = 83007


def recovery_report():
    report = pilot_report()
    old, candidate = report["upstreams"]["previous"], report["upstreams"]["candidate"]
    first = report["stages"][0]
    for slot, commit, build_run, wheel in ((old, "32" * 20, 83001, "c"), (candidate, COMMIT, 83002, "e")):
        slot["gateway"] = {"version": "0.3.0a1", "commit": commit, "run_id": build_run, "artifact_id": build_run + 10,
                           "wheel_sha256": wheel * 64, "metadata_sha256": "f" * 64, "runtime_files": 19}
    first.update(policy_sha256=report["policy_sha256"], gateway=deepcopy(old["gateway"]))
    report.update(schema_version=2, gateway_mode="verified_previews", status="failed", attempted_phase="upgrade",
                  failure_type="GatewayStartupError", host_startup_state="failed", stages=[first],
                  policy_comparison={"status": "pass", "candidate_runtime_check": "pass", "codes": [],
                                     "baseline_policy_sha256": first["policy_sha256"], "candidate_policy_sha256": "9" * 64},
                  fault={"kind": "missing_candidate_upstream", "exit_code": 1, "config_sha256": "8" * 64,
                         "policy_sha256": "9" * 64, "gateway": deepcopy(candidate["gateway"])},
                  recovery={**deepcopy(first), "phase": "recovery", "status": "passed"},
                  restored_verified_config_sha256=first["config_sha256"])
    return report


class RecoveryMatrixTests(unittest.TestCase):
    def setUp(self):
        self.job = job(35001, "lifecycle", "ubuntu-24.04", RUN, RECOVERY_STEPS)
        self.job["head_sha"] = PILOT_COMMIT

    def render(self, report, **kwargs):
        return render_recovery(PILOT_COMMIT, RUN, self.job, report, 35002,
                               **{"matrix_commit": COMMIT, "verify_run": 83002, "gateway_version": "0.3.0a1", **kwargs})

    def test_names_runner_versions_fault_and_distinct_builds(self):
        row = self.render(recovery_report())
        for expected in ("## 双构建故障恢复演练", "ubuntu-24.04", "2025.8.4", "2025.9.25", "0.167.0-alpha.3.2",
                         "1.30.0", "上游程序缺失", "重复调用", "c" * 12, "e" * 12, "/83001/artifacts/83011",
                         "/83002/artifacts/83012", "/83007/job/35001", "/83007/artifacts/35002", f"/commit/{PILOT_COMMIT}"):
            self.assertIn(expected, row)

    def test_incomplete_or_substituted_evidence_is_refused(self):
        cases = (
            (("schema_version",), 1), (("status",), "passed"), (("stages",), []),
            (("fault", "exit_code"), True), (("fault", "kind"), "missing_candidate_policy"),
            (("fault", "gateway", "artifact_id"), 83011), (("fault", "policy_sha256"), "d" * 64),
            (("policy_comparison", "candidate_runtime_check"), "error"),
            (("policy_comparison", "codes"), ["POLICY_TOOL_ADDED"]), (("rollback_error_type",), "ValueError"),
            (("recovery", "gateway", "wheel_sha256"), "e" * 64), (("recovery", "status"), "running"),
            (("recovery", "config_sha256"), "8" * 64), (("recovery", "policy_sha256"), "9" * 64),
            (("recovery", "target"), "UTC 09:00"), (("recovery", "weekday_field"), 0),
            (("recovery", "denial"), "pass"), (("restored_verified_config_sha256",), "a bad hash"),
            (("upstreams", "candidate", "installed_version"), "[untrusted](bad)"),
        )
        for path, value in cases:
            with self.subTest(path=path):
                report = recovery_report()
                item = report
                for key in path[:-1]:
                    item = item[key]
                item[path[-1]] = value
                with self.assertRaises(ValueError):
                    self.render(report)
        report = recovery_report()
        del report["recovery"]["policy_sha256"]
        with self.assertRaises(ValueError):
            self.render(report)

    def test_matrix_commit_builds_and_job_must_agree(self):
        for field in ("run_id", "artifact_id", "commit", "wheel_sha256"):
            with self.subTest(field=field):
                report = recovery_report()
                report["upstreams"]["previous"]["gateway"][field] = report["fault"]["gateway"][field]
                for stage in (report["stages"][0], report["recovery"]):
                    stage["gateway"] = deepcopy(report["upstreams"]["previous"]["gateway"])
                with self.assertRaises(ValueError):
                    self.render(report)
        with self.assertRaises(ValueError):
            self.render(recovery_report(), matrix_commit=PILOT_COMMIT)
        with self.assertRaises(ValueError):
            self.render(recovery_report(), verify_run=83001)
        with self.assertRaises(ValueError):
            self.render(recovery_report(), gateway_version="0.4.0")
        self.job["steps"].pop()
        with self.assertRaises(ValueError):
            self.render(recovery_report())
