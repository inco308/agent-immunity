"""用合成作业和结果报告核对版本支持矩阵的证据范围。"""
from copy import deepcopy
import unittest

from scripts.support_matrix import render_matrix


COMMIT = "1a" * 20
VERIFY_RUN = 82001
PILOT_RUN = 82002
SYSTEMS = ("ubuntu-latest", "windows-latest")
CORE_STEPS = ("测试与模拟规则基准", "检查归档内容、独立安装和 SHA-256")
INSPECTOR_STEP = "真实客户端与 SDK 上游端到端验证"
PILOT_STEP = "Codex 宿主安装、升级和回退"
NATIVE_STEP = "核对原生宿主的三阶段证据"
MAC_STEP = "核对 macOS 15 原生宿主的三阶段证据"


def job(job_id, name, system, run_id, steps):
    return {
        "id": job_id, "name": name, "labels": [system], "status": "completed",
        "conclusion": "success", "run_id": run_id, "run_attempt": 1, "head_sha": COMMIT,
        "html_url": f"https://github.com/inco308/agent-immunity/actions/runs/{run_id}/job/{job_id}",
        "steps": [{"name": step, "status": "completed", "conclusion": "success"} for step in steps],
    }


def inspector_report(python):
    return {
        "schema_version": 1, "scope": "INSPECTOR_SDK_APPLICATION_E2E", "status": "passed",
        "versions": {"inspector": "2.14.0", "node": "v24.22.1", "mcp_python": "1.30.0", "python": python},
        "checks": [
            {"name": "official_client_handshake", "status": "passed", "protocol": "2025-06-18"},
            {"name": "read_generate_write_reread_publish", "status": "passed",
             "task_count": 4, "report_bytes": 249, "http_requests": 1},
        ],
    }


def pilot_report():
    old, new = "2025.8.4", "2025.9.25"
    stages = []
    for phase, version in (("install", old), ("upgrade", new), ("rollback", old)):
        stages.append({
            "phase": phase, "version": version, "config_sha256": ("a" if version == old else "b") * 64,
            "visible_tools": ["convert_time"], "source": "UTC 09:00", "target": "Asia/Tokyo 18:00",
            "difference": "+9.0h", "weekday_field": version == new, "denial": "TRANSITION_DENIED",
        })
    return {
        "schema_version": 1, "scope": "CODEX_MCP_LIFECYCLE", "status": "passed",
        "codex_version": "codex-cli 0.167.0-alpha.3.2", "gateway_version": "0.3.0a1", "mcp_sdk": "1.30.0",
        "gateway_wheel_sha256": "e" * 64, "policy_sha256": "d" * 64, "attempted_phase": "rollback",
        "upstreams": {slot: {"installed_version": version, "raw_tools": ["convert_time", "get_current_time"],
                             "policy_check": "pass", "catalog_sha256": "c" * 64}
                      for slot, version in (("previous", old), ("candidate", new))},
        "stages": stages,
    }


def native_pilot(target, check_step=NATIVE_STEP):
    if target == "macos-arm64":
        job_id, label = 121, "macos-15"
        system, os_version, arch, machine = "Darwin", "15.8.2", "arm64", "arm64"
    else:
        job_id, label = 122, "windows-2025"
        system, os_version, arch, machine = "Windows", "10.0.26100", "x64", "AMD64"
    pythons = {}
    for role, patch in (("gateway", 9), ("previous", 10), ("candidate", 11)):
        python = {"implementation": "CPython", "version": f"3.12.{patch}", "machine": machine}
        if system == "Windows":
            python["python_platform"] = "win-amd64"
        pythons[role] = python
    report = pilot_report()
    # 同一网关版本由不同平台各自打包，归档摘要可与 Linux 基线不同。
    report["gateway_wheel_sha256"] = ("f" if system == "Windows" else "b") * 64
    report["host_environment"] = {"system": system, "os_version": os_version, "codex_arch": arch, "pythons": pythons}
    return job(job_id, f"lifecycle-{target}", label, PILOT_RUN, [PILOT_STEP, check_step]), report


class SupportMatrixTests(unittest.TestCase):
    def setUp(self):
        self.jobs = []
        for os_label in SYSTEMS:
            for python in ("3.10", "3.12"):
                name = f"test ({os_label}, {python})"
                self.jobs.append(job(101 + len(self.jobs), name, os_label, VERIFY_RUN, CORE_STEPS))
            self.jobs.append(job(101 + len(self.jobs), f"interop ({os_label})", os_label, VERIFY_RUN, [INSPECTOR_STEP]))
        self.reports = {"ubuntu-latest": inspector_report("3.12.16"), "windows-latest": inspector_report("3.12.10")}
        self.pilot_job = job(111, "lifecycle", "ubuntu-24.04", PILOT_RUN, [PILOT_STEP])
        self.pilot = pilot_report()

    def render(self, **changes):
        inputs = dict(verify_jobs=self.jobs, interop_reports=self.reports, pilot_job=self.pilot_job, pilot_report=self.pilot)
        inputs.update(changes)
        return render_matrix(COMMIT, VERIFY_RUN, PILOT_RUN, **inputs)

    def test_observed_combinations_each_link_to_their_own_job(self):
        matrix = self.render()
        rows = [line for line in matrix.splitlines() if "/job/" in line]
        self.assertEqual(len(rows), 7)
        for entry in [*self.jobs, self.pilot_job]:
            link = f"/actions/runs/{entry['run_id']}/job/{entry['id']}"
            matching, = [line for line in rows if link in line]
            if entry["name"].startswith("interop"):
                report = self.reports[entry["labels"][0]]
                self.assertIn(report["versions"]["python"], matching)
                self.assertIn("2.14.0", matching)
            elif entry["name"] == "lifecycle":
                for version in ("0.167.0-alpha.3.2", "2025.8.4", "2025.9.25"):
                    self.assertIn(version, matching)
            else:
                self.assertNotIn("2.14.0", matching)
                self.assertNotIn("0.167.0-alpha.3.2", matching)

    def test_native_jobs_add_only_their_measured_platforms(self):
        original = self.render()
        self.assertEqual(self.render(native_pilots=[]), original)
        old_rows = [line for line in original.splitlines() if "/job/" in line]
        # 旧 Mac 作业与后来的双平台作业使用不同的原生架构验收步骤名。
        for pilots in ([native_pilot("macos-arm64", MAC_STEP)], [native_pilot("windows-x64")],
                       [native_pilot("macos-arm64"), native_pilot("windows-x64")]):
            with self.subTest(jobs=[entry["name"] for entry, _ in pilots]):
                rows = [line for line in self.render(native_pilots=pilots).splitlines() if "/job/" in line]
                self.assertEqual(len(rows), len(old_rows) + len(pilots))
                for old in old_rows:
                    self.assertIn(old, rows)
                for native_job, native_report in pilots:
                    link = f"/actions/runs/{PILOT_RUN}/job/{native_job['id']})"
                    row, = [line for line in rows if link in line]
                    env = native_report["host_environment"]
                    for expected in (native_job["labels"][0], env["os_version"], env["codex_arch"],
                                     "0.167.0-alpha.3.2", "2025.8.4", "2025.9.25"):
                        self.assertIn(expected, row)
                    for python in env["pythons"].values():
                        self.assertIn(python["version"], row)

    def test_job_label_report_and_native_gate_must_agree(self):
        mac, mac_report = native_pilot("macos-arm64")
        windows, win_report = native_pilot("windows-x64")
        skipped = {**windows["steps"][1], "conclusion": "skipped"}
        for label, entry, report in (
            ("Mac 报告作为 Windows 证据", windows, mac_report),
            ("Windows 报告作为 Mac 证据", mac, win_report),
            ("错误 runner", {**windows, "labels": ["macos-15"]}, win_report),
            ("其他运行的宿主作业", {**mac, "run_id": VERIFY_RUN}, mac_report),
            ("缺少架构验收步骤", {**mac, "steps": mac["steps"][:1]}, mac_report),
            ("跳过架构验收", {**windows, "steps": [windows["steps"][0], skipped]}, win_report),
            ("Windows 作业使用旧 Mac 步骤", *native_pilot("windows-x64", MAC_STEP)),
        ):
            with self.subTest(case=label), self.assertRaises(ValueError):
                self.render(native_pilots=[(entry, report)])
        with self.assertRaises(ValueError):
            self.render(pilot_job={**self.pilot_job, "labels": ["windows-2025"]})

    def test_native_host_and_every_interpreter_need_observed_architecture(self):
        for target, field, value in (("windows-x64", "codex_arch", "arm64"),
                                     ("macos-arm64", "os_version", "15.8.2|extra")):
            entry, report = native_pilot(target)
            report["host_environment"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.render(native_pilots=[(entry, report)])
        for target, role, field, value in (
            ("windows-x64", "gateway", "python_platform", "win32"),
            ("windows-x64", "previous", "machine", "ARM64"),
            ("macos-arm64", "candidate", "version", "3.11.9"),
            ("macos-arm64", "gateway", "implementation", "PyPy"),
        ):
            entry, report = native_pilot(target)
            report["host_environment"]["pythons"][role][field] = value
            with self.subTest(role=role, field=field), self.assertRaises(ValueError):
                self.render(native_pilots=[(entry, report)])
        entry, report = native_pilot("windows-x64")
        del report["host_environment"]["pythons"]["candidate"]
        with self.assertRaises(ValueError):
            self.render(native_pilots=[(entry, report)])

    def test_native_row_needs_full_lifecycle_for_matrix_gateway_version(self):
        entry, report = native_pilot("macos-arm64")
        for field, value in (("gateway_version", "0.3.0a2"), ("scope", "preflight"),
                             ("stages", report["stages"][:2])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.render(native_pilots=[(entry, {**report, field: value})])
        report["stages"][2]["denial"] = ""
        with self.assertRaises(ValueError):
            self.render(native_pilots=[(entry, report)])

    def test_missing_platform_job_or_skipped_required_step_is_rejected(self):
        with self.assertRaises(ValueError):
            self.render(verify_jobs=self.jobs[:-1])
        for index, step in ((0, CORE_STEPS[0]), (1, CORE_STEPS[1]), (2, INSPECTOR_STEP)):
            jobs = deepcopy(self.jobs)
            next(item for item in jobs[index]["steps"] if item["name"] == step)["conclusion"] = "skipped"
            with self.subTest(step=step), self.assertRaises(ValueError):
                self.render(verify_jobs=jobs)
        failed_pilot_job = {**self.pilot_job, "conclusion": "failure"}
        with self.assertRaises(ValueError):
            self.render(pilot_job=failed_pilot_job)

    def test_an_additional_packaging_platform_only_adds_a_packaging_row(self):
        additional = job(150, "test (macos-15, 3.13)", "macos-15", VERIFY_RUN, CORE_STEPS)
        rows = [row for row in self.render(verify_jobs=[*self.jobs, additional]).splitlines() if "macos-15" in row]
        row, = rows
        self.assertIn("Python 3.13", row)
        self.assertIn("/job/150)", row)
        self.assertNotIn("Inspector", row)
        self.assertNotIn("Codex", row)

    def test_inspector_pass_needs_both_handshake_and_observed_http_request(self):
        missing_handshake = deepcopy(self.reports)
        missing_handshake["windows-latest"]["checks"].pop(0)
        with self.assertRaises(ValueError):
            self.render(interop_reports=missing_handshake)
        for field in ("http_requests", "report_bytes"):
            reports = deepcopy(self.reports)
            reports["windows-latest"]["checks"][1][field] = 0
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.render(interop_reports=reports)

    def test_preflight_partial_run_and_wrong_rollback_cannot_claim_lifecycle(self):
        with self.assertRaises(ValueError):
            self.render(pilot_report={**self.pilot, "scope": "preflight"})
        with self.assertRaises(ValueError):
            self.render(pilot_report={**self.pilot, "stages": self.pilot["stages"][:2]})
        for field, value in (("config_sha256", "b" * 64), ("version", "2025.9.25"),
                             ("denial", ""), ("visible_tools", ["convert_time", "get_current_time"]),
                             ("target", "Asia/Tokyo 09:00")):
            pilot = deepcopy(self.pilot)
            pilot["stages"][2][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.render(pilot_report=pilot)

    def test_version_fields_cannot_add_markdown_cells_or_rows(self):
        for field, value in (("inspector", "2.14.0|错误组合"), ("python", "3.12\n|额外行|")):
            reports = deepcopy(self.reports)
            reports["ubuntu-latest"]["versions"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.render(interop_reports=reports)


if __name__ == "__main__":
    unittest.main()
