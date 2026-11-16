"""用合成作业和结果报告核对版本支持矩阵的证据范围。"""
from copy import deepcopy
import unittest

from scripts.package_protocol import PROTOCOL_STEP
from scripts.support_matrix import package_row, render_matrix
from scripts.support_evidence import RECOVERY_CHECK_STEP


COMMIT = "1a" * 20
VERIFY_RUN = 82001
PILOT_RUN = 82002
SYSTEMS = ("ubuntu-latest", "windows-latest")
CORE_STEPS = ("测试与模拟规则基准", "检查归档内容、独立安装和 SHA-256")
PACKAGE_STEPS = ("核对两个安装环境的 macOS、架构和 Python 系列", "保存 macOS 安装验收报告")
X64_PACKAGE_STEPS = ("核对两个安装环境的 x64 系统、架构和 Python 系列", "保存 x64 安装验收报告")
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


def install_report(series, environment):
    packages = []
    for kind, filename, digest in (("wheel", "agent_immunity-0.3.0a1-py3-none-any.whl", "a" * 64),
                                   ("sdist", "agent_immunity-0.3.0a1.tar.gz", "b" * 64)):
        packages.append({"kind": kind, "filename": filename, "sha256": digest, "installed_version": "0.3.0a1",
                         "implementation": "CPython", "python": series + ".10", "policy_check": "pass",
                         "proxy_ping": True, **environment})
    return {"schema_version": 1, "scope": "CORE_PACKAGE_INSTALL", "status": "passed", "packages": packages}


def mac_package_job(series="3.12"):
    entry = job(150, f"test (macos-15, {series})", "macos-15", VERIFY_RUN, (*CORE_STEPS, *PACKAGE_STEPS))
    entry["package_install_report"] = install_report(series, {"system": "Darwin", "os_version": "15.8.2", "machine": "arm64"})
    return entry


def x64_package_job(runner, series="3.12", job_id=160):
    entry = job(job_id, f"test ({runner}, {series})", runner, VERIFY_RUN, (*CORE_STEPS, *PACKAGE_STEPS, *X64_PACKAGE_STEPS))
    for step in entry["steps"]:
        if step["name"] in PACKAGE_STEPS:
            step["conclusion"] = "skipped"
    if runner == "ubuntu-latest":
        env = {"system": "Linux", "os_version": "7.0.0-1019-azure", "distro_id": "ubuntu", "distro_version": "26.04",
               "machine": "x86_64", "python_platform": "linux-x86_64"}
    else:
        env = {"system": "Windows", "os_version": "10.0.26100", "machine": "AMD64", "python_platform": "win-amd64"}
    entry["package_install_report"] = install_report(series, {**env, "pointer_bits": 64})
    return entry


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

    def test_normal_lifecycle_can_use_candidate_policy_comparison(self):
        old = self.render()
        del self.pilot["upstreams"]["candidate"]["policy_check"]
        comparison = {"status": "pass", "codes": [], "baseline_policy_sha256": self.pilot["policy_sha256"],
                      "candidate_policy_sha256": "7" * 64}
        self.pilot["policy_comparison"] = comparison
        self.assertEqual(self.render(), old)
        self.pilot_job["steps"].append({"name": RECOVERY_CHECK_STEP, "status": "completed", "conclusion": "success"})
        with self.assertRaises(ValueError):
            self.render()
        for stage in self.pilot["stages"]:
            stage["policy_sha256"] = comparison["candidate_policy_sha256"] if stage["phase"] == "upgrade" else self.pilot["policy_sha256"]
        comparison["candidate_runtime_check"] = "pass"
        self.assertEqual(self.render(), old)
        self.pilot["stages"][-1]["policy_sha256"] = comparison["candidate_policy_sha256"]
        with self.assertRaises(ValueError):
            self.render()

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
        self.assertNotIn("arm64", row)

    def test_package_row_uses_both_installed_environments(self):
        for difference in ({}, {"python": "3.12.11"}, {"os_version": "15.8.3"}):
            entry = mac_package_job()
            packages = entry["package_install_report"]["packages"]
            packages[1].update(difference)
            with self.subTest(difference=difference):
                matrix = self.render(verify_jobs=[*self.jobs, entry])
                row, = [line for line in matrix.splitlines() if f"/actions/runs/{VERIFY_RUN}/job/150)" in line]
                for record in packages:
                    for field in ("kind", "python", "os_version", "machine"):
                        self.assertIn(record[field], row)
                    self.assertIn(f"{record['kind']} `{record['sha256'][:12]}`", row)
                self.assertNotIn("Inspector", row)
                self.assertNotIn("Codex", row)
                packages.reverse()
                self.assertEqual(self.render(verify_jobs=[*self.jobs, entry]), matrix)

    def test_package_job_rejects_missing_evidence_or_wrong_python_series(self):
        entry = mac_package_job()
        del entry["package_install_report"]
        with self.assertRaises(ValueError):
            self.render(verify_jobs=[*self.jobs, entry])
        for step_name in PACKAGE_STEPS:
            entry = mac_package_job()
            next(step for step in entry["steps"] if step["name"] == step_name)["conclusion"] = "skipped"
            with self.subTest(step=step_name), self.assertRaises(ValueError):
                self.render(verify_jobs=[*self.jobs, entry])
        entry = mac_package_job("3.10")
        entry["package_install_report"] = mac_package_job("3.12")["package_install_report"]
        with self.assertRaises(ValueError):
            self.render(verify_jobs=[*self.jobs, entry])
        entry = mac_package_job()
        entry["steps"] = [s for s in entry["steps"] if s["name"] in CORE_STEPS]
        with self.assertRaises(ValueError):
            self.render(verify_jobs=[*self.jobs, entry])

    def test_x64_install_evidence_enriches_only_its_existing_package_row(self):
        jobs = [entry for entry in self.jobs if entry["name"].startswith("interop")]
        measured = []
        for runner in SYSTEMS:
            for series in ("3.10", "3.12"):
                measured.append(x64_package_job(runner, series, 160 + len(measured)))
        legacy = self.render()
        matrix = self.render(verify_jobs=[*jobs, *measured])
        self.assertEqual(matrix.count("/job/"), legacy.count("/job/"))
        for line in legacy.splitlines():
            if "/job/" in line and "核心包安装" not in line:
                self.assertIn(line, matrix.splitlines())
        for entry in measured:
            row, = [line for line in matrix.splitlines() if f"/actions/runs/{VERIFY_RUN}/job/{entry['id']})" in line]
            for p in entry["package_install_report"]["packages"]:
                for field in ("os_version", "python_platform", "python"):
                    self.assertIn(p[field], row)
                self.assertIn(f"{p['kind']} `{p['sha256'][:12]}`", row)
                if p["system"] == "Linux":
                    self.assertIn("Ubuntu " + p["distro_version"], row)
            self.assertNotIn("Codex", row)
            self.assertNotIn("Inspector", row)

    def test_changes_to_only_one_archives_environment_are_visible(self):
        for runner, field, updated in (("ubuntu-latest", "distro_version", "24.04"),
                                       ("ubuntu-latest", "os_version", "6.17.0-1009-azure"),
                                       ("windows-latest", "os_version", "10.0.26100.23"),
                                       ("windows-latest", "python", "3.12.22")):
            entry = x64_package_job(runner)
            wheel, source = entry["package_install_report"]["packages"]
            source[field] = updated
            jobs = [j for j in self.jobs if j["name"] != entry["name"]]
            with self.subTest(runner=runner, field=field):
                matrix = self.render(verify_jobs=[*jobs, entry])
                row, = [line for line in matrix.splitlines() if "/job/160)" in line]
                environment = row.split("|")[2]
                self.assertIn("wheel", environment)
                self.assertIn("sdist", environment)
                self.assertIn(wheel[field], environment.split("sdist")[0])
                self.assertIn(source[field], environment.split("sdist")[1])

    def test_each_x64_archive_requires_matching_machine_tag_bit_width_and_result(self):
        for runner in SYSTEMS:
            jobs = [j for j in self.jobs if j["name"] != f"test ({runner}, 3.12)"]
            cases = [("pointer_bits", 32), ("pointer_bits", 64.0), ("pointer_bits", "64"), ("machine", "arm64"),
                     ("python_platform", "win32"), ("python", "3.10.11"), ("implementation", "PyPy"),
                     ("filename", "other.whl"), ("policy_check", "review"), ("proxy_ping", 1)]
            if runner == "ubuntu-latest":
                cases.extend([("distro_id", "debian"), ("distro_version", "7.0.0-1019-azure"),
                              ("os_version", "7.0.0|other column")])
            else:
                cases.append(("os_version", "Windows Server 2025"))
            for index in (0, 1):
                for field, wrong in cases:
                    entry = x64_package_job(runner)
                    entry["package_install_report"]["packages"][index][field] = wrong
                    with self.subTest(runner=runner, kind=index, field=field, value=wrong), self.assertRaises(ValueError):
                        self.render(verify_jobs=[*jobs, entry])

    def test_missing_or_swapped_x64_receipts_cannot_fall_back_to_job_labels(self):
        entry = x64_package_job("windows-latest")
        jobs = [j for j in self.jobs if j["name"] != entry["name"]]
        del entry["package_install_report"]
        with self.assertRaises(ValueError):
            self.render(verify_jobs=[*jobs, entry])
        entry["package_install_report"] = x64_package_job("ubuntu-latest")["package_install_report"]
        with self.assertRaises(ValueError):
            self.render(verify_jobs=[*jobs, entry])
        entry = x64_package_job("windows-latest")
        # 同版本的两份有效安装也须属于本矩阵选择的网关版本。
        for package in entry["package_install_report"]["packages"]:
            package["installed_version"] = "0.3.0a2"
            package["filename"] = package["filename"].replace("0.3.0a1", "0.3.0a2")
        with self.assertRaises(ValueError):
            self.render(verify_jobs=[*jobs, entry])

    def test_inactive_platform_steps_preserve_previous_receipts_and_label_only_rows(self):
        previous = mac_package_job()
        current = deepcopy(previous)
        current["steps"].extend({"name": name, "status": "completed", "conclusion": "skipped"}
                                for name in X64_PACKAGE_STEPS)
        for record in current["package_install_report"]["packages"]:
            record.update(pointer_bits=64, python_platform="macosx-11.0-arm64")
        old_x64_jobs = deepcopy(self.jobs)
        for entry in old_x64_jobs:
            if entry["name"].startswith("test ("):
                entry["steps"].extend({"name": name, "status": "completed", "conclusion": "skipped"}
                                      for name in PACKAGE_STEPS)
        self.assertEqual(self.render(verify_jobs=[*old_x64_jobs, current]), self.render(verify_jobs=[*self.jobs, previous]))

    def test_package_receipt_requires_exactly_one_wheel_and_sdist(self):
        entry = mac_package_job()
        report = entry["package_install_report"]
        wheel, source = report["packages"]
        for bad in ([wheel], [wheel, wheel], [wheel, source, source], [wheel, {**source, "sha256": wheel["sha256"]}]):
            report["packages"] = bad
            with self.subTest(kinds=[p["kind"] for p in bad]), self.assertRaises(ValueError):
                self.render(verify_jobs=[*self.jobs, entry])
        for field, value in (("schema_version", True), ("status", "failed"), ("scope", "preflight")):
            entry = mac_package_job()
            entry["package_install_report"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.render(verify_jobs=[*self.jobs, entry])
        entry = mac_package_job()
        for package in entry["package_install_report"]["packages"]:
            package["installed_version"] = "0.3.0a2"
            package["filename"] = package["filename"].replace("0.3.0a1", "0.3.0a2")
        with self.assertRaises(ValueError):
            self.render(verify_jobs=[*self.jobs, entry])

    def test_protocol_is_shown_only_for_two_checked_installations(self):
        for entry in (mac_package_job(), x64_package_job("windows-latest"), x64_package_job("ubuntu-latest")):
            with self.subTest(job=entry["name"]):
                report = entry["package_install_report"]
                protocol_step = {"name": PROTOCOL_STEP, "status": "completed", "conclusion": "success"}
                legacy = package_row(entry, VERIFY_RUN, "0.3.0a1")
                self.assertNotIn("握手", legacy)
                entry["steps"].append(protocol_step)
                with self.assertRaises(ValueError):
                    package_row(entry, VERIFY_RUN, "0.3.0a1")
                report["schema_version"] = 2
                for package in report["packages"]:
                    package["protocol_version"] = "2025-06-18"
                row = package_row(entry, VERIFY_RUN, "0.3.0a1")
                self.assertIn("MCP 2025-06-18 握手", row)
                self.assertIn("CPython", row)
                for package in report["packages"]:
                    value = package.pop("protocol_version")
                    with self.assertRaises(ValueError):
                        package_row(entry, VERIFY_RUN, "0.3.0a1")
                    package["protocol_version"] = value
                entry["steps"].pop()
                with self.assertRaises(ValueError):
                    package_row(entry, VERIFY_RUN, "0.3.0a1")

    def test_partial_protocol_job_cannot_fall_back_to_legacy_row(self):
        step = {"name": PROTOCOL_STEP, "status": "completed", "conclusion": "success"}
        entry = mac_package_job()
        for steps in ([{**step, "conclusion": "skipped"}], [{**step, "conclusion": "failure"}], [step, step]):
            with self.subTest(steps=steps), self.assertRaises(ValueError):
                package_row({**entry, "steps": entry["steps"] + steps}, VERIFY_RUN, "0.3.0a1")
        without_report = job(150, "test (macos-15, 3.12)", "macos-15", VERIFY_RUN, [*CORE_STEPS, PROTOCOL_STEP])
        with self.assertRaises(ValueError):
            package_row(without_report, VERIFY_RUN, "0.3.0a1")

    def test_package_receipt_validates_each_archive_and_measured_platform(self):
        cases = (
            ("installed_version", "0.3.0a2"), ("filename", "other-archive"), ("sha256", "z" * 64),
            ("proxy_ping", 1), ("policy_check", "review"), ("system", "Linux"), ("machine", "x86_64"),
            ("os_version", "14.8.2"), ("python", "3.10.11"), ("implementation", "PyPy"),
        )
        for index in (0, 1):
            for field, value in cases:
                entry = mac_package_job()
                record = entry["package_install_report"]["packages"][index]
                record[field] = value
                with self.subTest(kind=record["kind"], field=field), self.assertRaises(ValueError):
                    self.render(verify_jobs=[*self.jobs, entry])

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
