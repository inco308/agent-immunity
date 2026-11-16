"""用合成 GitHub 记录验证支持矩阵取证的来源、尝试和产物绑定。"""

import hashlib
import io
import json
from pathlib import Path
import subprocess
import unittest
import zipfile
from unittest.mock import Mock, patch

from scripts import support_evidence as evidence
from tests.test_x64_install_receipt import install_receipt


COMMIT = "a" * 40


def run_record(run_id, workflow):
    repository = {"id": 1381124176, "full_name": "inco308/agent-immunity"}
    return {"id": run_id, "head_sha": COMMIT, "event": "push", "head_branch": "main",
            "status": "completed", "conclusion": "success", "run_attempt": 1,
            "path": f".github/workflows/{workflow}.yml", "repository": repository,
            "head_repository": dict(repository)}


def job(run_id, number, name):
    return {"id": number, "run_id": run_id, "run_attempt": 1, "head_sha": COMMIT,
            "status": "completed", "conclusion": "success", "name": name}


def packaging_job(number, system="macos-15", python="3.12", conclusion="success"):
    steps = [{"name": name, "status": "completed", "conclusion": conclusion}
             for name in ("核对两个安装环境的 macOS、架构和 Python 系列", "保存 macOS 安装验收报告")]
    return {**job(11, number, f"test ({system}, {python})"), "labels": [system], "steps": steps}


def x64_steps(conclusion="success"):
    return [{"name": name, "status": "completed", "conclusion": conclusion} for name in (
        "核对两个安装环境的 x64 系统、架构和 Python 系列", "保存 x64 安装验收报告",
    )]


class SupportEvidenceTests(unittest.TestCase):
    def test_only_expected_attempts_and_three_scoped_artifacts_are_read(self):
        verify_jobs = [job(11, 1, "first"), job(11, 2, "second")]
        pilot_job = job(22, 3, "lifecycle")
        base = "repos/inco308/agent-immunity/actions/runs"
        routes = {
            f"{base}/11": run_record(11, "ci"),
            f"{base}/22": run_record(22, "codex-time-pilot"),
            f"{base}/11/attempts/1/jobs?per_page=100": [
                {"total_count": 2, "jobs": [row]} for row in verify_jobs
            ],
            f"{base}/22/attempts/1/jobs?per_page=100": [{"total_count": 1, "jobs": [pilot_job]}],
        }
        downloads = []

        def gh(args):
            if args[0] == "api":
                endpoint = args[-1]
                options = ["--paginate", "--slurp"] if "/jobs?" in endpoint else []
                self.assertEqual(args, ["api", "--hostname", "github.com", *options, endpoint])
                return json.dumps(routes[endpoint]).encode()
            run_id, name, directory = int(args[2]), args[6], Path(args[8])
            self.assertEqual(args, ["run", "download", str(run_id), "--repo", "github.com/inco308/agent-immunity",
                                    "--name", name, "--dir", str(directory)])
            self.assertEqual(list(directory.iterdir()), [])
            downloads.append((run_id, name, directory))
            (directory / "report.json").write_text(json.dumps({"name": name}), encoding="utf-8")
            return b""

        with patch.object(evidence, "_gh", side_effect=gh):
            actual, interop, selected, report, native = evidence.fetch_evidence(COMMIT, 11, 22)
        self.assertEqual(native, [])
        self.assertEqual((actual, selected, report), (verify_jobs, pilot_job, {"name": "codex-time-lifecycle"}))
        self.assertEqual(interop, {key: {"name": "interop-" + key} for key in ("ubuntu-latest", "windows-latest")})
        self.assertEqual([(r, n) for r, n, _ in downloads],
                         [(11, "interop-ubuntu-latest"), (11, "interop-windows-latest"), (22, "codex-time-lifecycle")])
        self.assertTrue(all(not directory.exists() for _, _, directory in downloads))

    def test_install_reports_are_bound_to_the_verify_run_axis_and_filename(self):
        mac310 = packaging_job(1, python="3.10")
        mac312 = packaging_job(2)
        historical = {**packaging_job(3, python="3.13"), "steps": []}
        linux = packaging_job(4, system="ubuntu-latest", conclusion="skipped")
        windows = packaging_job(5, system="windows-latest", conclusion="skipped")
        unrelated = {**packaging_job(6), "name": "preview test (macos-15, 3.12)"}
        verify_jobs = [mac310, mac312, historical, linux, windows, unrelated]
        pilot = [job(22, 7, "lifecycle")]
        with patch.object(evidence, "_verify_run"), patch.object(evidence, "_jobs", side_effect=[verify_jobs, pilot]), \
                patch.object(evidence, "_report", side_effect=lambda run, name, *args: {"artifact": name}) as read:
            actual, _, _, _, _ = evidence.fetch_evidence(COMMIT, 11, 22)
        package_calls = [c.args for c in read.call_args_list if len(c.args) == 3]
        self.assertEqual(package_calls, [(11, "package-install-macos-15-py3.10", "package-install.json"),
                                         (11, "package-install-macos-15-py3.12", "package-install.json")])
        for index, call in enumerate(package_calls):
            self.assertEqual(actual[index], {**verify_jobs[index], "package_install_report": {"artifact": call[1]}})
            self.assertNotIn("package_install_report", verify_jobs[index])
        self.assertEqual(actual[2:], verify_jobs[2:])

    def test_partial_failed_duplicate_or_wrong_platform_packaging_proof_is_rejected(self):
        mac = packaging_job(1)
        check, upload = mac["steps"]
        bad = ([check], [upload], [check, upload, upload], [check, {**upload, "conclusion": "skipped"}],
               [{**check, "status": "in_progress"}, upload])
        candidates = [[{**mac, "steps": steps}] for steps in bad]
        candidates.extend((
            [{**mac, "steps": None}], [{**mac, "conclusion": "failure"}], [{**mac, "labels": ["windows-latest"]}],
            [{**mac, "labels": ["macos-15", "ubuntu-latest"]}], [packaging_job(2, system="windows-latest")],
            [mac, packaging_job(2)],
        ))
        for jobs in candidates:
            with self.subTest(jobs=jobs), patch.object(evidence, "_verify_run"), \
                    patch.object(evidence, "_jobs", side_effect=[jobs, [job(22, 3, "lifecycle")]]), \
                    patch.object(evidence, "_report") as read, self.assertRaises(ValueError):
                evidence.fetch_evidence(COMMIT, 11, 22)
            read.assert_not_called()

    def test_x64_and_mac_jobs_only_download_their_own_reports(self):
        jobs = []
        expected = []
        for runner in ("ubuntu-latest", "windows-latest", "macos-15"):
            mac = runner == "macos-15"
            for series in ("3.10", "3.12"):
                record = packaging_job(len(jobs) + 1, runner, series, "success" if mac else "skipped")
                record["steps"].extend(x64_steps("skipped" if mac else "success"))
                jobs.append(record)
                expected.append((11, f"package-install-{runner}-py{series}", "package-install.json"))
        legacy = packaging_job(7, "ubuntu-latest", "3.11", "skipped")
        pilot = job(22, 8, "lifecycle")
        with patch.object(evidence, "_verify_run") as gate, \
                patch.object(evidence, "_jobs", side_effect=[[*jobs, legacy], [pilot]]), \
                patch.object(evidence, "_report", side_effect=lambda run, name, *args: {"source": name}) as read:
            selected, _, _, _, _ = evidence.fetch_evidence(COMMIT, 11, 22)
        self.assertEqual([c.args for c in read.call_args_list if len(c.args) == 3], expected)
        for selected_job, (_, artifact, _) in zip(selected, expected):
            self.assertEqual(selected_job["package_install_report"], {"source": artifact})
        self.assertEqual(selected[-1], legacy)
        self.assertEqual([c.args for c in gate.call_args_list],
                         [(COMMIT, 11, "ci"), (COMMIT, 22, "codex-time-pilot")] * 2)

    def test_incomplete_skipped_or_cross_platform_x64_steps_are_not_evidence(self):
        linux = packaging_job(1, "ubuntu-latest", conclusion="skipped")
        check, upload = x64_steps()
        for steps in ([check], [upload], [check, check, upload], [check, {**upload, "status": "in_progress"}],
                      x64_steps("skipped"), x64_steps("failure"), x64_steps() + packaging_job(1)["steps"]):
            with self.subTest(steps=steps), self.assertRaises(ValueError):
                evidence.package_artifact_name({**linux, "steps": steps})
        mac = packaging_job(2)
        for steps in (x64_steps(), x64_steps("skipped")[:1], [check, {**upload, "conclusion": "skipped"}]):
            with self.subTest(steps=steps), self.assertRaises(ValueError):
                evidence.package_artifact_name({**mac, "steps": mac["steps"] + steps})
        for runner in ("ubuntu-latest", "windows-latest"):
            record = packaging_job(3, runner, conclusion="skipped")
            record["steps"].extend(x64_steps())
            with self.subTest(runner=runner):
                with self.assertRaises(ValueError):
                    evidence.package_artifact_name({**record, "labels": ["macos-15"]})
                with self.assertRaises(ValueError):
                    evidence.package_artifact_name({**record, "conclusion": "failure"})
                with patch.object(evidence, "_verify_run"), \
                        patch.object(evidence, "_jobs", side_effect=[[record], [job(22, 4, "lifecycle")]]), \
                        patch.object(evidence, "_report", side_effect=ValueError("报告缺失")) as read:
                    with self.assertRaisesRegex(ValueError, "报告缺失"):
                        evidence.fetch_evidence(COMMIT, 11, 22)
                    read.assert_called_once_with(11, f"package-install-{runner}-py3.12", "package-install.json")

    def test_package_download_requires_the_specific_report_file(self):
        def wrong_file(args):
            (Path(args[-1]) / "report.json").write_text("{}", encoding="utf-8")
            return b""

        with patch.object(evidence, "_gh", side_effect=wrong_file), self.assertRaisesRegex(ValueError, "package-install"):
            evidence._report(11, "package-install-macos-15-py3.12", "package-install.json")
        with patch.object(evidence, "_verify_run"), \
                patch.object(evidence, "_jobs", side_effect=[[packaging_job(1)], [job(22, 2, "lifecycle")]]), \
                patch.object(evidence, "_report", side_effect=ValueError("报告缺失")) as read, self.assertRaises(ValueError):
            evidence.fetch_evidence(COMMIT, 11, 22)
        read.assert_called_once_with(11, "package-install-macos-15-py3.12", "package-install.json")

    def test_only_observed_native_jobs_read_their_own_named_reports_in_stable_order(self):
        linux = job(22, 1, "lifecycle")
        mac = job(22, 2, "lifecycle-macos-arm64")
        windows = job(22, 3, "lifecycle-windows-x64")
        unrelated = job(22, 4, "lifecycle-windows-x64-preview")
        mac_artifact = "codex-time-lifecycle-macos-arm64"
        windows_artifact = "codex-time-lifecycle-windows-x64"
        for optional, expected in (([windows, mac], [(mac, mac_artifact), (windows, windows_artifact)]),
                                   ([mac], [(mac, mac_artifact)]), ([windows], [(windows, windows_artifact)])):
            with self.subTest(optional=optional), patch.object(evidence, "_verify_run"), \
                    patch.object(evidence, "_jobs", side_effect=[[], [unrelated, *optional, linux]]), \
                    patch.object(evidence, "_report", side_effect=lambda run, name: {"name": name}) as download:
                *_, native = evidence.fetch_evidence(COMMIT, 11, 22)
                self.assertEqual(native, [(selected, {"name": name}) for selected, name in expected])
                self.assertEqual([c.args for c in download.call_args_list], [
                    (11, "interop-ubuntu-latest"), (11, "interop-windows-latest"), (22, "codex-time-lifecycle"),
                    *((22, name) for _, name in expected),
                ])

    def test_ambiguous_or_incomplete_native_job_cannot_be_silently_dropped(self):
        linux = job(22, 1, "lifecycle")
        for name in ("lifecycle-macos-arm64", "lifecycle-windows-x64"):
            native = job(22, 2, name)
            for rows in ([native, job(22, 3, name)], [{**native, "conclusion": "skipped"}],
                         [{**native, "status": "in_progress"}]):
                with self.subTest(name=name, rows=rows), patch.object(evidence, "_verify_run"), \
                        patch.object(evidence, "_jobs", side_effect=[[], [linux, *rows]]), \
                        patch.object(evidence, "_report") as download:
                    with self.assertRaises(ValueError):
                        evidence.fetch_evidence(COMMIT, 11, 22)
                    download.assert_not_called()

    def test_missing_native_artifact_fails_the_snapshot(self):
        jobs = [job(22, 1, "lifecycle"), job(22, 2, "lifecycle-macos-arm64")]
        with patch.object(evidence, "_verify_run"), patch.object(evidence, "_jobs", side_effect=[[], jobs]), \
                patch.object(evidence, "_report", side_effect=[{}, {}, {}, ValueError("报告缺失")]) as download:
            with self.assertRaisesRegex(ValueError, "报告缺失"):
                evidence.fetch_evidence(COMMIT, 11, 22)
        self.assertEqual(download.call_args.args, (22, "codex-time-lifecycle-macos-arm64"))

    def test_unusable_run_or_input_cannot_authorize_artifact_download(self):
        with patch.object(evidence, "_gh") as gh:
            for args in (("a" * 8, 11, 22), (COMMIT, False, 22), (COMMIT, -1, 22), (COMMIT, 11, 11)):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    evidence.fetch_evidence(*args)
            gh.assert_not_called()
        for key, value in (
            ("head_sha", "b" * 40), ("event", "pull_request"), ("id", 99), ("head_branch", "other"),
            ("path", ".github/workflows/other.yml"), ("run_attempt", 2), ("status", "queued"),
            ("conclusion", "failure"), ("repository", {}), ("head_repository", {"full_name": "other/repo"}),
        ):
            record = {**run_record(11, "ci"), key: value}
            with self.subTest(field=key), patch.object(evidence, "_api", return_value=record), \
                    patch.object(evidence, "_report") as download:
                with self.assertRaises(ValueError):
                    evidence.fetch_evidence(COMMIT, 11, 22)
                download.assert_not_called()

    def test_partial_or_mixed_job_pages_and_ambiguous_pilot_fail(self):
        first = job(11, 1, "test")
        for rows, count in (([first], 2), ([first, first], 2), ([{**first, "run_id": 22}], 1),
                            ([{**first, "head_sha": "wrong"}], 1), ([{**first, "run_attempt": 2}], 1)):
            with self.subTest(rows=rows), patch.object(evidence, "_api", return_value=[{"total_count": count, "jobs": rows}]), \
                    self.assertRaises(ValueError):
                evidence._jobs(COMMIT, 11)
        for rows in ([], [job(22, 1, "lifecycle"), job(22, 2, "lifecycle")],
                     [{**job(22, 1, "lifecycle"), "conclusion": "cancelled"}]):
            with self.subTest(rows=rows), patch.object(evidence, "_verify_run"), \
                    patch.object(evidence, "_jobs", side_effect=[[first], rows]), \
                    patch.object(evidence, "_report") as reports:
                with self.assertRaises(ValueError):
                    evidence.fetch_evidence(COMMIT, 11, 22)
                reports.assert_not_called()

    def test_rerun_during_download_invalidates_reports(self):
        first, pilot = run_record(11, "ci"), run_record(22, "codex-time-pilot")
        pilot_jobs = [job(22, 2, "lifecycle"), job(22, 3, "lifecycle-windows-x64")]
        with patch.object(evidence, "_api", side_effect=[first, pilot, first, {**pilot, "run_attempt": 2}]), \
                patch.object(evidence, "_jobs", side_effect=[[job(11, 1, "test")], pilot_jobs]), \
                patch.object(evidence, "_report", return_value={}) as download, self.assertRaises(ValueError):
            evidence.fetch_evidence(COMMIT, 11, 22)
        self.assertEqual(download.call_args.args, (22, "codex-time-lifecycle-windows-x64"))

    def test_failed_download_never_reuses_stale_file_or_echoes_signed_url(self):
        directories = []

        def interrupted(args):
            directory = Path(args[-1])
            directories.append(directory)
            if len(directories) == 1:
                (directory / "report.json").write_text("{}", encoding="utf-8")
                raise evidence._NetworkError()
            return b""

        with patch.object(evidence, "_gh", side_effect=interrupted), self.assertRaises(ValueError):
            evidence._report(22, "codex-time-lifecycle")
        self.assertNotEqual(*directories)
        for stderr in (b"http 410 GITHUB_FAKE_SIGNED_URL", b"http 404 GITHUB_FAKE_SIGNED_URL"):
            with patch.object(subprocess, "run", return_value=Mock(returncode=1, stderr=stderr)), \
                    self.assertRaises(ValueError) as error:
                evidence._report(22, "codex-time-lifecycle")
            self.assertNotIn("GITHUB_FAKE_SIGNED_URL", str(error.exception))


class PreviewPairEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.branch = "ci/reviewed-preview"
        self.run = {**run_record(11, "ci"), "head_branch": self.branch}
        self.job = packaging_job(47, "ubuntu-latest", "3.12", conclusion="skipped")
        self.job["steps"].extend(x64_steps())
        self.job["steps"].extend({"name": name, "status": "completed", "conclusion": "success"} for name in (
            "构建源码分发包及其 wheel", "检查归档内容、独立安装和 SHA-256", evidence.PROTOCOL_STEP, "保存可下载的发行文件",
        ))
        self.logs = b""
        for step, number in (("保存 x64 安装验收报告", 55), ("保存可下载的发行文件", 56)):
            self.logs += (f"{self.job['name']}\t{step}\t2026-11-16T10:00:00Z Artifact download URL: "
                          f"{evidence.REPO_URL}/actions/runs/11/artifacts/{number}\n").encode()
        self.report = install_receipt("ubuntu-latest", "3.12")
        self.report["schema_version"] = 2
        self.dist = {}
        sums = []
        for p in self.report["packages"]:
            data = p["kind"].encode()
            self.dist[p["filename"]] = data
            p.update(sha256=hashlib.sha256(data).hexdigest(), protocol_version="2025-06-18")
            sums.append(f"{p['sha256']}  {p['filename']}")
        self.dist["SHA256SUMS"] = "\r\n".join(reversed(sums)).encode()

    def download(self, commit, run_id, name, *, expected_id):
        self.assertEqual((commit, run_id), (COMMIT, 11))
        if (name, expected_id) == ("agent-immunity-dist", 56):
            members = self.dist
        elif (name, expected_id) == ("package-install-ubuntu-latest-py3.12", 55):
            members = {"package-install.json": json.dumps(self.report).encode()}
        else:
            raise ValueError("上传日志与产物元数据不符")
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for filename, data in members.items():
                archive.writestr(filename, data)
        return {"id": expected_id, "data": stream.getvalue()}

    def fetch(self, branch=None):
        args = () if branch is None else (branch,)
        with patch.object(evidence, "_api", side_effect=[
                self.run, [{"total_count": 1, "jobs": [self.job]}], self.run]), \
                patch.object(evidence, "_gh", return_value=self.logs), \
                patch.object(evidence, "_download_artifact", side_effect=self.download):
            return evidence.fetch_preview_pair(COMMIT, 11, *args)

    def test_only_explicit_reviewed_branch_can_replace_main(self):
        self.assertEqual(self.fetch(self.branch), (self.job, self.report, 56, 55))
        with self.assertRaises(ValueError):
            self.fetch()
        for fields in ({"event": "pull_request"}, {"run_attempt": 2}, {"head_sha": "b" * 40},
                       {"head_repository": {"id": 12, "full_name": "another/repo"}}):
            with self.subTest(fields=fields), patch.dict(self.run, fields), self.assertRaises(ValueError):
                self.fetch(self.branch)

    def test_both_upload_ids_must_come_from_the_same_job_and_steps(self):
        good = self.logs
        for changed in (
                good.replace(b"/artifacts/55", b"/artifacts/57"),
                good.replace(b"/runs/11/", b"/runs/12/"),
                good.replace(b"test (ubuntu-latest, 3.12)", b"test (ubuntu-latest, 3.10)", 1),
                good.replace("保存 x64 安装验收报告".encode(), "其他上传步骤".encode()), good + good):
            self.logs = changed
            with self.subTest(log=changed), self.assertRaises(ValueError):
                self.fetch(self.branch)
        self.logs = good
        self.job["steps"][-1]["conclusion"] = "skipped"
        with self.assertRaises(ValueError):
            self.fetch(self.branch)

    def test_same_name_different_archive_and_false_sums_are_rejected(self):
        for filename in self.dist:
            with self.subTest(filename=filename), patch.dict(self.dist, {filename: b"other build"}), self.assertRaises(ValueError):
                self.fetch(self.branch)
        with patch.dict(self.report, {"schema_version": 1}), self.assertRaises(ValueError):
            self.fetch(self.branch)


class RecoveryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.dispatch = {**run_record(37, "codex-time-pilot"), "event": "workflow_dispatch",
                         "head_branch": "pilot/recovery"}
        self.job = {**job(37, 43, "lifecycle"), "labels": ["ubuntu-24.04"],
                    "steps": [{"name": step, "status": "completed", "conclusion": "success"}
                              for step in evidence.RECOVERY_STEPS]}
        self.routes = {
            f"{evidence.RUNS_API}/37": self.dispatch,
            f"{evidence.RUNS_API}/37/attempts/1/jobs?per_page=100": [{"total_count": 1, "jobs": [self.job]}],
        }
        self.archives = {}
        self.report = {"schema_version": 2, "gateway_mode": "verified_previews", "upstreams": {}}
        for slot, sha, run, artifact in (("previous", "b" * 40, 31, 51), ("candidate", "c" * 40, 32, 52)):
            data = f"{slot} wheel".encode()
            self.report["upstreams"][slot] = {"gateway": {
                "commit": sha, "run_id": run, "artifact_id": artifact, "version": "0.3.0a1",
                "wheel_sha256": hashlib.sha256(data).hexdigest(),
            }}
            self.routes[f"{evidence.RUNS_API}/{run}"] = {**run_record(run, "ci"), "head_sha": sha}
            self.archive(run, sha, artifact, "agent-immunity-dist", {"agent_immunity-0.3.0a1-py3-none-any.whl": data})
        self.policy_archive()

    def archive(self, run, sha, artifact, name, members):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as output:
            for key, data in members.items():
                output.writestr(key, data)
        data = stream.getvalue()
        self.archives[f"repos/{evidence.REPOSITORY}/actions/artifacts/{artifact}/zip"] = data
        self.routes[f"{evidence.RUNS_API}/{run}/artifacts?name={name}&per_page=100"] = {
            "total_count": 1, "artifacts": [{
                "id": artifact, "name": name, "expired": False, "size_in_bytes": len(data),
                "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                "workflow_run": {"id": run, "head_sha": sha, "repository_id": evidence.REPOSITORY_ID,
                                 "head_repository_id": evidence.REPOSITORY_ID},
            }],
        }

    def policy_archive(self, marker=b"1\n"):
        self.archive(37, COMMIT, 57, "codex-time-policy-recovery",
                     {"report.json": json.dumps(self.report).encode(), "candidate-exit.txt": marker})

    def fetch(self):
        with patch.object(evidence, "_api", side_effect=lambda key, **_: self.routes[key]), \
                patch.object(evidence, "_gh", side_effect=lambda args: self.archives[args[-1]]):
            return evidence.fetch_recovery_evidence(COMMIT, 37)

    def test_dispatch_reads_two_main_builds_and_exact_wheel_bytes(self):
        self.assertEqual(self.fetch(), (self.job, self.report, 57))
        self.report["upstreams"]["candidate"]["gateway"]["wheel_sha256"] = "d" * 64
        self.policy_archive()
        with self.assertRaisesRegex(ValueError, "wheel"):
            self.fetch()

    def test_retain_original_archives_once_after_final_run_check(self):
        captured = {}
        for rerun in (False, True):
            with self.subTest(rerun=rerun):
                downloads = []

                def download(args):
                    endpoint = args[-1]
                    downloads.append(endpoint)
                    if rerun and len(downloads) == 3:
                        self.dispatch["run_attempt"] = 2
                    return self.archives[endpoint]

                with patch.object(evidence, "_api", side_effect=lambda key, **_: self.routes[key]), \
                        patch.object(evidence, "_gh", side_effect=download):
                    if rerun:
                        captured = {"recovery": "existing"}
                        with self.assertRaises(ValueError):
                            evidence.fetch_recovery_evidence(COMMIT, 37, archives=captured)
                        self.assertEqual(captured, {"recovery": "existing"})
                    else:
                        self.assertEqual(evidence.fetch_recovery_evidence(COMMIT, 37, archives=captured),
                                         (self.job, self.report, 57))
                        self.assertEqual(set(captured), {"recovery", "previous", "candidate"})
                        for role, number in (("recovery", 57), ("previous", 51), ("candidate", 52)):
                            raw = self.archives[f"repos/{evidence.REPOSITORY}/actions/artifacts/{number}/zip"]
                            self.assertEqual(captured[role], {"id": number, "sha256": hashlib.sha256(raw).hexdigest(),
                                                              "data": raw})
                self.assertCountEqual(downloads, self.archives.keys())

    def test_wrong_marker_single_gateway_and_skipped_download_fail(self):
        self.policy_archive(marker=b"2\n")
        with self.assertRaisesRegex(ValueError, "退出码"):
            self.fetch()
        self.report["schema_version"] = 1
        self.policy_archive()
        with self.assertRaisesRegex(ValueError, "两份"):
            self.fetch()
        self.job["steps"][0]["conclusion"] = "skipped"
        with self.assertRaises(ValueError):
            self.fetch()

    def test_exact_member_set_is_optional_for_original_archives(self):
        raw = self.archives[f"repos/{evidence.REPOSITORY}/actions/artifacts/57/zip"]
        members = {"candidate-exit.txt": 3}
        self.assertEqual(evidence.read_artifact_files(raw, members), {"candidate-exit.txt": b"1\n"})
        with self.assertRaisesRegex(ValueError, "额外成员"):
            evidence.read_artifact_files(raw, members, exact=True)

    def test_run_artifact_mismatch_and_reruns_fail(self):
        meta = self.routes[f"{evidence.RUNS_API}/32/artifacts?name=agent-immunity-dist&per_page=100"]["artifacts"][0]
        for obj, key, wrong in (
                (self.dispatch, "event", "push"), (self.dispatch, "run_attempt", 2),
                (self.routes[f"{evidence.RUNS_API}/31"], "head_branch", "preview"),
                (meta, "id", 51), (meta["workflow_run"], "head_sha", COMMIT),
                (meta["workflow_run"], "head_repository_id", 1), (meta, "expired", True),
                (meta, "digest", "sha256:" + "0" * 64)):
            with self.subTest(key=key, wrong=wrong), patch.dict(obj, {key: wrong}), self.assertRaises(ValueError):
                self.fetch()
