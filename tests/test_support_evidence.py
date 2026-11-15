"""用合成 GitHub 记录验证支持矩阵取证的来源、尝试和产物绑定。"""

import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

from scripts import support_evidence as evidence


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
