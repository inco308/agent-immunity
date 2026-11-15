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
            actual, interop, selected, report = evidence.fetch_evidence(COMMIT, 11, 22)
        self.assertEqual((actual, selected, report), (verify_jobs, pilot_job, {"name": "codex-time-lifecycle"}))
        self.assertEqual(interop, {key: {"name": "interop-" + key} for key in ("ubuntu-latest", "windows-latest")})
        self.assertEqual([(r, n) for r, n, _ in downloads],
                         [(11, "interop-ubuntu-latest"), (11, "interop-windows-latest"), (22, "codex-time-lifecycle")])
        self.assertTrue(all(not directory.exists() for _, _, directory in downloads))

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
        with patch.object(evidence, "_api", side_effect=[first, pilot, first, {**pilot, "run_attempt": 2}]), \
                patch.object(evidence, "_jobs", side_effect=[[job(11, 1, "test")], [job(22, 2, "lifecycle")]]), \
                patch.object(evidence, "_report", return_value={}), self.assertRaises(ValueError):
            evidence.fetch_evidence(COMMIT, 11, 22)

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
