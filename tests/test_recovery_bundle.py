"""使用合成的在线收据和原始 ZIP 验证恢复证据留存及断网复核。"""
import hashlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import zipfile

from scripts import recovery_bundle as bundle
from scripts.support_evidence import RECOVERY_STEPS
from tests.support import temporary_directory
from tests.test_recovery_matrix import PILOT_COMMIT, RUN, recovery_report
from tests.test_support_matrix import job


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive(files):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as zipped:
        for name, data in files.items():
            zipped.writestr(name, data)
    return result.getvalue()


def members(data):
    with zipfile.ZipFile(io.BytesIO(data)) as zipped:
        return {name: zipped.read(name) for name in zipped.namelist()}


class RecoveryBundleTests(unittest.TestCase):
    def setUp(self):
        temp = temporary_directory()
        self.addCleanup(temp.cleanup)
        self.dest = Path(temp.name) / "retained.zip"
        self.report = recovery_report()
        self.job = job(35001, "lifecycle", "ubuntu-24.04", RUN, RECOVERY_STEPS)
        self.job["head_sha"] = PILOT_COMMIT
        self.archives = {}
        for role in ("previous", "candidate"):
            wheel = archive({"agent_immunity/build.txt": role.encode()})
            source = self.report["upstreams"][role]["gateway"]
            source["wheel_sha256"] = sha(wheel)
            for record in ([self.report["stages"][0], self.report["recovery"]]
                           if role == "previous" else [self.report["fault"]]):
                record["gateway"]["wheel_sha256"] = sha(wheel)
            self.source_archive(role, source["artifact_id"], {"agent_immunity-0.3.0a1-py3-none-any.whl": wheel})
        self.source_archive("recovery", 35002, {"report.json": json.dumps(self.report).encode(),
                                                "candidate-exit.txt": b"1\n"})

    def source_archive(self, role, artifact_id, files):
        data = archive(files)
        self.archives[role] = {"id": artifact_id, "data": data, "sha256": sha(data)}

    def fetch(self, commit, run, *, archives):
        self.assertEqual((commit, run), (PILOT_COMMIT, RUN))
        archives.update(self.archives)
        return self.job, self.report, 35002

    def capture(self):
        with patch.object(bundle, "fetch_recovery_evidence", side_effect=self.fetch):
            return bundle.capture(PILOT_COMMIT, RUN, self.dest)

    def test_offline_verification_replays_exact_archives_and_original_time(self):
        before = datetime.now(timezone.utc).replace(microsecond=0)
        anchor = self.capture()
        after = datetime.now(timezone.utc)
        raw = self.dest.read_bytes()
        self.assertEqual(anchor, sha(raw))
        files = members(raw)
        self.assertEqual(set(files), {"manifest.json", "previous.zip", "candidate.zip", "recovery.zip"})
        for role, original in self.archives.items():
            self.assertEqual(files[role + ".zip"], original["data"])
        manifest = json.loads(files["manifest.json"])
        timestamp = manifest["verified_at"]
        recorded = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        self.assertLessEqual(before, recorded)
        self.assertLessEqual(recorded, after)
        with patch("subprocess.Popen", side_effect=AssertionError("离线复核不能调用 git 或 gh")), \
                patch("socket.socket", side_effect=AssertionError("离线复核不能访问网络")):
            rendered = bundle.verify(self.dest, anchor)
        self.assertIn("ubuntu-24.04", rendered)
        self.assertIn(timestamp, rendered)
        self.assertIn(PILOT_COMMIT, rendered)
        for role in ("previous", "candidate"):
            self.assertIn(self.report["upstreams"][role]["gateway"]["wheel_sha256"][:12], rendered)

    def test_wrong_anchor_or_changed_bytes_fail(self):
        anchor = self.capture()
        with self.assertRaises(ValueError):
            bundle.verify(self.dest, "e" * 64)
        with self.dest.open("ab") as output:
            output.write(b"modified")
        with self.assertRaises(ValueError):
            bundle.verify(self.dest, anchor)

    def test_interrupted_capture_and_publication_do_not_replace_a_previous_bundle(self):
        with patch.object(bundle, "fetch_recovery_evidence", side_effect=ValueError("在线产物已过期")), \
                self.assertRaises(ValueError):
            bundle.capture(PILOT_COMMIT, RUN, self.dest)
        self.assertFalse(self.dest.exists())
        anchor = self.capture()
        with self.assertRaises(FileExistsError):
            self.capture()
        self.assertEqual(sha(self.dest.read_bytes()), anchor)

    def test_repacked_archives_must_still_match_report_and_exit_evidence(self):
        self.capture()
        original = self.dest.read_bytes()
        for role, filename, replacement in (
            ("recovery", "candidate-exit.txt", b"2\n"),
            ("candidate", "agent_immunity-0.3.0a1-py3-none-any.whl", b"another wheel"),
        ):
            with self.subTest(role=role):
                files = members(original)
                inner = members(files[role + ".zip"])
                inner[filename] = replacement
                files[role + ".zip"] = archive(inner)
                # 即便包级摘要和清单都随之更新，内部证据仍须各自符合报告约定。
                manifest = json.loads(files["manifest.json"])
                manifest["artifacts"][role]["sha256"] = sha(files[role + ".zip"])
                files["manifest.json"] = json.dumps(manifest).encode()
                rebuilt = archive(files)
                self.dest.write_bytes(rebuilt)
                with self.assertRaises(ValueError):
                    bundle.verify(self.dest, sha(rebuilt))

    def test_file_created_during_capture_wins_publication(self):
        def competing_capture(commit, run, *, archives):
            self.dest.write_bytes(b"existing capture")
            return self.fetch(commit, run, archives=archives)

        with patch.object(bundle, "fetch_recovery_evidence", side_effect=competing_capture), \
                self.assertRaises(FileExistsError):
            bundle.capture(PILOT_COMMIT, RUN, self.dest)
        self.assertEqual(self.dest.read_bytes(), b"existing capture")
        self.assertEqual(list(self.dest.parent.iterdir()), [self.dest])
