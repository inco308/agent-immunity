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


def replace_member(raw_bundle, role, filename, replacement):
    files = members(raw_bundle)
    inner_zip = role + ".zip"
    inner = members(files[inner_zip])
    inner[filename] = replacement
    files[inner_zip] = archive(inner)
    # 即使包级摘要和清单也被重新计算，报告中的业务与构建收据仍需能被独立核对。
    manifest = json.loads(files["manifest.json"])
    manifest["artifacts"][role]["sha256"] = sha(files[inner_zip])
    files["manifest.json"] = json.dumps(manifest).encode()
    return archive(files)


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
                rebuilt = replace_member(original, role, filename, replacement)
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

    def test_install_uses_selected_receipt_and_only_original_verified_bytes(self):
        anchor = self.capture()
        original = self.dest.read_bytes()
        original_open = Path.open
        filename = "agent_immunity-0.3.0a1-py3-none-any.whl"

        def swap_after_read(path, *args, **kwargs):
            if path == self.dest and (args[0] if args else kwargs.get("mode")) == "rb":
                with original_open(path, "rb") as src:
                    snapshot = src.read()
                with original_open(path, "wb") as out:
                    out.write(b"replaced after the first read")
                return io.BytesIO(snapshot)
            return original_open(path, *args, **kwargs)

        for role in ("previous", "candidate"):
            with self.subTest(role=role):
                self.dest.write_bytes(original)
                expected = self.report["upstreams"][role]["gateway"]
                wheel_bytes = members(self.archives[role]["data"])[filename]

                def inspect(wheel_path, work, receipt):
                    self.assertEqual(receipt, expected)
                    self.assertEqual(wheel_path.name, filename)
                    self.assertEqual(wheel_path.read_bytes(), wheel_bytes)
                    self.assertEqual(sha(wheel_bytes), receipt["wheel_sha256"])
                    self.assertTrue(work.is_dir())
                    observed = {key: receipt[key] for key in ("version", "wheel_sha256", "metadata_sha256", "runtime_files")}
                    return {**observed, "policy_check": "pass", "protocol_version": "2025-06-18", "proxy_ping": True}

                with patch.object(Path, "open", swap_after_read), \
                        patch.object(bundle, "check_retained_wheel", side_effect=inspect) as install:
                    result = bundle.check_install(self.dest, anchor, role)
                install.assert_called_once()
                self.assertEqual((result["role"], result["bundle_sha256"]), (role, anchor))
                self.assertEqual((result["source_commit"], result["source_run"], result["source_artifact"]),
                                 (expected["commit"], expected["run_id"], expected["artifact_id"]))
                self.assertEqual(result["wheel_sha256"], expected["wheel_sha256"])
                self.assertFalse(install.call_args.args[0].exists())
                self.assertEqual(self.dest.read_bytes(), b"replaced after the first read")

    def test_invalid_evidence_or_role_rejected_before_wheel_is_staged(self):
        anchor = self.capture()
        original = self.dest.read_bytes()
        filename = "agent_immunity-0.3.0a1-py3-none-any.whl"
        wrong_wheel = replace_member(original, "previous", filename, b"unselected wheel mismatch")
        bad_report = json.dumps({**self.report, "status": "passed"}).encode()
        wrong_report = replace_member(original, "recovery", "report.json", bad_report)
        original_open = Path.open

        def reject_wheel_write(path, mode="r", *args, **kwargs):
            if path.suffix == ".whl" and any(flag in mode for flag in "wax+"):
                self.fail("证据未通过校验时尝试写出 wheel")
            return original_open(path, mode, *args, **kwargs)

        for label, data, checksum, role in (
            ("错误外部摘要", original, "0" * 64, "candidate"),
            ("未选中的构建失配", wrong_wheel, sha(wrong_wheel), "candidate"),
            ("报告语义有误", wrong_report, sha(wrong_report), "previous"),
            ("未知角色", original, anchor, "other"),
        ):
            with self.subTest(case=label):
                self.dest.write_bytes(data)
                with patch.object(Path, "open", reject_wheel_write), patch.object(bundle, "check_retained_wheel") as install:
                    with self.assertRaises(ValueError):
                        bundle.check_install(self.dest, checksum, role)
                install.assert_not_called()
