"""核对发行包认证、环境准备与描述文件发布之间的顺序。"""
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from pilot.codex_time import prepare, prepare_preview
from scripts import verify_preview_pair as pair
from tests.support import temporary_directory
from tests.test_support_matrix import COMMIT, VERIFY_RUN, x64_package_job


class PreparePreviewTests(unittest.TestCase):
    def setUp(self):
        tmp = temporary_directory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.directory = base / "downloads"
        self.directory.mkdir()
        self.root = base / "prepare"
        self.original = self.root / "gen-existing" / "gateway.txt"
        self.original.parent.mkdir(parents=True)
        self.original.write_bytes(b"previous gateway")
        self.descriptor = self.root / "environment.json"
        self.descriptor.write_bytes(json.dumps({"scope": prepare.SCOPE, "gateway": str(self.original)}).encode())
        self.active = base / "host-project" / ".codex" / "config.toml"
        self.active.parent.mkdir(parents=True)
        self.active.write_bytes(b'mcp_servers.time_pilot = { command = "previous" }\n')
        job = x64_package_job("ubuntu-latest", "3.12")
        report = job.pop("package_install_report")
        report["schema_version"] = 2
        self.files = {}
        for item in report["packages"]:
            path = self.directory / item["filename"]
            path.write_bytes(("verified " + item["kind"]).encode())
            item.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), protocol_version="2025-06-18")
            self.files[item["kind"]] = path
        self.fetch = self.mock(patch.object(pair, "fetch_preview_pair", return_value=(job, report, 510, 520)))
        self.run = self.mock(patch.object(prepare, "run"))
        self.mock(patch.object(prepare.sys, "version_info", (3, 12)))

    def mock(self, manager):
        result = manager.start()
        self.addCleanup(manager.stop)
        return result

    def invoke(self):
        return prepare_preview.prepare_preview(self.root, self.directory, COMMIT, VERIFY_RUN)

    def replace_source_after_first_read(self):
        original_read = pair.read_regular_file
        wheel = self.files["wheel"]
        expected = wheel.read_bytes()

        def swap(path, limit):
            observed = original_read(path, limit)
            if path == wheel:
                wheel.write_bytes(b"replaced after verification")
            return observed

        self.mock(patch.object(pair, "read_regular_file", side_effect=swap))
        return expected

    def test_rejected_preview_preserves_existing_environment_and_registration(self):
        before = {p.relative_to(self.root): p.read_bytes() if p.is_file() else None
                  for p in self.root.rglob("*")}
        active = self.active.read_bytes()
        for defect in ("wheel", "sdist", "source"):
            with self.subTest(defect=defect):
                originals = {p: p.read_bytes() for p in self.files.values()}
                if defect == "source":
                    self.fetch.side_effect = ValueError("构建来源不符")
                else:
                    self.files[defect].write_bytes(b"other build with the same version")
                sums = self.directory / "SHA256SUMS"
                sums.write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
                                        for p in self.files.values()), encoding="ascii")
                with self.assertRaises(ValueError):
                    self.invoke()
                self.run.assert_not_called()
                self.assertEqual({p.relative_to(self.root): p.read_bytes() if p.is_file() else None
                                  for p in self.root.rglob("*")}, before)
                self.assertEqual(self.active.read_bytes(), active)
                self.fetch.side_effect = None
                for path, data in originals.items():
                    path.write_bytes(data)

    def test_stages_verified_bytes_and_pins_the_hash_installed_by_pip(self):
        expected = self.replace_source_after_first_read()
        checksum = hashlib.sha256(expected).hexdigest()
        old_descriptor = self.descriptor.read_bytes()
        old_registration = self.active.read_bytes()
        checked = []
        locks = []

        def install(command, work, env, timeout):
            self.assertEqual(self.descriptor.read_bytes(), old_descriptor)
            if "install" in command and "--no-index" in command:
                self.assertIn("--require-hashes", command)
                lock = Path(command[command.index("-r") + 1])
                locks.append(lock.read_text(encoding="utf-8").strip())

        def inspect(python, wheel, version, digest, work, env):
            wheel = Path(wheel)
            self.assertEqual(self.descriptor.read_bytes(), old_descriptor)
            self.assertTrue(wheel.is_relative_to(self.root))
            self.assertEqual(wheel.read_bytes(), expected)
            self.assertEqual(digest, checksum)
            self.assertEqual(version, "0.3.0a1")
            self.assertTrue(Path(python).is_relative_to(self.root))
            self.assertEqual(locks, [f"{wheel.as_uri()} --hash=sha256:{checksum}"])
            checked.append(wheel)
            return {"version": version, "wheel_sha256": digest, "runtime_files": 19, "metadata_sha256": "a" * 64}

        self.run.side_effect = install
        with patch.object(prepare, "installed_identity", side_effect=inspect):
            result = self.invoke()
        self.assertEqual(result, self.descriptor)
        self.assertEqual(len(checked), 1)
        self.assertEqual(self.active.read_bytes(), old_registration)
        self.assertEqual(self.files["wheel"].read_bytes(), b"replaced after verification")
        settings = json.loads(self.descriptor.read_bytes())
        self.assertEqual(settings["gateway_wheel_sha256"], checksum)
        self.assertEqual(settings["gateway_identity"]["metadata_sha256"], "a" * 64)
        self.assertEqual(settings["preview_pair"]["receipt_artifact_id"], 520)
        self.assertEqual(settings["preview_pair"]["commit"], COMMIT)
        self.assertEqual(len(settings["preview_pair"]["packages"]), 2)

    def test_gateway_identity_failure_does_not_publish_prepared_generation(self):
        before = self.descriptor.read_bytes()
        registration = self.active.read_bytes()

        with patch.object(prepare, "installed_identity", side_effect=ValueError("安装内容与 wheel 不符")) as check:
            with self.assertRaises(ValueError):
                self.invoke()
        check.assert_called_once()
        self.assertEqual(self.descriptor.read_bytes(), before)
        self.assertEqual(self.active.read_bytes(), registration)
        self.assertEqual(self.original.read_bytes(), b"previous gateway")
