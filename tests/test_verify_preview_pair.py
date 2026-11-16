"""把同版本不同构建的本地归档与指定作业的权威收据逐包比对。"""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import verify_preview_pair as preview
from scripts.package_protocol import PROTOCOL_STEP
from tests.support import temporary_directory
from tests.test_support_matrix import COMMIT, VERIFY_RUN, x64_package_job


class VerifyPreviewPairTests(unittest.TestCase):
    def setUp(self):
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "downloads"
        self.directory.mkdir()
        job = x64_package_job("ubuntu-latest", "3.12")
        self.report = job.pop("package_install_report")
        self.report["schema_version"] = 2
        job["steps"].extend({"name": name, "status": "completed", "conclusion": "success"}
                            for name in (PROTOCOL_STEP, "保存可下载的发行文件"))
        self.paths = {}
        for item in self.report["packages"]:
            path = self.directory / item["filename"]
            path.write_bytes(f"accepted build of {item['kind']}".encode())
            item.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), protocol_version="2025-06-18")
            self.paths[item["kind"]] = path
        self.sums = self.directory / "SHA256SUMS"
        self.enter_mock("scripts.verify_preview_pair.fetch_preview_pair", return_value=(job, self.report, 510, 520))
        self.enter_mock("subprocess.Popen", side_effect=AssertionError("本地归档应按字节核对"))

    def enter_mock(self, target, **kwargs):
        ctx = patch(target, **kwargs)
        ctx.start()
        self.addCleanup(ctx.stop)

    def check_pair(self):
        return preview.verify_pair(self.directory, COMMIT, VERIFY_RUN)

    def local_checksums(self):
        return "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                       for path in self.paths.values())

    def snapshot(self):
        return {file.name: file.read_bytes() for file in self.directory.iterdir()}

    def test_local_files_match_receipt_with_or_without_checksum_list(self):
        (self.directory / "说明.txt").write_text("用户下载说明", encoding="utf-8")
        manifest = self.local_checksums()
        windows_reordered = "\r\n".join(line[:64].upper() + line[64:] for line in reversed(manifest.splitlines())) + "\r\n"
        for checksum_text in (None, manifest, windows_reordered):
            with self.subTest(checksum_text=checksum_text):
                if checksum_text is not None:
                    self.sums.write_bytes(checksum_text.encode("ascii"))
                before = self.snapshot()
                result = self.check_pair()
                self.assertEqual(result["status"], "passed")
                self.assertCountEqual([(p["kind"], p["filename"], p["sha256"]) for p in result["packages"]],
                                      [(p["kind"], p["filename"], p["sha256"]) for p in self.report["packages"]])
                self.assertEqual(self.snapshot(), before)

    def test_same_name_replacement_fails_even_with_recomputed_local_checksums(self):
        for kind, path in self.paths.items():
            with self.subTest(kind=kind):
                accepted = path.read_bytes()
                path.write_bytes(b"other build with identical filename and version")
                self.sums.write_bytes(self.local_checksums().encode("ascii"))
                before = self.snapshot()
                with self.assertRaises((ValueError, OSError)):
                    self.check_pair()
                self.assertEqual(self.snapshot(), before)
                path.write_bytes(accepted)

    def test_missing_extra_archives_and_inconsistent_checksum_list_fail(self):
        extra = self.directory / "agent_immunity-0.2.0-py3-none-any.whl"
        extra.touch()
        with self.assertRaises((ValueError, OSError)):
            self.check_pair()
        extra.unlink()
        wheel_line, source_line = self.local_checksums().splitlines()
        for text in (wheel_line, f"{wheel_line}\n{wheel_line}", f"{'0' * 64}{wheel_line[64:]}\n{source_line}"):
            with self.subTest(manifest=text):
                self.sums.write_bytes((text + "\n").encode("ascii"))
                with self.assertRaises((ValueError, OSError)):
                    self.check_pair()
        self.sums.unlink()
        self.paths["sdist"].unlink()
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = preview.main(["--dist", str(self.directory), "--run", str(VERIFY_RUN), "--commit", COMMIT])
        self.assertNotEqual(status, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertTrue(stderr.getvalue().strip())

    def test_link_to_identical_bytes_is_rejected_for_each_input(self):
        self.sums.write_bytes(self.local_checksums().encode("ascii"))
        for path in [*self.paths.values(), self.sums]:
            outside = self.directory.parent / path.name
            contents = path.read_bytes()
            path.rename(outside)
            try:
                path.symlink_to(outside)
            except OSError as exc:
                if getattr(exc, "winerror", None) == 1314:
                    self.skipTest("当前宿主不允许创建文件符号链接")
                raise
            with self.subTest(filename=path.name):
                with self.assertRaises((ValueError, OSError)):
                    self.check_pair()
                self.assertEqual(outside.read_bytes(), contents)
                path.unlink()
                outside.rename(path)
