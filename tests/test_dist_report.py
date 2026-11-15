"""用独立的安装结果核对发行包验收报告及失败时的输出边界。"""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from scripts import check_dist
from tests.support import temporary_directory


class DistReportTests(unittest.TestCase):
    def setUp(self):
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.report = self.root / "install.json"
        self.wheel = self.dist / "agent_immunity-1.2.3-py3-none-any.whl"
        self.source = self.dist / "agent_immunity-1.2.3.tar.gz"
        self.wheel.write_bytes(b"fixture wheel")
        self.source.write_bytes(b"fixture sdist")
        # 真实归档及安装由 CI 构建。此处保留磁盘、CLI、摘要和报告生成逻辑。
        members = patch.object(check_dist, "verify_members")
        members.start()
        self.addCleanup(members.stop)
        install = patch.object(check_dist, "smoke_install")
        self.install = install.start()
        self.addCleanup(install.stop)

    def invoke(self, report=None):
        argv = ["check_dist.py", str(self.dist)]
        if report is not None:
            argv.extend(["--report", str(report)])
        # 用私有的临时目录模拟源码树和其外部安装位置，不依赖调用方的 TMPDIR。
        with patch.object(check_dist, "REPO", self.root / "checkout"), \
                patch.object(check_dist.tempfile, "tempdir", str(self.root)), patch.object(sys, "argv", argv), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            check_dist.main()

    def measured(self, python):
        return {"installed_version": "1.2.3", "implementation": "CPython", "python": python,
                "system": "Darwin", "os_version": "15.0", "machine": "arm64",
                "policy_check": "pass", "proxy_ping": True}

    def test_each_archive_has_its_own_observation_and_sha256(self):
        # 两份合成观察用不同补丁号，以便发现误将第一次探测结果复制到两行的回归。
        wheel_probe = self.measured("3.12.1")
        source_probe = self.measured("3.12.2")
        self.install.side_effect = [wheel_probe.copy(), source_probe.copy()]
        self.invoke(self.report)
        first, second = self.install.call_args_list
        self.assertEqual([first.args[0], second.args[0]], [self.wheel, self.source])
        self.assertNotEqual(first.args[1], second.args[1])
        report = json.loads(self.report.read_bytes())
        self.assertEqual((report["schema_version"], report["scope"], report["status"]),
                         (1, "CORE_PACKAGE_INSTALL", "passed"))
        expected_rows = []
        for path, kind, probe in ((self.wheel, "wheel", wheel_probe), (self.source, "sdist", source_probe)):
            expected_rows.append({**probe, "kind": kind, "filename": path.name,
                                  "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        self.assertEqual(report["packages"], expected_rows)
        self.assertEqual([first.kwargs["expected_sha256"], second.kwargs["expected_sha256"]],
                         [row["sha256"] for row in expected_rows])
        expected_sums = "".join(f"{row['sha256']}  {row['filename']}\n" for row in expected_rows)
        self.assertEqual((self.dist / "SHA256SUMS").read_bytes(), expected_sums.encode("ascii"))
        self.assertEqual(set(self.dist.iterdir()), {self.wheel, self.source, self.dist / "SHA256SUMS"})

    def test_second_install_failure_cannot_publish_or_replace_a_report(self):
        for previous in (None, b"previous acceptance\n"):
            with self.subTest(previous=previous):
                if previous is not None:
                    self.report.write_bytes(previous)
                self.install.side_effect = [self.measured("3.10.1"), subprocess.CalledProcessError(1, "smoke")]
                with self.assertRaises(subprocess.CalledProcessError):
                    self.invoke(self.report)
                if previous is None:
                    self.assertFalse(self.report.exists())
                else:
                    self.assertEqual(self.report.read_bytes(), previous)
                self.assertFalse((self.dist / "SHA256SUMS").exists())

    def test_report_inside_distribution_directory_is_rejected_before_install(self):
        for destination in (self.dist / "report.json", self.dist / "nested" / "report.json", self.wheel):
            with self.subTest(destination=destination), self.assertRaises((ValueError, SystemExit)):
                self.invoke(destination)
        self.install.assert_not_called()
        self.assertEqual(set(self.dist.iterdir()), {self.wheel, self.source})
        self.assertEqual(self.wheel.read_bytes(), b"fixture wheel")
        self.assertEqual(self.source.read_bytes(), b"fixture sdist")

    def test_report_cannot_replace_a_distribution_symlink_to_an_external_file(self):
        outside = self.wheel.rename(self.root / "archive-copy.whl")
        try:
            self.wheel.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("当前宿主不允许创建文件符号链接")
        with self.assertRaises((ValueError, SystemExit)):
            self.invoke(self.wheel)
        self.install.assert_not_called()
        self.assertTrue(self.wheel.is_symlink())
        self.assertEqual(outside.read_bytes(), b"fixture wheel")

    def test_installed_version_must_match_the_archive_name(self):
        probe = self.measured("3.12.1")
        self.install.side_effect = [probe, {**probe, "installed_version": "1.0.0"}]
        with self.assertRaises(ValueError):
            self.invoke(self.report)
        self.assertFalse(self.report.exists())

    def test_archive_changed_during_install_cannot_be_certified(self):
        def swap_archive(package, work, *, expected_sha256):
            if package == self.source:
                self.wheel.write_bytes(b"replacement")
            return self.measured("3.12.1")

        self.report.write_bytes(b"previous acceptance\n")
        self.install.side_effect = swap_archive
        with self.assertRaises(ValueError):
            self.invoke(self.report)
        self.assertEqual(self.report.read_bytes(), b"previous acceptance\n")
