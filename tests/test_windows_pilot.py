"""验证 Windows x64 宿主证据与所选可执行文件和解释器一一对应。"""
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from pilot.codex_time import run as pilot


class WindowsHostEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.root = Path.cwd()
        self.binary = self.root / "fixture host" / "codex.exe"
        self.environment = {role: str(self.root / role / "Scripts" / "python.exe")
                            for role in ("gateway", "previous", "candidate")}
        # 不同补丁号能识别把一个环境的结果复制给其他角色的错误。
        self.observed = {role: {"implementation": "CPython", "version": f"3.12.{index}",
                                "machine": "AMD64", "python_platform": "win-amd64"}
                         for index, role in enumerate(self.environment, 1)}
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.system = stack.enter_context(patch.object(pilot.platform, "system", return_value="Windows"))
        self.os_version = stack.enter_context(patch.object(pilot.platform, "win32_ver",
                                                          return_value=("2025Server", "10.0.26100", "", "")))
        self.native = stack.enter_context(patch.object(pilot, "require_windows_x64_executable"))
        self.command = stack.enter_context(patch.object(pilot, "run_command", side_effect=self.respond))

    def respond(self, args, cwd):
        self.assertEqual(cwd, self.root)
        self.assertIn("-I", args)
        self.assertIn("-c", args)
        by_python = {python: role for role, python in self.environment.items()}
        return json.dumps(self.observed[by_python[str(args[0])]]) + "\n"

    def observe(self):
        return pilot.windows_host_environment(self.binary, self.environment, self.root)

    def test_records_selected_native_host_and_three_independent_pythons(self):
        result = self.observe()
        self.native.assert_called_once_with(self.binary)
        self.assertEqual(self.command.call_count, 3)
        self.assertEqual(result["system"], "Windows")
        self.assertEqual(result["os_version"], "10.0.26100")
        self.assertEqual(result["codex_arch"], "x64")
        self.assertEqual(result["pythons"], self.observed)

    def test_native_host_check_must_pass(self):
        self.native.side_effect = ValueError("并非原生 Windows x64 可执行文件")
        with self.assertRaises(ValueError):
            self.observe()

    def test_incompatible_or_unreported_python_is_rejected_in_each_role(self):
        for role, key, wrong in (("gateway", "python_platform", "win32"), ("previous", "machine", "ARM64"),
                                 ("candidate", "version", "3.11.9"), ("gateway", "implementation", "PyPy"),
                                 ("previous", "python_platform", None)):
            record = self.observed[role]
            with self.subTest(role=role, key=key), patch.dict(record), self.assertRaises(ValueError):
                if wrong is None:
                    del record[key]
                else:
                    record[key] = wrong
                self.observe()

    def test_requires_windows_and_an_observed_os_version(self):
        self.system.return_value = "Linux"
        with self.assertRaises(ValueError):
            self.observe()
        self.system.return_value = "Windows"
        self.os_version.return_value = ("", "", "", "")
        with self.assertRaises(ValueError):
            self.observe()

    def test_cli_rejects_preflight_and_conflicting_host_requirements(self):
        for flag in ("--preflight-only", "--require-macos-arm64"):
            with self.subTest(flag=flag):
                command = [sys.executable, "-X", "utf8", "-m", "pilot.codex_time.run", "--require-windows-x64",
                           flag, "--environment", "unused.json", "--output-dir", "unused-output"]
                result = subprocess.run(command, cwd=pilot.REPO, capture_output=True, timeout=20)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(flag.encode(), result.stderr)
                self.assertNotIn(b"Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
