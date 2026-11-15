"""以离线探针结果覆盖 Apple Silicon 宿主和三个独立 Python 环境的验收边界。"""
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from pilot.codex_time import run as pilot


class MacHostEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.root = Path.cwd()
        self.binary = self.root / "fixture-host" / "codex"
        self.environment = {slot: str(self.root / slot / "bin/python")
                            for slot in ("gateway", "previous", "candidate")}
        self.cpus = "arm64"
        # 不同的合成补丁号可以发现误用同一解释器代替三个环境探测的回归。
        self.observed = {slot: {"implementation": "CPython", "version": f"3.12.{index}", "machine": "arm64"}
                         for index, slot in enumerate(self.environment, 1)}
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.system = stack.enter_context(patch.object(pilot.platform, "system", return_value="Darwin"))
        self.mac_ver = stack.enter_context(patch.object(pilot.platform, "mac_ver",
                                                        return_value=("15.8.2", ("", "", ""), "arm64")))
        self.command = stack.enter_context(patch.object(pilot, "run_command", side_effect=self.respond))

    def respond(self, argv, cwd):
        self.assertEqual(cwd, self.root)
        if str(argv[0]) == "/usr/bin/lipo":
            self.assertEqual(argv[1], "-archs")
            self.assertEqual(Path(argv[2]), self.binary)
            return self.cpus + "\n"
        self.assertIn("-I", argv)
        self.assertIn("-c", argv)
        by_python = {value: slot for slot, value in self.environment.items()}
        return json.dumps(self.observed[by_python[str(argv[0])]]) + "\n"

    def observe(self):
        return pilot.macos_host_environment(self.binary, self.environment, self.root)

    def test_records_exact_native_binary_and_each_selected_python(self):
        recorded = self.observe()
        self.assertEqual(recorded["system"], "Darwin")
        self.assertEqual(recorded["os_version"], "15.8.2")
        self.assertEqual(recorded["codex_arch"], "arm64")
        self.assertEqual(recorded["pythons"], self.observed)
        self.assertEqual(self.command.call_count, 4)

    def test_x86_universal_and_missing_binary_architecture_are_rejected(self):
        for cpus in ("x86_64", "x86_64 arm64", ""):
            self.cpus = cpus
            with self.subTest(cpus=cpus), self.assertRaises(ValueError):
                self.observe()

    def test_incompatible_or_incomplete_python_in_any_role_is_rejected(self):
        for slot, field, bad in (("gateway", "machine", "x86_64"), ("previous", "version", "3.11.9"),
                                 ("candidate", "implementation", "PyPy"), ("candidate", "machine", None)):
            base = self.observed[slot]
            with self.subTest(slot=slot, field=field), patch.dict(base), self.assertRaises(ValueError):
                if bad is None:
                    del base[field]
                else:
                    base[field] = bad
                self.observe()

    def test_wrong_system_or_missing_macos_version_is_not_platform_evidence(self):
        self.system.return_value = "Linux"
        with self.assertRaises(ValueError):
            self.observe()
        self.system.return_value = "Darwin"
        self.mac_ver.return_value = ("", ("", "", ""), "")
        with self.assertRaises(ValueError):
            self.observe()

    def test_cli_rejects_preflight_as_native_lifecycle_evidence(self):
        cli = [sys.executable, "-X", "utf8", "-m", "pilot.codex_time.run",
               "--require-macos-arm64", "--preflight-only",
               "--environment", "unused-environment.json", "--output-dir", "unused-output"]
        result = subprocess.run(cli, cwd=pilot.REPO, capture_output=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"--preflight-only", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
