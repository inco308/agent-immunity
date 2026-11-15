"""在独立虚拟环境中构造安装记录并用实际入口核验 wheel 身份。"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
import venv
import zipfile

from tests.support import temporary_directory


SCRIPT = Path(__file__).resolve().parents[1] / "pilot/codex_time/wheel_identity.py"
VERSION = "0.3.0a1"
INFO = f"agent_immunity-{VERSION}.dist-info"
METADATA = b"Metadata-Version: 2.1\nName: agent-immunity\nVersion: 0.3.0a1\nSummary: first build\n"


class WheelIdentityTests(unittest.TestCase):
    def setUp(self):
        temp = temporary_directory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        environment = self.root / "env"
        venv.EnvBuilder(with_pip=False).create(environment)
        self.python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        location = subprocess.check_output([self.python, "-I", "-X", "utf8", "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))"], encoding="utf-8").strip()
        self.site = Path(location)
        self.wheel = self.root / f"agent_immunity-{VERSION}-py3-none-any.whl"
        self.members = {
            "agent_immunity/__init__.py": b"raise AssertionError('verification imported the package')\n",
            "agent_immunity/dataset/policy.json": b"{}\n",
            f"{INFO}/METADATA": METADATA,
        }
        with zipfile.ZipFile(self.wheel, "w") as archive:
            for name, content in self.members.items():
                archive.writestr(name, content)
                path = self.site / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        self.digest = hashlib.sha256(self.wheel.read_bytes()).hexdigest()
        self.record = {"url": self.wheel.as_uri(), "archive_info": {"hashes": {"sha256": self.digest}}}
        self.origin = self.site / INFO / "direct_url.json"
        self.origin.write_text(json.dumps(self.record), encoding="utf-8")

    def run_check(self, expected=None, *, passed=False):
        cmd = [self.python, "-I", "-X", "utf8", SCRIPT, "--wheel", self.wheel,
               "--sha256", self.digest if expected is None else expected, "--version", VERSION]
        result = subprocess.run(cmd, cwd=self.root, capture_output=True, encoding="utf-8", timeout=20)
        if passed:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("安装身份核验失败", result.stderr)

    def test_real_interpreter_reports_installed_content_and_ignores_normal_cache(self):
        init = self.site / "agent_immunity/__init__.py"
        subprocess.run([self.python, "-I", "-m", "py_compile", str(init)], check=True, timeout=20)
        self.assertEqual(self.run_check(passed=True), {
            "wheel_sha256": self.digest, "version": VERSION, "runtime_files": 2,
            "metadata_sha256": hashlib.sha256(METADATA).hexdigest(),
        })

    def test_same_version_different_metadata_or_receipt_digest_is_rejected(self):
        self.run_check("1" * 64)
        metadata_file = self.site / INFO / "METADATA"
        metadata_file.write_bytes(METADATA.replace(b"first build", b"other build"))
        self.run_check()

    def test_missing_conflicting_or_nonlocal_pip_origin_is_rejected(self):
        self.origin.unlink()
        self.run_check()
        for record in (
            {**self.record, "url": "https://example.invalid/" + self.wheel.name},
            {**self.record, "archive_info": {"hashes": {}}},
            {**self.record, "archive_info": {"hashes": {"sha256": "0" * 64}}},
            {**self.record, "archive_info": {"hashes": {"sha256": self.digest}, "hash": "sha256=" + "0" * 64}},
        ):
            with self.subTest(record=record):
                self.origin.write_text(json.dumps(record), encoding="utf-8")
                self.run_check()

    def test_ambiguous_same_name_distribution_is_rejected(self):
        other = self.site / "agent_immunity-0.3.0a2.dist-info"
        other.mkdir()
        # 保持 METADATA 中的发行名和版本完全一致，目录名与构建摘要形成歧义。
        (other / "METADATA").write_bytes(METADATA.replace(b"first build", b"other build"))
        self.run_check()

    def test_extra_changed_and_missing_package_files_are_rejected(self):
        extra = self.site / "agent_immunity/extra.py"
        extra.write_bytes(b"# extra module\n")
        self.run_check()
        extra.unlink()
        policy = self.site / "agent_immunity/dataset/policy.json"
        policy.write_bytes(b"[]\n")
        self.run_check()
        policy.unlink()
        self.run_check()

    def test_link_to_an_identical_file_outside_the_install_is_rejected(self):
        relative = "agent_immunity/dataset/policy.json"
        path = self.site / relative
        copy = self.root / "copy.json"
        copy.write_bytes(path.read_bytes())
        path.unlink()
        try:
            path.symlink_to(copy)
        except OSError:
            self.skipTest("当前宿主不允许创建符号链接")
        self.run_check()


if __name__ == "__main__":
    unittest.main()
