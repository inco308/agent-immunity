"""用两个独立安装环境的合成报告核对 x64 打包作业的验收边界。"""
import unittest

from scripts.check_x64_install_report import validate


def install_receipt(runner, series):
    if runner == "ubuntu-latest":
        system = {"system": "Linux", "os_version": "6.17.0-1012-azure", "machine": "x86_64",
                  "python_platform": "linux-x86_64", "distro_id": "ubuntu", "distro_version": "26.04"}
    else:
        system = {"system": "Windows", "os_version": "10.0.26100", "machine": "AMD64",
                  "python_platform": "win-amd64"}
    records = []
    for kind, patch, name, sha in (
        ("wheel", 10, "agent_immunity-0.3.0a1-py3-none-any.whl", "a" * 64),
        ("sdist", 11, "agent_immunity-0.3.0a1.tar.gz", "b" * 64),
    ):
        records.append({**system, "kind": kind, "filename": name, "sha256": sha, "installed_version": "0.3.0a1",
                        "implementation": "CPython", "python": f"{series}.{patch}", "pointer_bits": 64,
                        "policy_check": "pass", "proxy_ping": True})
    return {"schema_version": 1, "scope": "CORE_PACKAGE_INSTALL", "status": "passed", "packages": records}


class X64InstallReceiptTests(unittest.TestCase):
    def test_two_independent_patches_from_the_requested_python_series(self):
        for runner in ("ubuntu-latest", "windows-latest"):
            for series in ("3.10", "3.12"):
                with self.subTest(runner=runner, series=series):
                    self.assertIsNone(validate(install_receipt(runner, series), runner, series))

    def test_requires_both_archives_and_successful_install_checks(self):
        report = install_receipt("ubuntu-latest", "3.12")
        for field, value in (("status", "failed"), ("scope", "preflight"), ("schema_version", True)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate({**report, field: value}, "ubuntu-latest", "3.12")
        wheel, source = report["packages"]
        for records in ([wheel], [source], [wheel, wheel], [wheel, source, source]):
            with self.subTest(kinds=[r["kind"] for r in records]), self.assertRaises(ValueError):
                validate({**report, "packages": records}, "ubuntu-latest", "3.12")
        for index in (0, 1):
            for field, value in (("policy_check", "review"), ("proxy_ping", False), ("proxy_ping", 1)):
                broken = install_receipt("windows-latest", "3.12")
                broken["packages"][index][field] = value
                with self.subTest(index=index, field=field, value=value), self.assertRaises(ValueError):
                    validate(broken, "windows-latest", "3.12")

    def test_rejects_mismatched_architecture_and_interpreter_for_either_package(self):
        for runner, wrong_machine, wrong_platform in (
            ("ubuntu-latest", "aarch64", "linux-i686"), ("windows-latest", "ARM64", "win32"),
        ):
            for index in (0, 1):
                for field, value in (("machine", wrong_machine), ("python_platform", wrong_platform),
                                     ("pointer_bits", 32), ("pointer_bits", 64.0), ("pointer_bits", "64"),
                                     ("implementation", "PyPy"), ("python", "3.10.11"), ("python", "3.12")):
                    report = install_receipt(runner, "3.12")
                    report["packages"][index][field] = value
                    with self.subTest(runner=runner, index=index, field=field, value=value), self.assertRaises(ValueError):
                        validate(report, runner, "3.12")

    def test_requires_the_runner_os_and_its_own_version_evidence(self):
        with self.assertRaises(ValueError):
            validate(install_receipt("ubuntu-latest", "3.12"), "windows-latest", "3.12")
        for runner, field, value in (
            ("ubuntu-latest", "distro_id", "debian"), ("ubuntu-latest", "distro_version", "6.17.0-1012-azure"),
            ("ubuntu-latest", "distro_version", None), ("windows-latest", "os_version", "Windows Server 2025"),
        ):
            report = install_receipt(runner, "3.12")
            if value is None:
                del report["packages"][1][field]
            else:
                report["packages"][1][field] = value
            with self.subTest(runner=runner, field=field, value=value), self.assertRaises(ValueError):
                validate(report, runner, "3.12")

    def test_source_record_has_its_own_archive_identity(self):
        for field, bad in (("filename", "unrelated.tar.gz"), ("installed_version", "0.3.0a2"),
                           ("sha256", "not-a-digest"), ("sha256", "a" * 64)):
            report = install_receipt("ubuntu-latest", "3.12")
            report["packages"][1][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                validate(report, "ubuntu-latest", "3.12")


if __name__ == "__main__":
    unittest.main()
