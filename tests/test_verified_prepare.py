"""用合成收据核对双网关准备过程中的版本选择、安装参数和失败原子性。"""

import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from pilot.codex_time import prepare
from tests.support import temporary_directory


class VerifiedPrepareTests(unittest.TestCase):
    def setUp(self):
        staging = temporary_directory()
        self.addCleanup(staging.cleanup)
        self.root = Path(staging.name) / "试点 环境"
        self.sources = {"previous_preview": (12, "a" * 40), "candidate_preview": (34, "b" * 40)}
        self.same_wheel = False
        self.fetch = self.enter_patch(patch.object(prepare, "fetch_verified", side_effect=self.fetch_receipt))
        self.run = self.enter_patch(patch.object(prepare, "run"))
        # 这些测试检查准备流程生成的命令，不启动具体 Python 版本。
        self.enter_patch(patch.object(prepare.sys, "version_info", (3, 12)))

    def enter_patch(self, manager):
        result = manager.start()
        self.addCleanup(manager.stop)
        return result

    def fetch_receipt(self, run_id, sha, output):
        version = "0.3.0a1"
        name = f"agent_immunity-{version}-py3-none-any.whl"
        package = b"same wheel" if self.same_wheel else sha.encode()
        verified = output / "verified"
        verified.mkdir(parents=True)
        (verified / name).write_bytes(package)
        return {"version": version, "run_id": run_id, "commit": sha, "artifact_id": run_id + 100,
                "files": {name: hashlib.sha256(package).hexdigest()}}

    def test_two_builds_of_same_version_get_pinned_independent_environments(self):
        with patch.dict(prepare.os.environ, {"GH_TOKEN": "synthetic", "ACTIONS_RUNTIME_TOKEN": "synthetic"}):
            descriptor = prepare.prepare(self.root, **self.sources)
        env = json.loads(descriptor.read_bytes())
        self.assertEqual(env["schema_version"], 2)
        old, new = (env["gateway_slots"][slot] for slot in ("previous", "candidate"))
        self.assertEqual(old["version"], new["version"])
        self.assertNotEqual(old["wheel_sha256"], new["wheel_sha256"])
        self.assertNotEqual(old["python"], new["python"])
        self.assertEqual((env["gateway"], env["gateway_wheel_sha256"]), (old["python"], old["wheel_sha256"]))
        commands = [c.args[0] for c in self.run.call_args_list]
        for slot, record in env["gateway_slots"].items():
            wheel = Path(record["wheel"])
            run_id, sha = self.sources[slot + "_preview"]
            self.assertEqual((record["run_id"], record["commit"], record["artifact_id"]), (run_id, sha, run_id + 100))
            self.assertTrue(wheel.is_absolute() and Path(record["python"]).is_absolute())
            self.assertEqual(record["wheel_sha256"], hashlib.sha256(wheel.read_bytes()).hexdigest())
            self.fetch.assert_any_call(run_id, sha, wheel.parent.parent)
            install, = [cmd for cmd in commands if str(cmd[0]) == record["python"] and "install" in cmd]
            for flag in ("--no-deps", "--no-index", "--require-hashes"):
                self.assertIn(flag, install)
            lock = Path(install[install.index("-r") + 1])
            self.assertEqual(lock.read_text(encoding="utf-8").split(),
                             [wheel.as_uri(), "--hash=sha256:" + record["wheel_sha256"]])
            verify, = [cmd for cmd in commands if str(cmd[0]) == record["python"] and "--wheel" in cmd]
            self.assertEqual(verify[1:], ["-I", "-X", "utf8", str(prepare.HERE / "wheel_identity.py"), "--wheel",
                                          str(wheel), "--sha256", record["wheel_sha256"], "--version", record["version"]])
        for invocation in self.run.call_args_list:
            self.assertNotIn("GH_TOKEN", invocation.args[2])
            self.assertNotIn("ACTIONS_RUNTIME_TOKEN", invocation.args[2])

    def test_rejects_incomplete_mixed_and_identical_sources_before_any_fetch(self):
        initial = self.sources["previous_preview"]
        cases = ({"previous_preview": initial}, {"wheel": self.root / "local.whl", **self.sources},
                 {"previous_preview": initial, "candidate_preview": (14, initial[1])},
                 {"previous_preview": initial, "candidate_preview": (initial[0], "d" * 40)})
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError):
                prepare.prepare(self.root, **args)
        self.fetch.assert_not_called()
        self.run.assert_not_called()

    def test_two_commits_providing_identical_bytes_are_rejected_before_install(self):
        self.same_wheel = True
        with self.assertRaises(ValueError):
            prepare.prepare(self.root, **self.sources)
        self.assertEqual(self.fetch.call_count, 2)
        self.run.assert_not_called()
        self.assertFalse((self.root / "environment.json").exists())

    def test_single_source_wheel_still_checks_checkout_and_produces_original_descriptor(self):
        wheel = self.root.parent / "agent_immunity-0.3.0a1-py3-none-any.whl"
        wheel.write_bytes(b"synthetic wheel")
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        with patch.object(prepare, "check_wheel", return_value=("0.3.0a1", digest)) as check:
            env = json.loads(prepare.prepare(self.root, wheel).read_bytes())
        check.assert_called_once_with(wheel)
        self.fetch.assert_not_called()
        self.assertEqual(env["schema_version"], 1)
        self.assertNotIn("gateway_slots", env)
        self.assertEqual(env["gateway_wheel_sha256"], digest)
        for role in ("gateway", "previous", "candidate"):
            self.assertIn(role, Path(env[role]).parts)

    def test_candidate_identity_failure_keeps_previous_descriptor(self):
        self.root.mkdir()
        descriptor = self.root / "environment.json"
        original = json.dumps({"scope": prepare.SCOPE, "gateway": "先前验收的环境"}).encode()
        descriptor.write_bytes(original)

        def fail_identity(command, work, env, timeout):
            if "--wheel" in command and "gateway-candidate" in Path(command[0]).parts:
                raise subprocess.CalledProcessError(1, command)

        self.run.side_effect = fail_identity
        with self.assertRaises(subprocess.CalledProcessError):
            prepare.prepare(self.root, **self.sources)
        self.assertEqual(descriptor.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
