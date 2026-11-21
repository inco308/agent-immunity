"""dsh 评测后端的传输选择回归。

Windows 宿主经 WSL 原生发行版调用，POSIX 宿主直接调用本机安装。
两种传输必须共用同一套拒绝保护、模型身份校验与超时约束，
因此这里用假可执行文件和假子进程断言命令形状，不连接真实模型。
"""
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

from evals import dsh_backend
from evals.dsh_backend import DshBackend

REPO = Path(__file__).resolve().parents[1]
WORK_ROOT = REPO / "artifacts" / "llm-eval" / "transport-tests"
MODEL = "transport-test-model"
DEFAULT_PROVIDER = "deepseek-official"


class _Completed:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class DshTransportTests(unittest.TestCase):
    def setUp(self):
        # 假可执行文件放在系统临时目录，避免落在 /mnt/ 挂载路径上被当成 Windows 替身。
        self.binaries = tempfile.TemporaryDirectory()
        self.addCleanup(self.binaries.cleanup)
        self.paths = {}
        for name in ("node", "dsh", "timeout", "wsl.exe"):
            path = Path(self.binaries.name) / name
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(0o755)
            self.paths[name] = str(path)
        self.work_root = WORK_ROOT / ("case-" + uuid.uuid4().hex[:12])

    def _fake_run(self, calls, audit_overrides):
        overrides = audit_overrides or {}

        def fake_run(args, timeout=30, cwd=None, **kwargs):
            self.assertNotIn("shell", kwargs, "不得通过 shell 拼接命令")
            calls.append({"args": [str(item) for item in args], "cwd": cwd})
            if "wslpath" in args:
                return _Completed(stdout=(str(args[-1]) + "\n").encode())
            if "--version" in args:
                if any(str(item).endswith("dsh") for item in args):
                    return _Completed(stdout=b"0.1.1-rc.2\n")
                return _Completed(stdout=b"v24.20.0\n")
            if "bash" in args:
                found = "\n".join(self.paths[name] for name in ("node", "dsh", "timeout"))
                return _Completed(stdout=(found + "\n").encode())
            run_dir = (Path(cwd).parent if cwd
                       else Path(args[args.index("--patch") + 1]).parent)
            audit = {
                "status": "completed", "model": MODEL,
                "provider": os.environ.get("DSH_EVAL_PROVIDER", DEFAULT_PROVIDER),
                "content": '{"action":"finish"}', "guard_self_test_denied": True,
                "tool_attempts": 0, "model_tool_calls": 0, "usage": {},
            }
            audit.update(overrides)
            (run_dir / "planner-result.json").write_text(
                json.dumps(audit, ensure_ascii=False), encoding="utf-8")
            return _Completed()
        return fake_run

    @contextmanager
    def patched(self, platform="linux", env=None, audit_overrides=None, which_map=None):
        mapping = which_map if which_map is not None else (
            dict(self.paths) if platform == "win32"
            else {name: self.paths[name] for name in ("node", "dsh", "timeout")})
        calls = []
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, env or {}, clear=False))
            stack.enter_context(mock.patch.object(dsh_backend.sys, "platform", platform))
            stack.enter_context(mock.patch.object(
                dsh_backend.shutil, "which", side_effect=mapping.get))
            stack.enter_context(mock.patch.object(
                dsh_backend.subprocess, "run",
                side_effect=self._fake_run(calls, audit_overrides)))
            yield calls

    def backend(self):
        return DshBackend(model=MODEL, timeout=30, work_root=self.work_root)

    def generate(self, backend):
        return backend.generate([{"role": "user", "content": "先返回动作"}],
                                {"type": "object"}, 42)

    def test_posix_uses_native_transport_without_wsl_layer(self):
        with self.patched("linux") as calls:
            backend = self.backend()
            self.assertEqual(backend.transport, "native")
            metadata = backend.metadata()
            self.assertEqual(metadata["transport"], "native")
            self.assertEqual(metadata["provider"], DEFAULT_PROVIDER)
            self.assertNotIn("wsl_distro", metadata)
            self.generate(backend)
        call = calls[-1]
        self.assertEqual(call["args"][0], self.paths["timeout"])
        self.assertNotIn("--cd", call["args"])
        self.assertNotIn("--exec", call["args"])
        self.assertNotIn("--distribution", call["args"])
        self.assertEqual(Path(call["cwd"]).name, "empty")
        self.assertIn("--kill-after=5s", call["args"])
        self.assertIn("--profile", call["args"])

    def test_windows_keeps_wsl_transport_and_cd_exec(self):
        with self.patched("win32") as calls:
            backend = self.backend()
            self.assertEqual(backend.transport, "wsl")
            metadata = backend.metadata()
            self.assertEqual(metadata["transport"], "wsl")
            self.assertIn("wsl_distro", metadata)
            self.generate(backend)
        call = calls[-1]
        self.assertEqual(call["args"][0], self.paths["wsl.exe"])
        self.assertIn("--distribution", call["args"])
        self.assertIn("--cd", call["args"])
        self.assertIn("--exec", call["args"])
        self.assertEqual(call["args"][call["args"].index("--exec") + 1], self.paths["timeout"])
        self.assertIsNone(call["cwd"])

    def test_provider_comes_from_environment_not_hardcoded(self):
        env = {"DSH_EVAL_PROVIDER": "custom-provider"}
        with self.patched("linux", env=env) as calls:
            backend = self.backend()
            self.assertEqual(backend.provider, "custom-provider")
            self.assertEqual(backend.metadata()["provider"], "custom-provider")
            self.generate(backend)
        run_dir = Path(calls[-1]["cwd"]).parent
        payload = json.loads((run_dir / "input.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["expected_provider"], "custom-provider")
        patch_text = (run_dir / "planner.patch.yml").read_text(encoding="utf-8")
        self.assertIn('"provider": "custom-provider"', patch_text)

    def test_invalid_provider_is_rejected(self):
        for value in ("", "bad provider", "bad/provider"):
            with self.subTest(value=value):
                with mock.patch.dict(os.environ, {"DSH_EVAL_PROVIDER": value}, clear=False):
                    with self.assertRaises(ValueError):
                        self.backend()

    def test_guard_and_identity_failures_are_fatal(self):
        samples = {
            "guard_failed": {"guard_self_test_denied": False},
            "tool_attempt": {"tool_attempts": 1},
            "model_tool_call": {"model_tool_calls": 1},
            "provider_mismatch": {"provider": "someone-else"},
            "model_mismatch": {"model": "other-model"},
            "status": {"status": "failed"},
        }
        for label, overrides in samples.items():
            with self.subTest(label=label):
                with self.patched("linux", audit_overrides=overrides):
                    backend = self.backend()
                    with self.assertRaises(RuntimeError):
                        self.generate(backend)

    def test_missing_binary_on_posix_is_rejected(self):
        which_map = {name: self.paths[name] for name in ("node", "dsh")}
        with self.patched("linux", which_map=which_map):
            with self.assertRaises(RuntimeError):
                self.backend()

    def test_windows_without_wsl_is_rejected(self):
        with self.patched("win32", which_map={}):
            with self.assertRaises(RuntimeError):
                self.backend()

    def test_work_root_outside_artifacts_is_rejected(self):
        with self.assertRaises(ValueError):
            DshBackend(model=MODEL, timeout=30, work_root=REPO / "tests")

    def test_availability_flag_only_after_verified_generation(self):
        with self.patched("linux"):
            backend = self.backend()
            self.assertFalse(backend.metadata()["availability_verified"])
            self.generate(backend)
            self.assertTrue(backend.metadata()["availability_verified"])

        failed = {"guard_self_test_denied": False}
        with self.patched("linux", audit_overrides=failed):
            backend = self.backend()
            with self.assertRaises(RuntimeError):
                self.generate(backend)
            self.assertFalse(backend.metadata()["availability_verified"])


if __name__ == "__main__":
    unittest.main()
