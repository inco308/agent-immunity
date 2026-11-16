"""区分网关启动失败、发现超时与其他宿主错误，并检查故障探针的实际退出码。"""
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import unittest
from unittest.mock import patch

from pilot.codex_time import host, startup_probe
from tests.support import temporary_directory


class GatewayStartupTests(unittest.TestCase):
    def start_host(self, runtime):
        def response(child, sequence, method, args):
            if method == "thread/start":
                return {"thread": {"id": "test"}}
            if method == "mcpServerStatus/list":
                if isinstance(runtime, Exception):
                    raise runtime
                return {"data": [{"name": host.SERVER_NAME, "runtimeStatus": runtime}]}
            return {}

        with patch.object(host, "configured_command"), patch.object(host, "_JsonProcess"), \
                patch.object(host, "rpc", side_effect=response), patch.object(host.time, "sleep"):
            host.host_stage("codex", Path("."), True)

    def test_failed_connection_and_discovery_poll_timeout_are_distinct(self):
        for runtime, state in (("failed", "failed"), ("starting", "discovery_timeout")):
            with self.subTest(runtime=runtime), self.assertRaises(host.GatewayStartupError) as raised:
                self.start_host(runtime)
            self.assertEqual(raised.exception.state, state)

    def test_authentication_and_rpc_error_do_not_count_as_gateway_startup_failure(self):
        for runtime in ("authenticationRequired", RuntimeError("RPC 不可用")):
            with self.subTest(runtime=runtime), self.assertRaises(RuntimeError) as raised:
                self.start_host(runtime)
            self.assertNotIsInstance(raised.exception, host.GatewayStartupError)

    def test_missing_policy_records_actual_exit_without_starting_upstream(self):
        with temporary_directory() as root:
            marker = Path(root) / "gateway-exit.txt"
            args = ["startup_probe.py", str(marker), "--policy", str(Path(root) / "missing.json"),
                    "--timeout", "15", "--", "unused-upstream"]
            stdout = io.StringIO()
            with patch.object(startup_probe.sys, "argv", args.copy()), redirect_stdout(stdout), \
                    redirect_stderr(io.StringIO()), patch("agent_immunity.mcp_stdio.StdioProxy") as upstream:
                self.assertEqual(startup_probe.main(), 2)
                upstream.assert_not_called()
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(marker.read_bytes(), b"2\n")
            with patch.object(startup_probe.sys, "argv", args.copy()), patch.object(startup_probe, "gateway_main", return_value=7):
                self.assertEqual(startup_probe.main(), 7)
            self.assertEqual(marker.read_bytes(), b"2\n")
