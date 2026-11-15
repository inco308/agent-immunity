"""真实 stdio 代理面对慢读、停读和断管客户端时的输出与退出行为。"""

import json
import os
from pathlib import Path
import queue
import select
import subprocess
import sys
import threading
import time
import unittest

from tests.support import DATA, FIXTURES, policy_data, temporary_directory


REPO = Path(__file__).resolve().parents[1]
# 两个方向的 JSON 帧均小于默认 256 KiB。ASCII 主体比一个系统管道大得多。
TEXT = DATA["document"] + ("a" * 1536 + "分块🙂\n") * 112
READ_TEXT = {"name": "read_file", "arguments": {"path": "large.txt"}}
WRITE_LATER = {"name": "write_file", "arguments": {"path": "later.txt", "content": "unexpected"}}


def bounded_read(operation, timeout=6):
    """管道读取由临时线程执行；被测程序即使挂起也不会阻塞测试主线程。"""
    result = queue.Queue(maxsize=1)

    def read():
        try:
            value = operation()
        except Exception as exc:
            result.put((False, exc))
        else:
            result.put((True, value))

    threading.Thread(target=read, daemon=True).start()
    try:
        ok, value = result.get(timeout=timeout)
    except queue.Empty as exc:
        raise AssertionError("限期内未读到预期响应") from exc
    if not ok:
        raise value
    return value


def wait_readable(stream, timeout=4):
    """等待第一批真实响应字节可读，保持管道内容原样。"""
    if os.name == "nt":
        import _winapi
        import msvcrt

        handle = msvcrt.get_osfhandle(stream.fileno())
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if _winapi.PeekNamedPipe(handle, 0)[0]:
                return
            time.sleep(0.005)
    elif select.select([stream], [], [], timeout)[0]:
        return
    raise AssertionError("上游结果没有进入代理的输出管道")


def process_alive(pid):
    if os.name == "nt":
        import _winapi

        try:
            handle = _winapi.OpenProcess(_winapi.SYNCHRONIZE, False, pid)
        except OSError as exc:
            if exc.winerror == 87:  # PID 已退出，无法打开该进程。
                return False
            raise
        try:
            return _winapi.WaitForSingleObject(handle, 0) == _winapi.WAIT_TIMEOUT
        finally:
            _winapi.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class ClientOutputTests(unittest.TestCase):
    def setUp(self):
        fixture = temporary_directory()
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name)
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_text(json.dumps(policy_data(self.root)), encoding="utf-8")
        (self.root / "large.txt").write_text(TEXT, encoding="utf-8")
        self.upstream = None

    def command(self, output_timeout):
        return [
            sys.executable, "-X", "utf8", "-m", "agent_immunity.mcp_stdio",
            "--policy", str(self.policy_path), "--output-timeout", str(output_timeout),
            "--timeout", "3", "--", sys.executable, "-X", "utf8", "-u",
            str(FIXTURES / "mcp_server.py"), "--root", str(self.root),
        ]

    def start(self, timeout):
        self.proc = subprocess.Popen(self.command(timeout), cwd=REPO, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        self.addCleanup(self.stop)
        if sys.platform.startswith("linux"):
            import fcntl

            size = fcntl.fcntl(self.proc.stdout, fcntl.F_SETPIPE_SZ, 4096)
            self.assertLess(size, len(TEXT.encode("utf-8")))
        self.send(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                   "clientInfo": {"name": "bounded-output-test", "version": "1"}})
        frame = bounded_read(self.proc.stdout.readline)
        self.assertEqual(json.loads(frame)["result"]["protocolVersion"], "2025-06-18")
        self.send(None, "notifications/initialized", {})
        self.upstream = int((self.root / "server.pid").read_text(encoding="utf-8"))
        self.assertTrue(process_alive(self.upstream))

    def stop(self):
        self.proc.stdout.close()
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)

    def send(self, identifier, method, params):
        request = {"jsonrpc": "2.0", "method": method, "params": params}
        if identifier is not None:
            request["id"] = identifier
        data = (json.dumps(request) + "\n").encode("utf-8")
        self.assertEqual(self.proc.stdin.write(data), len(data))

    def upstream_calls(self):
        path = self.root / "calls.jsonl"
        return [json.loads(line)["name"] for line in path.read_text(encoding="utf-8").splitlines()]

    def assert_failed_and_reaped(self):
        self.assertFalse(self.proc.stdin.closed)
        self.assertEqual(self.proc.wait(timeout=6), 1)
        self.assertFalse(process_alive(self.upstream), "代理退出后直接上游仍存活")
        self.assertEqual(self.upstream_calls(), ["read_file"])

    def test_stalled_output_exits_without_dispatching_queued_followup(self):
        self.start(0.6)
        self.send(2, "tools/call", READ_TEXT)
        wait_readable(self.proc.stdout)
        self.send(3, "tools/call", WRITE_LATER)
        self.assert_failed_and_reaped()
        self.assertFalse((self.root / "later.txt").exists())

    def test_chunked_reader_gets_complete_ordered_utf8_frames(self):
        self.start(3)
        self.send(2, "tools/call", READ_TEXT)
        wait_readable(self.proc.stdout)
        self.send(3, "ping", {})

        def read_two_frames():
            parts = []
            lines = 0
            while lines < 2:
                part = self.proc.stdout.read(2047)
                if not part:
                    raise AssertionError("完整响应之前收到 EOF")
                parts.append(part)
                lines += part.count(b"\n")
                time.sleep(0.003)
            return b"".join(parts)

        raw = bounded_read(read_two_frames)
        self.assertTrue(raw.endswith(b"\n"))
        first, second = [json.loads(line.decode("utf-8")) for line in raw.splitlines()]
        self.assertEqual(first["id"], 2)
        self.assertFalse(first["result"]["isError"])
        self.assertEqual(first["result"]["content"][0]["text"], TEXT)
        self.assertEqual(second, {"id": 3, "jsonrpc": "2.0", "result": {}})
        self.assertEqual(self.upstream_calls(), ["read_file"])
        self.proc.stdin.close()
        self.assertEqual(self.proc.wait(timeout=5), 0)

    def test_closed_output_exits_promptly_with_input_still_open(self):
        self.start(300)
        self.send(2, "tools/call", READ_TEXT)
        wait_readable(self.proc.stdout)
        self.proc.stdout.close()
        self.assert_failed_and_reaped()

    def test_invalid_output_timeout_fails_before_upstream_starts(self):
        for invalid in ("0", "-1", "300.01", "nan", "inf"):
            with self.subTest(output_timeout=invalid):
                result = subprocess.run(self.command(invalid), cwd=REPO, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "server.pid").exists())


if __name__ == "__main__":
    unittest.main()
