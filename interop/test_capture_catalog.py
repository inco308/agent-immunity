"""验证官方 SDK 原始目录采集的发现范围、分页限制和输出完整性。"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import anyio

from agent_immunity import capture as catalog
from interop.sdk_cancellation import process_is_running


REPO = Path(__file__).resolve().parents[1]
SERVER = REPO / "examples" / "sdk_workspace" / "server.py"


def page(names, cursor=None, schema=None):
    return SimpleNamespace(
        tools=[SimpleNamespace(name=name, inputSchema=schema or {"type": "object"},
                               description="UPSTREAM_PRIVATE_DESCRIPTION") for name in names],
        nextCursor=cursor,
    )


class CatalogTests(unittest.TestCase):
    def setUp(self):
        parent = REPO / ".test-tmp"
        parent.mkdir(exist_ok=True)
        tmp = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.output = self.root / "catalog.json"

    def pages(self, responses, **limits):
        self.cursors = []
        responses = iter(responses)

        async def list_page(cursor):
            self.cursors.append(cursor)
            return next(responses)

        async def collect():
            return await catalog.collect_pages(list_page, time.monotonic() + 5, **limits)
        return anyio.run(collect)

    def cli(self, command, timeout=15):
        return subprocess.run(
            [sys.executable, "-X", "utf8", "-m", "interop.capture_catalog",
             "--output", str(self.output), "--timeout", str(timeout), "--", *command],
            cwd=REPO, capture_output=True, encoding="utf-8", timeout=timeout + 20,
        )

    def test_capture_independent_sdk_without_business_calls(self):
        work = self.root / "workspace"
        work.mkdir()
        journal = self.root / "calls.jsonl"
        self.output.write_bytes(b"previous")
        proc = self.cli([sys.executable, "-X", "utf8", str(SERVER), "--workspace", str(work),
                         "--journal", str(journal)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")
        snapshot = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(set(snapshot), {"tools"})
        tools = {t["name"]: t for t in snapshot["tools"]}
        # 私有管理工具被网关过滤。这里能看到它才证明采集的是原始上游。
        self.assertIn("admin_action", tools)
        self.assertIn("publish_report", tools)
        self.assertEqual(set(tools["read_document"]), {"name", "inputSchema"})
        self.assertEqual(tools["read_document"]["inputSchema"]["properties"]["path"], {"type": "string"})
        self.assertIn("path", tools["read_document"]["inputSchema"]["required"])
        self.assertFalse(journal.exists())
        self.assertEqual(list(work.iterdir()), [])

    def test_schema_annotations_removed_while_constraints_and_literals_survive(self):
        business_value = {"description": "业务枚举值", "examples": ["d"], "default": 9}
        schema = {
            "$defs": {"summary": {"description": "私有描述", "type": "string", "pattern": "^[a-z]+$"}},
            "type": "object", "description": "PRIVATE", "examples": ["example-secret"],
            "required": ["description", "title"], "additionalProperties": False,
            "properties": {
                "description": {"title": "字段说明", "enum": [business_value]},
                "title": {"anyOf": [{"$ref": "#/$defs/summary"}, {"type": "null", "default": None}]},
            },
        }
        first = page(["read"], "opaque", schema)
        blob = self.pages([first, page(["write"])])
        self.assertEqual(self.cursors, [None, "opaque"])
        tools = json.loads(blob)["tools"]
        self.assertEqual([t["name"] for t in tools], ["read", "write"])
        clean = tools[0]["inputSchema"]
        self.assertEqual(clean, {
            "$defs": {"summary": {"type": "string", "pattern": "^[a-z]+$"}},
            "type": "object", "required": ["description", "title"], "additionalProperties": False,
            "properties": {"description": {"enum": [business_value]},
                           "title": {"anyOf": [{"$ref": "#/$defs/summary"}, {"type": "null"}]}},
        })
        self.assertNotIn(b"PRIVATE", blob)

    def test_limits_and_duplicate_pages_abort(self):
        tests = (
            ([page(["a"], "loop"), page([], "loop")], {}, "游标"),
            ([page(["a"], "next"), page(["a"])], {}, "工具名"),
            ([page([], "next")], {"max_pages": 1}, "页数"),
            ([page(["a", "b"])], {"max_tools": 1}, "数量"),
            ([page(["a"])], {"max_bytes": 16}, "字节"),
            ([page(["a"], schema={"$ref": "#/properties/x/examples/0"})], {}, "引用"),
        )
        for responses, limits, error in tests:
            with self.subTest(error=error), self.assertRaisesRegex(catalog.CatalogError, error):
                self.pages(responses, **limits)

    def test_timeout_releases_upstream_and_preserves_previous_file(self):
        self.output.write_bytes(b"previous")
        pidfile = self.root / "pid"
        script = (
            "from pathlib import Path\n"
            "import os,sys,time\n"
            "Path(sys.argv[1]).write_text(str(os.getpid()))\n"
            "print('PRIVATE_UPSTREAM_STDERR',file=sys.stderr,flush=True)\n"
            "time.sleep(60)\n"
        )
        proc = self.cli([sys.executable, "-c", script, str(pidfile)], timeout=2)
        self.assertEqual(proc.returncode, 1)
        self.assertTrue(pidfile.exists(), "须已启动上游，才构成进程回收验证")
        self.assertFalse(process_is_running(int(pidfile.read_text())))
        self.assertIn("超时", proc.stderr)
        self.assertEqual(proc.stdout, "")
        self.assertNotIn("PRIVATE", proc.stderr)
        self.assertEqual(self.output.read_bytes(), b"previous")
        self.assertEqual(list(self.root.glob(".catalog-*")), [])

    def test_incompatible_protocol_aborts_before_tool_discovery(self):
        self.output.write_bytes(b"previous")
        journal = self.root / "methods.txt"
        script = (
            "import json,sys\n"
            "for line in sys.stdin:\n"
            "    call=json.loads(line)\n"
            "    with open(sys.argv[1], 'a') as log: print(call['method'],file=log)\n"
            "    result={'protocolVersion':'2025-11-25','capabilities':{'tools':{}},"
            "'serverInfo':{'name':'PRIVATE_SERVER_INFO','version':'1'}}\n"
            "    print(json.dumps({'jsonrpc':'2.0','id':call['id'],'result':result}),flush=True)\n"
        )
        proc = self.cli([sys.executable, "-c", script, str(journal)])
        self.assertEqual(proc.returncode, 1)
        self.assertIn("2025-06-18", proc.stderr)
        self.assertNotIn("PRIVATE_SERVER_INFO", proc.stderr)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(journal.read_text().splitlines(), ["initialize"])
        self.assertEqual(self.output.read_bytes(), b"previous")

    def test_atomic_replace_failure_leaves_no_partial_snapshot(self):
        self.output.write_bytes(b"previous")
        with patch.object(catalog.os, "replace", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                catalog.write_atomic(self.output, b"new")
        self.assertEqual(self.output.read_bytes(), b"previous")
        self.assertEqual(list(self.root.glob(".catalog-*")), [])


if __name__ == "__main__":
    unittest.main()
