"""以已发布的 Inspector mcpdo 驱动独立 SDK 上游；不使用自制 JSON-RPC 客户端。"""
import argparse
import base64
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "sdk_workspace"
INSPECTOR = REPO / "interop" / "node_modules" / "@modelcontextprotocol" / "inspector"
CLIENT = INSPECTOR / "clients" / "mcpdo" / "build" / "mcp-bin.js"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def journal_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


class InspectorClient:
    """只启动外部客户端命令；协议、连接和重连由 Inspector 实现。"""
    def __init__(self, node, storage):
        self.node = node
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("MCP_")}
        self.env.update({
            "MCP_STORAGE_DIR": str(storage),
            "MCP_INSPECTOR_DAEMON_DIR": str(storage / "daemon"),
            "MCP_INSPECTOR_DAEMON_TOKEN": secrets.token_hex(32),
            "MCP_INSPECTOR_OAUTH_STATE_PATH": str(storage / "oauth.json"),
            "MCP_INSPECTOR_SECRET_FILE": str(storage / "secrets.json"),
            "MCP_INSPECTOR_SECRET_STORE": "file",
            "MCP_CLIENT_CONFIG_PATH": str(storage / "client-config.json"),
            "MCP_AUTO_OPEN_ENABLED": "false",
            "NO_COLOR": "1",
            "PYTHONIOENCODING": "utf-8",
        })
        (storage / "catalog.json").write_text('{"mcpServers":{}}', encoding="utf-8")
        (storage / "client-config.json").write_text('{}', encoding="utf-8")
        self.commands = 0

    def run(self, *args, allowed_codes=(0,), timeout=45):
        completed = subprocess.run(
            [self.node, str(CLIENT), "--format", "json", *map(str, args)],
            cwd=REPO, env=self.env, capture_output=True, text=True,
            encoding="utf-8", timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self.commands += 1
        if completed.returncode not in allowed_codes:
            # 本例只包含虚构数据；错误摘要不回显完整命令或工具参数。
            raise RuntimeError(f"Inspector {args[0]} 失败，退出码 {completed.returncode}: {completed.stderr[-1200:]}")
        try:
            # 不存在的工具由 Inspector 的发现缓存拒绝，错误 JSON 只写 stderr。
            payload = json.loads(completed.stdout if completed.stdout.strip() else completed.stderr)
        except ValueError as exc:
            raise RuntimeError(f"Inspector {args[0]} 未返回 JSON，退出码 {completed.returncode}: {completed.stderr[-1200:]}") from exc
        return completed.returncode, payload

    def call(self, name, arguments=None, allowed_codes=(0,)):
        return self.run("--connection", "immunity", "tools/call", name,
                        "--tool-args-json", json.dumps(arguments or {}, ensure_ascii=False),
                        allowed_codes=allowed_codes)

    def info(self):
        _, result = self.call("session_info")
        return result["structuredContent"]

    def stop(self):
        self.run("daemon", "stop")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            _, status = self.run("daemon", "status")
            require(type(status.get("running")) is bool, "Inspector daemon 状态缺少 running 字段")
            if not status.get("running"):
                return
            time.sleep(.1)
        raise RuntimeError("本次测试的 Inspector daemon 未退出")


def make_report(project):
    counts = Counter(task["status"] for task in project["tasks"])
    lines = [f"# {project['name']} 状态报告", "", project["description"], "",
             f"任务总数：{len(project['tasks'])}",
             f"已完成：{counts['done']}；进行中：{counts['doing']}；待处理：{counts['todo']}", ""]
    lines.extend(f"- {task['id']} {task['title']} [{task['status']}]" for task in project["tasks"])
    return "\n".join(lines) + "\n"


def prepare(run_dir, origin):
    workspace = run_dir / "工作 目录"
    workspace.mkdir()
    data = load_json(EXAMPLE / "fixtures.json")
    for key in ("project", "credentials"):
        (workspace / data["paths"][key]).write_text(json.dumps(data[key], ensure_ascii=False), encoding="utf-8")
    (workspace / data["paths"]["notes"]).write_text(data["notes"], encoding="utf-8")
    policy = load_json(EXAMPLE / "policy.template.json")
    policy["workspace"] = str(workspace)
    policy["tools"]["publish_report"]["origins"] = [origin]
    policy_path = run_dir / "policy.json"
    policy_path.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
    journal = run_dir / "upstream.jsonl"
    config = {
        "mcpServers": {
            "immunity": {
                "command": sys.executable,
                "args": ["-X", "utf8", "-m", "agent_immunity.mcp_stdio",
                         "--policy", str(policy_path), "--timeout", "8", "--",
                         sys.executable, "-X", "utf8", str(EXAMPLE / "server.py"),
                         "--workspace", str(workspace), "--journal", str(journal)],
                "cwd": str(REPO), "protocolEra": "legacy", "requestTimeout": 0,
            }
        }
    }
    config_path = run_dir / "client.json"
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    return data, workspace, policy_path, journal, config_path


def run(node, output):
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    run_dir = output.parent / ("run-" + uuid.uuid4().hex[:10])
    run_dir.mkdir()
    report = {"schema_version": 1, "scope": "INSPECTOR_SDK_APPLICATION_E2E",
              "status": "running", "checks": [], "run_directory": str(run_dir),
              "not_measured": ["LLM planning or prompt-injection susceptibility",
                               "production client ecosystem compatibility", "OS sandboxing"]}
    # 即使本轮被外部强制终止，也不能残留上一轮的成功报告。
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 <= size <= 65536:
                self.send_error(413)
                return
            received.append({"path": self.path, "body": self.rfile.read(size)})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"published")
        def log_message(self, *args):
            pass

    server = None
    client = None
    storage_context = None
    data = None

    def check(name, **evidence):
        report["checks"].append({"name": name, "status": "passed", **evidence})
        print("PASS", name, flush=True)

    try:
        require(CLIENT.exists(), "请先在 interop 目录运行 npm ci --ignore-scripts")
        require(importlib.metadata.version("mcp") == "1.30.0", "此验证入口要求锁定的 mcp==1.30.0 环境")
        inspector_version = load_json(INSPECTOR / "package.json")["version"]
        require(inspector_version == "2.14.0", "Inspector 版本与锁定测试对象不符")
        node_version = subprocess.check_output([node, "--version"], text=True).strip()
        require(node_version == "v24.22.1", "此验证入口固定 Node 24.22.1")
        report["versions"] = {"inspector": inspector_version, "node": node_version,
                              "mcp_python": importlib.metadata.version("mcp"), "python": platform.python_version()}
        server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        origin = f"http://127.0.0.1:{server.server_port}"
        data, workspace, policy_path, journal, config_path = prepare(run_dir, origin)
        # Unix socket 需要短路径；Windows 使用工作区内目录以兼容受限 TEMP。
        temp_parent = None
        if os.name == "nt":
            temp_parent = REPO / ".test-tmp"
            temp_parent.mkdir(exist_ok=True)
        storage_context = tempfile.TemporaryDirectory(prefix="aimcp-", dir=temp_parent)
        client = InspectorClient(node, Path(storage_context.name))
        client.run("connect", "immunity", "--config", config_path, "--era", "legacy", "--elicit", "off")
        _, connection = client.run("connections/show", "immunity")
        require(connection.get("protocolVersion") == "2025-06-18", f"协议协商不符：{connection}")
        check("official_client_handshake", protocol=connection["protocolVersion"])
        _, listing = client.run("--connection", "immunity", "tools/list")
        names = {tool["name"] for tool in listing["tools"]}
        require("admin_action" not in names and {"read_document", "write_report", "publish_report"} <= names, "工具发现未应用本地登记")
        check("filtered_tool_discovery", visible_tools=sorted(names))
        first = client.info()
        _, source = client.call("read_document", {"path": data["paths"]["project"]})
        require(source["structuredContent"]["session_id"] == first["session_id"], "读取项目时意外重连")
        project = json.loads(source["structuredContent"]["text"])
        counts = Counter(task["status"] for task in project["tasks"])
        expected = data["expected"]
        require(len(project["tasks"]) == expected["task_count"] and all(counts[k] == expected[k + "_count"] for k in ("done", "doing", "todo")), "读取项目统计不符")
        report_text = make_report(project)
        client.call("write_report", {"path": data["paths"]["report"], "content": report_text})
        _, reread = client.call("read_document", {"path": data["paths"]["report"]})
        require(reread["structuredContent"]["text"] == report_text, "写入后读取结果不一致")
        require((workspace / data["paths"]["report"]).read_text(encoding="utf-8") == report_text, "未生成真实报告")
        client.call("publish_report", {"url": origin + "/reports", "payload": report_text})
        require(len(received) == 1 and received[0]["body"].decode("utf-8") == report_text, "真实接收器未收到完整报告")
        (output.parent / "status-report.md").write_text(report_text, encoding="utf-8")
        check("read_generate_write_reread_publish", task_count=len(project["tasks"]),
              report_bytes=len(report_text.encode("utf-8")), http_requests=len(received))
        client.call("read_document", {"path": data["paths"]["credentials"]})
        # 在同一会话中只读取一次凭证，后续明文/编码等请求必须共享跟踪状态。
        secret = data["credentials"]["api_key"]
        replacements = {"$ORIGIN": origin, "$SECRET_BASE64": base64.b64encode(secret.encode()).decode(), "$SECRET": secret}
        for case in data["attacks"]:
            arguments = dict(case["arguments"])
            for key, value in arguments.items():
                if isinstance(value, str):
                    for source, target in replacements.items():
                        value = value.replace(source, target)
                    arguments[key] = value
            before = len(journal_rows(journal))
            rc, result = client.call(case["tool"], arguments, allowed_codes=(5,))
            if "expected_client_error" in case:
                code = result.get("error", {}).get("code")
                require(code == case["expected_client_error"], f"{case['id']} 客户端错误不符：{code}")
                layer = "inspector_after_filtered_discovery"
            else:
                require(result.get("isError") is True, f"{case['id']} 未返回工具错误")
                code = result.get("_meta", {}).get("agent_immunity", {}).get("code")
                require(code == case["expected_code"], f"{case['id']} 拒绝码不符：{code}")
                layer = "gateway"
            require(len(journal_rows(journal)) == before, f"{case['id']} 仍到达上游")
            require(len(received) == 1, f"{case['id']} 产生了额外 HTTP 请求")
            check(case["id"], category=case["category"], denial_code=code, enforcement_layer=layer, client_exit_code=rc, forwarded=False)
        require(not any((workspace / name).exists() for name in ("admin-marker.txt", "leaked-secret.txt")), "拒绝调用产生标记文件")
        require(not (workspace.parent / "outside.txt").exists(), "越界调用产生文件")
        _, notes = client.call("read_document", {"path": data["paths"]["notes"]})
        client.call("publish_report", {"url": origin + "/notes", "payload": notes["structuredContent"]["text"]})
        require(len(received) == 2 and received[-1]["body"].decode("utf-8") == data["notes"], "正常安全术语文档被误拒绝")
        require(client.info()["session_id"] == first["session_id"], "攻击/正常调用期间客户端更换了会话")
        check("same_session_and_benign_control", session_id=first["session_id"], http_requests=len(received))
        _, failure = client.call("fail_task", allowed_codes=(5,))
        require(failure.get("isError") is True and "agent_immunity" not in failure.get("_meta", {}), "SDK 工具错误被错误归类")
        require(client.info()["session_id"] == first["session_id"], "正常工具错误使会话失效")
        check("sdk_tool_error_preserves_session")
        before_slow = len([r for r in journal_rows(journal) if r["tool"] == "slow_task"])
        rc, timeout_result = client.call("slow_task", allowed_codes=(1, 4, 5))
        require(rc != 0, "慢工具未触发失败")
        timeout_message = timeout_result.get("error", {}).get("message", "")
        require(timeout_message == "上游响应超时，会话已关闭", f"失败不是代理超时：{timeout_result}")
        require(len([r for r in journal_rows(journal) if r["tool"] == "slow_task"]) == before_slow + 1, "慢工具未被实际调用或被自动重试")
        from sdk_cancellation import process_is_running
        deadline = time.monotonic() + 5
        while process_is_running(first["pid"]) and time.monotonic() < deadline:
            time.sleep(.05)
        require(not process_is_running(first["pid"]), "超时后的旧上游仍在运行")
        after = client.info()
        require(after["session_id"] != first["session_id"], "超时后未建立新的上游会话")
        require(not (workspace / "slow-marker.txt").exists(), "慢工具发生了延迟写入")
        client.call("write_report", {"path": "after-reconnect.txt", "content": "public recovery check"})
        check("timeout_then_new_session", old_session=first["session_id"], new_session=after["session_id"],
              client_exit_code=rc, client_error_classification="gateway_timeout_message",
              numeric_code_preserved_by_client=False, old_upstream_exited=True,
              tool_retries=0, credential_state="new_session_created")
        # 明确记录跨会话限制：新代理尚未识别该虚构凭证，第一次可通过；重新读取后才拒绝。
        fresh_payload = {"url": origin + "/session-limit", "payload": replacements["$SECRET_BASE64"]}
        client.call("publish_report", fresh_payload)
        require(len(received) == 3 and received[-1]["body"].decode("utf-8") == fresh_payload["payload"], "新会话边界对照不符")
        client.call("read_document", {"path": data["paths"]["credentials"]})
        before_replay = len(journal_rows(journal))
        _, replay = client.call("publish_report", fresh_payload, allowed_codes=(5,))
        require(replay.get("_meta", {}).get("agent_immunity", {}).get("code") == "SENSITIVE_FLOW", "新会话重新读取后未阻断")
        require(len(received) == 3 and len(journal_rows(journal)) == before_replay, "重复凭证请求仍有副作用")
        check("cross_session_tracking_limit_observed", known_limitation=True,
              before_reobservation="allowed_to_loopback", after_reobservation="blocked")
        client.run("disconnect", "immunity")
        check("explicit_disconnect")
        # 精确取消通知的补充验证使用官方 Python SDK 公开接口，不归入 Inspector 的能力声明。
        from sdk_cancellation import verify_cancellation
        import anyio
        cancellation = anyio.run(verify_cancellation, sys.executable, REPO, policy_path, EXAMPLE / "server.py", workspace, run_dir / "cancellation.jsonl")
        check("official_sdk_cancellation", **cancellation)
        report["upstream_calls"] = journal_rows(journal)
        report["client_commands"] = client.commands
        report["status"] = "passed"
    except Exception as exc:
        report["status"] = "failed"
        message = f"{type(exc).__name__}: {exc}"
        if data:
            secret = data["credentials"]["api_key"]
            message = message.replace(secret, "[CANARY]").replace(base64.b64encode(secret.encode()).decode(), "[CANARY_BASE64]")
        report["error"] = message
    finally:
        if client:
            try:
                client.stop()
                check("private_daemon_stopped")
            except Exception as exc:
                report["status"] = "failed"
                report["cleanup_error"] = f"{type(exc).__name__}: 私有客户端守护进程清理失败"
        if server:
            server.shutdown()
            server.server_close()
        if storage_context and "cleanup_error" not in report:
            try:
                storage_context.cleanup()
            except OSError:
                report["status"] = "failed"
                report["cleanup_error"] = "私有客户端状态目录清理失败"
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"端到端报告：{output}")
    if report["status"] != "passed":
        print(report.get("error", report.get("cleanup_error", "验证未通过")), file=sys.stderr)
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", default=shutil.which("node"), help="固定版本的 Node 24.22.1 可执行文件")
    parser.add_argument("--output", type=Path, default=REPO / "artifacts" / "interop" / "report.json")
    args = parser.parse_args()
    if not args.node:
        parser.error("需要 --node 指定 Node 24.22.1")
    return run(str(Path(args.node).resolve()), args.output)


if __name__ == "__main__":
    raise SystemExit(main())
