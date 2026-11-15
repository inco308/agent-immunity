"""通过 Codex App Server 的线程级接口调用项目配置中的真实 MCP 工具。"""
import json
from datetime import datetime, timedelta
import subprocess
import time

from evals.codex_backend import _JsonProcess


SERVER_NAME = "time_pilot"
INPUT = {"source_timezone": "UTC", "time": "09:00", "target_timezone": "Asia/Tokyo"}
HOST_VERSION = "0.167.0-alpha.3.2"


class GatewayStartupError(RuntimeError):
    """宿主发现网关启动失败，或在轮询期限内仍未发现可用连接。"""

    def __init__(self, state):
        self.state = state
        super().__init__(f"Codex 未能连接试点网关（{state}）")


def configured_command(binary, project, *args):
    """从本阶段活动文件读取一条 TOML 赋值，作为进程独立的 -c 参数。"""
    setting = (project / ".codex/config.toml").read_text(encoding="utf-8").rstrip("\n")
    return [str(binary), "-c", setting, *args]


def rpc(child, seq, method, params):
    child.send({"id": seq, "method": method, "params": params})
    while True:
        message = child.receive()
        if message is None:
            raise RuntimeError(f"Codex 在 {method} 期间退出")
        if "method" in message and "id" in message:
            raise RuntimeError(f"{method} 期间宿主请求交互，请核对配置")
        if message.get("id") == seq:
            if "error" in message:
                raise RuntimeError(f"Codex {method} 返回 RPC 错误 {message['error'].get('code')}")
            return message["result"]


def host_stage(binary, project, expect_weekday):
    command = configured_command(binary, project, "--no-daemon", "app-server", "--listen", "stdio://")
    child = _JsonProcess(command, project, 90)
    try:
        rpc(child, 1, "initialize", {"clientInfo": {"name": "time_pilot", "version": "1"}})
        child.send({"method": "initialized", "params": {}})
        session = rpc(child, 2, "thread/start", {
            "ephemeral": True, "cwd": str(project), "approvalPolicy": "never", "sandbox": "read-only",
        })
        thread_id = session["thread"]["id"]
        seq = 3
        while True:
            result = rpc(child, seq, "mcpServerStatus/list", {
                "threadId": thread_id, "serverName": SERVER_NAME, "detail": "toolsAndAuthOnly",
            })
            seq += 1
            statuses = [s for s in result["data"] if s["name"] == SERVER_NAME]
            runtime = statuses[0].get("runtimeStatus") if statuses else None
            if statuses and (runtime == "connected" or (runtime is None and statuses[0].get("tools"))):
                names = sorted(statuses[0]["tools"])
                break
            if runtime == "failed":
                raise GatewayStartupError("failed")
            if runtime == "authenticationRequired":
                raise RuntimeError("Codex 连接试点网关时需要认证")
            if seq > 50:
                raise GatewayStartupError("discovery_timeout")
            time.sleep(.25)
        if names != ["convert_time"]:
            raise ValueError("Codex 中可见的工具与本地登记不一致")
        params = {"threadId": thread_id, "server": SERVER_NAME, "tool": "convert_time", "arguments": INPUT}
        allowed = rpc(child, seq, "mcpServer/tool/call", params)
        if allowed.get("isError") or len(allowed.get("content", [])) != 1 or allowed["content"][0].get("type") != "text":
            raise ValueError("首次时区转换未取得预期的文本结果")
        clock = json.loads(allowed["content"][0]["text"])
        for key, zone, hour, offset in (("source", "UTC", 9, 0), ("target", "Asia/Tokyo", 18, 9)):
            entry = clock[key]
            point = datetime.fromisoformat(entry["datetime"])
            if (entry["timezone"] != zone or (point.hour, point.minute) != (hour, 0)
                    or point.utcoffset() != timedelta(hours=offset)):
                raise ValueError("第三方工具返回了错误的时区或时间")
            if ("day_of_week" in entry) != expect_weekday or (expect_weekday and not entry["day_of_week"]):
                raise ValueError("上游返回字段与激活版本不符")
        if clock["time_difference"] != "+9.0h":
            raise ValueError("时差不符")
        denied = rpc(child, seq + 1, "mcpServer/tool/call", params)
        code = (denied.get("_meta") or {}).get("agent_immunity", {}).get("code")
        if not denied.get("isError") or code != "TRANSITION_DENIED":
            raise ValueError("同会话第二次转换未取得网关的策略拒绝")
        return {"visible_tools": names, "source": "UTC 09:00", "target": "Asia/Tokyo 18:00",
                "difference": clock["time_difference"], "weekday_field": expect_weekday, "denial": code}
    finally:
        try:
            if child.process.stdin and not child.process.stdin.closed:
                child.process.stdin.close()
            child.process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            pass
        finally:
            child.close()
