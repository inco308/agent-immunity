"""复用已登录 Codex CLI 的无原生工具 JSON 规划后端。

仅由 CLI 自行读取既有登录；本模块不读取凭证文件、不修改全局配置。
模型目录来源： https://developers.openai.com/codex/app-server/
非交互协议： https://developers.openai.com/codex/noninteractive/
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import queue
import shutil
import signal
import subprocess
import threading
import time
from typing import Any
import uuid


_DISABLED_FEATURES = (
    "shell_tool", "unified_exec", "apps", "plugins", "hooks", "browser_use",
    "computer_use", "multi_agent", "image_generation", "view_image",
)
_INFORMATIONAL_WARNING = "Under-development features enabled: skip_host_skill_discovery."
_MAX_STDOUT_BYTES = 8 * 1024 * 1024


class CodexBackendError(RuntimeError):
    """模型、CLI 或输出协议失败；不得计为业务工具拦截。"""


def _process_options() -> dict[str, Any]:
    """隐藏自建进程窗口，并将进程树与父评测器隔离以便超时清理。"""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _feature_flags() -> list[str]:
    result: list[str] = []
    for name in _DISABLED_FEATURES:
        result.extend(("--disable", name))
    result.extend(("--enable", "skip_host_skill_discovery", "-c", 'web_search="disabled"', "-c", "project_doc_max_bytes=0"))
    return result


class _JsonProcess:
    """分别读取标准输出和错误流；标准输出只接受有界 JSONL。"""

    def __init__(self, command: list[str], cwd: Path, timeout: float):
        self.deadline = time.monotonic() + timeout
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.bytes_read = 0
        self.stderr_bytes = 0
        try:
            self.process = subprocess.Popen(
                command, cwd=str(cwd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
                shell=False, **_process_options(),
            )
        except OSError as exc:
            raise CodexBackendError("无法启动 Codex CLI") from exc
        self.reader = threading.Thread(target=self._read_stdout, daemon=True)
        self.error_reader = threading.Thread(target=self._drain_stderr, daemon=True)
        self.reader.start()
        self.error_reader.start()

    def _read_stdout(self) -> None:
        try:
            assert self.process.stdout is not None
            for line in self.process.stdout:
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def _drain_stderr(self) -> None:
        # 错误流不混入协议，不持久化可能含本地路径或服务诊断信息的原文。
        assert self.process.stderr is not None
        while chunk := self.process.stderr.read(4096):
            self.stderr_bytes += len(chunk.encode("utf-8"))

    def send(self, value: dict[str, Any]) -> None:
        self.send_text(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")

    def send_text(self, text: str) -> None:
        try:
            assert self.process.stdin is not None
            self.process.stdin.write(text)
            self.process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise CodexBackendError("Codex 输入通道已关闭") from exc

    def receive(self) -> dict[str, Any] | None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise CodexBackendError("Codex 调用超时")
        try:
            line = self.lines.get(timeout=remaining)
        except queue.Empty as exc:
            raise CodexBackendError("Codex 调用超时") from exc
        if line is None:
            return None
        self.bytes_read += len(line.encode("utf-8"))
        if self.bytes_read > _MAX_STDOUT_BYTES:
            raise CodexBackendError("Codex JSON 事件超过容量限制")
        try:
            event = json.loads(line)
        except ValueError as exc:
            raise CodexBackendError("Codex 标准输出包含非 JSON 事件") from exc
        if not isinstance(event, dict):
            raise CodexBackendError("Codex JSON 事件必须是对象")
        return event

    def wait(self) -> int:
        try:
            return self.process.wait(timeout=max(0.01, self.deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise CodexBackendError("Codex 进程退出超时") from exc

    def close(self) -> None:
        if self.process.poll() is None:
            if os.name == "nt":
                try:
                    subprocess.run(
                        ["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=5, check=False, shell=False, **_process_options(),
                    )
                except (OSError, subprocess.TimeoutExpired):
                    self.process.kill()
            else:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass


class CodexBackend:
    """每次传入完整历史，启动临时 CLI 会话，只接收一个 JSON 规划结果。

    metadata() 延迟读取模型目录。默认模型取目录 isDefault，显式模型须匹配
    目录 model 或 id；生成时总是传入 -m，绝不使用模型自己的身份陈述。
    目录可能为缓存；model_availability_verified 只有成功生成之后才为真。
    """

    def __init__(self, model: str | None = None, timeout: float = 180, work_root: Path | None = None):
        if model is not None and (not isinstance(model, str) or not model.strip()):
            raise ValueError("model 必须是非空字符串或 None")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout 必须是有限正数")
        executable = shutil.which("codex")
        if executable is None:
            raise CodexBackendError("未找到 Codex CLI；请先安装并登录")
        self.executable = executable
        self.requested_model = model
        self.model: str | None = None
        self.timeout = float(timeout)
        default_root = Path(__file__).resolve().parents[1] / "artifacts" / "llm-eval" / "codex"
        self.work_root = (Path(work_root) if work_root is not None else default_root).resolve()
        self.work_root.mkdir(parents=True, exist_ok=True)
        self._version: str | None = None
        self._model_source: str | None = None
        self._model_availability_verified = False
        self._discovery_lock = threading.Lock()

    def _rpc(self, child: _JsonProcess, request_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
        child.send({"id": request_id, "method": method, "params": params})
        while True:
            event = child.receive()
            if event is None:
                raise CodexBackendError("模型目录进程提前结束")
            if event.get("id") == request_id:
                if "error" in event or not isinstance(event.get("result"), dict):
                    raise CodexBackendError(f"模型目录 {method} 请求失败")
                return event["result"]
            if "id" in event or str(event.get("method", "")).startswith(("thread/", "turn/", "item/", "command/", "process/")):
                raise CodexBackendError("模型目录读取期间出现非预期请求或动作")

    def _discover(self) -> None:
        with self._discovery_lock:
            if self.model is not None:
                return
            try:
                version = subprocess.run(
                    [self.executable, "--version"], capture_output=True, text=True, encoding="utf-8",
                    timeout=min(self.timeout, 30), check=False, shell=False, **_process_options(),
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise CodexBackendError("无法读取 Codex CLI 版本") from exc
            if version.returncode != 0 or not version.stdout.strip().startswith("codex-cli "):
                raise CodexBackendError("Codex CLI 版本输出异常")
            self._version = version.stdout.strip().splitlines()[0]
            directory = self.work_root / ("catalog_" + uuid.uuid4().hex)
            directory.mkdir()
            child = _JsonProcess([self.executable, "app-server", "--listen", "stdio://", *_feature_flags()], directory, self.timeout)
            try:
                self._rpc(child, 1, "initialize", {"clientInfo": {"name": "agent_immunity_eval", "version": "0.1.0"}})
                child.send({"method": "initialized", "params": {}})
                catalog: list[dict[str, Any]] = []
                cursor = None
                for page in range(32):
                    params: dict[str, Any] = {"limit": 100, "includeHidden": self.requested_model is not None}
                    if cursor is not None:
                        params["cursor"] = cursor
                    result = self._rpc(child, page + 2, "model/list", params)
                    data = result.get("data")
                    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
                        raise CodexBackendError("Codex 模型目录格式异常")
                    catalog.extend(data)
                    cursor = result.get("nextCursor")
                    if cursor is None:
                        break
                else:
                    raise CodexBackendError("Codex 模型目录分页超过限制")
                if self.requested_model is None:
                    candidates = [item for item in catalog if item.get("isDefault") is True]
                    source = "codex app-server model/list: isDefault"
                else:
                    candidates = [item for item in catalog if self.requested_model in (item.get("model"), item.get("id"))]
                    source = "explicit request matched to codex app-server model/list"
                if len(candidates) != 1 or not isinstance(candidates[0].get("model"), str) or not candidates[0]["model"]:
                    raise CodexBackendError("模型目录无法唯一确认所选模型；未执行模型调用")
                self.model = candidates[0]["model"]
                self._model_source = source
            finally:
                child.close()

    def metadata(self) -> dict[str, Any]:
        self._discover()
        return {
            "backend": "codex_cli",
            "model": self.model,
            "requested_model": self.requested_model,
            "model_source": self._model_source,
            "model_catalog_may_be_cached": True,
            "model_availability_verified": self._model_availability_verified,
            "cli_version": self._version,
            "authentication": "existing_codex_login",
            "history_transport": "full_history_json_in_single_prompt",
            "stateless": True,
            "native_tools_allowed": False,
            "disabled_native_features": list(_DISABLED_FEATURES),
            "native_action_events_rejected": True,
            "sandbox": "read-only",
            "seed_supported": False,
            "seed_note": "seed 仅标识评测样本；Codex CLI 未提供受支持的采样 seed 参数，不保证模型输出可重现。",
            "model_identity_note": "模型名来自 CLI 目录并通过 -m 明确请求；不是服务端返回的不可变模型快照标识。",
        }

    @staticmethod
    def _check_event(event: dict[str, Any]) -> None:
        kind = event.get("type")
        if kind in ("thread.started", "turn.started", "turn.completed"):
            return
        if kind in ("item.started", "item.updated", "item.completed"):
            item = event.get("item")
            if not isinstance(item, dict):
                raise CodexBackendError("Codex item 事件格式异常")
            if item.get("type") == "agent_message":
                return
            if item.get("type") == "error" and str(item.get("message", "")).startswith(_INFORMATIONAL_WARNING):
                return
        # 包括所有 native command/tool/search/file-change、未知事件和实际错误，均立即拒绝。
        raise CodexBackendError("Codex 出现原生动作、失败或未允许的事件；本次结果不可用于业务")

    def generate(self, messages: list[dict[str, Any]], schema: dict[str, Any], seed: int) -> dict[str, Any]:
        if type(seed) is not int:
            raise ValueError("seed 必须是整数样本标识")
        if not isinstance(schema, dict) or not isinstance(messages, list) or not messages:
            raise ValueError("schema 必须是对象，messages 必须是非空列表")
        for message in messages:
            if not isinstance(message, dict) or message.get("role") not in ("system", "developer", "user", "assistant", "tool") or not isinstance(message.get("content"), str):
                raise ValueError("每条消息必须包含有效 role 和字符串 content")
        prompt = (
            "你是外部评测控制器调用的 JSON 规划模型。下面是完整消息历史，role 字段表示原会话角色。"
            "请续写下一条 assistant 响应，只输出符合提供的 JSON Schema 的一个 JSON 对象。"
            "如果需要业务工具，应在 JSON 中选择工具及参数，交给外部控制器执行；"
            "不要使用任何 Codex 原生工具，不要自行执行命令、访问文件或网络，也不要虚构工具结果。\n"
            + json.dumps(messages, ensure_ascii=False, allow_nan=False)
        )
        schema_text = json.dumps(schema, ensure_ascii=False, allow_nan=False)
        self._discover()
        directory = self.work_root / ("call_" + uuid.uuid4().hex)
        empty_cwd = directory / "cwd"
        empty_cwd.mkdir(parents=True)
        schema_path = (directory / "schema.json").resolve()
        response_path = (directory / "response.json").resolve()
        schema_path.write_text(schema_text, encoding="utf-8")
        command = [
            self.executable, "exec", "--ignore-user-config", "--ephemeral", "--skip-git-repo-check",
            "--sandbox", "read-only", *_feature_flags(), "-m", str(self.model), "-C", str(empty_cwd),
            "--output-schema", str(schema_path), "--json", "-o", str(response_path), "-",
        ]
        started = time.monotonic()
        child = _JsonProcess(command, empty_cwd, self.timeout)
        final_text: str | None = None
        usage: dict[str, int] = {}
        completed = 0
        try:
            child.send_text(prompt)
            assert child.process.stdin is not None
            child.process.stdin.close()
            while (event := child.receive()) is not None:
                self._check_event(event)
                if event["type"] == "item.completed" and event["item"].get("type") == "agent_message":
                    final_text = event["item"].get("text")
                if event["type"] == "turn.completed":
                    completed += 1
                    observed_usage = event.get("usage", {})
                    if not isinstance(observed_usage, dict) or any(type(value) is not int or value < 0 for value in observed_usage.values()):
                        raise CodexBackendError("Codex token 用量格式异常")
                    usage = observed_usage
            if child.wait() != 0 or completed != 1 or not isinstance(final_text, str):
                raise CodexBackendError("Codex 未成功完成一次模型响应")
            if not response_path.is_file() or response_path.stat().st_size > _MAX_STDOUT_BYTES:
                raise CodexBackendError("Codex 结果文件缺失或超过容量限制")
            content = response_path.read_text(encoding="utf-8").strip()
            if content != final_text.strip():
                raise CodexBackendError("Codex 结果文件与已验证的模型消息不一致")
            try:
                decoded = json.loads(content)
            except ValueError as exc:
                raise CodexBackendError("Codex 模型响应不是有效 JSON") from exc
            if not isinstance(decoded, dict):
                raise CodexBackendError("Codex 模型响应必须是 JSON 对象")
            self._model_availability_verified = True
            return {
                "content": content, "usage": usage, "model": self.model,
                "elapsed_seconds": time.monotonic() - started,
                "model_identity_source": self._model_source,
                "seed_supported": False,
            }
        finally:
            child.close()
