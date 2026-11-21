"""通过原生 dsh 调用受限规划器；业务动作交给上层执行器。

Windows 宿主经 WSL 原生发行版调用，POSIX 宿主直接调用本机安装。
两种传输共用同一套拒绝保护、模型身份校验与超时约束。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid


class DshBackend:
    """保留现有登录机制，每次创建独立、禁止原生工具的模型会话。"""

    def __init__(self, model="deepseek-v4-flash", timeout=120, work_root: Path = None):
        if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", model):
            raise ValueError("模型名称不合法")
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 600:
            raise ValueError("timeout 必须位于 0 到 600 秒之间")
        self.model = model
        self.timeout = float(timeout)
        self.repo_root = Path(__file__).resolve().parents[1]
        artifact_root = (self.repo_root / "artifacts" / "llm-eval").resolve()
        self.work_root = Path(work_root).resolve() if work_root else artifact_root / "dsh"
        if not self.work_root.is_relative_to(artifact_root):
            raise ValueError("dsh 工作目录必须位于本仓库 artifacts/llm-eval 内")
        self.distro = os.environ.get("DSH_WSL_DISTRO", "Ubuntu")
        # 提供方由部署侧配置决定；评测不得假定某个固定标识。
        self.provider = os.environ.get("DSH_EVAL_PROVIDER", "deepseek-official")
        if not isinstance(self.provider, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", self.provider):
            raise ValueError("DSH_EVAL_PROVIDER 必须是非空提供方标识")
        self.wsl = shutil.which("wsl.exe") or shutil.which("wsl")
        if sys.platform == "win32":
            if not self.wsl:
                raise RuntimeError("未发现 WSL，不能调用原生 dsh")
            self.transport = "wsl"
        else:
            # POSIX 宿主上 dsh 就是本机安装；不再经 wsl.exe 转一层。
            self.transport = "native"
        self._discover()

    def _base_command(self):
        """wsl.exe 前缀；原生传输没有前缀。"""
        return [self.wsl, "--distribution", self.distro] if self.transport == "wsl" else []

    @staticmethod
    def _decode(value: bytes) -> str:
        return value.decode("utf-8", errors="replace")

    def _run(self, args, timeout=30, cwd=None):
        try:
            return subprocess.run(
                args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, check=False,
                cwd=cwd, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("dsh 子进程启动失败或超过时限") from exc

    def _discover(self):
        if self.transport == "native":
            self._discover_native()
            return
        # 这是固定脚本，不插入模型、提示词、工作路径等动态内容。
        discovery = self._run(self._base_command() + [
            "--exec", "bash", "-ic",
            'command -v node\nreadlink -f "$(command -v dsh)"\ncommand -v timeout',
        ])
        paths = [line.strip() for line in self._decode(discovery.stdout).splitlines()
                 if line.strip().startswith("/")]
        if discovery.returncode or len(paths) != 3:
            raise RuntimeError("无法发现 WSL 原生 node、dsh 与 timeout")
        self.node_path, self.dsh_path, self.timeout_path = paths
        if any(path.startswith("/mnt/") for path in (self.node_path, self.dsh_path)):
            raise RuntimeError("命令落到了 Windows shim，拒绝冒充 WSL 原生 dsh")
        version = self._run(self._base_command() + [
            "--exec", self.node_path, self.dsh_path, "--version",
        ])
        self.version = self._decode(version.stdout).strip()
        if version.returncode or not re.fullmatch(r"[0-9][A-Za-z0-9.+-]*", self.version):
            raise RuntimeError("dsh 版本检查失败")
        node_version = self._run(self._base_command() + ["--exec", self.node_path, "--version"])
        self.node_version = self._decode(node_version.stdout).strip()
        if node_version.returncode or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", self.node_version):
            raise RuntimeError("WSL Node 版本检查失败")

    def _discover_native(self):
        """在 POSIX 宿主按绝对真实路径解析可执行文件，不回退到 Windows 挂载的替身。"""
        found = {}
        for name in ("node", "dsh", "timeout"):
            located = shutil.which(name)
            if not located:
                raise RuntimeError(f"无法发现本机 {name}，不能调用原生 dsh")
            found[name] = str(Path(located).resolve(strict=True))
        self.node_path, self.dsh_path, self.timeout_path = (
            found["node"], found["dsh"], found["timeout"])
        if any(path.startswith("/mnt/") for path in (self.node_path, self.dsh_path)):
            raise RuntimeError("命令落到了 Windows 挂载路径，拒绝冒充本机原生 dsh")
        version = self._run([self.node_path, self.dsh_path, "--version"])
        self.version = self._decode(version.stdout).strip()
        if version.returncode or not re.fullmatch(r"[0-9][A-Za-z0-9.+-]*", self.version):
            raise RuntimeError("dsh 版本检查失败")
        node_version = self._run([self.node_path, "--version"])
        self.node_version = self._decode(node_version.stdout).strip()
        if node_version.returncode or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", self.node_version):
            raise RuntimeError("本机 Node 版本检查失败")

    def _visible_path(self, path: Path) -> str:
        """把宿主路径转换成上游进程可见的路径；原生传输保持不变。"""
        resolved = path.resolve(strict=True)
        if self.transport == "native":
            return str(resolved)
        result = self._run(self._base_command() + [
            "--exec", "wslpath", "-a", "-u", str(resolved),
        ])
        translated = self._decode(result.stdout).strip()
        if result.returncode or not translated.startswith("/") or "\n" in translated:
            raise RuntimeError("无法安全转换 WSL 路径")
        return translated

    def metadata(self) -> dict:
        data = {
            "backend": "dsh", "version": self.version,
            "model": self.model, "provider": self.provider,
            "transport": self.transport,
            "resolved_node": self.node_path,
            "resolved_command": self.dsh_path,
            "node_version": self.node_version,
            "native_tools": "全局单调拒绝保护；模型工具 schema 置空",
            "guard_self_test_required": True, "seed_supported": False,
            "schema_enforcement": "提示词约束；上层执行器必须校验 JSON schema",
            "timeout_seconds": self.timeout,
        }
        if self.transport == "wsl":
            data["wsl_distro"] = self.distro
        return data

    @staticmethod
    def _diagnostic(stdout: bytes, stderr: bytes, code: int) -> str:
        # 不将第三方诊断原文、认证信息或配置内容写入审计记录。
        diagnostic = (stdout + stderr).decode("utf-8", errors="replace").lower()
        if code in (124, 137):
            return "timeout"
        if "model_mismatch" in diagnostic:
            return "model_mismatch"
        if "guard_failed" in diagnostic:
            return "guard_failed"
        if "plugin tree failed" in diagnostic or "entry did not activate" in diagnostic:
            return "plugin_activation_error"
        if any(word in diagnostic for word in ("unauthorized", "authentication", "api key", "credential")):
            return "authentication_error"
        if any(word in diagnostic for word in ("capacity", "unavailable", "429", "503")):
            return "provider_unavailable"
        return "process_error"

    def generate(self, messages: list, schema: dict, seed: int) -> dict:
        if not isinstance(messages, list) or not isinstance(schema, dict):
            raise ValueError("messages 必须是列表，schema 必须是对象")
        if not isinstance(seed, int):
            raise ValueError("seed 必须是整数；dsh 不提供确定性 seed 控制")
        for message in messages:
            if not isinstance(message, dict) or message.get("role") not in {"system", "user", "assistant", "tool"}:
                raise ValueError("messages 包含不支持的角色")
            if "content" not in message:
                raise ValueError("messages 缺少 content")
        run_dir = self.work_root / (time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:12])
        empty_dir = run_dir / "empty"
        empty_dir.mkdir(parents=True)
        plugin_path = run_dir / "dsh_plugin.mjs"
        shutil.copyfile(Path(__file__).with_name("dsh_plugin.mjs"), plugin_path)
        # 文件只包含本轮输入与输出规范；不读取或复制认证文件。
        input_data = {"messages": messages, "schema": schema, "expected_model": self.model,
                      "expected_provider": self.provider, "requested_seed": seed}
        (run_dir / "input.json").write_text(json.dumps(input_data, ensure_ascii=False), encoding="utf-8")
        plugin_visible = self._visible_path(plugin_path)
        empty_visible = self._visible_path(empty_dir)
        disabled = ["session-title-llm", "session-telemetry-otel", "session-persistence-jsonl",
                    "session-checkpoint-policy", "agent-instructions", "skill-filesystem", "code-runtime"]
        overlay = [{"id": row, "disabled": True} for row in disabled]
        overlay += [
            {"id": "tools", "config": {"mode": "native"}},
            {"id": "system-prompt", "config": {"includeRuntimeContext": False,
                "persona": "你是受限动作规划器。只输出动作 JSON，不调用任何原生工具。"}},
            {"id": "agent-default-model", "config": {"provider": self.provider, "model": self.model}},
            {"insert": [{"id": "planner-deny-all", "name": plugin_visible}]},
            {"id": "headless-runner", "inject": ["headlessStartup", "plannerNoTools"]},
        ]
        # JSON 是 YAML 子集；最后一项用官方动态配置语法读取保护层提供的任务。
        patch_text = "\n".join("- " + json.dumps(row, ensure_ascii=False) for row in overlay[:-1])
        patch_text += "\n- id: headless-runner\n  inject: [headlessStartup, plannerNoTools]\n  config:\n    task: !!js ctx.plannerNoTools.task\n"
        patch_path = run_dir / "planner.patch.yml"
        patch_path.write_text(patch_text, encoding="utf-8")
        sandboxed = [
            self.timeout_path,
            "--signal=TERM", "--kill-after=5s", f"{self.timeout:g}s",
            self.node_path, self.dsh_path, "--profile", "headless",
            "--patch", self._visible_path(patch_path), "执行本次受限 JSON 规划任务。",
        ]
        if self.transport == "wsl":
            # wsl.exe 用 --cd/--exec 指定上游工作目录与命令。
            command = self._base_command() + ["--cd", empty_visible, "--exec"] + sandboxed
            cwd = None
        else:
            # 原生传输复用本进程的 cwd 隔离与绝对可执行文件。
            command = sandboxed
            cwd = empty_visible
        started = time.perf_counter()
        process = self._run(command, timeout=self.timeout + 15, cwd=cwd)
        elapsed = time.perf_counter() - started
        audit_path = run_dir / "planner-result.json"
        if not audit_path.is_file():
            diagnostic = self._diagnostic(process.stdout, process.stderr, process.returncode)
            (run_dir / "failure.json").write_text(json.dumps({
                "exit_code": process.returncode, "diagnostic": diagnostic,
                "elapsed_seconds": elapsed,
            }), encoding="utf-8")
            raise RuntimeError(f"dsh 调用失败：{diagnostic}（退出码 {process.returncode}）")
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        if process.returncode or audit.get("status") != "completed":
            diagnostic = self._diagnostic(process.stdout, process.stderr, process.returncode)
            (run_dir / "failure.json").write_text(json.dumps({
                "exit_code": process.returncode, "diagnostic": diagnostic,
                "status": audit.get("status", "unknown"), "elapsed_seconds": elapsed,
            }), encoding="utf-8")
            raise RuntimeError(f"dsh 未正常完成：{audit.get('status', 'unknown')}，{diagnostic}（退出码 {process.returncode}）")
        if audit.get("model") != self.model or audit.get("provider") != self.provider:
            raise RuntimeError("dsh 实际模型或提供方与请求不一致")
        if (not audit.get("guard_self_test_denied") or audit.get("tool_attempts", -1) != 0
                or audit.get("model_tool_calls", -1) != 0):
            raise RuntimeError("dsh 工具保护验证失败或模型尝试调用了原生工具")
        content = audit.get("content")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("dsh 没有返回规划器正文")
        return {"content": content, "usage": audit.get("usage", {}),
                "model": audit["model"], "elapsed_seconds": elapsed}
