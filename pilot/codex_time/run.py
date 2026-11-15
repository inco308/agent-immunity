"""在独立试点项目验证 Codex 注册的时区服务，记录旧版、新版和回退证据。"""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

from .host import HOST_VERSION, SERVER_NAME, configured_command, host_stage

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
VERSIONS = {"previous": "2025.8.4", "candidate": "2025.9.25"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic_write(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as out:
        temporary = Path(out.name)
        try:
            out.write(data)
        except BaseException:
            out.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def registration(gateway, policy, upstream):
    args = ["-I", "-m", "agent_immunity.mcp_stdio", "--policy", str(policy), "--timeout", "15",
            "--", upstream, "-I", "-m", "mcp_server_time", "--local-timezone", "UTC"]
    return {"command": gateway, "args": args}


def config_bytes(target):
    command = json.dumps(target["command"], ensure_ascii=False)
    args = json.dumps(target["args"], ensure_ascii=False)
    return f"mcp_servers.{SERVER_NAME} = {{ command = {command}, args = {args} }}\n".encode("utf-8")


def run_command(args, cwd):
    return subprocess.run(args, cwd=cwd, timeout=90, check=True, text=True, encoding="utf-8",
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def native_pythons(environment, root, machine, python_platform=None):
    """从网关和两个上游各自使用的解释器取证。Windows 还需核对解释器的构建平台。"""
    probe = ("import json, platform, sysconfig; print(json.dumps(dict(implementation=platform.python_implementation(), "
             "version=platform.python_version(), machine=platform.machine(), python_platform=sysconfig.get_platform())))")
    pythons = {}
    for role in ("gateway", "previous", "candidate"):
        observed = json.loads(run_command([environment[role], "-I", "-c", probe], root))
        if (not isinstance(observed, dict) or observed.get("implementation") != "CPython"
                or observed.get("machine") != machine or not isinstance(observed.get("version"), str)
                or (python_platform is not None and observed.get("python_platform") != python_platform)
                or not re.fullmatch(r"3\.12\.[0-9]+", observed["version"])):
            raise ValueError(f"{role} 环境需要原生 {machine} CPython 3.12")
        pythons[role] = {key: observed[key] for key in ("implementation", "version", "machine")}
        if python_platform is not None:
            pythons[role]["python_platform"] = observed["python_platform"]
    return pythons


def macos_host_environment(executable, environment, root):
    if platform.system() != "Darwin":
        raise ValueError("Apple Silicon 宿主演练需要在 macOS 运行")
    os_version = platform.mac_ver()[0]
    arch = run_command(["/usr/bin/lipo", "-archs", executable], root).strip()
    if not os_version or arch != "arm64":
        raise ValueError("需要选择锁定 npm 包中仅含 arm64 的 Codex 原生程序")
    return {"system": "Darwin", "os_version": os_version, "codex_arch": arch,
            "pythons": native_pythons(environment, root, "arm64")}


def windows_host_environment(executable, environment, root):
    if platform.system() != "Windows" or not (os_version := platform.win32_ver()[1]):
        raise ValueError("Windows x64 宿主演练需要实际的 Windows 系统版本")
    from .windows_arch import require_windows_x64_executable

    require_windows_x64_executable(executable)
    return {"system": "Windows", "os_version": os_version, "codex_arch": "x64",
            "pythons": native_pythons(environment, root, "AMD64", "win-amd64")}


def verify_registration(binary, target, project):
    """回读 Codex 本次进程解析出的命令和参数，再启动业务验收。"""
    command = configured_command(binary, project, "mcp", "get", SERVER_NAME, "--json")
    saved = json.loads(run_command(command, project))
    transport = saved.get("transport") or {}
    if (transport.get("command") != target["command"] or transport.get("args") != target["args"]
            or saved.get("enabled") is False):
        raise ValueError("Codex 注册回读与准备的启动参数不一致")


def preflight(environment, slot, root, policy):
    upstream = environment[slot]
    version = run_command([upstream, "-I", "-c",
                           "from importlib.metadata import version; print(version('mcp-server-time'))"], root).strip()
    if version != VERSIONS[slot]:
        raise ValueError(f"{slot} 的已安装上游版本不正确")
    catalog = root / f"{slot}-tools.json"
    run_command([upstream, "-X", "utf8", "-m", "interop.capture_catalog", "--output", str(catalog),
                 "--cwd", str(policy.parent / "workspace"), "--", upstream, "-I", "-m", "mcp_server_time",
                 "--local-timezone", "UTC"], REPO)
    raw_names = {tool["name"] for tool in json.loads(catalog.read_bytes())["tools"]}
    if raw_names != {"get_current_time", "convert_time"}:
        raise ValueError("第三方服务接口发生了预期外的变化")
    verdict = json.loads(run_command([environment["gateway"], "-I", "-m", "agent_immunity.doctor",
                                      "--policy", str(policy), "--catalog", str(catalog), "--json"], root))
    if verdict["status"] != "pass" or verdict["hidden_tools"] != 1:
        raise ValueError("第三方目录和策略未通过检查")
    return {"installed_version": version, "raw_tools": sorted(raw_names), "policy_check": verdict["status"],
            "catalog_sha256": digest(catalog.read_bytes())}


def validate_clean_account():
    # 演练会启动宿主。在个人账号里可使用文档中的正常接入方法。
    config_root = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    if (config_root / "config.toml").exists() or (config_root / "auth.json").exists():
        raise ValueError("自动宿主演练需要单独的测试账号或干净的 CI runner；当前账号已配置 Codex")


def run(args):
    require_macos = getattr(args, "require_macos_arm64", False)
    require_windows = getattr(args, "require_windows_x64", False)
    if (require_macos or require_windows) and args.preflight_only:
        print("原生宿主验收必须执行完整三阶段，请移除 --preflight-only", file=sys.stderr)
        return 1
    environment = json.loads(args.environment.resolve(strict=True).read_bytes())
    root = args.output_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    (root / "workspace").mkdir()
    policy = root / "policy.json"
    shutil.copyfile(HERE / "policy.json", policy)
    project = root / "host-project"
    (project / ".codex").mkdir(parents=True)
    active = project / ".codex/config.toml"
    report = {"schema_version": 1, "scope": "preflight" if args.preflight_only else "CODEX_MCP_LIFECYCLE",
              "status": "running", "policy_sha256": digest(policy.read_bytes()),
              "gateway_version": environment["versions"]["gateway"], "mcp_sdk": environment["versions"]["mcp"],
              "gateway_wheel_sha256": environment["gateway_wheel_sha256"], "stages": []}
    report_path = root / "report.json"

    def save():
        atomic_write(report_path, (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode())

    save()
    verified = None
    try:
        probes = {slot: preflight(environment, slot, root, policy) for slot in VERSIONS}
        report["upstreams"] = probes
        if not args.preflight_only:
            validate_clean_account()
            executable = shutil.which(args.codex)
            if not executable:
                raise ValueError("找不到指定的 Codex CLI")
            executable = Path(executable).absolute()
            if require_macos:
                report["attempted_phase"] = "macos_host_check"
                report["host_environment"] = macos_host_environment(executable, environment, root)
            elif require_windows:
                report["attempted_phase"] = "windows_host_check"
                report["host_environment"] = windows_host_environment(executable, environment, root)
            host_version = run_command([executable, "--version"], root).strip()
            if host_version != f"codex-cli {HOST_VERSION}":
                raise ValueError("Codex 版本与该试点的固定版本不符")
            report["codex_version"] = host_version
            run_command(["git", "init", "--quiet"], project)
            existing = json.loads(run_command([executable, "mcp", "list", "--json"], root))
            if not isinstance(existing, list) or existing:
                raise ValueError("一次性宿主演练需要空的 MCP 注册表")
            original = registration(environment["gateway"], policy, environment["previous"])
            upgrade = registration(environment["gateway"], policy, environment["candidate"])
            if original == upgrade:
                raise ValueError("前后版本必须安装在不同环境")
            for phase, slot, target in (("install", "previous", original), ("upgrade", "candidate", upgrade),
                                        ("rollback", "previous", original)):
                report["attempted_phase"] = phase
                started = time.monotonic()
                config = config_bytes(target)
                atomic_write(active, config)
                verify_registration(executable, target, project)
                result = host_stage(executable, project, expect_weekday=slot == "candidate")
                if active.read_bytes() != config:
                    raise RuntimeError("宿主配置在演练过程中被改变")
                report["stages"].append({"phase": phase, "version": VERSIONS[slot], "config_sha256": digest(config),
                                         "elapsed_seconds": round(time.monotonic() - started, 3), **result})
                try:
                    save()
                except BaseException:
                    report["stages"].pop()
                    raise
                verified = config
        report["status"] = "passed"
        save()
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        report["status"] = "failed"
        report["failure_type"] = type(exc).__name__
        try:
            if verified is None:
                active.unlink(missing_ok=True)
            else:
                atomic_write(active, verified)
                report["restored_verified_config_sha256"] = digest(verified)
        except Exception as rollback_error:
            report["rollback_error_type"] = type(rollback_error).__name__
        try:
            save()
        except Exception as save_error:
            print(f"无法保存失败报告（{type(save_error).__name__}）", file=sys.stderr)
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        print(f"演练失败（{report['failure_type']}）  {report_path}", file=sys.stderr)
        return 1
    print(f"{report['status']}  {report_path}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    native = parser.add_mutually_exclusive_group()
    native.add_argument("--require-macos-arm64", action="store_true", help="核验原生 Apple Silicon 宿主和 Python 环境并运行完整三阶段")
    native.add_argument("--require-windows-x64", action="store_true", help="核验原生 Windows x64 宿主和 Python 环境并运行完整三阶段")
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="本次新建的演练目录")
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--preflight-only", action="store_true", help="仅验收第三方目录与安装后的策略检查器")
    raise SystemExit(run(parser.parse_args()))
