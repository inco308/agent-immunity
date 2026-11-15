"""在独立试点项目验证 Codex 注册的时区服务，记录旧版、新版和回退证据。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from .host import HOST_VERSION, SERVER_NAME, host_stage

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
    return (f"[mcp_servers.{SERVER_NAME}]\ncommand = {json.dumps(target['command'], ensure_ascii=False)}\n"
            f"args = {json.dumps(target['args'], ensure_ascii=False)}\n").encode("utf-8")


def run_command(args, cwd):
    return subprocess.run(args, cwd=cwd, timeout=90, check=True, text=True, encoding="utf-8",
                          stdout=subprocess.PIPE).stdout


def register(binary, target, cwd):
    """通过 Codex 自身的 CLI 激活所选版本，并回读宿主保存的配置。"""
    run_command([binary, "mcp", "add", SERVER_NAME, "--", target["command"], *target["args"]], cwd)
    saved = json.loads(run_command([binary, "mcp", "get", SERVER_NAME, "--json"], cwd))
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
    temporary_registration = False
    success = False
    try:
        probes = {slot: preflight(environment, slot, root, policy) for slot in VERSIONS}
        report["upstreams"] = probes
        if not args.preflight_only:
            validate_clean_account()
            executable = shutil.which(args.codex)
            if not executable:
                raise ValueError("找不到指定的 Codex CLI")
            executable = Path(executable).absolute()
            host_version = run_command([executable, "--version"], root).strip()
            if host_version != f"codex-cli {HOST_VERSION}":
                raise ValueError("Codex 版本与该试点的固定版本不符")
            report["codex_version"] = host_version
            run_command(["git", "init", "--quiet"], project)
            existing = json.loads(run_command([executable, "mcp", "list", "--json"], root))
            if not isinstance(existing, list) or existing:
                raise ValueError("一次性宿主演练需要空的 MCP 注册表")
            temporary_registration = True
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
                register(executable, target, root)
                result = host_stage(executable, project, expect_weekday=slot == "candidate")
                if active.read_bytes() != config:
                    raise RuntimeError("宿主配置在演练过程中被改变")
                verified = config
                report["stages"].append({"phase": phase, "version": VERSIONS[slot], "config_sha256": digest(config),
                                         "elapsed_seconds": round(time.monotonic() - started, 3), **result})
                save()
        report["status"] = "passed"
        success = True
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        report["status"] = "failed"
        # 失败时只恢复本次新建项目内已验收的配置。既有部署不受试点脚本影响。
        if verified is not None:
            atomic_write(active, verified)
            report["restored_verified_config_sha256"] = digest(verified)
        elif active.exists():
            active.unlink()
        report["failure_type"] = type(exc).__name__
        print(str(exc) if isinstance(exc, (ValueError, RuntimeError)) else type(exc).__name__, file=sys.stderr)
    finally:
        if temporary_registration:
            try:
                run_command([executable, "mcp", "remove", SERVER_NAME], root)
            except (OSError, RuntimeError, subprocess.SubprocessError):
                success = False
                report["status"] = "failed"
                report["cleanup_error"] = "临时 MCP 注册清理失败"
        save()
        print(f"{report['status']}  {report_path}")
    return 0 if success else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="本次新建的演练目录")
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--preflight-only", action="store_true", help="仅验收第三方目录与安装后的策略检查器")
    raise SystemExit(run(parser.parse_args()))
