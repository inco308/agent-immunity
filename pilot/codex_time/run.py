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


def verify_registration(binary, target, project):
    """回读 Codex 本次进程解析出的命令和参数，再启动业务验收。"""
    command = configured_command(binary, project, "mcp", "get", SERVER_NAME, "--json")
    saved = json.loads(run_command(command, project))
    transport = saved.get("transport") or {}
    if (transport.get("command") != target["command"] or transport.get("args") != target["args"]
            or saved.get("enabled") is False):
        raise ValueError("Codex 注册回读与准备的启动参数不一致")


def preflight(environment, slot, root, policy, *, catalog_only=False):
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
    probe = {"installed_version": version, "raw_tools": sorted(raw_names),
             "catalog_sha256": digest(catalog.read_bytes())}
    if catalog_only:
        return probe
    verdict = json.loads(run_command([environment["gateway"], "-I", "-m", "agent_immunity.doctor",
                                      "--policy", str(policy), "--catalog", str(catalog), "--json"], root))
    if verdict["status"] != "pass" or verdict["hidden_tools"] != 1:
        raise ValueError("第三方目录和策略未通过检查")
    return {**probe, "policy_check": verdict["status"]}


def compare_candidate(gateway, baseline, candidate, catalog):
    command = [gateway, "-I", "-m", "agent_immunity.doctor", "--policy", str(candidate),
               "--baseline", str(baseline), "--catalog", str(catalog), "--json"]
    process = subprocess.run(command, cwd=candidate.parent, timeout=90, capture_output=True,
                             encoding="utf-8", check=False)
    verdict = json.loads(process.stdout)
    status = verdict["status"]
    comparison = verdict["comparison"]
    if ({"pass": 0, "error": 1, "review": 2}.get(status) != process.returncode
            or verdict["schema_version"] != 1 or verdict["scope"] != "policy_and_catalog"
            or comparison["scope"] != "added_tools_capabilities_file_roots_and_network_origins"
            or (status != "error" and comparison["status"] != "compared")):
        raise ValueError("已安装检查器的返回值与策略对比报告不一致")
    return {"status": status, "codes": sorted({item["code"] for item in verdict["findings"]})}


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
    template = getattr(args, "candidate_policy_template", None)
    candidate = root / "candidate-policy.json" if template is not None else policy

    def inspect_candidate():
        # 同目录快照使相对 workspace 和部署时一致，注册使用这份已检查的副本。
        with template.open("rb") as stream:
            content = stream.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise ValueError("候选策略超过格式上限")
        atomic_write(candidate, content)
        catalog = root / "candidate-tools.json"
        baseline_hash = report["policy_sha256"]
        catalog_hash = report["upstreams"]["candidate"]["catalog_sha256"]
        candidate_hash = digest(content)
        verdict = compare_candidate(environment["gateway"], policy, candidate, catalog)
        if (digest(policy.read_bytes()) != baseline_hash or digest(candidate.read_bytes()) != candidate_hash
                or digest(catalog.read_bytes()) != catalog_hash):
            raise ValueError("已比较的输入与验收快照不一致")
        report["policy_comparison"] = {**verdict, "baseline_policy_sha256": baseline_hash,
                                       "candidate_policy_sha256": candidate_hash}
        return verdict["status"]

    def finish(status):
        report["status"] = {"pass": "passed", "review": "review", "error": "failed"}[status]
        save()
        print(f"{report['status']}  {report_path}")
        return {"pass": 0, "review": 2, "error": 1}[status]

    try:
        report["upstreams"] = {
            slot: preflight(environment, slot, root, policy, catalog_only=(slot == "candidate" and template is not None))
            for slot in VERSIONS
        }
        if args.preflight_only and template is not None:
            return finish(inspect_candidate())
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
            original = registration(environment["gateway"], policy, environment["previous"])
            upgrade = registration(environment["gateway"], candidate, environment["candidate"])
            if original == upgrade:
                raise ValueError("前后版本必须安装在不同环境")
            for phase, slot, target in (("install", "previous", original), ("upgrade", "candidate", upgrade),
                                        ("rollback", "previous", original)):
                report["attempted_phase"] = phase
                if phase == "upgrade" and template is not None:
                    status = inspect_candidate()
                    if active.read_bytes() != verified:
                        raise RuntimeError("活动注册与已验收安装不一致")
                    if status != "pass":
                        verify_registration(executable, original, project)
                        result = host_stage(executable, project, expect_weekday=False)
                        current = active.read_bytes()
                        if current != verified or digest(policy.read_bytes()) != report["policy_sha256"]:
                            raise RuntimeError("原配置或策略在重新连接时被改变")
                        report["retained"] = {"phase": "retained", "version": VERSIONS["previous"],
                                              "config_sha256": digest(current), **result}
                        return finish(status)
                started = time.monotonic()
                config = config_bytes(target)
                atomic_write(active, config)
                verify_registration(executable, target, project)
                result = host_stage(executable, project, expect_weekday=slot == "candidate")
                stage_policy = candidate if slot == "candidate" else policy
                expected_hash = (report["policy_comparison"]["candidate_policy_sha256"]
                                 if slot == "candidate" and template is not None else report["policy_sha256"])
                if active.read_bytes() != config or digest(stage_policy.read_bytes()) != expected_hash:
                    raise RuntimeError("宿主配置或策略在演练过程中被改变")
                report["stages"].append({"phase": phase, "version": VERSIONS[slot], "config_sha256": digest(config),
                                         "elapsed_seconds": round(time.monotonic() - started, 3), **result})
                try:
                    save()
                except BaseException:
                    report["stages"].pop()
                    raise
                verified = config
        return finish("pass")
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="本次新建的演练目录")
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--preflight-only", action="store_true", help="仅验收第三方目录与安装后的策略检查器")
    parser.add_argument("--candidate-policy-template", type=Path, help="按演练目录解析的候选策略模板；升级前与安装策略和候选目录对比")
    raise SystemExit(run(parser.parse_args()))
