"""在独立试点项目验证 Codex 注册的时区服务，记录旧版、新版和回退证据。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

from .host import GatewayStartupError, HOST_VERSION, SERVER_NAME, configured_command, host_stage

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


def registration(gateway, policy, upstream, *, exit_marker=None):
    entry = ["-m", "agent_immunity.mcp_stdio"] if exit_marker is None else [str(HERE / "startup_probe.py"), str(exit_marker)]
    args = ["-I", *entry, "--policy", str(policy), "--timeout", "15",
            "--", upstream, "-I", "-m", "mcp_server_time", "--local-timezone", "UTC"]
    return {"command": gateway, "args": args}


def startup_fault_registration(gateway, root, upstream, *, candidate_policy=None):
    if candidate_policy is not None:
        return registration(gateway, candidate_policy, str(root / "absent-candidate-upstream"),
                            exit_marker=root / "candidate-exit.txt")
    return registration(gateway, root / "absent-candidate-policy.json", upstream, exit_marker=root / "candidate-exit.txt")


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


def verified_slots(environment, required):
    """旧描述文件沿用本地构建模式，双收据模式需要两套相互独立的来源。"""
    schema = environment.get("schema_version")
    if type(schema) is not int:
        raise ValueError("环境描述版本无效")
    if schema == 1 and "gateway_slots" not in environment and not required:
        return None
    slots = environment.get("gateway_slots")
    if (schema != 2 or environment.get("scope") != "CODEX_TIME_PILOT_ENVIRONMENT"
            or not isinstance(slots, dict) or set(slots) != set(VERSIONS)):
        raise ValueError("需要经过双预览包准备流程生成的环境描述")
    for entry in slots.values():
        if (not isinstance(entry, dict) or not isinstance(entry.get("version"), str) or not entry["version"]
                or not all(isinstance(entry.get(key), str) and Path(entry[key]).is_absolute()
                           for key in ("python", "wheel"))
                or not all(type(entry.get(key)) is int and entry[key] > 0 for key in ("run_id", "artifact_id"))
                or not isinstance(entry.get("commit"), str) or not re.fullmatch(r"[0-9a-f]{40}", entry["commit"])
                or not isinstance(entry.get("wheel_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["wheel_sha256"])):
            raise ValueError("环境描述缺少网关来源或绝对安装路径")
    for field in ("python", "wheel_sha256", "commit", "run_id", "artifact_id"):
        if slots["previous"][field] == slots["candidate"][field]:
            raise ValueError("必须使用两个独立构建的网关")
    return slots


def gateway_identity(entry, root):
    """用即将注册给宿主的解释器，对照核验时保存的 wheel 检查已安装内容。"""
    wheel = Path(entry["wheel"])
    receipt = json.loads(wheel.with_name("receipt.json").read_bytes())
    fields = ("version", "commit", "run_id", "artifact_id")
    if (not isinstance(receipt, dict)
            or not all(type(receipt.get(k)) is type(entry[k]) and receipt[k] == entry[k] for k in fields)
            or not isinstance(receipt.get("files"), dict) or receipt["files"].get(wheel.name) != entry["wheel_sha256"]):
        raise ValueError("下载时保存的查验收据与本阶段选择的构建不一致")
    output = run_command([entry["python"], "-I", "-X", "utf8", str(HERE / "wheel_identity.py"),
                          "--wheel", entry["wheel"], "--version", entry["version"],
                          "--sha256", entry["wheel_sha256"]], root)
    observed = json.loads(output)
    if (not isinstance(observed, dict) or observed.get("wheel_sha256") != entry["wheel_sha256"]
            or observed.get("version") != entry["version"] or type(observed.get("runtime_files")) is not int
            or observed["runtime_files"] < 1 or not isinstance(observed.get("metadata_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", observed["metadata_sha256"])):
        raise ValueError("安装树核验结果与选定的网关收据不一致")
    return {**{key: entry[key] for key in ("commit", "run_id", "artifact_id")},
            **{key: observed[key] for key in ("version", "wheel_sha256", "metadata_sha256", "runtime_files")}}


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
              "status": "running", "policy_sha256": digest(policy.read_bytes()), "stages": []}
    report_path = root / "report.json"

    def save():
        atomic_write(report_path, (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode())

    def save_failure():
        try:
            save()
        except Exception as save_error:
            print(f"无法保存失败报告（{type(save_error).__name__}）", file=sys.stderr)

    def exercise(phase, slot, target, config, *, restoring=False):
        """用活动配置启动新宿主，并在调用前后核对策略和安装。"""
        started = time.monotonic()
        identity = gateway_identity(slots[slot], root) if slots else None
        if restoring and identity != report["stages"][-1].get("gateway"):
            raise ValueError("恢复的安装与先前通过宿主验收的构建不同")
        stage_policy = candidate if slot == "candidate" else policy
        expected_policy = (report["policy_comparison"]["candidate_policy_sha256"]
                           if slot == "candidate" and template is not None else report["policy_sha256"])
        if digest(stage_policy.read_bytes()) != expected_policy:
            raise ValueError("宿主调用前的策略与已核对的策略不同")
        if not restoring:
            atomic_write(active, config)
        if active.read_bytes() != config:
            raise ValueError("活动配置与本次准备核验的配置不同")
        verify_registration(executable, target, project)
        result = host_stage(executable, project, expect_weekday=slot == "candidate")
        if active.read_bytes() != config or digest(stage_policy.read_bytes()) != expected_policy:
            raise RuntimeError("宿主配置或策略在演练过程中被改变")
        if slots:
            if gateway_identity(slots[slot], root) != identity:
                raise ValueError("宿主调用前后的网关安装证据不一致")
            result = {**result, "gateway": identity}
        return {"phase": phase, "version": VERSIONS[slot], "config_sha256": digest(config),
                "policy_sha256": expected_policy, "elapsed_seconds": round(time.monotonic() - started, 3), **result}

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
        gateway = targets["candidate"]["command"]
        checker = getattr(args, "policy_check_python", None)
        # 保留 venv/bin/python 入口；解引用可能会变为不含检查器的系统解释器。
        checker = str(Path(checker).absolute()) if checker is not None else gateway
        verdict = compare_candidate(checker, policy, candidate, catalog)
        if checker == gateway and verdict["status"] == "pass":
            verdict["candidate_runtime_check"] = "pass"
        if verdict["status"] == "pass" and checker != gateway:
            # 冻结的候选网关也必须接受这份策略以及真实的候选目录。
            try:
                runtime = json.loads(run_command([gateway, "-I", "-m", "agent_immunity.doctor", "--policy", str(candidate),
                                                  "--catalog", str(catalog), "--json"], root))
            except (subprocess.CalledProcessError, ValueError):
                runtime = None
            compatible = (isinstance(runtime, dict) and runtime.get("status") == "pass"
                          and runtime.get("scope") == "policy_and_catalog")
            verdict["candidate_runtime_check"] = "pass" if compatible else "error"
        if (digest(policy.read_bytes()) != baseline_hash or digest(candidate.read_bytes()) != candidate_hash
                or digest(catalog.read_bytes()) != catalog_hash):
            raise ValueError("已比较的输入与验收快照不一致")
        report["policy_comparison"] = {**verdict, "baseline_policy_sha256": baseline_hash,
                                       "candidate_policy_sha256": candidate_hash}
        return "error" if verdict.get("candidate_runtime_check") == "error" else verdict["status"]

    def finish(status):
        report["status"] = {"pass": "passed", "review": "review", "error": "failed"}[status]
        save()
        print(f"{report['status']}  {report_path}")
        return {"pass": 0, "review": 2, "error": 1}[status]

    simulate = getattr(args, "simulate_candidate_startup_failure", False)
    marker = root / "candidate-exit.txt"
    absent_policy = root / "absent-candidate-policy.json"
    try:
        if simulate and args.preflight_only:
            raise ValueError("候选启动故障演练需要运行宿主")
        slots = verified_slots(environment, getattr(args, "require_verified_gateways", False))
        report["mcp_sdk"] = environment["versions"]["mcp"]
        if slots:
            report.update(schema_version=2, gateway_mode="verified_previews")
        else:
            report.update(gateway_version=environment["versions"]["gateway"],
                          gateway_wheel_sha256=environment["gateway_wheel_sha256"])
        report["upstreams"] = {}
        targets = {}
        for slot in VERSIONS:
            gateway = slots[slot]["python"] if slots else environment["gateway"]
            identity = gateway_identity(slots[slot], root) if slots else None
            probe = preflight({**environment, "gateway": gateway}, slot, root, policy,
                              catalog_only=(slot == "candidate" and template is not None))
            if identity:
                probe["gateway"] = identity
            report["upstreams"][slot] = probe
            targets[slot] = registration(gateway, candidate if slot == "candidate" else policy, environment[slot])
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
            if targets["previous"] == targets["candidate"]:
                raise ValueError("前后版本必须安装在不同环境")
            for phase, slot in (("install", "previous"), ("upgrade", "candidate"), ("rollback", "previous")):
                report["attempted_phase"] = phase
                if phase == "upgrade" and template is not None:
                    status = inspect_candidate()
                    if active.read_bytes() != verified:
                        raise RuntimeError("活动注册与已验收安装不一致")
                    if status != "pass":
                        report["attempted_phase"] = "retained"
                        report["retained"] = exercise("retained", "previous", targets["previous"], verified, restoring=True)
                        return finish(status)
                target = targets[slot]
                if simulate and phase == "upgrade":
                    target = startup_fault_registration(target["command"], root, environment[slot],
                                                        candidate_policy=candidate if template is not None else None)
                config = config_bytes(target)
                stage = exercise(phase, slot, target, config)
                if simulate and phase == "upgrade":
                    raise RuntimeError("演练中的候选网关意外通过了宿主验收")
                report["stages"].append(stage)
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
        reconnect = (isinstance(exc, GatewayStartupError) and report.get("attempted_phase") == "upgrade"
                     and verified is not None and report["stages"][-1]["phase"] == "install")
        if reconnect:
            report["host_startup_state"] = exc.state
            if simulate:
                try:
                    missing = absent_policy if template is None else root / "absent-candidate-upstream"
                    exit_code = 2 if template is None else 1
                    if (not missing.exists() and marker.read_bytes().splitlines() == [str(exit_code).encode("ascii")]
                            and active.read_bytes() == config):
                        fault = {"kind": "missing_candidate_policy" if template is None else "missing_candidate_upstream",
                                 "exit_code": exit_code, "config_sha256": digest(config)}
                        if template is not None:
                            fault["policy_sha256"] = digest(candidate.read_bytes())
                            if slots:
                                fault["gateway"] = report["upstreams"]["candidate"]["gateway"]
                        report["fault"] = fault
                except OSError:
                    pass  # 缺少故障证据时仍尝试恢复；独立演练验收要求该证据存在。
        try:
            if verified is None:
                active.unlink(missing_ok=True)
            else:
                atomic_write(active, verified)
                if active.read_bytes() != verified:
                    raise ValueError("写回的配置与最近通过验收的配置不同")
                report["restored_verified_config_sha256"] = digest(verified)
        except Exception as rollback_error:
            report["rollback_error_type"] = type(rollback_error).__name__
        else:
            if reconnect:
                report["recovery"] = {"status": "running"}
                save_failure()
                try:
                    result = exercise("recovery", "previous", targets["previous"], verified, restoring=True)
                    report["recovery"] = {**result, "status": "passed"}
                except (Exception, KeyboardInterrupt, SystemExit) as recovery_error:
                    report["recovery"] = {"status": "failed", "error_type": type(recovery_error).__name__}
                    if isinstance(recovery_error, (KeyboardInterrupt, SystemExit)):
                        save_failure()
                        raise
        save_failure()
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
    parser.add_argument("--policy-check-python", type=Path,
                        help="执行候选策略差异检查的已安装解释器；默认使用候选网关解释器")
    parser.add_argument("--require-verified-gateways", action="store_true", help="只接受两个已核验预览构建的环境描述")
    parser.add_argument("--simulate-candidate-startup-failure", action="store_true",
                        help="模拟候选启动故障并复验原构建；提供候选模板时模拟上游不可启动，否则模拟策略缺失")
    raise SystemExit(run(parser.parse_args()))
