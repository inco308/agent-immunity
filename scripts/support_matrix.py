"""从同一 main 提交的打包、Inspector 和 Codex 验收记录生成 Markdown 矩阵。"""
import argparse
import re
import sys

from .check_x64_install_report import validate as validate_x64_install
from .recovery_matrix import render_recovery
from .support_evidence import (
    NATIVE_TARGETS, PACKAGE_JOB, PLATFORMS, RECOVERY_CHECK_STEP, REPO_URL, by_name, fetch_evidence,
    fetch_recovery_evidence, job_link, package_artifact_name, version,
)


def mac_package_details(report, series, gateway):
    """分别校验两个安装环境，只在实际观测值相同时合并显示。"""
    if (type(report["schema_version"]) is not int or report["schema_version"] != 1
            or report["scope"] != "CORE_PACKAGE_INSTALL" or report["status"] != "passed"
            or not isinstance(report["packages"], list) or len(report["packages"]) != 2):
        raise ValueError("需要两种发行包均通过的独立安装报告")
    filenames = {"wheel": f"agent_immunity-{gateway}-py3-none-any.whl", "sdist": f"agent_immunity-{gateway}.tar.gz"}
    environments, hashes = {}, {}
    for package in report["packages"]:
        kind = package["kind"]
        if (kind not in filenames or kind in environments or package["filename"] != filenames[kind]
                or package["installed_version"] != gateway or not re.fullmatch(r"[a-f0-9]{64}", package["sha256"])
                or package["policy_check"] != "pass" or package["proxy_ping"] is not True):
            raise ValueError("归档名、安装版本、SHA-256 或安装后的检查不符")
        os_version, patch = package["os_version"], package["python"]
        if (package["system"] != "Darwin" or package["machine"] != "arm64"
                or not re.fullmatch(r"15\.[0-9]+(?:\.[0-9]+)?", os_version) or package["implementation"] != "CPython"
                or not re.fullmatch(re.escape(series) + r"\.[0-9]+", patch)):
            raise ValueError(f"{kind} 的系统、架构或解释器与 macOS 打包作业不符")
        environments[kind] = f"macOS {os_version} arm64 · CPython {patch}"
        hashes[kind] = package["sha256"]
    if hashes["wheel"] == hashes["sdist"]:
        raise ValueError("wheel 和源码包指向同一归档摘要")
    return format_package_details(environments, hashes)


def x64_package_details(report, runner, series, gateway):
    """使用生产报告时的校验器，另核对本张矩阵对应的网关版本。"""
    validate_x64_install(report, runner, series)
    environments, hashes = {}, {}
    for package in report["packages"]:
        if package["installed_version"] != gateway:
            raise ValueError("安装报告中的网关版本与支持矩阵不符")
        if runner == "ubuntu-latest":
            os_text = f"Ubuntu {package['distro_version']}（内核 {package['os_version']}）"
        else:
            os_text = f"Windows 内部版本 {package['os_version']}"
        kind = package["kind"]
        environments[kind] = (f"{os_text} · {package['python_platform']}（{package['pointer_bits']} 位）"
                              f" · CPython {package['python']}")
        hashes[kind] = package["sha256"]
    return format_package_details(environments, hashes)


def format_package_details(environments, hashes):
    environment = environments["wheel"]
    if environment != environments["sdist"]:
        environment = f"wheel ({environment}) / sdist ({environments['sdist']})"
    components = f"wheel `{hashes['wheel'][:12]}` / sdist `{hashes['sdist'][:12]}`"
    return environment, components


def package_row(job, run, gateway):
    match = PACKAGE_JOB.fullmatch(job["name"])
    if not match:
        raise ValueError("无法辨认打包作业的运行器和 Python 系列")
    system, series = match.groups()
    evidence = job_link(job, run, system, "测试与模拟规则基准", "检查归档内容、独立安装和 SHA-256")
    if package_artifact_name(job) is not None:
        report = job["package_install_report"]
        if system == "macos-15":
            details, components = mac_package_details(report, series, gateway)
        else:
            details, components = x64_package_details(report, system, series, gateway)
        environment = f"`{system}` · {details}"
    else:
        if "package_install_report" in job:
            raise ValueError("安装报告缺少对应的验收和上传步骤")
        environment, components = f"`{system}` · Python {series}", "wheel 和 sdist"
    return f"| 核心包安装 | {environment} | {components} | 各自在新环境安装，运行策略体检、基准和代理 ping | {evidence} |"


def inspector_row(report, job, run, system):
    evidence = job_link(job, run, system, "真实客户端与 SDK 上游端到端验证")
    if (report["schema_version"] != 1 or report["scope"] != "INSPECTOR_SDK_APPLICATION_E2E"
            or report["status"] != "passed"):
        raise ValueError("Inspector 报告未通过完整互操作验收")
    checks = by_name(report["checks"])
    protocol = checks["official_client_handshake"]["protocol"]
    app = checks["read_generate_write_reread_publish"]
    if (not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", protocol)
            or any(check["status"] != "passed" for check in checks.values())
            or type(app["report_bytes"]) is not int or app["report_bytes"] <= 0
            or type(app["task_count"]) is not int or app["task_count"] <= 0
            or type(app["http_requests"]) is not int or app["http_requests"] != 1):
        raise ValueError("Inspector 握手或文件与回环 HTTP 业务证据不完整")
    versions = report["versions"]
    env = f"`{system}` · Python {version(versions['python'])} · Node {version(versions['node'].removeprefix('v'))}"
    components = f"Inspector {version(versions['inspector'])} · Python SDK {version(versions['mcp_python'])}"
    return f"| Inspector 互操作 | {env} | {components} | MCP {protocol} 握手、文件读写和回环 HTTP 发布 | {evidence} |"


def native_environment(name, host):
    """按作业约定核对宿主与三个独立解释器，从实际观测值生成环境列。"""
    windows = name == "lifecycle-windows-x64"
    system, arch, machine = ("Windows", "x64", "AMD64") if windows else ("Darwin", "arm64", "arm64")
    os_version = host["os_version"]
    os_pattern = r"10\.0\.[0-9]+(?:\.[0-9]+)?" if windows else r"15\.[0-9]+(?:\.[0-9]+)?"
    if host["system"] != system or host["codex_arch"] != arch or not re.fullmatch(os_pattern, os_version):
        raise ValueError("原生 Codex 的系统、版本或可执行文件架构与作业不符")
    patches = []
    for role in ("gateway", "previous", "candidate"):
        python = host["pythons"][role]
        if (python["implementation"] != "CPython" or python["machine"] != machine
                or not re.fullmatch(r"3\.12\.[0-9]+", python["version"])
                or (windows and python["python_platform"] != "win-amd64")):
            raise ValueError(f"原生作业的 {role} 解释器证据不完整或不符")
        patches.append(python["version"])
    python_text = patches[0] if len(set(patches)) == 1 else (
        f"网关 {patches[0]}、初始上游 {patches[1]}、候选上游 {patches[2]}"
    )
    os_name = "Windows 内部版本" if windows else "macOS"
    return f"{os_name} {os_version} {arch} · CPython {python_text}"


def codex_row(report, job, run):
    if (type(report["schema_version"]) is not int or report["schema_version"] != 1
            or report["scope"] != "CODEX_MCP_LIFECYCLE" or report["status"] != "passed"
            or [stage["phase"] for stage in report["stages"]] != ["install", "upgrade", "rollback"]):
        raise ValueError("需要 Codex 宿主完整的初装、升级和回退报告")
    systems = [label for label in job["labels"] if re.fullmatch(r"(?:ubuntu|windows|macos)-[a-z0-9.]+", label)]
    if len(systems) != 1:
        raise ValueError("无法确定 Codex 作业平台")
    system = systems[0]
    environment = f"`{system}`"
    steps = ["Codex 宿主安装、升级和回退"]
    name = job["name"]
    if name == "lifecycle":
        if not system.startswith("ubuntu-") or report.get("host_environment", {}).get("system", "Linux") != "Linux":
            raise ValueError("基础 lifecycle 作业与 Linux 宿主证据不符")
    else:
        if name not in NATIVE_TARGETS or system != NATIVE_TARGETS[name][0]:
            raise ValueError("原生宿主作业名与运行器标签不符")
        arch_steps = {"核对原生宿主的三阶段证据"}
        if name == "lifecycle-macos-arm64":
            arch_steps.add("核对 macOS 15 原生宿主的三阶段证据")
        observed_steps = [s["name"] for s in job["steps"] if s["name"] in arch_steps]
        if not observed_steps:
            raise ValueError("缺少原生宿主架构验收步骤")
        steps.extend(observed_steps)
        environment += " · " + native_environment(name, report["host_environment"])
    evidence = job_link(job, run, system, *steps)
    upstreams = report["upstreams"]
    previous = version(upstreams["previous"]["installed_version"])
    candidate = version(upstreams["candidate"]["installed_version"])
    stages = report["stages"]
    hashes = [stage["config_sha256"] for stage in stages]
    if (previous == candidate or [s["version"] for s in stages] != [previous, candidate, previous]
            or not all(re.fullmatch(r"[a-f0-9]{64}", h) for h in hashes) or hashes[0] != hashes[2] or hashes[0] == hashes[1]):
        raise ValueError("上游安装版本或回退配置证据不符")
    if upstreams["previous"]["policy_check"] != "pass":
        raise ValueError("初始上游目录未通过策略体检")
    combined_workflow = any(step["name"] == RECOVERY_CHECK_STEP for step in job["steps"])
    if "policy_comparison" in report or combined_workflow:
        # 早期候选策略演练只有两份策略的摘要；组合故障演练还逐阶段记录实际策略。
        comparison = report["policy_comparison"]
        baseline, candidate_hash = comparison["baseline_policy_sha256"], comparison["candidate_policy_sha256"]
        if (comparison["status"] != "pass" or comparison["codes"] != []
                or upstreams["candidate"].get("policy_check", "pass") != "pass"
                or not all(re.fullmatch(r"[0-9a-f]{64}", h) for h in (baseline, candidate_hash))
                or report["policy_sha256"] != baseline):
            raise ValueError("宿主三阶段策略与候选检查证据不符")
        if combined_workflow or "candidate_runtime_check" in comparison or any("policy_sha256" in s for s in stages):
            if (comparison["candidate_runtime_check"] != "pass"
                    or [s["policy_sha256"] for s in stages] != [baseline, candidate_hash, baseline]):
                raise ValueError("缺少候选网关自身的体检或逐阶段策略摘要")
    elif upstreams["candidate"]["policy_check"] != "pass":
        raise ValueError("候选上游目录未通过策略体检")
    for s in stages:
        if (s["source"] != "UTC 09:00" or s["target"] != "Asia/Tokyo 18:00" or s["difference"] != "+9.0h"
                or s["visible_tools"] != ["convert_time"] or s["denial"] != "TRANSITION_DENIED"
                or s["weekday_field"] is not (s["phase"] == "upgrade")):
            raise ValueError("缺少分阶段的时区业务或策略拒绝证据")
    codex = report["codex_version"]
    if not codex.startswith("codex-cli "):
        raise ValueError("报告缺少实际 Codex CLI 版本")
    components = f"Codex CLI {version(codex.removeprefix('codex-cli '))} · Python SDK {version(report['mcp_sdk'])}"
    return (f"| 编码宿主试点 | {environment} | {components} | mcp-server-time "
            f"{previous} → {candidate} → {previous}，三阶段时区转换与重复调用拒绝 | {evidence} |")


def render_matrix(commit, verify_run, pilot_run, verify_jobs, interop_reports, pilot_job, pilot_report, native_pilots=()):
    if (not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit)
            or not all(type(run) is int and run > 0 for run in (verify_run, pilot_run))):
        raise ValueError("需指定完整的小写提交 SHA 和两个正整数运行编号")
    try:
        jobs = by_name(verify_jobs)
        gateway = version(pilot_report["gateway_version"])
        rows = []
        # 每个打包作业贡献一行；其他平台的宿主能力不能由打包作业推导。
        axes = []
        for name in jobs:
            match = PACKAGE_JOB.fullmatch(name)
            if match:
                axes.append(match.groups())
        if not axes:
            raise ValueError("缺少发行包验收作业")
        for system, python in sorted(axes, key=lambda pair: (pair[0], tuple(map(int, pair[1].split("."))))):
            rows.append(package_row(jobs[f"test ({system}, {python})"], verify_run, gateway))
        for system in PLATFORMS:
            rows.append(inspector_row(interop_reports[system], jobs[f"interop ({system})"], verify_run, system))
        if pilot_job["name"] != "lifecycle":
            raise ValueError("缺少基础 Linux 宿主作业")
        rows.append(codex_row(pilot_report, pilot_job, pilot_run))
        seen = set()
        for job, report in native_pilots:
            name = job["name"]
            if name not in NATIVE_TARGETS or name in seen or report["gateway_version"] != gateway:
                raise ValueError("原生宿主作业重复、未知或网关版本与矩阵不符")
            seen.add(name)
            rows.append(codex_row(report, job, pilot_run))
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("作业或报告缺少生成矩阵所需的字段") from exc
    return "\n".join([
        f"网关版本 `{gateway}`。验收提交 [`{commit[:7]}`]({REPO_URL}/commit/{commit})。",
        "", "| 使用路径 | CI 环境 | 组件 | 已执行的验收 | 证据 |", "| --- | --- | --- | --- | --- |", *rows, "",
    ])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True, help="两个工作流共同验收的完整 main 提交 SHA")
    parser.add_argument("--verify-run", required=True, type=int, help="verify 工作流的运行编号")
    parser.add_argument("--pilot-run", required=True, type=int, help="codex-time-pilot 工作流的运行编号")
    parser.add_argument("--recovery-run", type=int, help="双预览模式的 codex-time-pilot 手动运行编号")
    parser.add_argument("--recovery-commit", help="运行恢复演练的完整提交 SHA，可与网关构建提交不同")
    args = parser.parse_args(argv)
    if (args.recovery_run is None) != (args.recovery_commit is None):
        parser.error("--recovery-run 和 --recovery-commit 必须一起提供")
    try:
        evidence = fetch_evidence(args.commit, args.verify_run, args.pilot_run)
        matrix = render_matrix(args.commit, args.verify_run, args.pilot_run, *evidence)
        if args.recovery_run is not None:
            recovery = fetch_recovery_evidence(args.recovery_commit, args.recovery_run)
            matrix += "\n" + render_recovery(args.recovery_commit, args.recovery_run, *recovery,
                                            matrix_commit=args.commit, verify_run=args.verify_run,
                                            gateway_version=evidence[3]["gateway_version"])
    except (ValueError, OSError) as exc:
        print(f"无法生成支持矩阵：{exc}", file=sys.stderr)
        return 1
    print(matrix, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
