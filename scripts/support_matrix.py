"""从同一 main 提交的打包、Inspector 和 Codex 验收记录生成 Markdown 矩阵。"""
import argparse
import re
import sys

from .support_evidence import NATIVE_TARGETS, PLATFORMS, REPOSITORY, fetch_evidence


REPO_URL = f"https://github.com/{REPOSITORY}"


def version(value):
    # 只将版本号放入表格，避免把报告中的自由文本或 Markdown 当成证据发布。
    if not isinstance(value, str) or not re.fullmatch(r"[0-9][0-9A-Za-z.+!-]{0,63}", value):
        raise ValueError("报告中的版本号无效")
    return value


def by_name(items):
    indexed = {item["name"]: item for item in items}
    if len(indexed) != len(items):
        raise ValueError("证据中存在重名项目")
    return indexed


def job_link(job, run, os_label, *required_steps):
    if (job["status"] != "completed" or job["conclusion"] != "success"
            or type(job["run_id"]) is not int or job["run_id"] != run
            or os_label not in job["labels"] or type(job["id"]) is not int or job["id"] <= 0):
        raise ValueError("作业运行编号、平台或成功状态不符")
    steps = by_name([step for step in job["steps"] if step["name"] in required_steps])
    for name in required_steps:
        step = steps.get(name, {})
        if step.get("status") != "completed" or step.get("conclusion") != "success":
            raise ValueError(f"缺少成功的验收步骤：{name}")
    return f"[作业记录]({REPO_URL}/actions/runs/{run}/job/{job['id']})"


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
    for upstream in (upstreams["previous"], upstreams["candidate"]):
        if upstream["policy_check"] != "pass":
            raise ValueError("上游目录未通过策略体检")
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
        rows = []
        # 每个打包作业贡献一行；其他平台的宿主能力不能由打包作业推导。
        axes = []
        for name in jobs:
            match = re.fullmatch(r"test \(((?:ubuntu|windows|macos)-[a-z0-9.]+), ([0-9]+\.[0-9]+)\)", name)
            if match:
                axes.append(match.groups())
        if not axes:
            raise ValueError("缺少发行包验收作业")
        for system, python in sorted(axes, key=lambda pair: (pair[0], tuple(map(int, pair[1].split("."))))):
            evidence = job_link(jobs[f"test ({system}, {python})"], verify_run, system,
                                "测试与模拟规则基准", "检查归档内容、独立安装和 SHA-256")
            rows.append(f"| 核心包安装 | `{system}` · Python {python} | wheel 和 sdist | 各自在新环境安装，运行策略体检、基准和代理 ping | {evidence} |")
        for system in PLATFORMS:
            rows.append(inspector_row(interop_reports[system], jobs[f"interop ({system})"], verify_run, system))
        if pilot_job["name"] != "lifecycle":
            raise ValueError("缺少基础 Linux 宿主作业")
        rows.append(codex_row(pilot_report, pilot_job, pilot_run))
        gateway = version(pilot_report["gateway_version"])
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True, help="两个工作流共同验收的完整 main 提交 SHA")
    parser.add_argument("--verify-run", required=True, type=int, help="verify 工作流的运行编号")
    parser.add_argument("--pilot-run", required=True, type=int, help="codex-time-pilot 工作流的运行编号")
    args = parser.parse_args()
    try:
        evidence = fetch_evidence(args.commit, args.verify_run, args.pilot_run)
        matrix = render_matrix(args.commit, args.verify_run, args.pilot_run, *evidence)
    except (ValueError, OSError) as exc:
        print(f"无法生成支持矩阵：{exc}", file=sys.stderr)
        return 1
    print(matrix, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
