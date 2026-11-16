"""将独立双构建故障演练的报告渲染为支持矩阵的附表。"""
import re

from . import support_evidence as evidence


def digest(value, length=64):
    if not isinstance(value, str) or not re.fullmatch(f"[0-9a-f]{{{length}}}", value):
        raise ValueError("提交或摘要必须为指定长度的小写十六进制字符串")
    return value


def build_link(build):
    commit = digest(build["commit"], 40)
    wheel = digest(build["wheel_sha256"])
    digest(build["metadata_sha256"])
    if any(type(build[key]) is not int or build[key] <= 0 for key in ("run_id", "artifact_id", "runtime_files")):
        raise ValueError("网关来源或安装文件数无效")
    url = f"{evidence.REPO_URL}/actions/runs/{build['run_id']}/artifacts/{build['artifact_id']}"
    return f"[{evidence.version(build['version'])} · `{wheel[:12]}`]({url})（提交 `{commit[:7]}`）"


def recovery_row(report, matrix_commit, verify_run, gateway_version):
    if (not evidence._matches(report, {"schema_version": 2, "scope": "CODEX_MCP_LIFECYCLE", "status": "failed",
                                       "gateway_mode": "verified_previews", "attempted_phase": "upgrade",
                                       "failure_type": "GatewayStartupError"})
            or report["host_startup_state"] not in ("failed", "discovery_timeout")
            or "rollback_error_type" in report):
        raise ValueError("需要双预览构建在宿主升级时启动失败的报告")
    stages = report["stages"]
    if not isinstance(stages, list) or len(stages) != 1 or stages[0]["phase"] != "install":
        raise ValueError("恢复基线应为唯一成功的初装阶段")
    initial, recovered = stages[0], report["recovery"]
    fault, comparison = report["fault"], report["policy_comparison"]
    if (not evidence._matches(recovered, {"phase": "recovery", "status": "passed"})
            or not evidence._matches(fault, {"kind": "missing_candidate_upstream", "exit_code": 1})
            or not evidence._matches(comparison, {"status": "pass", "candidate_runtime_check": "pass", "codes": []})):
        raise ValueError("需要候选策略检查通过、上游缺失退出和原宿主重连证据")

    original_policy = digest(report["policy_sha256"])
    candidate_policy = digest(comparison["candidate_policy_sha256"])
    original_config = digest(initial["config_sha256"])
    if (comparison["baseline_policy_sha256"] != original_policy or candidate_policy == original_policy
            or fault["policy_sha256"] != candidate_policy or digest(fault["config_sha256"]) == original_config
            or report["restored_verified_config_sha256"] != original_config):
        raise ValueError("候选故障配置或恢复策略的摘要不符")

    upstreams = report["upstreams"]
    previous, candidate = (upstreams[key]["gateway"] for key in ("previous", "candidate"))
    previous_link, candidate_link = build_link(previous), build_link(candidate)
    if (any(previous[key] == candidate[key] for key in ("commit", "run_id", "artifact_id", "wheel_sha256"))
            or candidate["commit"] != matrix_commit or candidate["run_id"] != verify_run
            or candidate["version"] != gateway_version
            or not evidence._matches(fault["gateway"], candidate)):
        raise ValueError("候选构建必须匹配矩阵提交、故障安装和独立的来源收据")
    old, new = (evidence.version(upstreams[key]["installed_version"]) for key in ("previous", "candidate"))
    if old == new or upstreams["previous"]["policy_check"] != "pass":
        raise ValueError("上游版本或初装兼容性检查不符")
    for slot in ("previous", "candidate"):
        digest(upstreams[slot]["catalog_sha256"])
        if upstreams[slot]["raw_tools"] != ["convert_time", "get_current_time"]:
            raise ValueError("第三方时区工具目录证据不符")
    expected = {"version": old, "policy_sha256": original_policy, "config_sha256": original_config,
                "visible_tools": ["convert_time"], "source": "UTC 09:00", "target": "Asia/Tokyo 18:00",
                "difference": "+9.0h", "weekday_field": False, "denial": "TRANSITION_DENIED"}
    for stage in (initial, recovered):
        if not evidence._matches(stage, expected) or not evidence._matches(stage["gateway"], previous):
            raise ValueError("初装或恢复阶段的网关、策略、时区转换或重复调用拒绝记录不符")
    codex = report["codex_version"]
    if not codex.startswith("codex-cli "):
        raise ValueError("报告缺少实际 Codex CLI 版本")
    host = f"Codex CLI {evidence.version(codex.removeprefix('codex-cli '))} · MCP Python SDK {evidence.version(report['mcp_sdk'])}"
    return (f"| `ubuntu-24.04` · {host} | 原 {previous_link} → 候选 {candidate_link} → 原构建 | "
            f"mcp-server-time 从 {old} 升级到 {new} 时上游程序缺失，候选网关退出 1。恢复 {old} 后完成时区转换并拒绝重复调用 |")


def render_recovery(commit, run_id, job, report, artifact_id, *, matrix_commit, verify_run, gateway_version):
    """以演练自身的提交和作业标记附表，候选网关必须来自主矩阵提交。"""
    digest(commit, 40)
    digest(matrix_commit, 40)
    if any(type(value) is not int or value <= 0 for value in (run_id, artifact_id, verify_run)):
        raise ValueError("需要正整数演练编号与报告产物编号")
    try:
        if not evidence._matches(job, {"name": "lifecycle", "run_attempt": 1, "head_sha": commit}):
            raise ValueError("演练作业与指定提交不一致")
        link = evidence.job_link(job, run_id, "ubuntu-24.04", *evidence.RECOVERY_STEPS)
        row = recovery_row(report, matrix_commit, verify_run, gateway_version)
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("恢复报告或作业缺少有效字段") from exc
    artifact = f"{evidence.REPO_URL}/actions/runs/{run_id}/artifacts/{artifact_id}"
    return "\n".join([
        "## 双构建故障恢复演练", "",
        f"演练提交 [`{commit[:7]}`]({evidence.REPO_URL}/commit/{commit})。网关按各自的 wheel SHA-256 前缀标识。",
        "", "| CI 环境与宿主 | 网关构建 | 已执行的故障与恢复验收 | 证据 |", "| --- | --- | --- | --- |",
        f"{row} {link} · [恢复报告]({artifact}) |", "",
    ])
