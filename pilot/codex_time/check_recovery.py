"""独立验收候选启动失败后的 Codex 业务恢复报告和本次演练的磁盘证据。"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from .run import HERE, VERSIONS, config_bytes, registration, startup_fault_registration


def matches_receipt(identity, source):
    return (all(identity[key] == source[key] for key in ("commit", "run_id", "artifact_id", "version", "wheel_sha256"))
            and re.fullmatch("[0-9a-f]{64}", identity["metadata_sha256"])
            and type(identity["runtime_files"]) is int and identity["runtime_files"] > 0)


def validate(output_dir, environment_path, runner_exit_code, *, candidate_policy_template=None):
    """只接受预设故障被观测、初装保留且原工具在新宿主中重新通过验收的结果。"""
    if runner_exit_code != 1:
        raise ValueError("原升级命令应当报告失败并返回 1")
    root = Path(output_dir).resolve()
    report = json.loads((root / "report.json").read_bytes())
    env = json.loads(Path(environment_path).read_bytes())
    if (report["scope"] != "CODEX_MCP_LIFECYCLE" or report["status"] != "failed"
            or report["attempted_phase"] != "upgrade" or report["failure_type"] != "GatewayStartupError"
            or report["host_startup_state"] not in {"failed", "discovery_timeout"}):
        raise ValueError("宿主未观测到预期的候选启动故障")
    fault = report["fault"]
    combined = candidate_policy_template is not None
    kind, code = ("missing_candidate_upstream", 1) if combined else ("missing_candidate_policy", 2)
    missing_input = root / ("absent-candidate-upstream" if combined else "absent-candidate-policy.json")
    if (missing_input.exists() or fault["kind"] != kind or type(fault["exit_code"]) is not int or fault["exit_code"] != code
            or (root / "candidate-exit.txt").read_bytes() not in (f"{code}\n".encode(), f"{code}\r\n".encode())):
        raise ValueError("候选网关的退出证据不符")
    if len(report["stages"]) != 1 or report["stages"][0]["phase"] != "install":
        raise ValueError("只有成功的初装可以成为本次恢复的基线")
    initial = report["stages"][0]
    recovery = report["recovery"]
    if recovery["status"] != "passed" or recovery["phase"] != "recovery" or "rollback_error_type" in report:
        raise ValueError("原配置未完成独立的宿主重连验收")

    schema = env["schema_version"]
    if schema != report["schema_version"] or schema not in (1, 2):
        raise ValueError("恢复报告与准备好的环境类型不一致")
    if schema == 2:
        source = env["gateway_slots"]["previous"]
        gateway = source["python"]
        candidate = env["gateway_slots"]["candidate"]["python"]
        identity = initial["gateway"]
        if (report["gateway_mode"] != "verified_previews" or recovery["gateway"] != identity
                or report["upstreams"]["previous"]["gateway"] != identity
                or not matches_receipt(identity, source)):
            raise ValueError("恢复阶段的网关安装证据与预览收据或初装记录不一致")
    else:
        gateway = env["gateway"]
        candidate = gateway
        if (report["gateway_wheel_sha256"] != env["gateway_wheel_sha256"]
                or report["gateway_version"] != env["versions"]["gateway"]):
            raise ValueError("初装的网关与准备环境不符")

    policy = root / "policy.json"
    if policy.read_bytes() != (HERE / "policy.json").read_bytes():
        raise ValueError("活动策略与试点策略不一致")
    expected = config_bytes(registration(gateway, policy, env["previous"]))
    candidate_policy = root / "candidate-policy.json" if combined else None
    if combined:
        comparison = report["policy_comparison"]
        original_hash = hashlib.sha256(policy.read_bytes()).hexdigest()
        candidate_bytes = candidate_policy.read_bytes()
        candidate_hash = hashlib.sha256(candidate_bytes).hexdigest()
        if (candidate_bytes != Path(candidate_policy_template).read_bytes()
                or comparison["status"] != "pass" or comparison["codes"] != []
                or comparison["candidate_runtime_check"] != "pass"
                or comparison["baseline_policy_sha256"] != original_hash
                or comparison["candidate_policy_sha256"] != candidate_hash or fault["policy_sha256"] != candidate_hash
                or initial["policy_sha256"] != original_hash or recovery["policy_sha256"] != original_hash):
            raise ValueError("候选检查、故障注册或恢复阶段的策略证据不符")
        if schema == 2:
            origin = env["gateway_slots"]["candidate"]
            identity = fault["gateway"]
            if (identity != report["upstreams"]["candidate"]["gateway"]
                    or identity["wheel_sha256"] == recovery["gateway"]["wheel_sha256"]
                    or not matches_receipt(identity, origin)):
                raise ValueError("候选故障网关的安装身份与候选构建收据不符")
    fault_config = config_bytes(startup_fault_registration(candidate, root, env["candidate"],
                                                           candidate_policy=candidate_policy))
    if fault["config_sha256"] != hashlib.sha256(fault_config).hexdigest():
        raise ValueError("故障配置摘要与准备环境中的候选网关、候选上游和启动探针不符")
    active = (root / "host-project/.codex/config.toml").read_bytes()
    digest = hashlib.sha256(active).hexdigest()
    if (active != expected or report["policy_sha256"] != hashlib.sha256(policy.read_bytes()).hexdigest()
            or any(value != digest for value in (initial["config_sha256"], recovery["config_sha256"],
                                                 report["restored_verified_config_sha256"]))):
        raise ValueError("磁盘上的配置、策略或恢复摘要不符")
    for stage in (initial, recovery):
        if (stage["version"] != VERSIONS["previous"] or stage["visible_tools"] != ["convert_time"]
                or stage["source"] != "UTC 09:00" or stage["target"] != "Asia/Tokyo 18:00"
                or stage["difference"] != "+9.0h" or stage["weekday_field"] is not False
                or stage["denial"] != "TRANSITION_DENIED"):
            raise ValueError("初装或重连后的可见工具、时区业务结果或策略拒绝不符")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--runner-exit-code", type=int, required=True)
    parser.add_argument("--candidate-policy-template", type=Path, help="核验该候选策略通过检查后发生的启动故障")
    args = parser.parse_args()
    try:
        validate(args.output_dir, args.environment, args.runner_exit_code, candidate_policy_template=args.candidate_policy_template)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        parser.exit(1, f"故障恢复证据未通过验收：{exc}\n")
    print("已核对候选启动失败、原配置与原宿主业务恢复。")


if __name__ == "__main__":
    main()
