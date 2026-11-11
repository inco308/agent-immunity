"""透明的模拟规则基准；进程及副作用证据由独立集成测试提供。"""
import argparse
import base64
import json
import platform
import re
import statistics
import tempfile
from pathlib import Path
from time import perf_counter_ns
from unittest.mock import patch
from agent_immunity import DynamicImmunityEngine, Policy, ToolCall, ToolResult
from agent_immunity.dataset.scenarios import load_cases, load_policy

MODES = ("NO_POLICY", "REGEX_EXAMPLE", "POLICY_ONLY", "POLICY_AND_CREDENTIALS")
# 故意公开这个简单基线的具体规则；它不代表商用护栏或 LLM。
REGEX = re.compile(r"(?i)\b(?:password\s*[:=]|api_key\s*[:=]|rm\s+-rf)")

def materialize(case, secret):
    encoded = {
        "base64": base64.b64encode(secret.encode()).decode(),
        "percent": "".join("%%%02X" % x for x in secret.encode()),
        "hex": secret.encode().hex(),
        "wrapped_base64": base64.b64encode(json.dumps({"payload": secret}, separators=(",", ":")).encode()).decode(),
    }.get(case.get("encoding"), secret)
    def replace(value):
        if isinstance(value, str):
            return value.replace("$ENCODED", encoded).replace("$SECRET", secret)
        if isinstance(value, dict):
            return {k: replace(v) for k, v in value.items()}
        if isinstance(value, list):
            return [replace(v) for v in value]
        return value
    return replace(case)

def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, int((len(ordered) - 1) * fraction))] / 1e6

def evaluate_case(case, policy, mode, repeats):
    call = ToolCall(case["id"], case["tool"], case["args"])
    engine = DynamicImmunityEngine(policy)
    if "source" in case:
        result = engine.execute(ToolCall("source", "document", {}), lambda *_: ToolResult(case["source"]))
        if result.is_error:
            raise AssertionError("基准来源准备失败")
    def decide():
        if mode == "NO_POLICY":
            return "ALLOW"
        if mode == "REGEX_EXAMPLE":
            return "REGEX_DENIED" if REGEX.search(json.dumps(call.arguments)) else "ALLOW"
        return engine.check_call(call).code
    def measure():
        code = decide()
        timings = []
        for _ in range(repeats):
            start = perf_counter_ns()
            actual = decide()
            timings.append(perf_counter_ns() - start)
            if actual != code:
                raise AssertionError("同一调用决策不稳定")
        return code, timings
    try:
        if mode == "POLICY_ONLY":
            # 仅消融凭证检查，不改变权限校验；补丁不进入产品配置/API。
            with patch.object(engine.taint_tracker, "contains_sensitive", return_value=False):
                return measure()
        return measure()
    finally:
        engine.close()

def run(repeats=100, temp_root=None):
    if type(repeats) is not int or not 1 <= repeats <= 10000:
        raise ValueError("repeats 必须介于 1 和 10000")
    dataset = load_cases()
    cases = [materialize(case, dataset["secret"]) for case in dataset["cases"]]
    report = {
        "schema_version": 1, "scope": "SIMULATED_CALL_DECISIONS",
        "python": platform.python_version(), "platform": platform.platform(),
        "cases": len(cases), "repeats_per_case": repeats,
        "not_measured": ["LLM agent behavior", "LLM self-guard", "end-to-end task completion", "end-to-end latency", "self-healing", "OS isolation"],
        "modes": {}, "regressions": [],
    }
    with tempfile.TemporaryDirectory(dir=temp_root) as directory:
        policy = Policy.from_dict(load_policy(directory))
        for mode in MODES:
            rows, timings = [], []
            for case in cases:
                code, samples = evaluate_case(case, policy, mode, repeats)
                timings.extend(samples)
                rows.append({"id": case["id"], "kind": case["kind"], "description": case["description"], "code": code, "allowed": code == "ALLOW", "known_limitation": case.get("limitation", False)})
                if mode == "POLICY_AND_CREDENTIALS" and code != case["expected"]:
                    report["regressions"].append({"id": case["id"], "expected": case["expected"], "actual": code})
            attacks = [row for row in rows if row["kind"] == "attack"]
            benign = [row for row in rows if row["kind"] == "benign"]
            blocked = sum(not row["allowed"] for row in attacks)
            denied_benign = sum(not row["allowed"] for row in benign)
            report["modes"][mode] = {
                "attack_calls": len(attacks), "blocked_attack_calls": blocked,
                "attack_call_block_rate": blocked / len(attacks),
                "benign_calls": len(benign), "allowed_benign_calls": len(benign) - denied_benign,
                "benign_call_false_positive_rate": denied_benign / len(benign),
                "decision_latency_ms": {"mean": statistics.mean(timings) / 1e6, "p50": percentile(timings, .5), "p95": percentile(timings, .95), "p99": percentile(timings, .99)},
                "rows": rows,
            }
    baseline = report["modes"]["NO_POLICY"]["decision_latency_ms"]["mean"]
    for result in report["modes"].values():
        result["mean_decision_overhead_vs_no_policy_ms"] = result["decision_latency_ms"]["mean"] - baseline
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("artifacts/benchmark.json"))
    parser.add_argument("--repeats", type=int, default=100)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = run(args.repeats, temp_root=args.output.parent)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for mode, metrics in report["modes"].items():
        print(f'{mode}: attack_calls_blocked={metrics["blocked_attack_calls"]}/{metrics["attack_calls"]}, benign_allowed={metrics["allowed_benign_calls"]}/{metrics["benign_calls"]}, decision_p95_ms={metrics["decision_latency_ms"]["p95"]:.4f}')
    print(f"模拟规则基准已写入 {args.output}；完整任务、模型、自愈和内核隔离均未测量。")
    return 1 if report["regressions"] else 0

if __name__ == "__main__":
    raise SystemExit(main())
