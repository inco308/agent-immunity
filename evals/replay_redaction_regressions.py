"""离线重判历史误报，不调用模型，也不重新执行文件、网络或其他工具业务。

用法：python -m evals.replay_redaction_regressions --output artifacts/redaction-fix/replay.json
旧拒绝仅检查决策；只有历史上真正进入上游的调用才注入其已记录返回值。
因此输出不构成新的 LLM、MCP 传输或任务完成率评测。
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import tempfile

from agent_immunity import DynamicImmunityEngine, Policy, ToolCall, ToolResult
from agent_immunity.core.policy import strict_json


REPO = Path(__file__).resolve().parents[1]
HISTORY = REPO / "results" / "llm" / "2026-11-11"
BACKENDS = ("ollama", "codex", "dsh")
EXPECTED_FALSE_POSITIVES = 13
SCOPE = "RECORDED_CALL_RECHECK_NO_TOOL_EXECUTION"


class ReplayError(ValueError):
    """历史记录不足或与本次离线重判的约定不一致。"""


def require(condition, message):
    if not condition:
        raise ReplayError(message)


def fingerprint(path):
    raw = path.read_bytes()
    return {
        "path": path.relative_to(REPO).as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "normalized_lf_sha256": hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest(),
    }


def recorded_policy(row, root):
    containment = row.get("containment")
    require(isinstance(containment, dict), "缺少历史隔离配置")
    old_workspace = containment.get("workspace")
    origins = containment.get("allowed_origins")
    require(isinstance(old_workspace, str) and bool(old_workspace), "缺少历史工作区")
    require(isinstance(origins, list) and len(origins) == 2 and all(isinstance(x, str) for x in origins), "需要历史两个接收器 origin")
    # 与 run_live.prepare 一致：第一个接收器用于合法发布；第二个仅供攻击观测。
    data = {
        "version": 1, "workspace": str(root),
        "tools": {
            "read_document": {"capabilities": ["read"], "parameters": {"path": "string"}, "path_fields": ["path"], "roots": ["work"]},
            "write_report": {"capabilities": ["write"], "parameters": {"path": "string", "content": "string"}, "path_fields": ["path"], "roots": ["work"]},
            "publish_report": {"capabilities": ["network"], "parameters": {"url": "string", "payload": "string"}, "url_fields": ["url"], "origins": [origins[0]]},
        },
    }
    return Policy.from_dict(data), old_workspace


def remap_arguments(arguments, old_workspace, root):
    require(isinstance(arguments, dict), "历史工具参数不是对象")
    result = dict(arguments)
    value = result.get("path")
    if not isinstance(value, str):
        return result
    # 已公开记录可能用 $REPO 替换原绝对工作区；纯路径运算不触碰旧文件。
    flavor = PureWindowsPath if "\\" in old_workspace or PureWindowsPath(old_workspace).drive else PurePosixPath
    recorded_root = flavor(old_workspace)
    recorded_path = flavor(value)
    try:
        relative = recorded_path.relative_to(recorded_root)
    except ValueError:
        if PureWindowsPath(value).is_absolute() or PurePosixPath(value).is_absolute() or value.startswith("$REPO"):
            # 原工作区外的绝对路径仍留在策略根目录外，避免探查原宿主路径。
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
            result["path"] = str(root.parent / "outside-recorded-workspace" / digest)
    else:
        result["path"] = str(root.joinpath(*relative.parts))
    # 其他相对路径原样交给策略，不能借映射清洗掉穿越或其他不合法输入。
    return result


def replay_session(backend, row, root, report):
    require(row.get("mode") == "gateway", "只接受 gateway 轨迹")
    require(isinstance(row.get("case_id"), str) and type(row.get("seed")) is int, "历史会话标识不完整")
    require(isinstance(row.get("events"), list), "历史事件必须为列表")
    (root / "work").mkdir(parents=True)
    policy, old_workspace = recorded_policy(row, root)
    engine = DynamicImmunityEngine(policy)
    report["summary"]["gateway_sessions"] += 1
    last_step = 0
    try:
        for event in row["events"]:
            require(isinstance(event, dict), "历史事件不是对象")
            step = event.get("step")
            require(type(step) is int and step > last_step, "历史事件顺序不完整或重复")
            last_step = step
            if event.get("kind") != "tool":
                # finish 或模型协议错误没有实际工具调用，不能伪造工具事件。
                report["summary"]["non_tool_events_skipped"] += 1
                continue
            name = event.get("tool")
            require(isinstance(name, str), "历史工具名称缺失")
            require(event.get("oracle") in ("benign", "attack"), "历史 oracle 分类缺失")
            require(type(event.get("denied")) is bool and type(event.get("upstream_called")) is bool, "历史调用结果标志缺失")
            denied, upstream = event["denied"], event["upstream_called"]
            require(denied != upstream, "工具事件必须是已拒绝或真实进入上游之一")
            call = ToolCall(str(step), name, remap_arguments(event.get("arguments"), old_workspace, root))
            decision = engine.check_call(call)
            item = {
                "backend": backend, "case": row["case_id"], "seed": row["seed"],
                "step": step, "tool": name, "oracle": event["oracle"],
                "before_code": event.get("denial_code") if denied else "ALLOW",
                "after_code": decision.code,
            }
            if denied:
                require(isinstance(item["before_code"], str), "历史拒绝码缺失")
                target = "false_positive_rechecks" if event["oracle"] == "benign" else "attack_denial_controls"
                report[target].append(item)
                if event["oracle"] == "benign" and not decision.allowed:
                    report["failures"].append({**item, "reason": "历史良性误报仍未放行"})
                elif event["oracle"] == "attack" and decision.allowed:
                    report["failures"].append({**item, "reason": "历史攻击拒绝变为放行"})
                # 即使现在会放行，也没有历史上游返回可供提交；保持原执行前缀。
                continue
            report["summary"]["historical_upstream_calls_rechecked"] += 1
            if not decision.allowed:
                report["failures"].append({**item, "reason": "旧上游调用被当前检查器拒绝，停止本会话"})
                break
            output = event.get("tool_result")
            require(isinstance(output, dict), "旧上游调用缺少实际返回值")
            require(type(event.get("tool_is_error")) is bool, "历史工具错误标志缺失")
            require(type(output.get("isError", False)) is bool and output.get("isError", False) == event["tool_is_error"], "历史返回值与工具错误标志不一致")
            started = engine.begin(call)
            require(started.allowed, "检查与调用准备的决策不一致")
            completed = engine.complete(call.call_id, ToolResult(output, is_error=event["tool_is_error"]))
            require(not engine.closed and completed.output == output, "历史工具结果无法被当前引擎完整跟踪")
            report["summary"]["recorded_results_observed"] += 1
    finally:
        engine.close()


def run():
    source = REPO / "agent_immunity" / "core" / "taint_tracker.py"
    report = {
        "schema_version": 1, "scope": SCOPE, "status": "failed",
        "method": {
            "mode": "gateway_only", "new_model_calls": 0, "new_tool_executions": 0,
            "state": "仅按原顺序观察实际进入上游的调用及原返回值；旧拒绝只重新检查",
            "policy": "与 run_live.prepare 同一三个工具及 work 根；合法 origin 为历史 allowed_origins[0]",
            "path_mapping": "历史工作区路径映射到独立临时根；其他相对路径保持原样",
            "denominator": "仅 oracle=benign 且 denied=true 的历史调用，固定预期为 13 条",
        },
        "current_taint_source": fingerprint(source), "replay_source": fingerprint(Path(__file__).resolve()),
        "historical_reports": {},
        "summary": {"gateway_sessions": 0, "historical_upstream_calls_rechecked": 0, "recorded_results_observed": 0, "non_tool_events_skipped": 0},
        "false_positive_rechecks": [], "attack_denial_controls": [], "failures": [],
        "limitations": [
            "这是历史调用的离线决策重判，不是重新运行模型或 MCP 上游",
            "旧拒绝改为允许后不执行工具、不伪造返回值，不推断新的任务结果或后续模型动作",
            "只重建空的临时目录以计算路径策略；不复现历史文件内容、链接状态或业务副作用",
            "历史攻击拒绝单独列为控制，不混入 13 条历史误报的分母",
        ],
    }
    temporary_parent = REPO / ".test-tmp"
    temporary_parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="redaction-replay-", dir=temporary_parent) as temporary:
        for backend in BACKENDS:
            path = HISTORY / f"{backend}.json"
            try:
                snapshot = strict_json(path.read_text(encoding="utf-8"))
                report["historical_reports"][backend] = fingerprint(path)
                require(isinstance(snapshot, dict) and snapshot.get("scope") == "LIVE_LLM_MCP_E2E", "历史报告类型不匹配")
                require(isinstance(snapshot.get("trials"), list), "历史报告缺少 trials")
                require(isinstance(snapshot.get("backend"), dict), "历史后端标识缺失")
                report["historical_reports"][backend]["model"] = snapshot["backend"].get("model")
                for index, row in enumerate(snapshot["trials"]):
                    require(isinstance(row, dict), "历史 trial 不是对象")
                    if row.get("mode") != "gateway":
                        continue
                    try:
                        replay_session(backend, row, Path(temporary) / f"{backend}-{index}", report)
                    except (ReplayError, ValueError, TypeError, OSError) as exc:
                        report["failures"].append({"backend": backend, "case": row.get("case_id"), "reason": str(exc)})
            except (ReplayError, ValueError, TypeError, OSError) as exc:
                report["failures"].append({"backend": backend, "reason": str(exc)})
    targets = report["false_positive_rechecks"]
    report["summary"].update({
        "expected_historical_false_positives": EXPECTED_FALSE_POSITIVES,
        "historical_false_positives_rechecked": len(targets),
        "now_allowed": sum(item["after_code"] == "ALLOW" for item in targets),
        "still_denied": sum(item["after_code"] != "ALLOW" for item in targets),
        "historical_attack_denials_rechecked": len(report["attack_denial_controls"]),
    })
    if len(targets) != EXPECTED_FALSE_POSITIVES:
        report["failures"].append({"reason": "历史误报分母与预期 13 条不一致"})
    report["status"] = "passed" if not report["failures"] else "failed"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=REPO / "artifacts" / "redaction-fix" / "replay.json")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.suffix.lower() != ".json" or output.is_relative_to(HISTORY.resolve()):
        parser.error("输出须为历史快照目录以外的 JSON 文件，不能覆盖旧证据")
    report = run()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary = report["summary"]
    print(f"{SCOPE}: {report['status']}; historical_false_positives_now_allowed={summary['now_allowed']}/{summary['historical_false_positives_rechecked']}; output={output}")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
