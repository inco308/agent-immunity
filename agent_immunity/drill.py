#!/usr/bin/env python3
"""上游升级前的策略回归演练：对比两个版本的 tools/list 目录并各跑一次策略体检。

目录用 `interop.capture_catalog` 采集（该步骤需要锁定的 MCP SDK），本工具只做
比较与判定，不依赖 SDK：

    agent-immunity-capture --output before.json -- <升级前上游命令>
    agent-immunity-capture --output after.json  -- <升级后上游命令>
    agent-immunity-drill --policy P.json \
        --old-catalog before.json --new-catalog after.json --json

目录只描述输入。要覆盖输出变化，另用 agent-immunity-probe 采两份观测，
再用 --old-observations/--new-observations 交给本工具比较，可用 --expect
把"必须保持不变的值"写成断言：

    agent-immunity-probe --calls calls.json --output obs-before.json -- <升级前上游>
    agent-immunity-probe --calls calls.json --output obs-after.json  -- <升级后上游>
    agent-immunity-drill --policy P.json \
        --old-catalog before.json --new-catalog after.json \
        --old-observations obs-before.json --new-observations obs-after.json \
        --expect expectations.json --json

判定与 doctor 的退出码保持一致：0 通过，2 需要人工复核，1 存在错误。

本工具的边界：它比较的是**输入描述**。上游放松必填、新增可选参数、
改变输出结构或语义，都不会让 doctor 报错；这些必须靠业务验收覆盖，
工具只负责把它们列出来提醒。
"""
import argparse
import json
from pathlib import Path
import sys

from . import doctor

EXIT_CODES = {"pass": 0, "review": 2, "error": 1}
# 合同变严会被 doctor 直接判错；这里列出的是 doctor 不会报错、
# 但升级后行为可能变化的变化类型。
REVIEW_KINDS = frozenset({
    "TOOL_ADDED", "TOOL_REMOVED", "REQUIRED_LOOSENED",
    "PROPERTY_ADDED", "PROPERTY_REMOVED", "TYPE_CHANGED",
    "CALL_MISSING", "ERROR_CHANGED", "FIELD_ADDED", "FIELD_REMOVED",
    "OBSERVATION_TYPE_CHANGED", "VALUE_CHANGED", "DECISION_CHANGED",
    "STRUCTURED_ADDED", "STRUCTURED_REMOVED",
})
OBSERVATION_MESSAGES = {
    "CALL_MISSING": "两份观测的调用集合不同，无法逐项比较。",
    "ERROR_CHANGED": "同一调用的成功/失败状态发生变化。",
    "FIELD_ADDED": "返回中新增字段；请确认调用方不依赖固定字段集。",
    "FIELD_REMOVED": "返回中缺少原有字段；下游解析可能失败。",
    "OBSERVATION_TYPE_CHANGED": "同一字段的类型发生变化。",
    "VALUE_CHANGED": "同一字段的取值发生变化。",
    "DECISION_CHANGED": "同一次调用的策略判定发生变化。",
    "STRUCTURED_ADDED": "上游开始提供 structuredContent。",
    "STRUCTURED_REMOVED": "上游不再提供 structuredContent。",
}
_MISSING = object()
MESSAGES = {
    "TOOL_ADDED": "上游新增工具，本地策略未登记，代理不会向宿主暴露它。",
    "TOOL_REMOVED": "本地策略登记的工具在上游已不存在，调用会直接失败。",
    "REQUIRED_STRICTENED": "上游新增必填字段，现有策略描述的调用可能被上游拒绝。",
    "REQUIRED_LOOSENED": "上游不再要求该字段；doctor 不会报错，但服务端可能开始使用默认值。",
    "PROPERTY_ADDED": "上游新增可选参数；本地策略未公开它，调用仍可通过。",
    "PROPERTY_REMOVED": "上游移除了该参数；本地策略仍公开它，调用可能被上游拒绝。",
    "TYPE_CHANGED": "参数类型发生变化，需要核对该字段的取值。",
}


def catalog_drift(old, new):
    """列出两个目录之间与升级相关的差异；输入是 {工具名: inputSchema}。"""
    changes = []
    for name in sorted(set(old) - set(new)):
        changes.append({"kind": "TOOL_REMOVED", "tool": name})
    for name in sorted(set(new) - set(old)):
        changes.append({"kind": "TOOL_ADDED", "tool": name})
    for name in sorted(set(old) & set(new)):
        before, after = old[name], new[name]
        required_before = set(before.get("required") or [])
        required_after = set(after.get("required") or [])
        for field in sorted(required_after - required_before):
            changes.append({"kind": "REQUIRED_STRICTENED", "tool": name, "field": field})
        for field in sorted(required_before - required_after):
            changes.append({"kind": "REQUIRED_LOOSENED", "tool": name, "field": field})
        props_before = before.get("properties") or {}
        props_after = after.get("properties") or {}
        for field in sorted(set(props_after) - set(props_before)):
            changes.append({"kind": "PROPERTY_ADDED", "tool": name, "field": field})
        for field in sorted(set(props_before) - set(props_after)):
            changes.append({"kind": "PROPERTY_REMOVED", "tool": name, "field": field})
        for field in sorted(set(props_before) & set(props_after)):
            type_before = props_before[field].get("type")
            type_after = props_after[field].get("type")
            if type_before != type_after:
                changes.append({"kind": "TYPE_CHANGED", "tool": name, "field": field,
                                "from": type_before, "to": type_after})
    for change in changes:
        change["message"] = MESSAGES[change["kind"]]
    return changes


def _value_at(document, path):
    """按点号路径取值；数组用下标。取不到时返回 _MISSING。"""
    current = document
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return _MISSING
    return current


def _ignored(path, patterns):
    return any(path == pattern or path.startswith(pattern + ".") for pattern in patterns)


def load_observation_document(path):
    """读取 agent-immunity-probe 产出的完整观测文档。"""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"观测文件无法读取: {Path(path).name}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("观测文件必须是 schema_version=1 的对象")
    calls = data.get("calls")
    if not isinstance(calls, list):
        raise ValueError("观测文件缺少 calls 列表")
    effects = data.get("effects", [])
    if not isinstance(effects, list) or any(not isinstance(item, dict) for item in effects):
        raise ValueError("观测文件的 effects 必须是对象列表")
    return data


def load_observations(path):
    """按调用 id 索引观测记录。"""
    indexed = {}
    for entry in load_observation_document(path)["calls"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise ValueError("观测文件的每个调用都需要字符串 id")
        indexed[entry["id"]] = entry
    return indexed


def observation_changes(old_calls, new_calls, ignore=()):
    """比较两份观测：字段增删、类型变化、取值变化与调用集合差异。"""
    changes = []

    def add(kind, call, path=None, **extra):
        entry = {"kind": kind, "call": call, "message": OBSERVATION_MESSAGES[kind]}
        if path is not None:
            entry["path"] = path
        entry.update(extra)
        changes.append(entry)

    for call_id in sorted(set(old_calls) | set(new_calls)):
        before, after = old_calls.get(call_id), new_calls.get(call_id)
        if before is None or after is None:
            add("CALL_MISSING", call_id)
            continue
        if bool(before.get("is_error")) != bool(after.get("is_error")):
            add("ERROR_CHANGED", call_id)
        old_decision, new_decision = before.get("decision"), after.get("decision")
        if old_decision is not None and new_decision is not None and old_decision != new_decision:
            add("DECISION_CHANGED", call_id, before=old_decision, after=new_decision)
        if bool(before.get("structured")) != bool(after.get("structured")):
            add("STRUCTURED_ADDED" if after.get("structured") else "STRUCTURED_REMOVED", call_id)
        shape_before, shape_after = before.get("shape") or {}, after.get("shape") or {}
        for path in sorted(set(shape_before) - set(shape_after)):
            if not _ignored(path, ignore):
                add("FIELD_REMOVED", call_id, path)
        for path in sorted(set(shape_after) - set(shape_before)):
            if not _ignored(path, ignore):
                add("FIELD_ADDED", call_id, path)
        for path in sorted(set(shape_before) & set(shape_after)):
            if _ignored(path, ignore):
                continue
            if shape_before[path] != shape_after[path]:
                add("OBSERVATION_TYPE_CHANGED", call_id, path,
                    before=shape_before[path], after=shape_after[path])
                continue
            if shape_after[path] in ("object", "array"):
                continue
            old_json, new_json = before.get("json"), after.get("json")
            # JSON 与纯文本的差异会表现为字段增删（text 与具体字段），这里只比较同形态取值。
            if old_json is None and new_json is None:
                if before.get("text") != after.get("text"):
                    add("VALUE_CHANGED", call_id, "text")
                break
            old_value = _value_at(old_json, path)
            new_value = _value_at(new_json, path)
            if old_value is not _MISSING and new_value is not _MISSING and old_value != new_value:
                add("VALUE_CHANGED", call_id, path,
                    before=_preview(old_value), after=_preview(new_value))
    return changes


def _preview(value, limit=120):
    """报告里只放短预览；观测文件本身可能含真实数据。"""
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return text if len(text) <= limit else text[:limit] + "…"


def load_expectations(path):
    """读取断言文件：ignore 路径列表与 expect 断言列表。"""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"断言文件无法读取: {Path(path).name}") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("断言文件必须是 version=1 的对象")
    unknown = set(data) - {"version", "ignore", "expect", "forbid_effects", "note"}
    if unknown:
        raise ValueError(f"断言文件含不支持的字段: {', '.join(sorted(unknown))}")
    ignore = data.get("ignore", [])
    expect = data.get("expect", [])
    if not isinstance(ignore, list) or any(not isinstance(item, str) or not item for item in ignore):
        raise ValueError("ignore 必须是非空字符串列表")
    if not isinstance(expect, list):
        raise ValueError("expect 必须是列表")
    for index, item in enumerate(expect):
        if not isinstance(item, dict):
            raise ValueError(f"expect 第 {index + 1} 项必须是对象")
        extra = set(item) - {"id", "path", "equals", "contains", "decision", "note"}
        if extra:
            raise ValueError(f"expect 第 {index + 1} 项含不支持的字段: {', '.join(sorted(extra))}")
        if not isinstance(item.get("id"), str) or not item["id"]:
            raise ValueError(f"expect 第 {index + 1} 项缺少字符串 id")
        if "contains" in item:
            if not isinstance(item["contains"], str):
                raise ValueError(f"expect 第 {index + 1} 项的 contains 必须是字符串")
        elif "decision" in item:
            if not isinstance(item["decision"], str) or not item["decision"]:
                raise ValueError(f"expect 第 {index + 1} 项的 decision 必须是非空字符串")
        elif not isinstance(item.get("path"), str) or "equals" not in item:
            raise ValueError(f"expect 第 {index + 1} 项需要 path 与 equals、contains 或 decision")
    forbid = data.get("forbid_effects", [])
    if not isinstance(forbid, list) or any(not isinstance(item, str) or not item for item in forbid):
        raise ValueError("forbid_effects 必须是非空字符串列表")
    return {"ignore": ignore, "expect": expect, "forbid_effects": forbid}


def check_forbidden_effects(effects, forbidden):
    """副作用验收：被禁止的路径不得出现在任何一次快照差异里。"""
    failures = []
    for entry in effects:
        if entry.get("truncated"):
            failures.append({"reason": "文件快照被截断，无法据此证明没有副作用",
                             "root": entry.get("root")})
            continue
        for kind in ("created", "modified", "removed"):
            for path in entry.get(kind) or []:
                if any(path == item or path.startswith(item.rstrip("/") + "/") for item in forbidden):
                    failures.append({"root": entry.get("root"), "path": path,
                                     "kind": kind, "reason": "被禁止的路径发生了变化"})
    return failures


def check_expectations(calls, expectations):
    """逐条核对断言；失败项直接判错，不做猜测。"""
    failures = []
    for item in expectations:
        call_id = item["id"]
        record = calls.get(call_id)
        if record is None:
            failures.append({"call": call_id, "reason": "观测里没有这个调用"})
            continue
        if "contains" in item:
            if item["contains"] not in (record.get("text") or ""):
                failures.append({"call": call_id, "reason": "返回文本不含期望片段",
                                 "expected": item["contains"]})
            continue
        if "decision" in item:
            actual_decision = record.get("decision")
            if actual_decision is None:
                failures.append({"call": call_id, "reason": "该观测未经过代理，没有判定码",
                                 "expected": item["decision"]})
            elif actual_decision != item["decision"]:
                failures.append({"call": call_id, "reason": "判定码不符",
                                 "expected": item["decision"], "actual": actual_decision})
            continue
        actual = _value_at(record.get("json"), item["path"])
        if actual is _MISSING:
            failures.append({"call": call_id, "path": item["path"], "reason": "返回里没有该路径"})
        elif actual != item["equals"]:
            failures.append({"call": call_id, "path": item["path"],
                             "expected": _preview(item["equals"]), "actual": _preview(actual)})
    return failures


def verdict(baseline, upgraded, changes):
    """升级后是否仍可交付：错误优先，其次是 doctor 复核项与目录变化。"""
    severity = {finding.get("severity") for report in (baseline, upgraded)
                for finding in report["findings"]}
    if "error" in severity:
        return "error"
    if "review" in severity or any(change["kind"] in REVIEW_KINDS for change in changes):
        return "review"
    return "pass"


def run(policy_path, old_catalog_path, new_catalog_path,
        old_observations=None, new_observations=None, expectations=None):
    old_catalog = doctor.read_catalog(Path(old_catalog_path))
    new_catalog = doctor.read_catalog(Path(new_catalog_path))
    baseline = doctor.check(Path(policy_path), Path(old_catalog_path))
    upgraded = doctor.check(Path(policy_path), Path(new_catalog_path))
    changes = catalog_drift(old_catalog, new_catalog)

    observation_report = None
    failures = []
    if new_observations is not None:
        spec = expectations or {"ignore": [], "expect": []}
        # 只给新版观测时做单版本断言（例如升级后核对"该被拒的确实被拒了"）。
        before = load_observations(old_observations) if old_observations is not None else {}
        after = load_observations(new_observations)
        document = load_observation_document(new_observations)
        # 没有升级前观测时只做单版本断言，不比较调用集合。
        observation_changes_list = (observation_changes(before, after, spec["ignore"])
                                    if old_observations is not None else [])
        failures = check_expectations(after, spec["expect"])
        effect_failures = check_forbidden_effects(document.get("effects", []),
                                                  spec.get("forbid_effects", []))
        failures = failures + effect_failures
        observation_report = {
            "calls": sorted(set(before) | set(after)),
            "changes": observation_changes_list,
            "expectation_failures": failures,
            "ignored_paths": spec["ignore"],
            "effects": document.get("effects", []),
            "proxied": bool((document.get("upstream") or {}).get("proxied")),
        }
        changes = changes + observation_changes_list
        # 判定从拒绝变成放行是安全回退，必须判错而不是只提示复核。
        if any(change["kind"] == "DECISION_CHANGED" and change["after"] == "PASS"
               and change["before"] != "PASS" for change in observation_changes_list):
            failures.append({"reason": "同一次调用从被拒变为放行，属于安全回退"})

    status = "error" if failures else verdict(baseline, upgraded, changes)
    not_measured = ["语义变化", "真实业务结果"]
    if old_observations is None:
        not_measured.insert(0, "输出结构变化")
    if observation_report is None or not observation_report["effects"]:
        not_measured.append("副作用是否发生（未提供 --watch 快照）")
    report = {
        "schema_version": 1,
        "scope": "UPGRADE_DRIFT",
        "status": status,
        "baseline": baseline,
        "upgraded": upgraded,
        "changes": changes,
        "not_measured": not_measured,
    }
    if observation_report is not None:
        report["observations"] = observation_report
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--policy", required=True, type=Path, help="升级前后共用的本地策略")
    parser.add_argument("--old-catalog", required=True, type=Path, help="升级前的 tools/list 快照")
    parser.add_argument("--new-catalog", required=True, type=Path, help="升级后的 tools/list 快照")
    parser.add_argument("--old-observations", type=Path, help="升级前的调用观测（agent-immunity-probe）")
    parser.add_argument("--new-observations", type=Path, help="升级后的调用观测（agent-immunity-probe）")
    parser.add_argument("--expect", type=Path, help="业务断言与忽略路径")
    parser.add_argument("--output", type=Path, help="把完整报告写入该文件")
    parser.add_argument("--json", action="store_true", help="输出适合 CI 使用的 JSON")
    args = parser.parse_args(argv)

    if args.old_observations is not None and args.new_observations is None:
        parser.error("--old-observations 需要同时提供 --new-observations")
    if args.expect is not None and args.new_observations is None:
        parser.error("--expect 必须与观测一起使用")
    try:
        expectations = load_expectations(args.expect) if args.expect else None
    except ValueError as error:
        parser.error(str(error))
    try:
        report = run(args.policy, args.old_catalog, args.new_catalog,
                     args.old_observations, args.new_observations, expectations)
    except ValueError as error:
        parser.error(str(error))
    payload = json.dumps(report, ensure_ascii=True, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    if args.json:
        print(payload)
    else:
        print(f"{report['status'].upper()}  升级漂移演练；变化条目 {len(report['changes'])}")
        for name, label in (("baseline", "升级前"), ("upgraded", "升级后")):
            findings = report[name]["findings"]
            codes = sorted({finding["code"] for finding in findings}) or ["无"]
            print(f"  {label} doctor：{report[name]['status']}，"
                  f"隐藏工具 {report[name]['hidden_tools']}，发现 {', '.join(codes)}")
        for change in report["changes"]:
            location = change.get("field") or change.get("path") or ""
            subject = change.get("tool") or change.get("call") or ""
            print(f"  - {change['kind']} {subject} {location}".rstrip())
        observations = report.get("observations")
        if observations is not None:
            print(f"  观测调用 {len(observations['calls'])} 个，"
                  f"忽略路径 {len(observations['ignored_paths'])} 条，"
                  f"断言失败 {len(observations['expectation_failures'])} 条")
            for failure in observations["expectation_failures"]:
                # 副作用类失败没有 call，用 root/kind 定位。
                subject = " ".join(str(failure[key]) for key in ("call", "root", "path", "kind")
                                   if failure.get(key))
                print(f"  ! 失败 {subject}：{failure['reason']}".replace("  ", " "))
        print("  未测量：" + "、".join(report["not_measured"]))
    return EXIT_CODES[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
