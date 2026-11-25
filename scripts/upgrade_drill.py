#!/usr/bin/env python3
"""上游升级前的策略回归演练：对比两个版本的 tools/list 目录并各跑一次策略体检。

目录用 `interop.capture_catalog` 采集（该步骤需要锁定的 MCP SDK），本工具只做
比较与判定，不依赖 SDK：

    agent-immunity-capture --output before.json -- <升级前上游命令>
    agent-immunity-capture --output after.json  -- <升级后上游命令>
    python -m scripts.upgrade_drill --policy P.json \
        --old-catalog before.json --new-catalog after.json --json

判定与 doctor 的退出码保持一致：0 通过，2 需要人工复核，1 存在错误。

本工具的边界：它比较的是**输入描述**。上游放松必填、新增可选参数、
改变输出结构或语义，都不会让 doctor 报错；这些必须靠业务验收覆盖，
工具只负责把它们列出来提醒。
"""
import argparse
import json
from pathlib import Path
import sys

from agent_immunity import doctor

EXIT_CODES = {"pass": 0, "review": 2, "error": 1}
# 合同变严会被 doctor 直接判错；这里列出的是 doctor 不会报错、
# 但升级后行为可能变化的变化类型。
REVIEW_KINDS = frozenset({
    "TOOL_ADDED", "TOOL_REMOVED", "REQUIRED_LOOSENED",
    "PROPERTY_ADDED", "PROPERTY_REMOVED", "TYPE_CHANGED",
})
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


def verdict(baseline, upgraded, changes):
    """升级后是否仍可交付：错误优先，其次是 doctor 复核项与目录变化。"""
    severity = {finding.get("severity") for report in (baseline, upgraded)
                for finding in report["findings"]}
    if "error" in severity:
        return "error"
    if "review" in severity or any(change["kind"] in REVIEW_KINDS for change in changes):
        return "review"
    return "pass"


def run(policy_path, old_catalog_path, new_catalog_path):
    old_catalog = doctor.read_catalog(Path(old_catalog_path))
    new_catalog = doctor.read_catalog(Path(new_catalog_path))
    baseline = doctor.check(Path(policy_path), Path(old_catalog_path))
    upgraded = doctor.check(Path(policy_path), Path(new_catalog_path))
    changes = catalog_drift(old_catalog, new_catalog)
    return {
        "schema_version": 1,
        "scope": "UPGRADE_DRIFT",
        "status": verdict(baseline, upgraded, changes),
        "baseline": baseline,
        "upgraded": upgraded,
        "changes": changes,
        "not_measured": ["输出结构变化", "语义变化", "真实业务结果", "副作用是否发生"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--policy", required=True, type=Path, help="升级前后共用的本地策略")
    parser.add_argument("--old-catalog", required=True, type=Path, help="升级前的 tools/list 快照")
    parser.add_argument("--new-catalog", required=True, type=Path, help="升级后的 tools/list 快照")
    parser.add_argument("--output", type=Path, help="把完整报告写入该文件")
    parser.add_argument("--json", action="store_true", help="输出适合 CI 使用的 JSON")
    args = parser.parse_args(argv)

    report = run(args.policy, args.old_catalog, args.new_catalog)
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
            location = change.get("field") or ""
            print(f"  - {change['kind']} {change['tool']} {location}".rstrip())
        print("  未测量：输出结构、语义、真实业务结果、副作用是否发生")
    return EXIT_CODES[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
