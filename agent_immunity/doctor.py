"""在启动代理前，离线检查本地策略以及可选的上游 tools/list 快照。"""
import argparse
import json
from pathlib import Path

from .core.policy import UNSUPPORTED_VERSION_HINT, Policy, UnsupportedPolicyVersion, contained, resolved, strict_json


MESSAGES = {
    "POLICY_INVALID": "无法加载策略。请确认文件可读、UTF-8 JSON 完整且键名唯一，再检查整数 version、策略字段和工作目录。",
    "POLICY_VERSION_UNSUPPORTED": UNSUPPORTED_VERSION_HINT,
    "POLICY_TOOL_ADDED": "候选策略新增了此工具，请核对其声明的能力。",
    "POLICY_CAPABILITIES_ADDED": "候选策略为已有工具新增了能力，请核对用途和授权边界。",
    "POLICY_FILE_ROOTS_EXPANDED": "此工具保留的读写能力覆盖了原授权目录之外的位置，请核对两份策略的 roots 与 workspace。",
    "POLICY_NETWORK_ORIGINS_EXPANDED": "此工具获准访问原策略范围之外的网络目标，请在本地核对两份策略的 origins。",
    "POLICY_WRITABLE": "策略文件落在此工具声明的写入根目录内。请将策略移到受保护的目录。",
    "EXEC_ARGUMENTS_INVALID": "至少一个执行白名单条目无法通过这份策略自身的参数检查。",
    "CATALOG_INVALID": "目录必须是完整的 UTF-8 tools/list 快照，工具名唯一，且没有后续分页。",
    "TOOL_MISSING": "策略登记的工具没有出现在这份上游目录中。",
    "REQUIRED_MISMATCH": "上游要求一个本地输入描述没有要求的字段。",
    "FIELD_NOT_ACCEPTED": "本地公开了上游明确禁止的参数。",
    "TYPE_MISMATCH": "本地公开的参数类型超出上游声明的范围。",
    "SCHEMA_REVIEW": "上游含当前无法自动比较的约束，请核对原始 inputSchema。",
}
ANNOTATIONS = {"title", "description", "default", "examples", "$comment", "deprecated", "readOnly", "writeOnly"}
JSON_TYPES = {"null", "boolean", "object", "array", "number", "integer", "string"}
EXIT_CODES = {"pass": 0, "error": 1, "review": 2}
INPUT_ERRORS = (OSError, ValueError, TypeError, RecursionError, OverflowError)


def read_catalog(path):
    with path.open("rb") as stream:
        data = stream.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        raise ValueError("目录过大")
    result = strict_json(data.decode("utf-8"))
    if not isinstance(result, dict) or "nextCursor" in result or not isinstance(result.get("tools"), list):
        raise ValueError("不是完整目录")
    catalog = {}
    for tool in result["tools"]:
        if not isinstance(tool, dict):
            raise ValueError("无效工具")
        name, schema = tool.get("name"), tool.get("inputSchema")
        if not isinstance(name, str) or not name or name in catalog or not isinstance(schema, dict):
            raise ValueError("无效工具名称或输入描述")
        if schema.get("type") != "object":
            raise ValueError("工具输入需要对象类型")
        catalog[name] = schema
    return catalog


def field_issue(local_type, remote):
    if remote is True:
        return None
    if remote is False:
        return "FIELD_NOT_ACCEPTED"
    if not isinstance(remote, dict) or "$ref" in remote or "$schema" in remote:
        return "SCHEMA_REVIEW"
    unknown = bool(remote.keys() - ANNOTATIONS - {"type"})
    if "type" not in remote:
        return "SCHEMA_REVIEW" if unknown else None
    types = remote["type"]
    types = [types] if isinstance(types, str) else types
    if (not isinstance(types, list) or not types or
            any(not isinstance(t, str) or t not in JSON_TYPES for t in types) or len(set(types)) != len(types)):
        return "SCHEMA_REVIEW"
    if local_type in types or (local_type == "integer" and "number" in types):
        return "SCHEMA_REVIEW" if unknown else None
    return "TYPE_MISMATCH"


def contract_issues(spec, schema):
    # 比较客户端实际看到的本地输入描述与上游声明，方向是“本地公开的输入能否被上游接受”。
    relevant = schema.keys() - ANNOTATIONS - {"type", "properties", "required", "additionalProperties"}
    props = schema.get("properties", {})
    required = schema.get("required", [])
    extra = schema.get("additionalProperties", True)
    if (not isinstance(props, dict) or not isinstance(required, list) or
            any(not isinstance(k, str) for k in required) or len(set(required)) != len(required)
            or not isinstance(extra, (dict, bool))
            or any(not isinstance(value, (dict, bool)) for value in props.values())):
        yield "CATALOG_INVALID", None
        return
    if relevant:
        yield "SCHEMA_REVIEW", None
    if "$ref" in schema or "$schema" in schema:
        # 引用的兄弟关键字在不同方言中语义不同。
        return
    if set(required) - set(spec.required):
        yield "REQUIRED_MISMATCH", None
    for field, local_type in sorted(spec.parameters.items()):
        if field not in props and "patternProperties" in schema:
            # 模式属性可能已经接纳该字段，此时 additionalProperties 不适用。
            continue
        problem = field_issue(local_type, props.get(field, extra))
        if problem:
            yield problem, field


def file_roots_expanded(candidate_roots, baseline_roots):
    # 两边均已由策略加载器解析。匹配目录自身和完整祖先，避免逐对比较两份根列表。
    baseline = {str(root) for root in baseline_roots}
    for root in candidate_roots:
        if str(root) not in baseline and not any(str(parent) in baseline for parent in root.parents):
            return True
    return False


def check(policy_path, catalog_path=None, *, baseline_path=None):
    report = {
        "schema_version": 1, "scope": "policy" if catalog_path is None else "policy_and_catalog",
        "status": "pass", "registered_tools": 0, "hidden_tools": None, "findings": [],
    }

    comparing = baseline_path is not None
    if comparing:
        report["comparison"] = {"scope": "added_tools_capabilities_file_roots_and_network_origins", "status": "not_compared"}

    def record(code, tool=None, field=None, *, policy_role=None, capabilities=None):
        severity = "review" if code in (
            "SCHEMA_REVIEW", "POLICY_TOOL_ADDED", "POLICY_CAPABILITIES_ADDED", "POLICY_FILE_ROOTS_EXPANDED",
            "POLICY_NETWORK_ORIGINS_EXPANDED",
        ) else "error"
        entry = {"code": code, "severity": severity, "message": MESSAGES[code]}
        if tool is not None:
            entry["tool"] = tool
        if field is not None:
            entry["field"] = field
        if policy_role is not None:
            entry["policy_role"] = policy_role
        if capabilities is not None:
            entry["capabilities"] = sorted(capabilities)
        report["findings"].append(entry)
        if report["status"] != "error":
            report["status"] = severity

    policy_role = "candidate" if comparing else None
    policy = baseline = None
    try:
        supplied = Path(policy_path).absolute()
        path = resolved(supplied, strict=True)
        policy = Policy.load(path)
        report["registered_tools"] = len(policy.tools)
        if comparing:
            policy_role = "baseline"
            baseline = Policy.load(baseline_path)
    except UnsupportedPolicyVersion:
        record("POLICY_VERSION_UNSUPPORTED", field="version", policy_role=policy_role)
    except INPUT_ERRORS:
        record("POLICY_INVALID", policy_role=policy_role)
    if policy is None:
        return report
    if baseline is not None:
        for name, spec in sorted(policy.tools.items()):
            old = baseline.tools.get(name)
            if old is None:
                record("POLICY_TOOL_ADDED", name, capabilities=spec.capabilities)
            else:
                added = spec.capabilities - old.capabilities
                if added:
                    record("POLICY_CAPABILITIES_ADDED", name, capabilities=added)
                retained = old.capabilities & spec.capabilities
                file_capabilities = retained & {"read", "write"}
                if file_capabilities and file_roots_expanded(spec.roots, old.roots):
                    record("POLICY_FILE_ROOTS_EXPANDED", name, capabilities=file_capabilities)
                if "network" in retained and not spec.origins.issubset(old.origins):
                    record("POLICY_NETWORK_ORIGINS_EXPANDED", name, capabilities=["network"])
        report["comparison"]["status"] = "compared"
    for name, spec in sorted(policy.tools.items()):
        # 工具既可能覆盖目标文件，也可能替换通向该文件的链接。
        if "write" in spec.capabilities and any(contained(p, root) for root in spec.roots for p in (path, supplied)):
            record("POLICY_WRITABLE", name)
        if "execute" in spec.capabilities:
            for encoded in sorted(spec.allowed_arguments):
                try:
                    policy.validate_arguments(spec, strict_json(encoded))
                except INPUT_ERRORS:
                    record("EXEC_ARGUMENTS_INVALID", name)
                    break
    if catalog_path is not None:
        try:
            catalog = read_catalog(Path(catalog_path))
        except INPUT_ERRORS:
            record("CATALOG_INVALID")
            return report
        report["hidden_tools"] = len(catalog.keys() - policy.tools.keys())
        for name, spec in sorted(policy.tools.items()):
            if name not in catalog:
                record("TOOL_MISSING", name)
                continue
            for issue, field in contract_issues(spec, catalog[name]):
                record(issue, name, field)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path, help="本地策略文件")
    parser.add_argument("--baseline", type=Path, help="已验收的旧策略，用于核对新增工具、能力、读写目录范围和网络目标")
    parser.add_argument("--catalog", type=Path, help="从原始上游采集的完整 tools/list 快照")
    parser.add_argument("--json", action="store_true", help="输出适合 CI 使用的 JSON")
    args = parser.parse_args(argv)
    report = check(args.policy, args.catalog, baseline_path=args.baseline)
    if args.json:
        print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    else:
        print(f"{report['status'].upper()}  检查范围 {report['scope']}，策略登记工具数 {report['registered_tools']}")
        if "comparison" in report:
            if report["comparison"]["status"] == "not_compared":
                print("两份策略未能完成对比。")
            elif any("capabilities" in item for item in report["findings"]):
                print("发现新增授权，详见下方审阅项。")
            else:
                print("在本次对比范围内未发现新增授权。")
            print("对比范围包括工具名、声明能力、读写目录和网络能力允许的目标。参数与状态约束需另行核对。")
        for issue in report["findings"]:
            location = [json.dumps(issue[k], ensure_ascii=True) for k in ("tool", "field") if k in issue]
            if "policy_role" in issue:
                location.insert(0, "基准策略" if issue["policy_role"] == "baseline" else "候选策略")
            if "capabilities" in issue:
                location.append(", ".join(issue["capabilities"]))
            print(" ".join([issue["code"], *location, issue["message"]]))
    return EXIT_CODES[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
