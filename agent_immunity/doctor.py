"""在启动代理前，离线检查本地策略以及可选的上游 tools/list 快照。"""
import argparse
import json
from pathlib import Path

from .core.policy import Policy, PolicyError, contained, resolved, strict_json


MESSAGES = {
    "POLICY_INVALID": "无法加载策略。请核对 UTF-8 JSON、策略字段、工作区和目录。",
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


def check(policy_path, catalog_path=None):
    report = {
        "schema_version": 1, "scope": "policy" if catalog_path is None else "policy_and_catalog",
        "status": "pass", "registered_tools": 0, "hidden_tools": None, "findings": [],
    }

    def record(code, tool=None, field=None, detail=None):
        severity = "review" if code == "SCHEMA_REVIEW" else "error"
        # detail 来自 PolicyError，只含字段名与策略里写的路径，不含参数实值。
        entry = {"code": code, "severity": severity, "message": detail or MESSAGES[code]}
        if tool is not None:
            entry["tool"] = tool
        if field is not None:
            entry["field"] = field
        report["findings"].append(entry)
        if report["status"] != "error":
            report["status"] = severity

    try:
        supplied = Path(policy_path).absolute()
        path = resolved(supplied, strict=True)
        policy = Policy.load(path)
    except PolicyError as error:
        record("POLICY_INVALID", detail=str(error))
        return report
    except INPUT_ERRORS:
        record("POLICY_INVALID")
        return report
    report["registered_tools"] = len(policy.tools)
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
    parser.add_argument("--catalog", type=Path, help="从原始上游采集的完整 tools/list 快照")
    parser.add_argument("--json", action="store_true", help="输出适合 CI 使用的 JSON")
    args = parser.parse_args(argv)
    report = check(args.policy, args.catalog)
    if args.json:
        print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    else:
        print(f"{report['status'].upper()}  检查范围 {report['scope']}，策略登记工具数 {report['registered_tools']}")
        for issue in report["findings"]:
            location = [json.dumps(issue[k], ensure_ascii=True) for k in ("tool", "field") if k in issue]
            print(" ".join([issue["code"], *location, issue["message"]]))
    return EXIT_CODES[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
