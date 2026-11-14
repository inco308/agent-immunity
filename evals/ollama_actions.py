"""将 Ollama 的单个结构化动作转换为现有 MCP 工具参数。"""

from decimal import Decimal, InvalidOperation
import json
import math


MAX_ACTION_BYTES = 262144
MAX_JSON_DEPTH = 32
_FIELDS = {
    "read_document": {"path"},
    "write_report": {"path", "content"},
    "publish_report": {"url", "payload"},
    "admin_action": set(),
}
_REPORT_FIELD = {"write_report": "content", "publish_report": "payload"}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("动作 JSON 含重复键")
        result[key] = value
    return result


def _reject_constant(_text):
    raise ValueError("动作 JSON 含非有限数值")


def _read_float(text):
    # Python 的 JSON 编码器用 repr 输出浮点数。比较输出与输入的十进制值，
    # 允许 0.1 和 1e-3，拒绝溢出、下溢或舍入后会改变原值的数。
    number = float(text)
    if not math.isfinite(number):
        raise ValueError("动作 JSON 数值溢出")
    try:
        unchanged = Decimal(repr(number)) == Decimal(text)
    except InvalidOperation as exc:
        raise ValueError("动作 JSON 数值超出支持范围") from exc
    if not unchanged:
        raise ValueError("动作 JSON 数值无法无损序列化")
    return number


def _check_tree(value, depth=0):
    if isinstance(value, str):
        # 原始 JSON 中转义的孤立代理码点会在解析后出现，不能作为 UTF-8 传入 MCP。
        value.encode("utf-8")
    elif isinstance(value, (dict, list)):
        if depth >= MAX_JSON_DEPTH:
            raise ValueError("动作 JSON 嵌套过深")
        if isinstance(value, dict):
            for key in value:
                key.encode("utf-8")
            children = value.values()
        else:
            children = value
        for child in children:
            _check_tree(child, depth + 1)


def decode_action(raw: str) -> tuple[str, dict[str, str], str]:
    """返回工具名、MCP 字符串参数和最终答复。动作整体限 256 KiB、32 层容器。"""
    if not isinstance(raw, str):
        raise ValueError("动作必须是 JSON 文本")
    if len(raw) > MAX_ACTION_BYTES or len(raw.encode("utf-8")) > MAX_ACTION_BYTES:
        raise ValueError("动作 JSON 超过大小限制")
    try:
        action = json.loads(raw, object_pairs_hook=_unique_object,
                            parse_float=_read_float, parse_constant=_reject_constant)
    except RecursionError as exc:
        raise ValueError("动作 JSON 嵌套过深") from exc
    _check_tree(action)
    if not isinstance(action, dict) or not isinstance(action.get("tool"), str):
        raise ValueError("动作必须包含字符串工具名")
    name = action["tool"]
    if name == "finish":
        if set(action) != {"tool", "final"} or not isinstance(action["final"], str):
            raise ValueError("finish 只接受字符串 final")
        return name, {}, action["final"]
    if name not in _FIELDS or set(action) != {"tool", "arguments"}:
        raise ValueError("未知工具或调用动作字段不匹配")
    arguments = action["arguments"]
    if not isinstance(arguments, dict) or set(arguments) != _FIELDS[name]:
        raise ValueError("工具参数字段不匹配")
    for field, value in arguments.items():
        if isinstance(value, str):
            continue
        if field != _REPORT_FIELD.get(name) or not isinstance(value, dict):
            raise ValueError("参数类型与工具接口不匹配")
        document = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                              separators=(",", ":"))
        if len(document.encode("utf-8")) > MAX_ACTION_BYTES:
            raise ValueError("序列化后的报告超过大小限制")
        arguments[field] = document
    return name, arguments, ""
