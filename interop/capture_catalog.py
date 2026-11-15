"""用官方 SDK 从受信 stdio 上游采集原始工具接口，供离线策略体检。"""
import argparse
from importlib.metadata import PackageNotFoundError, version
import json
import logging
import math
import os
from pathlib import Path
import sys
import tempfile
import time
from urllib.parse import unquote, urlsplit


PROTOCOL_VERSION = "2025-06-18"
MAX_PAGES = 32
MAX_TOOLS = 512
MAX_BYTES = 1024 * 1024

# 只在已知的 schema 节点移除文档注解。属性名、枚举值和未知约束保留原义。
_ANNOTATIONS = {"$comment", "title", "description", "examples", "default", "readOnly", "writeOnly", "deprecated"}
_SCHEMA_MAPS = {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas", "dependencies"}
_SCHEMA_LISTS = {"prefixItems", "allOf", "anyOf", "oneOf"}
_SCHEMAS = {
    "additionalProperties", "unevaluatedProperties", "propertyNames", "additionalItems",
    "unevaluatedItems", "contains", "not", "if", "then", "else", "contentSchema",
}


class CatalogError(ValueError):
    """错误消息仅描述操作种类，不包含上游文本、参数或工具值。"""


def strip_annotations(schema):
    if not isinstance(schema, dict):
        return schema
    clean = {}
    for key, value in schema.items():
        if key in _ANNOTATIONS:
            continue
        if key in {"$ref", "$dynamicRef", "$recursiveRef"} and isinstance(value, str):
            # 指向注解内部的非常规指针可能依赖将被删除的内容；整次采集保守失败。
            # 含同名业务属性的此类引用也需要人工检查原始 schema。
            fragment = unquote(urlsplit(value).fragment)
            tokens = {s.replace("~1", "/").replace("~0", "~") for s in fragment.split("/")[1:]}
            if tokens & _ANNOTATIONS:
                raise CatalogError("输入 schema 的引用可能依赖文档注解，无法安全精简")
        if key in _SCHEMA_MAPS and isinstance(value, dict):
            clean[key] = {name: strip_annotations(child) for name, child in value.items()}
        elif (key in _SCHEMA_LISTS or key == "items") and isinstance(value, list):
            clean[key] = [strip_annotations(child) for child in value]
        elif key in _SCHEMAS or key == "items":
            clean[key] = strip_annotations(value)
        else:
            clean[key] = value
    return clean


def _entry(tool):
    if not isinstance(tool.name, str) or not tool.name or not isinstance(tool.inputSchema, dict):
        raise CatalogError("上游返回的工具缺少有效名称或输入 schema")
    item = {"name": tool.name, "inputSchema": strip_annotations(tool.inputSchema)}
    return json.dumps(item, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


async def collect_pages(list_page, deadline, max_pages=MAX_PAGES, max_tools=MAX_TOOLS, max_bytes=MAX_BYTES):
    """仅保留完整的目录。输出上限包含包装、分隔符和末尾换行。"""
    prefix, suffix = b'{"tools":[', b']}\n'
    size = len(prefix) + len(suffix)
    entries, names, cursors = [], set(), set()
    cursor = None
    for _ in range(max_pages):
        page = await list_page(cursor)
        for tool in page.tools:
            if tool.name in names:
                raise CatalogError("上游分页目录含重复工具名")
            if len(entries) >= max_tools:
                raise CatalogError("工具数量超过采集上限")
            entry = _entry(tool)
            size += len(entry) + bool(entries)
            if size > max_bytes:
                raise CatalogError("目录快照超过字节上限")
            names.add(tool.name)
            entries.append(entry)
        if time.monotonic() >= deadline:
            raise CatalogError("采集超时")
        cursor = page.nextCursor
        if cursor is None:
            return prefix + b",".join(entries) + suffix
        if not isinstance(cursor, str) or cursor in cursors:
            raise CatalogError("上游游标无效或重复")
        cursors.add(cursor)
    raise CatalogError("目录页数超过采集上限")


async def _capture(command, cwd, timeout):
    import anyio
    from mcp import ClientSession, StdioServerParameters, types
    from mcp.client.stdio import stdio_client

    deadline = time.monotonic() + timeout
    parameters = StdioServerParameters(command=command[0], args=command[1:], cwd=cwd)
    with open(os.devnull, "w", encoding="utf-8") as errlog:
        async with stdio_client(parameters, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as session:
                # 整个握手和所有分页共享同一时限，超时后由外层 SDK 收回直接上游进程。
                with anyio.fail_after(max(0, deadline - time.monotonic())):
                    # 1.30.0 的 initialize() 固定请求 SDK 默认版本，使用公开的类型化接口指定代理版本。
                    request = types.InitializeRequest(params=types.InitializeRequestParams(
                        protocolVersion=PROTOCOL_VERSION,
                        capabilities=types.ClientCapabilities(),
                        clientInfo=types.Implementation(name="agent-immunity-catalog", version="1"),
                    ))
                    result = await session.send_request(types.ClientRequest(request), types.InitializeResult)
                    if result.protocolVersion != PROTOCOL_VERSION:
                        raise CatalogError("上游没有协商到所需的 MCP 2025-06-18")
                    if result.capabilities.tools is None:
                        raise CatalogError("上游没有声明 tools 能力")
                    await session.send_notification(types.ClientNotification(types.InitializedNotification()))

                    async def list_page(cursor):
                        params = types.PaginatedRequestParams(cursor=cursor) if cursor is not None else None
                        return await session.list_tools(params=params)

                    return await collect_pages(list_page, deadline)


def write_atomic(output, data):
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".catalog-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        os.replace(temporary, output)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def _safe_reason(error):
    # AnyIO 可能用异常组携带握手错误，其他异常的文本可能来自上游。
    if isinstance(error, CatalogError):
        return str(error)
    if isinstance(error, TimeoutError):
        return "采集超时"
    for inner in getattr(error, "exceptions", ()):
        reason = _safe_reason(inner)
        if reason:
            return reason
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "用法：--output 快照.json [--timeout 秒] [--cwd 目录] -- 可执行程序 [参数...]。"
        "启动受信上游时，其自身可能执行初始化副作用。输入 schema 可包含敏感常量，请妥善保存快照。"
    ))
    parser.add_argument("--output", type=Path, required=True, help="采集成功后原子替换此文件")
    parser.add_argument("--cwd", type=Path, help="受信上游的工作目录，默认为当前目录")
    parser.add_argument("--timeout", type=float, default=30, help="握手和全部分页的总时限，单位秒")
    argv = list(sys.argv[1:] if argv is None else argv)
    separator = argv.index("--") if "--" in argv else len(argv)
    args = parser.parse_args(argv[:separator])
    command = argv[separator + 1:]
    if not command or not command[0]:
        parser.error("请在 -- 后指定受信上游命令")
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 300:
        parser.error("时限必须大于 0 且不超过 300 秒")
    try:
        if version("mcp") != "1.30.0":
            raise ImportError
        import anyio
    except (ImportError, PackageNotFoundError):
        print("请使用独立互操作环境，并执行 python -m pip install --require-hashes -r interop/requirements.lock", file=sys.stderr)
        return 2

    previous_logging = logging.root.manager.disable
    try:
        # SDK 的畸形输入诊断可能包含整行原文。CLI 仅输出已知的固定失败说明。
        logging.disable(logging.CRITICAL)
        data = anyio.run(_capture, command, args.cwd, args.timeout)
        write_atomic(args.output, data)
    except Exception as exc:
        print(_safe_reason(exc) or "目录采集失败，请检查上游协议、启动环境和输出位置", file=sys.stderr)
        return 1
    finally:
        logging.disable(previous_logging)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
