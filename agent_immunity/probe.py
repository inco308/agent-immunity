"""对受信上游执行固定调用并记录返回，用于升级前后的业务验收。

目录比较只看输入描述，看不出输出变化。本工具把同一组调用分别在升级前后各跑
一次，记下原始返回文本、结构化返回和展开后的字段路径，供
`scripts/upgrade_drill.py` 比较。

用法：

    agent-immunity-probe --calls calls.json --output before.json -- <升级前上游命令>

`calls.json` 形如：

    {"version": 1, "calls": [
      {"id": "convert-tokyo", "tool": "convert_time",
       "arguments": {"source_timezone": "UTC", "time": "09:00", "target_timezone": "Asia/Tokyo"}}]}

观测文件可能包含上游返回的真实数据，请按敏感材料保存。
"""
import argparse
import json
import logging
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import sys

from .capture import write_atomic

MAX_CALLS = 64
MAX_TEXT = 262144


class ProbeError(ValueError):
    pass


def load_calls(path):
    """读取调用清单；字段固定，避免把任意配置带进上游。"""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProbeError(f"调用清单无法读取: {Path(path).name}") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ProbeError("调用清单必须是 version=1 的对象")
    calls = data.get("calls")
    if not isinstance(calls, list) or not 1 <= len(calls) <= MAX_CALLS:
        raise ProbeError(f"calls 必须是 1 到 {MAX_CALLS} 项的列表")
    seen = set()
    for index, call in enumerate(calls):
        if not isinstance(call, dict):
            raise ProbeError(f"第 {index + 1} 项必须是对象")
        unknown = set(call) - {"id", "tool", "arguments"}
        if unknown:
            raise ProbeError(f"第 {index + 1} 项含不支持的字段: {', '.join(sorted(unknown))}")
        name, tool = call.get("id"), call.get("tool")
        if not isinstance(name, str) or not name or name in seen:
            raise ProbeError(f"第 {index + 1} 项的 id 必须是非空且唯一的字符串")
        if not isinstance(tool, str) or not tool:
            raise ProbeError(f"调用 {name} 的 tool 必须是非空字符串")
        arguments = call.get("arguments", {})
        if not isinstance(arguments, dict):
            raise ProbeError(f"调用 {name} 的 arguments 必须是对象")
        seen.add(name)
    return calls


def summarize(is_error, texts, structured):
    """把一次调用结果整理成可比较的观测；纯函数，便于离线回归。"""
    text = "\n".join(item for item in texts if isinstance(item, str))[:MAX_TEXT]
    parsed = None
    if text.strip():
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
    return {
        "is_error": is_error,
        "text": text,
        "json": parsed,
        "structured": structured,
        # 纯文本没有字段路径，统一记成单一 text 叶子，便于和 JSON 返回区分。
        "shape": {"text": "string"} if parsed is None else flatten(parsed),
    }


def flatten(value, prefix=""):
    """把 JSON 或文本展开成 {路径: 类型}，路径用点号连接、数组用下标。"""
    shape = {}
    if isinstance(value, dict):
        if prefix:
            shape[prefix] = "object"
        for key, item in value.items():
            shape.update(flatten(item, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(value, list):
        if prefix:
            shape[prefix] = "array"
        for index, item in enumerate(value):
            shape.update(flatten(item, f"{prefix}.{index}" if prefix else str(index)))
    elif isinstance(value, bool):
        shape[prefix] = "boolean"
    elif isinstance(value, (int, float)):
        shape[prefix] = "number"
    elif value is None:
        shape[prefix] = "null"
    else:
        shape[prefix] = "string"
    return shape


def _run(command, cwd, entries, timeout):
    import anyio
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def run_all():
        params = StdioServerParameters(command=command[0], args=command[1:], cwd=cwd)
        observations = []
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                with anyio.fail_after(timeout):
                    await session.initialize()
                for entry in entries:
                    with anyio.fail_after(timeout):
                        result = await session.call_tool(entry["tool"], dict(entry.get("arguments", {})))
                    texts = [getattr(block, "text", "") for block in result.content]
                    structured = getattr(result, "structuredContent", None)
                    observed = summarize(bool(result.isError), texts, structured)
                    observations.append({"id": entry["id"], "tool": entry["tool"],
                                         "arguments": entry.get("arguments", {}), **observed})
        return observations

    return anyio.run(run_all)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--calls", required=True, type=Path, help="固定调用清单")
    parser.add_argument("--output", required=True, type=Path, help="观测结果写入该文件")
    parser.add_argument("--cwd", type=Path, help="受信上游的工作目录，默认为当前目录")
    parser.add_argument("--timeout", type=float, default=60, help="每次握手或调用的时限，单位秒")
    argv = list(sys.argv[1:] if argv is None else argv)
    separator = argv.index("--") if "--" in argv else len(argv)
    args = parser.parse_args(argv[:separator])
    command = argv[separator + 1:]
    if not command or not command[0]:
        parser.error("请在 -- 后指定受信上游命令")

    try:
        entries = load_calls(args.calls)
    except ProbeError as error:
        print(str(error), file=sys.stderr)
        return 2

    try:
        if version("mcp") != "1.30.0":
            raise ImportError
        import anyio  # noqa: F401
    except (ImportError, PackageNotFoundError):
        print("业务验收需要官方 MCP SDK：请执行 python -m pip install 'agent-immunity[interop]'，"
              "或在仓库内执行 python -m pip install --require-hashes -r interop/requirements.lock",
              file=sys.stderr)
        return 2

    previous = logging.root.manager.disable
    try:
        # SDK 的畸形输入诊断可能包含整行原文，这里只输出固定说明。
        logging.disable(logging.CRITICAL)
        observations = _run(command, args.cwd, entries, args.timeout)
    except Exception as error:  # pragma: no cover - 依赖上游具体失败
        reason = "采集超时" if isinstance(error, TimeoutError) else "调用失败，请检查上游协议、启动环境和调用清单"
        print(reason, file=sys.stderr)
        return 1
    finally:
        logging.disable(previous)

    payload = {
        "schema_version": 1,
        "scope": "UPSTREAM_OBSERVATIONS",
        "upstream": {"command": command, "mcp_sdk": version("mcp")},
        "calls": observations,
    }
    write_atomic(args.output, (json.dumps(payload, ensure_ascii=False, indent=1) + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
