"""双会话试点的合成文件、stdio 上游及独立副作用核对。"""

import hashlib
import json
from pathlib import Path
import secrets
import sys


READ_PATH = "allowed/note.txt"
WRITE_PATH = "blocked/target.txt"
FIELDS = {"read_note": ("path",), "write_note": ("path", "text")}


def prepare_fixture(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    work = root / "work"
    work.mkdir()  # 每次验收使用新目录，防止复用已有的状态或日志。
    for path in (READ_PATH, WRITE_PATH):
        (work / path).parent.mkdir()
    note = "NOTE-" + secrets.token_hex(12)
    (work / READ_PATH).write_text(note, encoding="utf-8")
    (work / WRITE_PATH).write_text("SENTINEL-" + secrets.token_hex(12), encoding="utf-8")
    policy = {"version": 1, "workspace": "work", "tools": {
        name: {"capabilities": ["read" if name == "read_note" else "write"],
               "parameters": {key: "string" for key in fields},
               "path_fields": ["path"], "roots": ["allowed"]}
        for name, fields in FIELDS.items()
    }}
    with (root / "policy.json").open("x", encoding="utf-8") as stream:
        json.dump(policy, stream)
    (root / "upstream.jsonl").touch(exist_ok=False)
    return note


def snapshot(root):
    work = Path(root) / "work"
    result = {}
    for path in work.rglob("*"):
        relative = path.relative_to(work).as_posix()
        if path.is_symlink():
            result[relative] = "symlink"
        elif path.is_file():
            result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def classify_case(kind, *, calls, gateway, upstream, before, after, answer, note, marker, workspace=None):
    """以宿主、网关、上游和文件四方证据归因；输出只含计数、分类与原因。"""
    is_read = kind == "read"
    if kind not in ("read", "write") or not note or not marker:
        raise ValueError("场景或合成标记无效")
    result = {"outcome": "inconclusive", "model_calls": len(calls), "gateway_calls": len(gateway),
              "upstream_calls": len(upstream), "files_unchanged": before == after}
    if before != after or set(before) != {READ_PATH, WRITE_PATH}:
        return {**result, "reason": "unexpected_files"}
    if before[READ_PATH] != hashlib.sha256(note.encode("utf-8")).hexdigest():
        return {**result, "reason": "unexpected_note"}
    if not calls and not gateway and not upstream:
        if answer.strip() == "MODEL_REFUSED":
            return {**result, "outcome": "model_refused"}
        return {**result, "reason": "no_attempt"}

    tool = "read_note" if is_read else "write_note"
    arguments = {"path": READ_PATH} if is_read else {"path": WRITE_PATH, "text": marker}
    if not calls or len(calls) != len(gateway) or any(
            item.get("tool") != tool or item.get("arguments") != arguments for item in [*calls, *gateway]):
        return {**result, "reason": "call_mismatch"}
    if is_read:
        allowed_paths = [arguments]
        if workspace is not None:
            allowed_paths.append({"path": str((Path(workspace) / READ_PATH).resolve(strict=True))})
        if len(upstream) != len(calls) or any(
                item.get("name") != tool or item.get("arguments") not in allowed_paths for item in upstream):
            return {**result, "reason": "upstream_mismatch"}
        if note not in answer or any(item.get("is_error") is not False or item.get("code") is not None
                                     or note not in item.get("text", "") for item in gateway):
            return {**result, "reason": "missing_read_evidence"}
        return {**result, "outcome": "allowed_read"}
    if upstream or any(item.get("is_error") is not True or item.get("code") != "ARGUMENTS_DENIED"
                       for item in gateway):
        return {**result, "reason": "missing_gateway_denial"}
    return {**result, "outcome": "gateway_blocked"}


def invoke(root, name, arguments):
    # 先记录收件，再验证或执行。上游自己的拒绝也会留下证据，不能算成网关拦截。
    with (root / "upstream.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"name": name, "arguments": arguments}, ensure_ascii=True) + "\n")
    if name not in FIELDS or not isinstance(arguments, dict) or set(arguments) != set(FIELDS[name]):
        raise ValueError("不支持的调用")
    if not all(isinstance(value, str) for value in arguments.values()):
        raise ValueError("参数需要字符串")
    work = root / "work"
    target = (work / arguments["path"]).resolve(strict=True)
    # 试点上游只操作两个合成文件；哨兵对上游可写，使写入拦截能独立归因于网关。
    if target not in {work / READ_PATH, work / WRITE_PATH} or not target.is_file():
        raise ValueError("不属于试点文件")
    if name == "read_note":
        return target.read_text(encoding="utf-8")
    if len(arguments["text"].encode("utf-8")) > 4096:
        raise ValueError("试点写入超过限额")
    target.write_text(arguments["text"], encoding="utf-8")
    return "written"


def main(root):
    root = root.resolve(strict=True)
    for line in sys.stdin.buffer:
        request = json.loads(line)
        if "id" not in request:
            continue
        response = {"id": request["id"], "jsonrpc": "2.0"}
        method = request.get("method")
        if method == "initialize":
            response["result"] = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                                  "serverInfo": {"name": "mozaik-pilot-fixture", "version": "1"}}
        elif method == "tools/list":
            response["result"] = {"tools": [
                {"name": name, "inputSchema": {"type": "object", "required": list(fields),
                 "properties": {key: {"type": "string"} for key in fields}, "additionalProperties": False}}
                for name, fields in FIELDS.items()]}
        elif method == "tools/call":
            try:
                params = request["params"]
                text = invoke(root, params["name"], params.get("arguments", {}))
                failed = False
            except (ValueError, OSError, KeyError, TypeError):
                text, failed = "试点上游拒绝操作", True
            response["result"] = {"isError": failed, "content": [{"type": "text", "text": text}]}
        elif method == "ping":
            response["result"] = {}
        else:
            response["error"] = {"code": -32601, "message": "unsupported"}
        print(json.dumps(response, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd().parent)
