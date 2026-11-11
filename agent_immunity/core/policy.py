"""受信本地策略；不接受工具描述或模型输出授予权限。"""
import json
import math
import ntpath
import os
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from types import MappingProxyType
from urllib.parse import urlsplit

class PolicyError(ValueError):
    pass

def resolved(path, strict=False):
    try:
        if strict:
            return path.resolve(strict=True)
        # 输出文件可能尚不存在，但已存在的祖先必须能被完整解析。
        # Windows 的非严格解析会吞掉链接环、权限等错误，不能用于安全判定。
        missing = []
        current = path
        while True:
            try:
                current.lstat()
            except FileNotFoundError:
                parent = current.parent
                if parent == current:
                    raise PolicyError("路径不存在可解析的根目录")
                missing.append(current.name)
                current = parent
            else:
                existing = current.resolve(strict=True)
                if missing and not existing.is_dir():
                    raise PolicyError("不存在的路径组件必须位于目录之下")
                return existing.joinpath(*reversed(missing))
    except RuntimeError as exc:
        # Python 3.10–3.12 将符号链接环报告为 RuntimeError。
        raise PolicyError("路径无法安全解析") from exc

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"))

def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("重复的 JSON 键")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("JSON 不允许非有限数值")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)

def string_list(value, name):
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value) or len(set(value)) != len(value):
        raise PolicyError(f"{name} 必须是无重复的非空字符串列表")
    return tuple(value)

def origin(url):
    if not isinstance(url, str) or any(ord(c) < 33 for c in url) or "\\" in url:
        raise PolicyError("无效的 URL")
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("https", "http") or not parts.hostname or parts.username is not None or parts.password is not None:
            raise ValueError()
        host = parts.hostname.encode("idna").decode("ascii").lower()
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
        if port == 0:
            raise ValueError()
        return parts.scheme, host, port
    except (ValueError, UnicodeError) as exc:
        raise PolicyError("仅支持无用户信息的 http/https URL") from exc

def contained(path, root):
    try:
        return os.path.commonpath([str(path), str(root)]) == str(root)
    except ValueError:
        return False

@dataclass(frozen=True)
class ToolPolicy:
    capabilities: frozenset[str]
    parameters: object
    required: tuple[str, ...]
    path_fields: tuple[str, ...]
    roots: tuple[Path, ...]
    url_fields: tuple[str, ...]
    origins: frozenset[tuple]
    allowed_arguments: frozenset[str]
    output_untrusted: bool
    sensitive_fields: tuple[str, ...]
    state: str

    def input_schema(self):
        return {"type": "object", "properties": {key: {"type": value} for key, value in self.parameters.items()}, "required": list(self.required), "additionalProperties": False}

@dataclass(frozen=True)
class Policy:
    workspace: Path
    tools: object
    transitions: object
    max_bytes: int = 262144
    max_secrets: int = 128
    max_events: int = 256

    @classmethod
    def load(cls, path):
        path = resolved(Path(path))
        if path.stat().st_size > 1048576:
            raise PolicyError("策略文件过大")
        return cls.from_dict(strict_json(path.read_text(encoding="utf-8")), path.parent)

    @classmethod
    def from_dict(cls, data, base=None):
        if not isinstance(data, dict) or set(data) - {"version", "workspace", "tools", "transitions", "max_bytes", "max_secrets", "max_events"}:
            raise PolicyError("无效策略字段")
        if type(data.get("version")) is not int or data["version"] != 1:
            raise PolicyError("仅支持 version=1 的策略")
        if not isinstance(data.get("workspace"), str) or not data["workspace"]:
            raise PolicyError("必须指定 workspace")
        workspace = resolved(Path(base or Path.cwd()) / data["workspace"], strict=True)
        if not workspace.is_dir():
            raise PolicyError("workspace 必须是现有目录")
        raw_tools = data.get("tools")
        if not isinstance(raw_tools, dict):
            raise PolicyError("tools 必须是对象")
        tools = {}
        fields = {"capabilities", "parameters", "required", "path_fields", "roots", "url_fields", "origins", "allowed_arguments", "output_untrusted", "sensitive_fields", "state"}
        types = {"string", "integer", "number", "boolean", "object", "array"}
        for name, spec in raw_tools.items():
            if not isinstance(name, str) or not name or not isinstance(spec, dict) or set(spec) - fields:
                raise PolicyError("无效工具定义")
            caps = frozenset(string_list(spec.get("capabilities", []), "capabilities"))
            if not caps or caps - {"read", "write", "network", "execute", "compute"}:
                raise PolicyError("无效的工具能力")
            params = spec.get("parameters", {})
            if not isinstance(params, dict) or any(not isinstance(k, str) or not k or not isinstance(v, str) or v not in types for k, v in params.items()):
                raise PolicyError("parameters 使用受支持的顶层类型")
            required = string_list(spec.get("required", list(params)), "required")
            paths = string_list(spec.get("path_fields", []), "path_fields")
            urls = string_list(spec.get("url_fields", []), "url_fields")
            if not set(required) <= params.keys() or any(params.get(k) != "string" or k not in required for k in paths + urls):
                raise PolicyError("路径和 URL 字段必须是必填字符串")
            roots = tuple(resolved(workspace / p, strict=True) for p in string_list(spec.get("roots", []), "roots"))
            if any(not p.is_dir() or not contained(p, workspace) for p in roots):
                raise PolicyError("roots 必须是 workspace 内的现有目录")
            if caps & {"read", "write"} and (not roots or not paths):
                raise PolicyError("文件读写工具必须限定路径和根目录")
            origins = []
            for item in string_list(spec.get("origins", []), "origins"):
                parts = urlsplit(item)
                if parts.path not in ("", "/") or parts.query or parts.fragment:
                    raise PolicyError("origins 只接受协议、主机及端口")
                origins.append(origin(item))
            if "network" in caps and (not urls or not origins):
                raise PolicyError("网络能力必须指定 URL 字段和允许 origin")
            allowed = spec.get("allowed_arguments", [])
            if not isinstance(allowed, list) or any(not isinstance(x, dict) for x in allowed):
                raise PolicyError("allowed_arguments 必须是参数对象列表")
            if "execute" in caps and not allowed:
                raise PolicyError("执行能力必须有精确参数白名单")
            untrusted = spec.get("output_untrusted", True)
            if type(untrusted) is not bool:
                raise PolicyError("output_untrusted 必须为布尔值")
            state = spec.get("state", name)
            if not isinstance(state, str) or not state or state == "START":
                raise PolicyError("无效工具状态")
            tools[name] = ToolPolicy(caps, MappingProxyType(dict(params)), required, paths, roots, urls, frozenset(origins), frozenset(canonical(x) for x in allowed), untrusted, string_list(spec.get("sensitive_fields", []), "sensitive_fields"), state)
        transitions = data.get("transitions", {})
        states = {"START"} | {spec.state for spec in tools.values()}
        if not isinstance(transitions, dict) or any(k not in states for k in transitions):
            raise PolicyError("无效状态表")
        transitions = {k: frozenset(string_list(v, "transitions")) for k, v in transitions.items()}
        if any(not v <= states for v in transitions.values()):
            raise PolicyError("转移目标未定义")
        limits = {}
        for key, default, upper in [("max_bytes", 262144, 1048576), ("max_secrets", 128, 4096), ("max_events", 256, 4096)]:
            value = data.get(key, default)
            if type(value) is not int or not 1 <= value <= upper:
                raise PolicyError(f"{key} 超出范围")
            limits[key] = value
        return cls(workspace, MappingProxyType(tools), MappingProxyType(transitions), **limits)

    def validate_arguments(self, spec, arguments):
        if not isinstance(arguments, dict) or set(arguments) - spec.parameters.keys() or not set(spec.required) <= arguments.keys():
            raise PolicyError("参数缺失或包含未授权字段")
        checks = {"string": lambda x: isinstance(x, str), "integer": lambda x: type(x) is int, "number": lambda x: type(x) in (int, float) and math.isfinite(x), "boolean": lambda x: type(x) is bool, "object": lambda x: isinstance(x, dict), "array": lambda x: isinstance(x, list)}
        for key, value in arguments.items():
            if not checks[spec.parameters[key]](value):
                raise PolicyError("参数类型错误")
        # 深拷贝与限制一并进行，防止调用方在检查后修改原参数。
        encoded = canonical(arguments)
        if len(encoded.encode("utf-8")) > self.max_bytes:
            raise PolicyError("参数超过大小限制")
        if "execute" in spec.capabilities and encoded not in spec.allowed_arguments:
            raise PolicyError("执行参数不在精确白名单中")
        result = json.loads(encoded)
        for key in spec.path_fields:
            value = result[key]
            drive, tail = ntpath.splitdrive(value)
            if not value or any(ord(c) < 32 for c in value) or ":" in tail or value.startswith(("\\\\", "//")) or (drive and not tail.startswith(("/", "\\"))) or (os.name != "nt" and (drive or "\\" in value)):
                raise PolicyError("不支持的路径格式")
            components = value.replace("\\", "/").split("/")
            if any(PureWindowsPath(part).is_reserved() or (part not in ("", ".") and part.endswith((" ", "."))) for part in components):
                raise PolicyError("不支持设备名称或带尾部空白、句点的路径")
            if ".." in value.replace("\\", "/").split("/"):
                raise PolicyError("禁止路径穿越")
            path = resolved(self.workspace / value)
            if not any(contained(path, root) for root in spec.roots):
                raise PolicyError("路径超出允许根目录")
            result[key] = str(path)
        for key in spec.url_fields:
            if origin(result[key]) not in spec.origins:
                raise PolicyError("网络目标未授权")
        return result
