"""工具调用、来源标记和决策的数据结构。"""
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class ToolCall:
    call_id: str
    tool_name: str
    arguments: dict[str, Any]

@dataclass(frozen=True)
class TaintTag:
    source_tool: str
    untrusted: bool = False
    sensitive: bool = False

@dataclass
class ToolResult:
    output: Any
    is_error: bool = False
    taint_tag: TaintTag | None = None

@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str
    reason: str
    arguments: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class AuditEvent:
    tool_name: str
    code: str
    completed: bool
