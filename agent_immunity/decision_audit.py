"""将 stdio 工具调用的转发前策略判定写到会话专属的 JSONL 文件。"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
from threading import Lock
import uuid

from .core.policy import Policy


MAX_AUDIT_BYTES = 4 * 1024 * 1024
_DECISIONS = frozenset({
    "ALLOW", "UNKNOWN_TOOL", "INVALID_CALL", "SESSION_CLOSED", "SESSION_BUSY",
    "ARGUMENTS_DENIED", "TRANSITION_DENIED", "SENSITIVE_FLOW",
})


class AuditError(OSError):
    """固定诊断只表示审计器无法工作，可安全返回给代理。"""


def _comparable(path: Path) -> Path:
    # Windows 的 readlink 可能返回扩展长度路径。统一命名空间再用 WindowsPath 比较大小写。
    if os.name == "nt":
        value = str(path)
        prefix = "\\\\?\\"
        if value.upper().startswith(prefix + "UNC\\"):
            return Path("\\\\" + value[len(prefix) + 4:])
        if value.startswith(prefix):
            return Path(value[len(prefix):])
    return path


def _audit_directory(directory, policy: Policy) -> Path:
    if not directory:
        raise AuditError("请提供现有的受信审计目录")
    path = Path(directory).absolute()
    destination = path.resolve(strict=True)
    if not destination.is_dir():
        raise AuditError("请提供现有的受信审计目录")
    roots = {_comparable(root) for spec in policy.tools.values()
             if "write" in spec.capabilities for root in spec.roots}
    # 同时保护链接所在目录和目标目录，包括先进入可写树、再通过另一条链接离开的情况。
    pending, seen = [path], set()
    while pending:
        item = pending.pop()
        for part in (item, *item.parents):
            if part in seen:
                continue
            seen.add(part)
            lexical = _comparable(part)
            actual = _comparable(part.resolve(strict=True))
            if any(lexical.is_relative_to(root) or actual.is_relative_to(root) for root in roots):
                raise AuditError("审计目录路径经过工具可写根目录")
            info = part.lstat()
            reparse = getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            if stat.S_ISLNK(info.st_mode) or reparse:
                pending.append(part.parent / part.readlink())
    return destination


class DecisionAudit:
    def __init__(self, fd: int, session_id: str, indexes: dict[str, int]):
        self._fd = fd
        self._session_id = session_id
        self._indexes = indexes
        self._sequence = 0
        self._bytes = 0
        self._failed = False
        self._lock = Lock()

    @classmethod
    def open(cls, directory, policy: Policy):
        try:
            destination = _audit_directory(directory, policy)
            session_id = uuid.uuid4().hex
            indexes = {name: i for i, name in enumerate(sorted(policy.tools), 1)}
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            fd = os.open(destination / f"{session_id}.jsonl", flags, 0o600)
        except AuditError:
            raise
        except (OSError, ValueError, TypeError, RuntimeError):
            raise AuditError("无法初始化判定审计文件") from None
        return cls(fd, session_id, indexes)

    def record(self, tool_name, code):
        with self._lock:
            if self._fd is None or self._failed:
                raise AuditError("判定审计文件不可用")
            if type(code) is not str or code not in _DECISIONS:
                self._failed = True
                raise AuditError("无法记录未知的策略判定码")
            index = self._indexes.get(tool_name, 0) if type(tool_name) is str else 0
            sequence = self._sequence + 1
            event = {
                "schema_version": 1,
                "utc": datetime.now(timezone.utc).isoformat(),
                "session_id": self._session_id,
                "sequence": sequence,
                "tool_index": index,
                "decision_code": code,
            }
            line = (json.dumps(event, separators=(",", ":")) + "\n").encode("ascii")
            if self._bytes + len(line) > MAX_AUDIT_BYTES:
                self._failed = True
                raise AuditError("判定审计文件达到容量上限")
            try:
                # 无用户态缓冲，每次成功返回前已向操作系统交付整行。
                if os.write(self._fd, line) != len(line):
                    self._failed = True
                    os.ftruncate(self._fd, self._bytes)
                    raise AuditError("无法完整写入判定审计")
            except OSError:
                self._failed = True
                raise AuditError("无法完整写入判定审计") from None
            self._sequence = sequence
            self._bytes += len(line)

    def close(self):
        with self._lock:
            if self._fd is not None:
                fd, self._fd = self._fd, None
                try:
                    os.close(fd)
                except OSError:
                    raise AuditError("无法关闭判定审计文件") from None
