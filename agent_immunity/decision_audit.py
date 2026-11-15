"""将转发前策略判定与会话终止时的待核对提示写入受信目录。"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import tempfile
from threading import Lock
import uuid

from .core.policy import Policy


MAX_AUDIT_BYTES = 4 * 1024 * 1024
# 固定字段、UUID 和受会话预算限制的十进制序号使两类提示均小于此值。
_NOTE_RESERVE = 256
_UNCONFIRMED_REASONS = frozenset({"upstream_result_unknown", "client_delivery_unconfirmed"})
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


def _publish_note(path: Path, data: bytes):
    """在受信目录内完成写入和关闭，然后独占发布最终文件名。"""
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".unconfirmed-", suffix=".tmp")
    try:
        try:
            if os.write(fd, data) != len(data):
                raise AuditError("无法完整写入待核对提示")
        finally:
            os.close(fd)
        if os.name == "nt":
            # Windows 的 rename 遇到已有目标就会失败。
            os.rename(temporary, path)
        else:
            os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class DecisionAudit:
    def __init__(self, fd: int, session_id: str, indexes: dict[str, int], *, journal: Path | None = None):
        self._fd = fd
        self._journal = journal
        self._session_id = session_id
        self._indexes = indexes
        self._sequence = 0
        self._bytes = 0
        self._stopped = False
        self._last_allow = None
        self._lock = Lock()

    @classmethod
    def open(cls, directory, policy: Policy):
        try:
            destination = _audit_directory(directory, policy)
            session_id = uuid.uuid4().hex
            indexes = {name: i for i, name in enumerate(sorted(policy.tools), 1)}
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            journal = destination / f"{session_id}.jsonl"
            # 即使旧日志已移走，也不能让遗留提示指向新会话。
            if os.path.lexists(journal.with_suffix(".unconfirmed.json")):
                raise AuditError("会话审计文件已存在")
            fd = os.open(journal, flags, 0o600)
        except AuditError:
            raise
        except (OSError, ValueError, TypeError, RuntimeError):
            raise AuditError("无法初始化判定审计文件") from None
        return cls(fd, session_id, indexes, journal=journal)

    def record(self, tool_name, code):
        with self._lock:
            if self._fd is None or self._stopped:
                raise AuditError("判定审计文件不可用")
            if type(code) is not str or code not in _DECISIONS:
                self._stopped = True
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
            reserve = _NOTE_RESERVE if code == "ALLOW" and self._journal is not None else 0
            if self._bytes + len(line) + reserve > MAX_AUDIT_BYTES:
                self._stopped = True
                raise AuditError("判定审计文件达到容量上限")
            try:
                # 无用户态缓冲，每次成功返回前已向操作系统交付整行。
                if os.write(self._fd, line) != len(line):
                    os.ftruncate(self._fd, self._bytes)
                    raise AuditError("无法完整写入判定审计")
            except OSError:
                self._stopped = True
                raise AuditError("无法完整写入判定审计") from None
            self._sequence = sequence
            self._bytes += len(line)
            self._last_allow = sequence if code == "ALLOW" else None
            return sequence

    def record_unconfirmed(self, decision_sequence, reason):
        """为最后一条 ALLOW 判定独占发布一次待核对记录，随后封闭本会话。"""
        with self._lock:
            if self._fd is None or self._stopped or self._journal is None:
                raise AuditError("待核对提示不可用")
            if (type(decision_sequence) is not int or decision_sequence != self._last_allow
                    or type(reason) is not str or reason not in _UNCONFIRMED_REASONS):
                raise AuditError("待核对原因或判定序号无效")
            self._stopped = True
            event = {
                "schema_version": 1,
                "utc": datetime.now(timezone.utc).isoformat(),
                "session_id": self._session_id,
                "decision_sequence": decision_sequence,
                "reason": reason,
            }
            data = (json.dumps(event, separators=(",", ":")) + "\n").encode("ascii")
            if len(data) > _NOTE_RESERVE or self._bytes + len(data) > MAX_AUDIT_BYTES:
                raise AuditError("待核对提示达到容量上限")
            try:
                # 运维移动或替换判定文件后，不能把序号关联到另一份同名日志。
                journal_stat = self._journal.lstat()
                if journal_stat.st_size != self._bytes or not os.path.samestat(journal_stat, os.fstat(self._fd)):
                    raise AuditError("判定日志已变更")
                _publish_note(self._journal.with_suffix(".unconfirmed.json"), data)
            except OSError:
                raise AuditError("无法发布待核对提示") from None

    def close(self):
        with self._lock:
            if self._fd is not None:
                fd, self._fd = self._fd, None
                try:
                    os.close(fd)
                except OSError:
                    raise AuditError("无法关闭判定审计文件") from None
