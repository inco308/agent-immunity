"""最小可用的判定审计：追加写入 JSONL，只记录判定本身。

这条日志回答"某次调用被放行还是被拒绝、以什么诊断码"，用于事后核对；
它**不是**防篡改审计，也不做远程汇聚或签名。

刻意不写入的内容：工具参数、工具返回值、用户目标、策略里的路径与 origin。
写入失败或超过容量上限时按失败关闭处理——由引擎抛给调用方，拒绝后续调用。
"""
import json
import os
from pathlib import Path
import time

RECORD_VERSION = 1
DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_RECORDS = 100000
# 事件类型固定，避免把任意字符串写进日志。
EVENTS = frozenset({"decision", "completion", "abort"})


class AuditError(RuntimeError):
    """审计不可用：调用方必须按失败关闭处理。"""


class AuditLog:
    """追加写入的判定日志。每次写入一行，字段固定。"""

    def __init__(self, path, max_bytes=DEFAULT_MAX_BYTES, max_records=DEFAULT_MAX_RECORDS,
                 clock=time.time):
        if type(max_bytes) is not int or not 1024 <= max_bytes <= 1024 * 1024 * 1024:
            raise ValueError("审计文件上限必须介于 1 KiB 与 1 GiB 之间")
        if type(max_records) is not int or not 1 <= max_records <= 10000000:
            raise ValueError("审计记录上限必须介于 1 与 1000 万之间")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.max_records = max_records
        self._clock = clock
        self._records = 0
        self._bytes = 0
        self._stream = None
        self._closed = False
        try:
            # 启动即打开，避免运行到一半才发现不可写。
            self._stream = self.path.open("a", encoding="utf-8", newline="\n")
            self._bytes = self.path.stat().st_size
            self._records = self._resume_sequence()
        except OSError as exc:
            raise AuditError(f"审计文件无法写入: {self.path.name}") from exc

    def _resume_sequence(self):
        """从已有文件尾部续接 seq；只读最后 4 KiB，不扫描整个日志。"""
        if self._bytes == 0:
            return 0
        try:
            with self.path.open("rb") as stream:
                stream.seek(max(0, self._bytes - 4096))
                tail = stream.read().decode("utf-8", errors="replace")
            last = [line for line in tail.splitlines() if line.strip()][-1]
            sequence = json.loads(last).get("seq")
            return sequence if type(sequence) is int and sequence >= 0 else 0
        except (OSError, ValueError, IndexError):
            return 0

    def write(self, event, tool_name, code, completed):
        """写一条判定。字段白名单之外的任何内容都不会进入日志。"""
        if self._closed:
            raise AuditError("审计已关闭")
        if event not in EVENTS:
            raise ValueError("未知审计事件类型")
        if not isinstance(tool_name, str) or not isinstance(code, str) or type(completed) is not bool:
            raise ValueError("审计字段类型不符")
        if self._records >= self.max_records:
            raise AuditError("审计记录数已达上限")
        record = {
            "v": RECORD_VERSION,
            "seq": self._records + 1,
            "ts": round(self._clock(), 6),
            "event": event,
            "tool": tool_name,
            "code": code,
            "completed": completed,
        }
        line = json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n"
        encoded = len(line.encode("utf-8"))
        if self._bytes + encoded > self.max_bytes:
            raise AuditError("审计文件已达大小上限")
        try:
            self._stream.write(line)
            # 每行 flush 让进程崩溃时尽量少丢；不 fsync，掉电仍可能丢尾部。
            self._stream.flush()
        except (OSError, ValueError) as exc:
            raise AuditError("审计写入失败") from exc
        self._records += 1
        self._bytes += encoded
        return record

    @property
    def records(self):
        return self._records

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._stream is not None:
            try:
                self._stream.close()
            except OSError:
                pass
            self._stream = None
