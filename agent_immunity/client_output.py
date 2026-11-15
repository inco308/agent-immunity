"""在 CLI 会话内顺序写出响应，按整帧限制事件循环的等待时间。"""
import os
import queue
import sys
import threading
import time


class OutputUnavailable(Exception):
    """客户端输出通道已经失效。"""


class ClientOutput:
    def __init__(self, stream, timeout):
        self.timeout = timeout
        self.frames = queue.Queue(maxsize=1)
        self.completions = queue.Queue(maxsize=1)
        self.stopping = threading.Event()
        self.owned = stream is None
        if self.owned:
            # 写线程独占无缓冲的副本，解释器退出时不争用 sys.stdout 的缓冲锁。
            fd = os.dup(sys.stdout.fileno())
            try:
                os.set_inheritable(fd, False)
                stream = os.fdopen(fd, "wb", buffering=0)
            except BaseException:
                os.close(fd)
                raise
        self.stream = stream
        self.worker = threading.Thread(target=self._run, daemon=True)
        try:
            self.worker.start()
        except BaseException:
            if self.owned:
                stream.close()
            raise

    def _write_frame(self, frame):
        remaining = memoryview(frame)
        while remaining and not self.stopping.is_set():
            written = self.stream.write(remaining)
            if type(written) is not int or not 0 < written <= len(remaining):
                raise OSError("无效的写入长度")
            remaining = remaining[written:]
        if not self.stopping.is_set():
            self.stream.flush()

    def _run(self):
        try:
            while True:
                frame = self.frames.get()
                if frame is None or self.stopping.is_set():
                    return
                self._write_frame(frame)
                del frame
                self.completions.put_nowait(time.monotonic())
        except Exception:
            # 仅向事件循环传递失败信号，避免保留可能包含数据的异常或堆栈。
            self.completions.put_nowait(None)
        finally:
            if self.owned:
                self.stream.close()

    def send(self, frame):
        # 唯一生产者是代理事件循环，在上一帧完成之前不会接收下一帧。
        if self.stopping.is_set():
            raise OutputUnavailable()
        deadline = time.monotonic() + self.timeout
        self.frames.put_nowait(frame)
        try:
            finished = self.completions.get(timeout=max(0.0, deadline - time.monotonic()))
        except queue.Empty:
            finished = None
        if finished is None or finished > deadline:
            self.close()
            raise OutputUnavailable()

    def close(self):
        # 操作系统可能仍在写上一帧。主线程不关闭正在写入的 fd，也不等待它解阻。
        self.stopping.set()
        try:
            self.frames.put_nowait(None)
        except queue.Full:
            pass  # 队列中的帧会唤醒线程，由 stopping 阻止后续写入。
