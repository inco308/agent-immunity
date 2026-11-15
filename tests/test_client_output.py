"""验证输出流的短写、刷新超时和不可用状态。"""
import io
import threading
import unittest

from agent_immunity.client_output import ClientOutput, OutputUnavailable


class OutputStreamTests(unittest.TestCase):
    def test_short_writes_resume_from_the_actual_position(self):
        class ShortStream(io.BytesIO):
            def write(self, block):
                return super().write(block[:3])

        stream = ShortStream()
        output = ClientOutput(stream, 2)
        try:
            for frame in (b"12345678\n", "报告🙂\n".encode()):
                output.send(frame)
            self.assertEqual(stream.getvalue(), "12345678\n报告🙂\n".encode())
        finally:
            output.close()
            output.worker.join(timeout=2)
        self.assertFalse(output.worker.is_alive())
        self.assertFalse(stream.closed)

    def test_blocked_flush_consumes_same_frame_deadline(self):
        release = threading.Event()

        class SlowFlush(io.BytesIO):
            def flush(self):
                if not release.wait(3):
                    raise OSError("测试写入没有释放")

        stream = SlowFlush()
        output = ClientOutput(stream, 0.3)
        try:
            with self.assertRaises(OutputUnavailable):
                output.send(b"first\n")
            with self.assertRaises(OutputUnavailable):
                output.send(b"later\n")
        finally:
            release.set()
            output.close()
            output.worker.join(timeout=2)
        self.assertFalse(output.worker.is_alive())
        self.assertEqual(stream.getvalue(), b"first\n")

    def test_invalid_write_count_and_flush_error_are_terminal(self):
        class FailingStream:
            def __init__(self, count):
                self.count = count

            def write(self, block):
                return len(block) if self.count == "flush" else self.count

            def flush(self):
                raise BrokenPipeError("虚构的私密错误详情")

        for count in (None, 0, -1, 99, "flush"):
            with self.subTest(count=count):
                output = ClientOutput(FailingStream(count), 2)
                try:
                    with self.assertRaises(OutputUnavailable) as raised:
                        output.send(b"x\n")
                    self.assertNotIn("虚构", str(raised.exception))
                    with self.assertRaises(OutputUnavailable):
                        output.send(b"after failure\n")
                finally:
                    output.close()
                    output.worker.join(timeout=2)
                self.assertFalse(output.worker.is_alive())
