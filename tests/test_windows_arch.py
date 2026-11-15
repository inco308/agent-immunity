"""以不可执行的合成文件头检查试点宿主的架构判定。"""
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from pilot.codex_time import windows_arch
from tests.support import temporary_directory


def image_headers(machine=0x8664, flags=0x0022):
    # 只构造本次判定读取的头部，不含程序段或代码。
    dos = bytearray(64)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 60, len(dos))
    optional = b"\x0b\x02" + bytes(110)
    coff = struct.pack("<HHIIIHH", machine, 0, 0, 0, 0, len(optional), flags)
    return bytes(dos) + b"PE\0\0" + coff + optional


class WindowsArchitectureTests(unittest.TestCase):
    def setUp(self):
        root = temporary_directory()
        self.addCleanup(root.cleanup)
        self.executable = Path(root.name) / "host.exe"

    def test_reads_only_selected_native_image_on_an_x64_system(self):
        self.executable.write_bytes(image_headers())
        with patch.object(windows_arch, "_native_machine", return_value=0x8664):
            windows_arch.require_windows_x64_executable(self.executable)
        with patch.object(windows_arch, "_native_machine", return_value=0xaa64), self.assertRaises(ValueError):
            windows_arch.require_windows_x64_executable(self.executable)

    def test_other_machine_types_and_dll_are_rejected(self):
        for data in (image_headers(0x014c), image_headers(0xaa64), image_headers(flags=0x2022)):
            self.executable.write_bytes(data)
            with self.subTest(header=data[68:88]), patch.object(windows_arch, "_native_machine", return_value=0x8664), \
                    self.assertRaises(ValueError):
                windows_arch.require_windows_x64_executable(self.executable)

    def test_script_bad_offset_signature_and_truncation_are_rejected(self):
        complete = image_headers()
        cases = {
            "script": b"#!/usr/bin/env node" + bytes(64), "short_dos": complete[:63],
            "offset_inside_dos": complete[:60] + bytes(4) + complete[64:],
            "missing_signature": complete[:64] + b"NOPE" + complete[68:],
            "short_coff": complete[:87], "short_optional": complete[:-1],
            "pe32": complete[:88] + b"\x0b\x01" + complete[90:],
        }
        with patch.object(windows_arch, "_native_machine", return_value=0x8664):
            for label, data in cases.items():
                self.executable.write_bytes(data)
                with self.subTest(case=label), self.assertRaises(ValueError):
                    windows_arch.require_windows_x64_executable(self.executable)

    def test_non_windows_cannot_publish_native_windows_evidence(self):
        with patch.object(windows_arch.sys, "platform", "linux"), self.assertRaises(ValueError):
            windows_arch.require_windows_x64_executable(self.executable)
