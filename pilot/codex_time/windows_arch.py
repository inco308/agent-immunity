"""核对 Windows 系统的原生架构和所选 Codex 程序的 PE 机器类型。"""
import ctypes
import os
from pathlib import Path
import sys


IMAGE_FILE_MACHINE_AMD64 = 0x8664


def _native_machine():
    if sys.platform != "win32":
        raise ValueError("Windows 原生宿主演练需要在 Windows 运行")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    current_process = kernel.GetCurrentProcess
    current_process.argtypes = []
    current_process.restype = ctypes.c_void_p
    query = getattr(kernel, "IsWow64Process2", None)
    if query is None:
        raise ValueError("当前系统无法用 IsWow64Process2 核实原生架构")
    machine_pointer = ctypes.POINTER(ctypes.c_ushort)
    query.argtypes = [ctypes.c_void_p, machine_pointer, machine_pointer]
    query.restype = ctypes.c_int
    process_machine, native_machine = ctypes.c_ushort(), ctypes.c_ushort()
    if not query(current_process(), ctypes.byref(process_machine), ctypes.byref(native_machine)):
        raise ctypes.WinError(ctypes.get_last_error())
    return native_machine.value


def require_windows_x64_executable(executable: Path) -> None:
    if _native_machine() != IMAGE_FILE_MACHINE_AMD64:
        raise ValueError("试点需要原生 x64 Windows 系统")
    with Path(executable).open("rb") as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ValueError("需要选择锁定 npm 包中的 Windows 原生程序")
        # DOS 头最后四个字节指向 PE 签名，其后是 20 字节的 COFF 文件头。
        offset = int.from_bytes(dos[60:64], "little")
        if offset < len(dos):
            raise ValueError("Codex 程序的 PE 头偏移无效")
        stream.seek(offset)
        header = stream.read(24)
        if len(header) != 24 or header[:4] != b"PE\0\0":
            raise ValueError("Codex 程序缺少完整 PE/COFF 文件头")
        if int.from_bytes(header[4:6], "little") != IMAGE_FILE_MACHINE_AMD64:
            raise ValueError("所选 Codex 程序的机器类型必须为 AMD64")
        flags = int.from_bytes(header[22:24], "little")
        if not flags & 0x0002 or flags & 0x2000:
            raise ValueError("需要可执行的 PE 应用程序")
        # PE32+ 在数据目录之前有 112 字节。仅核对头部长度和格式标志。
        optional_size = int.from_bytes(header[20:22], "little")
        if (optional_size < 112 or stream.tell() + optional_size > os.fstat(stream.fileno()).st_size
                or stream.read(2) != b"\x0b\x02"):
            raise ValueError("Codex 程序缺少完整 PE32+ 可选头")
