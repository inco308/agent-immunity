"""校验已核实外层摘要的预览 ZIP，在调用方独占的空暂存目录中准备三份文件。"""

from copy import copy
import hashlib
import io
from pathlib import Path
import re
import stat
import tempfile
import zipfile
import zlib


MEMBER_LIMIT = 16 * 1024 * 1024
TOTAL_LIMIT = 32 * 1024 * 1024
CHUNK = 64 * 1024
MANIFEST = "SHA256SUMS"
VERSION = r"(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:\.[a-z0-9]+)*)?"
WHEEL = re.compile(rf"agent_immunity-(?P<version>{VERSION})-py3-none-any\.whl")


def _layout(infos):
    if len(infos) != 3:
        raise ValueError("预览 ZIP 必须恰含三个文件")
    entries = {}
    wheels = []
    for info in infos:
        name = info.filename
        # ZipInfo 可能截掉 NUL 后缀，或在 Windows 将反斜杠规范化。
        if name != info.orig_filename or not name.isascii() or len(name) > 255 or name in entries:
            raise ValueError("预览 ZIP 的成员名异常或重复")
        mode = stat.S_IFMT(info.external_attr >> 16)
        # 同时检查 Unix 节点类型及 DOS/Windows 卷标、目录、设备、重解析点标志。
        if info.is_dir() or mode not in (0, stat.S_IFREG) or info.external_attr & 0x458:
            raise ValueError("预览 ZIP 含特殊文件")
        if info.flag_bits & (0x1 | 0x40 | 0x2000):
            raise ValueError("预览 ZIP 含加密成员")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise ValueError("预览 ZIP 使用不支持的压缩方式")
        if info.file_size > MEMBER_LIMIT or (info.compress_type == zipfile.ZIP_STORED and info.compress_size != info.file_size):
            raise ValueError("预览 ZIP 的成员大小异常")
        entries[name] = info
        match = WHEEL.fullmatch(name)
        if match:
            wheels.append((name, match["version"]))
    if len(wheels) != 1:
        raise ValueError("需要一个符合预览命名约定的 wheel")
    wheel, version = wheels[0]
    source = f"agent_immunity-{version}.tar.gz"
    if set(entries) != {MANIFEST, wheel, source}:
        raise ValueError("预览 ZIP 仅允许根目录下的同版本 wheel、sdist 和 SHA256SUMS")
    if sum(info.file_size for info in infos) > TOTAL_LIMIT:
        raise ValueError("预览 ZIP 的未压缩总大小超限")
    return entries, version, (wheel, source)


def _stream(archive, info, target, remaining):
    # 多读取一个探测字节，以识别 ZipExtFile 按虚假 file_size 截断的压缩数据。
    probe = copy(info)
    probe.file_size += 1
    limit = min(MEMBER_LIMIT, remaining, info.file_size)
    digest = hashlib.sha256()
    written = 0
    with archive.open(probe) as source:
        while chunk := source.read(min(CHUNK, limit - written + 1)):
            written += len(chunk)
            if written > limit:
                raise ValueError("实际解压大小超出声明或预算")
            digest.update(chunk)
            target.write(chunk)
    if written != info.file_size:
        raise ValueError("ZIP 声明大小与实际解压大小不一致")
    return digest.hexdigest(), written


def _checksums(data, names):
    # 只接受 LF/CRLF，末行可带一个换行符。整行匹配，避免接受尾随字段或路径。
    lines = data.replace(b"\r\n", b"\n").removesuffix(b"\n").split(b"\n")
    if len(lines) != 2:
        raise ValueError("SHA256SUMS 必须恰含两行")
    hashes = {}
    for line in lines:
        match = re.fullmatch(rb"([a-fA-F0-9]{64})  ([\x21-\x7e]+)", line)
        if not match:
            raise ValueError("SHA256SUMS 行格式错误")
        name = match[2].decode("ascii")
        if name not in names or name in hashes:
            raise ValueError("SHA256SUMS 包名重复或错误")
        hashes[name] = match[1].decode("ascii").lower()
    return hashes


def verify_archive(archive: Path, staging: Path) -> dict:
    """成功返回版本和两个包的实测 SHA-256，调用方负责后续发布及失败清理。"""
    target = Path(staging)
    attributes = target.lstat()
    if (not stat.S_ISDIR(attributes.st_mode) or getattr(attributes, "st_file_attributes", 0) & 0x400
            or any(target.iterdir())):
        raise ValueError("校验需要调用方独占的新空暂存目录")
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries, version, names = _layout(bundle.infolist())
            # 合法清单最多包含两行摘要、两个文件名、分隔符和两个 CRLF。
            manifest_max = sum(64 + 2 + len(name) + 2 for name in names)
            if entries[MANIFEST].file_size > manifest_max:
                raise ValueError("SHA256SUMS 超过合法清单的长度")
            manifest = io.BytesIO()
            _, total = _stream(bundle, entries[MANIFEST], manifest, manifest_max)
            data = manifest.getvalue()
            expected = _checksums(data, names)
            verified = {}
            with tempfile.TemporaryDirectory(dir=target, prefix=".verify-") as work:
                scratch = Path(work)
                for name in names:
                    with (scratch / name).open("xb") as output:
                        actual, size = _stream(bundle, entries[name], output, TOTAL_LIMIT - total)
                    total += size
                    if expected[name] != actual:
                        raise ValueError("预览包的内容与 SHA256SUMS 不一致")
                    verified[name] = actual
                (scratch / MANIFEST).write_bytes(data)
                # 所有内容验证通过后才在暂存区给出正式文件名。
                for name in (*names, MANIFEST):
                    (scratch / name).rename(target / name)
    except (zipfile.BadZipFile, NotImplementedError, EOFError, zlib.error) as exc:
        raise ValueError("预览 ZIP 损坏或不受支持") from exc
    return {"version": version, "files": verified}
