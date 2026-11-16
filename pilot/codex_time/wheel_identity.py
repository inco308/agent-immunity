"""在宿主选定的网关虚拟环境中，将安装来源、元数据和运行文件与受信 wheel 比对。"""

import argparse
import hashlib
from importlib import metadata, util
import io
import json
from pathlib import Path
import re
import stat
import sys
import sysconfig
from urllib.parse import unquote, urlsplit
import zipfile


def regular_mode(path):
    """拒绝符号链接和 Windows 重解析点，再由调用方核对节点类型。"""
    attrs = path.lstat()
    if stat.S_ISLNK(attrs.st_mode) or getattr(attrs, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("核验路径中出现链接")
    return attrs.st_mode


def installed_files(package):
    if not stat.S_ISDIR(regular_mode(package)):
        raise ValueError("安装的网关包目录无效")
    files = {}
    directories = [package]
    while directories:
        directory = directories.pop()
        for entry in directory.iterdir():
            mode = regular_mode(entry)
            if directory.name == "__pycache__" and stat.S_ISREG(mode) and entry.suffix == ".pyc":
                continue
            if stat.S_ISDIR(mode):
                directories.append(entry)
            elif stat.S_ISREG(mode):
                files[entry.relative_to(package.parent).as_posix()] = entry
            else:
                raise ValueError("安装目录含特殊文件")
    return files


def check_install_origin(origin, wheel, digest):
    record = json.loads(origin.read_bytes())
    if not isinstance(record, dict) or not isinstance(record.get("url"), str):
        raise ValueError("pip 安装来源记录无效")
    url = urlsplit(record["url"])
    if (url.scheme != "file" or url.netloc not in ("", "localhost") or url.query or url.fragment
            or unquote(url.path).rsplit("/", 1)[-1] != wheel.name):
        raise ValueError("pip 安装来源必须为所选名称的本地 wheel")
    archive = record.get("archive_info")
    if not isinstance(archive, dict):
        raise ValueError("pip 安装记录缺少归档摘要")
    hashes = archive.get("hashes", {})
    legacy = archive.get("hash")
    if (not isinstance(hashes, dict) or hashes.get("sha256", digest) != digest
            or (legacy is not None and legacy != "sha256=" + digest)
            or ("sha256" not in hashes and legacy is None)):
        raise ValueError("pip 安装记录中的 SHA-256 与可信 wheel 不符")


def verify(wheel, expected_sha, version):
    if sys.prefix == sys.base_prefix or not sys.flags.isolated:
        raise ValueError("请使用网关虚拟环境的 python -I 执行核验")
    if wheel.name != f"agent_immunity-{version}-py3-none-any.whl" or not re.fullmatch("[0-9a-f]{64}", expected_sha):
        raise ValueError("所选 wheel 名称、版本或预期摘要无效")
    data = wheel.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha:
        raise ValueError("wheel 字节与预期 SHA-256 不符")

    site = Path(sysconfig.get_path("purelib")).resolve(strict=True)
    if not site.is_relative_to(Path(sys.prefix).resolve(strict=True)):
        raise ValueError("安装目录位于当前虚拟环境之外")
    package = site / "agent_immunity"
    files = installed_files(package)
    spec = util.find_spec("agent_immunity")
    if (spec is None or not spec.origin or Path(spec.origin).resolve() != package / "__init__.py"
            or [Path(p).resolve() for p in spec.submodule_search_locations or ()] != [package]):
        raise ValueError("实际模块查找路径与被核验的包不同")

    info = site / f"agent_immunity-{version}.dist-info"
    meta = info / "METADATA"
    origin = info / "direct_url.json"
    if not stat.S_ISDIR(regular_mode(info)) or not all(stat.S_ISREG(regular_mode(p)) for p in (meta, origin)):
        raise ValueError("发行元数据或 pip 安装来源记录无效")
    distributions = list(metadata.distributions(name="agent-immunity"))
    if len(distributions) != 1:
        raise ValueError("网关虚拟环境中必须恰有一份可见的发行元数据")
    dist = distributions[0]
    if Path(dist.locate_file("")).resolve() != site or dist.version != version:
        raise ValueError("安装的发行版本或元数据来源不符")
    check_install_origin(origin, wheel, digest)

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        records = [i.filename for i in archive.infolist() if not i.is_dir()]
        names = {name for name in records if name.startswith("agent_immunity/")}
        if (len(records) != len(set(records)) or "agent_immunity/__init__.py" not in names
                or names != files.keys()):
            raise ValueError("wheel 与安装的运行文件清单不一致")
        for name, path in files.items():
            expected = archive.read(name)
            with path.open("rb") as source:
                if expected != source.read(len(expected) + 1):
                    raise ValueError(f"安装文件与 wheel 的字节不符：{name}")
        meta_name = f"{info.name}/METADATA"
        installed = meta.read_bytes()
        if meta_name not in records or archive.read(meta_name) != installed:
            raise ValueError("已安装的 METADATA 与所选构建不符")
    return {"wheel_sha256": digest, "version": version, "runtime_files": len(files),
            "metadata_sha256": hashlib.sha256(installed).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        result = verify(args.wheel, args.sha256, args.version)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"安装身份核验失败：{exc}\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
