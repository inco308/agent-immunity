"""验收 wheel 和 sdist，在仓库外分别安装，运行入口后生成 SHA256SUMS。"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile


REPO = Path(__file__).resolve().parents[1]
DATA = {"agent_immunity/dataset/cases.json", "agent_immunity/dataset/policy.json"}

# 由每个已安装包的 python -I 在源码树外执行，只输出可公开的环境字段。
INSTALL_PROBE = """
from importlib.metadata import distribution
import json
from pathlib import Path
import platform
import sys
import agent_immunity

prefix = (Path.cwd() / "env").resolve(strict=True)
dist = distribution("agent-immunity")
if sys.prefix == sys.base_prefix or Path(sys.prefix).resolve(strict=True) != prefix:
    raise ValueError("安装检查未使用预期的虚拟环境")
metadata_files = [p for p in dist.files or () if p.name == "METADATA" and p.parent.name.endswith(".dist-info")]
if (len(metadata_files) != 1
        or not Path(dist.locate_file("")).resolve(strict=True).is_relative_to(prefix)
        or not Path(dist.locate_file(metadata_files[0])).resolve(strict=True).is_relative_to(prefix)
        or not Path(agent_immunity.__file__).resolve(strict=True).is_relative_to(prefix)):
    raise ValueError("发行元数据或导入的网关包位于预期环境之外")
if agent_immunity.__version__ != dist.version:
    raise ValueError("已安装的网关模块与发行元数据版本不符")
system = platform.system()
if system == "Darwin":
    os_version = platform.mac_ver()[0]
elif system == "Windows":
    os_version = platform.win32_ver()[1]
else:
    os_version = platform.release()
print(json.dumps({"installed_version": dist.version, "implementation": platform.python_implementation(),
                  "python": platform.python_version(), "system": system, "os_version": os_version,
                  "machine": platform.machine()}))
"""


def verify_members(package, runtime):
    """检查实际归档清单，只允许运行模块、基准数据及各格式需要的打包元数据。"""
    if package.suffix == ".whl":
        name, version, *_tags = package.name.split("-")
        prefix = f"{name}-{version}.dist-info/"
        with zipfile.ZipFile(package) as archive:
            files = set()
            for item in archive.infolist():
                if stat.S_ISLNK(item.external_attr >> 16):
                    raise ValueError(f"wheel 包含符号链接：{item.filename}")
                if not item.is_dir():
                    files.add(item.filename)
        required = runtime | {prefix + tail for tail in ("METADATA", "WHEEL", "RECORD", "entry_points.txt")}
        licenses = {prefix + "licenses/LICENSE", prefix + "LICENSE"}
        if not files & licenses:
            raise ValueError("wheel 缺少 LICENSE")
        allowed = required | licenses | {prefix + "top_level.txt"}
    else:
        prefix = package.name.removesuffix(".tar.gz") + "/"
        with tarfile.open(package, "r:gz") as archive:
            files = set()
            for item in archive:
                if item.isdir():
                    continue
                if not item.isfile() or not item.name.startswith(prefix):
                    raise ValueError(f"sdist 成员类型或根路径异常：{item.name}")
                files.add(item.name[len(prefix):])
        required = runtime | {"README.md", "LICENSE", "pyproject.toml", "PKG-INFO"}
        metadata = {"PKG-INFO", "SOURCES.txt", "dependency_links.txt", "entry_points.txt", "top_level.txt"}
        allowed = required | {"MANIFEST.in", "setup.cfg"} | {"agent_immunity.egg-info/" + part for part in metadata}
    missing, extra = required - files, files - allowed
    if missing or extra:
        raise ValueError(f"{package.name} 归档内容不符：缺少 {sorted(missing)}，多出 {sorted(extra)}")


def smoke_install(package, work, *, expected_sha256=None):
    """两个发行文件使用不同的全新 venv；工作目录不含源码或其他可导入副本。"""
    work.mkdir()
    subprocess.run([sys.executable, "-I", "-m", "venv", "env"], cwd=work, check=True)
    windows = os.name == "nt"
    scripts = work / "env" / ("Scripts" if windows else "bin")
    python = scripts / ("python.exe" if windows else "python")
    env = {k: v for k, v in os.environ.items() if k.upper() not in {"PYTHONPATH", "PYTHONHOME"}}
    env["PYTHONUTF8"] = "1"

    def run(command, **options):
        return subprocess.run(command, cwd=work, env=env, check=True, timeout=180, **options)

    # 由 pip 校验它实际读取的本地归档，包含同名文件在验收期间被替换的情形。
    digest = expected_sha256 if expected_sha256 is not None else hashlib.sha256(package.read_bytes()).hexdigest()
    lock = work / "package.lock"
    lock.write_text(f"{package.resolve().as_uri()} --hash=sha256:{digest}\n", encoding="utf-8")
    run([python, "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir",
         "--no-deps", "--require-hashes", "-r", lock])
    probe = run([python, "-I", "-c", INSTALL_PROBE], stdout=subprocess.PIPE)
    observed = json.loads(probe.stdout)
    run([scripts / ("agent-immunity-check.exe" if windows else "agent-immunity-check"), "--help"])
    run([python, "-I", "-X", "utf8", "-m", "agent_immunity.doctor", "--help"])
    run([python, "-I", "-X", "utf8", "-m", "agent_immunity.benchmark.run_evaluation", "--output", "benchmark.json", "--repeats", "2"])
    # 收到协议响应能同时验证代理入口、策略装载及子进程启动。
    (work / "policy.json").write_text(json.dumps({"version": 1, "workspace": ".", "tools": {}}), encoding="utf-8")
    checked = run([scripts / ("agent-immunity-check.exe" if windows else "agent-immunity-check"),
                   "--policy", "policy.json", "--json"], stdout=subprocess.PIPE)
    if json.loads(checked.stdout)["status"] != "pass":
        raise ValueError(f"{package.name} 安装后的策略体检失败")
    proxy = scripts / ("agent-immunity.exe" if windows else "agent-immunity")
    reply = run([proxy, "--policy", "policy.json", "--", python, "-I", "-c", "import sys; sys.stdin.buffer.read()"],
                input=b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n', stdout=subprocess.PIPE)
    if json.loads(reply.stdout) != {"jsonrpc": "2.0", "id": 1, "result": {}}:
        raise ValueError(f"{package.name} 未返回预期的 ping 响应")
    return {**observed, "policy_check": "pass", "proxy_ping": True}


def write_report(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "scope": "CORE_PACKAGE_INSTALL", "status": "passed", "packages": records}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, mode="w", encoding="utf-8", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        temporary.replace(path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="本次构建产物目录")
    parser.add_argument("--report", type=Path, help="在发行目录外保存两份安装验收的 JSON 记录")
    args = parser.parse_args()
    directory = args.dist.resolve()
    if args.report is not None and (args.report.resolve().is_relative_to(directory)
                                    or args.report.parent.resolve().is_relative_to(directory)):
        parser.error("报告路径必须位于发行文件目录之外")
    wheels = sorted(directory.glob("agent_immunity-*.whl"))
    sources = sorted(directory.glob("agent_immunity-*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        parser.error("目录应包含一个 agent-immunity wheel 和一个 sdist")
    packages = [wheels[0], sources[0]]
    stem = sources[0].name.removesuffix(".tar.gz")
    if not wheels[0].name.startswith(stem + "-"):
        parser.error("两个包的版本不一致")
    sums = directory / "SHA256SUMS"
    if args.report is not None and args.report.resolve() in {path.resolve() for path in (*packages, sums)}:
        parser.error("报告路径不能替换发行文件或校验清单指向的目标")
    if set(directory.iterdir()) - {*packages, sums}:
        parser.error("目录含额外文件，请指定仅含本次发行包的目录")
    runtime = {path.relative_to(REPO).as_posix() for path in (REPO / "agent_immunity").rglob("*.py")} | DATA
    for package in packages:
        verify_members(package, runtime)
    hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in packages}
    expected = "".join(f"{hashes[path]}  {path.name}\n" for path in packages)
    if sums.exists() and sums.read_text(encoding="ascii") != expected:
        raise ValueError("SHA256SUMS 与发行文件不符")
    records = []
    with tempfile.TemporaryDirectory(prefix="agent-immunity-dist-") as tmp:
        outside = Path(tmp).resolve()
        if outside.is_relative_to(REPO):
            raise ValueError("请将系统临时目录设置在源码仓库之外")
        for package, label in zip(packages, ("wheel", "sdist")):
            observed = smoke_install(package, outside / label, expected_sha256=hashes[package])
            if observed["installed_version"] != stem.removeprefix("agent_immunity-"):
                raise ValueError(f"{package.name} 安装后的发行版本与归档名不符")
            records.append({"kind": label, "filename": package.name, "sha256": hashes[package], **observed})
    if any(hashlib.sha256(path.read_bytes()).hexdigest() != hashes[path] for path in packages):
        raise ValueError("发行文件在安装验收期间发生变化")
    sums.write_bytes(expected.encode("ascii"))
    print(expected, end="")
    if args.report is not None:
        write_report(args.report, records)


if __name__ == "__main__":
    main()
