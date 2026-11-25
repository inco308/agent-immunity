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
        # requires.txt 只在声明了可选依赖（extras）时出现，属于正常元数据。
        metadata = {"PKG-INFO", "SOURCES.txt", "dependency_links.txt", "entry_points.txt",
                    "top_level.txt", "requires.txt"}
        allowed = required | {"MANIFEST.in", "setup.cfg"} | {"agent_immunity.egg-info/" + part for part in metadata}
    missing, extra = required - files, files - allowed
    if missing or extra:
        raise ValueError(f"{package.name} 归档内容不符：缺少 {sorted(missing)}，多出 {sorted(extra)}")


def smoke_install(package, work):
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

    run([python, "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir", "--no-deps", package])
    run([python, "-I", "-c", "import sys, agent_immunity; from pathlib import Path; "
         "assert Path(agent_immunity.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())"])
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="本次构建产物目录")
    directory = parser.parse_args().dist.resolve()
    wheels = sorted(directory.glob("agent_immunity-*.whl"))
    sources = sorted(directory.glob("agent_immunity-*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        parser.error("目录应包含一个 agent-immunity wheel 和一个 sdist")
    packages = [wheels[0], sources[0]]
    stem = sources[0].name.removesuffix(".tar.gz")
    if not wheels[0].name.startswith(stem + "-"):
        parser.error("两个包的版本不一致")
    sums = directory / "SHA256SUMS"
    if set(directory.iterdir()) - {*packages, sums}:
        parser.error("目录含额外文件，请指定仅含本次发行包的目录")
    runtime = {path.relative_to(REPO).as_posix() for path in (REPO / "agent_immunity").rglob("*.py")} | DATA
    for package in packages:
        verify_members(package, runtime)
    expected = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in packages)
    if sums.exists() and sums.read_text(encoding="ascii") != expected:
        raise ValueError("SHA256SUMS 与发行文件不符")
    with tempfile.TemporaryDirectory(prefix="agent-immunity-dist-") as tmp:
        outside = Path(tmp).resolve()
        if outside.is_relative_to(REPO):
            raise ValueError("请将系统临时目录设置在源码仓库之外")
        for package, label in zip(packages, ("wheel", "sdist")):
            smoke_install(package, outside / label)
    sums.write_bytes(expected.encode("ascii"))
    print(expected, end="")


if __name__ == "__main__":
    main()
