"""为 Codex 时间工具轮换试点准备独立 Python 3.12 环境。"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import zipfile


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SCOPE = "CODEX_TIME_PILOT_ENVIRONMENT"
UPSTREAM = {"previous": "2025.8.4", "candidate": "2025.9.25"}
SDK = "1.30.0"


def check_wheel(wheel):
    with (REPO / "pyproject.toml").open("rb") as stream:
        version = tomllib.load(stream)["project"]["version"]
    if wheel.name != f"agent_immunity-{version}-py3-none-any.whl":
        raise ValueError(f"请选择当前仓库 {version} 的通用网关 wheel")
    checksum = hashlib.sha256(wheel.read_bytes()).hexdigest()
    manifest = wheel.with_name("SHA256SUMS")
    if manifest.exists() and f"{checksum}  {wheel.name}" not in manifest.read_text(encoding="ascii").splitlines():
        raise ValueError("网关 wheel 与同目录 SHA256SUMS 不一致")
    # 核对实际运行代码与数据；同版本号的旧 wheel 也可能来自其他提交。
    sources = {
        path.relative_to(REPO).as_posix(): path
        for path in (REPO / "agent_immunity").rglob("*")
        if path.is_file() and path.suffix in (".py", ".json")
    }
    with zipfile.ZipFile(wheel) as archive:
        packaged = {name for name in archive.namelist() if name.startswith("agent_immunity/") and not name.endswith("/")}
        if packaged != sources.keys():
            raise ValueError("网关 wheel 的运行文件清单与当前源码不一致")
        for name, source in sources.items():
            if archive.read(name).replace(b"\r\n", b"\n") != source.read_bytes().replace(b"\r\n", b"\n"):
                raise ValueError(f"网关 wheel 与当前源码不同：{name}")
    return version, checksum


def interpreter(venv):
    # POSIX 的 venv/bin/python 可能是符号链接，不能解引用到系统解释器。
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def run(command, work, env, timeout):
    subprocess.run(
        command, cwd=work, env=env, stdin=subprocess.DEVNULL,
        timeout=timeout, check=True,
    )


INSPECT = """
from importlib import import_module, metadata
import sys
from pathlib import Path
role, expected, sdk, prefix = sys.argv[1:]
gateway = role == 'gateway'
module = import_module('agent_immunity' if gateway else 'mcp_server_time')
installed = metadata.version('agent-immunity' if gateway else 'mcp-server-time')
home = Path(sys.prefix).resolve()
if sys.version_info[:2] != (3, 12) or home != Path(prefix).resolve() or not Path(module.__file__).resolve().is_relative_to(home):
    raise RuntimeError('导入来源或 Python 环境不符合试点配置')
if installed != expected:
    raise RuntimeError(f'安装版本不一致：{installed} / {expected}')
if not gateway:
    import mcp
    if metadata.version('mcp') != sdk or not Path(mcp.__file__).resolve().is_relative_to(home):
        raise RuntimeError('MCP SDK 版本或安装来源不一致')
print(f'{role}: {installed} @ {module.__file__}')
"""


def prepare(root, wheel):
    if sys.version_info[:2] != (3, 12):
        raise ValueError("请使用 Python 3.12 运行环境准备脚本")
    version, digest = check_wheel(wheel)
    root.mkdir(parents=True, exist_ok=True)
    descriptor = root / "environment.json"
    if descriptor.exists():
        old = json.loads(descriptor.read_text(encoding="utf-8"))
        if not isinstance(old, dict) or old.get("scope") != SCOPE:
            raise ValueError("指定目录已有其他用途的 environment.json，请选择独立试点目录")

    # venv 中的可执行入口会记住安装绝对路径，直接在最终位置新建一代。
    generation = Path(tempfile.mkdtemp(prefix="gen-", dir=root))
    work = generation / "work"
    work.mkdir()
    temporary = generation / "tmp"
    temporary.mkdir()
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(("PIP_", "PYTHON")) and k.upper() != "VIRTUAL_ENV"}
    env.update(PIP_CONFIG_FILE=os.devnull, PYTHONUTF8="1", TMP=str(temporary),
               TMPDIR=str(temporary), TEMP=str(temporary))
    pip = ["--disable-pip-version-check", "--no-input", "--cache-dir", str(root / "pip-cache"),
           "--timeout", "30", "--retries", "2"]
    versions = {"gateway": version, **UPSTREAM}
    result = {"schema_version": 1, "scope": SCOPE, "versions": {**versions, "mcp": SDK}, "gateway_wheel_sha256": digest}
    for role, expected in versions.items():
        venv = generation / role
        print(f"准备 {role} {expected}", flush=True)
        run([sys.executable, "-I", "-m", "venv", str(venv)], work, env, timeout=120)
        python = interpreter(venv)
        if role == "gateway":
            install = ["--no-index", str(wheel)]
        else:
            install = ["--index-url", "https://pypi.org/simple", "--only-binary=:all:", "--require-hashes",
                       "-r", str(HERE / (role + ".lock"))]
        run([python, "-I", "-m", "pip", *pip, "install", *install], work, env, timeout=600)
        run([python, "-I", "-m", "pip", *pip, "check"], work, env, timeout=60)
        run([python, "-I", "-X", "utf8", "-c", INSPECT, role, expected, SDK, str(venv)], work, env, timeout=60)
        result[role] = str(python)
    # 所有版本及安装来源核实后才替换描述文件。旧环境的路径仍可用于回滚。
    staged = generation / "environment.json.tmp"
    staged.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    staged.replace(descriptor)
    return descriptor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="独立试点环境及 environment.json 的输出目录")
    parser.add_argument("--wheel", type=Path, required=True, help="由当前仓库源码构建并验收的预览 wheel")
    args = parser.parse_args()
    try:
        print(prepare(args.root.resolve(), args.wheel.resolve()))
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        parser.exit(1, f"环境准备失败：{exc}\n")


if __name__ == "__main__":
    main()
