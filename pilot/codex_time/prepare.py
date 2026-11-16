"""为 Codex 时间工具轮换试点准备独立 Python 3.12 环境。"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SCOPE = "CODEX_TIME_PILOT_ENVIRONMENT"
UPSTREAM = {"previous": "2025.8.4", "candidate": "2025.9.25"}
SDK = "1.30.0"

# 兼容原有直接运行 prepare.py 的命令。
if __package__ in (None, ""):
    sys.path.insert(0, str(REPO))
from scripts.fetch_verified_dist import fetch_verified


def check_wheel(wheel):
    # 准备试点环境时要求 3.12；其余版本仍可导入模块或查看帮助。
    import tomllib

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


def fetch_gateway(source, output):
    run_id, commit = source
    receipt = fetch_verified(run_id, commit, output)
    name = f"agent_immunity-{receipt['version']}-py3-none-any.whl"
    return {
        "version": receipt["version"], "wheel": str(output / "verified" / name),
        "wheel_sha256": receipt["files"][name], "run_id": receipt["run_id"],
        "commit": receipt["commit"], "artifact_id": receipt["artifact_id"],
    }


def prepare(root, wheel=None, *, previous_preview=None, candidate_preview=None):
    if sys.version_info[:2] != (3, 12):
        raise ValueError("请使用 Python 3.12 运行环境准备脚本")
    if wheel is None:
        if previous_preview is None or candidate_preview is None:
            raise ValueError("需同时提供初始和候选预览的运行编号与提交")
        if previous_preview[0] == candidate_preview[0] or previous_preview[1] == candidate_preview[1]:
            raise ValueError("两份预览需来自不同的运行和提交")
    else:
        if previous_preview is not None or candidate_preview is not None:
            raise ValueError("请选择本地 wheel 或两份已指定的预览")
        wheel = Path(wheel).resolve()
        version, digest = check_wheel(wheel)
        gateways = {"previous": {"version": version, "wheel": str(wheel), "wheel_sha256": digest}}
    root = Path(root).resolve()
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
    github_credentials = {"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
                          "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"}
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(("PIP_", "PYTHON")) and k.upper() != "VIRTUAL_ENV"
           and k.upper() not in github_credentials}
    env.update(PIP_CONFIG_FILE=os.devnull, PYTHONUTF8="1", TMP=str(temporary),
               TMPDIR=str(temporary), TEMP=str(temporary))
    pip = ["--disable-pip-version-check", "--no-input", "--cache-dir", str(root / "pip-cache"),
           "--timeout", "30", "--retries", "2"]

    def install(directory, role, expected, requirements):
        venv = generation / directory
        print(f"准备 {directory} {expected}", flush=True)
        run([sys.executable, "-I", "-m", "venv", str(venv)], work, env, timeout=120)
        python = interpreter(venv)
        run([python, "-I", "-m", "pip", *pip, "install", *requirements], work, env, timeout=600)
        run([python, "-I", "-m", "pip", *pip, "check"], work, env, timeout=60)
        run([python, "-I", "-X", "utf8", "-c", INSPECT, role, expected, SDK, str(venv)], work, env, timeout=60)
        return str(python)

    if wheel is None:
        gateways = {slot: fetch_gateway(source, generation / f"preview-{slot}")
                    for slot, source in (("previous", previous_preview), ("candidate", candidate_preview))}
        if gateways["previous"]["wheel_sha256"] == gateways["candidate"]["wheel_sha256"]:
            raise ValueError("两个提交提供了相同的网关 wheel，无法区分安装与回退")

    for slot, gateway in gateways.items():
        directory = f"gateway-{slot}" if wheel is None else "gateway"
        # 将收据中的摘要交给 pip，核验安装动作实际读取的 wheel 字节。
        lock = generation / f"{directory}.lock"
        lock.write_text(f"{Path(gateway['wheel']).as_uri()} --hash=sha256:{gateway['wheel_sha256']}\n", encoding="utf-8")
        requirements = ["--no-index", "--no-deps", "--require-hashes", "-r", str(lock)]
        python = install(directory, "gateway", gateway["version"], requirements)
        run([python, "-I", "-X", "utf8", str(HERE / "wheel_identity.py"), "--wheel", gateway["wheel"],
             "--sha256", gateway["wheel_sha256"], "--version", gateway["version"]], work, env, timeout=60)
        gateway["python"] = python

    original = gateways["previous"]
    result = {"schema_version": 2 if wheel is None else 1, "scope": SCOPE, "gateway": original["python"],
              "versions": {"gateway": original["version"], **UPSTREAM, "mcp": SDK},
              "gateway_wheel_sha256": original["wheel_sha256"]}
    if wheel is None:
        result["gateway_slots"] = gateways
    for slot, version in UPSTREAM.items():
        requirements = ["--index-url", "https://pypi.org/simple", "--only-binary=:all:", "--require-hashes",
                        "-r", str(HERE / (slot + ".lock"))]
        result[slot] = install(slot, slot, version, requirements)
    # 所有版本及安装来源核实后才替换描述文件。旧环境的路径仍可用于回滚。
    staged = generation / "environment.json.tmp"
    staged.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    staged.replace(descriptor)
    return descriptor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="独立试点环境及 environment.json 的输出目录")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--wheel", type=Path, help="由当前仓库源码构建并验收的预览 wheel")
    source.add_argument("--previous-preview", nargs=2, metavar=("RUN_ID", "COMMIT"), help="初始网关的 main 构建")
    parser.add_argument("--candidate-preview", nargs=2, metavar=("RUN_ID", "COMMIT"), help="候选网关的 main 构建")
    args = parser.parse_args()
    if bool(args.previous_preview) != bool(args.candidate_preview):
        parser.error("--previous-preview 和 --candidate-preview 必须成对提供，且不可与 --wheel 同用")
    try:
        if args.wheel is not None:
            print(prepare(args.root, args.wheel))
        else:
            previous_id, previous_sha = args.previous_preview
            candidate_id, candidate_sha = args.candidate_preview
            print(prepare(args.root, previous_preview=(int(previous_id), previous_sha),
                          candidate_preview=(int(candidate_id), candidate_sha)))
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        parser.exit(1, f"环境准备失败：{exc}\n")


if __name__ == "__main__":
    main()
