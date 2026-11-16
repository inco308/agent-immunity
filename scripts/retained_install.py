"""在独立的离线虚拟环境中安装留存 wheel，核对运行文件并启动实际入口。"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from .check_dist import REPO, probe_entry_points


def check_retained_wheel(wheel_path, work, expected):
    work = Path(work).resolve(strict=True)
    wheel = Path(wheel_path).resolve(strict=True)
    if any(work.iterdir()):
        raise ValueError("安装验收需要新建的空目录")
    if (wheel.name != f"agent_immunity-{expected['version']}-py3-none-any.whl"
            or hashlib.sha256(wheel.read_bytes()).hexdigest() != expected["wheel_sha256"]):
        raise ValueError("待安装 wheel 与构建收据不符")

    env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT") if key in os.environ}
    env.update(HOME=str(work), USERPROFILE=str(work), TMPDIR=str(work), TMP=str(work), TEMP=str(work),
               PATH=str(Path(sys.executable).parent), PYTHONUTF8="1", PIP_CONFIG_FILE=os.devnull)

    def run(command):
        try:
            return subprocess.run(command, cwd=work, env=env, check=True, capture_output=True, timeout=180).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError("离线安装或构建身份检查失败") from exc

    run([sys.executable, "-I", "-m", "venv", "env"])
    windows = os.name == "nt"
    scripts = work / "env" / ("Scripts" if windows else "bin")
    python = scripts / ("python.exe" if windows else "python")
    requirements = work / "selected.lock"
    requirements.write_text(f"{wheel.as_uri()} --hash=sha256:{expected['wheel_sha256']}\n", encoding="ascii")
    run([python, "-I", "-m", "pip", "--isolated", "--disable-pip-version-check", "install",
         "--no-index", "--no-deps", "--no-cache-dir", "--only-binary=:all:", "--require-hashes", "-r", requirements])

    verifier = REPO / "pilot" / "codex_time" / "wheel_identity.py"
    identity = json.loads(run([python, "-I", "-X", "utf8", verifier, "--wheel", wheel,
                               "--sha256", expected["wheel_sha256"], "--version", expected["version"]]))
    for key in ("version", "wheel_sha256", "metadata_sha256", "runtime_files"):
        if key not in identity or type(identity[key]) is not type(expected[key]) or identity[key] != expected[key]:
            raise ValueError("已安装的构建身份与留存收据不符")
    try:
        smoke = probe_entry_points(scripts, python, work, env)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("离线安装后的入口验收失败") from exc
    return {**identity, **smoke}
