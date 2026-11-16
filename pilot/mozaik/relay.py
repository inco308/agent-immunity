"""固定 Mozaik 源码并在回环地址启动一次性的内存网络。"""
import argparse
import http.client
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


NETWORK_SHA = "026da49c6fb160307170714574213352f1d6f5eb"
ADAPTER_SHA = "c43b4b3fef6b2f2e6cf37a324366475c3d1a6620"
REVISIONS = {"mozaik-network": NETWORK_SHA, "mozaik-codex": ADAPTER_SHA}

# 使用官方服务实现，指定回环监听和系统分配的空闲端口。
START = """
const fs = require('node:fs');
const { initNetworkModule } = require('./src/network-module.ts');
const { createApp } = require('./src/app.ts');
initNetworkModule();
const server = createApp().listen(0, '127.0.0.1', () => {
  fs.writeFileSync(process.argv[1], String(server.address().port));
});
"""


@dataclass(frozen=True)
class Network:
    origin: str
    invite: str = field(repr=False)
    adapter: Path


def check_checkout(repo, sha):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    if head != sha:
        raise ValueError(f"{repo.name} 版本与固定提交不符")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=repo, check=True)


def prepare(deps_dir):
    deps_dir = Path(deps_dir).resolve()
    deps_dir.mkdir(parents=True, exist_ok=True)
    for name, sha in REVISIONS.items():
        repo = deps_dir / name
        if not repo.exists():
            # 下载中断时，下一次准备仍从完整的固定提交开始。
            with tempfile.TemporaryDirectory(dir=deps_dir) as temporary:
                staging = Path(temporary) / name
                subprocess.run(["git", "init", "-q", str(staging)], check=True)
                subprocess.run(["git", "fetch", "--depth", "1", f"https://github.com/jigjoy-ai/{name}.git", sha],
                               cwd=staging, check=True)
                subprocess.run(["git", "checkout", "-q", "--detach", sha], cwd=staging, check=True)
                staging.rename(repo)
        check_checkout(repo, sha)
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if not npm:
        raise RuntimeError("需要 Node.js 22 或以上版本及 npm")
    subprocess.run([npm, "ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"],
                   cwd=deps_dir / "mozaik-network", check=True)


def post(port, path, data):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("POST", path, json.dumps(data), {"Content-Type": "application/json"})
        response = conn.getresponse()
        if response.status != 201:
            raise RuntimeError(f"本地网络创建失败：HTTP {response.status}")
        return json.load(response)
    finally:
        conn.close()


@contextmanager
def local_network(deps_dir, run_dir):
    deps_dir, run_dir = Path(deps_dir).resolve(), Path(run_dir).resolve()
    for name, sha in REVISIONS.items():
        check_checkout(deps_dir / name, sha)
    adapter = deps_dir / "mozaik-codex" / "dist" / "server.cjs"
    node = shutil.which("node")
    if not node or not adapter.is_file():
        raise RuntimeError("请先安装 Node.js 并准备固定版本的网络依赖")
    run_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="relay-", dir=run_dir) as temporary:
        scratch = Path(temporary)
        env = {k: os.environ[k] for k in ("SystemRoot", "WINDIR") if k in os.environ}
        env.update({k: temporary for k in ("HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP")})
        env["PATH"] = str(Path(node).parent)
        env["TSX_DISABLE_CACHE"] = "1"
        ready = scratch / "port"
        with (run_dir / "relay-stderr.log").open("wb") as log:
            proc = subprocess.Popen([node, "--require", "tsx/cjs", "--eval", START, str(ready)],
                                    cwd=deps_dir / "mozaik-network", env=env,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
            try:
                deadline = time.monotonic() + 20
                while not ready.exists() or not ready.stat().st_size:
                    if proc.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("本地网络未能启动，请查看 relay-stderr.log")
                    time.sleep(.05)
                port = int(ready.read_text(encoding="ascii"))
                origin = f"http://127.0.0.1:{port}"
                network_id = post(port, "/networks", {"name": "isolation-pilot"})["id"]
                invite = post(port, f"/networks/{network_id}/invites", {})["invite"]
                yield Network(origin, f"{origin}#{invite}", adapter)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", type=Path, required=True, help="下载和安装固定版本依赖的目录")
    prepare(parser.parse_args().prepare)
