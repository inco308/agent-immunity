"""在临时 Linux CI 主机上运行固定开源模型；缺模型或运行失败均返回非零。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


REPO = Path(__file__).resolve().parents[1]
MODEL = "qwen3.5:0.8b"
VERSION = "0.40.15"
# 2026-11-11 从官方 registry manifest 原始响应计算，并非模型权重层摘要。
MODEL_DIGEST = "de63045f29755d4721c09d54c9b45c2dadb644f4fd7d604d4cac90d96049971c"
MANIFEST_URL = "https://registry.ollama.ai/v2/library/qwen3.5/manifests/0.8b"
ARCHIVE_SHA256 = "628c018404a4206493efd38e46251c154ede5141b8b8dc85c659b3b027c47379"
CASE_IDS = ("B02", "I01", "L01")
MODES = ("baseline", "gateway")
NOTE = "本报告仅为 CPU 上 qwen3.5:0.8b 的六次探索性评测，与本地 qwen3.5:4b 的结果分别记录，不合并统计。"


def request_json(endpoint, path, payload=None, timeout=10):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(endpoint + path, data=data,
                                     headers={"Content-Type": "application/json"})
    # 本地模型服务不得经过主机 HTTP 代理。
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise RuntimeError("服务响应超过大小限制")
    result = json.loads(raw)
    if "error" in result:
        raise RuntimeError("Ollama 请求失败")
    return result


def verify_registry():
    request = urllib.request.Request(MANIFEST_URL, headers={
        "Accept": "application/vnd.docker.distribution.manifest.v2+json",
        "User-Agent": "agent-immunity-live-eval",
    })
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != MODEL_DIGEST:
        raise RuntimeError("官方模型标签摘要已变化；请审查新版本后更新固定摘要")


def stop_process_group(process):
    if process is None:
        return
    # 终止本次创建的会话，包括 Ollama 派生的推理进程和评测 SDK 上游。
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def write_ci_metadata(output, error=None):
    if output.exists():
        report = json.loads(output.read_text(encoding="utf-8"))
    else:
        report = {
            "schema_version": 1, "scope": "LIVE_LLM_MCP_E2E", "status": "failed",
            "backend": {"backend": "ollama", "model": MODEL, "availability_verified": False},
            "planned_trials": 6, "completed_trial_records": 0, "trials": [],
        }
    report["ci"] = {
        "model_manifest_url": MANIFEST_URL, "expected_model_digest": MODEL_DIGEST,
        "expected_server_version": VERSION, "ollama_archive_sha256": ARCHIVE_SHA256,
        "model_tag_drift_is_failure": True, "case_ids": list(CASE_IDS),
        "modes": list(MODES), "seed": 42, "max_steps": 6, "request_timeout_seconds": 180,
        "evaluation_timeout_seconds": 840, "scope_note": NOTE,
    }
    if error is not None:
        report["status"] = "failed"
        report["ci"]["error"] = error
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown = output.with_suffix(".md")
    body = markdown.read_text(encoding="utf-8") if markdown.exists() else "# 真实 LLM 评测\n"
    body += "\n\n" + NOTE + "\n\n固定模型摘要：`" + MODEL_DIGEST + "`。\n"
    if error is not None:
        body += "\nCI 状态：失败。" + error + "\n"
    markdown.write_text(body, encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(body)


def validate_report(output):
    report = json.loads(output.read_text(encoding="utf-8"))
    rows = report.get("trials", [])
    expected = {(case, mode, 42) for case in CASE_IDS for mode in MODES}
    observed = {(row.get("case_id"), row.get("mode"), row.get("seed")) for row in rows}
    backend = report.get("backend", {})
    if (report.get("status") != "completed" or len(rows) != 6 or observed != expected
            or report.get("completed_trial_records") != 6
            or backend.get("model") != MODEL or backend.get("model_digest") != MODEL_DIGEST
            or backend.get("server_version") != VERSION
            or backend.get("availability_verified") is not True
            or any(not row.get("events") for row in rows)
            or not any(event.get("kind") == "tool" and event.get("upstream_called") is True
                       for row in rows for event in row.get("events", []))):
        raise RuntimeError("未取得完整的六次真实模型轨迹，或模型身份核验未通过")


def interrupted(signum, frame):
    raise InterruptedError("CI 收到终止信号")


def run(args):
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    # 禁止把上一次的产物当成本次完成证据。
    if output.exists() or output.with_suffix(".md").exists():
        raise RuntimeError("输出文件已存在；请为本次运行指定新的输出目录")
    server = evaluator = None
    error = None
    signal.signal(signal.SIGTERM, interrupted)
    try:
        binary = args.ollama_bin.resolve(strict=True)
        print("核验官方模型摘要，下载仅发生在本次临时 CI 主机。", flush=True)
        verify_registry()
        with tempfile.TemporaryDirectory(prefix="agent-immunity-llm-", dir=args.runtime_root) as temporary:
            runtime = Path(temporary)
            (runtime / "models").mkdir()
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            endpoint = f"http://127.0.0.1:{port}"
            environment = dict(os.environ)
            environment.update({
                "OLLAMA_MODELS": str(runtime / "models"),
                "OLLAMA_HOST": f"127.0.0.1:{port}", "OLLAMA_NO_CLOUD": "1",
                "OLLAMA_NUM_PARALLEL": "1", "OLLAMA_MAX_LOADED_MODELS": "1",
                "CUDA_VISIBLE_DEVICES": "-1", "ROCR_VISIBLE_DEVICES": "-1",
            })
            # 服务日志仅存在临时目录中，不加入公开 artifact。
            with (runtime / "ollama.log").open("wb") as log:
                server = subprocess.Popen([str(binary), "serve"], cwd=runtime, env=environment,
                                          stdout=log, stderr=log, start_new_session=True)
                try:
                    deadline = time.monotonic() + 30
                    while True:
                        if server.poll() is not None:
                            raise RuntimeError("本次 Ollama 服务未能启动")
                        try:
                            version = request_json(endpoint, "/api/version", timeout=2)
                            if version.get("version") != VERSION:
                                raise RuntimeError("Ollama 服务版本与固定版本不一致")
                            break
                        except (urllib.error.URLError, TimeoutError):
                            if time.monotonic() >= deadline:
                                raise RuntimeError("Ollama 服务健康检查超时")
                            time.sleep(0.5)
                    print(f"下载 {MODEL}；下载失败或摘要变化将使 CI 失败。", flush=True)
                    pulled = request_json(endpoint, "/api/pull", {"model": MODEL, "stream": False}, timeout=240)
                    if pulled.get("status") != "success":
                        raise RuntimeError("模型下载没有成功完成")
                    models = request_json(endpoint, "/api/tags").get("models", [])
                    found = next((item for item in models if item.get("name") == MODEL), None)
                    if not found or found.get("digest") != MODEL_DIGEST or found.get("remote_host"):
                        raise RuntimeError("下载后的本地模型摘要或运行位置不符合要求")
                    print(NOTE, flush=True)
                    command = [
                        sys.executable, "-X", "utf8", "-m", "evals.run_live", "--backend", "ollama",
                        "--model", MODEL, "--expected-digest", MODEL_DIGEST, "--endpoint", endpoint,
                        "--case-ids", ",".join(CASE_IDS), "--seeds", "42", "--modes", ",".join(MODES),
                        "--max-steps", "6", "--request-timeout", "180", "--output", str(output),
                    ]
                    evaluator = subprocess.Popen(command, cwd=REPO, start_new_session=True)
                    if evaluator.wait(timeout=840) != 0:
                        raise RuntimeError("真实模型评测进程返回失败")
                    validate_report(output)
                finally:
                    try:
                        stop_process_group(evaluator)
                    finally:
                        stop_process_group(server)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        print(error, file=sys.stderr)
    finally:
        write_ci_metadata(output, error)
    return 1 if error else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ollama-bin", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--output", type=Path, default=REPO / "artifacts" / "llm-eval" / "ci.json")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("此入口只用于 Linux CI；不会在本机自动安装或下载模型")
    raise SystemExit(run(args))


if __name__ == "__main__":
    main()
