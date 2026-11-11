"""只使用本地 Ollama HTTP API 的模型规划后端。"""
import json
from pathlib import Path
import time
import urllib.request
from urllib.parse import urlsplit


class OllamaBackend:
    def __init__(self, model="qwen3.5:4b", timeout=240, work_root=None,
                 endpoint="http://127.0.0.1:11434", expected_digest=None):
        parsed = urlsplit(endpoint)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password or parsed.path not in ("", "/"):
            raise ValueError("Ollama 评测只连接显式的本地 127.0.0.1 HTTP 服务")
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.expected_digest = expected_digest
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self._metadata = None

    def request(self, path, value=None):
        body = None if value is None else json.dumps(value, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(self.endpoint + path, data=body, headers={"Content-Type": "application/json"})
        with self.opener.open(request, timeout=self.timeout) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise RuntimeError("模型响应超过大小限制")
        result = json.loads(raw)
        if "error" in result:
            raise RuntimeError("Ollama 返回模型服务错误")
        return result

    def metadata(self):
        if self._metadata is None:
            models = self.request("/api/tags")["models"]
            found = next((item for item in models if item.get("name") == self.model), None)
            if not found:
                raise RuntimeError(f"本机没有模型 {self.model}；评测不自动下载或替换模型")
            if found.get("remote_host"):
                raise RuntimeError("本地后端不自动切换到 Ollama 云模型")
            if self.expected_digest and found.get("digest") != self.expected_digest:
                raise RuntimeError("模型摘要与指定评测版本不一致")
            self._metadata = {
                "backend": "ollama", "model": self.model, "model_digest": found["digest"],
                "server_version": self.request("/api/version")["version"],
                "details": found.get("details", {}), "seed_supported": True,
                "temperature": 0, "num_predict": 512, "num_ctx": 8192, "think": False,
                "native_tools": "not_provided", "availability_verified": False,
            }
        return dict(self._metadata)

    def generate(self, messages, schema, seed):
        self.metadata()
        started = time.monotonic()
        response = self.request("/api/chat", {
            "model": self.model, "messages": messages, "stream": False, "think": False,
            "format": schema, "keep_alive": "30m",
            "options": {"temperature": 0, "seed": seed, "num_predict": 512, "num_ctx": 8192},
        })
        if response.get("model") != self.model or response.get("done") is not True:
            raise RuntimeError("模型身份或响应完成标志不符")
        message = response.get("message", {})
        if message.get("tool_calls"):
            raise RuntimeError("模型尝试输出未协商的原生工具调用")
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("模型没有返回规划文本")
        self._metadata["availability_verified"] = True
        return {
            "content": content, "model": response["model"], "elapsed_seconds": time.monotonic() - started,
            "usage": {key: response.get(key) for key in ("prompt_eval_count", "eval_count", "total_duration", "load_duration", "prompt_eval_duration", "eval_duration")},
        }
