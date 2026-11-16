"""仅用于合成夹具，记录真实网关处理前的参数与处理后的响应。"""
import json
from pathlib import Path
import sys

from agent_immunity import Policy
from agent_immunity.mcp_stdio import StdioProxy, valid_id


class ObservedGateway(StdioProxy):
    def __init__(self, root):
        super().__init__(Policy.load(root / "policy.json"),
                         [sys.executable, str(Path(__file__).with_name("fixture.py")), str(root)])
        self.calls = {}
        self.log_path = root / "gateway.jsonl"
        self.log_path.touch(exist_ok=False)

    def client_message(self, req):
        if isinstance(req, dict) and req.get("method") == "tools/call" and valid_id(req.get("id")):
            self.calls[req["id"]] = req.get("params", {})
        return super().client_message(req)

    def emit(self, message):
        params = self.calls.pop(message.get("id"), None)
        if params is not None:
            result = message.get("result", {})
            record = {"tool": params.get("name"), "arguments": params.get("arguments"),
                      "is_error": result.get("isError", "error" in message),
                      "code": result.get("_meta", {}).get("agent_immunity", {}).get("code"),
                      "text": "\n".join(item.get("text", "") for item in result.get("content", []))}
            with self.log_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record) + "\n")
        return super().emit(message)


if __name__ == "__main__":
    raise SystemExit(ObservedGateway(Path(sys.argv[1]).resolve()).run())
