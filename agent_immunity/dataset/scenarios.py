"""加载包内的确定性规则基准；不调用模型或产生网络、文件副作用。"""
import json
from importlib.resources import files

def load_cases():
    return json.loads(files("agent_immunity.dataset").joinpath("cases.json").read_text(encoding="utf-8"))

def load_policy(workspace):
    data = json.loads(files("agent_immunity.dataset").joinpath("policy.json").read_text(encoding="utf-8"))
    data["workspace"] = str(workspace)
    return data
