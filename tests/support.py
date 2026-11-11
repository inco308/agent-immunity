"""共享测试策略和虚构输入，全部位于临时目录。"""
import json
import tempfile
from pathlib import Path
from agent_immunity import Policy

FIXTURES = Path(__file__).parent / "fixtures"
DATA = json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8"))

def temporary_directory():
    parent = Path(__file__).resolve().parents[1] / ".test-tmp"
    parent.mkdir(exist_ok=True)
    return tempfile.TemporaryDirectory(dir=parent)

def policy_data(root, origin=None):
    data = json.loads((FIXTURES / "policy.json").read_text(encoding="utf-8"))
    data["workspace"] = str(root)
    if origin:
        data["tools"]["web_request"]["origins"] = [origin]
    return data

def policy(root):
    return Policy.from_dict(policy_data(root))
