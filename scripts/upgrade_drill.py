"""兼容入口：实现已移入 agent_immunity.drill。

新用法是安装 wheel 后的 `agent-immunity-drill`，或 `python -m agent_immunity.drill`。
"""
from agent_immunity.drill import *  # noqa: F401,F403
from agent_immunity.drill import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
