"""兼容入口：实现已移入 agent_immunity.capture，旧命令与旧导入路径继续可用。

新代码请使用 `agent-immunity-capture`（安装 wheel 后可用）或
`python -m agent_immunity.capture`。
"""
from agent_immunity.capture import *  # noqa: F401,F403
from agent_immunity.capture import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
