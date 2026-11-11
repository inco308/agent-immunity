"""旧模块入口：启动真实 stdio 代理，需要 --policy 与上游命令。"""
from agent_immunity.mcp_stdio import main

if __name__ == "__main__":
    raise SystemExit(main())
