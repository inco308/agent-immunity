"""供启动故障演练在候选网关解释器内运行，记录真实入口的退出码。"""
from pathlib import Path
import sys

from agent_immunity.mcp_stdio import main as gateway_main


def main():
    marker = Path(sys.argv.pop(1))
    try:
        code = gateway_main()
    except SystemExit as exc:
        code = exc.code
    # 每次演练使用新目录。宿主重试时保留第一次退出的证据。
    if code is None:
        code = 0
    elif not isinstance(code, int):
        code = 1
    try:
        with marker.open("xb") as evidence:
            evidence.write(f"{code}\n".encode("ascii"))
    except FileExistsError:
        pass
    return code


if __name__ == "__main__":
    raise SystemExit(main())
