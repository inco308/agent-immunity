"""按包核对发行验收中的 MCP 协商结果，保留旧报告的原有证据范围。"""
import argparse
import json
from pathlib import Path


PROTOCOL_STEP = "核对每份发行包的 MCP 握手协议"
PROTOCOL = "2025-06-18"


def validate_protocols(report, *, require_protocol=False):
    if (not isinstance(report, dict) or type(report.get("schema_version")) is not int
            or report.get("scope") != "CORE_PACKAGE_INSTALL" or report.get("status") != "passed"):
        raise ValueError("需要成功的核心包安装报告")
    if report["schema_version"] == 1 and not require_protocol:
        return None
    if report["schema_version"] != 2:
        raise ValueError("需要包含逐包握手结果的第 2 版安装报告")
    packages = report.get("packages")
    if (not isinstance(packages, list) or len(packages) != 2
            or not all(isinstance(p, dict) and p.get("kind") in ("wheel", "sdist") for p in packages)
            or packages[0]["kind"] == packages[1]["kind"]):
        raise ValueError("需要 wheel 和源码包各自的验收记录")
    for package in packages:
        if (package.get("protocol_version") != PROTOCOL or package.get("policy_check") != "pass"
                or package.get("proxy_ping") is not True):
            raise ValueError(f"{package['kind']} 缺少预期的握手、策略体检或 ping 结果")
    return packages[0]["protocol_version"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        protocol = validate_protocols(json.loads(args.report.read_bytes()), require_protocol=True)
    except (ValueError, OSError) as exc:
        parser.exit(1, f"安装协议收据校验失败：{exc}\n")
    print(f"wheel 和 sdist 均完成 MCP {protocol} 握手与 ping")


if __name__ == "__main__":
    main()
