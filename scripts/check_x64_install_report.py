"""在 CI 发布报告前，核对 Ubuntu 或 Windows x64 作业中两份包的实际安装记录。"""
import argparse
import json
from pathlib import Path
import re


TARGETS = {
    "ubuntu-latest": ("Linux", "x86_64", "linux-x86_64"),
    "windows-latest": ("Windows", "AMD64", "win-amd64"),
}


def matches(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def validate(report, runner, series):
    """以各自的 venv 为单位核对，不从第一条记录推断另一份包的环境。"""
    if not isinstance(runner, str) or runner not in TARGETS or not matches(series, r"[0-9]+\.[0-9]+"):
        raise ValueError("需要 Ubuntu 或 Windows 的 x64 打包作业和 Python 系列")
    if (not isinstance(report, dict) or type(report.get("schema_version")) is not int
            or report["schema_version"] != 1 or report.get("scope") != "CORE_PACKAGE_INSTALL"
            or report.get("status") != "passed"):
        raise ValueError("需要成功的核心包安装报告")
    packages = report.get("packages")
    if not isinstance(packages, list) or len(packages) != 2 or not all(isinstance(p, dict) for p in packages):
        raise ValueError("报告须包含 wheel 和源码包的两次安装")

    system, machine, tag = TARGETS[runner]
    names = {"wheel": "-py3-none-any.whl", "sdist": ".tar.gz"}
    hashes = {}
    version = packages[0].get("installed_version")
    if not matches(version, r"[0-9][0-9A-Za-z.!+_-]*"):
        raise ValueError("安装报告缺少发行版本")
    for p in packages:
        kind = p.get("kind")
        if (kind not in ("wheel", "sdist") or kind in hashes or p.get("installed_version") != version
                or p.get("filename") != f"agent_immunity-{version}{names[kind]}"
                or not matches(p.get("sha256"), r"[0-9a-f]{64}")
                or p.get("policy_check") != "pass" or p.get("proxy_ping") is not True):
            raise ValueError("包类型、安装版本、文件名、摘要或安装后检查结果不符")
        if (p.get("system") != system or p.get("machine") != machine or p.get("python_platform") != tag
                or type(p.get("pointer_bits")) is not int or p["pointer_bits"] != 64
                or p.get("implementation") != "CPython" or not matches(p.get("python"), re.escape(series) + r"\.[0-9]+")):
            raise ValueError(f"{kind} 的解释器、位数或平台与所选 CI 组合不符")
        if system == "Linux":
            if (p.get("distro_id") != "ubuntu" or not matches(p.get("distro_version"), r"[0-9]+\.[0-9]+(?:\.[0-9]+)?")
                    or not matches(p.get("os_version"), r"[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+_-]*")):
                raise ValueError(f"{kind} 缺少 Ubuntu 发行版或 Linux 内核的独立观测")
        elif not matches(p.get("os_version"), r"[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?"):
            raise ValueError(f"{kind} 缺少 Windows 系统内部版本")
        hashes[kind] = p["sha256"]
    if hashes["wheel"] == hashes["sdist"]:
        raise ValueError("两种发行文件的归档摘要相同")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="check_dist.py 生成的 package-install.json")
    parser.add_argument("--runner", required=True, choices=TARGETS)
    parser.add_argument("--python-series", required=True, help="此作业选择的 Python 主次版本")
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_bytes())
        validate(report, args.runner, args.python_series)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"安装报告校验失败：{exc}\n")
    for p in report["packages"]:
        platform = (f"Ubuntu {p['distro_version']} (Linux {p['os_version']})" if p["system"] == "Linux"
                    else f"Windows {p['os_version']}")
        print(f"{p['kind']}  {platform}  CPython {p['python']}  {p['python_platform']}  {p['pointer_bits']} bit")


if __name__ == "__main__":
    main()
