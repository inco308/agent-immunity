"""从经过同作业安装收据校验的预览文件准备 Codex 时区试点环境。"""
import argparse
import subprocess
import sys
from pathlib import Path

from scripts.verify_preview_pair import verify_pair_with_wheel
from .prepare import _prepare_environment


def prepare_preview(root, directory, commit, run_id, branch="main"):
    if sys.version_info[:2] != (3, 12):
        raise ValueError("请使用 Python 3.12 运行环境准备脚本")
    receipt, data = verify_pair_with_wheel(directory, commit, run_id, branch)
    wheel = next(p for p in receipt["packages"] if p["kind"] == "wheel")
    return _prepare_environment(root, Path(wheel["filename"]), wheel["installed_version"], wheel["sha256"],
                                preview=(receipt, data))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="时区试点的独立环境目录")
    parser.add_argument("--dist", required=True, type=Path, help="解压后的预览发行包目录")
    parser.add_argument("--commit", required=True, help="已审阅的完整来源提交 SHA")
    parser.add_argument("--run", required=True, type=int, help="对应的成功 push 运行编号")
    parser.add_argument("--branch", default="main", help="预期的来源分支，默认 main")
    args = parser.parse_args(argv)
    try:
        descriptor = prepare_preview(args.root, args.dist, args.commit, args.run, args.branch)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"预览环境准备失败：{exc}\n")
    print(descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
