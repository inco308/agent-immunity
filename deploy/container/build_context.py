"""为 Linux/amd64 容器试点生成独立构建目录。请将该目录传给 docker build。"""

import argparse
import hashlib
import shutil
import sys
from pathlib import Path
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def create_context(wheel, output):
    sys.path.insert(0, str(REPO))
    from agent_immunity import __version__
    from scripts.check_dist import DATA, verify_members

    expected = f"agent_immunity-{__version__}-py3-none-any.whl"
    if wheel.name != expected or not wheel.is_file():
        raise ValueError(f"请选择本次预览的 {expected}")
    sources = {
        "Dockerfile": HERE / "Dockerfile",
        "local_tools.py": REPO / "examples" / "local_tools.py",
        "policy.json": HERE / "policy.json",
        expected: wheel,
    }
    for path in sources.values():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"构建输入必须是普通文件：{path.name}")

    # 复用发行验收的成员白名单，并将实际装入镜像的代码与当前工作树逐项核对。
    runtime = {p.relative_to(REPO).as_posix() for p in (REPO / "agent_immunity").rglob("*.py")} | DATA
    verify_members(wheel, runtime)
    with zipfile.ZipFile(wheel) as archive:
        if len(archive.namelist()) != len(set(archive.namelist())):
            raise ValueError("wheel 包含重复归档成员")
        for name in sorted(runtime):
            if archive.read(name).replace(b"\r\n", b"\n") != (REPO / name).read_bytes().replace(b"\r\n", b"\n"):
                raise ValueError(f"wheel 内容与当前工作树不一致：{name}")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    sums = wheel.with_name("SHA256SUMS")
    if sums.exists() and f"{digest}  {wheel.name}" not in sums.read_text(encoding="ascii").splitlines():
        raise ValueError("wheel 与同目录 SHA256SUMS 不一致")
    # 独占创建可防止把已有文件一并送给 Docker，例如 .git 或用户保存在目录里的令牌。
    output.mkdir(parents=True, exist_ok=False)
    made = []
    try:
        for name, path in sources.items():
            target = output / name
            with path.open("rb") as src, target.open("xb") as dest:
                made.append(target)
                shutil.copyfileobj(src, dest)
        if hashlib.sha256((output / expected).read_bytes()).hexdigest() != digest:
            raise ValueError("复制期间 wheel 已发生变化")
    except (OSError, ValueError):
        # 只清理本次已经创建的文件，不碰并发产生的其他文件或子目录。
        for target in made:
            target.unlink(missing_ok=True)
        if not any(output.iterdir()):
            output.rmdir()
        raise
    print(f"构建上下文：{output.absolute()}，{expected} SHA-256：{digest}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path, help="由当前工作树源码构建或由其 CI 验收的预览 wheel")
    parser.add_argument("--output", required=True, type=Path, help="尚不存在的构建上下文目录")
    args = parser.parse_args()
    try:
        create_context(args.wheel, args.output)
    except FileExistsError:
        parser.exit(1, "构建上下文已存在，请选择新的输出目录。\n")
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"创建构建上下文失败：{exc}\n")


if __name__ == "__main__":
    main()
