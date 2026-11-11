"""发布仅含虚构数据的评测快照，保留模型结果和独立判据，移除本机路径身份。"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

from evals.metrics import render_markdown, summarize

REPO = Path(__file__).resolve().parents[1]


def sanitize(value):
    if isinstance(value, dict):
        return {key: sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        roots = (str(REPO), REPO.as_posix(), str(Path.home()), Path.home().as_posix())
        for root in roots:
            for spelling in (json.dumps(root)[1:-1], root):
                value = value.replace(spelling, "$REPO" if root in roots[:2] else "$USER_HOME")
        value = re.sub(r"/home/[^/ \\\"]+", "/home/$USER", value)
    return value


def fraction(numerator, denominator):
    return f"{numerator}/{denominator}" if denominator else "N/A（无实际调用）"


def export(paths, destination, availability=None):
    destination.mkdir(parents=True, exist_ok=True)
    reports = []
    for path in paths:
        report = json.loads(path.read_text(encoding="utf-8"))
        if report.get("status") != "completed" or report.get("completed_trial_records") != report.get("planned_trials"):
            raise ValueError(f"{path.name} 未完成，不能发布成完整成绩")
        if report.get("method", {}).get("effect_sampling") != "after_each_tool_call_and_at_finish":
            raise ValueError("不发布缺少逐次副作用证据的早期探索报告")
        if report.get("method", {}).get("containment") != "trial_root_and_exact_two_receiver_origins":
            raise ValueError("不发布未限定两个接收器的早期探索报告")
        if report["metrics"] != summarize(report["trials"]):
            raise ValueError("报告汇总与原始样本不一致")
        provenance = report["backend"]["provenance"]
        for name, digest in provenance["runtime_file_sha256"].items():
            if hashlib.sha256((REPO / name).read_bytes()).hexdigest() != digest:
                raise ValueError(f"当前运行文件与评测时不同：{name}")
        published = sanitize(copy.deepcopy(report))
        published["publication"] = {
            "raw_report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "synthetic_data_only": True,
            "local_path_identity_redacted": True,
            "source_base_commit_note": "Git 基线在特性提交之前；runtime_file_sha256 标识实际评测代码与输入。",
        }
        name = report["backend"]["backend"].replace("_cli", "")
        (destination / f"{name}.json").write_text(json.dumps(published, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (destination / f"{name}.md").write_text(
            f"# {name} / {report['backend']['model']}\n\n" + render_markdown(report["metrics"]), encoding="utf-8"
        )
        reports.append((name, report))
    lines = [
        "# 真实 LLM 评测快照", "",
        "这是固定小样本上的实际模型轨迹。基线与网关分别重新规划，样本分母不能解释为总体安全率。",
        "所有输入、canary 和服务均为评测自建；没有真实凭证。原始轨迹、判据、用量和代码摘要在各 JSON 中。", "",
        "| 后端 / 模型 | 样本 B/G | 正常任务完成 B/G | 全部任务完成 B/G | 网关拦截攻击调用 | 网关误拒绝合法调用 | 实际违规结果 B/G |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, report in reports:
        baseline, gateway = (report["metrics"]["modes"][mode] for mode in ("baseline", "gateway"))
        lines.append(
            f"| [{name}]({name}.json) / {report['backend']['model']} | {baseline['trial_count']}/{gateway['trial_count']} | "
            f"{fraction(baseline['benign_task_completed_trials'],baseline['benign_trials'])} / {fraction(gateway['benign_task_completed_trials'],gateway['benign_trials'])} | "
            f"{fraction(baseline['task_completed_trials'],baseline['trial_count'])} / {fraction(gateway['task_completed_trials'],gateway['trial_count'])} | "
            f"{fraction(gateway['blocked_attack_attempts'],gateway['attack_attempts'])} | "
            f"{fraction(gateway['blocked_benign_attempts'],gateway['benign_attempts'])} | "
            f"{baseline['unsafe_outcome_trials']}/{gateway['unsafe_outcome_trials']} |"
        )
    lines += [
        "", "B/G 分别表示无网关基线和网关。条件拦截率只有发生实际攻击调用时才有定义；模型没有尝试攻击不算网关拦截。",
        "合法调用误报分母包含攻击场景里的正常业务动作，不能用纯正常任务的零误拒绝掩盖脱敏报告的误报。",
        "任务产物成功和攻击成功独立记录；拦截成功也不保证模型能够恢复正常任务。", "",
        "本轮保留 api_key: [REDACTED] 被有限凭证检测误拒绝的现象，未为提高成绩修改目标产品。",
        "每个 case/模式只运行一个样本；Codex/dsh 不支持此评测的采样 seed，厂商系统提示与工具封装也不同，不能作为纯模型公平排名。",
        "每次调用返回后采样文件树，仍无法看到恶意工具在一次调用内部完成写入再完全恢复的行为。", "",
        "源 Git 基线是特性提交前的 HEAD，实际运行代码与数据由 JSON 中的逐文件 SHA256 标识。",
        "手动 CI 的 0.8B 模型报告在 Actions artifact 中，必须与这里的本地 4B/云端 CLI 结果分开解读。", "",
    ]
    if availability:
        raw = json.loads(availability.read_text(encoding="utf-8"))
        (destination / "availability.json").write_text(json.dumps(sanitize(raw), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        lines += ["AGY 本次最小调用返回 503 容量不足，工具隔离也未满足本评测要求；未计入样本，见 [可用性记录](availability.json)。", ""]
    (destination / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, nargs="+", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--availability", type=Path)
    args = parser.parse_args()
    export(args.reports, args.destination, args.availability)


if __name__ == "__main__":
    main()
