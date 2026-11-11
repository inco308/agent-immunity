"""只读核对三端前后真实评测报告，生成保留分子与分母的比较。

本模块不调用模型、不重放工具，也不修改历史快照。历史目录作为两侧输入
仅能在显式 --self-test 模式使用，该模式生成的文件不能作为复测证据。
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import quote

from evals.metrics import summarize


REPO = Path(__file__).resolve().parents[1]
BEFORE_DIR = REPO / "results" / "llm" / "2026-11-11"
BACKENDS = {"ollama": "ollama", "codex": "codex_cli", "dsh": "dsh"}
MODES = ("baseline", "gateway")
RATE_FIELDS = {
    "benign_task_completion_rate": ("正常任务完成", "benign_task_completed_trials", "benign_trials"),
    "task_completion_rate": ("全部任务完成", "task_completed_trials", "trial_count"),
    "conditional_attack_call_block_rate": ("实际攻击调用条件拦截", "blocked_attack_attempts", "attack_attempts"),
    "benign_call_false_positive_rate": ("全部场景合法调用误报", "blocked_benign_attempts", "benign_attempts"),
    "benign_task_false_rejection_rate": ("正常任务误拒绝", "benign_task_false_rejections", "benign_trials"),
    "unsafe_outcome_rate": ("违规结果数 / 样本数", "unsafe_outcome_trials", "trial_count"),
}
SAMPLING_FIELDS = ("seed_supported", "temperature", "num_predict", "num_ctx", "think", "timeout_seconds")
VERSION_FIELDS = ("cli_version", "version", "server_version", "node_version")


class ComparisonError(ValueError):
    """报告缺失、配对不成立或结果不一致。"""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ComparisonError(message)


def _sha(value: Any, label: str) -> str:
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None, f"{label} 不是有效 SHA-256")
    return value


def _read_json(path: Path) -> tuple[dict[str, Any], str]:
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, f"{path.name} 含重复 JSON 键：{key}")
            result[key] = value
        return result

    def constant(value):
        raise ComparisonError(f"{path.name} 含非有限 JSON 数值：{value}")

    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    _require(isinstance(value, dict), f"{path.name} 的顶层不是对象")
    return value, hashlib.sha256(raw).hexdigest()


def _unique_list(value: Any, item_type: type, label: str) -> list:
    _require(isinstance(value, list) and bool(value), f"{label} 必须为非空列表")
    _require(all(type(item) is item_type for item in value), f"{label} 的元素类型错误")
    _require(len(set(value)) == len(value), f"{label} 含重复值")
    if item_type is str:
        _require(all(item.strip() for item in value), f"{label} 含空名称")
    return value


def _key(row: dict[str, Any]) -> tuple:
    return row["case_id"], row["category"], row["mode"], row["seed"]


def load_report(path: Path, backend_name: str) -> dict[str, Any]:
    """重算已有轨迹，拒绝缺样本、重复样本和不一致的预计算指标。"""
    report, file_sha = _read_json(path)
    label = str(path)
    _require(report.get("scope") == "LIVE_LLM_MCP_E2E", f"{label} 不是实际模型评测报告")
    _require(report.get("schema_version") == 1 and report.get("status") == "completed", f"{label} 未有效完成")
    backend = report.get("backend")
    _require(isinstance(backend, dict), f"{label} 缺少 backend")
    _require(backend.get("backend") == BACKENDS[backend_name], f"{label} 的后端身份不符")
    _require(isinstance(backend.get("model"), str) and bool(backend["model"]), f"{label} 缺少模型名称")
    _require(type(backend.get("seed_supported")) is bool, f"{label} 缺少 seed_supported")
    if backend_name == "ollama":
        _sha(backend.get("model_digest"), f"{label} model_digest")
        _require(backend.get("availability_verified") is True, f"{label} 未确认模型生成")
    elif backend_name == "codex":
        _require(backend.get("model_availability_verified") is True, f"{label} 未确认模型生成")
    else:
        _require(backend.get("provider") == "deepseek-official", f"{label} 的 dsh 提供方不符")
    provenance = backend.get("provenance")
    _require(isinstance(provenance, dict), f"{label} 缺少 provenance")
    cases = _unique_list(provenance.get("selected_case_ids"), str, f"{label} selected_case_ids")
    seeds = _unique_list(provenance.get("sample_seeds"), int, f"{label} sample_seeds")
    max_steps = provenance.get("max_steps")
    _require(type(max_steps) is int and max_steps > 0, f"{label} max_steps 无效")
    _sha(report.get("dataset_sha256"), f"{label} dataset_sha256")
    _sha(report.get("system_prompt_sha256"), f"{label} system_prompt_sha256")
    rows = report.get("trials")
    _require(isinstance(rows, list) and bool(rows), f"{label} 没有 trial")
    planned = len(cases) * len(seeds) * len(MODES)
    _require(type(report.get("planned_trials")) is int and report["planned_trials"] == planned, f"{label} 计划样本数与配置不符")
    _require(type(report.get("completed_trial_records")) is int and report["completed_trial_records"] == len(rows) == planned,
             f"{label} 样本未齐全")
    try:
        recalculated = summarize(rows)
    except (ValueError, TypeError, KeyError) as exc:
        raise ComparisonError(f"{label} 的 trial 无法重算：{exc}") from exc
    saved_metrics = json.dumps(report.get("metrics"), sort_keys=True, ensure_ascii=False, allow_nan=False)
    fresh_metrics = json.dumps(recalculated, sort_keys=True, ensure_ascii=False, allow_nan=False)
    _require(saved_metrics == fresh_metrics, f"{label} 已保存 metrics 与 summarize 重算结果不一致")
    keys = [_key(row) for row in rows]
    _require(len(set(keys)) == len(keys), f"{label} 存在重复 trial")
    observed = {(row["case_id"], row["mode"], row["seed"]) for row in rows}
    expected = {(case, mode, seed) for case in cases for mode in MODES for seed in seeds}
    _require(observed == expected, f"{label} 的 case/mode/seed 组合缺失或多出")
    case_metadata: dict[str, tuple] = {}
    for row in rows:
        _require(row.get("error_kind") not in ("provider_error", "infrastructure_error") and row["status"] != "model_error",
                 f"{label} 含未完成的模型或基础设施错误")
        _require(row.get("split") in ("development", "holdout"), f"{label} 的 split 无效")
        case_sha = _sha(row.get("case_input_sha256"), f"{label} {row['case_id']} case_input_sha256")
        identity = (row["category"], row["split"], case_sha)
        _require(row["case_id"] not in case_metadata or case_metadata[row["case_id"]] == identity,
                 f"{label} 同一 case 的分类、split 或输入摘要不一致")
        case_metadata[row["case_id"]] = identity
        events = row.get("events")
        _require(isinstance(events, list) and bool(events), f"{label} 存在无模型事件的 trial")
        _require(len(events) <= row["model_calls"] <= max_steps, f"{label} 模型调用数超出预算或少于事件数")
        _require(all(isinstance(event, dict) and isinstance(event.get("model_output"), str)
                     and event.get("model") == backend["model"] for event in events), f"{label} 事件模型身份或输出字段不符")
    publication = report.get("publication", {})
    _require(isinstance(publication, dict), f"{label} publication 无效")
    declared_raw_sha = publication.get("raw_report_sha256")
    if declared_raw_sha is not None:
        _sha(declared_raw_sha, f"{label} publication.raw_report_sha256")
    return {"report": report, "metrics": recalculated, "file_sha256": file_sha,
            "normalized_lf_sha256": hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest(),
            "declared_raw_report_sha256": declared_raw_sha, "case_metadata": case_metadata,
            "keys": set(keys), "path": path.resolve()}


def _measurement(summary: dict, numerator: str, denominator: str) -> dict:
    count, total = summary[numerator], summary[denominator]
    return {"numerator": count, "denominator": total, "rate": count / total if total else None}


def _mode_comparison(before: dict, after: dict) -> dict:
    result = {}
    for name, (label, numerator, denominator) in RATE_FIELDS.items():
        old, new = _measurement(before, numerator, denominator), _measurement(after, numerator, denominator)
        delta = new["rate"] - old["rate"] if old["rate"] is not None and new["rate"] is not None else None
        result[name] = {"label": label, "before": old, "after": new,
                        "change": {"numerator": new["numerator"] - old["numerator"],
                                   "denominator": new["denominator"] - old["denominator"],
                                   "rate": delta, "percentage_points": None if delta is None else delta * 100}}
    return result


def _reference(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _source(loaded: dict) -> dict:
    path = loaded["path"]
    return {"path": _reference(path), "directory": _reference(path.parent),
            "directory_date": path.parent.name if re.fullmatch(r"\d{4}-\d{2}-\d{2}", path.parent.name) else None,
            "input_file_sha256": loaded["file_sha256"],
            "normalized_lf_input_file_sha256": loaded["normalized_lf_sha256"],
            "raw_report_sha256": loaded["declared_raw_report_sha256"] or loaded["file_sha256"],
            "raw_report_sha256_source": "publication_declaration" if loaded["declared_raw_report_sha256"] else "input_file_bytes",
            "sample_count": len(loaded["report"]["trials"])}


def compare_pair(name: str, before: dict, after: dict, self_test: bool) -> dict:
    old_report, new_report = before["report"], after["report"]
    old_backend, new_backend = old_report["backend"], new_report["backend"]
    old_prov, new_prov = old_backend["provenance"], new_backend["provenance"]
    for field in ("dataset_sha256", "system_prompt_sha256"):
        _require(old_report[field] == new_report[field], f"{name} 前后 {field} 不一致")
    _require(old_report.get("method") == new_report.get("method"), f"{name} 前后执行方法不一致")
    for field in ("model", "provider", *SAMPLING_FIELDS):
        _require(old_backend.get(field) == new_backend.get(field), f"{name} 前后模型或采样字段 {field} 不一致")
    if name == "ollama":
        _require(old_backend["model_digest"] == new_backend["model_digest"], "Ollama 前后模型摘要不一致")
    for field in ("selected_case_ids", "sample_seeds", "max_steps"):
        _require(old_prov[field] == new_prov[field], f"{name} 前后 provenance.{field} 不一致")
    _require(before["keys"] == after["keys"], f"{name} 前后 case/category/mode/seed 不一一对应")
    _require(before["case_metadata"] == after["case_metadata"], f"{name} 前后场景分类、split 或输入摘要不一致")
    if not self_test:
        _require(before["path"] != after["path"] and before["file_sha256"] != after["file_sha256"], f"{name} after 复用了 before 报告")
        old_raw = before["declared_raw_report_sha256"] or before["file_sha256"]
        new_raw = after["declared_raw_report_sha256"] or after["file_sha256"]
        _require(old_raw != new_raw, f"{name} 前后使用了同一原始报告，不能作为复测")
        old_rows = {_key(row): row for row in old_report["trials"]}
        _require(all(old_rows[_key(row)] != row for row in new_report["trials"]),
                 f"{name} after 含与 before 完全相同的 trial 记录，不能把旧调用作为复测")
    versions = {field: {"before": old_backend.get(field), "after": new_backend.get(field),
                        "changed": old_backend.get(field) != new_backend.get(field)}
                for field in VERSION_FIELDS if field in old_backend or field in new_backend}
    versions["mcp_python_sdk"] = {"before": old_prov.get("mcp_python_sdk"), "after": new_prov.get("mcp_python_sdk"),
                                  "changed": old_prov.get("mcp_python_sdk") != new_prov.get("mcp_python_sdk")}
    old_hashes, new_hashes = old_prov.get("runtime_file_sha256", {}), new_prov.get("runtime_file_sha256", {})
    _require(isinstance(old_hashes, dict) and isinstance(new_hashes, dict), f"{name} runtime_file_sha256 无效")
    runtime_changes = {path: {"before": old_hashes.get(path), "after": new_hashes.get(path)}
                       for path in sorted(set(old_hashes) | set(new_hashes)) if old_hashes.get(path) != new_hashes.get(path)}
    modes = {mode: _mode_comparison(before["metrics"]["modes"][mode], after["metrics"]["modes"][mode]) for mode in MODES}
    baseline_changes = [metric for metric, values in modes["baseline"].items() if values["before"] != values["after"]]
    return {"backend": name, "model": old_backend["model"], "model_digest": old_backend.get("model_digest"),
            "before": _source(before), "after": _source(after), "paired_trial_count": len(before["keys"]),
            "selected_case_ids": old_prov["selected_case_ids"], "sample_seeds": old_prov["sample_seeds"],
            "max_steps": old_prov["max_steps"], "seed_supported": old_backend["seed_supported"],
            "dataset_sha256": old_report["dataset_sha256"], "system_prompt_sha256": old_report["system_prompt_sha256"],
            "versions": versions, "runtime_file_changes": runtime_changes, "modes": modes,
            "baseline_changed_metrics": baseline_changes,
            "status_counts": {f"{side}_{mode}": loaded["metrics"]["modes"][mode]["status_counts"]
                              for side, loaded in (("before", before), ("after", after)) for mode in MODES}}


def build_comparison(after_dir: Path, *, self_test: bool = False) -> dict:
    """验证全部输入后才返回结果；不产生任何写入或模型调用。"""
    after_dir = after_dir.resolve()
    _require(after_dir.is_dir(), "after-dir 不存在")
    if self_test:
        _require(after_dir == BEFORE_DIR.resolve(), "self-test 只能用固定 before 目录作两侧输入")
    else:
        _require(after_dir != BEFORE_DIR.resolve(), "同一目录只允许显式 --self-test")
    pairs = {}
    for name in BACKENDS:
        before = load_report(BEFORE_DIR / f"{name}.json", name)
        after = load_report(after_dir / f"{name}.json", name)
        pairs[name] = compare_pair(name, before, after, self_test)
    additional = []
    extra = after_dir / "agy.json"
    if extra.is_file():
        report, digest = _read_json(extra)
        backend = report.get("backend", {})
        additional.append({"backend": "agy", "path": _reference(extra), "input_file_sha256": digest,
                           "status": report.get("status"), "model": backend.get("model") if isinstance(backend, dict) else None,
                           "sample_count": len(report.get("trials", [])) if isinstance(report.get("trials"), list) else None,
                           "paired": False, "note": "新增后端，无 before 同模型报告，不进入三端配对表；状态未参与配对验证。"})
    return {"schema_version": 1, "scope": "REDACTION_FIX_PAIRED_REPORT_COMPARISON",
            "status": "self_test_only" if self_test else "validated_comparison", "self_test": self_test,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "before_directory": _reference(BEFORE_DIR), "after_directory": _reference(after_dir),
            "paired_sample_count": sum(pair["paired_trial_count"] for pair in pairs.values()),
            "backends": pairs, "additional_backends": additional,
            "interpretation": ["每个百分比保留原始分子分母；零分母为 null/N/A，变化为 after 减 before。",
                               "CLI seed 仅标识样本，不能控制 Codex/dsh 采样；同模型名称也不是云端不可变快照。",
                               "baseline 自身变化必须同时查看，模型输出差异不能全部归因于核心修复。",
                               "本工具验证已保存报告的一致性，不调用模型，也不能独立证明报告的生成真实性。"]}


def _rate_text(value: dict) -> str:
    fraction = f"{value['numerator']}/{value['denominator']}"
    return fraction + ("（N/A）" if value["rate"] is None else f"（{value['rate']:.1%}）")


def _link(reference: str, output_dir: Path) -> str:
    source = Path(reference)
    source = source if source.is_absolute() else REPO / source
    try:
        target = Path(os.path.relpath(source, output_dir)).as_posix()
    except ValueError:
        target = source.as_posix()
    return quote(target, safe="/:")


def render_markdown(comparison: dict, output_dir: Path) -> str:
    title = "# 前后比较脚本自测（不是复测结果）" if comparison["self_test"] else "# 脱敏占位符修复前后比较"
    lines = [title, ""]
    if comparison["self_test"]:
        lines.extend(["本文件把同一份历史快照同时作为两侧输入，仅验证配对与汇总程序。没有重新调用模型，不能作为修复效果或复测证据。", ""])
    lines.extend([f"修复前目录：`{comparison['before_directory']}`；修复后输入目录：`{comparison['after_directory']}`。",
                  f"三端共核对 {comparison['paired_sample_count']} 对 trial；变化统一为修复后减修复前。", "",
                  "每个比率显示原始分子/分母。条件攻击调用拦截率没有实际攻击调用时为 N/A；错误及预算耗尽样本保留在分母。", ""])
    for name, pair in comparison["backends"].items():
        lines.extend([f"## {name} · {pair['model']}", "",
                      f"样本：前 {pair['before']['sample_count']} / 后 {pair['after']['sample_count']}；"
                      f"场景：`{','.join(pair['selected_case_ids'])}`；seed：`{','.join(map(str, pair['sample_seeds']))}`；"
                      f"每 trial 最多 {pair['max_steps']} 步。", "",
                      "| 模式 | 指标 | 修复前 | 修复后 | 变化 |", "| --- | --- | --- | --- | --- |"])
        for mode in MODES:
            for metric, values in pair["modes"][mode].items():
                delta = values["change"]
                if metric == "unsafe_outcome_rate":
                    change = f"{delta['numerator']:+d} 个违规样本"
                else:
                    change = "N/A" if delta["percentage_points"] is None else f"{delta['percentage_points']:+.1f} 个百分点"
                lines.append(f"| {mode} | {values['label']} | {_rate_text(values['before'])} | {_rate_text(values['after'])} | {change} |")
        changed = pair["baseline_changed_metrics"]
        labels = "、".join(RATE_FIELDS[key][0] for key in changed)
        lines.extend(["", f"baseline 自身也发生变化：{labels}。" if changed else "baseline 的上述计数与比率未变化；这不保证模型轨迹完全一致。", "",
                      "| 运行组件 | 修复前 | 修复后 | 版本变化 |", "| --- | --- | --- | --- |"])
        for field, values in pair["versions"].items():
            lines.append(f"| {field} | {values['before'] or '未记录'} | {values['after'] or '未记录'} | {'有' if values['changed'] else '无'} |")
        seed_note = "后端支持 seed；仍不保证跨运行逐字相同。" if pair["seed_supported"] else "seed_supported=false：seed 仅标识样本，不能控制此 CLI 的模型采样。"
        lines.extend(["", seed_note, ""])
    lines.extend(["## 输入来源与完整性", "",
                  "输入文件 SHA-256 根据本次读取的文件字节计算；原始报告 SHA 若来自 publication 字段，是快照声明的脱敏前摘要，二者分别保存。comparison.json 另存 normalized_lf_input_file_sha256，便于核对 Git 统一 LF 行尾后的快照内容。",
                  "", "| 后端 / 阶段 | 报告 | 输入文件 SHA-256 | 原始报告 SHA-256 |", "| --- | --- | --- | --- |"])
    for name, pair in comparison["backends"].items():
        for side in ("before", "after"):
            source = pair[side]
            lines.append(f"| {name} / {side} | [{source['directory_date'] or side}]({_link(source['path'], output_dir)}) | `{source['input_file_sha256']}` | `{source['raw_report_sha256']}` |")
    lines.extend(["", "配对已核对数据集与公共系统提示摘要、模型身份、场景输入摘要、步骤预算、seed、模式和 trial 唯一性，并使用 summarize 重算双方指标。运行源码变化及逐模式状态计数保存在 comparison.json。", "",
                  "CLI/server 版本和 baseline 自身变化应与 gateway 一起解读；模型差异不能全部归因于核心修复。此程序不重新调用模型，仅验证输入报告一致性。", ""])
    for extra in comparison["additional_backends"]:
        lines.extend(["## 新增后端", "",
                      f"[AGY 报告]({_link(extra['path'], output_dir)})：模型 `{extra['model']}`，报告状态 `{extra['status']}`，样本数 {extra['sample_count']}。没有修复前同模型数据，不纳入三端前后配对。", ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--after-dir", type=Path, required=True, help="包含 ollama/codex/dsh.json 的新评测目录")
    parser.add_argument("--output-dir", type=Path, required=True, help="comparison.json 与 README.md 输出目录")
    parser.add_argument("--self-test", action="store_true", help="仅用历史目录作两侧输入，明确标记为非复测自测")
    args = parser.parse_args()
    try:
        output = args.output_dir.resolve()
        _require(not output.is_relative_to(BEFORE_DIR.resolve()), "禁止向历史 before 快照目录写入")
        if args.self_test:
            _require(output.is_relative_to((REPO / "artifacts").resolve()), "自测结果必须写入 artifacts，不能写成正式快照")
        comparison = build_comparison(args.after_dir, self_test=args.self_test)
        markdown = render_markdown(comparison, output)
        # 全部验证通过后才写产物，验证失败不会覆盖既有比较文件。
        output.mkdir(parents=True, exist_ok=True)
        (output / "comparison.json").write_text(json.dumps(comparison, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        (output / "README.md").write_text(markdown, encoding="utf-8")
        print("比较自测完成（不是复测结果）。" if args.self_test else "三端报告已通过配对核对并生成比较。")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.exit(1, f"比较失败：{exc}\n")


if __name__ == "__main__":
    main()
