#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Quantitative Benchmark Runner.
Evaluates Vanilla, Regex Filter, LLM Self-Guard, and Dynamic Immunity across real-world scenarios.
Outputs metrics table and saves results for 
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Any

# Ensure project root in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Fix Windows console UTF-8 output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from agent_immunity.core.models import DefenseMode, AgentExecutionResult
from agent_immunity.core.agent_runtime import AgentRuntime
from agent_immunity.dataset.scenarios import BENIGN_SCENARIOS, ATTACK_SCENARIOS, ALL_SCENARIOS

def evaluate_mode(mode: DefenseMode, scenarios: List[Dict[str, Any]]) -> Dict[str, Any]:
    runtime = AgentRuntime(defense_mode=mode)
    results: List[AgentExecutionResult] = []

    benign_total = 0
    benign_success = 0
    benign_false_positives = 0

    attack_total = 0
    attack_blocked = 0
    attack_leaked = 0
    self_healed_count = 0
    total_latencies = []

    for sc in scenarios:
        res = runtime.run_task(task_id=sc["id"], scenario_data=sc)
        results.append(res)
        total_latencies.append(res.total_latency_ms)

        if sc["type"] == "BENIGN":
            benign_total += 1
            if res.task_completed and not res.security_incidents:
                benign_success += 1
            elif res.security_incidents and not res.task_completed:
                benign_false_positives += 1
        elif sc["type"] == "ATTACK":
            attack_total += 1
            if res.attack_succeeded:
                attack_leaked += 1
            else:
                attack_blocked += 1
            if res.self_healed:
                self_healed_count += 1

    benign_acc = (benign_success / benign_total * 100.0) if benign_total > 0 else 0.0
    benign_fpr = (benign_false_positives / benign_total * 100.0) if benign_total > 0 else 0.0
    mitigation_rate = (attack_blocked / attack_total * 100.0) if attack_total > 0 else 0.0
    leak_rate = (attack_leaked / attack_total * 100.0) if attack_total > 0 else 0.0
    self_heal_rate = (self_healed_count / attack_total * 100.0) if attack_total > 0 else 0.0
    avg_latency = sum(total_latencies) / len(total_latencies) if total_latencies else 0.0

    return {
        "mode": mode.value,
        "benign_total": benign_total,
        "benign_success_rate": round(benign_acc, 1),
        "benign_fpr": round(benign_fpr, 1),
        "attack_total": attack_total,
        "mitigation_rate": round(mitigation_rate, 1),
        "attack_leak_rate": round(leak_rate, 1),
        "self_heal_rate": round(self_heal_rate, 1),
        "avg_latency_ms": round(avg_latency, 2)
    }

def main():
    quick_mode = "--quick" in sys.argv
    print("=" * 75)
    print("  AI AGENT RUNTIME SECURITY BENCHMARK EVALUATION (REAL-WORLD TESTBED)")
    print("=" * 75)
    
    scenarios_to_run = ALL_SCENARIOS

    modes = [
        DefenseMode.VANILLA,
        DefenseMode.REGEX_FILTER,
        DefenseMode.LLM_SELF_GUARD,
        DefenseMode.DYNAMIC_IMMUNITY
    ]

    all_metrics = []
    for m in modes:
        print(f"[*] Running evaluation for Defense Configuration: {m.value} ...")
        metrics = evaluate_mode(m, scenarios_to_run)
        all_metrics.append(metrics)

    # Print Formatted Markdown Table
    print("\n" + "=" * 75)
    print("[*] 真实场景量化评估结果对比矩阵 (Empirical Results Matrix)")
    print("=" * 75)
    header = "| 防御方案配置 (Defense Configuration) | 正常业务完成率 | 正常业务误报率 (FPR) | 攻击防御拦截率 (TPR) | 攻击成功率 (Leak) | 自愈恢复率 | 平均时延 (ms) |"
    divider = "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |"
    print(header)
    print(divider)
    for row in all_metrics:
        print(f"| **{row['mode']}** | {row['benign_success_rate']}% | {row['benign_fpr']}% | {row['mitigation_rate']}% | {row['attack_leak_rate']}% | {row['self_heal_rate']}% | {row['avg_latency_ms']} ms |")

    # Save to JSON
    out_dir = ROOT_DIR / "agent_immunity" / "benchmark"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / "benchmark_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(all_metrics, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Quantitative benchmark data successfully saved to: {out_json}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
