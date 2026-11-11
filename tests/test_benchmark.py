"""防止基准把消融、未测能力和已知漏检隐藏成同一结论。"""
from pathlib import Path
import unittest
from agent_immunity.benchmark.run_evaluation import run
from tests.support import temporary_directory

class BenchmarkTests(unittest.TestCase):
    def test_ablation_and_known_limits_remain_visible(self):
        with temporary_directory() as root:
            report = run(repeats=2, temp_root=Path(root))
        modes = report["modes"]
        self.assertEqual(report["regressions"], [])
        self.assertEqual(modes["NO_POLICY"]["blocked_attack_calls"], 0)
        self.assertLess(modes["POLICY_ONLY"]["blocked_attack_calls"], modes["POLICY_AND_CREDENTIALS"]["blocked_attack_calls"])
        full = modes["POLICY_AND_CREDENTIALS"]
        self.assertEqual(full["benign_call_false_positive_rate"], 0)
        self.assertLess(full["blocked_attack_calls"], full["attack_calls"])
        self.assertTrue(any(row["known_limitation"] and row["allowed"] for row in full["rows"]))
        self.assertIn("LLM self-guard", report["not_measured"])
