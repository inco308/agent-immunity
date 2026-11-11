"""真实模型 CI 的证据门槛回归；这些夹具不计入模型成绩。"""
import copy
import json
from pathlib import Path
import unittest

from evals.ci_ollama import CASE_IDS, MODEL, MODEL_DIGEST, MODES, VERSION, validate_report
from tests.support import temporary_directory


class LiveCiEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = temporary_directory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "report.json"
        self.report = {
            "status": "completed", "completed_trial_records": 6,
            "backend": {"model": MODEL, "model_digest": MODEL_DIGEST,
                        "server_version": VERSION, "availability_verified": True},
            "trials": [{"case_id": case, "mode": mode, "seed": 42,
                        "events": [{"kind": "tool", "upstream_called": True}]}
                       for case in CASE_IDS for mode in MODES],
        }

    def validate(self, report):
        self.path.write_text(json.dumps(report), encoding="utf-8")
        validate_report(self.path)

    def test_complete_identified_model_and_tool_evidence_is_accepted(self):
        self.validate(self.report)

    def test_generated_text_without_real_tool_call_is_not_green(self):
        for row in self.report["trials"]:
            row["events"] = [{"kind": "finish", "model_output": '{"final":"完成"}'}]
        with self.assertRaises(RuntimeError):
            self.validate(self.report)

    def test_missing_trial_wrong_model_or_failed_run_is_rejected(self):
        samples = []
        missing = copy.deepcopy(self.report)
        missing["trials"].pop()
        samples.append(missing)
        wrong = copy.deepcopy(self.report)
        wrong["backend"]["model_digest"] = "different"
        samples.append(wrong)
        failed = copy.deepcopy(self.report)
        failed["status"] = "incomplete"
        samples.append(failed)
        unverified = copy.deepcopy(self.report)
        unverified["backend"]["availability_verified"] = False
        samples.append(unverified)
        for sample in samples:
            with self.subTest(sample=sample), self.assertRaises(RuntimeError):
                self.validate(sample)


if __name__ == "__main__":
    unittest.main()
