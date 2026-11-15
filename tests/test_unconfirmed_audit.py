"""检查待核对凭据的判定关联、脱敏、容量边界和独占发布。"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch
from uuid import UUID

from agent_immunity import decision_audit
from agent_immunity.decision_audit import AuditError, DecisionAudit
from tests.support import policy, temporary_directory


class UnconfirmedAuditTests(unittest.TestCase):
    def setUp(self):
        temporary = temporary_directory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        work = root / "work"
        work.mkdir()
        self.logs = root / "logs"
        self.logs.mkdir()
        self.policy = policy(work)

    def open_sink(self):
        sink = DecisionAudit.open(self.logs, self.policy)
        self.addCleanup(sink.close)
        return sink

    def test_note_points_to_last_allow_in_original_unchanged_decision_journal(self):
        sink = self.open_sink()
        self.assertEqual(sink.record("private-tool-name", "UNKNOWN_TOOL"), 1)
        seq = sink.record("document", "ALLOW")
        journal, = self.logs.glob("*.jsonl")
        original = journal.read_bytes()
        rows = [json.loads(line) for line in original.splitlines()]
        sink.record_unconfirmed(seq, "client_delivery_unconfirmed")
        self.assertEqual(journal.read_bytes(), original)
        note_path, = self.logs.glob("*.unconfirmed.json")
        info = json.loads(note_path.read_bytes())
        self.assertEqual(set(info), {"schema_version", "utc", "session_id", "decision_sequence", "reason"})
        self.assertEqual(info["schema_version"], 1)
        self.assertEqual(info["reason"], "client_delivery_unconfirmed")
        self.assertEqual(datetime.fromisoformat(info["utc"]).utcoffset(), timedelta(0))
        self.assertEqual(note_path.name, rows[-1]["session_id"] + ".unconfirmed.json")
        self.assertEqual((info["session_id"], info["decision_sequence"]), (rows[-1]["session_id"], rows[-1]["sequence"]))
        self.assertEqual((seq, rows[-1]["decision_code"]), (2, "ALLOW"))
        self.assertNotIn("private-tool-name", note_path.read_text(encoding="ascii"))
        self.assertNotIn("document", note_path.read_text(encoding="ascii"))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(note_path.stat().st_mode) & 0o077, 0)
        with self.assertRaises(AuditError):
            sink.record("document", "ALLOW")

    def test_invalid_reason_sequence_and_stale_or_absent_allow_cannot_publish(self):
        sink = self.open_sink()
        with self.assertRaises(AuditError):
            sink.record_unconfirmed(1, "upstream_result_unknown")
        first = sink.record("document", "ALLOW")
        for seq, reason in ((first, "private-argument"), (True, "upstream_result_unknown"),
                            (first + 1, "client_delivery_unconfirmed")):
            with self.subTest(seq=seq, reason=reason), self.assertRaises(AuditError) as err:
                sink.record_unconfirmed(seq, reason)
            self.assertNotIn("private-argument", str(err.exception))
        denied = sink.record("private-tool", "UNKNOWN_TOOL")
        for seq in (first, denied):
            with self.subTest(seq=seq), self.assertRaises(AuditError):
                sink.record_unconfirmed(seq, "upstream_result_unknown")
        sink.close()
        with self.assertRaises(AuditError):
            sink.record_unconfirmed(denied, "client_delivery_unconfirmed")
        self.assertEqual(list(self.logs.glob("*.json")), [])

    def test_concurrent_writers_publish_one_complete_note(self):
        sink = self.open_sink()
        seq = sink.record("document", "ALLOW")

        def publish(reason):
            try:
                sink.record_unconfirmed(seq, reason)
            except AuditError:
                return None
            return reason

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(publish, ("client_delivery_unconfirmed", "upstream_result_unknown")))
        winner, = [reason for reason in results if reason is not None]
        note_path, = self.logs.glob("*.unconfirmed.json")
        self.assertEqual(json.loads(note_path.read_bytes())["reason"], winner)
        self.assertEqual(len(list(self.logs.iterdir())), 2)

    def test_existing_file_is_preserved_and_short_write_never_exposes_final_name(self):
        first = self.open_sink()
        seq = first.record("document", "ALLOW")
        journal, = self.logs.glob("*.jsonl")
        existing = journal.with_suffix(".unconfirmed.json")
        existing.write_bytes(b"preexisting evidence\n")
        with self.assertRaises(AuditError):
            first.record_unconfirmed(seq, "upstream_result_unknown")
        self.assertEqual(existing.read_bytes(), b"preexisting evidence\n")

        second = self.open_sink()
        seq = second.record("document", "ALLOW")
        before = set(self.logs.iterdir())
        write = os.write

        def short_write(fd, data):
            self.assertEqual(list(self.logs.glob("*.unconfirmed.json")), [existing])
            return write(fd, data[:len(data) // 2])

        with patch.object(decision_audit.os, "write", side_effect=short_write), self.assertRaises(AuditError):
            second.record_unconfirmed(seq, "client_delivery_unconfirmed")
        self.assertEqual(set(self.logs.iterdir()), before)

    def test_allow_reserves_terminal_note_within_session_budget(self):
        sink = self.open_sink()
        with patch.object(decision_audit, "MAX_AUDIT_BYTES", 256), self.assertRaises(AuditError):
            sink.record("document", "ALLOW")
        empty, = self.logs.glob("*.jsonl")
        self.assertEqual(empty.read_bytes(), b"")
        second = self.open_sink()
        with patch.object(decision_audit, "MAX_AUDIT_BYTES", 512):
            seq = second.record("document", "ALLOW")
            second.record_unconfirmed(seq, "upstream_result_unknown")
        self.assertLessEqual(sum(p.stat().st_size for p in self.logs.iterdir()), 512)

    def test_truncated_decision_journal_cannot_receive_dangling_reference(self):
        sink = self.open_sink()
        seq = sink.record("document", "ALLOW")
        journal, = self.logs.glob("*.jsonl")
        journal.write_bytes(b"")
        with self.assertRaises(AuditError):
            sink.record_unconfirmed(seq, "client_delivery_unconfirmed")
        self.assertEqual(list(self.logs.iterdir()), [journal])

    def test_orphaned_note_cannot_be_reassociated_with_new_session(self):
        identifier = UUID("7417e33a28bd49ebba03528e8165bb6e")
        orphan = self.logs / f"{identifier.hex}.unconfirmed.json"
        orphan.write_bytes(b"old evidence\n")
        with patch.object(decision_audit.uuid, "uuid4", return_value=identifier), self.assertRaises(AuditError):
            DecisionAudit.open(self.logs, self.policy)
        self.assertEqual(list(self.logs.iterdir()), [orphan])
        self.assertEqual(orphan.read_bytes(), b"old evidence\n")
