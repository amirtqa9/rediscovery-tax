import json
import tempfile
import tracemalloc
import unittest
from pathlib import Path

from rediscovery_tax.cli import main
from rediscovery_tax.core import TraceError, analyze, validate
from rediscovery_tax.importer import import_trace, import_trace_file


def row(kind, identifier, session, seq, **fields):
    return {"type": kind, "id": identifier, "session": session, "seq": seq, **fields}


class ImporterTests(unittest.TestCase):
    def test_redacts_content_and_preserves_evidence_links(self):
        rows = [
            row("call", "c1", "s1", 1, tool="rg", prompt="private prompt 111",
                args={"query": "secret query 222", "path": "private/path", "extra": "private extra"}),
            row("result", "r1", "s1", 2, call_id="c1", output="secret result 333"),
            row("fact", "f1", "s1", 3, fact_key="secret fact 444", claim="private claim 555",
                source_ids=["c1", "r1"]),
            row("call", "c2", "s2", 1, tool="rg", args={"query": "secret query 222"}, duration_ms=5),
            row("result", "r2", "s2", 2, call_id="c2", output="secret result 333"),
            row("fact", "f2", "s2", 3, fact_key="secret fact 444", source_ids=["c2", "r2"]),
        ]
        events = import_trace(rows)
        serialized = json.dumps(events)
        for secret in ("private prompt 111", "secret query 222", "private/path", "private extra",
                       "secret result 333", "secret fact 444", "private claim 555"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(events, validate(events))
        self.assertEqual(events[1]["call_id"], "c1")
        self.assertEqual(events[2]["source_event_ids"], ["c1", "r1"])
        self.assertEqual(analyze(events)["summary"]["findings"], 2)
        self.assertEqual(events, import_trace(rows))

    def test_cli_writes_valid_jsonl_without_raw_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "raw.jsonl"
            output = Path(directory) / "clean.jsonl"
            rows = [row("call", "c", "s", 1, args={"query": "password=private"}),
                    row("result", "r", "s", 2, call_id="c", output="token=private")]
            source.write_text("".join(json.dumps(item) + "\n" for item in rows), encoding="utf-8")
            self.assertEqual(main(["import", str(source), "--out", str(output)]), 0)
            self.assertNotIn("private", output.read_text(encoding="utf-8"))
            self.assertEqual(main(["validate", str(output)]), 0)
            self.assertEqual(main(["import", str(source), "--out", str(source)]), 2)

    def test_invalid_source_reference_is_rejected(self):
        with self.assertRaises(TraceError):
            import_trace([row("result", "r", "s", 1, call_id="missing", output="secret")])

    def test_large_import_does_not_retain_raw_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "raw.jsonl"
            output = Path(directory) / "clean.jsonl"
            secret = "private-result-body-" * 120
            with source.open("w", encoding="utf-8") as stream:
                for index in range(8_000):
                    stream.write(json.dumps(row("call", f"c{index}", "s", index * 2,
                                                args={"query": secret})) + "\n")
                    stream.write(json.dumps(row("result", f"r{index}", "s", index * 2 + 1,
                                                call_id=f"c{index}", output=secret)) + "\n")
            tracemalloc.start()
            try:
                count = import_trace_file(source, output)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            self.assertEqual(count, 16_000)
            self.assertLess(peak, source.stat().st_size // 2)
            with output.open(encoding="utf-8") as stream:
                first = json.loads(next(stream))
            self.assertEqual(first["event_id"], "c0")
            self.assertNotIn("private-result-body", output.read_text(encoding="utf-8"))

    def test_failed_import_preserves_existing_output_and_removes_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "raw.jsonl"
            output = Path(directory) / "clean.jsonl"
            output.write_text("existing\n", encoding="utf-8")
            source.write_text(json.dumps(row("call", "c", "s", 1)) + "\n" +
                              json.dumps(row("result", "r", "s", 2, call_id="missing", output="secret")) + "\n",
                              encoding="utf-8")
            with self.assertRaisesRegex(TraceError, "invalid call_id"):
                import_trace_file(source, output)
            self.assertEqual(output.read_text(encoding="utf-8"), "existing\n")
            self.assertEqual(list(Path(directory).glob(".clean.jsonl.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
