import unittest

from rediscovery_tax.core import TraceError, analyze, validate


def event(identifier, session, seq, kind, **other):
    return {"schema_version": 1, "event_id": identifier, "session_id": session,
            "seq": seq, "kind": kind, **other}


class AnalyzeTests(unittest.TestCase):
    def test_explicit_repeat_and_shared_cost(self):
        rows = [event("a", "s1", 1, "fact", fact_key="auth", source_event_ids=[]),
                event("call", "s2", 1, "tool_call", duration_ms=20),
                event("b", "s2", 2, "fact", fact_key="auth", source_event_ids=["call"]),
                event("c", "s2", 3, "fact", fact_key="auth", source_event_ids=["call"])]
        report = analyze(rows)
        self.assertEqual(report["summary"]["observed_tool_calls"], 1)
        self.assertEqual(report["summary"]["observed_duration_ms"], 20)
        self.assertEqual(report["summary"]["usage"]["input_tokens"], None)
        self.assertTrue(report["findings"][1]["shared_attribution"])

    def test_changed_revision_and_expiry(self):
        rows = [event("a", "s1", 1, "fact", fact_key="auth", source_revision="old"),
                event("b", "s2", 1, "fact", fact_key="auth", source_revision="new")]
        self.assertEqual(analyze(rows)["summary"]["findings"], 0)

    def test_inferred_signature_and_review(self):
        rows = [event("a", "s1", 1, "tool_result", arguments={"path": "src/a.py", "symbol": "run"}),
                event("b", "s2", 1, "tool_result", arguments={"path": "src/a.py", "symbol": "run"})]
        report = analyze(rows)
        self.assertEqual(report["summary"]["findings"], 1)
        self.assertEqual(analyze(rows, min_confidence="high")["summary"]["findings"], 0)
        finding_id = report["findings"][0]["finding_id"]
        self.assertEqual(analyze(rows, review={finding_id: "different"})["summary"]["findings"], 0)

    def test_linked_call_arguments_are_used(self):
        rows = [event("a", "s1", 1, "tool_result", arguments={"path": "a.py", "symbol": "go"}),
                event("c1", "s2", 1, "tool_call", arguments={"path": "a.py", "symbol": "go"},
                      timestamp="2026-01-01T00:00:00Z", duration_ms=100, usage={"input_tokens": 2}),
                event("c2", "s2", 2, "tool_call", timestamp="2026-01-01T00:00:00.050Z",
                      duration_ms=100, usage={"input_tokens": 3}),
                event("b", "s2", 3, "tool_result", call_id="c1"),
                event("f", "s2", 4, "fact", fact_key="other", source_event_ids=["c1", "c2"]),
                event("g", "s3", 1, "fact", fact_key="other", source_event_ids=[])]
        report = analyze(rows)
        self.assertEqual(report["summary"]["findings"], 2)
        self.assertEqual(report["findings"][0]["match_basis"], "path_symbol")
        self.assertEqual(report["summary"]["observed_tool_calls"], 1)

    def test_invalid_link(self):
        with self.assertRaises(TraceError):
            validate([event("a", "s1", 1, "tool_result", call_id="missing")])

    def test_overlapping_calls_are_unioned_and_usage_counted(self):
        rows = [event("a", "s1", 1, "fact", fact_key="x"),
                event("b", "s1", 2, "fact", fact_key="y"),
                event("c1", "s2", 1, "tool_call", timestamp="2026-01-01T00:00:00Z",
                      duration_ms=100, usage={"input_tokens": 2}),
                event("c2", "s2", 2, "tool_call", timestamp="2026-01-01T00:00:00.050Z",
                      duration_ms=100, usage={"input_tokens": 3}),
                event("d", "s2", 3, "fact", fact_key="x", source_event_ids=["c1"]),
                event("e", "s2", 4, "fact", fact_key="y", source_event_ids=["c2"])]
        report = analyze(rows)
        self.assertEqual(report["summary"]["observed_tool_calls"], 2)
        self.assertEqual(report["summary"]["observed_duration_ms"], 150)
        self.assertEqual(report["summary"]["usage"]["input_tokens"], 5)

    def test_duplicate_and_bad_reference(self):
        with self.assertRaises(TraceError):
            validate([event("a", "s1", 1, "tool_call"), event("a", "s2", 1, "tool_call")])
        with self.assertRaises(TraceError):
            validate([event("a", "s1", 1, "fact", fact_key="x", source_event_ids=["missing"])])

    def test_determinism(self):
        rows = [event("a", "s1", 1, "fact", fact_key="x"), event("b", "s2", 1, "fact", fact_key="x")]
        self.assertEqual(analyze(rows), analyze(rows))


if __name__ == "__main__":
    unittest.main()
