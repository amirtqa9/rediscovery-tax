"""Import a local tool-trace JSONL export without copying raw content.

Accepted source rows use ``type`` (``call``, ``result``, or ``fact``), ``id``,
``session``, and an increasing integer ``seq`` per session. Calls may contain
``args`` with ``path``, ``symbol``, and ``query``; results may contain ``output``
and ``call_id``; facts may contain ``fact_key``, ``claim``, and ``source_ids``.
All other source fields are ignored unless explicitly copied below.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Iterable

from .core import TraceError, validate


_HASH = re.compile(r"^[0-9a-f]{64}$")
_KINDS = {"call": "tool_call", "result": "tool_result", "fact": "fact"}


def _fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _text(row: dict, key: str, index: int) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not value:
        raise TraceError(f"source row {index}: {key} must be a nonempty string")
    return value


def _normalize_row(row: dict, index: int) -> dict:
    if not isinstance(row, dict):
        raise TraceError(f"source row {index}: expected an object")
    kind = _KINDS.get(row.get("type"))
    if kind is None:
        raise TraceError(f"source row {index}: type must be call, result, or fact")
    event = {
        "schema_version": 1,
        "event_id": _text(row, "id", index),
        "session_id": _text(row, "session", index),
        "seq": row.get("seq"),
        "kind": kind,
    }
    for source, target in (("time", "timestamp"), ("duration_ms", "duration_ms"),
                           ("source_revision", "source_revision"), ("valid_until", "valid_until")):
        if source in row:
            event[target] = row[source]
    if kind == "tool_call":
        if "tool" in row:
            tool = row["tool"]
            if not isinstance(tool, str):
                raise TraceError(f"source row {index}: tool must be a string")
            event["tool"] = tool if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", tool) else _fingerprint(tool)
        args = row.get("args", {})
        if not isinstance(args, dict):
            raise TraceError(f"source row {index}: args must be an object")
        kept = {}
        for key in ("path", "symbol", "query"):
            value = args.get(key)
            if value is not None:
                if not isinstance(value, str):
                    raise TraceError(f"source row {index}: args.{key} must be a string")
                kept[key] = _fingerprint(value)
        if kept:
            event["arguments"] = kept
        if "usage" in row:
            usage = row["usage"]
            if not isinstance(usage, dict):
                raise TraceError(f"source row {index}: usage must be an object")
            event["usage"] = {key: usage[key] for key in ("input_tokens", "output_tokens", "cost_usd")
                              if key in usage}
    elif kind == "tool_result":
        event["call_id"] = _text(row, "call_id", index)
        if "output" in row:
            value = row["output"]
            if not isinstance(value, str):
                raise TraceError(f"source row {index}: output must be a string")
            event["result_hash"] = hashlib.sha256(value.encode("utf-8")).hexdigest()
        elif "result_hash" in row:
            value = row["result_hash"]
            if not isinstance(value, str) or not _HASH.fullmatch(value):
                raise TraceError(f"source row {index}: result_hash must be a SHA-256 hex digest")
            event["result_hash"] = value
    else:
        event["fact_key"] = _fingerprint(_text(row, "fact_key", index))
        refs = row.get("source_ids", [])
        if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
            raise TraceError(f"source row {index}: source_ids must be a list of IDs")
        event["source_event_ids"] = refs
    return event


def import_trace(rows: Iterable[dict]) -> list[dict]:
    """Return validated native events with content and arguments redacted."""
    events = [_normalize_row(row, index) for index, row in enumerate(rows, 1)]
    return validate(events)


def import_trace_file(source: Path, destination: Path) -> int:
    """Stream a JSONL import to an atomic output file, using disk for the ID index.

    Memory use is proportional to one source line, one normalized event, and
    SQLite's bounded cache, rather than the trace length. Raw prompt and result
    bodies never enter the index or output file. Forward references are checked
    after the entire trace has been read.
    """
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise TraceError("source and output paths must differ")
    temporary: Path | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="rediscovery-tax-index-") as index_dir:
            with sqlite3.connect(Path(index_dir) / "events.sqlite") as db:
                db.execute("CREATE TABLE events (id TEXT PRIMARY KEY, session TEXT NOT NULL, kind TEXT NOT NULL)")
                db.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY, last_seq INTEGER NOT NULL)")
                db.execute("CREATE TABLE refs (origin TEXT NOT NULL, target TEXT NOT NULL, relation TEXT NOT NULL)")
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                                 prefix=f".{destination.name}.", suffix=".tmp",
                                                 delete=False) as output:
                    temporary = Path(output.name)
                    count = 0
                    with source.open(encoding="utf-8") as stream:
                        for line_number, line in enumerate(stream, 1):
                            if not line.strip():
                                continue
                            try:
                                row = json.loads(line)
                            except json.JSONDecodeError as exc:
                                raise TraceError(f"{source}:{line_number}: {exc.msg}") from exc
                            event = _normalize_row(row, line_number)
                            identifier, session, seq = event["event_id"], event["session_id"], event["seq"]
                            if not isinstance(seq, int) or isinstance(seq, bool):
                                raise TraceError(f"event {line_number}: invalid seq")
                            previous = db.execute("SELECT last_seq FROM sessions WHERE id = ?", (session,)).fetchone()
                            if seq <= (previous[0] if previous else -1):
                                raise TraceError(f"event {line_number}: seq must increase within session")
                            try:
                                db.execute("INSERT INTO events VALUES (?, ?, ?)", (identifier, session, event["kind"]))
                            except sqlite3.IntegrityError as exc:
                                raise TraceError(f"event {line_number}: duplicate event_id {identifier}") from exc
                            db.execute("INSERT INTO sessions VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET last_seq=excluded.last_seq",
                                       (session, seq))
                            if event["kind"] == "tool_result":
                                db.execute("INSERT INTO refs VALUES (?, ?, 'call')", (identifier, event["call_id"]))
                            elif event["kind"] == "fact":
                                db.executemany("INSERT INTO refs VALUES (?, ?, 'source')",
                                               ((identifier, ref) for ref in event["source_event_ids"]))
                            output.write(json.dumps(event, sort_keys=True) + "\n")
                            count += 1
                    for origin, target, relation, origin_session, target_session, target_kind in db.execute(
                        "SELECT r.origin, r.target, r.relation, e.session, t.session, t.kind "
                        "FROM refs r JOIN events e ON e.id = r.origin LEFT JOIN events t ON t.id = r.target "
                        "ORDER BY r.rowid"
                    ):
                        if relation == "call":
                            if target_kind != "tool_call" or target_session != origin_session:
                                raise TraceError(f"event {origin}: invalid call_id")
                        elif target_session != origin_session:
                            raise TraceError(f"event {origin}: invalid source reference {target}")
            os.replace(temporary, destination)
            temporary = None
            return count
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
