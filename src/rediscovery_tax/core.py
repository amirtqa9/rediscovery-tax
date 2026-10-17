"""Provider-neutral RediscoveryTax analysis."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Iterable


class TraceError(ValueError):
    """Invalid input trace or review file."""


def validate(events: Iterable[dict]) -> list[dict]:
    rows = list(events)
    seen: set[str] = set()
    last_seq: dict[str, int] = {}
    sessions: list[str] = []
    for line, event in enumerate(rows, 1):
        if not isinstance(event, dict) or event.get("schema_version") != 1:
            raise TraceError(f"event {line}: unsupported schema_version")
        for key in ("event_id", "session_id", "kind"):
            if not isinstance(event.get(key), str) or not event[key]:
                raise TraceError(f"event {line}: missing {key}")
        if event["kind"] not in {"tool_call", "tool_result", "fact"}:
            raise TraceError(f"event {line}: invalid kind")
        if not isinstance(event.get("seq"), int) or isinstance(event["seq"], bool):
            raise TraceError(f"event {line}: invalid seq")
        if event["event_id"] in seen:
            raise TraceError(f"event {line}: duplicate event_id {event['event_id']}")
        seen.add(event["event_id"])
        session = event["session_id"]
        if session not in sessions:
            sessions.append(session)
        if event["seq"] <= last_seq.get(session, -1):
            raise TraceError(f"event {line}: seq must increase within session")
        last_seq[session] = event["seq"]
        if event["kind"] == "fact":
            if not isinstance(event.get("fact_key"), str) or not event["fact_key"]:
                raise TraceError(f"event {line}: fact_key required")
            refs = event.get("source_event_ids", [])
            if not isinstance(refs, list) or any(not isinstance(x, str) for x in refs):
                raise TraceError(f"event {line}: invalid source_event_ids")
    by_id = {e["event_id"]: e for e in rows}
    for event in rows:
        for ref in event.get("source_event_ids", []):
            if ref not in by_id or by_id[ref]["session_id"] != event["session_id"]:
                raise TraceError(f"event {event['event_id']}: invalid source reference {ref}")
        if event["kind"] == "tool_result" and event.get("call_id") is not None:
            call = by_id.get(event["call_id"])
            if not call or call["kind"] != "tool_call" or call["session_id"] != event["session_id"]:
                raise TraceError(f"event {event['event_id']}: invalid call_id")
    return rows


def _signature(event: dict) -> tuple[str, str, str] | None:
    args = event.get("arguments") or {}
    if not isinstance(args, dict):
        return None
    path, symbol = args.get("path"), args.get("symbol")
    if isinstance(path, str) and isinstance(symbol, str) and path and symbol:
        return ("path_symbol", path, symbol)
    query, digest = args.get("query"), event.get("result_hash")
    if isinstance(query, str) and isinstance(digest, str) and query.strip() and digest:
        return ("query_hash", " ".join(query.lower().split()), digest)
    return None


def _duration(event: dict) -> int | None:
    value = event.get("duration_ms")
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None


def _metrics(call_ids: Iterable[str], by_id: dict[str, dict]) -> dict:
    calls = [by_id[call_id] for call_id in call_ids]
    durations = [_duration(call) for call in calls]
    intervals = []
    for call, duration in zip(calls, durations):
        try:
            start = datetime.fromisoformat(call["timestamp"].replace("Z", "+00:00"))
            if start.tzinfo is None or duration is None:
                intervals = []
                break
            intervals.append((start.timestamp() * 1000, start.timestamp() * 1000 + duration))
        except (KeyError, AttributeError, ValueError):
            intervals = []
            break
    if any(duration is None for duration in durations):
        elapsed = None
    elif intervals:
        elapsed = 0
        end = float("-inf")
        for start, stop in sorted(intervals):
            elapsed += max(0, stop - max(start, end))
            end = max(end, stop)
        elapsed = round(elapsed)
    else:
        elapsed = sum(durations)
    usage = {}
    for field in ("input_tokens", "output_tokens", "cost_usd"):
        values = [(call.get("usage") or {}).get(field) for call in calls]
        usage[field] = sum(values) if values and all(isinstance(v, (int, float)) and v >= 0 for v in values) else None
    return {"observed_duration_ms": elapsed, "usage": usage}


def _same_revision(a: dict, b: dict) -> bool:
    left, right = a.get("source_revision"), b.get("source_revision")
    return not (left and right and left != right)


def _not_expired(a: dict, b: dict) -> bool:
    until, later = a.get("valid_until"), b.get("timestamp")
    if not until or not later:
        return True
    try:
        return datetime.fromisoformat(later.replace("Z", "+00:00")) <= datetime.fromisoformat(until.replace("Z", "+00:00"))
    except ValueError:
        return False


def analyze(events: Iterable[dict], facts: Iterable[dict] = (), review: dict | None = None,
            min_confidence: str = "medium") -> dict:
    rows = validate([*events, *facts])
    if min_confidence not in {"high", "medium"}:
        raise TraceError("min_confidence must be high or medium")
    review = review or {}
    if not isinstance(review, dict):
        raise TraceError("review must be an object")
    session_order = {s: i for i, s in enumerate(dict.fromkeys(e["session_id"] for e in rows))}
    by_id = {e["event_id"]: e for e in rows}
    candidates = []
    for event in rows:
        if event["kind"] == "fact":
            candidates.append((event, ("fact_key", event["fact_key"]), "high"))
        elif event["kind"] == "tool_result":
            call = by_id.get(event.get("call_id"), {})
            enriched = {**call, **event, "arguments": event.get("arguments") or call.get("arguments")}
            sig = _signature(enriched)
            if sig:
                candidates.append((event, sig, "medium"))
    first: dict[tuple, dict] = {}
    findings = []
    counted_calls: set[str] = set()
    for event, key, confidence in candidates:
        previous = first.get(key)
        if previous is None:
            first[key] = event
            continue
        if session_order[event["session_id"]] <= session_order[previous["session_id"]]:
            continue
        if not _same_revision(previous, event) or not _not_expired(previous, event):
            first[key] = event
            continue
        finding_id = hashlib.sha256(f"{previous['event_id']}:{event['event_id']}".encode()).hexdigest()[:12]
        decision = review.get(finding_id, "same")
        if decision not in {"same", "different", "ignore"}:
            raise TraceError(f"invalid review decision for {finding_id}")
        if decision != "same" or (min_confidence == "high" and confidence != "high"):
            continue
        refs = event.get("source_event_ids", []) if event["kind"] == "fact" else [event["event_id"]]
        calls = [by_id[r] for r in refs if r in by_id and by_id[r]["kind"] == "tool_call"]
        if not calls and event["kind"] == "tool_result":
            call_id = event.get("call_id")
            if call_id in by_id and by_id[call_id]["kind"] == "tool_call":
                calls = [by_id[call_id]]
        unique_calls = list(dict.fromkeys(c["event_id"] for c in calls))
        metrics = _metrics(unique_calls, by_id)
        finding = {
            "finding_id": finding_id,
            "fact_key": event.get("fact_key", ":".join(key)),
            "first_event_id": previous["event_id"],
            "repeat_event_id": event["event_id"],
            "first_session_id": previous["session_id"],
            "repeat_session_id": event["session_id"],
            "match_basis": key[0],
            "confidence": confidence,
            "search_event_ids": unique_calls,
            "observed_tool_calls": len(unique_calls),
            "observed_duration_ms": metrics["observed_duration_ms"],
            "usage": metrics["usage"],
            "shared_attribution": any(c in counted_calls for c in unique_calls),
        }
        findings.append(finding)
        counted_calls.update(unique_calls)
    fingerprint = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    totals = _metrics(sorted(counted_calls), by_id)
    return {"schema_version": 1, "input_hash": fingerprint,
            "summary": {"findings": len(findings), "observed_tool_calls": len(counted_calls),
                        "observed_duration_ms": totals["observed_duration_ms"], "usage": totals["usage"]},
            "findings": findings}
