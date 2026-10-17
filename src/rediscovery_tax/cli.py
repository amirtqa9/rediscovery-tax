"""Command-line interface for RediscoveryTax."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import TraceError, analyze, validate
from .importer import import_trace_file


def _jsonl(path: str) -> list[dict]:
    rows = []
    with Path(path).open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise TraceError(f"{path}:{number}: {exc.msg}") from exc
    return rows


def _markdown(report: dict) -> str:
    lines = ["# RediscoveryTax report", "", f"Repeated discoveries: {report['summary']['findings']}", "",
             "| Fact | Earlier event | Later event | Calls | Confidence |", "| --- | --- | --- | ---: | --- |"]
    for finding in report["findings"]:
        cells = [str(finding[key]).replace("|", "\\|") for key in
                 ("fact_key", "first_event_id", "repeat_event_id", "observed_tool_calls", "confidence")]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rediscovery-tax")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("validate")
    check.add_argument("trace")
    import_cmd = commands.add_parser("import", help="redact and normalize a local tool-trace JSONL export")
    import_cmd.add_argument("source", help="JSONL rows with type, id, session, seq; call args, result output, or fact key")
    import_cmd.add_argument("--out", required=True, help="destination for redacted native JSONL events")
    analyze_cmd = commands.add_parser("analyze")
    analyze_cmd.add_argument("trace")
    analyze_cmd.add_argument("--facts")
    analyze_cmd.add_argument("--review")
    analyze_cmd.add_argument("--format", choices=("json", "md"), default="json")
    analyze_cmd.add_argument("--out")
    analyze_cmd.add_argument("--min-confidence", choices=("high", "medium"), default="medium")
    explain = commands.add_parser("explain")
    explain.add_argument("report")
    explain.add_argument("finding_id")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            rows = validate(_jsonl(args.trace))
            print(f"valid: {len(rows)} events")
            return 0
        if args.command == "import":
            count = import_trace_file(Path(args.source), Path(args.out))
            print(f"imported: {count} redacted events")
            return 0
        if args.command == "explain":
            report = json.loads(Path(args.report).read_text(encoding="utf-8"))
            finding = next((f for f in report["findings"] if f["finding_id"] == args.finding_id), None)
            if finding is None:
                raise TraceError(f"finding not found: {args.finding_id}")
            print(json.dumps(finding, indent=2, sort_keys=True))
            return 0
        facts = _jsonl(args.facts) if args.facts else []
        review = json.loads(Path(args.review).read_text(encoding="utf-8")) if args.review else None
        report = analyze(_jsonl(args.trace), facts, review, args.min_confidence)
        output = _markdown(report) if args.format == "md" else json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.out:
            Path(args.out).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"rediscovery-tax: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
