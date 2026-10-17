# RediscoveryTax

RediscoveryTax finds facts that were discovered again in a later session and reports the observed tool calls, time, and available usage. Findings link the earlier and later events; missing measurements remain unknown rather than becoming zero.

## Install

Requires Python 3.11 or newer. From this repository:

```sh
python3 -m pip install -e .
```

## Use

```sh
rediscovery-tax import raw-trace.jsonl --out events.jsonl
rediscovery-tax validate events.jsonl
rediscovery-tax analyze events.jsonl --format json --out report.json
rediscovery-tax explain report.json FINDING_ID
```

The importer accepts local JSONL rows with `type` (`call`, `result`, or `fact`), `id`, `session`, and increasing `seq` values. It hashes fact keys and selected arguments, omits raw prompts and results, validates references, and writes output atomically. `analyze` also accepts `--review` overrides and Markdown output. Processing stays local.

Run the tests with `PYTHONPATH=src python3 -m unittest discover -s tests -q`.
