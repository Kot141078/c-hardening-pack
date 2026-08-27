#!/usr/bin/env python3
"""Run and audit the exactly reconstructed 62-scenario R1 suite."""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "adversarial" / "MANIFEST.json"


def parse_line(line: str) -> tuple[str, set[str]] | None:
    parts = line.strip().split("|")
    if len(parts) < 2 or parts[0].endswith("_PROBES pass="):
        return None
    fields = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    if "observed" not in fields:
        return None
    observed = fields["observed"]
    codes = set() if observed in {"none", "VALID"} else set(observed.split(","))
    if "issues" in fields:
        codes = set() if fields["issues"] == "none" else set(fields["issues"].split(","))
    return parts[0], codes


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    scenarios = manifest["scenarios"]
    ids = [item["id"] for item in scenarios]
    failures: list[str] = []
    if len(scenarios) != 62 or manifest.get("recovered_scenario_count") != 62 or manifest.get("unrecovered_scenario_count") != 0:
        failures.append("manifest must declare recovered=62 and unrecovered=0")
    duplicates = sorted(item for item, count in Counter(ids).items() if count > 1)
    if duplicates:
        failures.append(f"duplicate scenario IDs: {duplicates}")
    expected = {item["id"]: item for item in scenarios}
    observed: dict[str, set[str]] = {}
    for source in manifest["source_provenance"]:
        round_number = source["round"]
        path = ROOT / source["candidate_path"]
        proc = subprocess.run(
            [sys.executable, str(path)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            failures.append(f"round {round_number} exited {proc.returncode}: {proc.stderr.strip()}")
        round_ids = []
        for line in proc.stdout.splitlines():
            parsed = parse_line(line)
            if parsed is None:
                continue
            scenario_id, codes = parsed
            if scenario_id in observed:
                failures.append(f"duplicate runtime scenario output: {scenario_id}")
            observed[scenario_id] = codes
            round_ids.append(scenario_id)
        if len(round_ids) != source["scenario_count"]:
            failures.append(f"round {round_number} emitted {len(round_ids)} scenarios, expected {source['scenario_count']}")
    missing = sorted(set(expected) - set(observed))
    extra = sorted(set(observed) - set(expected))
    if missing or extra:
        failures.append(f"scenario inventory mismatch missing={missing} extra={extra}")
    for scenario_id, entry in expected.items():
        if scenario_id not in observed:
            continue
        required = set(entry["expected_issue_codes"])
        actual = observed[scenario_id]
        if not required.issubset(actual):
            failures.append(f"{scenario_id}: required={sorted(required)} observed={sorted(actual)}")
        if entry["expected_valid"] is True and actual:
            failures.append(f"{scenario_id}: positive control emitted issues {sorted(actual)}")
        if entry["expected_valid"] is False and not actual:
            failures.append(f"{scenario_id}: invalid mutation was accepted")
    print(f"RUNTIME_ADVERSARIAL_R1 scenarios=62 recovered=62 unrecovered=0 pass={62 - len(failures)} fail={len(failures)}")
    for failure in failures:
        print(failure, file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
