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
    historical_total = len(scenarios)
    historical_ids = set(ids)
    raw_r2_scenarios = manifest.get("r2_closure_scenarios", [])
    r2_scenarios = raw_r2_scenarios if isinstance(raw_r2_scenarios, list) else []
    r2_ids = {
        item.get("id")
        for item in r2_scenarios
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    raw_r3_scenarios = manifest.get("r3_medium_scenarios", [])
    r3_scenarios = raw_r3_scenarios if isinstance(raw_r3_scenarios, list) else []
    r3_ids = {
        item.get("id")
        for item in r3_scenarios
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    diagnostics: list[tuple[set[str], str]] = []
    structural_diagnostics: list[str] = []
    historical_failed_ids: set[str] = set()
    r2_failed_ids: set[str] = set()
    r3_failed_ids: set[str] = set()

    def record_diagnostic(
        message: str,
        affected_ids: set[str],
        *,
        group: str = "R1",
        structural: bool = False,
    ) -> None:
        affected = set(affected_ids)
        diagnostics.append((affected, message))
        if structural or not affected:
            structural_diagnostics.append(message)
        {
            "R1": historical_failed_ids,
            "R2": r2_failed_ids,
            "R3": r3_failed_ids,
        }[group].update(affected)

    if len(scenarios) != 62 or manifest.get("recovered_scenario_count") != 62 or manifest.get("unrecovered_scenario_count") != 0:
        record_diagnostic("manifest must declare recovered=62 and unrecovered=0", set(), structural=True)
    duplicates = sorted(item for item, count in Counter(ids).items() if count > 1)
    if duplicates:
        record_diagnostic(f"duplicate scenario IDs: {duplicates}", set(duplicates))
    all_declared_ids = [*ids, *r2_ids, *r3_ids]
    cross_inventory_duplicates = sorted(
        scenario_id
        for scenario_id, count in Counter(all_declared_ids).items()
        if count > 1
    )
    if cross_inventory_duplicates:
        record_diagnostic(
            "scenario IDs must be globally unique across R1, R2, and R3 inventories: "
            f"{cross_inventory_duplicates}",
            set(),
            structural=True,
        )
    expected = {item["id"]: item for item in scenarios}
    categories = manifest.get("category_scenarios")
    if not isinstance(categories, dict) or not categories:
        record_diagnostic("manifest must declare non-empty category_scenarios", set(), structural=True)
        categories = {}
    category_ids = [
        scenario_id
        for values in categories.values()
        if isinstance(values, list)
        for scenario_id in values
    ]
    duplicate_category_ids = sorted(item for item, count in Counter(category_ids).items() if count > 1)
    if duplicate_category_ids or set(category_ids) != set(ids):
        record_diagnostic(
            "category inventory mismatch "
            f"duplicates={duplicate_category_ids} missing={sorted(set(ids) - set(category_ids))} "
            f"extra={sorted(set(category_ids) - set(ids))}",
            set(),
            structural=True,
        )
    observed: dict[str, set[str]] = {}
    for source in manifest["source_provenance"]:
        round_number = source["round"]
        round_expected_ids = {
            item["id"] for item in scenarios if item["round"] == round_number
        }
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
            record_diagnostic(
                f"round {round_number} exited {proc.returncode}: {proc.stderr.strip()}",
                round_expected_ids,
            )
        elif proc.stderr.strip():
            record_diagnostic(
                f"round {round_number} emitted unexpected stderr: {proc.stderr.strip()}",
                set(),
                structural=True,
            )
        round_ids = []
        for line in proc.stdout.splitlines():
            parsed = parse_line(line)
            if parsed is None:
                continue
            scenario_id, codes = parsed
            if scenario_id in observed:
                record_diagnostic(f"duplicate runtime scenario output: {scenario_id}", {scenario_id})
            if scenario_id not in expected:
                record_diagnostic(
                    f"unexpected runtime scenario output in round {round_number}: {scenario_id}",
                    set(),
                    structural=True,
                )
            observed[scenario_id] = codes
            round_ids.append(scenario_id)
        if len(round_ids) != source["scenario_count"]:
            record_diagnostic(
                f"round {round_number} emitted {len(round_ids)} scenarios, expected {source['scenario_count']}",
                round_expected_ids,
            )
    missing = sorted(set(expected) - set(observed))
    extra = sorted(set(observed) - set(expected))
    if missing or extra:
        record_diagnostic(
            f"scenario inventory mismatch missing={missing} extra={extra}",
            set(missing) or historical_ids,
        )
    for scenario_id, entry in expected.items():
        if scenario_id not in observed:
            continue
        required = set(entry["expected_issue_codes"])
        actual = observed[scenario_id]
        if not required.issubset(actual):
            record_diagnostic(
                f"{scenario_id}: required={sorted(required)} observed={sorted(actual)}",
                {scenario_id},
            )
        if entry["expected_valid"] is True and actual:
            record_diagnostic(
                f"{scenario_id}: positive control emitted issues {sorted(actual)}",
                {scenario_id},
            )
        if entry["expected_valid"] is False and not actual:
            record_diagnostic(f"{scenario_id}: invalid mutation was accepted", {scenario_id})

    r2_observed: dict[str, set[str]] = {}
    if not isinstance(raw_r2_scenarios, list) or not r2_scenarios or len(r2_ids) != len(r2_scenarios):
        record_diagnostic(
            "manifest must declare unique non-empty r2_closure_scenarios",
            set(),
            group="R2",
            structural=True,
        )
    else:
        for entry in r2_scenarios:
            scenario_id = entry["id"]
            proc = subprocess.run(
                [sys.executable, str(ROOT / entry["candidate_path"])],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if proc.returncode != 0:
                record_diagnostic(
                    f"R2 scenario {scenario_id} exited {proc.returncode}: {proc.stderr.strip()}",
                    {scenario_id},
                    group="R2",
                )
            elif proc.stderr.strip():
                record_diagnostic(
                    f"R2 scenario {scenario_id} emitted unexpected stderr: {proc.stderr.strip()}",
                    set(),
                    group="R2",
                    structural=True,
                )
            emitted = [parsed for line in proc.stdout.splitlines() if (parsed := parse_line(line)) is not None]
            if len(emitted) != 1 or emitted[0][0] != scenario_id:
                record_diagnostic(
                    f"R2 scenario output mismatch for {scenario_id}: {emitted}",
                    {scenario_id},
                    group="R2",
                )
                continue
            _, actual = emitted[0]
            r2_observed[scenario_id] = actual
            required = set(entry["expected_issue_codes"])
            if not required.issubset(actual):
                record_diagnostic(
                    f"{scenario_id}: required={sorted(required)} observed={sorted(actual)}",
                    {scenario_id},
                    group="R2",
                )
            if entry["expected_valid"] is True and actual:
                record_diagnostic(
                    f"{scenario_id}: positive control emitted issues {sorted(actual)}",
                    {scenario_id},
                    group="R2",
                )
            if entry["expected_valid"] is False and not actual:
                record_diagnostic(
                    f"{scenario_id}: invalid mutation was accepted",
                    {scenario_id},
                    group="R2",
                )

    r3_observed: dict[str, set[str]] = {}
    if not isinstance(raw_r3_scenarios, list) or not r3_scenarios or len(r3_ids) != len(r3_scenarios):
        record_diagnostic(
            "manifest must declare unique non-empty r3_medium_scenarios",
            set(),
            group="R3",
            structural=True,
        )
    else:
        for entry in r3_scenarios:
            scenario_id = entry["id"]
            proc = subprocess.run(
                [sys.executable, str(ROOT / entry["candidate_path"])],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if proc.returncode != 0:
                record_diagnostic(
                    f"R3 scenario {scenario_id} exited {proc.returncode}: {proc.stderr.strip()}",
                    {scenario_id},
                    group="R3",
                )
            elif proc.stderr.strip():
                record_diagnostic(
                    f"R3 scenario {scenario_id} emitted unexpected stderr: {proc.stderr.strip()}",
                    set(),
                    group="R3",
                    structural=True,
                )
            emitted = [parsed for line in proc.stdout.splitlines() if (parsed := parse_line(line)) is not None]
            if len(emitted) != 1 or emitted[0][0] != scenario_id:
                record_diagnostic(
                    f"R3 scenario output mismatch for {scenario_id}: {emitted}",
                    {scenario_id},
                    group="R3",
                )
                continue
            _, actual = emitted[0]
            r3_observed[scenario_id] = actual
            required = set(entry["expected_issue_codes"])
            if not required.issubset(actual):
                record_diagnostic(
                    f"{scenario_id}: required={sorted(required)} observed={sorted(actual)}",
                    {scenario_id},
                    group="R3",
                )
            if entry["expected_valid"] is True and actual:
                record_diagnostic(
                    f"{scenario_id}: positive control emitted issues {sorted(actual)}",
                    {scenario_id},
                    group="R3",
                )
            if entry["expected_valid"] is False and not actual:
                record_diagnostic(
                    f"{scenario_id}: invalid mutation was accepted",
                    {scenario_id},
                    group="R3",
                )

    for category in sorted(categories):
        values = categories[category]
        if not isinstance(values, list):
            record_diagnostic(
                f"category {category!r} must be a scenario-ID array",
                set(),
                structural=True,
            )
            continue
        category_failures = len(set(values) & historical_failed_ids)
        print(
            f"RUNTIME_ADVERSARIAL_CATEGORY category={category} scenarios={len(values)} "
            f"pass={len(values) - category_failures} fail={category_failures}"
        )
    historical_failed_count = len(historical_failed_ids & historical_ids)
    historical_diagnostic_count = sum(
        1 for affected, _ in diagnostics if affected & historical_ids
    )
    print(
        f"RUNTIME_ADVERSARIAL_R1 scenarios={historical_total} "
        f"recovered={manifest.get('recovered_scenario_count')} "
        f"unrecovered={manifest.get('unrecovered_scenario_count')} "
        f"pass={historical_total - historical_failed_count} fail={historical_failed_count} "
        f"failed_scenarios={historical_failed_count} diagnostic_count={historical_diagnostic_count}"
    )
    r2_failed_count = len(r2_failed_ids & r2_ids)
    r2_diagnostic_count = sum(1 for affected, _ in diagnostics if affected & r2_ids)
    print(
        f"RUNTIME_ADVERSARIAL_R2 scenarios={len(r2_ids)} "
        f"pass={len(r2_ids) - r2_failed_count} fail={r2_failed_count} "
        f"failed_scenarios={r2_failed_count} diagnostic_count={r2_diagnostic_count}"
    )
    r3_failed_count = len(r3_failed_ids & r3_ids)
    r3_diagnostic_count = sum(1 for affected, _ in diagnostics if affected & r3_ids)
    print(
        f"RUNTIME_ADVERSARIAL_R3 scenarios={len(r3_ids)} "
        f"pass={len(r3_ids) - r3_failed_count} fail={r3_failed_count} "
        f"failed_scenarios={r3_failed_count} diagnostic_count={r3_diagnostic_count}"
    )
    total_failed_ids = (
        (historical_failed_ids & historical_ids)
        | (r2_failed_ids & r2_ids)
        | (r3_failed_ids & r3_ids)
    )
    total_scenarios = historical_total + len(r2_ids) + len(r3_ids)
    print(
        f"RUNTIME_ADVERSARIAL_TOTAL scenarios={total_scenarios} "
        f"pass={total_scenarios - len(total_failed_ids)} "
        f"failed_scenarios={len(total_failed_ids)} diagnostic_count={len(diagnostics)} "
        f"structural_diagnostics={len(structural_diagnostics)}"
    )
    for _, diagnostic in diagnostics:
        print(diagnostic, file=sys.stderr)
    return 0 if not diagnostics else 1


if __name__ == "__main__":
    raise SystemExit(main())
