#!/usr/bin/env python3
"""Run the complete committed R6A binding suite with bounded accounting."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "fixtures" / "cgam-durable-binding" / "MANIFEST.json"
TEST_ROOT = ROOT / "tests"
if str(TEST_ROOT) not in sys.path:
    sys.path.insert(0, str(TEST_ROOT))

import r6a_scenario_registry  # noqa: E402  (requires TEST_ROOT on sys.path)


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    scenario_ids = manifest.get("scenario_ids")
    if (
        not isinstance(scenario_ids, list)
        or not scenario_ids
        or len(scenario_ids) != len(set(scenario_ids))
        or not all(isinstance(item, str) and item.startswith("R6A-") for item in scenario_ids)
    ):
        print("R6A fixture manifest scenario IDs are missing, duplicate, or malformed", file=sys.stderr)
        return 2
    if tuple(scenario_ids) != r6a_scenario_registry.EXPECTED_SCENARIO_IDS:
        print("R6A scenario registry and fixture manifest differ", file=sys.stderr)
        return 2
    suite = unittest.TestSuite()
    for pattern in (
        "test_cgam_durable_binding*.py",
        "test_verify_cgam_durable_binding_source.py",
    ):
        suite.addTests(unittest.defaultTestLoader.discover(str(TEST_ROOT), pattern=pattern))
    r6a_scenario_registry.reset_hits()
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    passed = result.testsRun - failures - errors - skipped
    accounting = r6a_scenario_registry.accounting()
    hits = accounting["hits"]
    missing = [item for item in scenario_ids if hits.get(item, 0) == 0]
    duplicate = sorted(item for item, count in hits.items() if count != 1)
    unknown = sorted(set(hits) - set(scenario_ids))
    exact_hits = sum(1 for item in scenario_ids if hits.get(item) == 1)
    accounting_failures = len(missing) + len(duplicate) + len(unknown)
    unrecovered = failures + errors + skipped + accounting_failures
    evidence = {
        "profile": "R6A_CGAM_DURABLE_BINDING_SUITE_RESULT_v0.1",
        "tests_run": result.testsRun,
        "tests_passed": passed,
        "failures": failures,
        "errors": errors,
        "skipped": skipped,
        "fixture_scenario_ids": len(scenario_ids),
        "scenario_exact_hits": exact_hits,
        "scenario_missing": missing,
        "scenario_duplicate_or_nonunit": duplicate,
        "scenario_unknown": unknown,
        "scenario_hit_counts": {item: hits.get(item, 0) for item in scenario_ids},
        "source_custody_suite_included": True,
        "unrecovered_r6a_probes": unrecovered,
    }
    passed_gate = result.wasSuccessful() and not skipped and accounting_failures == 0
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    print(
        "R6A_BINDING_SUITE "
        f"tests={passed}/{result.testsRun} scenarios={exact_hits}/{len(scenario_ids)} "
        f"unrecovered={evidence['unrecovered_r6a_probes']} pass={int(passed_gate)}"
    )
    return 0 if passed_gate else 1


if __name__ == "__main__":
    raise SystemExit(main())
