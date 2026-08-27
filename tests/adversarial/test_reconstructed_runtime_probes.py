from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((ROOT / "tests/adversarial/MANIFEST.json").read_text(encoding="utf-8"))
SCENARIOS = MANIFEST["scenarios"]


def parse_line(line: str):
    parts = line.strip().split("|")
    fields = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    if "observed" not in fields:
        return None
    raw = fields.get("issues", fields["observed"])
    return parts[0], set() if raw in {"none", "VALID"} else set(raw.split(","))


class ReconstructedRuntimeProbes(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.observed = {}
        ids = [item["id"] for item in SCENARIOS]
        if len(ids) != 62 or len(set(ids)) != 62:
            raise AssertionError("adversarial manifest must contain exactly 62 unique scenario IDs")
        if MANIFEST.get("recovered_scenario_count") != 62 or MANIFEST.get("unrecovered_scenario_count") != 0:
            raise AssertionError("adversarial recovery accounting must be 62 recovered / 0 unrecovered")
        for source in MANIFEST["source_provenance"]:
            proc = subprocess.run(
                [sys.executable, str(ROOT / source["candidate_path"])],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if proc.returncode != 0:
                raise AssertionError(f"round {source['round']} failed:\n{proc.stdout}\n{proc.stderr}")
            emitted = 0
            for line in proc.stdout.splitlines():
                parsed = parse_line(line)
                if parsed is None:
                    continue
                scenario_id, codes = parsed
                if scenario_id in cls.observed:
                    raise AssertionError(f"duplicate runtime scenario: {scenario_id}")
                cls.observed[scenario_id] = codes
                emitted += 1
            if emitted != source["scenario_count"]:
                raise AssertionError(f"round {source['round']} emitted {emitted} scenarios")
        if set(cls.observed) != set(ids):
            raise AssertionError("runtime scenario output differs from exact manifest inventory")


def make_test(entry):
    def test(self):
        actual = self.observed[entry["id"]]
        required = set(entry["expected_issue_codes"])
        self.assertTrue(required.issubset(actual), f"required={sorted(required)} observed={sorted(actual)}")
        if entry["expected_valid"]:
            self.assertEqual(set(), actual)
        else:
            self.assertTrue(actual, "invalid mutation was accepted")
    return test


for index, scenario in enumerate(SCENARIOS, start=1):
    safe_id = re.sub(r"[^a-z0-9_]+", "_", scenario["id"].casefold())
    setattr(ReconstructedRuntimeProbes, f"test_{index:02d}_{safe_id}", make_test(scenario))


if __name__ == "__main__":
    unittest.main()
