from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


class RuntimeIntegrityR2ClosureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        cls.interval_probe = cls.load_module(
            "runtime_integrity_r2_interval_test",
            cls.root / "tests/adversarial/probes/r2_interval.py",
        )
        cls.runner = cls.load_module(
            "runtime_integrity_r2_runner_test",
            cls.root / "tools/run_runtime_adversarial_suite.py",
        )
        cls.action_pins = cls.load_module(
            "runtime_integrity_r2_action_pins_test",
            cls.root / "tools/verify_github_actions_pins.py",
        )

    @staticmethod
    def load_module(name: str, path: Path):
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def test_r2_c1_linked_witness_interval_excludes_attempt(self) -> None:
        mutation = json.loads(self.interval_probe.MUTATION_PATH.read_text(encoding="utf-8"))
        codes = self.interval_probe.evaluate_window(mutation["observation_window"])
        self.assertIn("non_effect_witness_interval_excludes_attempt", codes)

    def test_r2_c1_interval_boundaries_are_inclusive(self) -> None:
        equal_start = {
            "start": "2026-08-27T10:03:00+02:00",
            "end": "2026-08-27T10:03:30+02:00",
        }
        longer_window = {
            "start": "2026-08-27T10:02:30+02:00",
            "end": "2026-08-27T10:03:30+02:00",
        }
        self.assertEqual(set(), self.interval_probe.evaluate_window(equal_start))
        self.assertEqual(set(), self.interval_probe.evaluate_window(longer_window))

    def test_r2_c1_submicrosecond_order_is_exact(self) -> None:
        attempt = "2026-08-27T10:03:00.0000004+02:00"
        later_start = {
            "start": "2026-08-27T10:03:00.0000005+02:00",
            "end": "2026-08-27T10:03:01+02:00",
        }
        self.assertIn(
            "non_effect_witness_interval_excludes_attempt",
            self.interval_probe.evaluate_window(later_start, attempt),
        )
        validator = self.interval_probe.load_validator()
        self.assertLess(
            validator.parse_timestamp(attempt),
            validator.parse_timestamp(later_start["start"]),
        )

    def test_r2_c2_unique_failed_scenario_count_is_not_diagnostic_count(self) -> None:
        real_run = self.runner.subprocess.run

        def controlled_run(*args, **kwargs):
            result = real_run(*args, **kwargs)
            if args and "round_1.py" in str(args[0][-1]):
                lines = result.stdout.splitlines()
                lines[0] = (
                    "commit_duplicate_missing_preconditions|expected=INVALID|"
                    "observed=VALID|issues=none"
                )
                return subprocess.CompletedProcess(
                    result.args,
                    result.returncode,
                    stdout="\n".join(lines) + "\n",
                    stderr=result.stderr,
                )
            return result

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(self.runner.subprocess, "run", side_effect=controlled_run),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            return_code = self.runner.main()

        self.assertEqual(1, return_code)
        self.assertIn(
            "scenarios=62 recovered=62 unrecovered=0 pass=61 fail=1 "
            "failed_scenarios=1 diagnostic_count=2",
            stdout.getvalue(),
        )
        self.assertIn(
            "category=CONSEQUENCE_GRAPH scenarios=12 pass=11 fail=1",
            stdout.getvalue(),
        )
        self.assertEqual(2, len([line for line in stderr.getvalue().splitlines() if line]))

    def test_r2_c3_all_external_actions_are_verified_immutable_shas(self) -> None:
        issues, workflow_count, external_refs = self.action_pins.audit_repository()
        self.assertEqual([], issues)
        self.assertEqual(2, workflow_count)
        self.assertEqual(5, external_refs)

    def test_r2_c3_mutable_and_malformed_action_refs_fail_closed(self) -> None:
        bad_refs = (
            "actions/checkout@v4",
            "actions/checkout@main",
            "actions/checkout@" + "a" * 39,
            "actions/checkout@" + "a" * 41,
        )
        for bad_ref in bad_refs:
            text = f"# actions/checkout source run 1\n- uses: {bad_ref}\n"
            with self.subTest(ref=bad_ref):
                issues, _ = self.action_pins.validate_workflow_text(text)
                self.assertTrue(issues)
        quoted_issues, _ = self.action_pins.validate_workflow_text(
            '# actions/checkout source run 1\n- "uses": actions/checkout@v4\n'
        )
        unknown_issues, _ = self.action_pins.validate_workflow_text(
            '# evil/example source run 1\n- "uses": evil/example@main\n'
        )
        flow_issues, _ = self.action_pins.validate_workflow_text(
            "# evil/example source run 1\n- { uses : evil/example@main }\n"
        )
        nonfirst_flow_issues, _ = self.action_pins.validate_workflow_text(
            "# evil/example source run 1\n- { name: Evil, uses: evil/example@main }\n"
        )
        escaped_key_issues, _ = self.action_pins.validate_workflow_text(
            '# evil/example source run 1\n- "u\\u0073es": evil/example@main\n'
        )
        explicit_key_issues, _ = self.action_pins.validate_workflow_text(
            "# evil/example source run 1\n- ? uses\n  : evil/example@main\n"
        )
        nested_before_external_issues, _ = self.action_pins.validate_workflow_text(
            "# evil/example source run 1\n"
            "- { name: Evil, with: { uses: ./local }, uses: evil/example@main }\n"
        )
        alias_key_issues, _ = self.action_pins.validate_workflow_text(
            "action_key: &action_key uses\n"
            "# evil/example source run 1\n- *action_key: evil/example@main\n"
        )
        adjacent_alias_key_issues, _ = self.action_pins.validate_workflow_text(
            "strategy: { matrix: { key: [&k uses] } }\n"
            "steps: [{*k: evil/example@main}]\n"
        )
        self.assertTrue(quoted_issues)
        self.assertTrue(unknown_issues)
        self.assertTrue(flow_issues)
        self.assertTrue(nonfirst_flow_issues)
        self.assertTrue(escaped_key_issues)
        self.assertTrue(explicit_key_issues)
        self.assertTrue(nested_before_external_issues)
        self.assertTrue(alias_key_issues)
        self.assertTrue(adjacent_alias_key_issues)
        local_issues, local_seen = self.action_pins.validate_workflow_text(
            "- uses: ./local-action\n"
        )
        self.assertEqual([], local_issues)
        self.assertEqual(set(), local_seen)

    def test_historical_62_ids_remain_unchanged_and_r2_is_separate(self) -> None:
        manifest = json.loads(
            (self.root / "tests/adversarial/MANIFEST.json").read_text(encoding="utf-8")
        )
        historical_ids = [item["id"] for item in manifest["scenarios"]]
        r2_ids = [item["id"] for item in manifest["r2_closure_scenarios"]]
        self.assertEqual(62, len(historical_ids))
        self.assertEqual(62, len(set(historical_ids)))
        self.assertEqual(
            ["r2_c1_non_effect_witness_interval_excludes_attempt"],
            r2_ids,
        )


if __name__ == "__main__":
    unittest.main()
