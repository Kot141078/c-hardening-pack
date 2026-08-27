from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class RuntimeIntegrityR3ClosureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        cls.validator = cls.load_module(
            "runtime_integrity_r3_validator_test",
            cls.root / "tools/validate_runtime_integrity_extension.py",
        )
        cls.runner = cls.load_module(
            "runtime_integrity_r3_runner_test",
            cls.root / "tools/run_runtime_adversarial_suite.py",
        )

    @staticmethod
    def load_module(name: str, path: Path):
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def load_fixture(self, relative: str):
        return json.loads(
            (self.root / "fixtures/runtime-integrity" / relative).read_text(encoding="utf-8")
        )

    def evidence_issues(self, witness: dict, overrides: dict[str, dict]) -> set[str]:
        manifest = self.load_fixture("MANIFEST.json")
        registry = copy.deepcopy(manifest["evidence_registry"])
        original_load = self.validator.load_json
        resolved_overrides = {
            (self.root / relative).resolve(): copy.deepcopy(value)
            for relative, value in overrides.items()
        }
        for entry in registry.values():
            path = (self.root / entry["path"]).resolve()
            if path in resolved_overrides:
                entry["hash"] = self.validator.jcs_sha256(resolved_overrides[path])
        inventory_path = (
            self.root / "fixtures/runtime-integrity/evidence/non_effect_scope_inventory_42.json"
        ).resolve()
        if inventory_path in resolved_overrides:
            witness["scope_inventory_hash"] = self.validator.jcs_sha256(
                resolved_overrides[inventory_path]
            )

        def controlled_load(path: Path):
            resolved = Path(path).resolve()
            if resolved in resolved_overrides:
                return copy.deepcopy(resolved_overrides[resolved])
            return original_load(path)

        with mock.patch.object(self.validator, "load_json", side_effect=controlled_load):
            return {
                item.code
                for item in self.validator.validate_registered_evidence(witness, registry)
            }

    def test_r3_positive_closure_states_are_exact(self) -> None:
        witness = self.load_fixture("positive/non_effect_witness_valid.json")
        commit = self.load_fixture("positive/consequence_commit_denied_valid.json")
        carry = self.load_fixture("positive/continuity_carry_cost_profile.json")
        self.assertNotIn(
            "duplicate_logical_observation_coordinate",
            {item.code for item in self.validator.semantic_non_effect(witness)},
        )
        self.assertEqual(witness["gate_record_ref"], witness["attempt_ref"])
        self.assertEqual(
            self.validator.NOT_BOUND_COMMIT_CLAIM_BOUNDARY,
            commit["claim_boundary"],
        )
        self.assertEqual([], self.validator.semantic_carry_cost(carry))

    def test_r3_m01_logical_coordinate_ignores_id_and_kind_aliases(self) -> None:
        witness = self.load_fixture("positive/non_effect_witness_valid.json")
        witness["observation_surfaces"][1]["target_ref"] = witness["observation_surfaces"][0]["target_ref"]
        witness["observation_surfaces"][1]["target_coordinate"] = witness["observation_surfaces"][0]["target_coordinate"]
        witness["observation_surfaces"][1]["hash_domain"] = witness["observation_surfaces"][0]["hash_domain"]
        codes = {item.code for item in self.validator.semantic_non_effect(witness)}
        self.assertIn("duplicate_logical_observation_coordinate", codes)

    def test_r3_m01_inventory_binds_exact_descriptors_but_not_order(self) -> None:
        witness = self.load_fixture("positive/non_effect_witness_valid.json")
        inventory_rel = "fixtures/runtime-integrity/evidence/non_effect_scope_inventory_42.json"
        inventory = json.loads((self.root / inventory_rel).read_text(encoding="utf-8"))
        inventory["observation_surface_descriptors"].reverse()
        codes = self.evidence_issues(copy.deepcopy(witness), {inventory_rel: inventory})
        self.assertNotIn("non_effect_scope_inventory_mismatch", codes)

        inventory["observation_surface_descriptors"].append(
            {
                "surface_id": "alias-surface",
                "surface_kind": "FILESYSTEM",
                "target_ref": "endpoint:A",
                "target_coordinate": "endpoint:A/deployment-api",
                "hash_domain": "CANONICAL_STATE_SHA256_V1",
            }
        )
        codes = self.evidence_issues(copy.deepcopy(witness), {inventory_rel: inventory})
        self.assertIn("non_effect_scope_inventory_mismatch", codes)

    def test_r3_m02_attempt_and_gate_identity_is_exact(self) -> None:
        witness = self.load_fixture("positive/non_effect_witness_valid.json")
        for bad in (
            "attempt:unrelated",
            witness["gate_record_ref"] + " ",
            witness["gate_record_ref"].upper(),
        ):
            mutated = copy.deepcopy(witness)
            mutated["attempt_ref"] = bad
            with self.subTest(attempt_ref=bad):
                self.assertIn(
                    "non_effect_witness_attempt_mismatch",
                    {item.code for item in self.validator.semantic_non_effect(mutated)},
                )

    def test_r3_m03_not_bound_claim_ceiling_is_exact(self) -> None:
        commit = self.load_fixture("positive/consequence_commit_denied_valid.json")
        for bad in (
            "This proves no effect existed anywhere.",
            commit["claim_boundary"] + " ",
            commit["claim_boundary"].replace("only", "ONLY"),
            "prefix\n" + commit["claim_boundary"],
        ):
            mutated = copy.deepcopy(commit)
            mutated["claim_boundary"] = bad
            with self.subTest(claim_boundary=bad[:24]):
                self.assertIn(
                    "commit_claim_exceeds_linked_witness_scope",
                    {item.code for item in self.validator.semantic_commit(mutated)},
                )

    def test_r3_m04_carry_cost_map_and_rule_codes_are_closed(self) -> None:
        carry = self.load_fixture("positive/continuity_carry_cost_profile.json")
        mutations = []
        missing_code = copy.deepcopy(carry)
        missing_code["non_entailment_codes"].pop()
        mutations.append((missing_code, "carry_cost_rule_set_invalid"))
        extra_code = copy.deepcopy(carry)
        extra_code["non_entailment_codes"].append("RESOURCE_RECOVERY_PROVES_IDENTITY")
        mutations.append((extra_code, "carry_cost_rule_set_invalid"))
        prose = copy.deepcopy(carry)
        prose["rules"] = ["uptime proves identity"]
        prose.pop("non_entailment_codes")
        mutations.append((prose, "carry_cost_rule_set_invalid"))
        wrong_unit = copy.deepcopy(carry)
        wrong_unit["dimensions"][0]["unit"] = "identity-token"
        mutations.append((wrong_unit, "carry_cost_dimension_map_invalid"))
        identity = copy.deepcopy(carry)
        identity["dimensions"][0]["identity_bearing"] = True
        mutations.append((identity, "carry_cost_dimension_map_invalid"))
        for mutation, required in mutations:
            with self.subTest(required=required):
                self.assertIn(
                    required,
                    {item.code for item in self.validator.semantic_carry_cost(mutation)},
                )

    def test_non_effect_evidence_rejects_delayed_and_undeclared_state_fields(self) -> None:
        witness = self.load_fixture("positive/non_effect_witness_valid.json")
        event_rel = "fixtures/runtime-integrity/evidence/non_effect_event_log_42.json"
        route_rel = "fixtures/runtime-integrity/evidence/non_effect_routes_42.json"
        event_log = json.loads((self.root / event_rel).read_text(encoding="utf-8"))
        routes = json.loads((self.root / route_rel).read_text(encoding="utf-8"))

        scheduled = copy.deepcopy(event_log)
        scheduled["scheduled_events"] = [{"kind": "ASYNC_CREATE", "after_window": True}]
        self.assertIn(
            "non_effect_event_log_unresolved",
            self.evidence_issues(copy.deepcopy(witness), {event_rel: scheduled}),
        )
        create_revert = copy.deepcopy(event_log)
        create_revert["events"] = [
            {"kind": "CREATE", "surface_id": "target-state"},
            {"kind": "REVERT", "surface_id": "target-state"},
        ]
        self.assertIn(
            "non_effect_event_log_unresolved",
            self.evidence_issues(copy.deepcopy(witness), {event_rel: create_revert}),
        )
        route_metadata = copy.deepcopy(routes)
        route_metadata["open_but_undeclared_path_ids"] = ["delayed-scheduler"]
        self.assertIn(
            "alternate_path_evidence_unresolved",
            self.evidence_issues(copy.deepcopy(witness), {route_rel: route_metadata}),
        )
        malformed_route = copy.deepcopy(routes)
        malformed_route["path_states"].append("delayed-scheduler:OPEN")
        self.assertIn(
            "alternate_path_evidence_unresolved",
            self.evidence_issues(copy.deepcopy(witness), {route_rel: malformed_route}),
        )
        open_route = copy.deepcopy(routes)
        open_route["path_states"].append({"path_id": "delayed-scheduler", "status": "OPEN"})
        self.assertIn(
            "alternate_path_evidence_unresolved",
            self.evidence_issues(copy.deepcopy(witness), {route_rel: open_route}),
        )

    def run_runner_with_manifest(self, manifest: dict) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "MANIFEST.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(self.runner, "MANIFEST", manifest_path),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                return_code = self.runner.main()
        return return_code, stdout.getvalue(), stderr.getvalue()

    def test_runner_empty_required_inventories_fail_structurally(self) -> None:
        manifest = json.loads(
            (self.root / "tests/adversarial/MANIFEST.json").read_text(encoding="utf-8")
        )
        for key in ("r2_closure_scenarios", "r3_medium_scenarios"):
            mutated = copy.deepcopy(manifest)
            mutated[key] = []
            with self.subTest(key=key):
                return_code, stdout, stderr = self.run_runner_with_manifest(mutated)
                self.assertEqual(1, return_code)
                self.assertIn("structural_diagnostics=1", stdout)
                self.assertIn("manifest must declare unique non-empty", stderr)

    def test_runner_duplicate_ids_across_required_inventories_fail_structurally(self) -> None:
        manifest = json.loads(
            (self.root / "tests/adversarial/MANIFEST.json").read_text(encoding="utf-8")
        )
        mutated = copy.deepcopy(manifest)
        mutated["r3_medium_scenarios"][0]["id"] = mutated["scenarios"][0]["id"]
        return_code, stdout, stderr = self.run_runner_with_manifest(mutated)
        self.assertEqual(1, return_code)
        self.assertIn("structural_diagnostics=1", stdout)
        self.assertIn("globally unique across R1, R2, and R3", stderr)

    def test_runner_unknown_child_output_id_fails_structurally(self) -> None:
        real_run = self.runner.subprocess.run

        def controlled_run(*args, **kwargs):
            result = real_run(*args, **kwargs)
            if args and "round_1.py" in str(args[0][-1]):
                lines = result.stdout.splitlines()
                lines[0] = lines[0].replace(
                    "commit_duplicate_missing_preconditions",
                    "unknown_structural_scenario",
                    1,
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
        self.assertIn("structural_diagnostics=1", stdout.getvalue())
        self.assertIn("unexpected runtime scenario output", stderr.getvalue())

    def test_runner_idless_child_stderr_is_a_nonzero_structural_failure(self) -> None:
        real_run = self.runner.subprocess.run

        def controlled_run(*args, **kwargs):
            result = real_run(*args, **kwargs)
            if args and "round_1.py" in str(args[0][-1]):
                return subprocess.CompletedProcess(
                    result.args,
                    result.returncode,
                    stdout=result.stdout,
                    stderr="STRUCTURAL_DIAGNOSTIC\n",
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
        self.assertIn("failed_scenarios=0", stdout.getvalue())
        self.assertIn("structural_diagnostics=1", stdout.getvalue())
        self.assertIn("unexpected stderr", stderr.getvalue())

    def test_exact_historical_and_closure_inventories(self) -> None:
        manifest = json.loads(
            (self.root / "tests/adversarial/MANIFEST.json").read_text(encoding="utf-8")
        )
        historical = [item["id"] for item in manifest["scenarios"]]
        r2 = [item["id"] for item in manifest["r2_closure_scenarios"]]
        r3 = [item["id"] for item in manifest["r3_medium_scenarios"]]
        self.assertEqual(62, len(historical))
        self.assertEqual(62, len(set(historical)))
        self.assertEqual(0, manifest["unrecovered_scenario_count"])
        self.assertEqual(1, len(r2))
        self.assertEqual(4, len(r3))
        self.assertEqual(4, len(set(r3)))


if __name__ == "__main__":
    unittest.main()
