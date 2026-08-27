from __future__ import annotations

import copy
import hashlib
import os
import subprocess
import sys
import unittest
import importlib.util
import json
import jcs
from pathlib import Path
from unittest import mock


class RuntimeIntegrityExtensionTest(unittest.TestCase):
    def _load_validator(self, name: str):
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(
            name,
            root / "tools" / "validate_runtime_integrity_extension.py",
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return root, module

    def test_fixture_manifest(self) -> None:
        root = Path(__file__).resolve().parents[1]
        context = json.loads((root / "review-context" / "runtime-integrity-r1f.json").read_text(encoding="utf-8"))
        env = os.environ.copy()
        env.update({
            "RUNTIME_REVIEW_CONTEXT_SHA256": hashlib.sha256(jcs.canonicalize(context)).hexdigest(),
            "RUNTIME_EXPECTED_REPOSITORY": "https://github.com/Kot141078/c-hardening-pack",
            "RUNTIME_EXPECTED_BASE_SHA": "9a33e3866cde19939be22a903967bc94f566db76",
            "RUNTIME_EXPECTED_REVIEWED_PARENT_SHA": "ead3fe6c69d99aafb84b8db98d3df4329ea3c918",
            "RUNTIME_EXPECTED_CANDIDATE_SCOPE": "RUNTIME_SEMANTIC_CLOSURE_FROM_REVIEWED_PARENT",
            "RUNTIME_EXPECTED_TRUST_ROOT_CLASS": "CONTRACT_SHA256_PINNED_OWNER_INPUT",
        })
        proc = subprocess.run(
            [sys.executable, str(root / "tools" / "validate_runtime_integrity_extension.py"), "--verbose"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
        )
        self.assertEqual(
            proc.returncode,
            0,
            msg=f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}",
        )
        self.assertIn("fail=0", proc.stdout)

    def test_explicit_no_memory_influence_is_valid(self) -> None:
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(
            "runtime_integrity_validator",
            root / "tools" / "validate_runtime_integrity_extension.py",
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        data = json.loads(
            (root / "fixtures" / "runtime-integrity" / "positive" / "consequence_commit_denied_valid.json").read_text(encoding="utf-8")
        )
        data["memory_influence_state"] = "NONE"
        data["memory_reliance_refs"] = []
        schemas, registry = module.build_registry()
        schema_id = "urn:ivan-kotov:c-runtime-integrity:consequence-commit-record:0.1.1"
        hidden_issues = module.validate_schema(data, schema_id, schemas, registry)
        hidden_issues.extend(module.semantic_commit(data))
        self.assertIn("memory_influence_precondition_mismatch", {item.code for item in hidden_issues})
        for item in data["precondition_results"]:
            if item["name"] == "MEMORY_RELIANCE":
                item.update(status="PASS", evidence_ref="memory-influence:none")
        schemas, registry = module.build_registry()
        issues = module.validate_schema(data, schema_id, schemas, registry)
        issues.extend(module.semantic_commit(data))
        self.assertEqual([], issues)

    def test_limited_memory_cannot_authorize_unrestricted_open(self) -> None:
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(
            "runtime_integrity_validator_memory_aggregation",
            root / "tools" / "validate_runtime_integrity_extension.py",
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        fixture_root = root / "fixtures" / "runtime-integrity"
        data = json.loads((fixture_root / "positive" / "consequence_commit_denied_valid.json").read_text(encoding="utf-8"))
        data.update({
            "permission_status": "VALID",
            "permission_valid_until": "2026-08-27T11:00:00+02:00",
            "authorized_target_ref": "endpoint:A",
            "task_contract_status": "CURRENT",
            "task_endpoint_ref": "endpoint:A",
            "commit_outcome": "OPEN",
            "effect_state": "BOUND",
            "effect_artifact_hash": "f" * 64,
            "non_effect_witness_ref": None,
        })
        data["precondition_results"] = [dict(item, status="PASS") for item in data["precondition_results"]]
        manifest = json.loads((fixture_root / "MANIFEST.json").read_text(encoding="utf-8"))
        codes = {
            item.code
            for item in module.semantic_commit(data)
            + module.validate_registered_links(data, manifest["record_registry"])
        }
        self.assertIn("limited_memory_cannot_authorize_unrestricted_open", codes)

    def test_memory_evaluator_result_and_time_are_hash_bound(self) -> None:
        root, module = self._load_validator("runtime_integrity_validator_memory_result")
        path = root / "fixtures" / "runtime-integrity" / "positive" / "memory_reliance_valid.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["freshness_state"] = "CURRENT"
        data["verdict"] = "USE"
        data["use_limits"] = []
        codes = {item.code for item in module.semantic_memory_reliance(data)}
        self.assertIn("memory_evaluator_unresolved", codes)

    def test_open_with_limits_preserves_linked_memory_limits(self) -> None:
        root, module = self._load_validator("runtime_integrity_validator_memory_limits")
        fixture_root = root / "fixtures" / "runtime-integrity"
        data = json.loads((fixture_root / "positive" / "consequence_commit_denied_valid.json").read_text(encoding="utf-8"))
        data["commit_outcome"] = "OPEN_WITH_LIMITS"
        data["effect_state"] = "BOUND"
        data["effect_artifact_hash"] = "f" * 64
        data["non_effect_witness_ref"] = None
        data["commit_limits"] = ["an unrelated limit"]
        manifest = json.loads((fixture_root / "MANIFEST.json").read_text(encoding="utf-8"))
        codes = {item.code for item in module.validate_registered_links(data, manifest["record_registry"])}
        self.assertIn("memory_limits_not_propagated", codes)
        for item in data["precondition_results"]:
            if item["name"] == "MEMORY_RELIANCE":
                item["status"] = "PASS"
        codes = {item.code for item in module.validate_registered_links(data, manifest["record_registry"])}
        self.assertIn("memory_precondition_verdict_mismatch", codes)

    def test_non_effect_surface_measurements_are_event_log_bound(self) -> None:
        root, module = self._load_validator("runtime_integrity_validator_surface_evidence")
        fixture_root = root / "fixtures" / "runtime-integrity"
        data = json.loads((fixture_root / "positive" / "non_effect_witness_valid.json").read_text(encoding="utf-8"))
        for surface in data["observation_surfaces"]:
            surface["before_hash"] = "0" * 64
            surface["after_hash"] = "0" * 64
        manifest = json.loads((fixture_root / "MANIFEST.json").read_text(encoding="utf-8"))
        codes = {item.code for item in module.validate_registered_evidence(data, manifest["evidence_registry"])}
        self.assertIn("non_effect_event_log_unresolved", codes)
        self.assertFalse(module.target_coordinate_is_canonical("endpoint:A", "endpoint:A/../endpoint:B/api"))
        self.assertFalse(module.target_coordinate_is_canonical("endpoint:A", "endpoint:A/%2e%2e/endpoint:B/api"))
        self.assertFalse(module.target_coordinate_is_canonical("endpoint:A", "endpoint:A\\endpoint:B\\api"))
        self.assertTrue(module.target_coordinate_is_canonical("endpoint:A", "endpoint:A/deployment-api"))

    def test_non_effect_witness_requires_matching_not_bound_commit(self) -> None:
        root, module = self._load_validator("runtime_integrity_validator_witness_state")
        fixture_root = root / "fixtures" / "runtime-integrity"
        data = json.loads((fixture_root / "positive" / "consequence_commit_denied_valid.json").read_text(encoding="utf-8"))
        data["effect_state"] = "BOUND"
        data["effect_artifact_hash"] = "f" * 64
        manifest = json.loads((fixture_root / "MANIFEST.json").read_text(encoding="utf-8"))
        codes = {item.code for item in module.validate_registered_links(data, manifest["record_registry"])}
        self.assertIn("graph_witness_link_invalid", codes)

    def test_unresolved_commit_grant_task_and_conditions_are_rejected(self) -> None:
        root, module = self._load_validator("runtime_integrity_validator_commit_evidence")
        fixture_root = root / "fixtures" / "runtime-integrity"
        data = json.loads((fixture_root / "positive" / "consequence_commit_denied_valid.json").read_text(encoding="utf-8"))
        fake = {"artifact_id": "unresolved", "version": "0.1", "hash": "0" * 64}
        data["permission_grant_ref"] = fake
        data["task_contract_ref"] = fake
        data["current_conditions_ref"] = fake
        data["current_conditions_hash"] = fake["hash"]
        manifest = json.loads((fixture_root / "MANIFEST.json").read_text(encoding="utf-8"))
        codes = {item.code for item in module.validate_registered_evidence(data, manifest["evidence_registry"])}
        self.assertTrue({
            "commit_permission_grant_unresolved",
            "commit_task_contract_unresolved",
            "commit_current_conditions_unresolved",
        }.issubset(codes))

    def test_previous_commit_reference_must_resolve(self) -> None:
        root, module = self._load_validator("runtime_integrity_validator_previous_commit")
        fixture_root = root / "fixtures" / "runtime-integrity"
        data = json.loads((fixture_root / "positive" / "consequence_commit_denied_valid.json").read_text(encoding="utf-8"))
        data["previous_commit_record_ref"] = {"artifact_id": "missing-prior", "version": "0.1", "hash": "0" * 64}
        data["change_reason"] = "conditions changed"
        manifest = json.loads((fixture_root / "MANIFEST.json").read_text(encoding="utf-8"))
        codes = {item.code for item in module.validate_registered_links(data, manifest["record_registry"])}
        self.assertIn("previous_commit_record_unresolved", codes)

    def test_judge_divergence_evidence_must_resolve(self) -> None:
        root, module = self._load_validator("runtime_integrity_validator_judge_divergence")
        path = root / "fixtures" / "runtime-integrity" / "positive" / "judge_deliberation_valid.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["unresolved_divergence"][0]["evidence_refs"] = ["case:does-not-exist"]
        codes = {item.code for item in module.semantic_judge(data)}
        self.assertIn("judge_evidence_ref_unresolved", codes)

    def test_continuity_pair_classification_cannot_be_swapped(self) -> None:
        root, module = self._load_validator("runtime_integrity_validator_continuity_pair")
        path = root / "fixtures" / "runtime-integrity" / "positive" / "continuity_history_cases.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        target = next(item for item in data["cases"] if item["case_id"] == "fork-after-common-history")
        target["right"]["expected_classification"] = "RESUME_CONFIRMED"
        codes = {item.code for item in module.semantic_continuity_history(data)}
        self.assertIn("continuity_case_classification_mismatch", codes)

    def test_boundary_schema_rejects_zero_query_participants(self) -> None:
        root, module = self._load_validator("runtime_integrity_validator_boundary_zero")
        path = root / "fixtures" / "runtime-integrity" / "positive" / "boundary_probe_valid.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["query_count"] = 0
        schemas, registry = module.build_registry()
        issues = module.validate_schema(
            data,
            "urn:ivan-kotov:c-runtime-integrity:boundary-probe-record:0.1.1",
            schemas,
            registry,
        )
        self.assertIn("schema", {item.code for item in issues})

    def test_external_dependency_evidence_is_typed_and_not_fixture_proof(self) -> None:
        root, module = self._load_validator("runtime_integrity_validator_external_evidence")
        path = root / "fixtures" / "runtime-integrity" / "negative" / "external_intake_code_reuse_invalid.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["relation"] = "FORMAL_DEPENDENCY"
        data["claim_assertions"]["code_reuse_claimed"] = False
        data["license_evidence_refs"] = copy.deepcopy(data["dependency_evidence_refs"])
        codes = {item.code for item in module.semantic_external_intake(data)}
        self.assertIn("formal_dependency_proof_mismatch", codes)

        data = json.loads(path.read_text(encoding="utf-8"))
        data["relation"] = "FORMAL_DEPENDENCY"
        data["claim_assertions"]["code_reuse_claimed"] = False
        codes = {item.code for item in module.semantic_external_intake(data)}
        self.assertIn("negative_fixture_evidence_cannot_elevate_relation", codes)
        self.assertIn("formal_dependency_proof_mismatch", codes)

    def test_synthetic_code_reuse_manual_stop(self) -> None:
        root, module = self._load_validator("runtime_integrity_validator_code_reuse_stop")
        path = root / "fixtures" / "runtime-integrity" / "negative" / "external_intake_code_reuse_invalid.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        codes = {item.code for item in module.semantic_external_intake(data)}
        self.assertIn("code_reuse_record_requires_manual_review", codes)

    def test_earth_contract_binds_outer_state_and_commit_time(self) -> None:
        root, module = self._load_validator("runtime_integrity_validator_earth_contract")
        fixture_root = root / "fixtures" / "runtime-integrity"
        path = fixture_root / "positive" / "earth_test_runtime_integrity_valid.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        del data["schema_version"]
        original_load_json = module.load_json

        def load_with_late_commit(target_path):
            loaded = original_load_json(target_path)
            if target_path.name == "consequence_commit_denied_valid.json":
                loaded = copy.deepcopy(loaded)
                loaded["created_at"] = "2026-08-27T10:04:00+02:00"
            return loaded

        schemas, registry = module.build_registry()
        manifest = json.loads((fixture_root / "MANIFEST.json").read_text(encoding="utf-8"))
        with mock.patch.object(module, "load_json", side_effect=load_with_late_commit):
            codes = {
                item.code
                for item in module.semantic_earth_bundle(
                    data,
                    schemas,
                    registry,
                    manifest["record_registry"],
                    manifest["evidence_registry"],
                )
            }
        self.assertIn("earth_structure_invalid", codes)
        self.assertIn("earth_final_revalidation_incomplete", codes)


if __name__ == "__main__":
    unittest.main()
