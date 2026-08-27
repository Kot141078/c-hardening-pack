from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from unittest import mock


root = Path(__file__).resolve().parents[3]
fixture_root = root / "fixtures" / "runtime-integrity"
spec = importlib.util.spec_from_file_location("runtime_integrity_final_probes", root / "tools" / "validate_runtime_integrity_extension.py")
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
manifest = json.loads((fixture_root / "MANIFEST.json").read_text(encoding="utf-8"))
schemas, schema_registry = module.build_registry()


def load(relative: str):
    return json.loads((fixture_root / relative).read_text(encoding="utf-8"))


checks: list[tuple[str, str, set[str]]] = []

witness = load("positive/non_effect_witness_valid.json")
original_resolve_evidence = module.resolve_registered_evidence


def route_with_extra(ref_id, registry):
    result = original_resolve_evidence(ref_id, registry)
    if result and str(ref_id).startswith("evidence:") and result[0].get("schema_version") == "c-route-evidence-0.1":
        artifact = copy.deepcopy(result[0])
        artifact["path_states"].append({"path_id": "undeclared-live-connector", "status": "OPEN"})
        return artifact, result[1]
    return result


with mock.patch.object(module, "resolve_registered_evidence", side_effect=route_with_extra):
    codes = {x.code for x in module.validate_registered_evidence(witness, manifest["evidence_registry"])}
checks.append(("extra_open_route_state", "alternate_path_evidence_unresolved", codes))

witness = load("positive/non_effect_witness_valid.json")
for surface in witness["observation_surfaces"]:
    surface["target_ref"] = "endpoint:B"
    surface["target_coordinate"] = surface["target_coordinate"].replace("endpoint:A", "endpoint:B")
codes = {x.code for x in module.validate_registered_evidence(witness, manifest["evidence_registry"])}
checks.append(("wrong_effect_target_observed", "non_effect_surface_target_mismatch", codes))

earth = load("positive/earth_test_runtime_integrity_valid.json")
original_resolve_artifact = module.resolve_artifact_ref_evidence


def grant_revoked_before_plan(ref, registry):
    result = original_resolve_artifact(ref, registry)
    if result and result[0].get("artifact_id") == "CLI_AGENT_PERMISSION_GRANT:grant-42":
        artifact = copy.deepcopy(result[0])
        artifact["status_history"][1]["effective_at"] = "2026-08-27T09:00:00+02:00"
        return artifact, module.jcs_sha256(artifact)
    return result


with mock.patch.object(module, "resolve_artifact_ref_evidence", side_effect=grant_revoked_before_plan):
    codes = {
        x.code for x in module.semantic_earth_bundle(
            earth, schemas, schema_registry, manifest["record_registry"], manifest["evidence_registry"]
        )
    }
checks.append(("planning_permission_revoked_at_0900", "earth_initial_and_changed_state_unresolved", codes))

commit = load("positive/consequence_commit_denied_valid.json")
commit.update({"commit_outcome": "OPEN_WITH_LIMITS", "effect_state": "BOUND", "effect_artifact_hash": "f" * 64, "non_effect_witness_ref": None})
commit["commit_limits"] = list(load("positive/memory_reliance_valid.json")["use_limits"])
original_load_json = module.load_json
held_memory = load("positive/memory_reliance_valid.json")
held_memory["verdict"] = "HOLD"
commit["memory_reliance_refs"][0]["hash"] = module.jcs_sha256(held_memory)


def load_with_held_memory(path):
    if path.name == "memory_reliance_valid.json":
        return copy.deepcopy(held_memory)
    return original_load_json(path)


with mock.patch.object(module, "load_json", side_effect=load_with_held_memory):
    codes = {
        x.code for x in module.validate_registered_links(
            commit, manifest["record_registry"], schemas, schema_registry, manifest["evidence_registry"]
        )
    }
checks.append(("held_memory_binds_limited_open", "denied_memory_cannot_bind_effect", codes))

unresolved_memory = load("positive/memory_reliance_valid.json")
unresolved_memory["current_authority_ref"] = {"artifact_id": "authority:unresolved", "version": "0.1", "hash": "0" * 64}
commit = load("positive/consequence_commit_denied_valid.json")
commit["memory_reliance_refs"][0]["hash"] = module.jcs_sha256(unresolved_memory)


def load_with_unresolved_memory(path):
    if path.name == "memory_reliance_valid.json":
        return copy.deepcopy(unresolved_memory)
    return original_load_json(path)


with mock.patch.object(module, "load_json", side_effect=load_with_unresolved_memory):
    codes = {
        x.code for x in module.validate_registered_links(
            commit, manifest["record_registry"], schemas, schema_registry, manifest["evidence_registry"]
        )
    }
checks.append(("commit_linked_memory_authority_unresolved", "graph_memory_record_invalid", codes))

commit = load("positive/consequence_commit_denied_valid.json")
commit["source_grounding_ref"]["hash"] = "0" * 64
codes = {x.code for x in module.validate_registered_evidence(commit, manifest["evidence_registry"])}
checks.append(("commit_grounding_ref_forged", "commit_current_conditions_mismatch", codes))

witness = load("positive/non_effect_witness_valid.json")
witness["observation_surfaces"][0]["surface_kind"] = "FILESYSTEM"
witness["observation_surfaces"][0]["coverage"] = "PARTIAL"
codes = {x.code for x in module.validate_registered_evidence(witness, manifest["evidence_registry"])}
checks.append(("surface_kind_and_coverage_drift", "non_effect_event_log_unresolved", codes))

memory = load("positive/memory_reliance_valid.json")
qualification_path = fixture_root / "evidence" / "memory_qualification_registry_42.json"
qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
qualification["artifacts"].append(copy.deepcopy(qualification["artifacts"][0]))
memory["qualification_registry_ref"]["hash"] = module.jcs_sha256(qualification)


def load_with_duplicate_evaluator(path):
    if path.name == "memory_qualification_registry_42.json":
        return copy.deepcopy(qualification)
    return original_load_json(path)


with mock.patch.object(module, "load_json", side_effect=load_with_duplicate_evaluator):
    codes = {x.code for x in module.semantic_memory_reliance(memory)}
checks.append(("duplicate_evaluator_result", "memory_qualification_registry_invalid", codes))

decision = load("positive/decision_basis_valid.json")


def expired_grant(ref, registry):
    result = original_resolve_artifact(ref, registry)
    if result and result[0].get("artifact_id") == "CLI_AGENT_PERMISSION_GRANT:grant-42":
        artifact = copy.deepcopy(result[0])
        artifact["valid_until"] = "2026-08-27T00:00:00+02:00"
        return artifact, module.jcs_sha256(artifact)
    return result


with mock.patch.object(module, "resolve_artifact_ref_evidence", side_effect=expired_grant):
    codes = {x.code for x in module.validate_registered_evidence(decision, manifest["evidence_registry"])}
checks.append(("decision_grant_valid_after_expiry", "decision_permission_grant_unresolved", codes))

external = load("negative/external_intake_code_reuse_invalid.json")
external["relation"] = "FORMAL_DEPENDENCY"
external["claim_assertions"]["code_reuse_claimed"] = False
external["source_artifact"]["author"] = "Unrelated Author"
codes = {x.code for x in module.semantic_external_intake(external)}
checks.append(("elevated_source_metadata_relabelled", "dependency_source_metadata_mismatch", codes))

external = load("positive/external_intake_max_valid.json")
external["local_target"][0] = external["local_target"][0].split("#", 1)[0] + "#does-not-exist"
codes = {x.code for x in module.semantic_external_intake(external)}
checks.append(("markdown_target_fragment_missing", "external_local_target_unresolved", codes))

continuity = load("positive/continuity_history_cases.json")
fork = next(x for x in continuity["cases"] if x["case_id"] == "fork-after-common-history")
fork["right"]["lineage_id"] = fork["left"]["lineage_id"]
codes = {x.code for x in module.semantic_continuity_history(continuity)}
checks.append(("fork_same_lineage", "continuity_pair_relation_mismatch", codes))

earth = load("positive/earth_test_runtime_integrity_valid.json")
earth["later_retry_policy"]["may_reuse_old_commit"] = True
earth["claim_boundary"] = "This proves no effect existed anywhere."
codes = {
    x.code for x in module.semantic_earth_bundle(
        earth, schemas, schema_registry, manifest["record_registry"], manifest["evidence_registry"]
    )
}
checks.append(("earth_retry_and_claim_inflation", "earth_structure_invalid", codes))

type_codes = {
    x.code for x in module.semantic_carry_cost({"schema_version": "c-continuity-carry-cost-profile-0.1", "profile_id": "x", "dimensions": ["bad"], "rules": ["r"]})
}
checks.append(("carry_non_object_dimension", "carry_cost_structure_invalid", type_codes))
checks.append(("continuity_non_object", "continuity_structure_invalid", {x.code for x in module.semantic_continuity_history([])}))
checks.append(("earth_non_object", "earth_structure_invalid", {x.code for x in module.semantic_earth_bundle([], schemas, schema_registry, manifest["record_registry"], manifest["evidence_registry"])}))

failures = 0
for name, expected, observed in checks:
    passed = expected in observed
    failures += 0 if passed else 1
    print(f"{name}|{'PASS' if passed else 'FAIL'}|expected={expected}|observed={','.join(sorted(observed)) or 'none'}")
print(f"FINAL_ROUND_PROBES pass={len(checks) - failures} fail={failures}")
raise SystemExit(1 if failures else 0)
