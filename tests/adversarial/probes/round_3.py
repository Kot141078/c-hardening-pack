from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from unittest import mock


root = Path(__file__).resolve().parents[3]
fixture_root = root / "fixtures" / "runtime-integrity"
spec = importlib.util.spec_from_file_location("runtime_integrity_third_probes", root / "tools" / "validate_runtime_integrity_extension.py")
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
manifest = json.loads((fixture_root / "MANIFEST.json").read_text(encoding="utf-8"))
schemas, registry = module.build_registry()


def load(relative: str):
    return json.loads((fixture_root / relative).read_text(encoding="utf-8"))


checks: list[tuple[str, str, set[str]]] = []

memory = load("positive/memory_reliance_valid.json")
memory["freshness_state"] = "CURRENT"
memory["verdict"] = "USE"
memory["use_limits"] = []
checks.append(("memory_evaluator_result_promotion", "memory_evaluator_unresolved", {x.code for x in module.semantic_memory_reliance(memory)}))

memory = load("positive/memory_reliance_valid.json")
memory["current_authority_ref"] = {"artifact_id": "authority:unresolved", "version": "0.1", "hash": "0" * 64}
checks.append(("memory_current_authority_unresolved", "memory_current_authority_unresolved", {x.code for x in module.validate_registered_evidence(memory, manifest["evidence_registry"])}))

commit = load("positive/consequence_commit_denied_valid.json")
commit["commit_outcome"] = "OPEN_WITH_LIMITS"
commit["effect_state"] = "BOUND"
commit["effect_artifact_hash"] = "f" * 64
commit["non_effect_witness_ref"] = None
commit["commit_limits"] = ["unrelated limit"]
checks.append(("memory_limits_dropped", "memory_limits_not_propagated", {x.code for x in module.validate_registered_links(commit, manifest["record_registry"])}))

commit = load("positive/consequence_commit_denied_valid.json")
commit["effect_state"] = "BOUND"
commit["effect_artifact_hash"] = "f" * 64
checks.append(("bound_commit_with_non_effect_witness", "graph_witness_link_invalid", {x.code for x in module.validate_registered_links(commit, manifest["record_registry"])}))

commit = load("positive/consequence_commit_denied_valid.json")
commit["precondition_results"][-1]["status"] = "PASS"
checks.append(("current_conditions_blocking_state_drift", "commit_current_conditions_mismatch", {x.code for x in module.validate_registered_evidence(commit, manifest["evidence_registry"])}))

witness = load("positive/non_effect_witness_valid.json")
for surface in witness["observation_surfaces"]:
    surface["before_hash"] = surface["after_hash"] = "0" * 64
checks.append(("surface_measurements_unattested", "non_effect_event_log_unresolved", {x.code for x in module.validate_registered_evidence(witness, manifest["evidence_registry"])}))

witness = load("positive/non_effect_witness_valid.json")
witness["observation_window"] = {"start": "2026-08-27T10:04:00+02:00", "end": "2026-08-27T10:04:30+02:00"}
checks.append(("route_window_unbound", "alternate_path_evidence_unresolved", {x.code for x in module.validate_registered_evidence(witness, manifest["evidence_registry"])}))

boundary = load("positive/boundary_probe_valid.json")
boundary["signals"]["memory_assisted"] = True
boundary["aggregation_keys"]["shared_memory_lineage_refs"] = []
checks.append(("memory_probe_without_lineage", "memory_assisted_probe_requires_lineage_key", {x.code for x in module.semantic_boundary_probe(boundary)}))

boundary = load("positive/boundary_probe_valid.json")
boundary["query_count"] = 0
checks.append(("zero_query_nonzero_participants", "schema", {x.code for x in module.validate_schema(boundary, "urn:ivan-kotov:c-runtime-integrity:boundary-probe-record:0.1.1", schemas, registry)}))

judge = load("positive/judge_deliberation_valid.json")
judge["unresolved_divergence"][0]["evidence_refs"] = ["case:does-not-exist"]
checks.append(("dangling_divergence_evidence", "judge_evidence_ref_unresolved", {x.code for x in module.semantic_judge(judge)}))

continuity = load("positive/continuity_history_cases.json")
target = next(x for x in continuity["cases"] if x["case_id"] == "identity-preserved-under-l4-degradation")
target["right"]["expected_classification"] = "REJECTED"
checks.append(("l4_degradation_identity_rejected", "continuity_case_classification_mismatch", {x.code for x in module.semantic_continuity_history(continuity)}))

external = load("negative/external_intake_code_reuse_invalid.json")
external["relation"] = "FORMAL_DEPENDENCY"
external["claim_assertions"] = {key: False for key in external["claim_assertions"]}
checks.append(("formal_dependency_without_dependency_assertion", "elevated_relation_assertions_mismatch", {x.code for x in module.semantic_external_intake(external)}))

earth = load("positive/earth_test_runtime_integrity_valid.json")
del earth["schema_version"]
original_load = module.load_json


def late_commit(path: Path):
    value = original_load(path)
    if path.name == "consequence_commit_denied_valid.json":
        value = copy.deepcopy(value)
        value["created_at"] = "2026-08-27T10:04:00+02:00"
        value["permission_checked_at"] = "2026-08-27T10:00:00+02:00"
        value["task_contract_checked_at"] = "2026-08-27T10:00:00+02:00"
    return value


with mock.patch.object(module, "load_json", side_effect=late_commit):
    earth_codes = {x.code for x in module.semantic_earth_bundle(earth, schemas, registry, manifest["record_registry"], manifest["evidence_registry"])}
checks.append(("earth_outer_contract_missing", "earth_structure_invalid", earth_codes))
checks.append(("earth_commit_not_revalidated_at_execution", "earth_final_revalidation_incomplete", earth_codes))

failures = 0
for name, expected, observed in checks:
    passed = expected in observed
    failures += 0 if passed else 1
    print(f"{name}|{'PASS' if passed else 'FAIL'}|expected={expected}|observed={','.join(sorted(observed)) or 'none'}")
print(f"THIRD_ROUND_PROBES pass={len(checks) - failures} fail={failures}")
raise SystemExit(1 if failures else 0)
