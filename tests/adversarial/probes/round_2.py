from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
from tools import validate_runtime_integrity_extension as v  # noqa: E402

schemas, schema_registry = v.build_registry()
manifest = v.load_json(v.MANIFEST)
record_registry = manifest["record_registry"]
evidence_registry = manifest["evidence_registry"]


def load(relative: str):
    return v.load_json(v.FIXTURE_DIR / relative)


def codes(data, schema_id, semantic):
    found = v.validate_schema(data, schema_id, schemas, schema_registry)
    if not any(item.code == "schema" for item in found):
        found.extend(semantic(data))
        found.extend(v.validate_registered_evidence(data, evidence_registry))
        if data.get("record_type") in {"decision_basis_record", "consequence_commit_record", "non_effect_witness_record"}:
            found.extend(v.validate_registered_links(data, record_registry))
    return {item.code for item in found}


def check(name: str, found: set[str], expected: set[str]):
    ok = expected <= found
    print(f"{name}|{'PASS' if ok else 'FAIL'}|expected={','.join(sorted(expected))}|observed={','.join(sorted(found)) or 'none'}")
    if not ok:
        raise SystemExit(1)


boundary = load("positive/boundary_probe_valid.json")
case = copy.deepcopy(boundary)
case["aggregation_keys"]["provider_family_refs"] = []
check("boundary_empty_provider_aggregation", codes(case, "urn:ivan-kotov:c-runtime-integrity:boundary-probe-record:0.1.1", v.semantic_boundary_probe), {"schema"})
case = copy.deepcopy(boundary)
case["aggregation_keys"]["protected_policy_surface_ref"] = "policy:other"
check("boundary_surface_mismatch", codes(case, "urn:ivan-kotov:c-runtime-integrity:boundary-probe-record:0.1.1", v.semantic_boundary_probe), {"probe_aggregation_surface_mismatch"})
case = copy.deepcopy(boundary)
case["budget"]["evaluation_state"] = "UNKNOWN"
case["decision"] = "ALLOW"
check("boundary_unknown_budget_allow", codes(case, "urn:ivan-kotov:c-runtime-integrity:boundary-probe-record:0.1.1", v.semantic_boundary_probe), {"high_risk_probe_cannot_be_allowed"})
case = copy.deepcopy(boundary)
case["budget"]["budget_profile_ref"]["hash"] = "0" * 64
check("boundary_budget_hash_tamper", codes(case, "urn:ivan-kotov:c-runtime-integrity:boundary-probe-record:0.1.1", v.semantic_boundary_probe), {"probe_budget_profile_unresolved"})

witness = load("positive/non_effect_witness_valid.json")
case = copy.deepcopy(witness)
case["observation_window"]["end"] = case["observation_window"]["start"]
check("non_effect_zero_duration", codes(case, "urn:ivan-kotov:c-runtime-integrity:non-effect-witness-record:0.1.1", v.semantic_non_effect), {"non_effect_requires_positive_observation_window"})
case = copy.deepcopy(witness)
case["alternate_path_checks"][0]["evidence_ref"] = "missing:route-evidence"
check("non_effect_dangling_route", codes(case, "urn:ivan-kotov:c-runtime-integrity:non-effect-witness-record:0.1.1", v.semantic_non_effect), {"alternate_path_evidence_unresolved"})
case = copy.deepcopy(witness)
case["scope_inventory_hash"] = "0" * 64
check("non_effect_scope_hash_tamper", codes(case, "urn:ivan-kotov:c-runtime-integrity:non-effect-witness-record:0.1.1", v.semantic_non_effect), {"non_effect_scope_inventory_unresolved"})
case = copy.deepcopy(witness)
case["evidence_collection"]["collector_ref"] = "missing:collector"
check("non_effect_dangling_collector", codes(case, "urn:ivan-kotov:c-runtime-integrity:non-effect-witness-record:0.1.1", v.semantic_non_effect), {"non_effect_collector_evidence_unresolved"})

commit = load("positive/consequence_commit_denied_valid.json")
case = copy.deepcopy(commit)
case["non_effect_witness_ref"]["hash"] = "0" * 64
check("commit_witness_hash_tamper", codes(case, "urn:ivan-kotov:c-runtime-integrity:consequence-commit-record:0.1.1", v.semantic_commit), {"graph_witness_link_invalid"})
case = copy.deepcopy(commit)
case["decision_basis_ref"]["artifact_id"] = "alias-not-target-record-id"
alias_registry = dict(record_registry)
alias_registry["alias-not-target-record-id"] = "positive/decision_basis_valid.json"
found = {item.code for item in v.validate_registered_links(case, alias_registry)}
check("record_registry_alias_rejected", found, {"graph_decision_basis_link_invalid"})
case = copy.deepcopy(witness)
case["protected_effects"][0] = "tampered effect"
found = {item.code for item in v.validate_registered_links(case, record_registry)}
check("witness_content_tamper_rejected", found, {"graph_witness_link_invalid"})

memory = load("positive/memory_reliance_valid.json")
case = copy.deepcopy(memory)
case["provenance_state"] = "BOUNDED"
case["freshness_state"] = "CURRENT"
case["verdict"] = "USE"
case.pop("use_limits", None)
check("bounded_memory_unrestricted_use", codes(case, "urn:ivan-kotov:c-runtime-integrity:memory-reliance-record:0.1.1", v.semantic_memory_reliance), {"memory_qualification_requires_limits_or_denial"})
case = copy.deepcopy(memory)
case["freshness_evaluator_ref"]["hash"] = case["memory_item_ref"]["hash"]
check("memory_evaluator_hash_collision", codes(case, "urn:ivan-kotov:c-runtime-integrity:memory-reliance-record:0.1.1", v.semantic_memory_reliance), {"memory_self_certification_forbidden"})

continuity = load("positive/continuity_history_cases.json")
case = copy.deepcopy(continuity)
archive = case["cases"][0]["right"]
archive["transition_evidence_complete"] = True
archive["expected_classification"] = "RESUME_CONFIRMED"
found = {item.code for item in v.semantic_continuity_history(case)}
check("continuity_archive_false_resume", found, {"continuity_transition_evidence_mismatch", "resume_history_class_incompatible"})

judge = load("positive/judge_deliberation_valid.json")
case = copy.deepcopy(judge)
case["corpus_passport_path"] = "../READONLY_HANDOFF.txt"
check("judge_passport_path_escape", codes(case, "urn:ivan-kotov:c-runtime-integrity:judge-deliberation-record:0.1.1", v.semantic_judge), {"judge_corpus_passport_unresolved"})
case = copy.deepcopy(judge)
case["reviewers"][0]["evidence_refs"] = ["../READONLY_HANDOFF.txt"]
check("judge_evidence_path_escape", codes(case, "urn:ivan-kotov:c-runtime-integrity:judge-deliberation-record:0.1.1", v.semantic_judge), {"judge_evidence_ref_unresolved", "judge_corpus_source_hash_mismatch"})

earth = load("positive/earth_test_runtime_integrity_valid.json")
found = {item.code for item in v.semantic_earth_bundle(earth, schemas, schema_registry, record_registry, evidence_registry)}
check("earth_positive_control", found, set())

print("SECOND_ORDER_PROBES pass=17 fail=0")
