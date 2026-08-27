from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from tools import validate_runtime_integrity_extension as v  # noqa: E402


SCHEMA = {
    "decision": "urn:ivan-kotov:c-runtime-integrity:decision-basis-record:0.1.1",
    "memory": "urn:ivan-kotov:c-runtime-integrity:memory-reliance-record:0.1.1",
    "witness": "urn:ivan-kotov:c-runtime-integrity:non-effect-witness-record:0.1.1",
    "commit": "urn:ivan-kotov:c-runtime-integrity:consequence-commit-record:0.1.1",
    "boundary": "urn:ivan-kotov:c-runtime-integrity:boundary-probe-record:0.1.1",
    "judge": "urn:ivan-kotov:c-runtime-integrity:judge-deliberation-record:0.1.1",
    "external": "urn:ivan-kotov:c-runtime-integrity:external-construct-intake-record:0.1.1",
}


def fixture(relative: str):
    return json.loads((REPO / "fixtures" / "runtime-integrity" / relative).read_text(encoding="utf-8"))


schemas, registry = v.build_registry()
failures: list[str] = []


def record_probe(name: str, data: dict, schema_id: str, semantic):
    issues = v.validate_schema(data, schema_id, schemas, registry)
    if not any(issue.code == "schema" for issue in issues):
        issues.extend(semantic(data))
    observed = "VALID" if not issues else "INVALID"
    codes = ",".join(issue.code for issue in issues) or "none"
    print(f"{name}|expected=INVALID|observed={observed}|issues={codes}")
    if not issues:
        failures.append(name)


commit = fixture("positive/consequence_commit_denied_valid.json")

case = copy.deepcopy(commit)
passing = copy.deepcopy(next(x for x in case["precondition_results"] if x["status"] == "PASS"))
case["precondition_results"] = [copy.deepcopy(passing) for _ in range(6)]
case["commit_outcome"] = "OPEN"
case["effect_state"] = "BOUND"
case["effect_artifact_hash"] = "a" * 64
case["non_effect_witness_ref"] = None
record_probe("commit_duplicate_missing_preconditions", case, SCHEMA["commit"], v.semantic_commit)

case = copy.deepcopy(commit)
case.pop("memory_reliance_refs", None)
record_probe("commit_memory_influence_disappears", case, SCHEMA["commit"], v.semantic_commit)

case = copy.deepcopy(commit)
case["current_conditions_hash"] = case["decision_basis_ref"]["hash"]
record_probe("commit_conditions_hash_substituted_from_basis", case, SCHEMA["commit"], v.semantic_commit)

decision = fixture("positive/decision_basis_valid.json")
case = copy.deepcopy(decision)
case["basis"]["policy_refs"][1]["artifact_id"] = case["basis"]["policy_refs"][0]["artifact_id"]
case["basis_hash"] = v.jcs_sha256(case["basis"])
record_probe("decision_basis_duplicate_logical_policy_id", case, SCHEMA["decision"], v.semantic_decision_basis)

memory = fixture("positive/memory_reliance_valid.json")
case = copy.deepcopy(memory)
case.update({
    "provenance_state": "UNKNOWN",
    "freshness_state": "CURRENT",
    "revocation_state": "UNKNOWN",
    "consent_state": "UNKNOWN",
    "conflict_state": "UNKNOWN",
    "contamination_state": "UNKNOWN",
    "verdict": "USE",
})
case.pop("use_limits", None)
record_probe("memory_unknown_states_unrestricted_use", case, SCHEMA["memory"], v.semantic_memory_reliance)

witness = fixture("positive/non_effect_witness_valid.json")
case = copy.deepcopy(witness)
case["observation_window"] = {"start": "2026-08-27T00:16:00+02:00", "end": "2026-08-27T00:15:30+02:00"}
record_probe("non_effect_reversed_observation_window", case, SCHEMA["witness"], v.semantic_non_effect)

case = copy.deepcopy(witness)
case["observation_surfaces"] = [copy.deepcopy(case["observation_surfaces"][0]) for _ in range(3)]
case["alternate_path_checks"] = [copy.deepcopy(case["alternate_path_checks"][0]) for _ in range(3)]
record_probe("non_effect_duplicate_logical_inventory", case, SCHEMA["witness"], v.semantic_non_effect)

case = copy.deepcopy(witness)
case["claim_boundary"] = "This record proves globally and universally that no effect existed anywhere, on any undeclared surface, before or after the observation window."
record_probe("non_effect_global_narrative_inflation", case, SCHEMA["witness"], v.semantic_non_effect)

boundary = fixture("positive/boundary_probe_valid.json")
case = copy.deepcopy(boundary)
case["signals"]["cross_agent_aggregation"] = False
case["signals"]["provider_rotation"] = False
record_probe("boundary_counts_contradict_signals", case, SCHEMA["boundary"], v.semantic_boundary_probe)

case = copy.deepcopy(boundary)
case["window"] = {"start": "2026-08-27T00:15:00+02:00", "end": "2026-08-27T00:00:00+02:00"}
record_probe("boundary_reversed_window", case, SCHEMA["boundary"], v.semantic_boundary_probe)

judge = fixture("positive/judge_deliberation_valid.json")
case = copy.deepcopy(judge)
for reviewer in case["reviewers"]:
    reviewer["reviewer_id"] = "same-model-instance"
    reviewer["report_hash"] = "f" * 64
record_probe("judge_same_instance_masquerades_as_reviewers", case, SCHEMA["judge"], v.semantic_judge)

external = fixture("positive/external_intake_richard_valid.json")
case = copy.deepcopy(external)
case["source_artifact"]["uri"] = "x"
case["source_artifact"]["source_hash"] = None
case["source_artifact"]["freeze_status"] = "PUBLIC_REFERENCE_VERIFIED"
case["relation"] = "FORMAL_DEPENDENCY"
case["license_status"] = "LICENSE_CLEARED_FOR_ADAPTATION"
record_probe("external_formal_dependency_without_frozen_hash_or_dependency_proof", case, SCHEMA["external"], v.semantic_external_intake)

case = copy.deepcopy(external)
case["preserved_properties"] = []
case["rejected_properties"] = []
case["mapping_failures"] = []
case["terminology_substitutions"] = []
case["native_antecedents"] = []
case["attribution"] = {"required": False, "references": []}
case.pop("independent_prior_art_refs", None)
record_probe("external_empty_required_evidence_fields", case, SCHEMA["external"], v.semantic_external_intake)

continuity = fixture("positive/continuity_history_cases.json")
case = copy.deepcopy(continuity)
case["cases"][0]["left"]["transition_evidence_complete"] = False
issues = v.semantic_continuity_history(case)
print(f"continuity_resume_without_transition_evidence|expected=INVALID|observed={'VALID' if not issues else 'INVALID'}|issues={','.join(x.code for x in issues) or 'none'}")
if not issues:
    failures.append("continuity_resume_without_transition_evidence")

case = copy.deepcopy(continuity)
case["cases"] = [case["cases"][0]]
issues = v.semantic_continuity_history(case)
print(f"continuity_required_case_pairs_missing|expected=INVALID|observed={'VALID' if not issues else 'INVALID'}|issues={','.join(x.code for x in issues) or 'none'}")
if not issues:
    failures.append("continuity_required_case_pairs_missing")

print(f"ADVERSARIAL_PROBES pass={15 - len(failures)} fail={len(failures)}")
raise SystemExit(1 if failures else 0)
