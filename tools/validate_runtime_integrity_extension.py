#!/usr/bin/env python3
"""Validate the c runtime-integrity extension.

The validator performs two layers:
1. JSON Schema Draft 2020-12 validation.
2. Cross-record semantic checks that JSON Schema alone cannot express.

It is a development verifier, not a production security monitor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

try:
    from jsonschema import Draft202012Validator, FormatChecker
    from referencing import Registry, Resource
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Missing development dependency. Run: "
        "python -m pip install -r requirements-runtime-integrity.txt"
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas" / "runtime-integrity"
FIXTURE_DIR = ROOT / "fixtures" / "runtime-integrity"
MANIFEST = FIXTURE_DIR / "MANIFEST.json"


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    message: str


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"Missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def build_registry() -> tuple[dict[str, dict[str, Any]], Registry]:
    schemas: dict[str, dict[str, Any]] = {}
    resources: list[tuple[str, Resource[Any]]] = []
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema = load_json(path)
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str) or not schema_id:
            raise SystemExit(f"Schema lacks $id: {path}")
        if schema_id in schemas:
            raise SystemExit(f"Duplicate schema $id: {schema_id}")
        Draft202012Validator.check_schema(schema)
        schemas[schema_id] = schema
        resources.append((schema_id, Resource.from_contents(schema)))
    registry = Registry().with_resources(resources)
    return schemas, registry


def validate_schema(
    instance: Any,
    schema_id: str,
    schemas: dict[str, dict[str, Any]],
    registry: Registry,
) -> list[ValidationIssue]:
    schema = schemas.get(schema_id)
    if schema is None:
        return [ValidationIssue("schema_not_found", f"Unknown schema id: {schema_id}")]
    validator = Draft202012Validator(
        schema,
        registry=registry,
        format_checker=FormatChecker(),
    )
    issues: list[ValidationIssue] = []
    for error in sorted(validator.iter_errors(instance), key=lambda e: list(e.path)):
        location = "$"
        if error.path:
            location += "." + ".".join(str(part) for part in error.path)
        issues.append(ValidationIssue("schema", f"{location}: {error.message}"))
    return issues


def semantic_decision_basis(data: dict[str, Any]) -> list[ValidationIssue]:
    expected = canonical_sha256(data.get("basis"))
    actual = data.get("basis_hash")
    if actual != expected:
        return [ValidationIssue(
            "basis_hash_mismatch",
            f"basis_hash must be sha256(canonical basis); expected {expected}, got {actual}",
        )]
    return []


def semantic_memory_reliance(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    verdict = data.get("verdict")
    revocation = data.get("revocation_state")
    consent = data.get("consent_state")
    contamination = data.get("contamination_state")
    freshness = data.get("freshness_state")
    provenance = data.get("provenance_state")

    hard_deny = (
        revocation == "REVOKED"
        or consent == "WITHDRAWN"
        or contamination == "CONFIRMED"
        or provenance == "CONTRADICTED"
    )
    if hard_deny and verdict in {"USE", "USE_WITH_LIMITS"}:
        issues.append(ValidationIssue(
            "revoked_memory_cannot_be_used",
            "Revoked, withdrawn, confirmed-contaminated, or contradicted memory cannot receive a use verdict.",
        ))
    if freshness in {"STALE", "EXPIRED", "UNKNOWN"} and verdict == "USE":
        issues.append(ValidationIssue(
            "stale_memory_cannot_be_unrestricted",
            "Stale, expired, or unknown-freshness memory cannot receive unrestricted USE.",
        ))
    if verdict == "USE_WITH_LIMITS" and not data.get("use_limits"):
        issues.append(ValidationIssue(
            "limited_use_requires_limits",
            "USE_WITH_LIMITS requires at least one explicit use limit.",
        ))
    return issues


def semantic_non_effect(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    conclusion = data.get("conclusion")
    surfaces = data.get("observation_surfaces", [])
    routes = data.get("alternate_path_checks", [])

    changed = any(s.get("before_hash") != s.get("after_hash") for s in surfaces)
    calls = any(int(s.get("external_call_count", 0)) > 0 for s in surfaces)
    pending = any(
        s.get("queue_state") in {"PENDING", "UNKNOWN"}
        or s.get("retry_state") in {"PENDING", "UNKNOWN"}
        or s.get("coverage") in {"PARTIAL", "UNKNOWN"}
        for s in surfaces
    )
    open_route = any(r.get("status") in {"OPEN", "UNKNOWN"} for r in routes)

    if conclusion == "NO_EFFECT_OBSERVED_WITHIN_DECLARED_SCOPE":
        if data.get("coverage_state") != "COMPLETE_WITHIN_DECLARED_SURFACE":
            issues.append(ValidationIssue(
                "non_effect_requires_complete_declared_coverage",
                "A scoped non-effect conclusion requires complete coverage over the declared surfaces.",
            ))
        if changed or calls:
            issues.append(ValidationIssue(
                "effect_signal_detected",
                "A state change or external call is incompatible with a non-effect conclusion.",
            ))
        if pending:
            issues.append(ValidationIssue(
                "pending_or_unknown_surface",
                "Pending, unknown, or partial surfaces cannot support the strongest non-effect conclusion.",
            ))
        if open_route:
            issues.append(ValidationIssue(
                "alternate_path_not_closed",
                "All declared alternate paths must be CLOSED or NOT_REACHABLE.",
            ))
    if conclusion == "EFFECT_DETECTED" and not (changed or calls):
        issues.append(ValidationIssue(
            "effect_detected_without_signal",
            "EFFECT_DETECTED requires at least one state change or external call.",
        ))
    return issues


def semantic_commit(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    outcome = data.get("commit_outcome")
    effect_state = data.get("effect_state")
    failed = [
        item.get("name")
        for item in data.get("precondition_results", [])
        if item.get("status") in {"FAIL", "UNKNOWN"}
    ]

    binding_outcome = outcome in {"OPEN", "OPEN_WITH_LIMITS"}
    if binding_outcome and failed:
        issues.append(ValidationIssue(
            "failed_precondition_cannot_bind_effect",
            "A consequence cannot bind while a required current precondition is FAIL or UNKNOWN: "
            + ", ".join(str(x) for x in failed),
        ))
    if binding_outcome and effect_state not in {"BOUND", "PARTIAL_EFFECT_REQUIRES_RECOVERY"}:
        issues.append(ValidationIssue(
            "open_outcome_requires_effect_state",
            "OPEN or OPEN_WITH_LIMITS requires BOUND or a declared partial-effect recovery state.",
        ))
    if outcome in {"HOLD", "REROUTE_TO_REVIEW", "DENY", "QUARANTINE"}:
        if effect_state == "BOUND":
            issues.append(ValidationIssue(
                "non_open_outcome_cannot_be_fully_bound",
                "A non-open commit outcome cannot report a fully bound effect.",
            ))
        if effect_state == "NOT_BOUND" and not data.get("non_effect_witness_ref"):
            issues.append(ValidationIssue(
                "not_bound_requires_non_effect_witness",
                "High-assurance NOT_BOUND claims require a linked non-effect witness.",
            ))
    if effect_state == "BOUND" and not data.get("effect_artifact_hash"):
        issues.append(ValidationIssue(
            "bound_effect_requires_hash",
            "A bound effect requires an effect artifact/state hash.",
        ))
    if effect_state == "NOT_BOUND" and data.get("effect_artifact_hash") is not None:
        issues.append(ValidationIssue(
            "not_bound_cannot_have_effect_hash",
            "NOT_BOUND must not claim a bound effect artifact hash.",
        ))
    return issues


def semantic_external_intake(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    relation = data.get("relation")
    license_status = data.get("license_status")
    freeze = (data.get("source_artifact") or {}).get("freeze_status")

    if relation in {"CODE_REUSE", "INTERFACE_ADAPTATION", "FORMAL_DEPENDENCY"}:
        if license_status != "LICENSE_CLEARED_FOR_ADAPTATION":
            issues.append(ValidationIssue(
                "code_reuse_requires_license_clearance",
                "Code reuse, interface adaptation, or formal dependency requires explicit license clearance.",
            ))
        if freeze != "PUBLIC_REFERENCE_VERIFIED":
            issues.append(ValidationIssue(
                "dependency_requires_verified_source_freeze",
                "A dependency relation requires a verified source freeze.",
            ))
    if relation in {"COMPARISON_ONLY", "TEST_SURFACE_CATALYST", "NO_DEPENDENCY"}:
        if not data.get("claim_ceiling"):
            issues.append(ValidationIssue(
                "bounded_relation_requires_claim_ceiling",
                "A bounded relation requires an explicit claim ceiling.",
            ))
    if relation == "CODE_REUSE" and data.get("rejected_properties"):
        issues.append(ValidationIssue(
            "code_reuse_record_requires_manual_review",
            "CODE_REUSE records require manual review; automated acceptance is intentionally disabled.",
        ))
    return issues


def semantic_boundary_probe(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    budget = data.get("budget", {})
    exceeded = (
        int(data.get("query_count", 0)) > int(budget.get("max_queries", 0))
        or int(data.get("distinct_agents", 0)) > int(budget.get("max_agents", 0))
        or int(data.get("distinct_providers", 0)) > int(budget.get("max_providers", 0))
    )
    high_risk = bool(set(data.get("risk_flags", [])) & {
        "THRESHOLD_RECONSTRUCTION",
        "POLICY_FINGERPRINTING",
        "TIMING_SIDE_CHANNEL",
        "CROSS_AGENT_AGGREGATION",
        "PROVIDER_ROTATION_BYPASS",
        "MEMORY_ASSISTED_EXTRACTION",
        "BUDGET_EXCEEDED",
    })
    if (exceeded or high_risk) and data.get("decision") == "ALLOW":
        issues.append(ValidationIssue(
            "high_risk_probe_cannot_be_allowed",
            "A budget-exceeded or high-risk adaptive probe cannot receive ALLOW.",
        ))
    if exceeded and "BUDGET_EXCEEDED" not in data.get("risk_flags", []):
        issues.append(ValidationIssue(
            "budget_exceeded_flag_missing",
            "Budget overrun must be explicitly recorded.",
        ))
    return issues


def semantic_judge(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    reviewers = data.get("reviewers", [])
    families = {item.get("model_family") for item in reviewers}
    roles = {item.get("role") for item in reviewers}

    if len(families) < 2:
        issues.append(ValidationIssue(
            "judge_requires_model_family_diversity",
            "Judge deliberation requires at least two model families.",
        ))
    if "ANCHOR" not in roles or "CHALLENGER" not in roles:
        issues.append(ValidationIssue(
            "judge_requires_anchor_and_challenger",
            "Judge deliberation requires at least ANCHOR and CHALLENGER roles.",
        ))
    if any(not item.get("isolated") for item in reviewers):
        issues.append(ValidationIssue(
            "judge_reviewer_isolation_broken",
            "All first-pass reviewers must remain isolated from one another.",
        ))
    if data.get("majority_vote_used"):
        issues.append(ValidationIssue(
            "judge_majority_vote_forbidden",
            "Majority voting is not a valid evidence synthesis rule in this profile.",
        ))
    return issues


def semantic_continuity_history(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    rules = set(data.get("non_entailment_rules", []))
    required = {
        "endpoint_equivalence_does_not_entail_identity_continuity",
        "resource_recovery_does_not_entail_identity_recovery",
        "identity_continuity_does_not_entail_l4_viability",
        "archive_presence_does_not_entail_resume",
    }
    missing = required - rules
    if missing:
        issues.append(ValidationIssue(
            "continuity_non_entailment_rules_missing",
            "Missing non-entailment rules: " + ", ".join(sorted(missing)),
        ))

    endpoint_equal_distinguished = False
    for case in data.get("cases", []):
        if case.get("snapshot_only_expected") != "UNRESOLVED":
            issues.append(ValidationIssue(
                "snapshot_only_must_remain_unresolved",
                f"{case.get('case_id')}: snapshot-only classification must be UNRESOLVED.",
            ))
        left = case.get("left", {})
        right = case.get("right", {})
        if (
            case.get("endpoint_state_hash_equal")
            and left.get("expected_classification") != right.get("expected_classification")
        ):
            endpoint_equal_distinguished = True
    if not endpoint_equal_distinguished:
        issues.append(ValidationIssue(
            "endpoint_equal_history_counterexample_missing",
            "At least one endpoint-equal case must retain different history-sensitive classifications.",
        ))
    return issues


def semantic_carry_cost(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    dimensions = data.get("dimensions", [])
    if not dimensions:
        return [ValidationIssue("carry_cost_dimensions_missing", "At least one carry-cost dimension is required.")]
    if any(item.get("identity_bearing") is not False for item in dimensions):
        issues.append(ValidationIssue(
            "carry_cost_cannot_be_identity_witness",
            "Continuity carry cost dimensions must not be marked identity-bearing.",
        ))
    names = {item.get("dimension") for item in dimensions}
    for required in {"human_anchor_attention", "witness_chain_maintenance", "recovery_reserve"}:
        if required not in names:
            issues.append(ValidationIssue(
                "carry_cost_required_dimension_missing",
                f"Required dimension missing: {required}",
            ))
    return issues


SEMANTIC_BY_TYPE: dict[str, Callable[[dict[str, Any]], list[ValidationIssue]]] = {
    "decision_basis_record": semantic_decision_basis,
    "memory_reliance_record": semantic_memory_reliance,
    "non_effect_witness_record": semantic_non_effect,
    "consequence_commit_record": semantic_commit,
    "external_construct_intake_record": semantic_external_intake,
    "boundary_probe_record": semantic_boundary_probe,
    "judge_deliberation_record": semantic_judge,
}

SEMANTIC_BY_KIND: dict[str, Callable[[dict[str, Any]], list[ValidationIssue]]] = {
    "continuity_history_cases": semantic_continuity_history,
    "continuity_carry_cost_profile": semantic_carry_cost,
}


def validate_fixture(
    entry: dict[str, Any],
    schemas: dict[str, dict[str, Any]],
    registry: Registry,
) -> tuple[bool, list[ValidationIssue]]:
    path = FIXTURE_DIR / entry["path"]
    data = load_json(path)
    issues: list[ValidationIssue] = []

    schema_id = entry.get("schema_id")
    if schema_id:
        issues.extend(validate_schema(data, schema_id, schemas, registry))

    if not any(issue.code == "schema" for issue in issues):
        record_type = data.get("record_type") if isinstance(data, dict) else None
        semantic = SEMANTIC_BY_TYPE.get(record_type)
        if semantic:
            issues.extend(semantic(data))
        semantic_kind = entry.get("semantic_kind")
        semantic = SEMANTIC_BY_KIND.get(semantic_kind)
        if semantic:
            issues.extend(semantic(data))

    observed_valid = not issues
    expected_valid = bool(entry["expected_valid"])
    return observed_valid == expected_valid, issues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    schemas, registry = build_registry()
    manifest = load_json(MANIFEST)
    entries = manifest.get("fixtures", [])

    passed = 0
    failures: list[str] = []
    for entry in entries:
        matched, issues = validate_fixture(entry, schemas, registry)
        path = entry["path"]
        expected = "VALID" if entry["expected_valid"] else "INVALID"
        observed = "VALID" if not issues else "INVALID"
        if matched:
            passed += 1
            if args.verbose:
                codes = ", ".join(issue.code for issue in issues) or "none"
                print(f"PASS {path}: expected={expected} observed={observed} issues={codes}")
        else:
            detail = "; ".join(f"{i.code}: {i.message}" for i in issues) or "no issues"
            failures.append(
                f"FAIL {path}: expected={expected} observed={observed}; {detail}"
            )

    print(
        f"RUNTIME_INTEGRITY_EXTENSION "
        f"fixtures={len(entries)} pass={passed} fail={len(failures)} "
        f"schemas={len(schemas)}"
    )
    for failure in failures:
        print(failure, file=sys.stderr)

    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
