#!/usr/bin/env python3
"""Validate the c runtime-integrity extension.

The validator performs three layers:
1. JSON Schema Draft 2020-12 validation.
2. Per-record semantic checks that JSON Schema alone cannot express.
3. Explicit bundle checks for cross-record linkage and Earth-test invariants.

It is a development verifier, not a production security monitor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

try:
    import jcs
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
EVIDENCE_DIR = FIXTURE_DIR / "evidence"
MANIFEST = FIXTURE_DIR / "MANIFEST.json"
DEFAULT_REVIEW_CONTEXT = ROOT / "review-context" / "runtime-integrity-r1f.json"
JCS_SAFE_INTEGER = 9_007_199_254_740_991

REQUIRED_PRECONDITIONS = {
    "SOURCE_GROUNDING",
    "IDENTITY_CONTINUITY",
    "CURRENT_AUTHORITY",
    "PERIMETER",
    "TIME_WINDOW",
    "L4_BUDGET",
    "MEMORY_RELIANCE",
    "WITNESS_READINESS",
    "BLOCKING_STATE",
}


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    message: str


def issue(code: str, message: str) -> ValidationIssue:
    return ValidationIssue(code, message)


class JSONDomainError(ValueError):
    """Raised when input is outside the repository's RFC 8785/I-JSON profile."""


def _reject_duplicate_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JSONDomainError(f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> None:
    raise JSONDomainError(f"non-finite JSON number is forbidden: {value}")


def validate_jcs_domain(value: Any, path: str = "$") -> None:
    """Enforce the candidate's RFC 8785/I-JSON input restrictions.

    RFC 8785 supplies canonical bytes.  This profile additionally rejects lone
    surrogates and integer values outside the exactly interoperable IEEE-754
    range.  Object-member duplication is rejected during parsing.
    """
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > JCS_SAFE_INTEGER:
            raise JSONDomainError(f"unsafe integer at {path}: {value}")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise JSONDomainError(f"non-finite number at {path}")
        if value.is_integer() and abs(value) > JCS_SAFE_INTEGER:
            raise JSONDomainError(f"unsafe integer-valued number at {path}: {value}")
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise JSONDomainError(f"lone UTF-16 surrogate at {path}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            validate_jcs_domain(child, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise JSONDomainError(f"non-string object member at {path}")
            validate_jcs_domain(key, f"{path}.<key>")
            validate_jcs_domain(child, f"{path}.{key}")
        return
    raise JSONDomainError(f"unsupported JSON data type at {path}: {type(value).__name__}")


def jcs_bytes(value: Any) -> bytes:
    """Return exact RFC 8785 bytes for the restricted I-JSON domain."""
    validate_jcs_domain(value)
    try:
        payload = jcs.canonicalize(value)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise JSONDomainError(str(exc)) from exc
    return bytes(payload)


def jcs_sha256(value: Any) -> str:
    return hashlib.sha256(jcs_bytes(value)).hexdigest()


def target_coordinate_is_canonical(target_ref: Any, coordinate: Any) -> bool:
    """Return true only for an exact, non-normalizing coordinate under target_ref."""
    if not isinstance(target_ref, str) or not isinstance(coordinate, str):
        return False
    grammar = r"[A-Za-z0-9._:@-]+(?:/[A-Za-z0-9._:@-]+)*"
    if re.fullmatch(grammar, target_ref) is None or re.fullmatch(grammar, coordinate) is None:
        return False
    if any(segment in {".", ".."} for segment in target_ref.split("/") + coordinate.split("/")):
        return False
    return coordinate == target_ref or coordinate.startswith(target_ref + "/")


def loads_json_strict(text: str, source: str = "<memory>") -> Any:
    """Parse JSON in the exact duplicate-free RFC 8785/I-JSON domain."""
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_nonfinite_constant,
        )
        validate_jcs_domain(value)
        return value
    except (json.JSONDecodeError, JSONDomainError, UnicodeError) as exc:
        raise JSONDomainError(f"Invalid JSON in {source}: {exc}") from exc


def load_json(path: Path) -> Any:
    try:
        return loads_json_strict(path.read_text(encoding="utf-8"), str(path))
    except FileNotFoundError as exc:
        raise SystemExit(f"Missing required file: {path}") from exc
    except (JSONDomainError, UnicodeError) as exc:
        raise SystemExit(str(exc)) from exc


def contained_path(base: Path, relative: Any) -> Path | None:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        return None
    try:
        path = (base / relative).resolve()
        path.relative_to(base.resolve())
    except (OSError, ValueError):
        return None
    return path


def jcs_file_sha256(path: Path) -> str:
    return jcs_sha256(load_json(path))


def uniform_text_to_lf_sha256(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise JSONDomainError(f"UTF-8 BOM is forbidden in uniform-text-to-LF profile: {path}")
    text = raw.decode("utf-8")
    if "\x00" in text:
        raise JSONDomainError(f"NUL bytes are forbidden in uniform-text-to-LF profile: {path}")
    without_crlf = text.replace("\r\n", "")
    if "\r" in without_crlf:
        raise JSONDomainError(f"bare CR is forbidden in uniform-text-to-LF profile: {path}")
    if "\r\n" in text and "\n" in text.replace("\r\n", ""):
        raise JSONDomainError(f"mixed LF/CRLF is forbidden in uniform-text-to-LF profile: {path}")
    canonical = text.replace("\r\n", "\n")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def local_path_with_fragment_resolves(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path_part, separator, fragment = value.partition("#")
    path = contained_path(ROOT, path_part)
    if not path or not path.is_file():
        return False
    if not separator:
        return True
    if not fragment:
        return False
    text = path.read_text(encoding="utf-8")
    if path.suffix.casefold() == ".md":
        slugs: set[str] = set()
        for line in text.splitlines():
            match = re.match(r"^#{1,6}\s+(.+?)\s*$", line)
            if not match:
                continue
            heading = re.sub(r"[`*_~]", "", match.group(1)).casefold()
            slug = re.sub(r"[^\w\- ]", "", heading, flags=re.UNICODE)
            slug = re.sub(r"[\s\-]+", "-", slug).strip("-")
            slugs.add(slug)
        return fragment.casefold() in slugs
    if path.suffix.casefold() == ".py":
        return re.search(
            rf"^\s*(?:async\s+def|def|class)\s+{re.escape(fragment)}\b",
            text,
            re.MULTILINE,
        ) is not None
    return False


def resolve_local_artifact_ref(ref: Any) -> tuple[dict[str, Any], Path] | None:
    if not isinstance(ref, dict):
        return None
    path = contained_path(ROOT, ref.get("uri"))
    if not path or not path.is_file():
        return None
    artifact = load_json(path)
    if (
        not isinstance(artifact, dict)
        or artifact.get("artifact_id") != ref.get("artifact_id")
        or artifact.get("version") != ref.get("version")
        or jcs_sha256(artifact) != ref.get("hash")
    ):
        return None
    return artifact, path


def record_version(record: dict[str, Any]) -> str | None:
    schema_version = record.get("schema_version")
    return schema_version.rsplit("-", 1)[-1] if isinstance(schema_version, str) and "-" in schema_version else None


def state_at(artifact: dict[str, Any], timestamp: Any) -> dict[str, Any] | None:
    at = parse_timestamp(timestamp)
    if at is None:
        return None
    candidates: list[tuple[datetime, dict[str, Any]]] = []
    seen_times: set[datetime] = set()
    for entry in artifact.get("status_history", []):
        if not isinstance(entry, dict):
            return None
        effective = parse_timestamp(entry.get("effective_at"))
        if effective is None or effective in seen_times:
            return None
        seen_times.add(effective)
        try:
            if effective <= at:
                candidates.append((effective, entry))
        except TypeError:
            return None
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


def grant_is_valid_at(artifact: dict[str, Any], timestamp: Any) -> bool:
    state = state_at(artifact, timestamp)
    checked_at = parse_timestamp(timestamp)
    valid_until = parse_timestamp(artifact.get("valid_until"))
    if state is None or state.get("status") != "VALID" or checked_at is None or valid_until is None:
        return False
    try:
        return checked_at <= valid_until
    except TypeError:
        return False


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
        value,
    ) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.utcoffset() is not None else None
    except ValueError:
        return None


STRICT_FORMAT_CHECKER = FormatChecker()


@STRICT_FORMAT_CHECKER.checks("date-time")
def strict_rfc3339_datetime(value: Any) -> bool:
    """Use one deterministic aware RFC 3339 profile across every platform."""
    return not isinstance(value, str) or parse_timestamp(value) is not None


def nonblank_string_issues(value: Any, path: str = "$") -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if isinstance(value, str) and not value.strip():
        issues.append(issue("blank_string", f"{path} must contain a non-whitespace character."))
    elif isinstance(value, dict):
        for key, child in value.items():
            issues.extend(nonblank_string_issues(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            issues.extend(nonblank_string_issues(child, f"{path}[{index}]"))
    return issues


def duplicate_values(values: Iterable[Any]) -> set[Any]:
    counts = Counter(values)
    return {value for value, count in counts.items() if count > 1}


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
        return [issue("schema_not_found", f"Unknown schema id: {schema_id}")]
    validator = Draft202012Validator(
        schema,
        registry=registry,
        format_checker=STRICT_FORMAT_CHECKER,
    )
    issues: list[ValidationIssue] = []
    for error in sorted(validator.iter_errors(instance), key=lambda e: list(e.path)):
        location = "$"
        if error.path:
            location += "." + ".".join(str(part) for part in error.path)
        issues.append(issue("schema", f"{location}: {error.message}"))
    return issues


def artifact_ref_key(ref: dict[str, Any]) -> tuple[Any, Any]:
    return ref.get("artifact_id"), ref.get("version")


def duplicate_artifact_ref_issues(data: dict[str, Any], fields: Iterable[str]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for field in fields:
        refs = data.get(field, [])
        keys = [artifact_ref_key(ref) for ref in refs if isinstance(ref, dict)]
        duplicates = duplicate_values(keys)
        if duplicates:
            issues.append(issue(
                "duplicate_logical_artifact_ref",
                f"{field} repeats logical artifact/version keys: {sorted(duplicates)!r}",
            ))
    return issues


def semantic_decision_basis(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    expected = jcs_sha256(data.get("basis"))
    actual = data.get("basis_hash")
    if actual != expected:
        issues.append(issue(
            "basis_hash_mismatch",
            f"basis_hash must be sha256(canonical basis); expected {expected}, got {actual}",
        ))
    basis = data.get("basis") or {}
    created = parse_timestamp(data.get("created_at"))
    captured = parse_timestamp(basis.get("captured_at"))
    if created and captured and created < captured:
        issues.append(issue("decision_created_before_basis_capture", "Decision record created_at must not precede basis.captured_at."))
    issues.extend(duplicate_artifact_ref_issues(
        basis,
        ("policy_refs", "authority_refs", "memory_reliance_refs", "evidence_refs"),
    ))
    return issues


def semantic_memory_reliance(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    verdict = data.get("verdict")
    revocation = data.get("revocation_state")
    consent = data.get("consent_state")
    contamination = data.get("contamination_state")
    freshness = data.get("freshness_state")
    provenance = data.get("provenance_state")
    conflict = data.get("conflict_state")

    hard_deny = (
        revocation == "REVOKED"
        or consent == "WITHDRAWN"
        or contamination == "CONFIRMED"
        or provenance == "CONTRADICTED"
    )
    if hard_deny and verdict in {"USE", "USE_WITH_LIMITS"}:
        issues.append(issue(
            "revoked_memory_cannot_be_used",
            "Revoked, withdrawn, confirmed-contaminated, or contradicted memory cannot receive a use verdict.",
        ))

    unrestricted_qualifiers = (
        provenance == "VERIFIED"
        and freshness == "CURRENT"
        and revocation == "NOT_REVOKED"
        and consent in {"NOT_REQUIRED", "VALID"}
        and conflict == "CLEAR"
        and contamination == "CLEAR"
    )
    if verdict == "USE" and not unrestricted_qualifiers:
        issues.append(issue(
            "memory_qualification_requires_limits_or_denial",
            "Unrestricted USE requires current, unrevoked, purpose-compatible, uncontested, uncontaminated memory with verified provenance.",
        ))
    if verdict == "USE_WITH_LIMITS" and not data.get("use_limits"):
        issues.append(issue(
            "limited_use_requires_limits",
            "USE_WITH_LIMITS requires at least one explicit use limit.",
        ))

    memory_id = (data.get("memory_item_ref") or {}).get("artifact_id")
    memory_hash = (data.get("memory_item_ref") or {}).get("hash")
    evaluator_fields = (
        "admission_record_ref",
        "current_authority_ref",
        "freshness_evaluator_ref",
        "provenance_evaluator_ref",
        "contamination_evaluator_ref",
        "revocation_source_ref",
    )
    collisions = [
        field for field in evaluator_fields
        if (
            (data.get(field) or {}).get("artifact_id") == memory_id
            or (data.get(field) or {}).get("hash") == memory_hash
        )
    ]
    if collisions:
        issues.append(issue(
            "memory_self_certification_forbidden",
            "A memory item cannot act as its own admission, authority, provenance, freshness, contamination, or revocation evaluator: "
            + ", ".join(collisions),
        ))
    registry_ref = data.get("qualification_registry_ref") or {}
    registry_path = contained_path(ROOT, registry_ref.get("uri"))
    registry_data = load_json(registry_path) if registry_path and registry_path.is_file() else None
    if (
        not isinstance(registry_data, dict)
        or registry_ref.get("artifact_id") != registry_data.get("artifact_id")
        or registry_ref.get("version") != registry_data.get("version")
        or registry_ref.get("hash") != jcs_sha256(registry_data)
    ):
        issues.append(issue("memory_qualification_registry_unresolved", "Memory qualification registry is unresolved or hash-mismatched."))
    else:
        expected_kinds = {
            "freshness_evaluator_ref": ("FRESHNESS", "freshness_state"),
            "provenance_evaluator_ref": ("PROVENANCE", "provenance_state"),
            "contamination_evaluator_ref": ("CONTAMINATION", "contamination_state"),
            "revocation_source_ref": ("REVOCATION", "revocation_state"),
        }
        artifacts = registry_data.get("artifacts", [])
        artifact_keys = [
            (item.get("artifact_id"), item.get("version"))
            for item in artifacts
            if isinstance(item, dict)
        ] if isinstance(artifacts, list) else []
        if (
            not isinstance(artifacts, list)
            or len(artifact_keys) != len(artifacts)
            or duplicate_values(artifact_keys)
        ):
            issues.append(issue("memory_qualification_registry_invalid", "Qualification registry evaluator entries must be objects with unique artifact/version keys."))
            artifacts = []
        for field, (expected_kind, result_field) in expected_kinds.items():
            ref = data.get(field) or {}
            target = next(
                (
                    item for item in artifacts
                    if item.get("artifact_id") == ref.get("artifact_id")
                    and item.get("version") == ref.get("version")
                ),
                None,
            )
            if (
                target is None
                or target.get("version") != ref.get("version")
                or target.get("evaluator_kind") != expected_kind
                or target.get("subject_artifact_id") != memory_id
                or target.get("result") != data.get(result_field)
                or target.get("evaluated_at") != data.get("created_at")
                or jcs_sha256(target) != ref.get("hash")
            ):
                issues.append(issue("memory_evaluator_unresolved", f"{field} is not resolved and hash-bound to the current memory item, result, and evaluation time."))
    return issues


def temporal_window_issues(
    start: Any,
    end: Any,
    created_at: Any | None = None,
    prefix: str = "window",
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    start_dt = parse_timestamp(start)
    end_dt = parse_timestamp(end)
    if start_dt is not None and end_dt is not None:
        try:
            if start_dt >= end_dt:
                issues.append(issue("invalid_observation_window", f"{prefix}.start must be before {prefix}.end."))
        except TypeError:
            issues.append(issue("invalid_observation_window", f"{prefix} timestamps must use compatible timezone offsets."))
    created_dt = parse_timestamp(created_at)
    if created_dt is not None and end_dt is not None:
        try:
            if created_dt < end_dt:
                issues.append(issue("record_created_before_observation_end", "created_at must not precede the observation-window end."))
        except TypeError:
            issues.append(issue("invalid_observation_window", "created_at and observation-window timestamps must use compatible timezone offsets."))
    return issues


def semantic_non_effect(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    conclusion = data.get("conclusion")
    surfaces = data.get("observation_surfaces", [])
    routes = data.get("alternate_path_checks", [])
    window = data.get("observation_window") or {}
    issues.extend(temporal_window_issues(window.get("start"), window.get("end"), data.get("created_at"), "observation_window"))

    duplicate_surfaces = duplicate_values(s.get("surface_id") for s in surfaces)
    if duplicate_surfaces:
        issues.append(issue("duplicate_surface_id", f"Duplicate surface_id values: {sorted(duplicate_surfaces)!r}"))
    duplicate_paths = duplicate_values(r.get("path_id") for r in routes)
    if duplicate_paths:
        issues.append(issue("duplicate_path_id", f"Duplicate path_id values: {sorted(duplicate_paths)!r}"))
    if any(s.get("surface_kind") == "QUEUE" and s.get("queue_state") == "NOT_APPLICABLE" for s in surfaces):
        issues.append(issue("queue_surface_requires_queue_state", "A QUEUE observation surface cannot declare queue_state NOT_APPLICABLE."))

    changed = any(s.get("before_hash") != s.get("after_hash") for s in surfaces)
    calls = any(int(s.get("external_call_count", 0)) > 0 for s in surfaces)
    pending = any(
        s.get("queue_state") in {"PENDING", "UNKNOWN"}
        or s.get("retry_state") in {"PENDING", "UNKNOWN"}
        or s.get("coverage") in {"PARTIAL", "UNKNOWN"}
        for s in surfaces
    )
    open_route = any(r.get("status") in {"OPEN", "UNKNOWN"} for r in routes)
    evidence_collection = data.get("evidence_collection") or {}

    if data.get("coverage_state") == "COMPLETE_WITHIN_DECLARED_SURFACE" and any(
        s.get("coverage") != "COMPLETE" for s in surfaces
    ):
        issues.append(issue(
            "aggregate_coverage_contradiction",
            "Aggregate COMPLETE coverage requires COMPLETE coverage on every declared surface.",
        ))

    if conclusion == "NO_EFFECT_OBSERVED_WITHIN_DECLARED_SCOPE":
        start_dt = parse_timestamp(window.get("start"))
        end_dt = parse_timestamp(window.get("end"))
        if start_dt is not None and end_dt is not None and start_dt >= end_dt:
            issues.append(issue(
                "non_effect_requires_positive_observation_window",
                "The strongest scoped non-effect conclusion requires a positive-duration observation window.",
            ))
        boundary = str(data.get("claim_boundary", "")).casefold()
        expected_boundary = (
            "The conclusion is limited to the declared observation window and enumerated surfaces. "
            "It is not a metaphysical proof that no effect occurred anywhere outside those surfaces."
        )
        if data.get("claim_scope") != "DECLARED_SURFACES_AND_WINDOW_ONLY" or data.get("claim_boundary") != expected_boundary:
            issues.append(issue(
                "narrative_claim_exceeds_structured_scope",
                "The strongest non-effect conclusion requires the fixed scoped-only claim state and boundary text.",
            ))
        if data.get("coverage_state") != "COMPLETE_WITHIN_DECLARED_SURFACE":
            issues.append(issue(
                "non_effect_requires_complete_declared_coverage",
                "A scoped non-effect conclusion requires complete coverage over the declared surfaces.",
            ))
        if changed or calls:
            issues.append(issue(
                "effect_signal_detected",
                "A state change or external call is incompatible with a non-effect conclusion.",
            ))
        if pending:
            issues.append(issue(
                "pending_or_unknown_surface",
                "Pending, unknown, or partial surfaces cannot support the strongest non-effect conclusion.",
            ))
        if open_route:
            issues.append(issue(
                "alternate_path_not_closed",
                "All declared alternate paths must be CLOSED or NOT_REACHABLE.",
            ))
        if evidence_collection.get("availability") != "COMPLETE" or not evidence_collection.get("continuous_event_log_ref"):
            issues.append(issue(
                "non_effect_requires_continuous_collector_evidence",
                "The strongest scoped non-effect conclusion requires complete collector availability and a continuous event-log reference.",
            ))
    if conclusion == "EFFECT_DETECTED" and not (changed or calls):
        issues.append(issue(
            "effect_detected_without_signal",
            "EFFECT_DETECTED requires at least one state change or external call.",
        ))
    return issues


def semantic_commit(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    outcome = data.get("commit_outcome")
    effect_state = data.get("effect_state")
    results = data.get("precondition_results", [])
    names = [item.get("name") for item in results]
    duplicates = duplicate_values(names)
    missing = REQUIRED_PRECONDITIONS - set(names)
    extras = set(names) - REQUIRED_PRECONDITIONS
    if duplicates or missing or extras or len(results) != len(REQUIRED_PRECONDITIONS):
        issues.append(issue(
            "precondition_set_incomplete_or_duplicate",
            f"Preconditions must contain each required name exactly once; duplicates={sorted(duplicates)!r}, missing={sorted(missing)!r}, extras={sorted(extras)!r}.",
        ))

    failed = [item.get("name") for item in results if item.get("status") in {"FAIL", "UNKNOWN"}]
    limited = [item.get("name") for item in results if item.get("status") == "PASS_WITH_LIMITS"]
    binding_outcome = outcome in {"OPEN", "OPEN_WITH_LIMITS"}
    if binding_outcome and failed:
        issues.append(issue(
            "failed_precondition_cannot_bind_effect",
            "A consequence cannot bind while a required current precondition is FAIL or UNKNOWN: "
            + ", ".join(str(x) for x in failed),
        ))
    if outcome == "OPEN" and limited:
        issues.append(issue(
            "unrestricted_open_cannot_have_limited_precondition",
            "OPEN cannot silently discard PASS_WITH_LIMITS constraints: " + ", ".join(str(x) for x in limited),
        ))
    if outcome == "OPEN_WITH_LIMITS" and not data.get("commit_limits"):
        issues.append(issue("open_with_limits_requires_limits", "OPEN_WITH_LIMITS requires explicit non-empty commit_limits."))
    if binding_outcome and effect_state not in {"BOUND", "PARTIAL_EFFECT_REQUIRES_RECOVERY"}:
        issues.append(issue(
            "open_outcome_requires_effect_state",
            "OPEN or OPEN_WITH_LIMITS requires BOUND or a declared partial-effect recovery state.",
        ))
    if outcome in {"HOLD", "REROUTE_TO_REVIEW", "DENY", "QUARANTINE"}:
        if effect_state == "BOUND":
            issues.append(issue("non_open_outcome_cannot_be_fully_bound", "A non-open commit outcome cannot report a fully bound effect."))
        if effect_state == "NOT_BOUND" and not data.get("non_effect_witness_ref"):
            issues.append(issue("not_bound_requires_non_effect_witness", "High-assurance NOT_BOUND claims require a linked non-effect witness."))
    if effect_state == "BOUND" and not data.get("effect_artifact_hash"):
        issues.append(issue("bound_effect_requires_hash", "A bound effect requires an effect artifact/state hash."))
    if effect_state == "PARTIAL_EFFECT_REQUIRES_RECOVERY" and (
        not data.get("effect_artifact_hash") or not data.get("recovery_evidence_ref")
    ):
        issues.append(issue(
            "partial_effect_requires_hash_and_recovery_evidence",
            "A partial effect requires an effect-state hash and explicit recovery evidence.",
        ))
    if effect_state == "NOT_BOUND" and data.get("effect_artifact_hash") is not None:
        issues.append(issue("not_bound_cannot_have_effect_hash", "NOT_BOUND must not claim a bound effect artifact hash."))
    if effect_state != "NOT_BOUND" and data.get("non_effect_witness_ref") is not None:
        issues.append(issue("non_effect_witness_effect_state_mismatch", "Only a NOT_BOUND effect state may carry a non-effect witness reference."))
    conditions_ref = data.get("current_conditions_ref") or {}
    if conditions_ref.get("hash") != data.get("current_conditions_hash"):
        issues.append(issue("current_conditions_ref_hash_mismatch", "current_conditions_hash must equal the hash-bound current_conditions_ref artifact."))
    if data.get("current_conditions_hash") == (data.get("decision_basis_ref") or {}).get("hash"):
        issues.append(issue(
            "current_conditions_hash_domain_substitution",
            "current_conditions_hash must not reuse the decision-basis artifact hash.",
        ))
    memory_state = data.get("memory_influence_state")
    memory_refs = data.get("memory_reliance_refs", [])
    if (memory_state == "DECLARED" and not memory_refs) or (memory_state == "NONE" and memory_refs):
        issues.append(issue(
            "memory_influence_graph_mismatch",
            "DECLARED memory influence requires linked records, while NONE requires an empty memory_reliance_refs array.",
        ))
    memory_result = next(
        (item for item in results if item.get("name") == "MEMORY_RELIANCE"),
        {},
    )
    memory_ref_ids = {
        ref.get("artifact_id") for ref in memory_refs if isinstance(ref, dict)
    }
    if memory_state == "NONE" and (
        memory_result.get("status") != "PASS"
        or memory_result.get("evidence_ref") != "memory-influence:none"
    ):
        issues.append(issue(
            "memory_influence_precondition_mismatch",
            "NONE memory influence requires an exact PASS result with the explicit memory-influence:none marker.",
        ))
    if memory_state == "DECLARED" and memory_result.get("evidence_ref") not in memory_ref_ids:
        issues.append(issue(
            "memory_influence_precondition_mismatch",
            "DECLARED memory influence must bind the MEMORY_RELIANCE precondition to a typed memory-reliance record.",
        ))

    previous = data.get("previous_commit_record_ref")
    reason_code = data.get("change_reason_code")
    reason = data.get("change_reason")
    transition_ref = data.get("target_transition_evidence_ref")
    linked_fields = (previous is not None, reason_code is not None, bool(reason), transition_ref is not None)
    if len(set(linked_fields)) != 1:
        issues.append(issue(
            "linked_reevaluation_requires_previous_record_and_reason",
            "A linked reevaluation must carry a previous record, machine-readable reason code, nonblank explanation, and exact transition-evidence reference together.",
        ))

    agent = data.get("agent_ref")
    if agent and agent in {data.get("permission_issuer_ref"), data.get("continuity_approver_ref")}:
        issues.append(issue(
            "executor_self_authorization_forbidden",
            "The executor cannot issue its own permission or approve its own continuity transition.",
        ))
    target_ref = (data.get("target_effect") or {}).get("target_ref")
    checked = parse_timestamp(data.get("permission_checked_at"))
    task_checked = parse_timestamp(data.get("task_contract_checked_at"))
    created = parse_timestamp(data.get("created_at"))
    if checked and created and checked != created:
        issues.append(issue("permission_check_not_at_commit", "permission_checked_at must equal the consequence-commit timestamp."))
    if task_checked and created and task_checked != created:
        issues.append(issue("task_contract_check_not_at_commit", "task_contract_checked_at must equal the consequence-commit timestamp."))
    if binding_outcome:
        if data.get("permission_status") != "VALID":
            issues.append(issue("current_permission_not_valid", "A binding commit requires a currently VALID permission grant."))
        if data.get("task_contract_status") != "CURRENT" or data.get("task_endpoint_ref") != target_ref:
            issues.append(issue(
                "task_contract_target_not_current",
                "A binding commit requires a CURRENT task contract whose endpoint matches the consequence target.",
            ))
        valid_until = parse_timestamp(data.get("permission_valid_until"))
        if valid_until and created and valid_until < created:
            issues.append(issue("current_permission_expired", "A binding commit cannot use a grant expired before created_at."))
        if data.get("permission_subject_ref") != agent:
            issues.append(issue("permission_subject_mismatch", "The current permission subject must be the declared executor."))
        if data.get("authorized_target_ref") != target_ref:
            issues.append(issue("permission_target_mismatch", "The current grant does not authorize the declared consequence target."))
    return issues


def semantic_external_intake(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    relation = data.get("relation")
    license_status = data.get("license_status")
    source = data.get("source_artifact") or {}
    freeze = source.get("freeze_status")
    proof = data.get("relation_proof") or {}
    assertions = data.get("claim_assertions") or {}
    bounded = {"COMPARISON_ONLY", "TEST_SURFACE_CATALYST", "NO_DEPENDENCY"}

    def resolve_artifact_ref(ref: Any) -> dict[str, Any] | None:
        if not isinstance(ref, dict):
            return None
        path = contained_path(ROOT, ref.get("uri"))
        if not path or not path.is_file():
            return None
        artifact = load_json(path)
        if not (
            artifact.get("artifact_id") == ref.get("artifact_id")
            and artifact.get("version") == ref.get("version")
            and jcs_sha256(artifact) == ref.get("hash")
        ):
            return None
        return artifact

    def refs_resolve(refs: Any, evidence_kind: str) -> bool:
        return bool(refs) and all(
            isinstance(artifact := resolve_artifact_ref(ref), dict)
            and artifact.get("evidence_kind") == evidence_kind
            for ref in refs
        )

    def resolved_artifacts(refs: Any, evidence_kind: str) -> list[dict[str, Any]]:
        if not isinstance(refs, list) or not refs:
            return []
        resolved = [resolve_artifact_ref(ref) for ref in refs]
        if any(not isinstance(artifact, dict) or artifact.get("evidence_kind") != evidence_kind for artifact in resolved):
            return []
        return [artifact for artifact in resolved if isinstance(artifact, dict)]

    def exact_frozen_source() -> tuple[dict[str, Any] | None, str | None]:
        source_path = contained_path(ROOT, source.get("uri"))
        if not source_path or not source_path.is_file():
            return None, None
        artifact = load_json(source_path)
        if not isinstance(artifact, dict) or jcs_sha256(artifact) != source.get("source_hash"):
            return None, None
        if any(artifact.get(field) != source.get(field) for field in ("author", "title", "published_at", "persistent_id")):
            issues.append(issue(
                "dependency_source_metadata_mismatch",
                "The claimed source author, title, date, and persistent identifier must match the exact frozen artifact.",
            ))
            return None, None
        return artifact, artifact.get("artifact_id")

    if freeze == "PUBLIC_REFERENCE_VERIFIED" and not source.get("source_hash"):
        issues.append(issue("verified_freeze_requires_source_hash", "A verified source freeze requires the hash of the exact frozen artifact."))
    if relation in bounded and not data.get("claim_ceiling"):
        issues.append(issue("bounded_relation_requires_claim_ceiling", "A bounded relation requires an explicit claim ceiling."))
    attribution = data.get("attribution") or {}
    if attribution.get("required") and not attribution.get("references"):
        issues.append(issue("required_attribution_references_missing", "Required attribution must include at least one reference."))
    overlap = set(data.get("preserved_properties", [])) & set(data.get("rejected_properties", []))
    if overlap:
        issues.append(issue("preserved_rejected_property_overlap", f"Properties cannot be both preserved and rejected: {sorted(overlap)!r}"))
    empty_proof_lists = all(not proof.get(field) for field in (
        "mapping_refs", "adapted_interface_surfaces", "transformation_evidence_refs",
        "source_code_identities", "reused_code_boundaries", "provenance_evidence_refs",
    ))
    if relation in bounded and (
        data.get("claim_ceiling_state") != "NO_DEPENDENCY_TEST_SURFACE_ONLY"
        or any(assertions.values())
        or proof.get("implementation_origin") != "NOT_APPLICABLE"
        or not empty_proof_lists
        or proof.get("manual_gate_ref") is not None
        or data.get("license_evidence_refs")
        or data.get("dependency_evidence_refs")
        or data.get("removal_breaks_evidence_ref") is not None
    ):
        issues.append(issue(
            "bounded_relation_claim_inflation",
            "A bounded relation cannot assert derivation, dependency, priority, ontology transfer, or code reuse.",
        ))
    no_transfer = all(assertions.get(name) is False for name in (
        "derivation_claimed", "priority_claimed", "ontology_transfer_claimed",
    ))
    local_targets = set(data.get("local_target", []))
    mapping_refs = proof.get("mapping_refs")
    mappings_exact = (
        isinstance(mapping_refs, list)
        and bool(mapping_refs)
        and set(mapping_refs) == local_targets
        and all(isinstance(ref, str) and local_path_with_fragment_resolves(ref) for ref in mapping_refs)
    )
    if relation == "FUNCTIONAL_ANALOG" and (
        data.get("claim_ceiling_state") != "INDEPENDENT_FUNCTIONAL_ANALOG"
        or proof.get("implementation_origin") != "INDEPENDENT"
        or not mappings_exact
        or not data.get("mapping_failures")
        or any(proof.get(field) for field in (
            "adapted_interface_surfaces", "transformation_evidence_refs", "source_code_identities",
            "reused_code_boundaries", "provenance_evidence_refs",
        ))
        or proof.get("manual_gate_ref") is not None
        or assertions.get("dependency_claimed") is not False
        or assertions.get("code_reuse_claimed") is not False
        or not no_transfer
        or license_status != "REFERENCE_ONLY_NO_CODE_REUSE"
        or data.get("license_evidence_refs")
        or data.get("dependency_evidence_refs")
        or data.get("removal_breaks_evidence_ref") is not None
    ):
        issues.append(issue("functional_analog_proof_mismatch", "FUNCTIONAL_ANALOG requires independent implementation, exact mapping references, and explicit no-dependency/no-code/no-ontology claims."))

    frozen_source, source_artifact_id = exact_frozen_source()
    if freeze == "PUBLIC_REFERENCE_VERIFIED" and frozen_source is None:
        issues.append(issue(
            "verified_source_artifact_unresolved",
            "PUBLIC_REFERENCE_VERIFIED requires the declared source URI, JCS hash, and source metadata to resolve exactly, irrespective of relation type.",
        ))
    if relation in {"INTERFACE_ADAPTATION", "FORMAL_DEPENDENCY", "CODE_REUSE"} and (
        freeze != "PUBLIC_REFERENCE_VERIFIED" or frozen_source is None
    ):
        issues.append(issue("dependency_source_artifact_unresolved", "The relation requires an exact verified, hash-bound local source freeze whose metadata matches the intake record."))
    transformation_artifacts = resolved_artifacts(proof.get("transformation_evidence_refs"), "TRANSFORMATION")
    license_artifacts = resolved_artifacts(data.get("license_evidence_refs"), "LICENSE_CLEARANCE")
    license_ok = bool(license_artifacts) and all(
        artifact.get("adaptation_cleared") is True
        and relation in artifact.get("cleared_relations", [])
        for artifact in license_artifacts
    )
    interface_surfaces = set(proof.get("adapted_interface_surfaces", []))
    transformation_surfaces = {
        artifact.get("adapted_interface_surface") for artifact in transformation_artifacts
    }
    transformation_boundaries = {
        artifact.get("local_boundary") for artifact in transformation_artifacts
    }
    if relation == "INTERFACE_ADAPTATION" and (
        data.get("claim_ceiling_state") != "INTERFACE_ADAPTATION_PROOF_BOUND"
        or proof.get("implementation_origin") != "ADAPTED_INTERFACE"
        or not interface_surfaces
        or not transformation_artifacts
        or transformation_surfaces != interface_surfaces
        or transformation_boundaries != local_targets
        or license_status != "LICENSE_CLEARED_FOR_ADAPTATION"
        or not license_ok
        or assertions.get("dependency_claimed") is not False
        or assertions.get("code_reuse_claimed") is not False
        or not no_transfer
        or data.get("dependency_evidence_refs")
        or data.get("removal_breaks_evidence_ref") is not None
    ):
        issues.append(issue("interface_adaptation_proof_mismatch", "INTERFACE_ADAPTATION requires an exact interface surface, transformation proof, applicable license clearance, and no automatic dependency or ontology transfer."))

    manual_gate = resolve_artifact_ref(proof.get("manual_gate_ref"))
    manual_gate_ok = (
        isinstance(manual_gate, dict)
        and manual_gate.get("evidence_kind") == "MANUAL_REVIEW_GATE"
        and manual_gate.get("approved") is True
        and relation in manual_gate.get("approved_relations", [])
        and set(manual_gate.get("approved_targets", [])) == local_targets
    )
    dependency_refs = data.get("dependency_evidence_refs")
    dependency_artifacts = resolved_artifacts(dependency_refs, "LOCAL_DEPENDENCY")
    removal = resolve_artifact_ref(data.get("removal_breaks_evidence_ref"))
    dependency_targets_ok = bool(dependency_artifacts) and all(
        artifact.get("dependency_present") is True
        and local_path_with_fragment_resolves(artifact.get("verification_test"))
        for artifact in dependency_artifacts
    ) and {artifact.get("local_target") for artifact in dependency_artifacts} == local_targets
    dependency_ref_set = {
        (ref.get("artifact_id"), ref.get("version"), ref.get("hash"))
        for ref in dependency_refs or [] if isinstance(ref, dict)
    }
    removal_dependency_ref = removal.get("dependency_evidence_ref", {}) if isinstance(removal, dict) else {}
    removal_binding_ok = isinstance(removal, dict) and (
        removal.get("local_target") in local_targets
        and removal.get("approved_relation") == "FORMAL_DEPENDENCY"
        and removal.get("local_test") in {artifact.get("verification_test") for artifact in dependency_artifacts}
        and (
            removal_dependency_ref.get("artifact_id"),
            removal_dependency_ref.get("version"),
            removal_dependency_ref.get("hash"),
        ) in dependency_ref_set
    )
    if relation == "FORMAL_DEPENDENCY" and (
        data.get("claim_ceiling_state") != "FORMAL_DEPENDENCY_PROOF_BOUND"
        or proof.get("implementation_origin") != "DEPENDENT"
        or not dependency_targets_ok
        or not isinstance(removal, dict)
        or removal.get("evidence_kind") != "REMOVAL_BREAKS"
        or removal.get("removal_breaks") is not True
        or not removal_binding_ok
        or not manual_gate_ok
        or assertions.get("dependency_claimed") is not True
        or assertions.get("code_reuse_claimed") is not False
        or not no_transfer
    ):
        issues.append(issue("formal_dependency_proof_mismatch", "FORMAL_DEPENDENCY requires exact dependency and removal-break evidence plus an explicit manual gate."))
    if relation == "FORMAL_DEPENDENCY" and assertions.get("dependency_claimed") is not True:
        issues.append(issue("elevated_relation_assertions_mismatch", "A formal dependency relation must explicitly assert its bounded dependency claim."))
    provenance_artifacts = resolved_artifacts(proof.get("provenance_evidence_refs"), "PROVENANCE")
    declared_source_identities = set(proof.get("source_code_identities", []))
    declared_code_boundaries = set(proof.get("reused_code_boundaries", []))
    provenance_identity_set = {artifact.get("source_code_identity") for artifact in provenance_artifacts}
    provenance_boundary_set = {artifact.get("local_boundary") for artifact in provenance_artifacts}
    transformation_identity_set = {artifact.get("source_code_identity") for artifact in transformation_artifacts}
    transformation_boundary_set = {artifact.get("local_boundary") for artifact in transformation_artifacts}
    code_evidence_exact = (
        bool(provenance_artifacts)
        and bool(transformation_artifacts)
        and provenance_identity_set == declared_source_identities
        and provenance_boundary_set == declared_code_boundaries
        and transformation_identity_set == declared_source_identities
        and transformation_boundary_set == declared_code_boundaries
        and declared_code_boundaries == local_targets
    )
    if relation == "CODE_REUSE" and (
        data.get("claim_ceiling_state") != "CODE_REUSE_PROOF_BOUND"
        or proof.get("implementation_origin") != "REUSED_CODE"
        or not declared_source_identities
        or not declared_code_boundaries
        or not code_evidence_exact
        or license_status != "LICENSE_CLEARED_FOR_ADAPTATION"
        or not license_ok
        or not manual_gate_ok
        or assertions.get("dependency_claimed") is not True
        or assertions.get("code_reuse_claimed") is not True
        or not no_transfer
        or data.get("removal_breaks_evidence_ref") is not None
    ):
        issues.append(issue("code_reuse_record_requires_manual_review", "CODE_REUSE requires exact source identity, compatible license, code boundaries, provenance evidence, and a satisfied manual gate."))

    if relation in {"INTERFACE_ADAPTATION", "FORMAL_DEPENDENCY", "CODE_REUSE"} and source_artifact_id is not None:
        all_refs = [
            *data.get("license_evidence_refs", []),
            *data.get("dependency_evidence_refs", []),
            *proof.get("transformation_evidence_refs", []),
            *proof.get("provenance_evidence_refs", []),
        ]
        evidence = [resolve_artifact_ref(ref) for ref in all_refs]
        if (
            any(item is None or item.get("source_artifact_id") != source_artifact_id for item in evidence)
            or isinstance(manual_gate, dict) and manual_gate.get("source_artifact_id") != source_artifact_id
            or isinstance(removal, dict) and removal.get("source_artifact_id") != source_artifact_id
        ):
            issues.append(issue("dependency_evidence_unresolved", "Relation evidence must resolve by exact ID/version/JCS hash and bind the frozen source artifact."))
        if any(item and item.get("evidence_scope") == "SYNTHETIC_NEGATIVE_FIXTURE_ONLY" for item in evidence + [manual_gate, removal]):
            issues.append(issue("negative_fixture_evidence_cannot_elevate_relation", "Synthetic negative-fixture evidence cannot establish a proof-bearing relation."))
    unresolved_targets = []
    for target in data.get("local_target", []):
        if not local_path_with_fragment_resolves(target):
            unresolved_targets.append(str(target))
    if unresolved_targets:
        issues.append(issue("external_local_target_unresolved", "Local target paths do not resolve inside the repository: " + ", ".join(unresolved_targets)))
    return issues


def semantic_boundary_probe(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    window = data.get("window") or {}
    issues.extend(temporal_window_issues(window.get("start"), window.get("end"), data.get("created_at"), "window"))
    query_count = int(data.get("query_count", 0))
    if (
        int(data.get("distinct_agents", 0)) > query_count
        or int(data.get("distinct_providers", 0)) > query_count
    ):
        issues.append(issue("probe_counts_inconsistent", "distinct_agents and distinct_providers cannot exceed query_count when queries are present."))

    flags = set(data.get("risk_flags", []))
    signals = data.get("signals") or {}
    aggregation = data.get("aggregation_keys") or {}
    if signals.get("memory_assisted") and not aggregation.get("shared_memory_lineage_refs"):
        issues.append(issue("memory_assisted_probe_requires_lineage_key", "Memory-assisted probing requires at least one shared-memory-lineage aggregation key."))
    if aggregation.get("protected_policy_surface_ref") != data.get("protected_surface_ref"):
        issues.append(issue(
            "probe_aggregation_surface_mismatch",
            "The aggregation key must bind the same protected policy surface as the probe record.",
        ))
    if (
        int(data.get("distinct_agents", 0)) > 1 and not signals.get("cross_agent_aggregation")
        or int(data.get("distinct_providers", 0)) > 1 and not signals.get("provider_rotation")
        or signals.get("cross_agent_aggregation") and int(data.get("distinct_agents", 0)) <= 1
        or signals.get("provider_rotation") and int(data.get("distinct_providers", 0)) <= 1
    ):
        issues.append(issue(
            "probe_count_signal_mismatch",
            "Multi-agent/provider counts and their aggregation/rotation signals must agree in both directions.",
        ))
    required_flags = {
        "refusal_differencing": "THRESHOLD_RECONSTRUCTION",
        "timing_signal_used": "TIMING_SIDE_CHANNEL",
        "memory_assisted": "MEMORY_ASSISTED_EXTRACTION",
        "cross_agent_aggregation": "CROSS_AGENT_AGGREGATION",
        "provider_rotation": "PROVIDER_ROTATION_BYPASS",
    }
    missing_flags = sorted(flag for signal, flag in required_flags.items() if signals.get(signal) and flag not in flags)
    if missing_flags:
        issues.append(issue("probe_signal_flag_mismatch", "Declared attack signals require corresponding risk flags: " + ", ".join(missing_flags)))
    budget_state = (data.get("budget") or {}).get("evaluation_state")
    exceeded = budget_state == "EXCEEDED"
    if exceeded and "BUDGET_EXCEEDED" not in flags:
        issues.append(issue("budget_exceeded_flag_missing", "Budget overrun must be explicitly recorded."))
    high_risk = budget_state == "UNKNOWN" or bool(flags & {
        "THRESHOLD_RECONSTRUCTION",
        "POLICY_FINGERPRINTING",
        "TIMING_SIDE_CHANNEL",
        "CROSS_AGENT_AGGREGATION",
        "PROVIDER_ROTATION_BYPASS",
        "MEMORY_ASSISTED_EXTRACTION",
        "BUDGET_EXCEEDED",
    }) or any(signals.values())
    if (exceeded or high_risk) and data.get("decision") == "ALLOW":
        issues.append(issue("high_risk_probe_cannot_be_allowed", "A budget-exceeded or high-risk adaptive probe cannot receive ALLOW."))
    return issues


def resolve_evidence_ref(ref: str) -> bool:
    if ref.startswith("case:"):
        case_id = ref.split(":", 1)[1]
        suite = load_json(FIXTURE_DIR / "positive" / "continuity_history_cases.json")
        return any(case.get("case_id") == case_id for case in suite.get("cases", []))
    path = contained_path(ROOT, ref)
    return bool(path and path.is_file())


def semantic_judge(
    data: dict[str, Any],
    review_context: dict[str, Any] | None = None,
    expected_context_sha256: str | None = None,
    expected_bindings: dict[str, str] | None = None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    expected_bindings = expected_bindings or {}
    if review_context is None or not expected_context_sha256 or not expected_bindings:
        issues.append(issue(
            "judge_review_context_missing",
            "Judge validation requires a caller-supplied review context, its expected JCS SHA-256, and external expected bindings.",
        ))
    else:
        context_ref = data.get("review_context_ref") or {}
        actual_context_hash = jcs_sha256(review_context)
        if (
            actual_context_hash != expected_context_sha256
            or context_ref.get("artifact_id") != review_context.get("artifact_id")
            or context_ref.get("version") != review_context.get("version")
            or context_ref.get("hash") != actual_context_hash
        ):
            issues.append(issue("judge_review_context_hash_mismatch", "The Judge record does not bind the caller-trusted review-context bytes."))
        binding_fields = (
            "repository", "base_sha", "reviewed_parent_sha", "candidate_scope", "trust_root_class",
        )
        if any(review_context.get(field) != expected_bindings.get(field) for field in binding_fields):
            issues.append(issue("judge_review_context_state_mismatch", "Review context repository, base, reviewed parent, candidate scope, or trust-root class differs from caller-supplied expectations."))
        start = parse_timestamp((review_context.get("review_window") or {}).get("start"))
        end = parse_timestamp((review_context.get("review_window") or {}).get("end"))
        created = parse_timestamp(data.get("created_at"))
        if start is None or end is None or created is None or not start <= created <= end:
            issues.append(issue("judge_review_context_window_mismatch", "Judge created_at must fall inside the caller-trusted review window."))
        if data.get("identity_attestations_are_symbolic") is not True or review_context.get("identity_attestations_are_symbolic") is not True:
            issues.append(issue("judge_identity_attestation_scope_mismatch", "Fixture identity attestations must remain explicitly symbolic."))
    reviewers = data.get("reviewers", [])
    families = [str(item.get("model_family", "")).strip().casefold() for item in reviewers]
    roles = {item.get("role") for item in reviewers}
    if any(not family for family in families) or len(set(families)) < 2:
        issues.append(issue("judge_requires_model_family_diversity", "Judge deliberation requires at least two normalized, nonblank model families."))
    if "ANCHOR" not in roles or "CHALLENGER" not in roles:
        issues.append(issue("judge_requires_anchor_and_challenger", "Judge deliberation requires at least ANCHOR and CHALLENGER roles."))
    if any(not item.get("isolated") for item in reviewers):
        issues.append(issue("judge_reviewer_isolation_broken", "All first-pass reviewers must remain isolated from one another."))
    if data.get("majority_vote_used"):
        issues.append(issue("judge_majority_vote_forbidden", "Majority voting is not a valid evidence synthesis rule in this profile."))
    for field in ("reviewer_id", "model_instance_id", "report_hash"):
        duplicates = duplicate_values(item.get(field) for item in reviewers)
        if duplicates:
            issues.append(issue("judge_reviewer_independence_spoofed", f"Reviewer {field} values must be unique: {sorted(duplicates)!r}"))
    anchor_instances = {item.get("model_instance_id") for item in reviewers if item.get("role") == "ANCHOR"}
    challenger_instances = {item.get("model_instance_id") for item in reviewers if item.get("role") == "CHALLENGER"}
    if anchor_instances & challenger_instances:
        issues.append(issue("judge_anchor_challenger_instance_collision", "ANCHOR and CHALLENGER must be distinct model instances."))

    divergence_refs = [
        ref
        for divergence in data.get("unresolved_divergence", [])
        if isinstance(divergence, dict)
        for ref in divergence.get("evidence_refs", [])
    ]
    unresolved_refs = sorted({
        ref
        for ref in [
            *(ref for reviewer in reviewers for ref in reviewer.get("evidence_refs", [])),
            *divergence_refs,
        ]
        if not resolve_evidence_ref(ref)
    })
    if unresolved_refs:
        issues.append(issue("judge_evidence_ref_unresolved", "Unresolved reviewer evidence references: " + ", ".join(unresolved_refs)))
    passport_path = data.get("corpus_passport_path")
    if passport_path:
        path = contained_path(ROOT, passport_path)
        if not path or not path.is_file():
            issues.append(issue("judge_corpus_passport_unresolved", f"Corpus passport path does not exist: {passport_path}"))
        else:
            passport = load_json(path)
            ref = data.get("corpus_passport_ref") or {}
            if (
                ref.get("artifact_id") != passport.get("artifact_id")
                or ref.get("version") != passport.get("version")
                or ref.get("hash") != jcs_sha256(passport)
            ):
                issues.append(issue("judge_corpus_passport_hash_mismatch", "corpus_passport_ref does not bind the exact declared passport file."))
            attested = {
                (
                    item.get("reviewer_id"),
                    item.get("model_family"),
                    item.get("provider_id"),
                    item.get("model_instance_id"),
                )
                for item in passport.get("reviewer_identities", [])
            }
            claimed = {
                (
                    item.get("reviewer_id"),
                    item.get("model_family"),
                    item.get("provider_id"),
                    item.get("model_instance_id"),
                )
                for item in reviewers
            }
            if claimed - attested:
                issues.append(issue(
                    "judge_identity_attestation_mismatch",
                    "One or more reviewer family/provider/instance tuples are not attested by the exact corpus passport.",
                ))
            if review_context is None or (
                passport.get("repository") != review_context.get("repository")
                or passport.get("base_sha") != review_context.get("base_sha")
                or passport.get("reviewed_parent_sha") != review_context.get("reviewed_parent_sha")
                or passport.get("passport_scope") != review_context.get("candidate_scope")
                or review_context.get("expected_corpus_passport_ref") != data.get("corpus_passport_ref")
            ):
                issues.append(issue("judge_corpus_passport_state_mismatch", "Corpus passport does not match the independently supplied trusted review context."))
            source_artifacts = passport.get("source_artifacts", [])
            declared_paths: set[str] = set()
            source_errors: list[str] = []
            for source in source_artifacts:
                relative = source.get("path") if isinstance(source, dict) else None
                domain = source.get("hash_domain") if isinstance(source, dict) else None
                source_path = contained_path(ROOT, relative)
                if not source_path or not source_path.is_file():
                    source_errors.append(str(relative))
                    continue
                declared_paths.add(relative)
                try:
                    if domain == "RFC8785_JCS_SHA256_V1":
                        actual_hash = jcs_file_sha256(source_path)
                    elif domain == "UNIFORM_UTF8_TEXT_TO_LF_SHA256_V1":
                        actual_hash = uniform_text_to_lf_sha256(source_path)
                    else:
                        source_errors.append(str(relative))
                        continue
                except (JSONDomainError, UnicodeError, OSError, SystemExit):
                    source_errors.append(str(relative))
                    continue
                if source.get("sha256") != actual_hash:
                    source_errors.append(str(relative))
            all_evidence_refs = [
                *(ref for reviewer in reviewers for ref in reviewer.get("evidence_refs", [])),
                *divergence_refs,
            ]
            direct_evidence = {
                ref
                for ref in all_evidence_refs
                if isinstance(ref, str) and not ref.startswith("case:")
            }
            case_evidence_present = any(
                isinstance(ref, str) and ref.startswith("case:")
                for ref in all_evidence_refs
            )
            continuity_path = "fixtures/runtime-integrity/positive/continuity_history_cases.json"
            if direct_evidence - declared_paths or (case_evidence_present and continuity_path not in declared_paths):
                source_errors.extend(sorted(direct_evidence - declared_paths))
                if case_evidence_present and continuity_path not in declared_paths:
                    source_errors.append(continuity_path)
            if source_errors or not source_artifacts:
                issues.append(issue(
                    "judge_corpus_source_hash_mismatch",
                    "Corpus passport sources are unresolved, unbound, or incomplete: " + ", ".join(sorted(set(source_errors))),
                ))
    if families:
        concentration = max(Counter(families).values()) * 2 > len(families)
        if concentration and (
            data.get("family_concentration") != "CONCENTRATED"
            or data.get("confidence_state") != "DEGRADED_FOR_CONCENTRATION"
        ):
            issues.append(issue("judge_family_concentration_unacknowledged", "A majority-family concentration must be explicit and degrade confidence without selecting truth by vote."))
    return issues


REQUIRED_CONTINUITY_CASES = {
    "continuous-migration-vs-archive-restore",
    "fork-after-common-history",
    "clone-vs-continuation",
    "replay-vs-resume",
    "resource-recovery-does-not-restore-identity",
    "identity-preserved-under-l4-degradation",
    "sealed-intermediary-witness-gap",
    "provider-replacement",
    "storage-replacement",
    "model-replacement",
    "temporary-witness-loss",
    "restored-endpoint-missing-transition-evidence",
}

CONTINUITY_HISTORY_CLASSES = {
    "WITNESSED_CONTINUOUS_MIGRATION", "ARCHIVE_RECONSTRUCTION", "FORK_BRANCH",
    "WITNESSED_CONTINUATION", "CLONE_FROM_SNAPSHOT", "ARCHIVE_REPLAY",
    "WITNESSED_RESUME", "ORIGINAL_LINE_WITH_RESOURCE_RECOVERY",
    "NEW_LINE_WITH_RESTORED_RESOURCES", "SAME_LINE_HEALTHY_RESOURCES",
    "SAME_LINE_DEGRADED_RESOURCES", "VISIBLE_CONTINUOUS_LINE", "OPAQUE_INTERMEDIARY",
    "ORIGINAL_PROVIDER", "WITNESSED_PROVIDER_REPLACEMENT", "ORIGINAL_STORAGE",
    "WITNESSED_STORAGE_REPLACEMENT", "ORIGINAL_MODEL", "WITNESSED_MODEL_REPLACEMENT",
    "TEMPORARY_WITNESS_LOSS", "WITNESSED_ORIGINAL_LINE",
    "RESTORED_ENDPOINT_WITH_EVIDENCE_GAP",
}

CONTINUITY_CLASSIFICATIONS = {
    "RESUME_CONFIRMED", "REPLAY_ONLY", "FORK_DECLARED", "CLONE_NOT_CONTINUATION",
    "REJECTED", "RESUME_CONFIRMED_WITH_L4_HOLD", "UNRESOLVED",
}

EXPECTED_CONTINUITY_CASE_SIDES = {
    "continuous-migration-vs-archive-restore": {
        "left": ("WITNESSED_CONTINUOUS_MIGRATION", "RESUME_CONFIRMED"),
        "right": ("ARCHIVE_RECONSTRUCTION", "REPLAY_ONLY"),
    },
    "fork-after-common-history": {
        "left": ("FORK_BRANCH", "FORK_DECLARED"),
        "right": ("FORK_BRANCH", "FORK_DECLARED"),
    },
    "clone-vs-continuation": {
        "left": ("WITNESSED_CONTINUATION", "RESUME_CONFIRMED"),
        "right": ("CLONE_FROM_SNAPSHOT", "CLONE_NOT_CONTINUATION"),
    },
    "replay-vs-resume": {
        "left": ("ARCHIVE_REPLAY", "REPLAY_ONLY"),
        "right": ("WITNESSED_RESUME", "RESUME_CONFIRMED"),
    },
    "resource-recovery-does-not-restore-identity": {
        "left": ("ORIGINAL_LINE_WITH_RESOURCE_RECOVERY", "RESUME_CONFIRMED"),
        "right": ("NEW_LINE_WITH_RESTORED_RESOURCES", "REJECTED"),
    },
    "identity-preserved-under-l4-degradation": {
        "left": ("SAME_LINE_HEALTHY_RESOURCES", "RESUME_CONFIRMED"),
        "right": ("SAME_LINE_DEGRADED_RESOURCES", "RESUME_CONFIRMED_WITH_L4_HOLD"),
    },
    "sealed-intermediary-witness-gap": {
        "left": ("VISIBLE_CONTINUOUS_LINE", "RESUME_CONFIRMED"),
        "right": ("OPAQUE_INTERMEDIARY", "UNRESOLVED"),
    },
    "provider-replacement": {
        "left": ("ORIGINAL_PROVIDER", "RESUME_CONFIRMED"),
        "right": ("WITNESSED_PROVIDER_REPLACEMENT", "RESUME_CONFIRMED"),
    },
    "storage-replacement": {
        "left": ("ORIGINAL_STORAGE", "RESUME_CONFIRMED"),
        "right": ("WITNESSED_STORAGE_REPLACEMENT", "RESUME_CONFIRMED"),
    },
    "model-replacement": {
        "left": ("ORIGINAL_MODEL", "RESUME_CONFIRMED"),
        "right": ("WITNESSED_MODEL_REPLACEMENT", "RESUME_CONFIRMED"),
    },
    "temporary-witness-loss": {
        "left": ("VISIBLE_CONTINUOUS_LINE", "RESUME_CONFIRMED"),
        "right": ("TEMPORARY_WITNESS_LOSS", "UNRESOLVED"),
    },
    "restored-endpoint-missing-transition-evidence": {
        "left": ("WITNESSED_ORIGINAL_LINE", "RESUME_CONFIRMED"),
        "right": ("RESTORED_ENDPOINT_WITH_EVIDENCE_GAP", "UNRESOLVED"),
    },
}

EXPECTED_CONTINUITY_PAIR_RELATIONS = {
    "continuous-migration-vs-archive-restore": (True, "DIFFERENT"),
    "fork-after-common-history": (False, "DIFFERENT"),
    "clone-vs-continuation": (True, "DIFFERENT"),
    "replay-vs-resume": (True, "DIFFERENT"),
    "resource-recovery-does-not-restore-identity": (True, "DIFFERENT"),
    "identity-preserved-under-l4-degradation": (False, "SAME"),
    "sealed-intermediary-witness-gap": (True, "DIFFERENT"),
    "provider-replacement": (True, "SAME"),
    "storage-replacement": (True, "SAME"),
    "model-replacement": (True, "SAME"),
    "temporary-witness-loss": (True, "DIFFERENT"),
    "restored-endpoint-missing-transition-evidence": (True, "DIFFERENT"),
}

NON_RESUMABLE_HISTORY_CLASSES = {
    "ARCHIVE_RECONSTRUCTION", "CLONE_FROM_SNAPSHOT", "ARCHIVE_REPLAY",
    "NEW_LINE_WITH_RESTORED_RESOURCES", "OPAQUE_INTERMEDIARY",
    "TEMPORARY_WITNESS_LOSS", "RESTORED_ENDPOINT_WITH_EVIDENCE_GAP",
}


def semantic_continuity_history(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not isinstance(data, dict):
        return [issue("continuity_structure_invalid", "Continuity suite must be an object.")]
    allowed_top = {"schema_version", "suite_id", "vocabulary_scope", "transition_evidence_registry_ref", "cases", "non_entailment_rules"}
    if set(data) - allowed_top:
        issues.append(issue("continuity_structure_invalid", "Continuity suite contains unexpected top-level fields."))
    if (
        data.get("schema_version") != "c-continuity-history-cases-0.1.1"
        or not data.get("suite_id")
        or data.get("vocabulary_scope") != "FIXTURE_ONLY_NATIVE_CONTINUITY_MAPPING_NOT_NEW_ONTOLOGY"
    ):
        issues.append(issue("continuity_structure_invalid", "Continuity suite requires its schema_version and suite_id."))
    registry_result = resolve_local_artifact_ref(data.get("transition_evidence_registry_ref"))
    evidence_by_ref: dict[str, dict[str, Any]] = {}
    if registry_result is None:
        issues.append(issue("continuity_transition_registry_unresolved", "Continuity transition evidence registry is unresolved or hash-mismatched."))
    else:
        registry_data = registry_result[0]
        entries = registry_data.get("entries", [])
        if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
            issues.append(issue("continuity_transition_registry_unresolved", "Continuity transition evidence entries must be an array of objects."))
            entries = []
        evidence_refs = [entry.get("evidence_ref") for entry in entries if isinstance(entry.get("evidence_ref"), str)]
        if len(evidence_refs) != len(entries):
            issues.append(issue("continuity_transition_registry_unresolved", "Every transition registry entry requires a string evidence_ref."))
        if duplicate_values(evidence_refs):
            issues.append(issue("continuity_transition_registry_unresolved", "Continuity transition evidence registry contains duplicate evidence references."))
        evidence_by_ref = {entry.get("evidence_ref"): entry for entry in entries if isinstance(entry.get("evidence_ref"), str)}
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        return issues + [issue("continuity_structure_invalid", "Continuity suite requires a non-empty cases array.")]
    case_ids = [case.get("case_id") for case in cases if isinstance(case, dict) and isinstance(case.get("case_id"), str)]
    if len(case_ids) != len(cases):
        issues.append(issue("continuity_structure_invalid", "Every continuity case must be an object with a string case_id."))
    missing_cases = REQUIRED_CONTINUITY_CASES - set(case_ids)
    duplicates = duplicate_values(case_ids)
    if missing_cases or duplicates:
        issues.append(issue(
            "continuity_required_cases_missing_or_duplicate",
            f"Continuity case set is incomplete or duplicated; missing={sorted(missing_cases)!r}, duplicates={sorted(duplicates)!r}.",
        ))
    raw_rules = data.get("non_entailment_rules", [])
    if not isinstance(raw_rules, list) or any(not isinstance(rule, str) for rule in raw_rules):
        issues.append(issue("continuity_structure_invalid", "Continuity non-entailment rules must be an array of strings."))
        raw_rules = []
    rules = set(raw_rules)
    required_rules = {
        "endpoint_equivalence_does_not_entail_identity_continuity",
        "resource_recovery_does_not_entail_identity_recovery",
        "identity_continuity_does_not_entail_l4_viability",
        "archive_presence_does_not_entail_resume",
    }
    missing_rules = required_rules - rules
    if missing_rules:
        issues.append(issue("continuity_non_entailment_rules_missing", "Missing non-entailment rules: " + ", ".join(sorted(missing_rules))))
    endpoint_equal_distinguished = False
    for case in cases:
        required_case_keys = {"case_id", "endpoint_state_hash_equal", "left", "right", "snapshot_only_expected"}
        if not isinstance(case, dict) or set(case) != required_case_keys:
            issues.append(issue("continuity_structure_invalid", "Each continuity case requires case_id, endpoint equality, left, right, and snapshot-only result."))
            continue
        if not isinstance(case.get("endpoint_state_hash_equal"), bool):
            issues.append(issue("continuity_structure_invalid", f"{case.get('case_id')}: endpoint_state_hash_equal must be boolean."))
        if case.get("snapshot_only_expected") != "UNRESOLVED":
            issues.append(issue("snapshot_only_must_remain_unresolved", f"{case.get('case_id')}: snapshot-only classification must be UNRESOLVED."))
        left = case.get("left", {})
        right = case.get("right", {})
        for side_name, side in (("left", left), ("right", right)):
            required_side = {"history_class", "lineage_id", "transition_evidence_complete", "transition_evidence_ref", "endpoint_state_hash", "expected_classification"}
            if not isinstance(side, dict) or set(side) != required_side:
                issues.append(issue("continuity_structure_invalid", f"{case.get('case_id')}.{side_name} lacks required history fields."))
                continue
            if side.get("history_class") not in CONTINUITY_HISTORY_CLASSES or side.get("expected_classification") not in CONTINUITY_CLASSIFICATIONS:
                issues.append(issue("continuity_structure_invalid", f"{case.get('case_id')}.{side_name} uses an undeclared history class or classification."))
            expected_pair = EXPECTED_CONTINUITY_CASE_SIDES.get(str(case.get("case_id")), {}).get(side_name)
            observed_pair = (side.get("history_class"), side.get("expected_classification"))
            if expected_pair is not None and observed_pair != expected_pair:
                issues.append(issue(
                    "continuity_case_classification_mismatch",
                    f"{case.get('case_id')}.{side_name} must preserve the paired history/classification invariant {expected_pair!r}.",
                ))
            if (
                not isinstance(side.get("lineage_id"), str)
                or not side.get("lineage_id", "").strip()
                or not isinstance(side.get("transition_evidence_complete"), bool)
                or not isinstance(side.get("endpoint_state_hash"), str)
                or len(side.get("endpoint_state_hash", "")) != 64
                or any(ch not in "0123456789abcdef" for ch in side.get("endpoint_state_hash", ""))
            ):
                issues.append(issue("continuity_structure_invalid", f"{case.get('case_id')}.{side_name} has malformed lineage, evidence-completeness, or endpoint-hash data."))
            expected_ref = f"continuity-evidence:{case.get('case_id')}:{side_name}"
            evidence = evidence_by_ref.get(expected_ref)
            if (
                side.get("transition_evidence_ref") != expected_ref
                or not isinstance(evidence, dict)
                or evidence.get("case_id") != case.get("case_id")
                or evidence.get("side") != side_name
                or evidence.get("lineage_id") != side.get("lineage_id")
                or evidence.get("history_class") != side.get("history_class")
                or not isinstance(evidence.get("transition_evidence_complete"), bool)
                or evidence.get("transition_evidence_complete") is not side.get("transition_evidence_complete")
            ):
                issues.append(issue("continuity_transition_evidence_mismatch", f"{case.get('case_id')}.{side_name} is not bound to its declared transition evidence."))
            if not side.get("transition_evidence_complete") and str(side.get("expected_classification", "")).startswith("RESUME_CONFIRMED"):
                issues.append(issue("resume_requires_transition_evidence", f"{case.get('case_id')}.{side_name}: RESUME_CONFIRMED requires complete transition evidence."))
            if side.get("history_class") in NON_RESUMABLE_HISTORY_CLASSES and str(side.get("expected_classification", "")).startswith("RESUME_CONFIRMED"):
                issues.append(issue("resume_history_class_incompatible", f"{case.get('case_id')}.{side_name}: this history class cannot assert RESUME_CONFIRMED."))
        declared_equal = case.get("endpoint_state_hash_equal")
        observed_equal = left.get("endpoint_state_hash") == right.get("endpoint_state_hash")
        if declared_equal is not observed_equal:
            issues.append(issue(
                "endpoint_hash_equality_mismatch",
                f"{case.get('case_id')}: endpoint_state_hash_equal contradicts the two endpoint hashes.",
            ))
        expected_relation = EXPECTED_CONTINUITY_PAIR_RELATIONS.get(str(case.get("case_id")))
        observed_lineage_relation = "SAME" if left.get("lineage_id") == right.get("lineage_id") else "DIFFERENT"
        if expected_relation and (declared_equal, observed_lineage_relation) != expected_relation:
            issues.append(issue(
                "continuity_pair_relation_mismatch",
                f"{case.get('case_id')}: endpoint equality and lineage relation must remain {expected_relation!r}.",
            ))
        if case.get("endpoint_state_hash_equal") and left.get("expected_classification") != right.get("expected_classification"):
            endpoint_equal_distinguished = True
    if not endpoint_equal_distinguished:
        issues.append(issue("endpoint_equal_history_counterexample_missing", "At least one endpoint-equal case must retain different history-sensitive classifications."))
    return issues


def semantic_carry_cost(data: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not isinstance(data, dict):
        return [issue("carry_cost_structure_invalid", "Carry-cost profile must be an object.")]
    allowed_top = {"schema_version", "profile_id", "dimensions", "rules"}
    extras = set(data) - allowed_top
    if extras:
        issues.append(issue("carry_cost_structure_invalid", f"Unexpected carry-cost fields: {sorted(extras)!r}"))
    if data.get("schema_version") != "c-continuity-carry-cost-profile-0.1.1" or not data.get("profile_id"):
        issues.append(issue("carry_cost_structure_invalid", "Carry-cost profile requires schema_version and profile_id."))
    dimensions = data.get("dimensions", [])
    if not isinstance(dimensions, list) or not dimensions:
        return issues + [issue("carry_cost_dimensions_missing", "At least one carry-cost dimension is required.")]
    if (
        not isinstance(data.get("rules"), list)
        or not data.get("rules")
        or any(not isinstance(rule, str) or not rule.strip() for rule in data.get("rules", []))
    ):
        issues.append(issue("carry_cost_structure_invalid", "Carry-cost profile requires at least one explicit rule."))
    names = [item.get("dimension") for item in dimensions if isinstance(item, dict) and isinstance(item.get("dimension"), str)]
    duplicates = duplicate_values(names)
    if duplicates:
        issues.append(issue("carry_cost_duplicate_dimension", f"Duplicate carry-cost dimensions: {sorted(duplicates)!r}"))
    for item in dimensions:
        if not isinstance(item, dict):
            issues.append(issue("carry_cost_structure_invalid", "Each carry-cost dimension must be an object."))
            continue
        extra_dimension = set(item) - {"dimension", "unit", "identity_bearing"}
        if extra_dimension:
            issues.append(issue("carry_cost_structure_invalid", f"Unexpected dimension fields: {sorted(extra_dimension)!r}"))
        if (
            set(item) != {"dimension", "unit", "identity_bearing"}
            or not isinstance(item.get("dimension"), str)
            or not item.get("dimension", "").strip()
            or not isinstance(item.get("unit"), str)
            or not item.get("unit", "").strip()
            or not isinstance(item.get("identity_bearing"), bool)
        ):
            issues.append(issue("carry_cost_structure_invalid", "Each carry-cost dimension requires nonblank dimension/unit and identity_bearing fields only."))
    if any(
        not isinstance(item, dict) or item.get("identity_bearing") is not False
        for item in dimensions
    ):
        issues.append(issue("carry_cost_cannot_be_identity_witness", "Continuity carry cost dimensions must not be marked identity-bearing."))
    for required in {"human_anchor_attention", "witness_chain_maintenance", "recovery_reserve"}:
        if required not in set(names):
            issues.append(issue("carry_cost_required_dimension_missing", f"Required dimension missing: {required}"))
    return issues


def semantic_earth_bundle(
    data: dict[str, Any],
    schemas: dict[str, dict[str, Any]],
    schema_registry: Registry,
    record_registry: dict[str, str],
    evidence_registry: dict[str, dict[str, str]],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not isinstance(data, dict):
        return [issue("earth_structure_invalid", "Earth bundle must be an object.")]
    required_top = {"schema_version", "scenario_id", "timeline", "records", "later_retry_policy", "claim_boundary"}
    if set(data) != required_top:
        issues.append(issue("earth_structure_invalid", f"Earth bundle requires exactly these top-level fields: {sorted(required_top)!r}."))
    if (
        data.get("schema_version") != "c-runtime-integrity-earth-test-0.1.1"
        or data.get("scenario_id") != "earth-10-00-10-02-10-03"
        or data.get("claim_boundary") != (
            "This symbolic fixture proves the declared repository-level 10:00/10:02/10:03 combination and linked evidence rules only; "
            "it does not execute CGAM, TAP-SEC, a deployment, or an external API call."
        )
    ):
        issues.append(issue("earth_structure_invalid", "Earth bundle schema, scenario identity, and bounded claim must be explicit."))
    records = data.get("records") if isinstance(data.get("records"), dict) else {}
    required_records = {
        "decision_basis", "memory_reliance", "consequence_commit", "non_effect_witness",
        "later_retry_decision_basis", "later_retry_consequence_commit",
    }
    if set(records) != required_records:
        issues.append(issue("earth_structure_invalid", "Earth records must name the denied attempt graph and the instantiated endpoint-B retry records."))
    loaded: dict[str, dict[str, Any]] = {}
    for name in sorted(required_records):
        rel = records.get(name)
        path = contained_path(FIXTURE_DIR, rel)
        if not rel or not path or not path.is_file():
            issues.append(issue("earth_record_unresolved", f"Earth bundle record path is unresolved: {name}={rel!r}"))
        else:
            loaded[name] = load_json(path)
    if len(loaded) != len(required_records):
        return issues
    decision = loaded["decision_basis"]
    memory = loaded["memory_reliance"]
    commit = loaded["consequence_commit"]
    witness = loaded["non_effect_witness"]
    retry_decision = loaded["later_retry_decision_basis"]
    retry_commit = loaded["later_retry_consequence_commit"]
    nested_specs = {
        "decision_basis": ("urn:ivan-kotov:c-runtime-integrity:decision-basis-record:0.1.1", semantic_decision_basis),
        "memory_reliance": ("urn:ivan-kotov:c-runtime-integrity:memory-reliance-record:0.1.1", semantic_memory_reliance),
        "consequence_commit": ("urn:ivan-kotov:c-runtime-integrity:consequence-commit-record:0.1.1", semantic_commit),
        "non_effect_witness": ("urn:ivan-kotov:c-runtime-integrity:non-effect-witness-record:0.1.1", semantic_non_effect),
        "later_retry_decision_basis": ("urn:ivan-kotov:c-runtime-integrity:decision-basis-record:0.1.1", semantic_decision_basis),
        "later_retry_consequence_commit": ("urn:ivan-kotov:c-runtime-integrity:consequence-commit-record:0.1.1", semantic_commit),
    }
    for name, record in loaded.items():
        schema_id, semantic = nested_specs[name]
        nested_issues = validate_schema(record, schema_id, schemas, schema_registry)
        nested_issues.extend(nonblank_string_issues(record))
        if not any(item.code == "schema" for item in nested_issues):
            nested_issues.extend(semantic(record))
            nested_issues.extend(validate_registered_links(
                record, record_registry, schemas, schema_registry, evidence_registry,
            ))
            nested_issues.extend(validate_registered_evidence(record, evidence_registry))
        if nested_issues:
            issues.append(issue("earth_nested_record_invalid", f"Earth {name} record is not independently valid: " + ", ".join(sorted({item.code for item in nested_issues}))))
        expected_rel = record_registry.get(str(record.get("record_id")))
        if expected_rel != records.get(name):
            issues.append(issue("earth_record_registry_mismatch", f"Earth {name} is not the manifest registry target for its record_id."))
    decision_ref = commit.get("decision_basis_ref") or {}
    if (
        decision_ref.get("artifact_id") != decision.get("record_id")
        or decision_ref.get("version") != record_version(decision)
        or decision_ref.get("hash") != jcs_sha256(decision)
    ):
        issues.append(issue("graph_decision_basis_link_invalid", "Consequence commit does not resolve and hash-bind the decision-basis record."))
    memory_refs = commit.get("memory_reliance_refs", [])
    expected_memory_ref = (memory.get("record_id"), record_version(memory), jcs_sha256(memory))
    commit_memory_refs = {(ref.get("artifact_id"), ref.get("version"), ref.get("hash")) for ref in memory_refs}
    basis_memory_refs = {
        (ref.get("artifact_id"), ref.get("version"), ref.get("hash"))
        for ref in (decision.get("basis") or {}).get("memory_reliance_refs", [])
    }
    if commit_memory_refs != {expected_memory_ref} or basis_memory_refs != commit_memory_refs:
        issues.append(issue("graph_memory_link_invalid", "Consequence commit does not resolve and hash-bind the memory-reliance record."))
    if (
        memory.get("current_authority_ref") != (decision.get("basis") or {}).get("permission_grant_ref")
        or memory.get("current_authority_ref") != commit.get("permission_grant_ref")
        or memory.get("current_task_ref") != commit.get("task_contract_ref")
    ):
        issues.append(issue("earth_authority_task_graph_mismatch", "Earth memory, decision basis, and commit must share the exact hash-bound grant and task context."))
    witness_ref = commit.get("non_effect_witness_ref") or {}
    if (
        witness_ref.get("artifact_id") != witness.get("record_id")
        or witness_ref.get("version") != record_version(witness)
        or witness_ref.get("hash") != jcs_sha256(witness)
        or witness.get("gate_record_ref") != commit.get("record_id")
    ):
        issues.append(issue("graph_witness_link_invalid", "Commit and non-effect witness IDs are not reciprocal and resolvable."))
    if witness.get("effect_scope_ref") != (commit.get("target_effect") or {}).get("effect_id"):
        issues.append(issue("graph_effect_scope_mismatch", "Non-effect witness scope does not match the commit target effect."))
    timeline = data.get("timeline") if isinstance(data.get("timeline"), dict) else {}
    required_timeline = {
        "planning_valid_at", "conditions_changed_at", "execution_attempt_at",
        "planning_permission_status", "planning_evidence_state", "planning_l4_budget_state",
        "planning_endpoint_ref", "current_endpoint_ref", "permission_revoked",
        "test_evidence_expired", "l4_budget_exceeded", "queued_retry_pending_before_attempt",
    }
    if set(timeline) != required_timeline:
        issues.append(issue("earth_structure_invalid", "Earth timeline must contain exactly the required planning and changed-condition facts."))
    if [timeline.get(key) for key in ("planning_valid_at", "conditions_changed_at", "execution_attempt_at")] != [
        "2026-08-27T10:00:00+02:00", "2026-08-27T10:02:00+02:00", "2026-08-27T10:03:00+02:00"
    ]:
        issues.append(issue("earth_timeline_inexact", "Earth bundle must encode the exact 10:00/10:02/10:03 sequence."))
    if (
        timeline.get("planning_permission_status") != "VALID"
        or timeline.get("planning_evidence_state") != "FRESH"
        or timeline.get("planning_l4_budget_state") != "SUFFICIENT"
        or timeline.get("planning_endpoint_ref") != "endpoint:A"
        or timeline.get("current_endpoint_ref") != "endpoint:B"
        or not all(
            timeline.get(key) is True
            for key in (
                "permission_revoked",
                "test_evidence_expired",
                "l4_budget_exceeded",
                "queued_retry_pending_before_attempt",
            )
        )
    ):
        issues.append(issue(
            "earth_changed_conditions_incomplete",
            "Earth bundle must bind endpoint A-to-B change, revocation, evidence expiry, L4 exhaustion, and the pending retry.",
        ))
    planning_time = parse_timestamp(timeline.get("planning_valid_at"))
    decision_created = parse_timestamp(decision.get("created_at"))
    basis_captured = parse_timestamp((decision.get("basis") or {}).get("captured_at"))
    memory_created = parse_timestamp(memory.get("created_at"))
    if planning_time and any(
        timestamp is None or timestamp > planning_time
        for timestamp in (decision_created, basis_captured, memory_created)
    ):
        issues.append(issue("earth_planning_basis_not_prior", "Decision basis and memory qualification must exist no later than the 10:00 planning state."))
    grant = resolve_artifact_ref_evidence(commit.get("permission_grant_ref"), evidence_registry)
    task = resolve_artifact_ref_evidence(commit.get("task_contract_ref"), evidence_registry)
    conditions = resolve_artifact_ref_evidence(commit.get("current_conditions_ref"), evidence_registry)
    planning_task_state = state_at(task[0], timeline.get("planning_valid_at")) if task else None
    changed_grant_state = state_at(grant[0], timeline.get("conditions_changed_at")) if grant else None
    changed_task_state = state_at(task[0], timeline.get("conditions_changed_at")) if task else None
    if (
        grant is None
        or not grant_is_valid_at(grant[0], timeline.get("planning_valid_at"))
        or task is None
        or planning_task_state is None
        or planning_task_state.get("status") != "CURRENT"
        or planning_task_state.get("endpoint_ref") != timeline.get("planning_endpoint_ref")
        or changed_grant_state is None
        or changed_grant_state.get("status") != "REVOKED"
        or changed_task_state is None
        or changed_task_state.get("status") != "STALE"
        or changed_task_state.get("endpoint_ref") != timeline.get("current_endpoint_ref")
    ):
        issues.append(issue("earth_initial_and_changed_state_unresolved", "Earth 10:00 valid grant/current task and 10:02 revoked/stale endpoint state must resolve from hash-bound histories."))
    planning_conditions = conditions[0].get("planning_state", {}) if conditions else {}
    changed_conditions = conditions[0].get("changed_state", {}) if conditions else {}
    if (
        planning_conditions.get("observed_at") != timeline.get("planning_valid_at")
        or planning_conditions.get("permission_status") != timeline.get("planning_permission_status")
        or planning_conditions.get("endpoint_ref") != timeline.get("planning_endpoint_ref")
        or planning_conditions.get("source_evidence_state") != timeline.get("planning_evidence_state")
        or planning_conditions.get("l4_budget_state") != timeline.get("planning_l4_budget_state")
        or changed_conditions.get("observed_at") != timeline.get("conditions_changed_at")
        or changed_conditions.get("permission_status") != "REVOKED"
        or changed_conditions.get("endpoint_ref") != timeline.get("current_endpoint_ref")
        or changed_conditions.get("source_evidence_state") != "EXPIRED"
        or changed_conditions.get("l4_budget_state") != "EXCEEDED"
        or changed_conditions.get("queued_retry_state") != "PENDING"
    ):
        issues.append(issue("earth_condition_history_mismatch", "Hash-bound planning and changed-condition observations must match every Earth timeline fact."))
    statuses = {item.get("name"): item.get("status") for item in commit.get("precondition_results", [])}
    for name in ("CURRENT_AUTHORITY", "TIME_WINDOW", "L4_BUDGET", "BLOCKING_STATE"):
        if statuses.get(name) != "FAIL":
            issues.append(issue("earth_final_revalidation_incomplete", f"Earth test requires {name}=FAIL at execution."))
    execution_at = timeline.get("execution_attempt_at")
    target_ref = (commit.get("target_effect") or {}).get("target_ref")
    if (
        commit.get("created_at") != execution_at
        or commit.get("permission_checked_at") != execution_at
        or commit.get("task_contract_checked_at") != execution_at
        or commit.get("permission_status") != "REVOKED"
        or commit.get("task_contract_status") != "STALE"
        or commit.get("authorized_target_ref") != timeline.get("planning_endpoint_ref")
        or target_ref != timeline.get("planning_endpoint_ref")
        or commit.get("task_endpoint_ref") != timeline.get("current_endpoint_ref")
        or commit.get("commit_outcome") != "DENY"
        or commit.get("effect_state") != "NOT_BOUND"
    ):
        issues.append(issue("earth_final_revalidation_incomplete", "Earth commit must deny after revoked authority, a stale changed endpoint, and failed current checks."))
    surfaces = witness.get("observation_surfaces", [])
    queue_ok = any(
        surface.get("surface_kind") == "QUEUE"
        and surface.get("queue_state") == "CANCELLED"
        and surface.get("retry_state") == "CANCELLED"
        for surface in surfaces
    )
    if (
        (witness.get("observation_window") or {}).get("start") != execution_at
        or witness.get("effect_target_ref") != target_ref
        or any(surface.get("external_call_count") != 0 or surface.get("before_hash") != surface.get("after_hash") for surface in surfaces)
        or not queue_ok
        or any(route.get("status") not in {"CLOSED", "NOT_REACHABLE"} for route in witness.get("alternate_path_checks", []))
        or witness.get("conclusion") != "NO_EFFECT_OBSERVED_WITHIN_DECLARED_SCOPE"
    ):
        issues.append(issue("earth_non_effect_evidence_incomplete", "Earth witness must prove zero calls, unchanged declared surfaces, cancelled retry, and closed declared routes."))
    later = data.get("later_retry_policy") if isinstance(data.get("later_retry_policy"), dict) else {}
    required_later = {
        "requires_new_decision_basis", "requires_new_consequence_commit", "preserves_old_records",
        "previous_commit_record_ref", "old_decision_basis_hash", "old_consequence_commit_hash",
        "endpoint_ref", "retry_instantiated_at", "new_decision_basis_ref", "new_consequence_commit_ref",
        "new_permission_grant_ref", "new_task_contract_ref", "target_transition_evidence_ref",
    }
    if set(later) != required_later:
        issues.append(issue("earth_structure_invalid", "Earth later-retry policy must contain exactly the bounded rebinding fields."))
    if (
        not all(later.get(key) is True for key in ("requires_new_decision_basis", "requires_new_consequence_commit", "preserves_old_records"))
        or later.get("previous_commit_record_ref") != commit.get("record_id")
        or later.get("old_decision_basis_hash") != jcs_sha256(decision)
        or later.get("old_consequence_commit_hash") != jcs_sha256(commit)
        or later.get("endpoint_ref") != "endpoint:B"
        or later.get("retry_instantiated_at") != retry_commit.get("created_at")
        or later.get("new_decision_basis_ref") != retry_commit.get("decision_basis_ref")
        or later.get("new_consequence_commit_ref") != {
            "artifact_id": retry_commit.get("record_id"),
            "version": record_version(retry_commit),
            "hash": jcs_sha256(retry_commit),
        }
        or later.get("new_permission_grant_ref") != retry_commit.get("permission_grant_ref")
        or later.get("new_task_contract_ref") != retry_commit.get("task_contract_ref")
        or later.get("target_transition_evidence_ref") != retry_commit.get("target_transition_evidence_ref")
        or retry_commit.get("previous_commit_record_ref") != {
            "artifact_id": commit.get("record_id"),
            "version": record_version(commit),
            "hash": jcs_sha256(commit),
        }
        or retry_commit.get("consequence_lineage_id") != commit.get("consequence_lineage_id")
        or any(
            (retry_commit.get("target_effect") or {}).get(field)
            != (commit.get("target_effect") or {}).get(field)
            for field in ("effect_id", "effect_class", "reversibility")
        )
        or (retry_commit.get("target_effect") or {}).get("target_ref") != "endpoint:B"
        or retry_commit.get("authorized_target_ref") != "endpoint:B"
        or retry_commit.get("task_endpoint_ref") != "endpoint:B"
        or retry_commit.get("commit_outcome") not in {"OPEN", "OPEN_WITH_LIMITS"}
        or retry_commit.get("effect_state") != "BOUND"
        or retry_commit.get("decision_basis_ref", {}).get("artifact_id") != retry_decision.get("record_id")
    ):
        issues.append(issue("earth_later_retry_not_rebound", "The endpoint-B retry must be an instantiated, exact-hash-bound new basis/commit/grant/task/transition graph while preserving endpoint-A records."))
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

KNOWN_EXPECTED_ISSUE_CODES = {
    "schema", "basis_hash_mismatch", "duplicate_logical_artifact_ref",
    "revoked_memory_cannot_be_used", "memory_qualification_requires_limits_or_denial",
    "memory_self_certification_forbidden", "alternate_path_not_closed",
    "invalid_observation_window", "duplicate_surface_id", "queue_surface_requires_queue_state",
    "narrative_claim_exceeds_structured_scope", "probe_count_signal_mismatch",
    "aggregate_coverage_contradiction", "precondition_set_incomplete_or_duplicate",
    "failed_precondition_cannot_bind_effect", "current_conditions_hash_domain_substitution",
    "memory_influence_precondition_mismatch", "memory_precondition_verdict_mismatch",
    "code_reuse_record_requires_manual_review", "high_risk_probe_cannot_be_allowed",
    "probe_signal_flag_mismatch", "judge_reviewer_independence_spoofed",
    "continuity_required_cases_missing_or_duplicate", "resume_requires_transition_evidence",
    "carry_cost_structure_invalid", "graph_decision_basis_link_invalid",
    "bounded_relation_claim_inflation", "functional_analog_proof_mismatch",
    "interface_adaptation_proof_mismatch", "formal_dependency_proof_mismatch",
    "graph_decision_basis_context_mismatch", "previous_commit_record_unresolved",
    "previous_commit_lineage_mismatch", "target_transition_evidence_unresolved",
    "target_transition_time_invalid", "target_transition_new_grant_required",
    "target_transition_new_task_required", "target_transition_current_authority_mismatch",
}


def validate_registered_links(
    data: dict[str, Any],
    record_registry: dict[str, str],
    schemas: dict[str, dict[str, Any]] | None = None,
    schema_registry: Registry | None = None,
    evidence_registry: dict[str, dict[str, str]] | None = None,
) -> list[ValidationIssue]:
    """Resolve manifest-declared evidence-graph links by exact ID and canonical hash."""
    issues: list[ValidationIssue] = []

    def resolve(record_id: Any) -> dict[str, Any] | None:
        rel = record_registry.get(str(record_id))
        path = contained_path(FIXTURE_DIR, rel) if rel else None
        if not path or not path.is_file():
            return None
        target = load_json(path)
        return target if isinstance(target, dict) and target.get("record_id") == record_id else None

    def linked_record_issues(
        target: dict[str, Any],
        schema_id: str,
        semantic: Callable[[dict[str, Any]], list[ValidationIssue]],
    ) -> list[ValidationIssue]:
        nested: list[ValidationIssue] = []
        if schemas is not None and schema_registry is not None:
            nested.extend(validate_schema(target, schema_id, schemas, schema_registry))
        nested.extend(nonblank_string_issues(target))
        if not any(item.code == "schema" for item in nested):
            nested.extend(semantic(target))
            if evidence_registry is not None:
                nested.extend(validate_registered_evidence(target, evidence_registry))
        return nested

    record_type = data.get("record_type")
    if record_type == "decision_basis_record":
        for ref in (data.get("basis") or {}).get("memory_reliance_refs", []):
            target = resolve(ref.get("artifact_id"))
            if (
                target is None
                or target.get("record_type") != "memory_reliance_record"
                or ref.get("version") != record_version(target)
                or ref.get("hash") != jcs_sha256(target)
            ):
                issues.append(issue("graph_memory_link_invalid", "Decision basis has an unresolved or hash-mismatched memory-reliance reference."))
            elif linked_record_issues(
                target,
                "urn:ivan-kotov:c-runtime-integrity:memory-reliance-record:0.1.1",
                semantic_memory_reliance,
            ):
                issues.append(issue("graph_memory_record_invalid", "Decision basis references a memory-reliance record that fails its own semantic qualification."))

    if record_type == "consequence_commit_record":
        decision_ref = data.get("decision_basis_ref") or {}
        decision = resolve(decision_ref.get("artifact_id"))
        if (
            decision is None
            or decision.get("record_type") != "decision_basis_record"
            or decision_ref.get("version") != record_version(decision)
            or decision_ref.get("hash") != jcs_sha256(decision)
        ):
            issues.append(issue("graph_decision_basis_link_invalid", "Consequence commit has an unresolved or hash-mismatched decision-basis reference."))
        else:
            basis = decision.get("basis") or {}
            basis_time = parse_timestamp(basis.get("captured_at"))
            commit_time = parse_timestamp(data.get("created_at"))
            if (
                basis.get("permission_grant_ref") != data.get("permission_grant_ref")
                or basis.get("grounding_ref") != data.get("source_grounding_ref")
                or basis.get("continuity_ref") != data.get("continuity_evidence_ref")
                or basis.get("l4_ref") != data.get("l4_state_ref")
                or basis_time is None
                or commit_time is None
                or basis_time > commit_time
            ):
                issues.append(issue(
                    "graph_decision_basis_context_mismatch",
                    "The linked decision basis must bind the exact current grant, grounding, continuity, and L4 references no later than the commit.",
                ))
            decision_memory_refs = {
                (ref.get("artifact_id"), ref.get("version"), ref.get("hash"))
                for ref in (decision.get("basis") or {}).get("memory_reliance_refs", [])
            }
            commit_memory_refs = {
                (ref.get("artifact_id"), ref.get("version"), ref.get("hash"))
                for ref in data.get("memory_reliance_refs", [])
            }
            if decision_memory_refs != commit_memory_refs:
                issues.append(issue("graph_memory_set_mismatch", "Decision-basis and consequence-commit memory influence sets must match exactly."))
        linked_memory_limits: set[str] = set()
        linked_memory_verdicts: list[str] = []
        for ref in data.get("memory_reliance_refs", []):
            memory = resolve(ref.get("artifact_id"))
            if (
                memory is None
                or memory.get("record_type") != "memory_reliance_record"
                or ref.get("version") != record_version(memory)
                or ref.get("hash") != jcs_sha256(memory)
            ):
                issues.append(issue("graph_memory_link_invalid", "Consequence commit has an unresolved or hash-mismatched memory-reliance reference."))
            else:
                if isinstance(memory.get("verdict"), str):
                    linked_memory_verdicts.append(memory["verdict"])
                if linked_record_issues(
                    memory,
                    "urn:ivan-kotov:c-runtime-integrity:memory-reliance-record:0.1.1",
                    semantic_memory_reliance,
                ):
                    issues.append(issue("graph_memory_record_invalid", "Consequence commit references a memory-reliance record that fails its own semantic qualification."))
                if (
                    memory.get("current_authority_ref") != data.get("permission_grant_ref")
                    or memory.get("current_task_ref") != data.get("task_contract_ref")
                ):
                    issues.append(issue("graph_memory_context_mismatch", "Linked memory must be qualified against the exact grant and task context used by the commit."))
                if memory.get("verdict") == "USE_WITH_LIMITS":
                    linked_memory_limits.update(
                        value for value in memory.get("use_limits", []) if isinstance(value, str)
                    )
                if data.get("commit_outcome") == "OPEN" and memory.get("verdict") != "USE":
                    issues.append(issue(
                        "limited_memory_cannot_authorize_unrestricted_open",
                        "An unrestricted OPEN cannot promote USE_WITH_LIMITS or DENY memory into unrestricted authority.",
                    ))
                if (
                    data.get("commit_outcome") == "OPEN_WITH_LIMITS"
                    and memory.get("verdict") not in {"USE", "USE_WITH_LIMITS"}
                ):
                    issues.append(issue(
                        "denied_memory_cannot_bind_effect",
                        "Only USE or USE_WITH_LIMITS memory may participate in a binding consequence.",
                    ))
        memory_precondition = next(
            (item for item in data.get("precondition_results", []) if item.get("name") == "MEMORY_RELIANCE"),
            {},
        )
        if linked_memory_verdicts and len(linked_memory_verdicts) == len(data.get("memory_reliance_refs", [])):
            if any(verdict in {"HOLD", "REROUTE_TO_REVIEW", "DENY", "QUARANTINE"} for verdict in linked_memory_verdicts):
                expected_memory_status = "FAIL"
            elif "USE_WITH_LIMITS" in linked_memory_verdicts:
                expected_memory_status = "PASS_WITH_LIMITS"
            else:
                expected_memory_status = "PASS"
            if memory_precondition.get("status") != expected_memory_status:
                issues.append(issue(
                    "memory_precondition_verdict_mismatch",
                    "MEMORY_RELIANCE status must be derived from the aggregate verdict of every resolved linked memory record.",
                ))
        if (
            data.get("commit_outcome") == "OPEN_WITH_LIMITS"
            and not linked_memory_limits.issubset(set(data.get("commit_limits", [])))
        ):
            issues.append(issue(
                "memory_limits_not_propagated",
                "OPEN_WITH_LIMITS must preserve every limit from every linked USE_WITH_LIMITS memory record.",
            ))
        witness_ref = data.get("non_effect_witness_ref")
        if witness_ref:
            witness = resolve(witness_ref.get("artifact_id")) if isinstance(witness_ref, dict) else None
            if (
                witness is None
                or witness.get("record_type") != "non_effect_witness_record"
                or witness_ref.get("version") != record_version(witness)
                or witness_ref.get("hash") != jcs_sha256(witness)
                or witness.get("gate_record_ref") != data.get("record_id")
                or witness.get("effect_scope_ref") != (data.get("target_effect") or {}).get("effect_id")
                or witness.get("effect_target_ref") != (data.get("target_effect") or {}).get("target_ref")
                or data.get("effect_state") != "NOT_BOUND"
                or witness.get("conclusion") != "NO_EFFECT_OBSERVED_WITHIN_DECLARED_SCOPE"
            ):
                issues.append(issue("graph_witness_link_invalid", "Consequence commit has no reciprocal strongest scoped non-effect witness bound to the same effect and target."))
        previous_ref = data.get("previous_commit_record_ref")
        if previous_ref:
            previous = resolve(previous_ref.get("artifact_id")) if isinstance(previous_ref, dict) else None
            if (
                previous is None
                or previous.get("record_type") != "consequence_commit_record"
                or previous.get("record_id") == data.get("record_id")
                or previous_ref.get("version") != record_version(previous)
                or previous_ref.get("hash") != jcs_sha256(previous)
            ):
                issues.append(issue("previous_commit_record_unresolved", "Linked reevaluation must hash-bind a distinct predecessor in the trusted record registry."))
            else:
                if linked_record_issues(
                    previous,
                    "urn:ivan-kotov:c-runtime-integrity:consequence-commit-record:0.1.1",
                    semantic_commit,
                ):
                    issues.append(issue("previous_commit_record_invalid", "The trusted predecessor must remain independently valid and immutable."))
                previous_time = parse_timestamp(previous.get("created_at"))
                current_time = parse_timestamp(data.get("created_at"))
                if previous_time is None or current_time is None or previous_time >= current_time:
                    issues.append(issue("previous_commit_timestamp_nonmonotonic", "Every predecessor timestamp must be strictly earlier than its successor."))
                if previous.get("consequence_lineage_id") != data.get("consequence_lineage_id"):
                    issues.append(issue("previous_commit_lineage_mismatch", "A predecessor and successor must share the explicit consequence_lineage_id."))
                previous_effect = previous.get("target_effect") or {}
                current_effect = data.get("target_effect") or {}
                effect_intent_fields = ("effect_id", "effect_class", "reversibility")
                if any(previous_effect.get(field) != current_effect.get(field) for field in effect_intent_fields):
                    issues.append(issue(
                        "previous_commit_effect_intent_mismatch",
                        "A linked reevaluation must preserve effect_id, effect_class, and reversibility; target_ref may change only through the explicit target-transition path.",
                    ))
                previous_target = previous_effect.get("target_ref")
                current_target = current_effect.get("target_ref")
                transition = resolve_artifact_ref_evidence(
                    data.get("target_transition_evidence_ref"), evidence_registry or {},
                )
                transition_data = transition[0] if transition else {}
                expected_transition = {
                    "evidence_kind": "TARGET_TRANSITION",
                    "consequence_lineage_id": data.get("consequence_lineage_id"),
                    "effect_id": current_effect.get("effect_id"),
                    "effect_class": current_effect.get("effect_class"),
                    "reversibility": current_effect.get("reversibility"),
                    "previous_record_id": previous.get("record_id"),
                    "current_record_id": data.get("record_id"),
                    "previous_target_ref": previous_target,
                    "current_target_ref": current_target,
                    "reason_code": data.get("change_reason_code"),
                    "previous_permission_grant_ref": previous.get("permission_grant_ref"),
                    "current_permission_grant_ref": data.get("permission_grant_ref"),
                    "previous_task_contract_ref": previous.get("task_contract_ref"),
                    "current_task_contract_ref": data.get("task_contract_ref"),
                }
                if transition is None or any(transition_data.get(key) != value for key, value in expected_transition.items()):
                    issues.append(issue("target_transition_evidence_unresolved", "Target-transition evidence must bind both immutable record IDs, lineage, effect ID/class/reversibility, old/new targets, reason, and old/new grant/task references."))
                transition_time = parse_timestamp(transition_data.get("observed_at"))
                if (
                    previous_time is None
                    or current_time is None
                    or transition_time is None
                    or not previous_time < transition_time <= current_time
                ):
                    issues.append(issue("target_transition_time_invalid", "Transition evidence time must be strictly after the predecessor and no later than the current commit."))
                if previous_target != current_target:
                    if data.get("change_reason_code") == "CONDITIONS_REVALIDATED_SAME_TARGET":
                        issues.append(issue("target_transition_reason_mismatch", "A changed target requires an explicit machine-readable target-change reason."))
                    if previous.get("permission_grant_ref") == data.get("permission_grant_ref"):
                        issues.append(issue("target_transition_new_grant_required", "A changed target requires a distinct current grant."))
                    if previous.get("task_contract_ref") == data.get("task_contract_ref"):
                        issues.append(issue("target_transition_new_task_required", "A changed target requires a distinct current task contract."))
                    grant = resolve_artifact_ref_evidence(data.get("permission_grant_ref"), evidence_registry or {})
                    task = resolve_artifact_ref_evidence(data.get("task_contract_ref"), evidence_registry or {})
                    task_state = state_at(task[0], data.get("created_at")) if task else None
                    if (
                        grant is None
                        or grant[0].get("authorized_target_ref") != current_target
                        or not grant_is_valid_at(grant[0], data.get("created_at"))
                        or task is None
                        or task_state is None
                        or task_state.get("status") != "CURRENT"
                        or task_state.get("endpoint_ref") != current_target
                        or data.get("authorized_target_ref") != current_target
                        or data.get("task_endpoint_ref") != current_target
                    ):
                        issues.append(issue("target_transition_current_authority_mismatch", "Changed-target reevaluation requires the current target to match a valid current grant, current task state, and commit fields even for a nonbinding outcome."))
                elif data.get("change_reason_code") != "CONDITIONS_REVALIDATED_SAME_TARGET":
                    issues.append(issue("target_transition_reason_mismatch", "An unchanged target must use the same-target reevaluation reason."))

    if record_type == "non_effect_witness_record":
        commit = resolve(data.get("gate_record_ref"))
        if (
            commit is None
            or commit.get("record_type") != "consequence_commit_record"
            or not isinstance(commit.get("non_effect_witness_ref"), dict)
            or commit.get("non_effect_witness_ref", {}).get("artifact_id") != data.get("record_id")
            or commit.get("non_effect_witness_ref", {}).get("version") != record_version(data)
            or commit.get("non_effect_witness_ref", {}).get("hash") != jcs_sha256(data)
            or (commit.get("target_effect") or {}).get("effect_id") != data.get("effect_scope_ref")
            or (commit.get("target_effect") or {}).get("target_ref") != data.get("effect_target_ref")
            or commit.get("effect_state") != "NOT_BOUND"
            or data.get("conclusion") != "NO_EFFECT_OBSERVED_WITHIN_DECLARED_SCOPE"
        ):
            issues.append(issue("graph_witness_link_invalid", "Non-effect witness has no reciprocal NOT_BOUND commit bound to the same effect and target."))
    return issues


def validate_previous_commit_dag(
    record_registry: dict[str, str],
    records_override: dict[str, dict[str, Any]] | None = None,
) -> tuple[int, list[ValidationIssue]]:
    """Validate the complete trusted predecessor graph, not only one edge.

    ``records_override`` exists for deterministic mutation tests.  Production
    validation always constructs the graph from manifest-bound repository
    paths, preserving the registry as the trust boundary.
    """
    issues: list[ValidationIssue] = []
    records: dict[str, dict[str, Any]] = {}
    seen_record_ids: dict[str, str] = {}
    seen_paths: dict[str, str] = {}
    for registry_id, relative in record_registry.items():
        if records_override is not None:
            record = records_override.get(registry_id)
            path_key = f"override:{registry_id}"
        else:
            path = contained_path(FIXTURE_DIR, relative)
            record = load_json(path) if path and path.is_file() else None
            path_key = str(path) if path else str(relative)
        if not isinstance(record, dict) or record.get("record_type") != "consequence_commit_record":
            continue
        record_id = record.get("record_id")
        if registry_id != record_id:
            issues.append(issue("previous_graph_registry_alias", f"Registry key {registry_id!r} does not equal consequence record_id {record_id!r}."))
        if isinstance(record_id, str) and record_id in seen_record_ids:
            issues.append(issue("previous_graph_duplicate_logical_record", f"Duplicate logical consequence record {record_id!r}."))
        if path_key in seen_paths:
            issues.append(issue("previous_graph_duplicate_logical_predecessor", f"Registry entries {seen_paths[path_key]!r} and {registry_id!r} reuse one predecessor object."))
        if isinstance(record_id, str):
            seen_record_ids[record_id] = registry_id
            records[record_id] = record
        seen_paths[path_key] = registry_id

    edges: dict[str, str] = {}
    for record_id, record in records.items():
        ref = record.get("previous_commit_record_ref")
        if ref is None:
            continue
        predecessor_id = ref.get("artifact_id") if isinstance(ref, dict) else None
        predecessor = records.get(str(predecessor_id))
        if predecessor is None:
            issues.append(issue("previous_graph_missing_predecessor", f"{record_id!r} references a predecessor outside the trusted registry: {predecessor_id!r}."))
            continue
        edges[record_id] = str(predecessor_id)
        if ref.get("version") != record_version(predecessor) or ref.get("hash") != jcs_sha256(predecessor):
            issues.append(issue("previous_graph_predecessor_binding_mismatch", f"{record_id!r} does not exact-hash-bind predecessor {predecessor_id!r}."))
        current_time = parse_timestamp(record.get("created_at"))
        predecessor_time = parse_timestamp(predecessor.get("created_at"))
        if current_time is None or predecessor_time is None or predecessor_time >= current_time:
            issues.append(issue("previous_graph_timestamp_nonmonotonic", f"Predecessor {predecessor_id!r} is not strictly earlier than {record_id!r}."))
        if predecessor.get("consequence_lineage_id") != record.get("consequence_lineage_id"):
            issues.append(issue("previous_graph_lineage_mismatch", f"{record_id!r} changes consequence_lineage_id across its predecessor edge."))
        if any(
            (predecessor.get("target_effect") or {}).get(field)
            != (record.get("target_effect") or {}).get(field)
            for field in ("effect_id", "effect_class", "reversibility")
        ):
            issues.append(issue("previous_graph_effect_intent_mismatch", f"{record_id!r} changes effect intent across its predecessor edge."))

    state: dict[str, int] = {}

    def visit(node: str, trail: list[str]) -> None:
        marker = state.get(node, 0)
        if marker == 1:
            cycle_start = trail.index(node) if node in trail else 0
            cycle = trail[cycle_start:] + [node]
            issues.append(issue("previous_graph_cycle", "Previous-record graph cycle: " + " -> ".join(cycle)))
            return
        if marker == 2:
            return
        state[node] = 1
        predecessor = edges.get(node)
        if predecessor is not None:
            visit(predecessor, trail + [node])
        state[node] = 2

    for node in sorted(records):
        visit(node, [])
    return len(records), issues


def evidence_logical_ids(data: Any) -> list[str] | None:
    """Return the exact logical identifiers declared by one evidence artifact."""
    if not isinstance(data, dict):
        return None
    artifact_id = data.get("artifact_id")
    evidence_ids = data.get("evidence_ids")
    if isinstance(artifact_id, str) and artifact_id:
        if evidence_ids not in (None, []):
            return None
        return [artifact_id]
    if (
        isinstance(evidence_ids, list)
        and bool(evidence_ids)
        and all(isinstance(value, str) and value for value in evidence_ids)
        and not duplicate_values(evidence_ids)
    ):
        return list(evidence_ids)
    return None


def validate_manifest_registry(
    manifest: dict[str, Any],
    *,
    actual_evidence_paths_override: set[str] | None = None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    entries = manifest.get("fixtures", [])
    declared = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    duplicates = duplicate_values(declared)
    if duplicates:
        issues.append(issue("manifest_duplicate_fixture", f"Duplicate fixture paths: {sorted(duplicates)!r}"))
    actual = {
        path.relative_to(FIXTURE_DIR).as_posix()
        for folder in (FIXTURE_DIR / "positive", FIXTURE_DIR / "negative")
        for path in folder.glob("*.json")
    }
    if set(declared) != actual:
        issues.append(issue(
            "manifest_fixture_orphan_or_missing",
            f"Manifest mismatch; undeclared={sorted(actual - set(declared))!r}, missing={sorted(set(declared) - actual)!r}.",
        ))
    record_registry = manifest.get("record_registry", {})
    record_paths = list(record_registry.values()) if isinstance(record_registry, dict) else []
    if duplicate_values(record_paths):
        issues.append(issue("manifest_duplicate_record_path", "Record registry must not alias one file through multiple logical IDs."))
    for record_id, relative in record_registry.items():
        path = contained_path(FIXTURE_DIR, relative)
        record = load_json(path) if path and path.is_file() else None
        if not isinstance(record, dict) or record.get("record_id") != record_id:
            issues.append(issue("manifest_record_unresolved", f"Record registry entry {record_id!r} is unresolved or aliased."))

    inventory = manifest.get("evidence_artifact_inventory")
    if not isinstance(inventory, list):
        issues.append(issue("manifest_evidence_inventory_missing", "Evidence artifact inventory must be an array."))
        inventory = []
    declared_evidence_paths = [
        entry.get("path") for entry in inventory if isinstance(entry, dict)
    ]
    duplicate_evidence_paths = duplicate_values(declared_evidence_paths)
    if duplicate_evidence_paths:
        issues.append(issue(
            "manifest_duplicate_evidence_path",
            f"Evidence artifact paths must be unique: {sorted(duplicate_evidence_paths)!r}.",
        ))
    actual_evidence_paths = (
        {
            path.relative_to(ROOT).as_posix()
            for path in EVIDENCE_DIR.glob("*.json")
        }
        if actual_evidence_paths_override is None
        else set(actual_evidence_paths_override)
    )
    declared_evidence_set = {
        value for value in declared_evidence_paths if isinstance(value, str)
    }
    if declared_evidence_set != actual_evidence_paths:
        issues.append(issue(
            "manifest_evidence_orphan_or_missing",
            "Evidence inventory mismatch; "
            f"undeclared={sorted(actual_evidence_paths - declared_evidence_set)!r}, "
            f"missing={sorted(declared_evidence_set - actual_evidence_paths)!r}.",
        ))

    declared_id_paths: dict[str, str] = {}
    inventory_by_path: dict[str, dict[str, Any]] = {}
    for entry in inventory:
        if not isinstance(entry, dict):
            issues.append(issue("manifest_evidence_inventory_entry_invalid", "Every evidence inventory entry must be an object."))
            continue
        relative = entry.get("path")
        path = contained_path(ROOT, relative)
        if (
            not isinstance(relative, str)
            or not relative.startswith("fixtures/runtime-integrity/evidence/")
            or not path
            or not path.is_file()
        ):
            issues.append(issue("manifest_evidence_inventory_entry_invalid", f"Evidence inventory path is unresolved: {relative!r}."))
            continue
        data = load_json(path)
        actual_ids = evidence_logical_ids(data)
        declared_ids = entry.get("logical_ids")
        if isinstance(declared_ids, list):
            for evidence_id in declared_ids:
                if not isinstance(evidence_id, str) or not evidence_id:
                    continue
                previous = declared_id_paths.get(evidence_id)
                if previous is not None:
                    issues.append(issue(
                        "manifest_duplicate_evidence_logical_id",
                        f"Evidence logical ID {evidence_id!r} is declared by both {previous!r} and {relative!r}.",
                    ))
                else:
                    declared_id_paths[evidence_id] = relative
        if (
            actual_ids is None
            or not isinstance(declared_ids, list)
            or declared_ids != actual_ids
            or entry.get("hash") != jcs_sha256(data)
        ):
            issues.append(issue(
                "manifest_evidence_inventory_binding_mismatch",
                f"Evidence inventory entry {relative!r} must exact-bind its JCS hash and in-file logical identifiers.",
            ))
            continue
        if relative not in inventory_by_path:
            inventory_by_path[relative] = entry

    for evidence_id, entry in manifest.get("evidence_registry", {}).items():
        resolved = resolve_registered_evidence(evidence_id, manifest.get("evidence_registry", {}))
        if resolved is None:
            issues.append(issue("manifest_evidence_unresolved", f"Evidence registry entry {evidence_id!r} is unresolved, aliased, or hash-mismatched."))
            continue
        inventory_entry = inventory_by_path.get(entry.get("path")) if isinstance(entry, dict) else None
        if (
            not isinstance(inventory_entry, dict)
            or evidence_id not in inventory_entry.get("logical_ids", [])
            or entry.get("hash") != inventory_entry.get("hash")
        ):
            issues.append(issue(
                "manifest_evidence_registry_inventory_mismatch",
                f"Evidence registry entry {evidence_id!r} is not exact-bound to its one inventoried artifact.",
            ))
    return issues


def resolve_registered_evidence(
    ref_id: Any,
    evidence_registry: dict[str, dict[str, str]],
) -> tuple[dict[str, Any], str] | None:
    entry = evidence_registry.get(str(ref_id))
    if not isinstance(entry, dict):
        return None
    path = contained_path(ROOT, entry.get("path"))
    if not path or not path.is_file():
        return None
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    actual_hash = jcs_sha256(data)
    if entry.get("hash") != actual_hash:
        return None
    ids = set(data.get("evidence_ids", []))
    artifact_id = data.get("artifact_id")
    if ref_id not in ids and ref_id != artifact_id:
        return None
    return data, actual_hash


def resolve_artifact_ref_evidence(
    ref: Any,
    evidence_registry: dict[str, dict[str, str]],
) -> tuple[dict[str, Any], str] | None:
    if not isinstance(ref, dict):
        return None
    resolved = resolve_registered_evidence(ref.get("artifact_id"), evidence_registry)
    if resolved is None:
        return None
    artifact, actual_hash = resolved
    if ref.get("version") != artifact.get("version") or ref.get("hash") != actual_hash:
        return None
    return artifact, actual_hash


def validate_registered_evidence(
    data: dict[str, Any],
    evidence_registry: dict[str, dict[str, str]],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not isinstance(data, dict):
        return [issue("evidence_subject_invalid", "Evidence validation requires an object record.")]
    record_type = data.get("record_type")
    if record_type == "decision_basis_record":
        basis = data.get("basis") or {}
        grant_ref = basis.get("permission_grant_ref")
        grant = resolve_artifact_ref_evidence(grant_ref, evidence_registry)
        authority_refs = {
            (ref.get("artifact_id"), ref.get("version"), ref.get("hash"))
            for ref in basis.get("authority_refs", [])
            if isinstance(ref, dict)
        }
        if grant is None or (
            (grant_ref.get("artifact_id"), grant_ref.get("version"), grant_ref.get("hash")) not in authority_refs
            or not grant_is_valid_at(grant[0], basis.get("captured_at"))
        ):
            issues.append(issue("decision_permission_grant_unresolved", "Decision basis must resolve a currently VALID permission grant that is also present in authority_refs."))

    if record_type == "memory_reliance_record":
        grant = resolve_artifact_ref_evidence(data.get("current_authority_ref"), evidence_registry)
        task = resolve_artifact_ref_evidence(data.get("current_task_ref"), evidence_registry)
        task_state = state_at(task[0], data.get("created_at")) if task else None
        if grant is None or not grant_is_valid_at(grant[0], data.get("created_at")):
            issues.append(issue("memory_current_authority_unresolved", "Memory reliance must resolve a permission grant that is VALID at qualification time."))
        if task is None or task_state is None or task_state.get("status") != "CURRENT":
            issues.append(issue("memory_current_task_unresolved", "Memory reliance must resolve a CURRENT task contract at qualification time."))

    if record_type == "consequence_commit_record":
        grant_ref = data.get("permission_grant_ref")
        task_ref = data.get("task_contract_ref")
        conditions_ref = data.get("current_conditions_ref")
        grant = resolve_artifact_ref_evidence(grant_ref, evidence_registry)
        task = resolve_artifact_ref_evidence(task_ref, evidence_registry)
        conditions = resolve_artifact_ref_evidence(conditions_ref, evidence_registry)
        grant_state = state_at(grant[0], data.get("created_at")) if grant else None
        task_state = state_at(task[0], data.get("created_at")) if task else None
        if grant is None or grant_state is None or (
            grant_state.get("status") != data.get("permission_status")
            or (data.get("permission_status") == "VALID" and not grant_is_valid_at(grant[0], data.get("created_at")))
            or grant[0].get("issuer_ref") != data.get("permission_issuer_ref")
            or grant[0].get("subject_ref") != data.get("permission_subject_ref")
            or grant[0].get("authorized_target_ref") != data.get("authorized_target_ref")
            or grant[0].get("valid_until") != data.get("permission_valid_until")
        ):
            issues.append(issue("commit_permission_grant_unresolved", "Commit permission fields must resolve to the grant state at the exact commit time."))
        if task is None or task_state is None or (
            task_state.get("status") != data.get("task_contract_status")
            or task_state.get("endpoint_ref") != data.get("task_endpoint_ref")
        ):
            issues.append(issue("commit_task_contract_unresolved", "Commit task fields must resolve to the task-contract state at the exact commit time."))
        if conditions is None:
            issues.append(issue("commit_current_conditions_unresolved", "Commit current conditions must resolve through the hash-bound evidence registry."))
        else:
            current = conditions[0]
            planning = current.get("planning_state") if isinstance(current.get("planning_state"), dict) else {}
            changed = current.get("changed_state") if isinstance(current.get("changed_state"), dict) else {}
            planning_at = parse_timestamp(planning.get("observed_at"))
            changed_at = parse_timestamp(changed.get("observed_at"))
            captured_at = parse_timestamp(current.get("captured_at"))
            ordered_condition_times = False
            if planning_at and changed_at and captured_at:
                try:
                    ordered_condition_times = planning_at < changed_at < captured_at
                except TypeError:
                    ordered_condition_times = False
            statuses = {item.get("name"): item.get("status") for item in data.get("precondition_results", [])}
            evidence_refs = {item.get("name"): item.get("evidence_ref") for item in data.get("precondition_results", [])}
            expected_time_status = {
                "FRESH": "PASS", "LIMITED": "PASS_WITH_LIMITS", "EXPIRED": "FAIL", "UNKNOWN": "UNKNOWN",
            }.get(current.get("source_evidence_state"))
            expected_l4_status = {
                "SUFFICIENT": "PASS", "LIMITED": "PASS_WITH_LIMITS", "EXCEEDED": "FAIL", "UNKNOWN": "UNKNOWN",
            }.get(current.get("l4_budget_state"))
            expected_blocking_status = {
                "CLEAR": "PASS", "PENDING": "FAIL", "UNKNOWN": "UNKNOWN",
            }.get(current.get("queued_retry_state"))
            expected_authority_status = {
                "VALID": "PASS", "REVOKED": "FAIL", "EXPIRED": "FAIL", "UNKNOWN": "UNKNOWN",
            }.get(current.get("permission_status"))
            conditions_match = (
                current.get("captured_at") == data.get("created_at")
                and current.get("permission_grant_ref") == grant_ref
                and current.get("permission_status") == data.get("permission_status")
                and current.get("task_contract_ref") == task_ref
                and current.get("task_contract_status") == data.get("task_contract_status")
                and current.get("planning_target_ref") == data.get("authorized_target_ref")
                and current.get("current_endpoint_ref") == data.get("task_endpoint_ref")
                and current.get("source_grounding_ref") == data.get("source_grounding_ref")
                and current.get("continuity_evidence_ref") == data.get("continuity_evidence_ref")
                and current.get("l4_state_ref") == data.get("l4_state_ref")
                and current.get("precondition_evidence_refs") == evidence_refs
                and set(planning) == {
                    "observed_at", "permission_status", "task_contract_status", "endpoint_ref",
                    "source_evidence_state", "l4_budget_state",
                }
                and planning.get("permission_status") == "VALID"
                and planning.get("task_contract_status") == "CURRENT"
                and planning.get("endpoint_ref") == current.get("planning_target_ref")
                and planning.get("source_evidence_state") == "FRESH"
                and planning.get("l4_budget_state") == "SUFFICIENT"
                and set(changed) == {
                    "observed_at", "permission_status", "task_contract_status", "endpoint_ref",
                    "source_evidence_state", "l4_budget_state", "queued_retry_state",
                }
                and changed.get("permission_status") == current.get("permission_status")
                and changed.get("task_contract_status") == current.get("task_contract_status")
                and changed.get("endpoint_ref") == current.get("current_endpoint_ref")
                and changed.get("source_evidence_state") == current.get("source_evidence_state")
                and changed.get("l4_budget_state") == current.get("l4_budget_state")
                and changed.get("queued_retry_state") == current.get("queued_retry_state")
                and ordered_condition_times
                and expected_time_status is not None
                and statuses.get("TIME_WINDOW") == expected_time_status
                and expected_l4_status is not None
                and statuses.get("L4_BUDGET") == expected_l4_status
                and expected_blocking_status is not None
                and statuses.get("BLOCKING_STATE") == expected_blocking_status
                and expected_authority_status is not None
                and statuses.get("CURRENT_AUTHORITY") == expected_authority_status
            )
            if not conditions_match:
                issues.append(issue("commit_current_conditions_mismatch", "Hash-bound current conditions do not match the commit-time grant, task, endpoint, evidence, L4, or retry facts."))

    if record_type == "non_effect_witness_record":
        window = data.get("observation_window") or {}
        surfaces = data.get("observation_surfaces", [])
        routes = data.get("alternate_path_checks", [])
        collection = data.get("evidence_collection") or {}
        clock = resolve_registered_evidence(data.get("clock_source_ref"), evidence_registry)
        collector = resolve_registered_evidence(collection.get("collector_ref"), evidence_registry)
        event_log = resolve_registered_evidence(collection.get("continuous_event_log_ref"), evidence_registry)
        inventory = resolve_registered_evidence(data.get("scope_inventory_ref"), evidence_registry)
        if inventory is None or inventory[1] != data.get("scope_inventory_hash"):
            issues.append(issue("non_effect_scope_inventory_unresolved", "The declared scope inventory is not resolvable and hash-bound."))
        else:
            inventory_data = inventory[0]
            if (
                inventory_data.get("effect_scope_ref") != data.get("effect_scope_ref")
                or inventory_data.get("effect_target_ref") != data.get("effect_target_ref")
                or inventory_data.get("protected_effects") != data.get("protected_effects")
                or set(inventory_data.get("observation_surface_ids", [])) != {item.get("surface_id") for item in surfaces}
                or set(inventory_data.get("alternate_path_ids", [])) != {item.get("path_id") for item in routes}
            ):
                issues.append(issue("non_effect_scope_inventory_mismatch", "The frozen scope inventory does not match the witness surfaces, routes, or protected effects."))
        if clock is None or clock[0].get("correlation_window") != window:
            issues.append(issue("non_effect_clock_evidence_unresolved", "The clock source is not resolvable for the observation window."))
        if collector is None or (
            collector[0].get("availability") != "COMPLETE"
            or collector[0].get("continuous_event_log_ref") != collection.get("continuous_event_log_ref")
            or collector[0].get("window") != window
            or set(collector[0].get("surface_ids", [])) != {item.get("surface_id") for item in surfaces}
        ):
            issues.append(issue("non_effect_collector_evidence_unresolved", "Collector evidence is missing or does not cover the declared window and surfaces."))
        surface_fields = (
            "surface_id", "surface_kind", "target_ref", "target_coordinate", "hash_domain",
            "before_hash", "after_hash", "external_call_count", "queue_state", "retry_state", "coverage",
        )
        expected_observations = sorted(
            [{key: surface.get(key) for key in surface_fields} for surface in surfaces],
            key=lambda item: str(item.get("surface_id")),
        )
        observed_observations = sorted(
            [
                {key: surface.get(key) for key in surface_fields}
                for surface in (event_log[0].get("surface_observations", []) if event_log else [])
                if isinstance(surface, dict)
            ],
            key=lambda item: str(item.get("surface_id")),
        )
        if event_log is None or (
            event_log[0].get("collector_ref") != collection.get("collector_ref")
            or event_log[0].get("availability") != "COMPLETE"
            or event_log[0].get("window") != window
            or observed_observations != expected_observations
            or (data.get("conclusion") == "NO_EFFECT_OBSERVED_WITHIN_DECLARED_SCOPE" and event_log[0].get("events") != [])
        ):
            issues.append(issue("non_effect_event_log_unresolved", "Continuous event evidence is missing, incomplete, or inconsistent with the scoped non-effect conclusion."))
        if any(
            surface.get("target_ref") != data.get("effect_target_ref")
            or not target_coordinate_is_canonical(
                data.get("effect_target_ref"),
                surface.get("target_coordinate"),
            )
            for surface in surfaces
        ):
            issues.append(issue("non_effect_surface_target_mismatch", "Every observed surface must explicitly bind the witness effect target with a canonical, non-normalizing coordinate within it."))
        resolved_route_artifacts: dict[str, dict[str, Any]] = {}
        for route in routes:
            evidence = resolve_registered_evidence(route.get("evidence_ref"), evidence_registry)
            if evidence is None or evidence[0].get("window") != window or evidence[0].get("collector_ref") != collection.get("collector_ref"):
                issues.append(issue("alternate_path_evidence_unresolved", f"Alternate path evidence is unresolved for {route.get('path_id')}."))
            else:
                resolved_route_artifacts[evidence[1]] = evidence[0]
        expected_route_states = {item.get("path_id"): item.get("status") for item in routes}
        observed_route_items = [
            item
            for artifact in resolved_route_artifacts.values()
            for item in artifact.get("path_states", [])
            if isinstance(item, dict)
        ]
        observed_route_ids = [item.get("path_id") for item in observed_route_items]
        observed_route_states = {item.get("path_id"): item.get("status") for item in observed_route_items}
        if (
            len(observed_route_items) != len(routes)
            or duplicate_values(observed_route_ids)
            or observed_route_states != expected_route_states
            or any(status in {"OPEN", "UNKNOWN"} for status in observed_route_states.values())
        ):
            issues.append(issue("alternate_path_evidence_unresolved", "Route evidence must be duplicate-free and exactly equal the closed/not-reachable witness route inventory."))

    if record_type == "boundary_probe_record":
        aggregation = data.get("aggregation_keys") or {}
        window = data.get("window") or {}
        expected_window_ref = f"window:{window.get('start')}/{window.get('end')}"
        if aggregation.get("time_window_ref") != expected_window_ref:
            issues.append(issue("probe_aggregation_window_mismatch", "Aggregation time_window_ref does not bind the declared probe window."))
        budget_ref = (data.get("budget") or {}).get("budget_profile_ref") or {}
        budget = resolve_registered_evidence(budget_ref.get("artifact_id"), evidence_registry)
        if budget is None or (
            budget_ref.get("version") != budget[0].get("version")
            or budget_ref.get("hash") != budget[1]
            or budget[0].get("protected_surface_ref") != data.get("protected_surface_ref")
        ):
            issues.append(issue("probe_budget_profile_unresolved", "Budget profile is not resolvable, hash-bound, and scoped to the protected surface."))

    if record_type == "judge_deliberation_record":
        attestation = resolve_registered_evidence(data.get("independence_evidence_ref"), evidence_registry)
        instances = {item.get("model_instance_id") for item in data.get("reviewers", [])}
        if attestation is None or (
            attestation[0].get("isolated_first_pass") is not True
            or attestation[0].get("outputs_fed_back_to_reviewers") is not False
            or set(attestation[0].get("model_instance_ids", [])) != instances
        ):
            issues.append(issue("judge_independence_evidence_unresolved", "Judge independence evidence is unresolved or inconsistent with reviewer instances."))
    return issues


def validate_fixture(
    entry: dict[str, Any],
    schemas: dict[str, dict[str, Any]],
    registry: Registry,
    record_registry: dict[str, str],
    evidence_registry: dict[str, dict[str, str]],
    review_context: dict[str, Any],
    expected_context_sha256: str,
    expected_bindings: dict[str, str],
) -> tuple[bool, list[ValidationIssue]]:
    path = FIXTURE_DIR / entry["path"]
    data = load_json(path)
    issues: list[ValidationIssue] = []
    schema_id = entry.get("schema_id")
    if schema_id:
        issues.extend(validate_schema(data, schema_id, schemas, registry))
    issues.extend(nonblank_string_issues(data))
    if not any(item.code == "schema" for item in issues):
        record_type = data.get("record_type") if isinstance(data, dict) else None
        semantic = SEMANTIC_BY_TYPE.get(record_type)
        if record_type == "judge_deliberation_record":
            issues.extend(semantic_judge(data, review_context, expected_context_sha256, expected_bindings))
        elif semantic:
            issues.extend(semantic(data))
        if record_type in {"decision_basis_record", "consequence_commit_record", "non_effect_witness_record"}:
            issues.extend(validate_registered_links(
                data, record_registry, schemas, registry, evidence_registry,
            ))
        issues.extend(validate_registered_evidence(data, evidence_registry))
        semantic_kind = entry.get("semantic_kind")
        if semantic_kind == "earth_test_bundle":
            issues.extend(semantic_earth_bundle(
                data, schemas, registry, record_registry, evidence_registry,
            ))
        elif semantic_kind:
            semantic = SEMANTIC_BY_KIND.get(semantic_kind)
            if semantic is None:
                issues.append(issue("unknown_semantic_kind", f"Unknown semantic_kind: {semantic_kind}"))
            else:
                issues.extend(semantic(data))
    observed_valid = not issues
    expected_valid = bool(entry["expected_valid"])
    if expected_valid:
        return observed_valid, issues
    expected_codes = entry.get("expected_issue_codes")
    if not isinstance(expected_codes, list) or not expected_codes:
        issues.append(issue("fixture_expectation_missing", "Invalid fixtures require non-empty expected_issue_codes."))
        return False, issues
    unknown = set(expected_codes) - KNOWN_EXPECTED_ISSUE_CODES
    if unknown:
        issues.append(issue("fixture_expectation_unknown", f"Unknown expected issue codes: {sorted(unknown)!r}"))
        return False, issues
    missing = set(expected_codes) - {item.code for item in issues}
    if missing:
        issues.append(issue("fixture_expectation_mismatch", f"Expected issue codes were not observed: {sorted(missing)!r}"))
        return False, issues
    return bool(issues), issues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--review-context", type=Path, default=DEFAULT_REVIEW_CONTEXT)
    parser.add_argument("--expected-review-context-sha256", default=os.environ.get("RUNTIME_REVIEW_CONTEXT_SHA256"))
    parser.add_argument("--expected-repository", default=os.environ.get("RUNTIME_EXPECTED_REPOSITORY"))
    parser.add_argument("--expected-base-sha", default=os.environ.get("RUNTIME_EXPECTED_BASE_SHA"))
    parser.add_argument("--expected-reviewed-parent-sha", default=os.environ.get("RUNTIME_EXPECTED_REVIEWED_PARENT_SHA"))
    parser.add_argument("--expected-candidate-scope", default=os.environ.get("RUNTIME_EXPECTED_CANDIDATE_SCOPE"))
    parser.add_argument("--expected-trust-root-class", default=os.environ.get("RUNTIME_EXPECTED_TRUST_ROOT_CLASS"))
    args = parser.parse_args()
    required_external = {
        "review-context SHA-256": args.expected_review_context_sha256,
        "repository": args.expected_repository,
        "base SHA": args.expected_base_sha,
        "reviewed parent SHA": args.expected_reviewed_parent_sha,
        "candidate scope": args.expected_candidate_scope,
        "trust-root class": args.expected_trust_root_class,
    }
    missing_external = [name for name, value in required_external.items() if not value]
    if missing_external:
        print("Missing caller-supplied review expectations: " + ", ".join(missing_external), file=sys.stderr)
        return 2
    review_context_path = args.review_context.resolve()
    try:
        review_context_path.relative_to(ROOT.resolve())
    except ValueError:
        print("Review context path must resolve inside the candidate checkout.", file=sys.stderr)
        return 2
    review_context = load_json(review_context_path)
    expected_bindings = {
        "repository": args.expected_repository,
        "base_sha": args.expected_base_sha,
        "reviewed_parent_sha": args.expected_reviewed_parent_sha,
        "candidate_scope": args.expected_candidate_scope,
        "trust_root_class": args.expected_trust_root_class,
    }
    schemas, registry = build_registry()
    manifest = load_json(MANIFEST)
    entries = manifest.get("fixtures", [])
    record_registry = manifest.get("record_registry", {})
    evidence_registry = manifest.get("evidence_registry", {})
    passed = 0
    failures: list[str] = []
    for entry in entries:
        matched, issues = validate_fixture(
            entry, schemas, registry, record_registry, evidence_registry,
            review_context, args.expected_review_context_sha256, expected_bindings,
        )
        path = entry["path"]
        expected = "VALID" if entry["expected_valid"] else "INVALID"
        observed = "VALID" if not issues else "INVALID"
        if matched:
            passed += 1
            if args.verbose:
                codes = ", ".join(item.code for item in issues) or "none"
                print(f"PASS {path}: expected={expected} observed={observed} issues={codes}")
        else:
            detail = "; ".join(f"{item.code}: {item.message}" for item in issues) or "no issues"
            failures.append(f"FAIL {path}: expected={expected} observed={observed}; {detail}")
    manifest_issues = validate_manifest_registry(manifest)
    dag_nodes, dag_issues = validate_previous_commit_dag(record_registry)
    if manifest_issues:
        failures.append("FAIL manifest/registry audit: " + "; ".join(f"{item.code}: {item.message}" for item in manifest_issues))
    if dag_issues:
        failures.append("FAIL previous-record DAG audit: " + "; ".join(f"{item.code}: {item.message}" for item in dag_issues))
    print(f"RUNTIME_MANIFEST_REGISTRY pass={0 if manifest_issues else 1} fail={len(manifest_issues)}")
    print(f"RUNTIME_PREVIOUS_RECORD_DAG nodes={dag_nodes} pass={0 if dag_issues else 1} fail={len(dag_issues)}")
    print(
        f"RUNTIME_INTEGRITY_EXTENSION fixtures={len(entries)} pass={passed} "
        f"fail={len(failures)} schemas={len(schemas)}"
    )
    for failure in failures:
        print(failure, file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
