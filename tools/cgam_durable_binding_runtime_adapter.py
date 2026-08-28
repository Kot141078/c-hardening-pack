"""Thin in-memory adapter for the existing Runtime Consequence Integrity validator.

This module validates only the supplied decision-basis, consequence-commit, and
optional non-effect-witness records plus their directly reciprocal links.  It
does not claim complete registered-graph, registered-evidence, or full Runtime
Consequence Integrity validation; those broader checks remain in
``validate_runtime_integrity_extension.py``.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Sequence


def _load_existing_validator() -> Any:
    validator_path = Path(__file__).resolve().with_name(
        "validate_runtime_integrity_extension.py"
    )
    module_name = "_cgam_binding_existing_runtime_integrity_validator"
    spec = importlib.util.spec_from_file_location(module_name, validator_path)
    if spec is None or spec.loader is None:  # pragma: no cover - import machinery
        raise ImportError(f"Cannot load Runtime Consequence Integrity validator: {validator_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_RCI = _load_existing_validator()

DECISION_BASIS_SCHEMA_ID = (
    "urn:ivan-kotov:c-runtime-integrity:decision-basis-record:0.1.1"
)
CONSEQUENCE_COMMIT_SCHEMA_ID = (
    "urn:ivan-kotov:c-runtime-integrity:consequence-commit-record:0.1.1"
)
NON_EFFECT_WITNESS_SCHEMA_ID = (
    "urn:ivan-kotov:c-runtime-integrity:non-effect-witness-record:0.1.1"
)

# Re-export the validator-owned commit claim ceiling without duplicating it.
NOT_BOUND_COMMIT_CLAIM_BOUNDARY = _RCI.NOT_BOUND_COMMIT_CLAIM_BOUNDARY


def witness_claim_boundary() -> str:
    # This mirrors required record data embedded in semantic_non_effect; it is
    # not a copy or alternative implementation of that semantic function.
    return (
        "The conclusion is limited to the declared observation window and "
        "enumerated surfaces. It is not a metaphysical proof that no effect "
        "occurred anywhere outside those surfaces."
    )


WITNESS_CLAIM_BOUNDARY = witness_claim_boundary()


class RuntimeRecordValidationError(ValueError):
    """Structured validation failure preserving every issue code and message."""

    def __init__(self, issues: Sequence[Any]) -> None:
        self.issues = tuple(issues)
        self.details = tuple(
            {"code": item.code, "message": item.message} for item in self.issues
        )
        rendered = "; ".join(
            f"{item.code}: {item.message}" for item in self.issues
        )
        super().__init__(rendered or "runtime record validation failed")

    @property
    def codes(self) -> tuple[str, ...]:
        return tuple(item.code for item in self.issues)


def canonical_bytes(value: Any) -> bytes:
    """Return canonical bytes through the existing validator's JCS profile."""

    return _RCI.jcs_bytes(value)


def canonical_hash(value: Any) -> str:
    """Return the existing validator's full-record canonical SHA-256."""

    return _RCI.jcs_sha256(value)


def canonical_sha256(value: Any) -> str:
    """Explicitly named alias for :func:`canonical_hash`."""

    return canonical_hash(value)


def _validate_record(
    label: str,
    record: Any,
    schema_id: str,
    semantic: Callable[[dict[str, Any]], list[Any]],
    schemas: dict[str, dict[str, Any]],
    registry: Any,
) -> tuple[list[Any], bool]:
    issues: list[Any] = []
    try:
        _RCI.validate_jcs_domain(record)
    except _RCI.JSONDomainError as exc:
        issues.append(_RCI.issue("jcs_domain", f"{label}: {exc}"))
        return issues, False

    schema_issues = _RCI.validate_schema(record, schema_id, schemas, registry)
    issues.extend(schema_issues)
    issues.extend(_RCI.nonblank_string_issues(record))
    schema_succeeded = not any(item.code == "schema" for item in schema_issues)
    if schema_succeeded:
        issues.extend(semantic(record))
    return issues, schema_succeeded


def _record_ref_matches(ref: Any, record: dict[str, Any]) -> bool:
    return bool(
        isinstance(ref, dict)
        and ref.get("artifact_id") == record.get("record_id")
        and ref.get("version") == _RCI.record_version(record)
        and ref.get("hash") == _RCI.jcs_sha256(record)
    )


def validate_runtime_bundle(
    decision_basis: Any,
    consequence_commit: Any,
    non_effect_witness: Any | None = None,
) -> None:
    """Validate the bounded in-memory Runtime Consequence Integrity record set.

    Success returns ``None``.  Any record or reciprocal-link issue raises one
    :class:`RuntimeRecordValidationError` containing all observed issues.
    """

    schemas, registry = _RCI.build_registry()
    issues: list[Any] = []

    decision_issues, decision_schema_ok = _validate_record(
        "decision_basis",
        decision_basis,
        DECISION_BASIS_SCHEMA_ID,
        _RCI.semantic_decision_basis,
        schemas,
        registry,
    )
    commit_issues, commit_schema_ok = _validate_record(
        "consequence_commit",
        consequence_commit,
        CONSEQUENCE_COMMIT_SCHEMA_ID,
        _RCI.semantic_commit,
        schemas,
        registry,
    )
    issues.extend(decision_issues)
    issues.extend(commit_issues)

    witness_schema_ok = False
    if non_effect_witness is not None:
        witness_issues, witness_schema_ok = _validate_record(
            "non_effect_witness",
            non_effect_witness,
            NON_EFFECT_WITNESS_SCHEMA_ID,
            _RCI.semantic_non_effect,
            schemas,
            registry,
        )
        issues.extend(witness_issues)

    if (
        decision_schema_ok
        and commit_schema_ok
        and isinstance(decision_basis, dict)
        and isinstance(consequence_commit, dict)
        and not _record_ref_matches(
            consequence_commit.get("decision_basis_ref"), decision_basis
        )
    ):
        issues.append(_RCI.issue(
            "graph_decision_basis_link_invalid",
            "Consequence commit has an unresolved or hash-mismatched decision-basis reference.",
        ))

    if commit_schema_ok and isinstance(consequence_commit, dict):
        effect_state = consequence_commit.get("effect_state")
        if (
            effect_state == "BOUND"
            and non_effect_witness is not None
            and not any(
                item.code == "non_effect_witness_effect_state_mismatch"
                for item in issues
            )
        ):
            issues.append(_RCI.issue(
                "non_effect_witness_effect_state_mismatch",
                "Only a NOT_BOUND effect state may carry a non-effect witness reference.",
            ))
        elif effect_state == "NOT_BOUND":
            witness_available = witness_schema_ok and isinstance(
                non_effect_witness, dict
            )
            target_effect = consequence_commit.get("target_effect") or {}
            witness_link_invalid = not witness_available
            if witness_available:
                witness_link_invalid = not (
                    _record_ref_matches(
                        consequence_commit.get("non_effect_witness_ref"),
                        non_effect_witness,
                    )
                    and non_effect_witness.get("effect_scope_ref")
                    == target_effect.get("effect_id")
                    and non_effect_witness.get("effect_target_ref")
                    == target_effect.get("target_ref")
                    and non_effect_witness.get("conclusion")
                    == "NO_EFFECT_OBSERVED_WITHIN_DECLARED_SCOPE"
                )
            if witness_link_invalid:
                issues.append(_RCI.issue(
                    "graph_witness_link_invalid",
                    "Consequence commit has no reciprocal strongest scoped non-effect witness bound to the same effect and target.",
                ))
            if witness_available:
                commit_record_id = consequence_commit.get("record_id")
                if not (
                    non_effect_witness.get("attempt_ref") == commit_record_id
                    and non_effect_witness.get("gate_record_ref") == commit_record_id
                ):
                    issues.append(_RCI.issue(
                        "non_effect_witness_attempt_mismatch",
                        "The linked witness attempt_ref and gate_record_ref must both exactly equal the consequence commit record_id.",
                    ))
                issues.extend(
                    _RCI.linked_witness_interval_issues(
                        consequence_commit, non_effect_witness
                    )
                )

    if issues:
        raise RuntimeRecordValidationError(issues)
