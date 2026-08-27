
from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = ROOT / "fixtures" / "runtime-integrity"
MUTATION_PATH = (
    ROOT
    / "tests"
    / "adversarial"
    / "fixtures"
    / "r2_c1_non_effect_witness_interval_excludes_attempt.json"
)


def load_validator():
    module_name = "runtime_integrity_r2_interval_probe_validator"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(
        module_name,
        ROOT / "tools" / "validate_runtime_integrity_extension.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def evaluate_window(
    window: dict[str, str],
    attempt_time: str | None = None,
) -> set[str]:
    validator = load_validator()
    schemas, schema_registry = validator.build_registry()
    manifest = copy.deepcopy(validator.load_json(FIXTURE_ROOT / "MANIFEST.json"))
    original_load_json = validator.load_json
    mutation = json.loads(MUTATION_PATH.read_text(encoding="utf-8"))
    commit_path = FIXTURE_ROOT / mutation["commit_fixture"]
    witness_path = FIXTURE_ROOT / mutation["witness_fixture"]
    commit = original_load_json(commit_path)
    witness = original_load_json(witness_path)
    if attempt_time is not None:
        commit["created_at"] = attempt_time
        commit["permission_checked_at"] = attempt_time
        commit["task_contract_checked_at"] = attempt_time
    witness["observation_window"] = copy.deepcopy(window)
    overrides: dict[Path, object] = {}

    for relative in (
        "fixtures/runtime-integrity/evidence/non_effect_clock_42.json",
        "fixtures/runtime-integrity/evidence/non_effect_collector_42.json",
        "fixtures/runtime-integrity/evidence/non_effect_event_log_42.json",
        "fixtures/runtime-integrity/evidence/non_effect_routes_42.json",
    ):
        path = ROOT / relative
        artifact = original_load_json(path)
        artifact["correlation_window" if "clock" in relative else "window"] = copy.deepcopy(window)
        overrides[path.resolve()] = artifact
        artifact_hash = validator.jcs_sha256(artifact)
        for entry in manifest["evidence_registry"].values():
            if entry.get("path") == relative:
                entry["hash"] = artifact_hash

    overrides[witness_path.resolve()] = witness
    commit["non_effect_witness_ref"]["hash"] = validator.jcs_sha256(witness)
    overrides[commit_path.resolve()] = commit

    def patched_load_json(path: Path):
        resolved = Path(path).resolve()
        if resolved in overrides:
            return copy.deepcopy(overrides[resolved])
        return original_load_json(path)

    issues = []
    with mock.patch.object(validator, "load_json", side_effect=patched_load_json):
        for record, schema_id, semantic in (
            (
                commit,
                "urn:ivan-kotov:c-runtime-integrity:consequence-commit-record:0.1.1",
                validator.semantic_commit,
            ),
            (
                witness,
                "urn:ivan-kotov:c-runtime-integrity:non-effect-witness-record:0.1.1",
                validator.semantic_non_effect,
            ),
        ):
            issues.extend(validator.validate_schema(record, schema_id, schemas, schema_registry))
            issues.extend(validator.nonblank_string_issues(record))
            issues.extend(semantic(record))
            issues.extend(
                validator.validate_registered_links(
                    record,
                    manifest["record_registry"],
                    schemas,
                    schema_registry,
                    manifest["evidence_registry"],
                )
            )
            issues.extend(
                validator.validate_registered_evidence(
                    record,
                    manifest["evidence_registry"],
                )
            )
    return {item.code for item in issues}


def main() -> int:
    mutation = json.loads(MUTATION_PATH.read_text(encoding="utf-8"))
    codes = evaluate_window(mutation["observation_window"])
    required = set(mutation["expected_issue_codes"])
    valid = not codes
    matched = required.issubset(codes) and valid is mutation["expected_valid"]
    observed = "VALID" if valid else "INVALID"
    issues = "none" if not codes else ",".join(sorted(codes))
    print(
        f"{mutation['scenario_id']}|expected=INVALID|observed={observed}|issues={issues}"
    )
    return 0 if matched else 1


if __name__ == "__main__":
    raise SystemExit(main())
