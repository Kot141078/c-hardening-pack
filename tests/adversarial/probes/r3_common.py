from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    "runtime_integrity_r3_medium_validator",
    ROOT / "tools" / "validate_runtime_integrity_extension.py",
)
assert spec is not None and spec.loader is not None
validator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validator
spec.loader.exec_module(validator)

schemas, schema_registry = validator.build_registry()
original_load_json = validator.load_json

WITNESS = "fixtures/runtime-integrity/positive/non_effect_witness_valid.json"
COMMIT = "fixtures/runtime-integrity/positive/consequence_commit_denied_valid.json"
RETRY = "fixtures/runtime-integrity/positive/consequence_commit_retry_b_valid.json"
EARTH = "fixtures/runtime-integrity/positive/earth_test_runtime_integrity_valid.json"
EVENT_LOG = "fixtures/runtime-integrity/evidence/non_effect_event_log_42.json"
SCOPE_INVENTORY = "fixtures/runtime-integrity/evidence/non_effect_scope_inventory_42.json"

WITNESS_SCHEMA = "urn:ivan-kotov:c-runtime-integrity:non-effect-witness-record:0.1.1"
COMMIT_SCHEMA = "urn:ivan-kotov:c-runtime-integrity:consequence-commit-record:0.1.1"


class ProbeFailure(RuntimeError):
    pass


def load_root(relative: str) -> Any:
    return copy.deepcopy(original_load_json(ROOT / relative))


def replace_exact(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        return replacements.get(value, value)
    if isinstance(value, list):
        return [replace_exact(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: replace_exact(item, replacements) for key, item in value.items()}
    return value


def contains_exact(value: Any, target: str) -> bool:
    if isinstance(value, str):
        return value == target
    if isinstance(value, list):
        return any(contains_exact(item, target) for item in value)
    if isinstance(value, dict):
        return any(contains_exact(item, target) for item in value.values())
    return False


def pointer_value(value: Any, pointer: str) -> Any:
    current = value
    for raw in pointer.lstrip("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current


def set_pointer(value: Any, pointer: str, replacement: Any) -> None:
    tokens = [raw.replace("~1", "/").replace("~0", "~") for raw in pointer.lstrip("/").split("/")]
    current = value
    for token in tokens[:-1]:
        current = current[int(token)] if isinstance(current, list) else current[token]
    final = tokens[-1]
    if isinstance(current, list):
        current[int(final)] = replacement
    else:
        current[final] = replacement


def exact_documented_mutation(scenario_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    document = load_root(f"tests/adversarial/fixtures/{scenario_id}.json")
    if document.get("scenario_id") != scenario_id:
        raise ProbeFailure("scenario document ID mismatch")
    expected_codes = document.get("expected_issue_codes")
    if expected_codes != [SCENARIOS[scenario_id][0]]:
        raise ProbeFailure("scenario document expected issue mismatch")
    base = load_root(document["base_fixture"])
    negative = load_root(document["runtime_negative_fixture"])
    mutation = document["mutation"]
    if pointer_value(base, mutation["path"]) != mutation["from"]:
        raise ProbeFailure("documented mutation source value drifted")
    transformed = copy.deepcopy(base)
    set_pointer(transformed, mutation["path"], mutation["to"])
    if transformed != negative:
        raise ProbeFailure("runtime negative fixture differs from its positive by more than the documented mutation")
    return document, negative


class GraphCascade:
    def __init__(self) -> None:
        self.manifest = load_root("fixtures/runtime-integrity/MANIFEST.json")
        self.overrides: dict[Path, Any] = {}
        base_witness = load_root(WITNESS)
        base_commit = load_root(COMMIT)
        base_retry = load_root(RETRY)
        base_earth = load_root(EARTH)
        earth_policy = base_earth["later_retry_policy"]
        self.old_witness_hashes = {
            validator.jcs_sha256(base_witness),
            base_commit["non_effect_witness_ref"]["hash"],
        }
        self.old_commit_hashes = {
            validator.jcs_sha256(base_commit),
            base_retry["previous_commit_record_ref"]["hash"],
            earth_policy["old_consequence_commit_hash"],
        }
        self.old_retry_hashes = {
            validator.jcs_sha256(base_retry),
            earth_policy["new_consequence_commit_ref"]["hash"],
        }
        self.new_witness_hash = validator.jcs_sha256(base_witness)
        self.new_commit_hash = validator.jcs_sha256(base_commit)
        self.new_retry_hash = validator.jcs_sha256(base_retry)

    def put(self, relative: str, value: Any) -> None:
        self.overrides[(ROOT / relative).resolve()] = copy.deepcopy(value)

    def current(self, relative: str) -> Any:
        path = (ROOT / relative).resolve()
        if path in self.overrides:
            return copy.deepcopy(self.overrides[path])
        return load_root(relative)

    def patched_load_json(self, path: Path) -> Any:
        resolved = Path(path).resolve()
        if resolved in self.overrides:
            return copy.deepcopy(self.overrides[resolved])
        return copy.deepcopy(original_load_json(path))

    def rebind_evidence(self, relative: str, value: dict[str, Any]) -> str:
        self.put(relative, value)
        digest = validator.jcs_sha256(value)
        matched_registry = False
        for entry in self.manifest["evidence_registry"].values():
            if entry.get("path") == relative:
                entry["hash"] = digest
                matched_registry = True
        matched_inventory = False
        for entry in self.manifest["evidence_artifact_inventory"]:
            if entry.get("path") == relative:
                entry["hash"] = digest
                matched_inventory = True
        if not matched_registry or not matched_inventory:
            raise ProbeFailure(f"evidence path is not fully inventoried: {relative}")
        return digest

    def cascade(
        self,
        *,
        witness: dict[str, Any] | None = None,
        commit: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
        witness = copy.deepcopy(witness if witness is not None else load_root(WITNESS))
        commit = copy.deepcopy(commit if commit is not None else load_root(COMMIT))
        inventory_hash = self.rebind_evidence(SCOPE_INVENTORY, self.current(SCOPE_INVENTORY))
        witness["scope_inventory_hash"] = inventory_hash
        self.put(WITNESS, witness)
        self.new_witness_hash = validator.jcs_sha256(witness)
        commit["non_effect_witness_ref"]["hash"] = self.new_witness_hash
        self.put(COMMIT, commit)
        self.new_commit_hash = validator.jcs_sha256(commit)

        retry_replacements = {
            **{old: self.new_witness_hash for old in self.old_witness_hashes},
            **{old: self.new_commit_hash for old in self.old_commit_hashes},
        }
        retry = replace_exact(load_root(RETRY), retry_replacements)
        self.put(RETRY, retry)
        self.new_retry_hash = validator.jcs_sha256(retry)

        replacements = {
            **{old: self.new_witness_hash for old in self.old_witness_hashes},
            **{old: self.new_commit_hash for old in self.old_commit_hashes},
            **{old: self.new_retry_hash for old in self.old_retry_hashes},
        }
        earth = replace_exact(load_root(EARTH), replacements)
        self.put(EARTH, earth)

        protected_paths = {WITNESS, COMMIT, RETRY, EARTH}
        for entry in self.manifest["fixtures"]:
            relative = "fixtures/runtime-integrity/" + entry["path"]
            if relative in protected_paths:
                continue
            value = load_root(relative)
            rebound = replace_exact(value, replacements)
            if rebound != value:
                self.put(relative, rebound)

        self.verify_hash_cascade()
        return witness, commit, retry, earth

    def verify_hash_cascade(self) -> None:
        witness = self.current(WITNESS)
        commit = self.current(COMMIT)
        retry = self.current(RETRY)
        earth = self.current(EARTH)
        policy = earth["later_retry_policy"]
        checks = (
            commit["non_effect_witness_ref"]["hash"] == validator.jcs_sha256(witness),
            retry["previous_commit_record_ref"]["hash"] == validator.jcs_sha256(commit),
            policy["old_consequence_commit_hash"] == validator.jcs_sha256(commit),
            policy["new_consequence_commit_ref"]["hash"] == validator.jcs_sha256(retry),
        )
        if not all(checks):
            raise ProbeFailure("witness/commit/retry/Earth hash cascade is incomplete")

        changed = {
            **{old: self.new_witness_hash for old in self.old_witness_hashes if old != self.new_witness_hash},
            **{old: self.new_commit_hash for old in self.old_commit_hashes if old != self.new_commit_hash},
            **{old: self.new_retry_hash for old in self.old_retry_hashes if old != self.new_retry_hash},
        }
        for entry in self.manifest["fixtures"]:
            relative = "fixtures/runtime-integrity/" + entry["path"]
            value = self.current(relative)
            stale = [old for old in changed if contains_exact(value, old)]
            if stale:
                raise ProbeFailure(f"stale downstream hash remains in {relative}: {stale}")

        for entry in self.manifest["evidence_artifact_inventory"]:
            relative = entry["path"]
            if (ROOT / relative).resolve() not in self.overrides:
                continue
            actual_hash = validator.jcs_sha256(self.current(relative))
            registry_hashes = {
                candidate["hash"]
                for candidate in self.manifest["evidence_registry"].values()
                if candidate.get("path") == relative
            }
            if entry.get("hash") != actual_hash or registry_hashes != {actual_hash}:
                raise ProbeFailure(f"stale evidence registry or inventory hash: {relative}")

    def patch_loader(self):
        return mock.patch.object(validator, "load_json", side_effect=self.patched_load_json)


def record_codes(
    record: dict[str, Any],
    schema_id: str,
    semantic: Callable[[dict[str, Any]], list[Any]],
    cascade: GraphCascade,
) -> set[str]:
    issues = validator.validate_schema(record, schema_id, schemas, schema_registry)
    issues += validator.nonblank_string_issues(record)
    if not any(item.code == "schema" for item in issues):
        issues += semantic(record)
        issues += validator.validate_registered_links(
            record,
            cascade.manifest["record_registry"],
            schemas,
            schema_registry,
            cascade.manifest["evidence_registry"],
        )
        issues += validator.validate_registered_evidence(
            record,
            cascade.manifest["evidence_registry"],
        )
    return {item.code for item in issues}


def scenario_m01() -> set[str]:
    _, witness = exact_documented_mutation("r3_m01_duplicate_logical_observation_coordinate")
    cascade = GraphCascade()
    duplicate_surface = witness["observation_surfaces"][1]

    event_log = load_root(EVENT_LOG)
    event_matched = False
    for observation in event_log["surface_observations"]:
        if observation.get("surface_id") == duplicate_surface["surface_id"]:
            observation["target_coordinate"] = duplicate_surface["target_coordinate"]
            event_matched = True
    if not event_matched:
        raise ProbeFailure("event log lacks the mutated observation surface")
    cascade.rebind_evidence(EVENT_LOG, event_log)

    inventory = load_root(SCOPE_INVENTORY)
    inventory_matched = False
    for descriptor in inventory["observation_surface_descriptors"]:
        if descriptor.get("surface_id") == duplicate_surface["surface_id"]:
            descriptor["target_coordinate"] = duplicate_surface["target_coordinate"]
            inventory_matched = True
    if not inventory_matched:
        raise ProbeFailure("scope inventory lacks the mutated observation surface")
    witness["scope_inventory_hash"] = cascade.rebind_evidence(SCOPE_INVENTORY, inventory)

    witness, _, _, _ = cascade.cascade(witness=witness)
    with cascade.patch_loader():
        codes = record_codes(witness, WITNESS_SCHEMA, validator.semantic_non_effect, cascade)
    forbidden = {
        "non_effect_event_log_unresolved",
        "non_effect_scope_inventory_unresolved",
        "non_effect_scope_inventory_mismatch",
    }
    if codes & forbidden:
        raise ProbeFailure("duplicate-coordinate probe relied on stale evidence hashes")
    return codes


def scenario_m02() -> set[str]:
    _, witness = exact_documented_mutation("r3_m02_attempt_ref_mismatch")
    cascade = GraphCascade()
    witness, commit, _, _ = cascade.cascade(witness=witness)
    with cascade.patch_loader():
        return record_codes(witness, WITNESS_SCHEMA, validator.semantic_non_effect, cascade) | record_codes(
            commit,
            COMMIT_SCHEMA,
            validator.semantic_commit,
            cascade,
        )


def scenario_m03() -> set[str]:
    _, commit = exact_documented_mutation("r3_m03_not_bound_claim_ceiling")
    cascade = GraphCascade()
    witness, commit, _, _ = cascade.cascade(commit=commit)
    with cascade.patch_loader():
        return record_codes(commit, COMMIT_SCHEMA, validator.semantic_commit, cascade) | record_codes(
            witness,
            WITNESS_SCHEMA,
            validator.semantic_non_effect,
            cascade,
        )


def scenario_m04() -> set[str]:
    _, profile = exact_documented_mutation("r3_m04_carry_cost_identity_smuggling")
    codes = {item.code for item in validator.semantic_carry_cost(profile)}
    if "carry_cost_structure_invalid" in codes or "carry_cost_dimension_map_invalid" in codes:
        raise ProbeFailure("carry-cost probe changed structure or the closed dimension map")
    return codes


SCENARIOS: dict[str, tuple[str, Callable[[], set[str]]]] = {
    "r3_m01_duplicate_logical_observation_coordinate": (
        "duplicate_logical_observation_coordinate",
        scenario_m01,
    ),
    "r3_m02_attempt_ref_mismatch": (
        "non_effect_witness_attempt_mismatch",
        scenario_m02,
    ),
    "r3_m03_not_bound_claim_ceiling": (
        "commit_claim_exceeds_linked_witness_scope",
        scenario_m03,
    ),
    "r3_m04_carry_cost_identity_smuggling": (
        "carry_cost_rule_set_invalid",
        scenario_m04,
    ),
}


def run_scenario(scenario_id: str) -> int:
    expected, probe = SCENARIOS[scenario_id]
    try:
        codes = probe()
    except Exception as exc:
        codes = {"probe_harness_failure"}
        print(f"{scenario_id}: {type(exc).__name__}: {exc}", file=sys.stderr)
        exit_code = 1
    else:
        exit_code = 0 if expected in codes else 1
        if exit_code:
            print(
                f"{scenario_id}: expected issue {expected!r}, observed {sorted(codes)!r}",
                file=sys.stderr,
            )
    observed = "INVALID" if codes else "VALID"
    rendered = ",".join(sorted(codes)) if codes else "none"
    print(f"{scenario_id}|expected=INVALID|observed={observed}|issues={rendered}")
    return exit_code
