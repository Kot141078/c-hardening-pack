#!/usr/bin/env python3
"""Deterministically refresh hash-bound runtime-integrity test artifacts.

This maintenance utility is deliberately scoped to repository-local symbolic
fixtures.  It uses the same RFC 8785 implementation as the validator and does
not read or write any DOI-bound checksum domain.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import jcs


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "fixtures" / "runtime-integrity"
MANIFEST_PATH = FIXTURE_ROOT / "MANIFEST.json"
ZERO_HASH = "0" * 64


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def digest(value: Any) -> str:
    import hashlib

    return hashlib.sha256(bytes(jcs.canonicalize(value))).hexdigest()


def record_version(record: dict[str, Any]) -> str:
    return str(record["schema_version"]).rsplit("-", 1)[-1]


def reference_map_for_evidence(paths: list[Path]) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for path in paths:
        data = read(path)
        if not isinstance(data, dict):
            continue
        version = str(data.get("version", data.get("schema_version", "0.1"))).rsplit("-", 1)[-1]
        value = (version, digest(data))
        if isinstance(data.get("artifact_id"), str):
            result[data["artifact_id"]] = value
        for evidence_id in data.get("evidence_ids", []):
            if isinstance(evidence_id, str):
                result[evidence_id] = value
    return result


def evidence_logical_ids(data: Any) -> list[str]:
    artifact_id = data.get("artifact_id") if isinstance(data, dict) else None
    evidence_ids = data.get("evidence_ids") if isinstance(data, dict) else None
    if isinstance(artifact_id, str) and artifact_id and evidence_ids in (None, []):
        return [artifact_id]
    if (
        isinstance(evidence_ids, list)
        and evidence_ids
        and all(isinstance(value, str) and value for value in evidence_ids)
        and len(evidence_ids) == len(set(evidence_ids))
        and artifact_id is None
    ):
        return list(evidence_ids)
    raise SystemExit("evidence artifact must declare exactly one artifact_id or a unique non-empty evidence_ids array")


def refresh_refs(
    value: Any,
    evidence: dict[str, tuple[str, str]],
    records: dict[str, tuple[str, str]],
) -> bool:
    changed = False
    if isinstance(value, list):
        for item in value:
            changed = refresh_refs(item, evidence, records) or changed
        return changed
    if not isinstance(value, dict):
        return False
    artifact_id = value.get("artifact_id")
    binding = evidence.get(artifact_id) or records.get(artifact_id)
    if isinstance(artifact_id, str) and binding and "hash" in value:
        version, hash_value = binding
        if value.get("version") != version:
            value["version"] = version
            changed = True
        if value.get("hash") != hash_value:
            value["hash"] = hash_value
            changed = True
    uri = value.get("uri")
    if isinstance(uri, str):
        target = (ROOT / uri).resolve()
        try:
            target.relative_to(ROOT.resolve())
        except ValueError:
            target = Path()
        if target.is_file() and "hash" in value:
            actual = digest(read(target))
            if value.get("hash") != actual:
                value["hash"] = actual
                changed = True
        if target.is_file() and "source_hash" in value:
            actual = digest(read(target))
            if value.get("source_hash") != actual:
                value["source_hash"] = actual
                changed = True
    for child in value.values():
        changed = refresh_refs(child, evidence, records) or changed
    return changed


def write_if_changed(path: Path, value: Any) -> None:
    if read(path) != value:
        write(path, value)


def main() -> int:
    manifest = read(MANIFEST_PATH)
    evidence_paths = sorted((FIXTURE_ROOT / "evidence").glob("*.json"))

    # Evidence may contain exact references to other evidence.  The graph is
    # acyclic; a bounded fixed-point makes the dependency ordering explicit.
    for _ in range(12):
        evidence_map = reference_map_for_evidence(evidence_paths)
        changed = False
        for path in evidence_paths:
            data = read(path)
            if refresh_refs(data, evidence_map, {}):
                write(path, data)
                changed = True
        if not changed:
            break
    else:
        raise SystemExit("evidence reference refresh did not converge")
    evidence_map = reference_map_for_evidence(evidence_paths)

    record_map: dict[str, tuple[str, str]] = {}

    def refresh_record(relative: str, *, recompute_basis: bool = False) -> dict[str, Any]:
        path = FIXTURE_ROOT / relative
        data = read(path)
        refresh_refs(data, evidence_map, record_map)
        if recompute_basis:
            data["basis_hash"] = digest(data["basis"])
        if data.get("record_type") == "consequence_commit_record":
            data["current_conditions_hash"] = data["current_conditions_ref"]["hash"]
        write_if_changed(path, data)
        record_map[data["record_id"]] = (record_version(data), digest(data))
        return data

    memory = refresh_record("positive/memory_reliance_valid.json")
    decision = refresh_record("positive/decision_basis_valid.json", recompute_basis=True)
    witness = refresh_record("positive/non_effect_witness_valid.json")
    witness["scope_inventory_hash"] = evidence_map["evidence:scope-inventory-42"][1]
    write_if_changed(FIXTURE_ROOT / "positive/non_effect_witness_valid.json", witness)
    record_map[witness["record_id"]] = (record_version(witness), digest(witness))
    first_commit = refresh_record("positive/consequence_commit_denied_valid.json")
    retry_decision = refresh_record("positive/decision_basis_retry_b_valid.json", recompute_basis=True)
    retry_commit = refresh_record("positive/consequence_commit_retry_b_valid.json")

    # Refresh all existing fixtures without repairing their intentional
    # semantic mutation (for example, an invalid basis_hash stays invalid).
    protected_basis = FIXTURE_ROOT / "negative/decision_basis_hash_invalid.json"
    for folder in (FIXTURE_ROOT / "positive", FIXTURE_ROOT / "negative"):
        for path in sorted(folder.glob("*.json")):
            data = read(path)
            refresh_refs(data, evidence_map, record_map)
            if path != protected_basis and data.get("record_type") == "decision_basis_record" and path.parent.name == "positive":
                data["basis_hash"] = digest(data["basis"])
            write_if_changed(path, data)

    # A future-dated transition artifact supplies an exact-hash-bound negative
    # for temporal authorization of an otherwise structurally valid edge.
    transition_path = FIXTURE_ROOT / "evidence/target_transition_endpoint_b.json"
    future_transition = copy.deepcopy(read(transition_path))
    future_transition["artifact_id"] = "target-transition:earth-42-A-to-B-future"
    future_transition["current_record_id"] = "negative-change-future-transition"
    future_transition["observed_at"] = "2026-08-27T10:07:00+02:00"
    future_path = FIXTURE_ROOT / "evidence/target_transition_endpoint_b_future.json"
    write(future_path, future_transition)
    evidence_paths = sorted((FIXTURE_ROOT / "evidence").glob("*.json"))
    evidence_map = reference_map_for_evidence(evidence_paths)

    # Re-read after the generic refresh so each mutation begins from exactly
    # the current accepted endpoint-B edge.
    retry_commit = read(FIXTURE_ROOT / "positive/consequence_commit_retry_b_valid.json")
    first_commit = read(FIXTURE_ROOT / "positive/consequence_commit_denied_valid.json")
    decision = read(FIXTURE_ROOT / "positive/decision_basis_valid.json")
    cases: dict[str, dict[str, Any]] = {}

    case = copy.deepcopy(retry_commit)
    case["record_id"] = "negative-change-without-new-grant"
    case["permission_grant_ref"] = copy.deepcopy(first_commit["permission_grant_ref"])
    cases["consequence_commit_changed_target_without_new_grant_invalid.json"] = case

    case = copy.deepcopy(retry_commit)
    case["record_id"] = "negative-change-without-new-task"
    case["task_contract_ref"] = copy.deepcopy(first_commit["task_contract_ref"])
    cases["consequence_commit_changed_target_without_new_task_invalid.json"] = case

    case = copy.deepcopy(retry_commit)
    case["record_id"] = "negative-change-missing-transition-evidence"
    case["target_transition_evidence_ref"] = {
        "artifact_id": "target-transition:missing",
        "version": "0.1",
        "hash": ZERO_HASH,
    }
    cases["consequence_commit_missing_transition_evidence_invalid.json"] = case

    case = copy.deepcopy(retry_commit)
    case["record_id"] = "negative-change-unrelated-lineage"
    case["consequence_lineage_id"] = "consequence-lineage:unrelated"
    cases["consequence_commit_unrelated_lineage_invalid.json"] = case

    case = copy.deepcopy(retry_commit)
    case["record_id"] = "negative-change-predecessor-rewritten"
    case["previous_commit_record_ref"]["hash"] = "f" * 64
    cases["consequence_commit_predecessor_rewritten_invalid.json"] = case

    case = copy.deepcopy(retry_commit)
    case["record_id"] = "negative-change-old-target-as-current"
    case["authorized_target_ref"] = "endpoint:A"
    case["task_endpoint_ref"] = "endpoint:A"
    cases["consequence_commit_old_target_as_current_invalid.json"] = case

    case = copy.deepcopy(retry_commit)
    case["record_id"] = "negative-change-old-basis-new-target"
    case["decision_basis_ref"] = {
        "artifact_id": decision["record_id"],
        "version": record_version(decision),
        "hash": digest(decision),
    }
    cases["consequence_commit_old_basis_new_target_invalid.json"] = case

    case = copy.deepcopy(retry_commit)
    case["record_id"] = "negative-change-future-transition"
    case["target_transition_evidence_ref"] = {
        "artifact_id": future_transition["artifact_id"],
        "version": future_transition["version"],
        "hash": digest(future_transition),
    }
    cases["consequence_commit_future_transition_invalid.json"] = case

    for filename, data in cases.items():
        write(FIXTURE_ROOT / "negative" / filename, data)

    # Earth binds both immutable attempts and their exact evidence.
    earth_path = FIXTURE_ROOT / "positive/earth_test_runtime_integrity_valid.json"
    earth = read(earth_path)
    earth["later_retry_policy"].update({
        "old_decision_basis_hash": digest(decision),
        "old_consequence_commit_hash": digest(first_commit),
        "new_decision_basis_ref": {
            "artifact_id": retry_decision["record_id"],
            "version": record_version(retry_decision),
            "hash": digest(retry_decision),
        },
        "new_consequence_commit_ref": {
            "artifact_id": retry_commit["record_id"],
            "version": record_version(retry_commit),
            "hash": digest(retry_commit),
        },
        "new_permission_grant_ref": copy.deepcopy(retry_commit["permission_grant_ref"]),
        "new_task_contract_ref": copy.deepcopy(retry_commit["task_contract_ref"]),
        "target_transition_evidence_ref": copy.deepcopy(retry_commit["target_transition_evidence_ref"]),
    })
    write_if_changed(earth_path, earth)
    earth_negative = copy.deepcopy(earth)
    earth_negative["records"]["consequence_commit"] = "negative/consequence_commit_duplicate_preconditions_invalid.json"
    write(FIXTURE_ROOT / "negative/earth_test_dangling_graph_invalid.json", earth_negative)

    # Passport hashes are canonical JSON or an explicitly named uniform-text
    # checkout projection.  The latter accepts uniform LF or uniform CRLF and
    # hashes the LF projection; mixed line endings, BOM, and bare CR fail.
    passport_path = FIXTURE_ROOT / "evidence/corpus_passport_c_integrity_r0.json"
    passport = read(passport_path)
    import hashlib

    for source in passport["source_artifacts"]:
        path = ROOT / source["path"]
        if source["hash_domain"] == "RFC8785_JCS_SHA256_V1":
            source["sha256"] = digest(read(path))
        elif source["hash_domain"] == "UNIFORM_UTF8_TEXT_TO_LF_SHA256_V1":
            raw = path.read_bytes()
            text = raw.decode("utf-8")
            if raw.startswith(b"\xef\xbb\xbf") or "\r" in text.replace("\r\n", "") or ("\r\n" in text and "\n" in text.replace("\r\n", "")):
                raise SystemExit(f"source violates uniform-text-to-LF profile: {path}")
            source["sha256"] = hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()
        else:
            raise SystemExit(f"unknown passport domain: {source['hash_domain']}")
    write_if_changed(passport_path, passport)

    context_path = ROOT / "review-context/runtime-integrity-r1f.json"
    context = read(context_path)
    context["expected_corpus_passport_ref"]["hash"] = digest(passport)
    write_if_changed(context_path, context)
    context_hash = digest(context)
    passport_hash = digest(passport)
    for path in sorted((FIXTURE_ROOT / "positive").glob("judge*.json")) + sorted((FIXTURE_ROOT / "negative").glob("judge*.json")):
        data = read(path)
        if isinstance(data.get("review_context_ref"), dict):
            data["review_context_ref"]["hash"] = context_hash
        if isinstance(data.get("corpus_passport_ref"), dict):
            data["corpus_passport_ref"]["hash"] = passport_hash
        write_if_changed(path, data)

    manifest = read(MANIFEST_PATH)
    manifest["evidence_registry"][future_transition["artifact_id"]] = {
        "path": future_path.relative_to(ROOT).as_posix(),
        "hash": digest(future_transition),
    }
    for evidence_id, entry in manifest["evidence_registry"].items():
        entry["hash"] = digest(read(ROOT / entry["path"]))
    manifest["evidence_artifact_inventory"] = []
    for path in sorted((FIXTURE_ROOT / "evidence").glob("*.json")):
        data = read(path)
        manifest["evidence_artifact_inventory"].append({
            "path": path.relative_to(ROOT).as_posix(),
            "hash": digest(data),
            "logical_ids": evidence_logical_ids(data),
        })
    write(MANIFEST_PATH, manifest)
    print(f"review_context_sha256={context_hash}")
    print(f"passport_sha256={passport_hash}")
    print(f"evidence_entries={len(manifest['evidence_registry'])}")
    print(f"evidence_artifacts={len(manifest['evidence_artifact_inventory'])}")
    print(f"record_entries={len(manifest['record_registry'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
