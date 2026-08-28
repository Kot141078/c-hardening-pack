#!/usr/bin/env python3
"""Deterministic R4A lineage, union, normalization, and scope verifier."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN = "9a33e3866cde19939be22a903967bc94f566db76"
CHECKSUM = "ae31f55dface08d8faa384c2d15e3cfcefdcff96"
RUNTIME = "2bbd2d6c9a4634f3ba0128a34706ea936873397d"
FAILED_R2 = "362eca8d0989c20ff876a61d979433bc576a1378"
ABANDONED_R4 = "7c440424b7ea864e07e8f875e82fb35634d942f1"
EXPECTED_UNION_TREE = "bdba64c55328aa2101c2a38d48d0a0a2eca60ad6"
CHECKSUM_MERGE = "ea393a2d5cb5f70afb29ec55bd09897b11d3bf54"
RUNTIME_MERGE = "010a26f9ee19ebd8589bfb7baeed6f8538a8ae82"
NORMALIZATION_COMMIT = "248626a948a77d2e629086106b86711cbaa9d713"
NORMALIZATION_PATH = "docs/External_Construct_Intake_Boundary_v0_1.md"
PREIMAGE_BLOB = "21c469b2a2d08d644769d0ea0abdeb7b673b1df8"
POSTIMAGE_BLOB = "b87a696978b570665ce603102300cea924c183bc"
PREIMAGE_SHA256 = "3c2462af0049d801ea7e07519f2e2ed9d5377e33c4f72c1bd2d7476b825f55fe"
POSTIMAGE_SHA256 = "1e4a2d70802e66621a142b845eb9a355ac44a94e7792885fa34ba628f4e11d4c"
EXPECTED_PATCH_SHA256 = "1fae3efa86292f3e0ab578d5aa1667785143f423b8438fc64c6d12079c2f22fb"
R4A_FINAL = "47fed105d7b1df1df7375aa203a551b0f684c13d"
MANIFESTS = ("SHA256SUMS.txt", "manifests/SHA256SUMS.txt")
WORKFLOWS = (
    ".github/workflows/integrity.yml",
    ".github/workflows/runtime-integrity-extension.yml",
)
HARDENING_ALLOWLIST = {
    ".github/workflows/integrity.yml",
    ".github/workflows/runtime-integrity-extension.yml",
    "tools/verify_github_actions_pins.py",
    "tests/test_runtime_integrity_r2_closure.py",
    "RUNTIME_INTEGRITY_R4A_STATUS.md",
    "tools/verify_r4a_integration.py",
    "tests/test_runtime_integrity_r4a_integration.py",
}
NEW_INTEGRATION_PATHS = {
    "RUNTIME_INTEGRITY_R4A_STATUS.md",
    "tools/verify_r4a_integration.py",
    "tests/test_runtime_integrity_r4a_integration.py",
}
R6A_REQUIRED_MODIFICATIONS = {
    "tools/verify_github_actions_pins.py",
    "tools/verify_r4a_integration.py",
    "tests/test_runtime_integrity_r2_closure.py",
    "tests/test_runtime_integrity_r4a_integration.py",
}
R6A_REQUIRED_ADDITIONS = {
    ".github/workflows/cgam-durable-binding.yml",
    "docs/CGAM_DURABLE_BINDING_R6A_STATUS.md",
    "fixtures/cgam-durable-binding/MANIFEST.json",
    "fixtures/cgam-durable-binding/r6a_authority_revision_1_active.json",
    "fixtures/cgam-durable-binding/r6a_authority_revision_2_revoked.json",
    "fixtures/cgam-durable-binding/r6a_task_output.json",
    "schemas/cgam-durable-binding/r6a-cgam-authority-envelope-0.1.schema.json",
    "tests/r6a_scenario_registry.py",
    "tests/test_cgam_durable_binding.py",
    "tests/test_cgam_durable_binding_crash.py",
    "tests/test_cgam_durable_binding_runtime_adapter.py",
    "tests/test_cgam_durable_binding_security.py",
    "tests/test_verify_cgam_durable_binding_source.py",
    "tools/cgam_durable_binding.py",
    "tools/cgam_durable_binding_runtime_adapter.py",
    "tools/run_cgam_durable_binding_suite.py",
    "tools/verify_cgam_durable_binding_source.py",
}
OLD_STATUS = b"**Status:** Development governance note  \n"
NEW_STATUS = b"**Status:** Development governance note\\\n"
OLD_DATE = b"**Date:** 2026-08-27  \n"
NEW_DATE = b"**Date:** 2026-08-27\\\n"


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, check=check
    )


def text(*args: str) -> str:
    return git(*args).stdout.decode("utf-8").strip()


def raw(*args: str) -> bytes:
    return git(*args).stdout


def object_exists(ref: str) -> bool:
    return git("cat-file", "-e", ref, check=False).returncode == 0


def is_ancestor(ancestor: str, descendant: str = "HEAD") -> bool:
    if not object_exists(ancestor):
        return False
    return git("merge-base", "--is-ancestor", ancestor, descendant, check=False).returncode == 0


def parents(ref: str) -> list[str]:
    value = text("show", "-s", "--format=%P", ref)
    return value.split() if value else []


def tree(ref: str) -> str:
    return text("show", "-s", "--format=%T", ref)


def changed(base: str, head: str, *, diff_filter: str | None = None) -> set[str]:
    args = ["diff", "--name-only", "-z"]
    if diff_filter is not None:
        args.append(f"--diff-filter={diff_filter}")
    args.append(f"{base}..{head}")
    return {
        item.decode("utf-8")
        for item in raw(*args).split(b"\0")
        if item
    }


def blob(ref: str, path: str) -> str:
    return text("rev-parse", f"{ref}:{path}")


def r6a_additive_path(path: str) -> bool:
    return path.replace("\\", "/") in R6A_REQUIRED_ADDITIONS


def protected_paths() -> set[str]:
    result = set(MANIFESTS)
    for manifest in MANIFESTS:
        for line in raw("show", f"{MAIN}:{manifest}").decode("utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, path = line.split(maxsplit=1)
            if len(digest) != 64:
                raise ValueError(f"malformed protected manifest entry in {manifest}")
            result.add(path.lstrip("*"))
    return result


def normalization_evidence() -> dict[str, object]:
    pre = raw("cat-file", "blob", PREIMAGE_BLOB)
    post = raw("cat-file", "blob", POSTIMAGE_BLOB)
    expected = pre.replace(OLD_STATUS, NEW_STATUS).replace(OLD_DATE, NEW_DATE)
    patch = raw(
        "diff", "--no-ext-diff", "--binary", RUNTIME_MERGE, NORMALIZATION_COMMIT,
        "--", NORMALIZATION_PATH,
    )
    return {
        "preimage_bytes": len(pre),
        "postimage_bytes": len(post),
        "preimage_sha256": hashlib.sha256(pre).hexdigest(),
        "postimage_sha256": hashlib.sha256(post).hexdigest(),
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "only_authorized_substitutions": post == expected,
        "lf_only": b"\r" not in post,
        "no_bom": not post.startswith(b"\xef\xbb\xbf"),
        "final_lf": post.endswith(b"\n"),
    }


def audit(*, check_worktree: bool = True) -> tuple[list[str], dict[str, object]]:
    issues: list[str] = []
    candidate_head = text("rev-parse", "HEAD")
    candidate_tree = tree("HEAD")
    if not object_exists(R4A_FINAL) or not is_ancestor(R4A_FINAL, candidate_head):
        issues.append("r4a_final_not_candidate_ancestor")
        head = candidate_head
    else:
        # Audit the immutable R4A result at its exact accepted commit.  A
        # descendant candidate is checked separately below; its additive files
        # cannot redefine the historical R4A topology or union.
        head = R4A_FINAL
    head_tree = tree(head)
    checksum_paths = changed(MAIN, CHECKSUM)
    runtime_paths = changed(MAIN, RUNTIME)
    union = checksum_paths | runtime_paths
    mechanical_paths = changed(MAIN, RUNTIME_MERGE)
    hardening_paths = changed(NORMALIZATION_COMMIT, head)
    final_paths = changed(MAIN, head)
    protected = protected_paths()
    normalization = normalization_evidence()

    if parents(CHECKSUM_MERGE) != [MAIN, CHECKSUM]:
        issues.append("r4a_checksum_merge_order_invalid")
    if parents(RUNTIME_MERGE) != [CHECKSUM_MERGE, RUNTIME]:
        issues.append("r4a_runtime_merge_order_invalid")
    if parents(NORMALIZATION_COMMIT) != [RUNTIME_MERGE]:
        issues.append("r4a_normalization_parent_invalid")
    if parents(head) != [NORMALIZATION_COMMIT]:
        issues.append("r4a_hardening_commit_topology_invalid")
    if not is_ancestor(CHECKSUM, head):
        issues.append("r4a_checksum_component_not_ancestor")
    if not is_ancestor(RUNTIME, head):
        issues.append("r4a_runtime_component_not_ancestor")
    if is_ancestor(FAILED_R2, head):
        issues.append("r4a_failed_r2_is_ancestor")
    if is_ancestor(ABANDONED_R4, head):
        issues.append("r4a_abandoned_r4_is_ancestor")

    if len(checksum_paths) != 5 or len(runtime_paths) != 138:
        issues.append("r4a_component_path_count_invalid")
    if checksum_paths & runtime_paths:
        issues.append("r4a_component_scope_intersection_nonzero")
    if len(union) != 143 or mechanical_paths != union:
        issues.append("r4a_mechanical_union_path_mismatch")
    if tree(RUNTIME_MERGE) != EXPECTED_UNION_TREE:
        issues.append("r4a_mechanical_union_tree_mismatch")
    if changed(RUNTIME_MERGE, NORMALIZATION_COMMIT) != {NORMALIZATION_PATH}:
        issues.append("r4a_normalization_scope_invalid")
    if blob(RUNTIME_MERGE, NORMALIZATION_PATH) != PREIMAGE_BLOB:
        issues.append("r4a_normalization_preimage_invalid")
    if blob(NORMALIZATION_COMMIT, NORMALIZATION_PATH) != POSTIMAGE_BLOB:
        issues.append("r4a_normalization_postimage_invalid")
    if normalization != {
        "preimage_bytes": 3984,
        "postimage_bytes": 3982,
        "preimage_sha256": PREIMAGE_SHA256,
        "postimage_sha256": POSTIMAGE_SHA256,
        "patch_sha256": EXPECTED_PATCH_SHA256,
        "only_authorized_substitutions": True,
        "lf_only": True,
        "no_bom": True,
        "final_lf": True,
    }:
        issues.append("r4a_normalization_bytes_invalid")

    if not hardening_paths or not hardening_paths <= HARDENING_ALLOWLIST:
        issues.append("r4a_hardening_allowlist_invalid")
    if not NEW_INTEGRATION_PATHS <= hardening_paths:
        issues.append("r4a_integration_evidence_missing")
    if final_paths != union | NEW_INTEGRATION_PATHS:
        issues.append("r4a_final_union_delta_invalid")
    if changed(MAIN, head, diff_filter="D"):
        issues.append("r4a_deletion_detected")

    candidate_paths = changed(R4A_FINAL, candidate_head) if head == R4A_FINAL else set()
    candidate_added = (
        changed(R4A_FINAL, candidate_head, diff_filter="A") if head == R4A_FINAL else set()
    )
    candidate_modified = candidate_paths - candidate_added
    expected_modifications = set() if candidate_head == R4A_FINAL else R6A_REQUIRED_MODIFICATIONS
    if candidate_modified != expected_modifications:
        issues.append("r6a_predecessor_modification_scope_invalid")
    expected_additions = set() if candidate_head == R4A_FINAL else R6A_REQUIRED_ADDITIONS
    unexpected_candidate_additions = sorted(candidate_added - expected_additions)
    missing_candidate_additions = sorted(expected_additions - candidate_added)
    if candidate_added != expected_additions:
        issues.append("r6a_additive_scope_invalid")
    candidate_deletions = (
        changed(R4A_FINAL, candidate_head, diff_filter="D") if head == R4A_FINAL else set()
    )
    if candidate_deletions:
        issues.append("r6a_deletion_detected")
    candidate_protected_mismatches = [
        path for path in sorted(protected)
        if blob(candidate_head, path) != blob(R4A_FINAL, path)
    ] if head == R4A_FINAL else []
    if candidate_protected_mismatches:
        issues.append("r6a_protected_blob_mismatch")

    component_blob_mismatches: list[str] = []
    for path in sorted(checksum_paths - HARDENING_ALLOWLIST):
        if blob(head, path) != blob(CHECKSUM, path):
            component_blob_mismatches.append(f"checksum:{path}")
    runtime_exceptions = HARDENING_ALLOWLIST | {NORMALIZATION_PATH}
    for path in sorted(runtime_paths - runtime_exceptions):
        if blob(head, path) != blob(RUNTIME, path):
            component_blob_mismatches.append(f"runtime:{path}")
    if component_blob_mismatches:
        issues.append("r4a_component_blob_fidelity_invalid")

    protected_mismatches = [
        path for path in sorted(protected) if blob(head, path) != blob(MAIN, path)
    ]
    if len(protected) != 39 or protected_mismatches:
        issues.append("r4a_protected_blob_mismatch")

    diff_check = git("diff", "--check", f"{MAIN}..{head}", check=False)
    if diff_check.returncode != 0 or diff_check.stdout or diff_check.stderr:
        issues.append("r4a_diff_check_failed")
    candidate_diff_check = git(
        "diff", "--check", f"{R4A_FINAL}..{candidate_head}", check=False
    )
    if (
        candidate_diff_check.returncode != 0
        or candidate_diff_check.stdout
        or candidate_diff_check.stderr
    ):
        issues.append("r6a_diff_check_failed")

    workflow_text = {
        path: (ROOT / path).read_text(encoding="utf-8") for path in WORKFLOWS
    }
    if not all(
        "github.event.pull_request.head.sha || github.sha" in value
        and (
            "git rev-parse" in value
            or "'git','rev-parse'" in value
            or '"git","rev-parse"' in value
        )
        for value in workflow_text.values()
    ):
        issues.append("r4a_exact_head_assertion_missing")

    status_text = (ROOT / "RUNTIME_INTEGRITY_R4A_STATUS.md").read_text(encoding="utf-8")
    if not all(
        marker in status_text
        for marker in (
            "FINAL_HEAD := the Git commit whose tree contains this exact status artifact",
            "FINAL_TREE := the tree object directly referenced by FINAL_HEAD",
            "LOW 8 / INFORMATIONAL 12",
        )
    ) or "owner review is still required" not in status_text.casefold():
        issues.append("r4a_status_identity_or_boundary_missing")
    if blob(head, "RUNTIME_INTEGRITY_R4A_STATUS.md") != text(
        "hash-object", "RUNTIME_INTEGRITY_R4A_STATUS.md"
    ):
        issues.append("r4a_status_not_bound_to_final_tree")

    caches = sorted(
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.name == "__pycache__"
        or path.name == ".pytest_cache"
        or path.suffix in {".pyc", ".pyo"}
    )
    if caches:
        issues.append("r4a_bytecode_or_cache_artifact_present")
    status = text("status", "--porcelain=v1") if check_worktree else ""
    if check_worktree and status:
        issues.append("r4a_worktree_dirty")

    evidence: dict[str, object] = {
        "head": candidate_head,
        "tree": candidate_tree,
        "r4a_audited_head": head,
        "r4a_audited_tree": head_tree,
        "checksum_ancestor": is_ancestor(CHECKSUM, head),
        "runtime_ancestor": is_ancestor(RUNTIME, head),
        "failed_r2_nonancestor": not is_ancestor(FAILED_R2, head),
        "abandoned_r4_nonancestor": not is_ancestor(ABANDONED_R4, head),
        "checksum_paths": len(checksum_paths),
        "runtime_paths": len(runtime_paths),
        "intersection": len(checksum_paths & runtime_paths),
        "union_paths": len(union),
        "mechanical_union_tree": tree(RUNTIME_MERGE),
        "hardening_paths": sorted(hardening_paths),
        "protected": len(protected),
        "protected_mismatches": protected_mismatches,
        "component_blob_mismatches": component_blob_mismatches,
        "deletions": len(changed(MAIN, head, diff_filter="D")),
        "candidate_paths": sorted(candidate_paths),
        "candidate_added_paths": sorted(candidate_added),
        "candidate_modified_paths": sorted(candidate_modified),
        "candidate_deletions": sorted(candidate_deletions),
        "candidate_protected_mismatches": candidate_protected_mismatches,
        "unexpected_candidate_additions": unexpected_candidate_additions,
        "missing_candidate_additions": missing_candidate_additions,
        "normalization": normalization,
        "diff_check_exit": diff_check.returncode,
        "diff_check_stdout_bytes": len(diff_check.stdout),
        "diff_check_stderr_bytes": len(diff_check.stderr),
        "candidate_diff_check_exit": candidate_diff_check.returncode,
        "cache_artifacts": caches,
        "worktree_status": status,
        "event_expected_head": os.environ.get("EXPECTED_EVENT_HEAD") or os.environ.get("EXPECTED_HEAD"),
    }
    expected_event_head = evidence["event_expected_head"]
    if expected_event_head is not None and expected_event_head != candidate_head:
        issues.append("r4a_event_head_mismatch")
    return issues, evidence


def main() -> int:
    issues, evidence = audit()
    for issue in issues:
        print(issue)
    print(json.dumps(evidence, sort_keys=True))
    print(
        "R4A_INTEGRATION "
        f"head={evidence['head']} tree={evidence['tree']} "
        f"union={evidence['union_paths']}/143 protected={evidence['protected']}/39 "
        f"pass={int(not issues)} fail={len(issues)}"
    )
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
