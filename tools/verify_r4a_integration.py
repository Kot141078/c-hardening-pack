#!/usr/bin/env python3
"""Deterministic R4A lineage, union, normalization, and bounded descendant verifier."""

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

AGENTS_R0_CONTENT_COMMIT = "d9934d0ddc6b24a41a12d379cfd42a9d76a23e1c"
AGENTS_R0_PATH = "AGENTS.md"
AGENTS_R0_BLOB = "460060bb9f706c1b27a03fd93406e635d90ded35"
AGENTS_R0_SHA256 = "75ea2b206c5c09349d30f6d6fbfe8a7132a7b8843630aa05d7055d10434e3353"
AGENTS_R0_REQUIRED_ADDITIONS = {AGENTS_R0_PATH}
AGENTS_R0_REQUIRED_MODIFICATIONS = {
    "tools/verify_r4a_integration.py",
    "tests/test_runtime_integrity_r4a_integration.py",
}
AGENTS_R0_REQUIRED_MARKERS = (
    "# Repository Guidelines",
    "model, agent, or validator != `c`",
    "capability or permission != current authority",
    "local resource envelope != full L4",
    "signature or hash != truth",
    "replay, restart, or durable bytes != continuity",
    "Passing tests do not authorize merge, release, publication, deployment, or the next gate.",
)

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
    return git(
        "merge-base", "--is-ancestor", ancestor, descendant, check=False
    ).returncode == 0


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


def merge_commits(base: str, head: str) -> list[str]:
    value = text("rev-list", "--min-parents=2", f"{base}..{head}")
    return value.splitlines() if value else []


def validate_agents_r0_scope(
    *,
    candidate_is_r4a_final: bool,
    added: set[str],
    modified: set[str],
    deleted: set[str],
    unclassified: set[str],
) -> list[str]:
    issues: list[str] = []
    expected_added = set() if candidate_is_r4a_final else AGENTS_R0_REQUIRED_ADDITIONS
    expected_modified = (
        set() if candidate_is_r4a_final else AGENTS_R0_REQUIRED_MODIFICATIONS
    )
    if added != expected_added:
        issues.append("agents_r0_additive_scope_invalid")
    if modified != expected_modified:
        issues.append("agents_r0_modification_scope_invalid")
    if deleted:
        issues.append("agents_r0_deletion_detected")
    if unclassified:
        issues.append("agents_r0_unclassified_delta_detected")
    return issues


def agents_r0_evidence(ref: str) -> dict[str, object]:
    result: dict[str, object] = {
        "present": False,
        "blob": None,
        "sha256": None,
        "bytes": 0,
        "word_count": 0,
        "utf8": False,
        "lf_only": False,
        "no_bom": False,
        "final_lf": False,
        "required_markers_present": False,
    }
    object_ref = f"{ref}:{AGENTS_R0_PATH}"
    if not object_exists(object_ref):
        return result

    data = raw("show", object_ref)
    result.update(
        {
            "present": True,
            "blob": blob(ref, AGENTS_R0_PATH),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "lf_only": b"\r" not in data,
            "no_bom": not data.startswith(b"\xef\xbb\xbf"),
            "final_lf": data.endswith(b"\n"),
        }
    )
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return result
    result["utf8"] = True
    result["word_count"] = len(decoded.split())
    result["required_markers_present"] = all(
        marker in decoded for marker in AGENTS_R0_REQUIRED_MARKERS
    )
    return result


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
    candidate_descends_from_r4a = (
        object_exists(R4A_FINAL) and is_ancestor(R4A_FINAL, candidate_head)
    )
    if not candidate_descends_from_r4a:
        issues.append("r4a_final_not_candidate_ancestor")
        head = candidate_head
    else:
        # Audit the immutable R4A result at its exact accepted commit. The
        # descendant documentation candidate is checked separately below and
        # cannot redefine the historical R4A topology, union, or protected set.
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

    candidate_paths = (
        changed(R4A_FINAL, candidate_head) if candidate_descends_from_r4a else set()
    )
    candidate_added = (
        changed(R4A_FINAL, candidate_head, diff_filter="A")
        if candidate_descends_from_r4a
        else set()
    )
    candidate_modified = (
        changed(R4A_FINAL, candidate_head, diff_filter="M")
        if candidate_descends_from_r4a
        else set()
    )
    candidate_deletions = (
        changed(R4A_FINAL, candidate_head, diff_filter="D")
        if candidate_descends_from_r4a
        else set()
    )
    candidate_unclassified = (
        candidate_paths
        - candidate_added
        - candidate_modified
        - candidate_deletions
    )
    issues.extend(
        validate_agents_r0_scope(
            candidate_is_r4a_final=candidate_head == R4A_FINAL,
            added=candidate_added,
            modified=candidate_modified,
            deleted=candidate_deletions,
            unclassified=candidate_unclassified,
        )
    )

    agents_content_commit_exists = object_exists(AGENTS_R0_CONTENT_COMMIT)
    agents_content_commit_ancestor = (
        agents_content_commit_exists
        and is_ancestor(AGENTS_R0_CONTENT_COMMIT, candidate_head)
    )
    agents_content_commit_parent_ok = (
        agents_content_commit_exists
        and parents(AGENTS_R0_CONTENT_COMMIT) == [R4A_FINAL]
    )
    agents_content_commit_scope_ok = (
        agents_content_commit_exists
        and changed(R4A_FINAL, AGENTS_R0_CONTENT_COMMIT) == {AGENTS_R0_PATH}
        and changed(
            R4A_FINAL, AGENTS_R0_CONTENT_COMMIT, diff_filter="A"
        ) == {AGENTS_R0_PATH}
    )
    candidate_merge_commits = (
        merge_commits(AGENTS_R0_CONTENT_COMMIT, candidate_head)
        if agents_content_commit_ancestor
        else []
    )
    agents_evidence = agents_r0_evidence(candidate_head)

    if candidate_head != R4A_FINAL:
        if not agents_content_commit_ancestor:
            issues.append("agents_r0_content_commit_not_ancestor")
        if not agents_content_commit_parent_ok:
            issues.append("agents_r0_content_commit_parent_invalid")
        if not agents_content_commit_scope_ok:
            issues.append("agents_r0_content_commit_scope_invalid")
        if candidate_merge_commits:
            issues.append("agents_r0_descendant_merge_detected")
        if not agents_evidence["present"]:
            issues.append("agents_r0_file_missing")
        if agents_evidence["blob"] != AGENTS_R0_BLOB:
            issues.append("agents_r0_blob_mismatch")
        if agents_evidence["sha256"] != AGENTS_R0_SHA256:
            issues.append("agents_r0_sha256_mismatch")
        if not (
            agents_evidence["utf8"]
            and agents_evidence["lf_only"]
            and agents_evidence["no_bom"]
            and agents_evidence["final_lf"]
        ):
            issues.append("agents_r0_text_encoding_invalid")
        if not 200 <= int(agents_evidence["word_count"]) <= 400:
            issues.append("agents_r0_word_count_out_of_bounds")
        if not agents_evidence["required_markers_present"]:
            issues.append("agents_r0_required_markers_missing")

    candidate_protected_mismatches = (
        [
            path
            for path in sorted(protected)
            if blob(candidate_head, path) != blob(R4A_FINAL, path)
        ]
        if candidate_descends_from_r4a
        else []
    )
    if candidate_protected_mismatches:
        issues.append("agents_r0_protected_blob_mismatch")

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
        issues.append("agents_r0_diff_check_failed")

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

    status_text = (ROOT / "RUNTIME_INTEGRITY_R4A_STATUS.md").read_text(
        encoding="utf-8"
    )
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

    candidate_commit_count = (
        int(text("rev-list", "--count", f"{R4A_FINAL}..{candidate_head}") or "0")
        if candidate_descends_from_r4a
        else 0
    )
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
        "candidate_commit_count": candidate_commit_count,
        "candidate_paths": sorted(candidate_paths),
        "candidate_added_paths": sorted(candidate_added),
        "candidate_modified_paths": sorted(candidate_modified),
        "candidate_deletions": sorted(candidate_deletions),
        "candidate_unclassified_paths": sorted(candidate_unclassified),
        "candidate_merge_commits": candidate_merge_commits,
        "candidate_protected_mismatches": candidate_protected_mismatches,
        "agents_r0_content_commit_ancestor": agents_content_commit_ancestor,
        "agents_r0_content_commit_parent_ok": agents_content_commit_parent_ok,
        "agents_r0_content_commit_scope_ok": agents_content_commit_scope_ok,
        "agents_r0": agents_evidence,
        "normalization": normalization,
        "diff_check_exit": diff_check.returncode,
        "diff_check_stdout_bytes": len(diff_check.stdout),
        "diff_check_stderr_bytes": len(diff_check.stderr),
        "candidate_diff_check_exit": candidate_diff_check.returncode,
        "candidate_diff_check_stdout_bytes": len(candidate_diff_check.stdout),
        "candidate_diff_check_stderr_bytes": len(candidate_diff_check.stderr),
        "cache_artifacts": caches,
        "worktree_status": status,
        "event_expected_head": (
            os.environ.get("EXPECTED_EVENT_HEAD") or os.environ.get("EXPECTED_HEAD")
        ),
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
        f"r4a={evidence['r4a_audited_head']} "
        f"union={evidence['union_paths']}/143 protected={evidence['protected']}/39 "
        f"candidate_paths={len(evidence['candidate_paths'])} "
        f"pass={int(not issues)} fail={len(issues)}"
    )
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
