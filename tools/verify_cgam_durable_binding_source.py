#!/usr/bin/env python3
"""Fail-closed source-custody audit for the bounded R6A local binding.

This verifier binds the candidate to the exact c-hardening-pack predecessor and
to the detached, clean CGAM source freeze.  It also enforces the additive R6A
source boundary and a small set of statically auditable architecture limits.
It does not claim runtime correctness or CGAM conformance.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]

IMPLEMENTATION_BASE_COMMIT = "47fed105d7b1df1df7375aa203a551b0f684c13d"
IMPLEMENTATION_BASE_TREE = "f1162ca73c508d1cd82544265f93ce5242c2aecb"
CGAM_COMMIT = "c3b004d7439a8c608f08233fc17be1150c442b44"
CGAM_TREE = "9a0b25d162f40347a4434b2bc9482b92e0170e85"
CGAM_REMOTE = "https://github.com/Kot141078/c-governed-cli-agent-mesh.git"

# Values are (Git blob object id, SHA-256 of the exact Git blob bytes).
IMPLEMENTATION_SOURCE_PINS: dict[str, tuple[str, str]] = {
    "schemas/runtime-integrity/runtime-integrity-common-defs-0.1.1.schema.json": (
        "73059f194727c722e65147cefd6466fd24ca7df5",
        "1b6a4ebebfa74132e8324c900261e8e811c5418de9f5c2da2544c718cc53a26c",
    ),
    "schemas/runtime-integrity/c-decision-basis-record-0.1.1.schema.json": (
        "2e03841e970c77819e98a205ff2787287256204a",
        "8499ee84344db0bfae3f75409a994135eec2895676a9c298c6cb1ab32fd57ad1",
    ),
    "schemas/runtime-integrity/c-consequence-commit-record-0.1.1.schema.json": (
        "a0bd51c35de57e21950e23428c3127b3a8dff676",
        "640c61459173331e2e964b1434ce44668dd4d9f17442c4f7b1e676e56b166980",
    ),
    "schemas/runtime-integrity/c-non-effect-witness-record-0.1.1.schema.json": (
        "ab7a610506dea762f267d81f733159af682104b1",
        "cfcc3014f21838faee05c99f4190b390f19c45ca6fbf08b3e7bf6de8248727c4",
    ),
    "tools/validate_runtime_integrity_extension.py": (
        "c2ba855dad55c5ce6e96d5d38543e7d0a2bebc01",
        "c1d9278af6848995ce9bcfaf3ecceb9b3f24e04a30a2fe8bedef4784f4a2ec73",
    ),
}

CGAM_SOURCE_PINS: dict[str, tuple[str, str]] = {
    "README.md": (
        "461194018e88e25720ffee0a94f14218e6c4b1a0",
        "60a286818c14f83a7fef43cbe7bae2cdba140531f4d33589b2e30137764f5276",
    ),
    "CHECKSUM_SCOPE.json": (
        "ef2ebc2ba2ac435800d7eb1d6da8d029218c8c6b",
        "1349df9940e1afd0f915481d93b0b42c8c2ff467d47b0466e6ad1f63c4e5b5b7",
    ),
    "tools/verify_tagged_tree_manifest.py": (
        "0ca80bd93ac040af895e897504ef1e753540574d",
        "af81cbdedf4abb956fbd7f4e46dd1325256f8e6d5fa97b4310439dedbeeef19e",
    ),
    "docs/markdown/CLI_Agent_Task_Contract_Schema_v0_1.md": (
        "4f0e88fa196f9a8220a885cf71e8b615d673e9da",
        "7542c4600ef6bfbfc850f13dc26688c92a66451455292034840211a701f39525",
    ),
    "docs/markdown/CLI_Agent_Permission_and_Capability_Model_v0_1.md": (
        "af50f2b5cf3c4c88b947ec261fdaa6862c3d7ffa",
        "499911347c3747ab06753b2d4f5dbc57ca77811fd2e86f53b379e020eca07af8",
    ),
    "schemas/common/cgam-common-defs-0.1.schema.json": (
        "62398a016ab67a5f1af98f45db0e9f239060c03d",
        "6b06121ab2233158d859c3691dc2c60a701862a1b0bbcd187abfdd2ed3cdad0a",
    ),
    "schemas/task-contract/cli-agent-task-contract-0.1.schema.json": (
        "b17d33a06421565f2ff63b67118b32005a873d50",
        "c7d4c2d4e10ef2b2bc2b7260862269e9c83a0178ced6a83dee531b1813fdac15",
    ),
    "schemas/permission-capability/cli-agent-permission-grant-0.1.schema.json": (
        "9c0625a239cf91848bfeeb106a528c6932896fd2",
        "bb24e068ba189d44b6c8e450ace991a306b7e407eb86e77156c999cd9fe17c7b",
    ),
    "schemas/SCHEMA_INDEX.json": (
        "6f8c383099ce7615e415890fcaf938729169b4d6",
        "e931ab16ae52a5f4df9560dcd7077f79d6a0d4be3abec230709e65b10287da61",
    ),
    "validator/SEMANTIC_RULES_INDEX.json": (
        "b059c5e8b1e77b1c6ed633bbdf0d98e020f14910",
        "6e6b2a5b5d98c940894702db3a88acfd872ba3fa3c7cde61e4c4d12ec50c6011",
    ),
    "fixtures/FIXTURE_MANIFEST.json": (
        "a423fb1d60bca982e9a51f67354308f22c35c180",
        "8d6cd1dd546837a401f1683599db9f36e48390e2531a8ee543fa5577af958bfa",
    ),
}

EXPECTED_TABLES = frozenset({"journal_meta", "authority_heads", "attempts", "records"})
EXISTING_WORKFLOWS = (
    ".github/workflows/integrity.yml",
    ".github/workflows/runtime-integrity-extension.yml",
)
R6A_WORKFLOW = ".github/workflows/cgam-durable-binding.yml"
REQUIRED_R6A_ADDITIONS = frozenset(
    {
        R6A_WORKFLOW,
        "docs/CGAM_DURABLE_BINDING_R6A_STATUS.md",
        "fixtures/cgam-durable-binding/MANIFEST.json",
        "fixtures/cgam-durable-binding/r6a_authority_revision_1_active.json",
        "fixtures/cgam-durable-binding/r6a_authority_revision_2_revoked.json",
        "fixtures/cgam-durable-binding/r6a_task_output.json",
        "schemas/cgam-durable-binding/r6a-cgam-authority-envelope-0.1.schema.json",
        "tests/r6a_scenario_registry.py",
        "tests/test_cgam_durable_binding.py",
        "tests/test_cgam_durable_binding_crash.py",
        "tools/cgam_durable_binding_runtime_adapter.py",
        "tests/test_cgam_durable_binding_security.py",
        "tools/verify_cgam_durable_binding_source.py",
        "tests/test_cgam_durable_binding_runtime_adapter.py",
        "tests/test_verify_cgam_durable_binding_source.py",
        "tools/cgam_durable_binding.py",
        "tools/run_cgam_durable_binding_suite.py",
    }
)
REQUIRED_INTEGRATION_MODIFICATIONS = frozenset(
    {
        "tools/verify_github_actions_pins.py",
        "tools/verify_r4a_integration.py",
        "tests/test_runtime_integrity_r2_closure.py",
        "tests/test_runtime_integrity_r4a_integration.py",
    }
)
FORBIDDEN_DIRECT_IMPORTS = frozenset(
    {
        "django",
        "fastapi",
        "flask",
        "grpc",
        "httpx",
        "requests",
        "socket",
        "sqlalchemy",
    }
)
REQUIRED_SOURCE_MARKERS = (
    ".c_binding",
    "binding_state.sqlite3",
    "binding.lock",
    "journal_mode",
    "DELETE",
    "synchronous",
    "FULL",
    "foreign_keys",
    "integrity_check",
)
TABLE_PATTERN = re.compile(
    r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"`\[]?"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)


class GitAuditError(RuntimeError):
    """Raised when required Git evidence cannot be read."""


def _git(
    root: Path,
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise GitAuditError(f"git {' '.join(args)} failed: {detail}")
    return result


def _git_text(root: Path, *args: str) -> str:
    return _git(root, *args).stdout.decode("utf-8").strip()


def _git_bytes(root: Path, *args: str) -> bytes:
    return _git(root, *args).stdout


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _object_exists(root: Path, ref: str) -> bool:
    return _git(root, "cat-file", "-e", f"{ref}^{{commit}}", check=False).returncode == 0


def _tree(root: Path, ref: str) -> str:
    return _git_text(root, "show", "-s", "--format=%T", ref)


def _blob_oid(root: Path, ref: str, path: str) -> str:
    return _git_text(root, "rev-parse", f"{ref}:{path}")


def _blob_bytes(root: Path, oid: str) -> bytes:
    return _git_bytes(root, "cat-file", "blob", oid)


def _nul_paths(root: Path, *args: str) -> set[str]:
    return {
        item.decode("utf-8")
        for item in _git_bytes(root, *args).split(b"\0")
        if item
    }


def _changed_paths(root: Path, diff_filter: str | None = None) -> set[str]:
    args = ["diff", "--name-only", "-z"]
    if diff_filter is not None:
        args.append(f"--diff-filter={diff_filter}")
    args.append(f"{IMPLEMENTATION_BASE_COMMIT}..HEAD")
    return _nul_paths(root, *args)


def _normalized_remote(value: str) -> str:
    normalized = value.rstrip("/")
    return normalized[:-4] if normalized.endswith(".git") else normalized


def allowed_r6a_addition(path: str) -> bool:
    """Return whether one newly added path is inside the bounded R6A surface."""

    return path.replace("\\", "/") in REQUIRED_R6A_ADDITIONS


def imported_roots(path: Path) -> tuple[set[str], list[str]]:
    """Return direct import roots and parse issues for one Python source file."""

    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        return set(), [f"r6a_python_source_unreadable:{path.name}:{exc}"]
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots, []


def inspect_binding_sources(
    root: Path,
    candidate_paths: Iterable[str],
) -> tuple[list[str], dict[str, Any]]:
    """Statically enforce the bounded four-table/stdlib source surface."""

    issues: list[str] = []
    python_paths = sorted(
        path for path in candidate_paths
        if (
            path in REQUIRED_R6A_ADDITIONS
            and path.startswith("tools/")
            and path.endswith(".py")
        )
    )
    core_paths = [
        path for path in python_paths
        if "runtime_adapter" not in path and "verify_" not in Path(path).name
    ]
    if not core_paths:
        issues.append("r6a_core_source_missing")

    source_parts: list[str] = []
    direct_imports: set[str] = set()
    stdlib = set(getattr(sys, "stdlib_module_names", ()))
    allowed_local = {
        "cgam_durable_binding_runtime_adapter",
        "validate_runtime_integrity_extension",
    }
    for relative in python_paths:
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            issues.append(f"r6a_python_source_unreadable:{relative}:{exc}")
            continue
        if relative in core_paths:
            source_parts.append(text)
        imports, parse_issues = imported_roots(path)
        direct_imports.update(imports)
        issues.extend(parse_issues)
        for name in sorted(imports):
            if name in FORBIDDEN_DIRECT_IMPORTS:
                issues.append(f"r6a_forbidden_direct_import:{relative}:{name}")
            elif stdlib and name not in stdlib and name not in allowed_local:
                issues.append(f"r6a_nonstdlib_direct_import:{relative}:{name}")

    core_source = "\n".join(source_parts)
    table_names = TABLE_PATTERN.findall(core_source)
    table_set = set(table_names)
    if table_set != EXPECTED_TABLES or len(table_names) != len(EXPECTED_TABLES):
        issues.append("r6a_sqlite_table_surface_invalid")
    if re.search(r"\bAUTOINCREMENT\b", core_source, re.IGNORECASE):
        issues.append("r6a_sqlite_autoincrement_forbidden")
    missing_markers = [marker for marker in REQUIRED_SOURCE_MARKERS if marker not in core_source]
    if missing_markers:
        issues.append("r6a_required_source_marker_missing")

    evidence: dict[str, Any] = {
        "python_paths": python_paths,
        "core_paths": core_paths,
        "direct_imports": sorted(direct_imports),
        "tables": sorted(table_set),
        "table_create_statements": len(table_names),
        "missing_markers": missing_markers,
    }
    return issues, evidence


def _pin_evidence(
    root: Path,
    ref: str,
    pins: dict[str, tuple[str, str]],
    *,
    compare_worktree: bool,
    issue_prefix: str,
) -> tuple[list[str], list[dict[str, Any]]]:
    issues: list[str] = []
    evidence: list[dict[str, Any]] = []
    for path, (expected_blob, expected_sha256) in pins.items():
        entry: dict[str, Any] = {
            "path": path,
            "expected_blob": expected_blob,
            "expected_sha256": expected_sha256,
        }
        try:
            actual_blob = _blob_oid(root, ref, path)
            raw = _blob_bytes(root, actual_blob)
            actual_sha256 = _sha256(raw)
        except GitAuditError as exc:
            entry["error"] = str(exc)
            issues.append(f"{issue_prefix}_source_unresolved:{path}")
            evidence.append(entry)
            continue
        entry.update(
            {
                "actual_blob": actual_blob,
                "actual_sha256": actual_sha256,
                "bytes": len(raw),
                "blob_match": actual_blob == expected_blob,
                "sha256_match": actual_sha256 == expected_sha256,
            }
        )
        if actual_blob != expected_blob or actual_sha256 != expected_sha256:
            issues.append(f"{issue_prefix}_source_pin_mismatch:{path}")
        if compare_worktree:
            worktree_path = root / path
            try:
                is_regular = worktree_path.is_file() and not worktree_path.is_symlink()
                worktree_raw = worktree_path.read_bytes() if is_regular else b""
            except OSError:
                is_regular = False
                worktree_raw = b""
            entry["worktree_regular"] = is_regular
            entry["worktree_sha256"] = _sha256(worktree_raw) if is_regular else None
            entry["worktree_matches_blob"] = is_regular and worktree_raw == raw
            if not is_regular or worktree_raw != raw:
                issues.append(f"{issue_prefix}_worktree_blob_mismatch:{path}")
        evidence.append(entry)
    return issues, evidence


def _protected_paths(root: Path) -> set[str]:
    manifests = ("SHA256SUMS.txt", "manifests/SHA256SUMS.txt")
    result = set(manifests)
    for manifest in manifests:
        raw = _blob_bytes(root, _blob_oid(root, IMPLEMENTATION_BASE_COMMIT, manifest))
        for line in raw.decode("utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            digest, path = stripped.split(maxsplit=1)
            if not re.fullmatch(r"[0-9A-Fa-f]{64}", digest):
                raise GitAuditError(f"malformed checksum entry: {manifest}:{path}")
            result.add(path.lstrip("*"))
    return result


def audit_implementation(
    root: Path = ROOT,
    *,
    check_worktree: bool = True,
) -> tuple[list[str], dict[str, Any]]:
    """Audit the implementation candidate against its exact predecessor."""

    root = root.resolve()
    issues: list[str] = []
    evidence: dict[str, Any] = {"root": str(root)}
    try:
        if not _object_exists(root, IMPLEMENTATION_BASE_COMMIT):
            raise GitAuditError("implementation base commit is absent")
        base_tree = _tree(root, IMPLEMENTATION_BASE_COMMIT)
        head = _git_text(root, "rev-parse", "HEAD")
        head_tree = _tree(root, "HEAD")
        ancestor = _git(
            root,
            "merge-base",
            "--is-ancestor",
            IMPLEMENTATION_BASE_COMMIT,
            "HEAD",
            check=False,
        ).returncode == 0
        merge_commits = _git_text(
            root,
            "rev-list",
            "--min-parents=2",
            f"{IMPLEMENTATION_BASE_COMMIT}..HEAD",
        ).splitlines()
        changed = _changed_paths(root)
        added = _changed_paths(root, "A")
        deleted = _changed_paths(root, "D")
        modified_or_other = changed - added
    except (GitAuditError, UnicodeError, ValueError) as exc:
        return [f"implementation_git_evidence_unresolved:{exc}"], evidence

    if base_tree != IMPLEMENTATION_BASE_TREE:
        issues.append("implementation_base_tree_mismatch")
    if not ancestor:
        issues.append("implementation_base_not_ancestor")
    if merge_commits:
        issues.append("implementation_candidate_merge_commit_forbidden")
    if deleted:
        issues.append("implementation_candidate_deletion_forbidden")

    unexpected_additions = sorted(added - REQUIRED_R6A_ADDITIONS)
    missing_additions = sorted(REQUIRED_R6A_ADDITIONS - added)
    if added != REQUIRED_R6A_ADDITIONS:
        issues.append("implementation_r6a_addition_scope_invalid")
    if modified_or_other != REQUIRED_INTEGRATION_MODIFICATIONS:
        issues.append("implementation_predecessor_path_modified")
    changed_workflows = sorted(
        path for path in changed if path.startswith(".github/workflows/")
    )
    if changed_workflows != [R6A_WORKFLOW]:
        issues.append("implementation_workflow_surface_invalid")

    existing_workflow_mismatches: list[str] = []
    for path in EXISTING_WORKFLOWS:
        try:
            if _blob_oid(root, "HEAD", path) != _blob_oid(
                root, IMPLEMENTATION_BASE_COMMIT, path
            ):
                existing_workflow_mismatches.append(path)
        except GitAuditError:
            existing_workflow_mismatches.append(path)
    if existing_workflow_mismatches:
        issues.append("implementation_existing_workflow_modified")

    pin_issues, pin_evidence = _pin_evidence(
        root,
        "HEAD",
        IMPLEMENTATION_SOURCE_PINS,
        compare_worktree=True,
        issue_prefix="implementation",
    )
    issues.extend(pin_issues)

    try:
        protected = _protected_paths(root)
        protected_mismatches = sorted(
            path for path in protected
            if _blob_oid(root, "HEAD", path)
            != _blob_oid(root, IMPLEMENTATION_BASE_COMMIT, path)
        )
    except GitAuditError as exc:
        protected = set()
        protected_mismatches = [str(exc)]
    if len(protected) != 39 or protected_mismatches:
        issues.append("implementation_protected_blob_mismatch")

    source_issues, source_evidence = inspect_binding_sources(root, added)
    issues.extend(source_issues)

    diff_check = _git(
        root,
        "diff",
        "--check",
        f"{IMPLEMENTATION_BASE_COMMIT}..HEAD",
        check=False,
    )
    if diff_check.returncode != 0 or diff_check.stdout or diff_check.stderr:
        issues.append("implementation_diff_check_failed")
    status = _git_text(root, "status", "--porcelain=v1", "--untracked-files=all")
    if check_worktree and status:
        issues.append("implementation_worktree_dirty")

    expected_head = os.environ.get("EXPECTED_EVENT_HEAD") or os.environ.get("EXPECTED_HEAD")
    if expected_head is not None and expected_head != head:
        issues.append("implementation_event_head_mismatch")

    evidence.update(
        {
            "base_commit": IMPLEMENTATION_BASE_COMMIT,
            "base_tree": base_tree,
            "head": head,
            "tree": head_tree,
            "base_is_ancestor": ancestor,
            "merge_commits": merge_commits,
            "changed_paths": sorted(changed),
            "added_paths": sorted(added),
            "deleted_paths": sorted(deleted),
            "modified_or_other_paths": sorted(modified_or_other),
            "required_integration_modifications": sorted(REQUIRED_INTEGRATION_MODIFICATIONS),
            "unexpected_additions": unexpected_additions,
            "missing_required_paths": missing_additions,
            "changed_workflows": changed_workflows,
            "existing_workflow_mismatches": existing_workflow_mismatches,
            "source_pins": pin_evidence,
            "protected_count": len(protected),
            "protected_mismatches": protected_mismatches,
            "source_constraints": source_evidence,
            "diff_check_exit": diff_check.returncode,
            "diff_check_stdout_bytes": len(diff_check.stdout),
            "diff_check_stderr_bytes": len(diff_check.stderr),
            "worktree_status": status,
            "event_expected_head": expected_head,
        }
    )
    return sorted(set(issues)), evidence


def audit_cgam(root: Path) -> tuple[list[str], dict[str, Any]]:
    """Audit the detached CGAM source checkout without mutating it."""

    root = root.resolve()
    issues: list[str] = []
    evidence: dict[str, Any] = {"root": str(root)}
    try:
        head = _git_text(root, "rev-parse", "HEAD")
        tree = _tree(root, "HEAD")
        symbolic = _git(
            root, "symbolic-ref", "-q", "--short", "HEAD", check=False
        )
        detached = symbolic.returncode != 0
        status = _git_text(root, "status", "--porcelain=v1", "--untracked-files=all")
        origin = _git_text(root, "remote", "get-url", "origin")
        branch_lines = _git_text(
            root,
            "for-each-ref",
            "--format=%(refname:short) %(objectname)",
            "refs/heads",
        ).splitlines()
        local_branches = {
            line.split(" ", 1)[0]: line.split(" ", 1)[1]
            for line in branch_lines if " " in line
        }
    except (GitAuditError, UnicodeError, ValueError) as exc:
        return [f"cgam_git_evidence_unresolved:{exc}"], evidence

    if head != CGAM_COMMIT:
        issues.append("cgam_commit_mismatch")
    if tree != CGAM_TREE:
        issues.append("cgam_tree_mismatch")
    if not detached:
        issues.append("cgam_checkout_not_detached")
    if status:
        issues.append("cgam_worktree_dirty")
    if _normalized_remote(origin) != _normalized_remote(CGAM_REMOTE):
        issues.append("cgam_origin_mismatch")
    unexpected_branches = sorted(
        name for name, oid in local_branches.items()
        if name != "main" or oid != CGAM_COMMIT
    )
    if unexpected_branches:
        issues.append("cgam_unexpected_local_branch")

    pin_issues, pin_evidence = _pin_evidence(
        root,
        CGAM_COMMIT,
        CGAM_SOURCE_PINS,
        compare_worktree=True,
        issue_prefix="cgam",
    )
    issues.extend(pin_issues)
    tracked_paths = _nul_paths(root, "ls-tree", "-r", "--name-only", "-z", CGAM_COMMIT)

    evidence.update(
        {
            "head": head,
            "tree": tree,
            "detached": detached,
            "status": status,
            "origin": origin,
            "local_branches": local_branches,
            "unexpected_local_branches": unexpected_branches,
            "tracked_paths": len(tracked_paths),
            "source_pins": pin_evidence,
        }
    )
    return sorted(set(issues)), evidence


def _default_cgam_root(implementation_root: Path) -> Path:
    configured = os.environ.get("CGAM_SOURCE_ROOT")
    if configured:
        return Path(configured)
    return implementation_root.parent / "c-governed-cli-agent-mesh"


def audit(
    implementation_root: Path = ROOT,
    cgam_root: Path | None = None,
    *,
    check_worktree: bool = True,
) -> tuple[list[str], dict[str, Any]]:
    """Run both custody domains and return deterministic issues/evidence."""

    selected_cgam_root = cgam_root or _default_cgam_root(implementation_root)
    implementation_issues, implementation = audit_implementation(
        implementation_root,
        check_worktree=check_worktree,
    )
    cgam_issues, cgam = audit_cgam(selected_cgam_root)
    issues = [*(f"implementation:{item}" for item in implementation_issues)]
    issues.extend(f"cgam:{item}" for item in cgam_issues)

    implementation_pin_matches = sum(
        bool(item.get("blob_match") and item.get("sha256_match"))
        for item in implementation.get("source_pins", [])
    )
    cgam_pin_matches = sum(
        bool(
            item.get("blob_match")
            and item.get("sha256_match")
            and item.get("worktree_matches_blob")
        )
        for item in cgam.get("source_pins", [])
    )
    evidence = {
        "contract_id": "C_RUNTIME_CONSEQUENCE_INTEGRITY_R6A_DURABLE_LOCAL_CGAM_BINDING_v0_1",
        "verdict": "PASS" if not issues else "FAIL_RETURN_TO_R6A_SLOT_A",
        "issues": issues,
        "counts": {
            "failures": len(issues),
            "implementation_changed_paths": len(implementation.get("changed_paths", [])),
            "implementation_added_paths": len(implementation.get("added_paths", [])),
            "implementation_deletions": len(implementation.get("deleted_paths", [])),
            "implementation_source_pins": len(IMPLEMENTATION_SOURCE_PINS),
            "implementation_source_pins_matched": implementation_pin_matches,
            "implementation_protected_blobs": implementation.get("protected_count", 0),
            "cgam_source_pins": len(CGAM_SOURCE_PINS),
            "cgam_source_pins_matched": cgam_pin_matches,
            "cgam_tracked_paths": cgam.get("tracked_paths", 0),
            "sqlite_tables": len(
                implementation.get("source_constraints", {}).get("tables", [])
            ),
        },
        "implementation": implementation,
        "cgam": cgam,
    }
    return issues, evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cgam-root",
        type=Path,
        default=None,
        help="Detached c-governed-cli-agent-mesh checkout (default: sibling or CGAM_SOURCE_ROOT).",
    )
    args = parser.parse_args(argv)
    issues, evidence = audit(cgam_root=args.cgam_root)
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    counts = evidence["counts"]
    print(
        "R6A_SOURCE_CUSTODY "
        f"implementation_pins={counts['implementation_source_pins_matched']}/"
        f"{counts['implementation_source_pins']} "
        f"protected={counts['implementation_protected_blobs']}/39 "
        f"cgam_pins={counts['cgam_source_pins_matched']}/{counts['cgam_source_pins']} "
        f"tables={counts['sqlite_tables']}/4 pass={int(not issues)} "
        f"fail={counts['failures']}"
    )
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
