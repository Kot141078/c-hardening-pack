from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol


ROOT = Path(__file__).resolve().parent.parent
CONFIG_RELATIVE = "CHECKSUM_DOMAIN.json"
SCHEMA_VERSION = "checksum-domain.v2"
DOCUMENT_ID = "c-hardening-pack-v0.1-checksum-domain-portability"
REPOSITORY = "https://github.com/Kot141078/c-hardening-pack"
PROTECTED_BASELINE = "9a33e3866cde19939be22a903967bc94f566db76"
PROTECTED_DISTINCT_BLOBS = 39
EXPECTED_MANIFEST_PATHS = frozenset({"SHA256SUMS.txt", "manifests/SHA256SUMS.txt"})
DOMAIN_NAMES = ("lf_text_bytes", "crlf_text_bytes", "raw_bytes")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CHECKSUM_LINE_RE = re.compile(r"^([0-9A-Fa-f]{64}) {2}(\S(?:.*\S)?)$")
WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
ENCODED_STRUCTURAL_RE = re.compile(r"%(?:00|2e|2f|5c)", re.IGNORECASE)
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
WINDOWS_FORBIDDEN_CHARS = frozenset('<>:"|?*')
WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


class ChecksumDomainError(ValueError):
    """A fail-closed checksum policy or evidence error."""


def fail(message: str) -> None:
    raise ChecksumDomainError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_relative_path(relative: object, *, label: str = "path") -> str:
    if not isinstance(relative, str) or not relative:
        fail(f"{label} must be a non-empty string")
    if relative != relative.strip():
        fail(f"{label} has leading or trailing whitespace: {relative!r}")
    if "\x00" in relative or any(ord(character) < 0x20 for character in relative):
        fail(f"{label} contains a control character: {relative!r}")
    if "\\" in relative:
        fail(f"{label} must use POSIX separators: {relative!r}")
    if relative.startswith("/") or relative.startswith("//") or WINDOWS_DRIVE_RE.match(relative):
        fail(f"{label} must be repository-relative: {relative!r}")
    if ENCODED_STRUCTURAL_RE.search(relative):
        fail(f"{label} contains encoded structural characters: {relative!r}")

    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        fail(f"{label} is not canonical or traverses: {relative!r}")
    for part in parts:
        if any(character in WINDOWS_FORBIDDEN_CHARS for character in part):
            fail(f"{label} is not portable to Windows: {relative!r}")
        if part.endswith((".", " ")):
            fail(f"{label} has a Windows-ambiguous trailing character: {relative!r}")
        device_stem = part.split(".", 1)[0].upper()
        if device_stem in WINDOWS_DEVICE_NAMES:
            fail(f"{label} uses a reserved Windows device name: {relative!r}")
    canonical = PurePosixPath(*parts).as_posix()
    if canonical != relative:
        fail(f"{label} is not canonical: {relative!r}")
    return canonical


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        fail(f"Cannot inspect source path {path}: {exc}")
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


class ByteSource(Protocol):
    label: str
    exact_bytes: bool

    def read_bytes(self, relative: str) -> bytes:
        ...


@dataclass(frozen=True)
class DirectorySource:
    root: Path
    label: str
    exact_bytes: bool

    def read_bytes(self, relative: str) -> bytes:
        relative = validate_relative_path(relative, label="source path")
        if not self.root.exists():
            fail(f"Source root does not exist: {self.root}")
        if _is_link_or_reparse(self.root):
            fail(f"Symlink or reparse source root is not admissible: {self.root}")
        source_root = self.root.resolve(strict=True)
        candidate = self.root.joinpath(*relative.split("/"))

        current = self.root
        for part in relative.split("/"):
            current = current / part
            if not current.exists() and not current.is_symlink():
                fail(f"Missing source file: {relative}")
            if _is_link_or_reparse(current):
                fail(f"Symlink or reparse source path is not admissible: {relative}")

        resolved = candidate.resolve(strict=True)
        try:
            resolved.relative_to(source_root)
        except ValueError:
            fail(f"Source path escapes root: {relative}")
        if not resolved.is_file():
            fail(f"Source path is not a regular file: {relative}")
        return resolved.read_bytes()


class GitBlobSource:
    exact_bytes = True

    def __init__(self, repository: Path, ref: str) -> None:
        self.repository = repository.resolve(strict=True)
        self.commit = self._git("rev-parse", "--verify", f"{ref}^{{commit}}").decode("ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{40}", self.commit):
            fail(f"Git ref did not resolve to a full commit: {ref!r}")
        self.label = f"git-blob:{self.commit}"

    def _git(self, *arguments: str) -> bytes:
        process = subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode:
            detail = process.stderr.decode("utf-8", errors="replace").strip()
            fail(f"Git command failed ({' '.join(arguments)}): {detail}")
        return process.stdout

    def read_bytes(self, relative: str) -> bytes:
        relative = validate_relative_path(relative, label="Git blob path")
        tree_line = self._git("ls-tree", "-z", self.commit, "--", relative)
        records = [record for record in tree_line.split(b"\x00") if record]
        if len(records) != 1:
            fail(f"Missing or ambiguous Git blob path: {relative}")
        try:
            header, encoded_name = records[0].split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii").split(" ")
            name = encoded_name.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            fail(f"Malformed Git tree entry for: {relative}")
        if name != relative or object_type != "blob" or mode not in {"100644", "100755"}:
            fail(f"Git path is not a regular tracked blob: {relative}")
        return self._git("cat-file", "blob", object_id)


def decode_utf8_text(data: bytes, relative: str) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        fail(f"UTF-8 BOM is forbidden for declared text: {relative}")
    if data.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00")):
        fail(f"Non-UTF-8 BOM is forbidden for declared text: {relative}")
    if b"\x00" in data:
        fail(f"NUL is forbidden for declared text: {relative}")
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"Invalid UTF-8 for declared text {relative}: byte {exc.start}")


def newline_representation(data: bytes, relative: str) -> str:
    without_crlf = data.replace(b"\r\n", b"")
    if b"\r" in without_crlf:
        fail(f"Bare CR is not admissible: {relative}")
    has_crlf = b"\r\n" in data
    has_lf = b"\n" in without_crlf
    if has_crlf and has_lf:
        fail(f"Mixed CRLF and LF is not admissible: {relative}")
    if has_crlf:
        return "crlf"
    if has_lf:
        return "lf"
    return "newline-free"


def canonical_text_bytes(data: bytes, domain: str, relative: str, *, accept_checkout_forms: bool) -> bytes:
    if domain not in {"lf_text_bytes", "crlf_text_bytes"}:
        fail(f"Unsupported text domain: {domain!r}")
    decode_utf8_text(data, relative)
    representation = newline_representation(data, relative)

    if not accept_checkout_forms:
        required = "lf" if domain == "lf_text_bytes" else "crlf"
        if representation not in {required, "newline-free"}:
            fail(
                f"Exact source representation for {relative} is {representation}, "
                f"but its canonical domain is {required}"
            )

    if domain == "lf_text_bytes":
        return data.replace(b"\r\n", b"\n")
    if representation == "lf":
        return data.replace(b"\n", b"\r\n")
    return data


def normalized_manifest_bytes(data: bytes, relative: str, *, exact_source: bool) -> bytes:
    decode_utf8_text(data, relative)
    representation = newline_representation(data, relative)
    if exact_source and representation == "crlf":
        fail(f"Exact checksum manifest must use LF bytes: {relative}")
    return data.replace(b"\r\n", b"\n")


def manifest_entries(data: bytes, relative: str, *, exact_source: bool) -> list[tuple[str, str]]:
    normalized = normalized_manifest_bytes(data, relative, exact_source=exact_source)
    text = normalized.decode("utf-8")
    entries: list[tuple[str, str]] = []
    exact_seen: set[str] = set()
    logical_seen: set[str] = set()

    for line_number, line in enumerate(text.split("\n"), start=1):
        if not line or line.startswith("#"):
            continue
        match = CHECKSUM_LINE_RE.fullmatch(line)
        if not match:
            fail(f"Malformed checksum line {relative}:{line_number}")
        expected, entry_path = match.groups()
        entry_path = validate_relative_path(entry_path, label=f"checksum path at {relative}:{line_number}")
        logical_key = entry_path.casefold()
        if entry_path in exact_seen or logical_key in logical_seen:
            fail(f"Duplicate checksum path in {relative}: {entry_path}")
        exact_seen.add(entry_path)
        logical_seen.add(logical_key)
        entries.append((expected.lower(), entry_path))
    return entries


def _expect_exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    observed = set(value)
    if observed != expected:
        fail(f"{label} keys mismatch: expected={sorted(expected)} observed={sorted(observed)}")
    return value


def _reject_duplicate_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"Duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    fail(f"Non-finite JSON number is forbidden: {value}")


def _reject_json_float(value: str) -> object:
    fail(f"Floating-point JSON number is forbidden in checksum policy: {value}")


def load_config(data: bytes) -> dict[str, object]:
    decode_utf8_text(data, CONFIG_RELATIVE)
    newline_representation(data, CONFIG_RELATIVE)
    try:
        config = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
        )
    except json.JSONDecodeError as exc:
        fail(f"Malformed checksum-domain JSON: line {exc.lineno} column {exc.colno}")

    config = _expect_exact_keys(
        config,
        {
            "schema_version",
            "document_id",
            "repository",
            "protected_git_baseline",
            "scope",
            "authority_rule",
            "claim_boundary",
            "text_policy",
            "source_claims",
            "expected_total_entries",
            "manifests",
            "verification",
        },
        "checksum-domain config",
    )
    if config["schema_version"] != SCHEMA_VERSION:
        fail(f"Unsupported checksum-domain schema_version: {config['schema_version']!r}")
    if config["document_id"] != DOCUMENT_ID:
        fail("Checksum-domain document_id does not match this verifier")
    if config["repository"] != REPOSITORY:
        fail("Checksum-domain repository does not match this verifier")
    if config["protected_git_baseline"] != PROTECTED_BASELINE:
        fail("Protected Git baseline does not match the authorized main commit")
    if (
        not isinstance(config["expected_total_entries"], int)
        or isinstance(config["expected_total_entries"], bool)
        or config["expected_total_entries"] != 74
    ):
        fail("expected_total_entries must be exactly 74")
    for field in ("document_id", "repository", "scope", "authority_rule", "claim_boundary"):
        if not isinstance(config[field], str) or not config[field].strip():
            fail(f"{field} must be a non-empty string")

    text_policy = _expect_exact_keys(
        config["text_policy"],
        {"encoding", "bom", "unicode_normalization", "newline_free_text", "worktree_forms", "invalid_forms"},
        "text_policy",
    )
    expected_text_policy = {
        "encoding": "UTF-8-strict",
        "bom": "forbidden",
        "unicode_normalization": "none",
        "newline_free_text": "accepted",
        "worktree_forms": ["LF", "CRLF"],
        "invalid_forms": ["mixed-CRLF-LF", "bare-CR"],
    }
    if text_policy != expected_text_policy:
        fail("text_policy does not match the implemented fail-closed profile")

    source_claims = _expect_exact_keys(
        config["source_claims"], {"git_blob", "worktree", "release_archive"}, "source_claims"
    )
    if not all(isinstance(value, str) and value.strip() for value in source_claims.values()):
        fail("source_claims values must be non-empty strings")
    verification = _expect_exact_keys(
        config["verification"], {"worktree_command", "git_blob_command", "release_archive_command"}, "verification"
    )
    if not all(isinstance(value, str) and value.strip() for value in verification.values()):
        fail("verification commands must be non-empty strings")
    return config


def declaration_domains(declaration: object, manifest_paths: set[str]) -> dict[str, str]:
    declaration = _expect_exact_keys(
        declaration,
        {"path", "hash_algorithm", "expected_entries", "canonical_manifest_sha256", "path_domains"},
        "manifest declaration",
    )
    validate_relative_path(declaration["path"], label="manifest declaration path")
    if declaration["hash_algorithm"] != "sha256":
        fail(f"Unsupported hash algorithm for {declaration['path']!r}")
    if not isinstance(declaration["expected_entries"], int) or isinstance(declaration["expected_entries"], bool):
        fail(f"expected_entries must be an integer for {declaration['path']!r}")
    if declaration["expected_entries"] != len(manifest_paths):
        fail(f"Entry count mismatch for {declaration['path']!r}")
    digest = declaration["canonical_manifest_sha256"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        fail(f"Invalid canonical manifest SHA-256 for {declaration['path']!r}")

    path_domains = _expect_exact_keys(declaration["path_domains"], set(DOMAIN_NAMES), "path_domains")
    assignment: dict[str, str] = {}
    logical_seen: set[str] = set()
    for domain in DOMAIN_NAMES:
        paths = path_domains[domain]
        if not isinstance(paths, list):
            fail(f"{domain} must be an array")
        for path in paths:
            path = validate_relative_path(path, label=f"{domain} path")
            logical = path.casefold()
            if path in assignment or logical in logical_seen:
                fail(f"Conflicting or duplicate domain declaration: {path}")
            assignment[path] = domain
            logical_seen.add(logical)

    declared_paths = set(assignment)
    if declared_paths != manifest_paths:
        missing = sorted(manifest_paths - declared_paths)
        extra = sorted(declared_paths - manifest_paths)
        fail(f"Declared path partition mismatch: missing={missing} extra={extra}")
    return assignment


def validate_manifest_declaration_paths(declarations: object) -> list[dict[str, object]]:
    if not isinstance(declarations, list) or len(declarations) != 2:
        fail("Exactly two checksum manifests must be declared")
    paths: list[str] = []
    typed: list[dict[str, object]] = []
    for declaration in declarations:
        if not isinstance(declaration, dict):
            fail("Manifest declaration must be an object")
        paths.append(validate_relative_path(declaration.get("path"), label="manifest path"))
        typed.append(declaration)
    if len(set(paths)) != len(paths) or set(paths) != EXPECTED_MANIFEST_PATHS:
        fail(
            f"Manifest declaration paths mismatch: expected={sorted(EXPECTED_MANIFEST_PATHS)} "
            f"observed={sorted(paths)}"
        )
    return typed


@dataclass(frozen=True)
class VerificationResult:
    source: str
    policy_source: str
    checked_entries: int
    manifest_count: int
    raw_digest_matches: int
    transformed_domain_matches: int
    protected_git_blobs: int


def verify_source(
    source: ByteSource,
    *,
    baseline_source: ByteSource | None = None,
    policy_source: ByteSource | None = None,
) -> VerificationResult:
    effective_policy_source = policy_source or source
    config = load_config(effective_policy_source.read_bytes(CONFIG_RELATIVE))
    declarations = validate_manifest_declaration_paths(config["manifests"])

    manifest_declarations_seen: set[str] = set()
    reference_entries: dict[str, str] | None = None
    reference_domains: dict[str, str] | None = None
    checked = 0
    raw_digest_matches = 0
    transformed_domain_matches = 0
    protected_compared: set[str] = set()

    for declaration_object in declarations:
        if not isinstance(declaration_object, dict):
            fail("Manifest declaration must be an object")
        manifest_relative = validate_relative_path(declaration_object.get("path"), label="manifest path")
        if manifest_relative in manifest_declarations_seen:
            fail(f"Duplicate manifest declaration: {manifest_relative}")
        manifest_declarations_seen.add(manifest_relative)

        manifest_data = source.read_bytes(manifest_relative)
        normalized_manifest = normalized_manifest_bytes(
            manifest_data, manifest_relative, exact_source=source.exact_bytes
        )
        if sha256(normalized_manifest) != declaration_object.get("canonical_manifest_sha256"):
            fail(f"Canonical checksum manifest hash mismatch: {manifest_relative}")
        parsed_entries = manifest_entries(manifest_data, manifest_relative, exact_source=source.exact_bytes)
        entry_map = {path: digest for digest, path in parsed_entries}
        domains = declaration_domains(declaration_object, set(entry_map))

        if reference_entries is None:
            reference_entries = entry_map
            reference_domains = domains
        elif entry_map != reference_entries or domains != reference_domains:
            fail("The two checksum manifests or their declared domains disagree")

        if baseline_source is not None:
            baseline_manifest = baseline_source.read_bytes(manifest_relative)
            if manifest_data != baseline_manifest:
                fail(f"Protected checksum manifest differs from {PROTECTED_BASELINE}: {manifest_relative}")
            protected_compared.add(manifest_relative)

        for expected, relative in parsed_entries:
            raw = source.read_bytes(relative)
            domain = domains[relative]
            if domain == "raw_bytes":
                canonical = raw
            else:
                canonical = canonical_text_bytes(
                    raw,
                    domain,
                    relative,
                    # A Git blob is exact evidence for baseline equality, but its
                    # separately reported canonical-domain projection may still
                    # transform LF into a declared CRLF release domain. An
                    # extracted release archive must already contain canonical
                    # bytes and therefore receives no such projection allowance.
                    accept_checkout_forms=not source.exact_bytes or isinstance(source, GitBlobSource),
                )
            if sha256(raw) == expected:
                raw_digest_matches += 1
            if canonical != raw:
                transformed_domain_matches += 1
            if sha256(canonical) != expected:
                fail(f"Checksum mismatch in {manifest_relative}: {relative}")
            if baseline_source is not None and raw != baseline_source.read_bytes(relative):
                fail(f"Protected canonical Git blob differs from {PROTECTED_BASELINE}: {relative}")
            if baseline_source is not None:
                protected_compared.add(relative)
            checked += 1

    if checked != config["expected_total_entries"]:
        fail(f"Total entry count mismatch: expected={config['expected_total_entries']} observed={checked}")
    if baseline_source is not None and len(protected_compared) != PROTECTED_DISTINCT_BLOBS:
        fail(
            f"Protected Git blob count mismatch: expected={PROTECTED_DISTINCT_BLOBS} "
            f"observed={len(protected_compared)}"
        )
    return VerificationResult(
        source=source.label,
        policy_source=effective_policy_source.label,
        checked_entries=checked,
        manifest_count=len(declarations),
        raw_digest_matches=raw_digest_matches,
        transformed_domain_matches=transformed_domain_matches,
        protected_git_blobs=len(protected_compared),
    )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify declared checksum domains without changing canonical bytes.")
    parser.add_argument(
        "--source",
        choices=("worktree", "git-blob", "release-archive"),
        default="worktree",
        help="Evidence source and exact claim being verified.",
    )
    parser.add_argument(
        "--git-ref",
        help="Commit-ish for Git-blob evidence or release-archive policy (default in those modes: HEAD).",
    )
    parser.add_argument(
        "--archive-root",
        type=Path,
        help="Extracted archive root for --source release-archive; raw archive bytes are not normalized.",
    )
    return parser


def main(arguments: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(arguments)
    try:
        baseline_source: ByteSource | None = None
        policy_source: ByteSource | None = None
        if args.source == "worktree":
            if args.archive_root is not None:
                fail("--archive-root is valid only with --source release-archive")
            if args.git_ref is not None:
                fail("--git-ref is not valid with --source worktree")
            source: ByteSource = DirectorySource(ROOT, "worktree", exact_bytes=False)
        elif args.source == "git-blob":
            if args.archive_root is not None:
                fail("--archive-root is valid only with --source release-archive")
            source = GitBlobSource(ROOT, args.git_ref or "HEAD")
            baseline_source = GitBlobSource(ROOT, PROTECTED_BASELINE)
        else:
            if args.archive_root is None:
                fail("--archive-root is required with --source release-archive")
            source = DirectorySource(args.archive_root, f"release-archive:{args.archive_root.resolve()}", exact_bytes=True)
            policy_source = GitBlobSource(ROOT, args.git_ref or "HEAD")

        result = verify_source(source, baseline_source=baseline_source, policy_source=policy_source)
        protected_result = (
            f"{result.protected_git_blobs}/{PROTECTED_DISTINCT_BLOBS}"
            if baseline_source is not None
            else "not-applicable"
        )
        print(
            f"PASS {SCHEMA_VERSION}: {result.checked_entries}/{result.checked_entries} manifest entries "
            f"source={result.source} policy_source={result.policy_source} manifests={result.manifest_count} "
            f"raw_digest_matches={result.raw_digest_matches}/{result.checked_entries} "
            f"transformed_domain_matches={result.transformed_domain_matches}/{result.checked_entries} "
            f"protected_git_blobs={protected_result}"
        )
        return 0
    except (ChecksumDomainError, OSError, subprocess.SubprocessError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
