from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import verify_checksum_domain as checksum  # noqa: E402


def manifest_line(path: str, data: bytes = b"payload") -> bytes:
    digest = hashlib.sha256(data).hexdigest().upper()
    return f"{digest}  {path}\n".encode("ascii")


def one_path_declaration(path: str = "payload.txt", domain: str = "lf_text_bytes") -> dict[str, object]:
    domains = {name: [] for name in checksum.DOMAIN_NAMES}
    domains[domain] = [path]
    return {
        "path": "SHA256SUMS.txt",
        "hash_algorithm": "sha256",
        "expected_entries": 1,
        "canonical_manifest_sha256": "0" * 64,
        "path_domains": domains,
    }


class TextDomainTest(unittest.TestCase):
    def test_all_lf_input_to_lf_domain(self) -> None:
        data = b"one\ntwo\n"
        self.assertEqual(checksum.canonical_text_bytes(data, "lf_text_bytes", "x", accept_checkout_forms=True), data)

    def test_all_crlf_input_to_lf_domain(self) -> None:
        data = b"one\r\ntwo\r\n"
        self.assertEqual(
            checksum.canonical_text_bytes(data, "lf_text_bytes", "x", accept_checkout_forms=True),
            b"one\ntwo\n",
        )

    def test_all_lf_input_to_crlf_domain(self) -> None:
        data = b"one\ntwo\n"
        self.assertEqual(
            checksum.canonical_text_bytes(data, "crlf_text_bytes", "x", accept_checkout_forms=True),
            b"one\r\ntwo\r\n",
        )

    def test_all_crlf_input_to_crlf_domain(self) -> None:
        data = b"one\r\ntwo\r\n"
        self.assertEqual(checksum.canonical_text_bytes(data, "crlf_text_bytes", "x", accept_checkout_forms=True), data)

    def test_mixed_crlf_and_lf_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Mixed CRLF and LF"):
            checksum.canonical_text_bytes(b"one\r\ntwo\n", "lf_text_bytes", "x", accept_checkout_forms=True)

    def test_bare_cr_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Bare CR"):
            checksum.canonical_text_bytes(b"one\rtwo", "lf_text_bytes", "x", accept_checkout_forms=True)

    def test_utf8_bom_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "BOM is forbidden"):
            checksum.canonical_text_bytes(b"\xef\xbb\xbftext\n", "lf_text_bytes", "x", accept_checkout_forms=True)

    def test_utf16_bom_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Non-UTF-8 BOM"):
            checksum.canonical_text_bytes(b"\xff\xfet\x00", "lf_text_bytes", "x", accept_checkout_forms=True)

    def test_invalid_utf8_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Invalid UTF-8"):
            checksum.canonical_text_bytes(b"\x80\n", "lf_text_bytes", "x", accept_checkout_forms=True)

    def test_nul_rejected_for_declared_text(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "NUL is forbidden"):
            checksum.canonical_text_bytes(b"a\x00b", "lf_text_bytes", "x", accept_checkout_forms=True)

    def test_empty_text_is_newline_free_and_accepted(self) -> None:
        self.assertEqual(checksum.canonical_text_bytes(b"", "lf_text_bytes", "x", accept_checkout_forms=True), b"")
        self.assertEqual(checksum.canonical_text_bytes(b"", "crlf_text_bytes", "x", accept_checkout_forms=True), b"")

    def test_exact_lf_domain_rejects_crlf(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "canonical domain is lf"):
            checksum.canonical_text_bytes(b"a\r\n", "lf_text_bytes", "x", accept_checkout_forms=False)

    def test_exact_crlf_domain_rejects_lf(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "canonical domain is crlf"):
            checksum.canonical_text_bytes(b"a\n", "crlf_text_bytes", "x", accept_checkout_forms=False)

    def test_raw_binary_bytes_are_not_transformed(self) -> None:
        binary = b"\x00\xff\r\n\n\r"
        self.assertEqual(checksum.sha256(binary), hashlib.sha256(binary).hexdigest())


class ManifestParsingTest(unittest.TestCase):
    def test_valid_manifest_line(self) -> None:
        entries = checksum.manifest_entries(manifest_line("payload.txt"), "SHA256SUMS.txt", exact_source=True)
        self.assertEqual(entries[0][1], "payload.txt")

    def test_duplicate_checksum_path_rejected(self) -> None:
        data = manifest_line("payload.txt") + manifest_line("payload.txt")
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Duplicate checksum path"):
            checksum.manifest_entries(data, "SHA256SUMS.txt", exact_source=True)

    def test_case_alias_checksum_path_rejected(self) -> None:
        data = manifest_line("Payload.txt") + manifest_line("payload.txt")
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Duplicate checksum path"):
            checksum.manifest_entries(data, "SHA256SUMS.txt", exact_source=True)

    def test_malformed_checksum_line_rejected(self) -> None:
        data = b"0" * 64 + b" payload.txt\n"
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Malformed checksum line"):
            checksum.manifest_entries(data, "SHA256SUMS.txt", exact_source=True)

    def test_absolute_manifest_path_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "repository-relative"):
            checksum.manifest_entries(manifest_line("/payload.txt"), "SHA256SUMS.txt", exact_source=True)

    def test_windows_absolute_manifest_path_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "repository-relative"):
            checksum.manifest_entries(manifest_line("C:/payload.txt"), "SHA256SUMS.txt", exact_source=True)

    def test_parent_escape_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "traverses"):
            checksum.manifest_entries(manifest_line("../payload.txt"), "SHA256SUMS.txt", exact_source=True)

    def test_encoded_traversal_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "encoded structural"):
            checksum.manifest_entries(manifest_line("%2e%2e/payload.txt"), "SHA256SUMS.txt", exact_source=True)

    def test_backslash_path_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "POSIX separators"):
            checksum.manifest_entries(manifest_line("dir\\payload.txt"), "SHA256SUMS.txt", exact_source=True)

    def test_ntfs_alternate_data_stream_path_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "not portable to Windows"):
            checksum.manifest_entries(manifest_line("payload.txt:stream"), "SHA256SUMS.txt", exact_source=True)

    def test_windows_device_path_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "reserved Windows device"):
            checksum.manifest_entries(manifest_line("dir/COM1.txt"), "SHA256SUMS.txt", exact_source=True)

    def test_windows_nul_device_path_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "reserved Windows device"):
            checksum.manifest_entries(manifest_line("NUL"), "SHA256SUMS.txt", exact_source=True)

    def test_windows_trailing_dot_path_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Windows-ambiguous trailing"):
            checksum.manifest_entries(manifest_line("dir./payload.txt"), "SHA256SUMS.txt", exact_source=True)

    def test_manifest_bom_rejected(self) -> None:
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "BOM is forbidden"):
            checksum.manifest_entries(b"\xef\xbb\xbf" + manifest_line("payload.txt"), "SHA256SUMS.txt", exact_source=True)

    def test_manifest_mixed_line_endings_rejected(self) -> None:
        data = b"# comment\r\n" + manifest_line("payload.txt")
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Mixed CRLF and LF"):
            checksum.manifest_entries(data, "SHA256SUMS.txt", exact_source=False)


class DomainDeclarationTest(unittest.TestCase):
    def test_complete_single_path_partition(self) -> None:
        assignment = checksum.declaration_domains(one_path_declaration(), {"payload.txt"})
        self.assertEqual(assignment, {"payload.txt": "lf_text_bytes"})

    def test_conflicting_mode_declaration_rejected(self) -> None:
        declaration = one_path_declaration()
        declaration["path_domains"]["raw_bytes"].append("payload.txt")
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Conflicting or duplicate"):
            checksum.declaration_domains(declaration, {"payload.txt"})

    def test_duplicate_mode_declaration_rejected(self) -> None:
        declaration = one_path_declaration()
        declaration["path_domains"]["lf_text_bytes"].append("payload.txt")
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Conflicting or duplicate"):
            checksum.declaration_domains(declaration, {"payload.txt"})

    def test_declared_path_absent_from_manifest_rejected(self) -> None:
        declaration = one_path_declaration("extra.txt")
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "partition mismatch"):
            checksum.declaration_domains(declaration, {"payload.txt"})

    def test_manifest_path_absent_from_declaration_rejected(self) -> None:
        declaration = one_path_declaration("payload.txt")
        declaration["expected_entries"] = 2
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "partition mismatch"):
            checksum.declaration_domains(declaration, {"payload.txt", "extra.txt"})

    def test_unknown_path_domain_rejected(self) -> None:
        declaration = one_path_declaration()
        declaration["path_domains"]["automatic_text"] = []
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "keys mismatch"):
            checksum.declaration_domains(declaration, {"payload.txt"})

    def test_non_sha256_algorithm_rejected(self) -> None:
        declaration = one_path_declaration()
        declaration["hash_algorithm"] = "sha1"
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Unsupported hash algorithm"):
            checksum.declaration_domains(declaration, {"payload.txt"})


class ConfigParsingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = (ROOT / checksum.CONFIG_RELATIVE).read_bytes()

    def test_duplicate_json_key_rejected(self) -> None:
        newline = b"\r\n" if b"\r\n" in self.config else b"\n"
        needle = (
            b'  "protected_git_baseline": "9a33e3866cde19939be22a903967bc94f566db76",'
            + newline
        )
        duplicate = needle + needle
        self.assertIn(needle, self.config)
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Duplicate JSON object key"):
            checksum.load_config(self.config.replace(needle, duplicate, 1))

    def test_nan_rejected(self) -> None:
        mutated = self.config.replace(b'"expected_total_entries": 74', b'"expected_total_entries": NaN', 1)
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Non-finite JSON number"):
            checksum.load_config(mutated)

    def test_infinity_rejected(self) -> None:
        mutated = self.config.replace(b'"expected_total_entries": 74', b'"expected_total_entries": Infinity', 1)
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Non-finite JSON number"):
            checksum.load_config(mutated)

    def test_float_entry_count_rejected(self) -> None:
        mutated = self.config.replace(b'"expected_total_entries": 74', b'"expected_total_entries": 74.0', 1)
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Floating-point JSON number"):
            checksum.load_config(mutated)

    def test_boolean_entry_count_rejected(self) -> None:
        mutated = self.config.replace(b'"expected_total_entries": 74', b'"expected_total_entries": true', 1)
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "expected_total_entries"):
            checksum.load_config(mutated)

    def test_wrong_repository_identity_rejected(self) -> None:
        mutated = self.config.replace(
            b'"repository": "https://github.com/Kot141078/c-hardening-pack"',
            b'"repository": "https://example.invalid/wrong-repository"',
            1,
        )
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "repository does not match"):
            checksum.load_config(mutated)

    def test_wrong_document_identity_rejected(self) -> None:
        mutated = self.config.replace(
            b'"document_id": "c-hardening-pack-v0.1-checksum-domain-portability"',
            b'"document_id": "unrelated-policy"',
            1,
        )
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "document_id does not match"):
            checksum.load_config(mutated)

    def test_manifest_declaration_alias_rejected(self) -> None:
        config = checksum.load_config(self.config)
        declarations = copy.deepcopy(config["manifests"])
        declarations[0]["path"] = "copied/SHA256SUMS.txt"
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Manifest declaration paths mismatch"):
            checksum.validate_manifest_declaration_paths(declarations)

    def test_duplicate_manifest_declaration_path_rejected(self) -> None:
        config = checksum.load_config(self.config)
        declarations = copy.deepcopy(config["manifests"])
        declarations[1]["path"] = declarations[0]["path"]
        with self.assertRaisesRegex(checksum.ChecksumDomainError, "Manifest declaration paths mismatch"):
            checksum.validate_manifest_declaration_paths(declarations)


class CommandLineBoundaryTest(unittest.TestCase):
    def test_worktree_rejects_git_ref_claim(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = checksum.main(["--source", "worktree", "--git-ref", "HEAD"])
        self.assertEqual(result, 1)
        self.assertIn("--git-ref is not valid with --source worktree", stderr.getvalue())


class FileBoundaryTest(unittest.TestCase):
    def test_missing_file_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = checksum.DirectorySource(Path(temporary), "test", exact_bytes=False)
            with self.assertRaisesRegex(checksum.ChecksumDomainError, "Missing source file"):
                source.read_bytes("missing.txt")

    @unittest.skipIf(os.name == "nt", "POSIX symlink coverage; Windows junction coverage is separate")
    def test_symlink_escape_rejected_where_supported(self) -> None:
        with tempfile.TemporaryDirectory() as root_name, tempfile.TemporaryDirectory() as outside_name:
            root = Path(root_name)
            outside = Path(outside_name) / "payload.txt"
            outside.write_bytes(b"payload")
            link = root / "payload.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable on this platform: {exc}")
            source = checksum.DirectorySource(root, "test", exact_bytes=False)
            with self.assertRaisesRegex(checksum.ChecksumDomainError, "Symlink or reparse"):
                source.read_bytes("payload.txt")

    @unittest.skipIf(os.name == "nt", "POSIX symlink coverage; Windows junction coverage is separate")
    def test_symlink_source_root_rejected_where_supported(self) -> None:
        with tempfile.TemporaryDirectory() as parent_name, tempfile.TemporaryDirectory() as target_name:
            parent = Path(parent_name)
            target = Path(target_name)
            (target / "payload.txt").write_bytes(b"payload")
            link = parent / "root-link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks unavailable on this platform: {exc}")
            source = checksum.DirectorySource(link, "test", exact_bytes=False)
            with self.assertRaisesRegex(checksum.ChecksumDomainError, "source root"):
                source.read_bytes("payload.txt")

    @unittest.skipUnless(os.name == "nt", "Windows junction coverage")
    def test_windows_descendant_junction_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root_name, tempfile.TemporaryDirectory() as target_name:
            root = Path(root_name)
            target = Path(target_name)
            (target / "payload.txt").write_bytes(b"payload")
            junction = root / "junction"
            create = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(create.returncode, 0, f"{create.stdout}{create.stderr}")
            try:
                source = checksum.DirectorySource(root, "test", exact_bytes=False)
                with self.assertRaisesRegex(checksum.ChecksumDomainError, "Symlink or reparse"):
                    source.read_bytes("junction/payload.txt")
            finally:
                os.rmdir(junction)

    @unittest.skipUnless(os.name == "nt", "Windows junction coverage")
    def test_windows_junction_source_root_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent_name, tempfile.TemporaryDirectory() as target_name:
            parent = Path(parent_name)
            target = Path(target_name)
            (target / "payload.txt").write_bytes(b"payload")
            junction = parent / "root-junction"
            create = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(create.returncode, 0, f"{create.stdout}{create.stderr}")
            try:
                source = checksum.DirectorySource(junction, "test", exact_bytes=False)
                with self.assertRaisesRegex(checksum.ChecksumDomainError, "source root"):
                    source.read_bytes("payload.txt")
            finally:
                os.rmdir(junction)

    def test_regular_in_root_file_is_read_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "payload.bin").write_bytes(b"\x00\xff")
            source = checksum.DirectorySource(root, "test", exact_bytes=False)
            self.assertEqual(source.read_bytes("payload.bin"), b"\x00\xff")


class CurrentRepositoryTest(unittest.TestCase):
    def test_current_worktree_has_exactly_74_valid_entries(self) -> None:
        result = checksum.verify_source(checksum.DirectorySource(ROOT, "worktree-test", exact_bytes=False))
        self.assertEqual(result.checked_entries, 74)
        self.assertEqual(result.manifest_count, 2)

    def test_policy_partitions_every_manifest_path_once(self) -> None:
        config = checksum.load_config((ROOT / checksum.CONFIG_RELATIVE).read_bytes())
        for declaration in config["manifests"]:
            manifest = (ROOT / declaration["path"]).read_bytes()
            paths = {path for _, path in checksum.manifest_entries(manifest, declaration["path"], exact_source=False)}
            domains = checksum.declaration_domains(copy.deepcopy(declaration), paths)
            self.assertEqual(set(domains), paths)
            self.assertEqual(len(domains), 37)

    def test_two_protected_manifests_remain_byte_identical(self) -> None:
        self.assertEqual((ROOT / "SHA256SUMS.txt").read_bytes(), (ROOT / "manifests" / "SHA256SUMS.txt").read_bytes())


class ReleaseArchiveModeTest(unittest.TestCase):
    def _materialize_canonical_archive(self, root: Path) -> None:
        config_bytes = (ROOT / checksum.CONFIG_RELATIVE).read_bytes()
        config = checksum.load_config(config_bytes)
        worktree_source = checksum.DirectorySource(ROOT, "worktree", exact_bytes=False)
        first_declaration = config["manifests"][0]
        manifest_bytes = worktree_source.read_bytes(first_declaration["path"])
        entries = checksum.manifest_entries(manifest_bytes, first_declaration["path"], exact_source=False)
        domains = checksum.declaration_domains(first_declaration, {path for _, path in entries})

        for declaration in config["manifests"]:
            target = root.joinpath(*declaration["path"].split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(
                checksum.normalized_manifest_bytes(
                    worktree_source.read_bytes(declaration["path"]), declaration["path"], exact_source=False
                )
            )

        for _, relative in entries:
            target = root.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            data = worktree_source.read_bytes(relative)
            domain = domains[relative]
            if domain != "raw_bytes":
                data = checksum.canonical_text_bytes(data, domain, relative, accept_checkout_forms=True)
            target.write_bytes(data)

    def test_materialized_release_archive_has_74_exact_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._materialize_canonical_archive(root)
            result = checksum.verify_source(
                checksum.DirectorySource(root, "release-test", exact_bytes=True),
                policy_source=checksum.DirectorySource(ROOT, "policy-worktree", exact_bytes=False),
            )
            self.assertEqual(result.checked_entries, 74)
            self.assertEqual(result.raw_digest_matches, 74)
            self.assertEqual(result.transformed_domain_matches, 0)

    def test_release_archive_crlf_domain_cannot_be_lf(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._materialize_canonical_archive(root)
            target = root / "manifests" / "FILE_LIST.csv"
            target.write_bytes(target.read_bytes().replace(b"\r\n", b"\n"))
            with self.assertRaisesRegex(checksum.ChecksumDomainError, "canonical domain is crlf"):
                checksum.verify_source(
                    checksum.DirectorySource(root, "release-test", exact_bytes=True),
                    policy_source=checksum.DirectorySource(ROOT, "policy-worktree", exact_bytes=False),
                )


class CleanCheckoutIntegrationTest(unittest.TestCase):
    def test_platform_clean_clone_representation(self) -> None:
        head_policy = subprocess.run(
            ["git", "show", "HEAD:CHECKSUM_DOMAIN.json"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if head_policy.returncode or b'"checksum-domain.v2"' not in head_policy.stdout:
            self.skipTest("candidate must be committed before exact clean-clone integration")

        autocrlf = "true" if os.name == "nt" else "false"
        expected_platform = "Windows core.autocrlf=true" if os.name == "nt" else "Linux core.autocrlf=false"
        with tempfile.TemporaryDirectory() as temporary:
            seed = Path(temporary) / "seed.git"
            clone = Path(temporary) / "clone"
            initialize = subprocess.run(
                ["git", "init", "--bare", str(seed)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(initialize.returncode, 0, initialize.stderr)
            fetch = subprocess.run(
                ["git", f"--git-dir={seed}", "fetch", "--no-tags", str(ROOT), "HEAD:refs/heads/candidate"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(fetch.returncode, 0, fetch.stderr)
            clone_process = subprocess.run(
                [
                    "git",
                    "-c",
                    f"core.autocrlf={autocrlf}",
                    "clone",
                    "--no-local",
                    "--no-hardlinks",
                    "--branch",
                    "candidate",
                    str(seed),
                    str(clone),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(clone_process.returncode, 0, clone_process.stderr)
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            checkout = subprocess.run(
                ["git", "checkout", "--detach", head],
                cwd=clone,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(checkout.returncode, 0, checkout.stderr)
            verify = subprocess.run(
                [sys.executable, str(clone / "tools" / "verify_checksum_domain.py"), "--source", "worktree"],
                cwd=clone,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(verify.returncode, 0, f"{expected_platform}: {verify.stdout}{verify.stderr}")
            self.assertIn("74/74 manifest entries", verify.stdout)


if __name__ == "__main__":
    unittest.main()
