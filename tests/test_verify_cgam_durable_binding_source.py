from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CgamDurableBindingSourceVerifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        path = cls.root / "tools" / "verify_cgam_durable_binding_source.py"
        spec = importlib.util.spec_from_file_location(
            "verify_cgam_durable_binding_source_test", path
        )
        assert spec is not None and spec.loader is not None
        cls.verifier = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.verifier
        spec.loader.exec_module(cls.verifier)
        cls.cgam_root = cls.root.parent / "c-governed-cli-agent-mesh"

    def test_exact_reference_and_source_pin_inventory(self) -> None:
        self.assertEqual(
            "47fed105d7b1df1df7375aa203a551b0f684c13d",
            self.verifier.IMPLEMENTATION_BASE_COMMIT,
        )
        self.assertEqual(
            "f1162ca73c508d1cd82544265f93ce5242c2aecb",
            self.verifier.IMPLEMENTATION_BASE_TREE,
        )
        self.assertEqual(
            "c3b004d7439a8c608f08233fc17be1150c442b44",
            self.verifier.CGAM_COMMIT,
        )
        self.assertEqual(
            "9a0b25d162f40347a4434b2bc9482b92e0170e85",
            self.verifier.CGAM_TREE,
        )
        self.assertEqual(5, len(self.verifier.IMPLEMENTATION_SOURCE_PINS))
        self.assertEqual(11, len(self.verifier.CGAM_SOURCE_PINS))
        self.assertEqual(
            {"journal_meta", "authority_heads", "attempts", "records"},
            set(self.verifier.EXPECTED_TABLES),
        )

    def test_implementation_freeze_blobs_match_exact_base(self) -> None:
        issues, evidence = self.verifier._pin_evidence(
            self.root,
            self.verifier.IMPLEMENTATION_BASE_COMMIT,
            self.verifier.IMPLEMENTATION_SOURCE_PINS,
            compare_worktree=True,
            issue_prefix="implementation",
        )
        self.assertEqual([], issues)
        self.assertEqual(5, len(evidence))
        self.assertTrue(
            all(
                item["blob_match"]
                and item["sha256_match"]
                and item["worktree_matches_blob"]
                for item in evidence
            )
        )
        self.assertEqual(39, len(self.verifier._protected_paths(self.root)))

    def test_additive_path_scope_is_exact_and_rejects_marker_conforming_extras(self) -> None:
        allowed = {
            ".github/workflows/cgam-durable-binding.yml",
            "docs/CGAM_DURABLE_BINDING_R6A_STATUS.md",
            "fixtures/cgam-durable-binding/MANIFEST.json",
            "fixtures/cgam-durable-binding/r6a_authority_revision_1_active.json",
            "fixtures/cgam-durable-binding/r6a_authority_revision_2_revoked.json",
            "fixtures/cgam-durable-binding/r6a_task_output.json",
            "schemas/cgam-durable-binding/r6a-cgam-authority-envelope-0.1.schema.json",
            "tests/r6a_scenario_registry.py",
            "tools/cgam_durable_binding.py",
            "tools/verify_cgam_durable_binding_source.py",
            "tests/test_cgam_durable_binding_crash.py",
            "tests/test_cgam_durable_binding.py",
            "tests/test_cgam_durable_binding_runtime_adapter.py",
            "tests/test_cgam_durable_binding_security.py",
            "tests/test_verify_cgam_durable_binding_source.py",
            "tools/cgam_durable_binding_runtime_adapter.py",
            "tools/run_cgam_durable_binding_suite.py",
        }
        rejected = (
            ".github/workflows/integrity.yml",
            ".github/workflows/cgam-durable-binding-copy.yml",
            "tools/unrelated.py",
            "tools/r6a_extra.py",
            "docs/CGAM_DURABLE_BINDING_R6A_EXTRA.md",
            "tests/test_runtime_integrity_extension.py",
            "README.md",
            "fixtures/cgam/fixture.json",
        )
        self.assertEqual(allowed, set(self.verifier.REQUIRED_R6A_ADDITIONS))
        for path in allowed:
            with self.subTest(path=path):
                self.assertTrue(self.verifier.allowed_r6a_addition(path))
        for path in rejected:
            with self.subTest(path=path):
                self.assertFalse(self.verifier.allowed_r6a_addition(path))

    def test_source_constraints_accept_exact_four_table_stdlib_core(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r6a-source-valid-") as temp:
            root = Path(temp)
            tools = root / "tools"
            tools.mkdir()
            core = tools / "cgam_durable_binding.py"
            core.write_text(
                """from __future__ import annotations
import os
import sqlite3
SCHEMA = '''
CREATE TABLE journal_meta (id INTEGER PRIMARY KEY);
CREATE TABLE authority_heads (id TEXT PRIMARY KEY);
CREATE TABLE attempts (id TEXT PRIMARY KEY);
CREATE TABLE records (id TEXT PRIMARY KEY);
'''
INTERNAL = '.c_binding'
DATABASE = 'binding_state.sqlite3'
LOCK = 'binding.lock'
PRAGMAS = ('journal_mode', 'DELETE', 'synchronous', 'FULL',
           'foreign_keys', 'ON', 'integrity_check')
""",
                encoding="utf-8",
            )
            runner = tools / "run_cgam_durable_binding_suite.py"
            runner.write_text(
                "from r6a_scenario_registry import EXPECTED_SCENARIO_IDS\n",
                encoding="utf-8",
            )
            issues, evidence = self.verifier.inspect_binding_sources(
                root,
                [
                    "tools/cgam_durable_binding.py",
                    "tools/run_cgam_durable_binding_suite.py",
                ],
            )
        self.assertEqual([], issues)
        self.assertEqual(4, evidence["table_create_statements"])
        self.assertEqual(
            ["attempts", "authority_heads", "journal_meta", "records"],
            evidence["tables"],
        )

    def test_source_constraints_reject_fifth_table_and_external_stack(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r6a-source-invalid-") as temp:
            root = Path(temp)
            tools = root / "tools"
            tools.mkdir()
            core = tools / "cgam_durable_binding.py"
            core.write_text(
                """import requests
SCHEMA = '''
CREATE TABLE journal_meta (id INTEGER PRIMARY KEY AUTOINCREMENT);
CREATE TABLE authority_heads (id TEXT PRIMARY KEY);
CREATE TABLE attempts (id TEXT PRIMARY KEY);
CREATE TABLE records (id TEXT PRIMARY KEY);
CREATE TABLE plugins (id TEXT PRIMARY KEY);
'''
# .c_binding binding_state.sqlite3 binding.lock
# journal_mode DELETE synchronous FULL foreign_keys ON integrity_check
""",
                encoding="utf-8",
            )
            runner = tools / "run_cgam_durable_binding_suite.py"
            runner.write_text(
                "import arbitrary_local_module\n",
                encoding="utf-8",
            )
            issues, _ = self.verifier.inspect_binding_sources(
                root,
                [
                    "tools/cgam_durable_binding.py",
                    "tools/run_cgam_durable_binding_suite.py",
                ],
            )
        self.assertIn("r6a_sqlite_table_surface_invalid", issues)
        self.assertIn("r6a_sqlite_autoincrement_forbidden", issues)
        self.assertTrue(
            any(item.endswith(":requests") for item in issues),
            issues,
        )
        self.assertTrue(
            any(item.endswith(":arbitrary_local_module") for item in issues),
            issues,
        )

    def test_exact_detached_cgam_checkout_and_raw_source_bytes(self) -> None:
        if not (self.cgam_root / ".git").exists():
            self.skipTest("pinned sibling CGAM checkout is not present")
        issues, evidence = self.verifier.audit_cgam(self.cgam_root)
        self.assertEqual([], issues)
        self.assertEqual(self.verifier.CGAM_COMMIT, evidence["head"])
        self.assertEqual(self.verifier.CGAM_TREE, evidence["tree"])
        self.assertTrue(evidence["detached"])
        self.assertEqual(11, len(evidence["source_pins"]))
        self.assertTrue(
            all(item["worktree_matches_blob"] for item in evidence["source_pins"])
        )

    def test_cgam_mutation_is_detected_without_touching_pinned_checkout(self) -> None:
        if not (self.cgam_root / ".git").exists():
            self.skipTest("pinned sibling CGAM checkout is not present")
        with tempfile.TemporaryDirectory(prefix="r6a-cgam-mutated-") as temp:
            clone = Path(temp) / "cgam"
            subprocess.run(
                ["git", "clone", "--quiet", "--no-local", str(self.cgam_root), str(clone)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "checkout", "--quiet", "--detach", self.verifier.CGAM_COMMIT],
                cwd=clone,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "remote", "set-url", "origin", self.verifier.CGAM_REMOTE],
                cwd=clone,
                check=True,
                capture_output=True,
            )
            readme = clone / "README.md"
            readme.write_bytes(readme.read_bytes() + b"\nmutation\n")
            issues, evidence = self.verifier.audit_cgam(clone)
        self.assertIn("cgam_worktree_dirty", issues)
        self.assertTrue(
            any(item.startswith("cgam_worktree_blob_mismatch:README.md") for item in issues),
            issues,
        )
        self.assertNotEqual("", evidence["status"])


if __name__ == "__main__":
    unittest.main()
