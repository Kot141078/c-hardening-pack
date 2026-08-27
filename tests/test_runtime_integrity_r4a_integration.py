from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


class RuntimeIntegrityR4AIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        cls.integration = cls.load_module(
            "runtime_integrity_r4a_integration_verifier_test",
            cls.root / "tools/verify_r4a_integration.py",
        )
        cls.pins = cls.load_module(
            "runtime_integrity_r4a_pin_verifier_test",
            cls.root / "tools/verify_github_actions_pins.py",
        )

    @staticmethod
    def load_module(name: str, path: Path):
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def test_final_integration_lineage_union_scope_and_cleanliness(self) -> None:
        issues, evidence = self.integration.audit()
        self.assertEqual([], issues)
        self.assertEqual(143, evidence["union_paths"])
        self.assertEqual(39, evidence["protected"])
        self.assertEqual(0, evidence["deletions"])
        self.assertEqual(0, evidence["diff_check_exit"])

    def test_exact_normalization_bytes(self) -> None:
        evidence = self.integration.normalization_evidence()
        self.assertEqual(3984, evidence["preimage_bytes"])
        self.assertEqual(3982, evidence["postimage_bytes"])
        self.assertEqual(
            self.integration.EXPECTED_PATCH_SHA256,
            evidence["patch_sha256"],
        )
        self.assertTrue(evidence["only_authorized_substitutions"])
        self.assertTrue(evidence["lf_only"])
        self.assertTrue(evidence["no_bom"])
        self.assertTrue(evidence["final_lf"])

    def test_exact_merge_order_and_ancestor_boundaries(self) -> None:
        self.assertEqual(
            [self.integration.MAIN, self.integration.CHECKSUM],
            self.integration.parents(self.integration.CHECKSUM_MERGE),
        )
        self.assertEqual(
            [self.integration.CHECKSUM_MERGE, self.integration.RUNTIME],
            self.integration.parents(self.integration.RUNTIME_MERGE),
        )
        self.assertTrue(self.integration.is_ancestor(self.integration.CHECKSUM))
        self.assertTrue(self.integration.is_ancestor(self.integration.RUNTIME))
        self.assertFalse(self.integration.is_ancestor(self.integration.FAILED_R2))
        self.assertFalse(self.integration.is_ancestor(self.integration.ABANDONED_R4))

    def test_repository_action_inventory_and_pins(self) -> None:
        issues, workflows, refs = self.pins.audit_repository()
        self.assertEqual([], issues)
        self.assertEqual(2, workflows)
        self.assertEqual(5, refs)

    def test_duplicate_omitted_and_ambiguous_inventory_fails(self) -> None:
        runtime = ".github/workflows/runtime-integrity-extension.yml"
        issues, _, _ = self.pins.audit_repository(
            workflow_inventory=[runtime, runtime]
        )
        self.assertTrue(any("duplicate workflow inventory" in issue for issue in issues))
        self.assertTrue(any("omitted from audit inventory" in issue for issue in issues))

        case_issues, _, _ = self.pins.audit_repository(
            workflow_inventory=[
                ".github/workflows/integrity.yml",
                ".github/workflows/INTEGRITY.yml",
            ]
        )
        self.assertTrue(any("case-ambiguous" in issue for issue in case_issues))

    def test_new_tracked_workflow_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r4a-workflow-inventory-") as temp:
            root = Path(temp)
            workflow_root = root / ".github" / "workflows"
            workflow_root.mkdir(parents=True)
            for relative in self.pins.EXPECTED_WORKFLOW_PATHS:
                source = self.root / relative
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            (workflow_root / "unregistered.yml").write_text(
                "name: Unregistered\n", encoding="utf-8"
            )
            issues, _, _ = self.pins.audit_repository(root=root)
            self.assertTrue(any("omitted from audit inventory" in issue for issue in issues))

    def test_status_uses_immutable_self_reference_boundary(self) -> None:
        status = (self.root / "RUNTIME_INTEGRITY_R4A_STATUS.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "FINAL_HEAD := the Git commit whose tree contains this exact status artifact",
            status,
        )
        self.assertIn(
            "FINAL_TREE := the tree object directly referenced by FINAL_HEAD",
            status,
        )
        self.assertNotIn("TBD", status)
        self.assertNotIn("PLACEHOLDER", status)


if __name__ == "__main__":
    unittest.main()
