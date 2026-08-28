from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


class CgamDurableBindingRuntimeAdapterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        adapter_path = (
            cls.root / "tools" / "cgam_durable_binding_runtime_adapter.py"
        )
        spec = importlib.util.spec_from_file_location(
            "cgam_durable_binding_runtime_adapter_test", adapter_path
        )
        assert spec is not None and spec.loader is not None
        cls.adapter = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.adapter
        spec.loader.exec_module(cls.adapter)

    @classmethod
    def fixture(cls, name: str) -> dict:
        path = cls.root / "fixtures" / "runtime-integrity" / "positive" / name
        return json.loads(path.read_text(encoding="utf-8"))

    @classmethod
    def bound_bundle(cls) -> tuple[dict, dict, None]:
        return (
            cls.fixture("decision_basis_retry_b_valid.json"),
            cls.fixture("consequence_commit_retry_b_valid.json"),
            None,
        )

    @classmethod
    def denied_bundle(cls) -> tuple[dict, dict, dict]:
        return (
            cls.fixture("decision_basis_valid.json"),
            cls.fixture("consequence_commit_denied_valid.json"),
            cls.fixture("non_effect_witness_valid.json"),
        )

    def issue_codes(self, bundle: tuple[dict, dict, dict | None]) -> tuple[str, ...]:
        with self.assertRaises(self.adapter.RuntimeRecordValidationError) as caught:
            self.adapter.validate_runtime_bundle(*bundle)
        self.assertEqual(
            [(item.code, item.message) for item in caught.exception.issues],
            [(item["code"], item["message"]) for item in caught.exception.details],
        )
        for item in caught.exception.issues:
            self.assertIn(f"{item.code}: {item.message}", str(caught.exception))
        return caught.exception.codes

    def test_existing_positive_bound_bundle(self) -> None:
        self.assertIsNone(self.adapter.validate_runtime_bundle(*self.bound_bundle()))

    def test_existing_positive_denied_bundle(self) -> None:
        self.assertIsNone(self.adapter.validate_runtime_bundle(*self.denied_bundle()))

    def test_canonical_wrappers_delegate_to_existing_jcs(self) -> None:
        value = {"z": 1, "a": "two"}
        with mock.patch.object(
            self.adapter._RCI, "jcs_bytes", return_value=b"canonical"
        ) as bytes_mock:
            self.assertEqual(b"canonical", self.adapter.canonical_bytes(value))
        bytes_mock.assert_called_once_with(value)
        with mock.patch.object(
            self.adapter._RCI, "jcs_sha256", return_value="a" * 64
        ) as hash_mock:
            self.assertEqual("a" * 64, self.adapter.canonical_hash(value))
            self.assertEqual("a" * 64, self.adapter.canonical_sha256(value))
        self.assertEqual(2, hash_mock.call_count)

    def test_claim_boundaries_match_existing_positive_records(self) -> None:
        _, commit, witness = self.denied_bundle()
        self.assertEqual(
            commit["claim_boundary"],
            self.adapter.NOT_BOUND_COMMIT_CLAIM_BOUNDARY,
        )
        self.assertIsNotNone(witness)
        self.assertEqual(
            witness["claim_boundary"], self.adapter.WITNESS_CLAIM_BOUNDARY
        )
        self.assertEqual(
            self.adapter.WITNESS_CLAIM_BOUNDARY,
            self.adapter.witness_claim_boundary(),
        )

    def test_tampered_basis_hash_is_rejected(self) -> None:
        decision, commit, witness = self.denied_bundle()
        decision["basis_hash"] = "0" * 64
        commit["decision_basis_ref"]["hash"] = self.adapter.canonical_hash(decision)
        self.assertIn(
            "basis_hash_mismatch",
            self.issue_codes((decision, commit, witness)),
        )

    def test_tampered_witness_attempt_is_rejected(self) -> None:
        for fields in (
            ("attempt_ref",),
            ("gate_record_ref",),
            ("attempt_ref", "gate_record_ref"),
        ):
            decision, commit, witness = self.denied_bundle()
            for field in fields:
                witness[field] = "consequence-commit-unrelated"
            commit["non_effect_witness_ref"]["hash"] = self.adapter.canonical_hash(
                witness
            )
            with self.subTest(fields=fields):
                self.assertIn(
                    "non_effect_witness_attempt_mismatch",
                    self.issue_codes((decision, commit, witness)),
                )

    def test_witness_interval_excluding_attempt_is_rejected(self) -> None:
        decision, commit, witness = self.denied_bundle()
        witness["observation_window"]["start"] = "2026-08-27T10:03:01+02:00"
        commit["non_effect_witness_ref"]["hash"] = self.adapter.canonical_hash(witness)
        self.assertIn(
            "non_effect_witness_interval_excludes_attempt",
            self.issue_codes((decision, commit, witness)),
        )

    def test_tampered_witness_scope_or_target_is_rejected(self) -> None:
        for field, bad_value in (
            ("effect_scope_ref", "deploy:unrelated"),
            ("effect_target_ref", "endpoint:B"),
        ):
            decision, commit, witness = self.denied_bundle()
            witness[field] = bad_value
            commit["non_effect_witness_ref"]["hash"] = self.adapter.canonical_hash(
                witness
            )
            with self.subTest(field=field):
                self.assertIn(
                    "graph_witness_link_invalid",
                    self.issue_codes((decision, commit, witness)),
                )

    def test_not_bound_requires_strongest_non_effect_conclusion(self) -> None:
        for conclusion in ("UNRESOLVED", "EFFECT_DETECTED"):
            decision, commit, witness = self.denied_bundle()
            witness["conclusion"] = conclusion
            if conclusion == "EFFECT_DETECTED":
                witness["observation_surfaces"][0]["after_hash"] = "a" * 64
            commit["non_effect_witness_ref"]["hash"] = self.adapter.canonical_hash(
                witness
            )
            with self.subTest(conclusion=conclusion):
                self.assertIn(
                    "graph_witness_link_invalid",
                    self.issue_codes((decision, commit, witness)),
                )

    def test_tampered_full_record_hash_references_are_rejected(self) -> None:
        for ref_name, expected_code in (
            ("decision_basis_ref", "graph_decision_basis_link_invalid"),
            ("non_effect_witness_ref", "graph_witness_link_invalid"),
        ):
            decision, commit, witness = self.denied_bundle()
            commit[ref_name]["hash"] = "f" * 64
            with self.subTest(ref_name=ref_name):
                self.assertIn(
                    expected_code,
                    self.issue_codes((decision, commit, witness)),
                )

    def test_record_reference_id_and_version_are_exact(self) -> None:
        for ref_name, field, bad_value, expected_code in (
            (
                "decision_basis_ref",
                "artifact_id",
                "decision-basis-unrelated",
                "graph_decision_basis_link_invalid",
            ),
            (
                "decision_basis_ref",
                "version",
                "0.1.0",
                "graph_decision_basis_link_invalid",
            ),
            (
                "non_effect_witness_ref",
                "artifact_id",
                "non-effect-unrelated",
                "graph_witness_link_invalid",
            ),
            (
                "non_effect_witness_ref",
                "version",
                "0.1.0",
                "graph_witness_link_invalid",
            ),
        ):
            decision, commit, witness = self.denied_bundle()
            commit[ref_name][field] = bad_value
            with self.subTest(ref_name=ref_name, field=field):
                self.assertIn(
                    expected_code,
                    self.issue_codes((decision, commit, witness)),
                )

    def test_semantics_run_only_after_schema_success(self) -> None:
        decision, commit, witness = self.denied_bundle()
        del decision["record_id"]
        with mock.patch.object(
            self.adapter._RCI, "semantic_decision_basis"
        ) as semantic:
            codes = self.issue_codes((decision, commit, witness))
        self.assertIn("schema", codes)
        semantic.assert_not_called()

    def test_bound_bundle_rejects_supplied_witness(self) -> None:
        decision, commit, _ = self.bound_bundle()
        witness = self.fixture("non_effect_witness_valid.json")
        self.assertIn(
            "non_effect_witness_effect_state_mismatch",
            self.issue_codes((decision, commit, witness)),
        )


if __name__ == "__main__":
    unittest.main()
