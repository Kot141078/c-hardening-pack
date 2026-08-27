from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class RuntimeIntegrityR1FClosureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(
            "runtime_integrity_r1f_validator",
            cls.root / "tools" / "validate_runtime_integrity_extension.py",
        )
        assert spec is not None and spec.loader is not None
        cls.validator = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.validator
        spec.loader.exec_module(cls.validator)
        cls.fixture_root = cls.root / "fixtures" / "runtime-integrity"
        cls.manifest = cls.validator.load_json(cls.fixture_root / "MANIFEST.json")
        cls.schemas, cls.schema_registry = cls.validator.build_registry()

    def load(self, relative: str):
        return self.validator.load_json(self.fixture_root / relative)

    def test_exactly_reconstructed_62_scenarios(self) -> None:
        manifest = json.loads((self.root / "tests/adversarial/MANIFEST.json").read_text(encoding="utf-8"))
        ids = [item["id"] for item in manifest["scenarios"]]
        self.assertEqual(62, len(ids))
        self.assertEqual(62, len(set(ids)))
        self.assertEqual(62, manifest["recovered_scenario_count"])
        self.assertEqual(0, manifest["unrecovered_scenario_count"])
        proc = subprocess.run(
            [sys.executable, str(self.root / "tools/run_runtime_adversarial_suite.py")],
            cwd=self.root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(0, proc.returncode, f"{proc.stdout}\n{proc.stderr}")
        self.assertIn("scenarios=62 recovered=62 unrecovered=0 pass=62 fail=0", proc.stdout)
        expected_categories = {
            "BOUNDARY_PROBE": 8,
            "CONSEQUENCE_GRAPH": 12,
            "CONTINUITY_L4": 7,
            "EARTH_BUNDLE": 6,
            "EXTERNAL_INTAKE": 5,
            "JUDGE": 4,
            "MEMORY_RELIANCE": 8,
            "NON_EFFECT": 12,
        }
        for category, count in expected_categories.items():
            self.assertIn(
                f"category={category} scenarios={count} pass={count} fail=0",
                proc.stdout,
            )

    def test_strict_json_domain_rejects_ambiguous_inputs(self) -> None:
        invalid = (
            '{"a":1,"a":2}',
            '{"n":NaN}',
            '{"n":Infinity}',
            '{"n":1e400}',
            '{"n":9007199254740992}',
            '{"n":9007199254740992.0}',
            '{"n":9.007199254740992e15}',
            '{"s":"\\ud800"}',
        )
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(self.validator.JSONDomainError):
                self.validator.loads_json_strict(raw)

    def test_schema_date_time_format_is_strict_and_active(self) -> None:
        record = self.load("positive/external_intake_max_valid.json")
        record["created_at"] = "not-a-time"
        issues = self.validator.validate_schema(
            record,
            "urn:ivan-kotov:c-runtime-integrity:external-construct-intake-record:0.1.1",
            self.schemas,
            self.schema_registry,
        )
        self.assertIn("schema", {item.code for item in issues})

    def test_uniform_text_to_lf_profile_has_explicit_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lf = root / "lf.txt"
            crlf = root / "crlf.txt"
            empty = root / "empty.txt"
            lf.write_bytes(b"a\nb\n")
            crlf.write_bytes(b"a\r\nb\r\n")
            empty.write_bytes(b"")
            self.assertEqual(self.validator.uniform_text_to_lf_sha256(lf), self.validator.uniform_text_to_lf_sha256(crlf))
            self.assertEqual("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", self.validator.uniform_text_to_lf_sha256(empty))
            invalid = {
                "mixed.txt": b"a\r\nb\n",
                "bare-cr.txt": b"a\rb",
                "bom.txt": b"\xef\xbb\xbfa\n",
                "nul-binary.txt": b"a\x00b\n",
                "invalid-utf8.txt": b"\xff\xfe",
            }
            for name, payload in invalid.items():
                path = root / name
                path.write_bytes(payload)
                with self.subTest(name=name), self.assertRaises((self.validator.JSONDomainError, UnicodeDecodeError)):
                    self.validator.uniform_text_to_lf_sha256(path)

    def test_create_then_revert_is_not_non_effect(self) -> None:
        witness = self.load("positive/non_effect_witness_valid.json")
        original = self.validator.resolve_registered_evidence

        def create_then_revert(ref_id, registry):
            result = original(ref_id, registry)
            if ref_id == "evidence:event-log-42" and result is not None:
                artifact = copy.deepcopy(result[0])
                artifact["events"] = [
                    {
                        "event_id": "event:create-target-state",
                        "observed_at": "2026-08-27T10:03:10+02:00",
                        "surface_id": "target-state",
                        "operation": "CREATE",
                    },
                    {
                        "event_id": "event:revert-target-state",
                        "observed_at": "2026-08-27T10:03:20+02:00",
                        "surface_id": "target-state",
                        "operation": "REVERT",
                    },
                ]
                return artifact, self.validator.jcs_sha256(artifact)
            return result

        with mock.patch.object(
            self.validator,
            "resolve_registered_evidence",
            side_effect=create_then_revert,
        ):
            codes = {
                item.code for item in self.validator.validate_registered_evidence(
                    witness,
                    self.manifest["evidence_registry"],
                )
            }
        self.assertIn("non_effect_event_log_unresolved", codes)

    def test_changed_target_basis_and_transition_time_fail_closed(self) -> None:
        commit = self.load("positive/consequence_commit_retry_b_valid.json")
        old_basis = self.load("positive/decision_basis_valid.json")
        commit["decision_basis_ref"] = {
            "artifact_id": old_basis["record_id"],
            "version": self.validator.record_version(old_basis),
            "hash": self.validator.jcs_sha256(old_basis),
        }
        codes = {
            item.code for item in self.validator.validate_registered_links(
                commit,
                self.manifest["record_registry"],
                evidence_registry=self.manifest["evidence_registry"],
            )
        }
        self.assertIn("graph_decision_basis_context_mismatch", codes)

        commit = self.load("positive/consequence_commit_retry_b_valid.json")
        original = self.validator.resolve_artifact_ref_evidence

        def naive_transition(ref, registry):
            result = original(ref, registry)
            if result and result[0].get("evidence_kind") == "TARGET_TRANSITION":
                artifact = copy.deepcopy(result[0])
                artifact["observed_at"] = "2026-08-27T10:05:00"
                return artifact, self.validator.jcs_sha256(artifact)
            return result

        with mock.patch.object(self.validator, "resolve_artifact_ref_evidence", side_effect=naive_transition):
            codes = {item.code for item in self.validator.validate_registered_links(
                commit,
                self.manifest["record_registry"],
                evidence_registry=self.manifest["evidence_registry"],
            )}
        self.assertIn("target_transition_time_invalid", codes)

        for field, downgraded in (
            ("effect_class", "LOW"),
            ("reversibility", "REVERSIBLE"),
        ):
            commit = self.load("positive/consequence_commit_retry_b_valid.json")
            commit["target_effect"][field] = downgraded
            with self.subTest(effect_intent_field=field):
                codes = {
                    item.code for item in self.validator.validate_registered_links(
                        commit,
                        self.manifest["record_registry"],
                        evidence_registry=self.manifest["evidence_registry"],
                    )
                }
                self.assertIn("previous_commit_effect_intent_mismatch", codes)
                self.assertIn("target_transition_evidence_unresolved", codes)

    def test_judge_context_is_external_and_timestamp_strict(self) -> None:
        record = self.load("positive/judge_deliberation_valid.json")
        context = self.validator.load_json(self.root / "review-context/runtime-integrity-r1f.json")
        context["review_window"]["start"] = "2026-08-27 00:00:00+02:00"
        context_hash = self.validator.jcs_sha256(context)
        record["review_context_ref"]["hash"] = context_hash
        bindings = {key: context[key] for key in (
            "repository", "base_sha", "reviewed_parent_sha", "candidate_scope", "trust_root_class",
        )}
        codes = {item.code for item in self.validator.semantic_judge(record, context, context_hash, bindings)}
        self.assertIn("judge_review_context_window_mismatch", codes)

    def test_complete_predecessor_dag_mutations(self) -> None:
        original = self.load("positive/consequence_commit_denied_valid.json")

        def node(record_id, created_at, predecessor=None, lineage="lineage", effect="effect"):
            value = copy.deepcopy(original)
            value["record_id"] = record_id
            value["created_at"] = created_at
            value["consequence_lineage_id"] = lineage
            value["target_effect"]["effect_id"] = effect
            value["previous_commit_record_ref"] = predecessor
            if predecessor is None:
                value["change_reason_code"] = value["change_reason"] = value["target_transition_evidence_ref"] = None
            return value

        def ref(value):
            return {"artifact_id": value["record_id"], "version": self.validator.record_version(value), "hash": self.validator.jcs_sha256(value)}

        a = node("a", "2026-08-27T10:00:00Z")
        missing = node("m", "2026-08-27T10:01:00Z", {"artifact_id":"outside","version":"0.1.1","hash":"0" * 64})
        _, issues = self.validator.validate_previous_commit_dag({"a":"x","m":"y"}, {"a":a,"m":missing})
        self.assertIn("previous_graph_missing_predecessor", {item.code for item in issues})

        self_cycle = node("self", "2026-08-27T10:00:00Z", {"artifact_id":"self","version":"0.1.1","hash":"0" * 64})
        _, issues = self.validator.validate_previous_commit_dag({"self":"x"}, {"self":self_cycle})
        self.assertIn("previous_graph_cycle", {item.code for item in issues})

        b = node("b", "2026-08-27T10:01:00Z")
        a["previous_commit_record_ref"] = ref(b)
        b["previous_commit_record_ref"] = ref(a)
        _, issues = self.validator.validate_previous_commit_dag({"a":"x","b":"y"}, {"a":a,"b":b})
        self.assertIn("previous_graph_cycle", {item.code for item in issues})

        a = node("a", "2026-08-27T10:00:00Z")
        b = node("b", "2026-08-27T10:01:00Z", ref(a))
        c = node("c", "2026-08-27T10:02:00Z", ref(b))
        a["previous_commit_record_ref"] = ref(c)
        _, issues = self.validator.validate_previous_commit_dag({"a":"x","b":"y","c":"z"}, {"a":a,"b":b,"c":c})
        self.assertIn("previous_graph_cycle", {item.code for item in issues})

        earlier = node("earlier", "2026-08-27T10:02:00Z")
        later = node("later", "2026-08-27T10:01:00Z", ref(earlier), lineage="other", effect="other")
        _, issues = self.validator.validate_previous_commit_dag({"earlier":"x","later":"y"}, {"earlier":earlier,"later":later})
        codes = {item.code for item in issues}
        self.assertTrue({"previous_graph_timestamp_nonmonotonic","previous_graph_lineage_mismatch","previous_graph_effect_intent_mismatch"}.issubset(codes))

        for field, downgraded in (
            ("effect_class", "LOW"),
            ("reversibility", "REVERSIBLE"),
        ):
            predecessor = node(f"{field}-predecessor", "2026-08-27T10:00:00Z")
            successor = node(f"{field}-successor", "2026-08-27T10:01:00Z", ref(predecessor))
            successor["target_effect"][field] = downgraded
            with self.subTest(dag_effect_intent_field=field):
                _, issues = self.validator.validate_previous_commit_dag(
                    {predecessor["record_id"]: "x", successor["record_id"]: "y"},
                    {predecessor["record_id"]: predecessor, successor["record_id"]: successor},
                )
                self.assertIn("previous_graph_effect_intent_mismatch", {item.code for item in issues})

        duplicate = copy.deepcopy(a)
        _, issues = self.validator.validate_previous_commit_dag({"a":"x","alias":"y"}, {"a":a,"alias":duplicate})
        self.assertIn("previous_graph_duplicate_logical_record", {item.code for item in issues})

    def test_relation_specific_evidence_is_exactly_bound(self) -> None:
        cases = []
        functional = self.load("positive/external_taxonomy_functional_analog_valid.json")
        functional["relation_proof"]["mapping_refs"] = ["x"]
        cases.append(("functional mapping", functional, None, None, "functional_analog_proof_mismatch"))

        interface = self.load("positive/external_taxonomy_interface_adaptation_valid.json")
        transformation = self.validator.load_json(self.fixture_root / "evidence/taxonomy_transformation.json")
        transformation["adapted_interface_surface"] = "unrelated-surface"
        interface["relation_proof"]["transformation_evidence_refs"][0]["hash"] = self.validator.jcs_sha256(transformation)
        cases.append(("interface surface", interface, "taxonomy_transformation.json", transformation, "interface_adaptation_proof_mismatch"))

        formal = self.load("positive/external_taxonomy_formal_dependency_valid.json")
        dependency = self.validator.load_json(self.fixture_root / "evidence/taxonomy_dependency_proof.json")
        dependency["local_target"] = "docs/Runtime_Consequence_Integrity_Profile_for_c_v0_1.md"
        formal["dependency_evidence_refs"][0]["hash"] = self.validator.jcs_sha256(dependency)
        cases.append(("formal target", formal, "taxonomy_dependency_proof.json", dependency, "formal_dependency_proof_mismatch"))

        code = self.load("positive/external_taxonomy_code_reuse_valid.json")
        provenance = self.validator.load_json(self.fixture_root / "evidence/taxonomy_provenance.json")
        provenance["source_code_identity"] = "synthetic-taxonomy-source:0.1#other"
        code["relation_proof"]["provenance_evidence_refs"][0]["hash"] = self.validator.jcs_sha256(provenance)
        cases.append(("code provenance", code, "taxonomy_provenance.json", provenance, "code_reuse_record_requires_manual_review"))

        code_without_transform = self.load("positive/external_taxonomy_code_reuse_valid.json")
        code_without_transform["relation_proof"]["transformation_evidence_refs"] = []
        cases.append(("code transformation", code_without_transform, None, None, "code_reuse_record_requires_manual_review"))

        for name, record, artifact_name, artifact, expected in cases:
            original = self.validator.load_json

            def load_mutated(path, *, _name=artifact_name, _artifact=artifact):
                if _name and path.name == _name:
                    return copy.deepcopy(_artifact)
                return original(path)

            with self.subTest(name=name), mock.patch.object(self.validator, "load_json", side_effect=load_mutated):
                codes = {item.code for item in self.validator.semantic_external_intake(record)}
                self.assertIn(expected, codes)

        verified_comparison = self.load("positive/external_taxonomy_comparison_only_valid.json")
        verified_comparison["source_artifact"]["source_hash"] = "0" * 64
        codes = {item.code for item in self.validator.semantic_external_intake(verified_comparison)}
        self.assertIn("verified_source_artifact_unresolved", codes)

    def test_evidence_inventory_orphan_missing_alias_and_duplicate_guards(self) -> None:
        actual = {entry["path"] for entry in self.manifest["evidence_artifact_inventory"]}

        orphan_paths = set(actual)
        orphan_paths.add("fixtures/runtime-integrity/evidence/unregistered-orphan.json")
        codes = {
            item.code for item in self.validator.validate_manifest_registry(
                self.manifest,
                actual_evidence_paths_override=orphan_paths,
            )
        }
        self.assertIn("manifest_evidence_orphan_or_missing", codes)

        missing = copy.deepcopy(self.manifest)
        missing["evidence_artifact_inventory"].pop()
        codes = {
            item.code for item in self.validator.validate_manifest_registry(
                missing,
                actual_evidence_paths_override=actual,
            )
        }
        self.assertIn("manifest_evidence_orphan_or_missing", codes)

        aliased = copy.deepcopy(self.manifest)
        aliased["evidence_artifact_inventory"].append(
            copy.deepcopy(aliased["evidence_artifact_inventory"][0])
        )
        codes = {
            item.code for item in self.validator.validate_manifest_registry(
                aliased,
                actual_evidence_paths_override=actual,
            )
        }
        self.assertIn("manifest_duplicate_evidence_path", codes)

        duplicate_id = copy.deepcopy(self.manifest)
        duplicate_id["evidence_artifact_inventory"][1]["logical_ids"] = list(
            duplicate_id["evidence_artifact_inventory"][0]["logical_ids"]
        )
        codes = {
            item.code for item in self.validator.validate_manifest_registry(
                duplicate_id,
                actual_evidence_paths_override=actual,
            )
        }
        self.assertIn("manifest_duplicate_evidence_logical_id", codes)

        routes = next(
            entry for entry in self.manifest["evidence_artifact_inventory"]
            if entry["path"].endswith("non_effect_routes_42.json")
        )
        self.assertEqual(
            ["evidence:connector-disabled", "evidence:retry-cancelled", "evidence:capability-revoked"],
            routes["logical_ids"],
        )

    def test_manifest_and_exact_head_workflow_guards(self) -> None:
        self.assertEqual([], self.validator.validate_manifest_registry(self.manifest))
        workflow = (self.root / ".github/workflows/runtime-integrity-extension.yml").read_text(encoding="utf-8")
        self.assertIn("ubuntu-latest", workflow)
        self.assertIn("windows-latest", workflow)
        self.assertIn('["3.10", "3.12"]', workflow)
        self.assertIn("github.event.pull_request.head.sha || github.sha", workflow)
        self.assertIn("--require-hashes", workflow)


if __name__ == "__main__":
    unittest.main()
