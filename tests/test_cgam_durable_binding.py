from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

_TESTS_ROOT = str(Path(__file__).resolve().parent)
if _TESTS_ROOT not in sys.path:
    sys.path.insert(0, _TESTS_ROOT)
import r6a_scenario_registry as r6a_scenarios


class CgamDurableBindingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        path = cls.root / "tools" / "cgam_durable_binding.py"
        tools = str(path.parent)
        if tools not in sys.path:
            sys.path.insert(0, tools)
        spec = importlib.util.spec_from_file_location("cgam_durable_binding_test", path)
        assert spec is not None and spec.loader is not None
        cls.binding = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.binding
        spec.loader.exec_module(cls.binding)
        cls.fixture_root = cls.root / "fixtures" / "cgam-durable-binding"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="r6a-binding-")
        self.sandbox = Path(self.temp.name) / "sandbox"
        self.sandbox.mkdir()
        shutil.copyfile(self.fixture_root / "r6a_task_output.json", self.sandbox / "task.json")
        shutil.copyfile(
            self.fixture_root / "r6a_authority_revision_1_active.json",
            self.sandbox / "authority.json",
        )
        self.initial = self.binding.initialize_binding(self.sandbox)
        self.instance = self.initial["journal_instance_id"]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _json(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_json(self, path: Path, value: dict) -> None:
        path.write_bytes(self.binding.canonical_bytes(value) + b"\n")

    def _bind(self, payload: bytes = b"earth-bound-payload\n", **kwargs):
        return self.binding.bind_text(
            self.sandbox,
            task_basename="task.json",
            authority_basename="authority.json",
            target_basename="output.txt",
            payload=payload,
            attempt_id=str(uuid.uuid4()),
            expected_instance_id=self.instance,
            **kwargs,
        )

    def _revoked_successor(self) -> dict:
        revision_one = self._json(self.sandbox / "authority.json")
        successor = json.loads(json.dumps(revision_one))
        successor["authority_revision"] = 2
        successor["previous_grant_hash"] = self.binding.canonical_hash(
            revision_one["grant_payload"]
        )
        successor["grant_payload"]["grant_status"] = "REVOKED"
        successor["grant_payload"]["updated_at"] = "2026-08-28T00:01:00Z"
        successor["grant_payload"]["revocation"]["status"] = "REVOKED"
        successor["grant_payload"]["revocation"]["decision"] = "DENY"
        successor["grant_payload"]["revocation"]["summary"] = "Owner revoked before consequence"
        return successor

    def test_exact_sqlite_profile_and_four_table_schema(self) -> None:
        self.assertEqual("DELETE", self.initial["journal_mode"])
        self.assertEqual(2, self.initial["synchronous"])
        self.assertEqual(1, self.initial["foreign_keys"])
        self.assertEqual("ok", self.initial["integrity_check"])
        self.assertEqual(4, self.initial["table_count"])
        database = self.sandbox / ".c_binding" / "binding_state.sqlite3"
        with sqlite3.connect(database) as conn:
            names = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            self.assertEqual(
                {"journal_meta", "authority_heads", "attempts", "records"}, names
            )
            self.assertFalse(
                conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='sqlite_sequence'"
                ).fetchone()
            )

    @r6a_scenarios.scenario("R6A-CURRENT-001-VALID-WRITE")
    def test_real_allowed_effect_returns_only_durable_readback_records(self) -> None:
        payload = b"deterministic earth bytes\n"
        result = self._bind(payload)
        self.assertEqual("RECORDED_BOUND", result["state"])
        self.assertEqual("AUTHORIZED_EFFECT", result["reason_code"])
        self.assertTrue(result["durable_readback"])
        self.assertEqual(payload, (self.sandbox / "output.txt").read_bytes())
        self.assertEqual(
            {"decision_basis", "consequence_commit"}, set(result["records"])
        )
        commit = result["records"]["consequence_commit"]
        self.assertEqual("OPEN", commit["commit_outcome"])
        self.assertEqual("BOUND", commit["effect_state"])
        self.assertEqual(self.binding._sha256(payload), commit["effect_artifact_hash"])
        self.binding.validate_runtime_bundle(
            result["records"]["decision_basis"], commit, None
        )
        self.assertEqual([], list(self.sandbox.glob(".c_binding_payload_*")))
        repeated = self.binding.bind_text(
            self.sandbox,
            task_basename="task.json",
            authority_basename="authority.json",
            target_basename="output.txt",
            payload=payload,
            attempt_id=result["attempt_id"],
            expected_instance_id=self.instance,
        )
        self.assertEqual(result["record_set_hash"], repeated["record_set_hash"])

    @r6a_scenarios.scenario("R6A-PATH-009-ALREADY-SATISFIED")
    def test_mandatory_already_satisfied_guard_never_prepares_or_replaces(self) -> None:
        payload = b"pre-existing equal bytes\n"
        target = self.sandbox / "output.txt"
        target.write_bytes(payload)
        before = os.lstat(target)
        result = self._bind(payload)
        after = os.lstat(target)
        self.assertEqual("RECORDED_NOT_BOUND", result["state"])
        self.assertEqual("ALREADY_SATISFIED", result["reason_code"])
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual("HOLD", result["records"]["consequence_commit"]["commit_outcome"])
        self.assertEqual("NOT_BOUND", result["records"]["consequence_commit"]["effect_state"])
        self.assertEqual(
            "NO_EFFECT_OBSERVED_WITHIN_DECLARED_SCOPE",
            result["records"]["non_effect_witness"]["conclusion"],
        )
        database = self.sandbox / ".c_binding" / "binding_state.sqlite3"
        with sqlite3.connect(database) as conn:
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM attempts WHERE state='PREPARED'").fetchone()[0])
        self.assertEqual([], list(self.sandbox.glob(".c_binding_payload_*")))

    @r6a_scenarios.scenario("R6A-CURRENT-002-REVOKED-AFTER-PLANNING")
    def test_final_boundary_revocation_prevents_replace(self) -> None:
        target = self.sandbox / "output.txt"
        target.write_bytes(b"original\n")
        successor = self._revoked_successor()

        def revoke(_: Path) -> None:
            self._write_json(self.sandbox / "authority.json", successor)

        result = self._bind(b"must-not-land\n", before_final_revalidation=revoke)
        self.assertEqual("RECORDED_NOT_BOUND", result["state"])
        self.assertEqual("REVOKED_PERMISSION", result["reason_code"])
        self.assertEqual(b"original\n", target.read_bytes())
        self.assertEqual("DENY", result["records"]["consequence_commit"]["commit_outcome"])
        self.assertEqual([], list(self.sandbox.glob(".c_binding_payload_*")))

    @r6a_scenarios.scenario("R6A-EARTH-001-ROLLBACK-AFTER-REVOCATION")
    def test_earth_rollback_after_revocation_and_restart_is_denied(self) -> None:
        payload = b"earth revision one effect\n"
        first = self._bind(payload)
        self.assertEqual("RECORDED_BOUND", first["state"])
        revision_one = self._json(self.fixture_root / "r6a_authority_revision_1_active.json")
        successor = self._revoked_successor()
        self.binding.cooperative_write_authority(
            self.sandbox,
            authority_basename="authority.json",
            envelope=successor,
            expected_instance_id=self.instance,
        )
        revoked = self._bind(b"revoked bytes must not land\n")
        self.assertEqual("DENIED", revoked["state"])
        self.assertEqual("REVOKED_PERMISSION", revoked["reason_code"])
        self.assertEqual(payload, (self.sandbox / "output.txt").read_bytes())
        # Model stale-revision replay at the binder input boundary.  The
        # cooperative writer rejects this publication separately; this raw
        # restoration is required to exercise the durable journal comparison.
        self._write_json(self.sandbox / "authority.json", revision_one)
        rollback = self._bind(b"restored stale bytes must not land\n")
        self.assertEqual("DENIED", rollback["state"])
        self.assertEqual("AUTHORITY_ROLLBACK", rollback["reason_code"])
        self.assertEqual("DENY", rollback["records"]["consequence_commit"]["commit_outcome"])
        self.assertEqual("NOT_BOUND", rollback["records"]["consequence_commit"]["effect_state"])
        self.assertEqual(payload, (self.sandbox / "output.txt").read_bytes())
        self.assertEqual([], list(self.sandbox.glob(".c_binding_payload_*")))

    def test_runtime_record_basis_binds_every_contract_required_value(self) -> None:
        result = self._bind()
        decision = result["records"]["decision_basis"]
        refs = decision["basis"]["evidence_refs"]
        ids = {ref["artifact_id"] for ref in refs}
        required_prefixes = (
            "R6A:CGAM_SOURCE_PASSPORT",
            "R6A:TASK:",
            "R6A:AUTHORITY_ENVELOPE",
            "R6A:GRANT_PAYLOAD",
            "R6A:JOURNAL:",
            "R6A:ATTEMPT:",
            "R6A:PAYLOAD",
            "R6A:TARGET:",
            "R6A:EXPIRY_EVALUATION",
            "R6A:THREAT_PROFILE",
        )
        for prefix in required_prefixes:
            self.assertTrue(any(item.startswith(prefix) for item in ids), prefix)
        self.assertEqual(
            self.binding.THREAT_PROFILE_SHA256,
            next(ref["hash"] for ref in refs if ref["artifact_id"] == "R6A:THREAT_PROFILE"),
        )

    def test_platform_readback_is_truthful_and_no_power_loss_claim_is_present(self) -> None:
        result = self._bind()
        flush = result["directory_flush"]
        if os.name == "nt":
            self.assertEqual(
                {"supported": False, "result": "UNSUPPORTED_BY_PYTHON_STDLIB_ON_WINDOWS"},
                flush,
            )
        else:
            self.assertEqual({"supported": True, "result": "FSYNC_OK"}, flush)
        inspected = self.binding.inspect_binding(
            self.sandbox, expected_instance_id=self.instance
        )
        self.assertEqual("DELETE", inspected["journal_mode"])
        self.assertEqual(2, inspected["synchronous"])
        self.assertEqual("ok", inspected["integrity_check"])
        self.assertEqual(0, inspected["prepared_count"])
        self.assertNotIn("power-loss", json.dumps(result).casefold())


if __name__ == "__main__":
    unittest.main()
