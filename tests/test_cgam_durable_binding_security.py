from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

_TESTS_ROOT = str(Path(__file__).resolve().parent)
if _TESTS_ROOT not in sys.path:
    sys.path.insert(0, _TESTS_ROOT)
import r6a_scenario_registry as r6a_scenarios


class CgamDurableBindingSecurityTest(unittest.TestCase):
    """Fail-closed R6A authority, perimeter, and journal security matrix."""

    CHECKED_AT = "2030-01-01T00:00:00Z"

    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        module_path = cls.root / "tools" / "cgam_durable_binding.py"
        tools = str(module_path.parent)
        if tools not in sys.path:
            sys.path.insert(0, tools)
        spec = importlib.util.spec_from_file_location(
            "cgam_durable_binding_security_test", module_path
        )
        assert spec is not None and spec.loader is not None
        cls.binding = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.binding
        spec.loader.exec_module(cls.binding)
        cls.fixture_root = cls.root / "fixtures" / "cgam-durable-binding"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="r6a-security-")
        self._case_number = 0
        self.sandbox, self.instance = self._make_sandbox("primary")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _make_sandbox(self, label: str) -> tuple[Path, str]:
        self._case_number += 1
        sandbox = Path(self.temp.name) / f"{self._case_number:03d}-{label}"
        sandbox.mkdir()
        shutil.copyfile(
            self.fixture_root / "r6a_task_output.json", sandbox / "task.json"
        )
        shutil.copyfile(
            self.fixture_root / "r6a_authority_revision_1_active.json",
            sandbox / "authority.json",
        )
        initialized = self.binding.initialize_binding(sandbox)
        return sandbox, initialized["journal_instance_id"]

    @staticmethod
    def _json(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_json(self, path: Path, value: dict) -> None:
        path.write_bytes(self.binding.canonical_bytes(value) + b"\n")

    def _bind(
        self,
        payload: bytes = b"security-matrix-payload\n",
        *,
        sandbox: Path | None = None,
        instance: str | None = None,
        target: str = "output.txt",
        checked_at: str | None = None,
        attempt_id: str | None = None,
        before_final_revalidation=None,
    ) -> dict:
        case = sandbox or self.sandbox
        journal_instance = instance or self.instance
        with mock.patch.object(
            self.binding, "_utc_now", return_value=checked_at or self.CHECKED_AT
        ):
            return self.binding.bind_text(
                case,
                task_basename="task.json",
                authority_basename="authority.json",
                target_basename=target,
                payload=payload,
                attempt_id=attempt_id or str(uuid.uuid4()),
                expected_instance_id=journal_instance,
                before_final_revalidation=before_final_revalidation,
            )

    def _write_authority(
        self, envelope: dict, *, sandbox: Path | None = None, instance: str | None = None
    ) -> None:
        case = sandbox or self.sandbox
        journal_instance = instance or self.instance
        self.binding.cooperative_write_authority(
            case,
            authority_basename="authority.json",
            envelope=envelope,
            expected_instance_id=journal_instance,
        )

    def _revision_one(self, sandbox: Path | None = None) -> dict:
        return self._json((sandbox or self.sandbox) / "authority.json")

    def _successor(
        self,
        predecessor: dict,
        *,
        revision: int = 2,
        previous_hash: str | None = None,
        status: str = "ACTIVE",
    ) -> dict:
        successor = copy.deepcopy(predecessor)
        successor["authority_revision"] = revision
        successor["previous_grant_hash"] = (
            previous_hash
            if previous_hash is not None
            else self.binding.canonical_hash(predecessor["grant_payload"])
        )
        grant = successor["grant_payload"]
        grant["updated_at"] = f"2026-08-28T00:0{min(revision, 9)}:00Z"
        grant["grant_status"] = status
        if status == "REVOKED":
            grant["revocation"].update(
                {
                    "summary": "Owner revoked before consequence",
                    "status": "REVOKED",
                    "decision": "DENY",
                }
            )
        elif status == "EXPIRED":
            grant["revocation"].update(
                {"status": "NOT_REVOKED", "decision": "ALLOW"}
            )
        return successor

    def _database(self, sandbox: Path | None = None) -> Path:
        return (sandbox or self.sandbox) / ".c_binding" / "binding_state.sqlite3"

    def _head(self, sandbox: Path | None = None) -> dict:
        with sqlite3.connect(self._database(sandbox)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM authority_heads").fetchone()
            self.assertIsNotNone(row)
            return dict(row)

    def _assert_denied(
        self, result: dict, reason: str | None = None, *, sandbox: Path | None = None
    ) -> None:
        self.assertIn(result["state"], {"DENIED", "RECORDED_NOT_BOUND"})
        if reason is not None:
            self.assertEqual(reason, result["reason_code"])
        commit = result["records"]["consequence_commit"]
        self.assertEqual("DENY", commit["commit_outcome"])
        self.assertEqual("NOT_BOUND", commit["effect_state"])
        self.assertIn("non_effect_witness", result["records"])
        self.assertFalse(((sandbox or self.sandbox) / "output.txt").exists())

    def _assert_quarantine_error(self, call, *args, **kwargs) -> str:
        with self.assertRaises(self.binding.BindingError) as caught:
            call(*args, **kwargs)
        self.assertEqual("QUARANTINED_UNRESOLVED", caught.exception.state)
        return caught.exception.code

    @r6a_scenarios.scenario("R6A-AUTH-001")
    def test_r6a_auth_001_initial_active_revision_one(self) -> None:
        result = self._bind(b"auth-001\n")
        self.assertEqual("RECORDED_BOUND", result["state"])
        self.assertEqual("AUTHORIZED_EFFECT", result["reason_code"])
        self.assertEqual(b"auth-001\n", (self.sandbox / "output.txt").read_bytes())
        head = self._head()
        self.assertEqual(1, head["authority_revision"])
        self.assertIsNone(head["previous_grant_hash"])
        self.assertEqual("VALID", head["effective_status"])

    @r6a_scenarios.scenario("R6A-AUTH-002")
    def test_r6a_auth_002_idempotent_same_revision_and_hash(self) -> None:
        first = self._bind(b"auth-002-first\n")
        original_head = self._head()
        second = self._bind(b"auth-002-second\n")
        repeated_head = self._head()
        self.assertEqual("RECORDED_BOUND", first["state"])
        self.assertEqual("RECORDED_BOUND", second["state"])
        self.assertEqual(original_head["grant_hash"], repeated_head["grant_hash"])
        self.assertEqual(original_head["envelope_hash"], repeated_head["envelope_hash"])
        self.assertEqual(1, repeated_head["authority_revision"])
        self.assertEqual(b"auth-002-second\n", (self.sandbox / "output.txt").read_bytes())

    @r6a_scenarios.scenario("R6A-AUTH-003")
    def test_r6a_auth_003_revoked_successor_becomes_current_head(self) -> None:
        revision_one = self._revision_one()
        self._bind(b"auth-003-original\n")
        revoked = self._successor(revision_one, status="REVOKED")
        self._write_authority(revoked)
        result = self._bind(b"auth-003-must-not-land\n")
        self.assertEqual("DENIED", result["state"])
        self.assertEqual("REVOKED_PERMISSION", result["reason_code"])
        self.assertEqual(b"auth-003-original\n", (self.sandbox / "output.txt").read_bytes())
        head = self._head()
        self.assertEqual(2, head["authority_revision"])
        self.assertEqual("REVOKED", head["effective_status"])

    @r6a_scenarios.scenario("R6A-AUTH-004")
    def test_r6a_auth_004_restart_then_restored_revision_is_rollback(self) -> None:
        revision_one = self._revision_one()
        self._bind(b"auth-004-original\n")
        revoked = self._successor(revision_one, status="REVOKED")
        self._write_authority(revoked)
        revoked_result = self._bind(b"auth-004-revoked\n")
        self.assertEqual("REVOKED_PERMISSION", revoked_result["reason_code"])
        # Every call closes and reopens the durable journal.  This explicit
        # inspection represents the process-restart readback boundary.
        reopened = self.binding.inspect_binding(
            self.sandbox, expected_instance_id=self.instance
        )
        self.assertEqual(1, reopened["authority_head_count"])
        # Replay the old raw binder input after restart.  Cooperative writer
        # rejection is covered independently; this exercises journal rollback
        # detection and durable denial records at the consequence boundary.
        self._write_json(self.sandbox / "authority.json", revision_one)
        rollback = self._bind(b"auth-004-restored-stale\n")
        self.assertEqual("DENIED", rollback["state"])
        self.assertEqual("AUTHORITY_ROLLBACK", rollback["reason_code"])
        self.assertEqual(b"auth-004-original\n", (self.sandbox / "output.txt").read_bytes())
        self.assertEqual(2, self._head()["authority_revision"])

    @r6a_scenarios.scenario("R6A-AUTH-005")
    def test_r6a_auth_005_same_revision_changed_bytes_is_equivocation(self) -> None:
        self._bind(b"auth-005-original\n")
        equivocation = self._revision_one()
        equivocation["grant_payload"]["updated_at"] = "2026-08-28T00:09:00Z"
        self._write_json(self.sandbox / "authority.json", equivocation)
        result = self._bind(b"auth-005-must-not-land\n")
        self.assertEqual("DENIED", result["state"])
        self.assertEqual("AUTHORITY_EQUIVOCATION", result["reason_code"])
        self.assertEqual(b"auth-005-original\n", (self.sandbox / "output.txt").read_bytes())

    @r6a_scenarios.scenario("R6A-AUTH-006")
    def test_r6a_auth_006_skipped_revision_is_gap(self) -> None:
        revision_one = self._revision_one()
        self._bind(b"auth-006-original\n")
        revision_three = self._successor(revision_one, revision=3)
        self._write_json(self.sandbox / "authority.json", revision_three)
        result = self._bind(b"auth-006-must-not-land\n")
        self.assertEqual("DENIED", result["state"])
        self.assertEqual("AUTHORITY_REVISION_GAP", result["reason_code"])
        self.assertEqual(1, self._head()["authority_revision"])
        self.assertEqual(b"auth-006-original\n", (self.sandbox / "output.txt").read_bytes())

    @r6a_scenarios.scenario("R6A-AUTH-007")
    def test_r6a_auth_007_wrong_predecessor_hash_is_rejected(self) -> None:
        revision_one = self._revision_one()
        self._bind(b"auth-007-original\n")
        wrong = self._successor(revision_one, previous_hash="f" * 64)
        self._write_json(self.sandbox / "authority.json", wrong)
        result = self._bind(b"auth-007-must-not-land\n")
        self.assertEqual("DENIED", result["state"])
        self.assertEqual("AUTHORITY_PREDECESSOR_MISMATCH", result["reason_code"])
        self.assertEqual(1, self._head()["authority_revision"])
        self.assertEqual(b"auth-007-original\n", (self.sandbox / "output.txt").read_bytes())

    @r6a_scenarios.scenario("R6A-AUTH-008")
    def test_r6a_auth_008_missing_or_corrupt_established_journal_quarantines(self) -> None:
        for mode in ("database-missing", "directory-missing", "database-corrupt"):
            with self.subTest(mode=mode):
                sandbox, instance = self._make_sandbox(mode)
                self._bind(b"auth-008-original\n", sandbox=sandbox, instance=instance)
                target = sandbox / "output.txt"
                before = target.read_bytes()
                internal = sandbox / ".c_binding"
                database = internal / "binding_state.sqlite3"
                if mode == "database-missing":
                    database.unlink()
                elif mode == "directory-missing":
                    self.assertTrue(internal.resolve().is_relative_to(Path(self.temp.name).resolve()))
                    shutil.rmtree(internal)
                else:
                    database.write_bytes(b"not-a-sqlite-database")
                code = self._assert_quarantine_error(
                    self._bind,
                    b"auth-008-must-not-land\n",
                    sandbox=sandbox,
                    instance=instance,
                )
                self.assertIn(
                    code,
                    {
                        "JOURNAL_MISSING",
                        "JOURNAL_MISSING_AFTER_ESTABLISHMENT",
                        "JOURNAL_INSTANCE_MISMATCH",
                        "SQLITE_OPEN_OR_INTEGRITY_FAILURE",
                        "SQLITE_INTEGRITY_CHECK",
                    },
                )
                self.assertEqual(before, target.read_bytes())
                if mode == "directory-missing":
                    self.assertFalse(
                        database.exists(),
                        "an expected established journal must never be silently recreated",
                    )

    def test_current_scope_status_expiry_identity_and_prohibition_matrix(self) -> None:
        def task_authority_stale(task: dict, _: dict) -> None:
            task["authority"]["status"] = "STALE"

        def task_authority_denied(task: dict, _: dict) -> None:
            task["authority"]["decision"] = "DENY"

        def task_gate_denied(task: dict, _: dict) -> None:
            task["decision"] = "DENY"

        def task_scope_stale(task: dict, _: dict) -> None:
            task["scope"]["status"] = "STALE"

        def task_scope_denied(task: dict, _: dict) -> None:
            task["scope"]["decision"] = "DENY"

        def permission_status_stale(task: dict, _: dict) -> None:
            task["permission_requirements"]["status"] = "STALE"

        def grant_scope_stale(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["scope"]["status"] = "STALE"

        def grant_scope_denied(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["scope"]["decision"] = "DENY"

        def expires_at_boundary(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["expires_at"] = self.CHECKED_AT

        def explicit_expired_status(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["grant_status"] = "EXPIRED"

        def unknown_status(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["grant_status"] = "UNKNOWN"

        def not_yet_valid(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["created_at"] = "2040-01-01T00:00:00Z"

        def inconsistent_revocation(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["revocation"].update(
                {"status": "REVOKED", "decision": "DENY"}
            )

        def task_id_mismatch(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["task_id"] = "unrelated-task"

        def agent_mismatch(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["agent_id"] = "agent:unrelated"

        def entity_mismatch(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["governing_entity_id"] = "c:unrelated"

        def target_mismatch(task: dict, envelope: dict) -> None:
            refs = ["target-basename:alternate.txt"]
            task["scope"]["refs"] = refs
            envelope["grant_payload"]["scope"]["refs"] = list(refs)

        def missing_permission(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["permissions"] = []

        def missing_capability(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["capability_bindings"] = {
                self.binding.PERMISSION: []
            }

        def self_approval(task: dict, envelope: dict) -> None:
            agent = envelope["grant_payload"]["agent_id"]
            task["human_anchor_ref"] = agent
            envelope["grant_payload"]["human_anchor_ref"] = agent

        def source_passport_tampering(task: dict, _: dict) -> None:
            task["source_refs"][0]["hash_ref"] = "f" * 40

        def grant_ref_mismatch(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["grant_id"] = "grant:unrelated"

        def human_anchor_mismatch(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["human_anchor_ref"] = "a:unrelated-owner"

        def authority_reference_mismatch(task: dict, _: dict) -> None:
            task["authority"]["refs"] = ["grant:unrelated"]

        def prohibited_task_flag(task: dict, _: dict) -> None:
            task["uncontrolled_network_allowed"] = True

        def prohibited_grant_flag(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["direct_memory_write_allowed"] = True

        def prohibited_capability(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["capability_bindings"] = {
                self.binding.PERMISSION: [self.binding.CAPABILITY, "CAP-NETWORK"]
            }

        def unknown_envelope_member(_: dict, envelope: dict) -> None:
            envelope["unrecognized_authority_surface"] = {"network_operation": "ALLOW"}

        def unknown_grant_member(_: dict, envelope: dict) -> None:
            envelope["grant_payload"]["unrecognized_capability_semantics"] = "ALLOW"

        def unknown_task_member(task: dict, _: dict) -> None:
            task["unrecognized_task_surface"] = "ALLOW"

        def unknown_section_member(task: dict, _: dict) -> None:
            task["scope"]["unrecognized_scope_surface"] = "ALLOW"

        cases = (
            ("task-authority-stale", task_authority_stale, "STALE_CONTRACT"),
            ("task-authority-denied", task_authority_denied, None),
            ("task-gate-denied", task_gate_denied, "TASK_GATE_NOT_CURRENT"),
            ("task-scope-stale", task_scope_stale, "TASK_SCOPE_MISMATCH"),
            ("task-scope-denied", task_scope_denied, "TASK_SCOPE_MISMATCH"),
            (
                "permission-status-stale",
                permission_status_stale,
                "TASK_PERMISSION_REQUIREMENTS_MISMATCH",
            ),
            ("grant-scope-stale", grant_scope_stale, "GRANT_SCOPE_MISMATCH"),
            ("grant-scope-denied", grant_scope_denied, "GRANT_SCOPE_MISMATCH"),
            ("expiry-equality", expires_at_boundary, "EXPIRED_PERMISSION"),
            ("explicit-expired", explicit_expired_status, "EXPIRED_PERMISSION"),
            ("unknown-status", unknown_status, "UNKNOWN_PERMISSION_STATUS"),
            ("not-yet-valid", not_yet_valid, "GRANT_NOT_YET_VALID"),
            (
                "inconsistent-revocation",
                inconsistent_revocation,
                "REVOCATION_STATE_MISMATCH",
            ),
            ("task-id-mismatch", task_id_mismatch, "TASK_MISMATCH"),
            ("agent-mismatch", agent_mismatch, "AGENT_MISMATCH"),
            ("entity-mismatch", entity_mismatch, "GOVERNING_ENTITY_MISMATCH"),
            ("target-mismatch", target_mismatch, "GRANT_SCOPE_MISMATCH"),
            ("missing-permission", missing_permission, "MISSING_OR_EXTRA_PERMISSION"),
            ("missing-capability", missing_capability, "MISSING_OR_EXTRA_CAPABILITY"),
            ("self-approval", self_approval, "SELF_APPROVAL"),
            (
                "source-passport-tampering",
                source_passport_tampering,
                "SOURCE_PASSPORT_TAMPERING",
            ),
            ("grant-ref-mismatch", grant_ref_mismatch, "GRANT_REFERENCE_MISMATCH"),
            ("human-anchor-mismatch", human_anchor_mismatch, None),
            ("authority-reference-mismatch", authority_reference_mismatch, None),
            (
                "task-prohibition",
                prohibited_task_flag,
                "TASK_UNCONTROLLED_NETWORK_ALLOWED",
            ),
            (
                "grant-prohibition",
                prohibited_grant_flag,
                "GRANT_DIRECT_MEMORY_WRITE_ALLOWED",
            ),
            ("extra-capability", prohibited_capability, "MISSING_OR_EXTRA_CAPABILITY"),
            (
                "unknown-envelope-member",
                unknown_envelope_member,
                "AUTHORITY_ENVELOPE_MEMBER_SET",
            ),
            ("unknown-grant-member", unknown_grant_member, "GRANT_MEMBER_SET"),
            ("unknown-task-member", unknown_task_member, "TASK_MEMBER_SET"),
            ("unknown-section-member", unknown_section_member, "TASK_SCOPE_MISMATCH"),
        )
        scenario_by_case = {
            "task-authority-stale": "R6A-CURRENT-005-STALE-CONTRACT",
            "expiry-equality": "R6A-CURRENT-003-EXPIRED",
            "unknown-status": "R6A-CURRENT-004-UNKNOWN-STATUS",
            "task-id-mismatch": "R6A-CURRENT-006-TASK-MISMATCH",
            "agent-mismatch": "R6A-CURRENT-007-AGENT-MISMATCH",
            "entity-mismatch": "R6A-CURRENT-008-GOVERNING-ENTITY-MISMATCH",
            "target-mismatch": "R6A-CURRENT-009-TARGET-MISMATCH",
            "missing-permission": "R6A-CURRENT-010-MISSING-PERMISSION",
            "missing-capability": "R6A-CURRENT-011-MISSING-CAPABILITY",
            "self-approval": "R6A-CURRENT-012-SELF-APPROVAL",
            "extra-capability": "R6A-CURRENT-013-PROHIBITED-CAPABILITY",
            "source-passport-tampering": "R6A-CURRENT-014-SOURCE-PASSPORT-TAMPERING",
        }
        for label, mutate, expected_reason in cases:
            with self.subTest(case=label):
                sandbox, instance = self._make_sandbox(label)
                task = self._json(sandbox / "task.json")
                envelope = self._json(sandbox / "authority.json")
                mutate(task, envelope)
                self._write_json(sandbox / "task.json", task)
                # Install the isolated initial authority input before the
                # binder has accepted an authority head.  Deliberately invalid
                # inputs must reach the binder; the cooperative publisher is
                # separately tested to reject them before publication.
                self._write_json(sandbox / "authority.json", envelope)
                result = self._bind(
                    f"{label}\n".encode(), sandbox=sandbox, instance=instance
                )
                self._assert_denied(result, expected_reason, sandbox=sandbox)
                scenario_id = scenario_by_case.get(label)
                if scenario_id is not None:
                    r6a_scenarios.pass_scenario(scenario_id)
        r6a_scenarios.pass_scenario(
            "R6A-CURRENT-015-SECTION-STATUS-OR-DECISION"
        )

    def test_malformed_revision_is_a_durable_denial_not_an_unhandled_conversion(self) -> None:
        for bad_revision in ("2", {"revision": 2}):
            with self.subTest(revision=bad_revision):
                sandbox, instance = self._make_sandbox("malformed-revision")
                envelope = self._json(sandbox / "authority.json")
                envelope["authority_revision"] = bad_revision
                self._write_json(sandbox / "authority.json", envelope)
                result = self._bind(
                    b"malformed-revision-must-not-land\n",
                    sandbox=sandbox,
                    instance=instance,
                )
                self._assert_denied(
                    result, "AUTHORITY_REVISION_INVALID", sandbox=sandbox
                )

    def test_path_boundary_rejects_all_non_basename_and_reserved_forms(self) -> None:
        forbidden = (
            "",
            ".",
            "..",
            "nested/output.txt",
            r"nested\output.txt",
            "/absolute.txt",
            r"C:\output.txt",
            r"\\server\share",
            "CON",
            "con.txt",
            "NUL.log",
            "COM9.txt",
            "LPT1",
            "CLOCK$.txt",
            "CONIN$.txt",
            "CONOUT$",
            "COM¹.txt",
            "LPT².log",
            "name.",
            "name ",
            ".c_binding",
            ".C_BINDING_PAYLOAD_collision",
            ".c_binding_authority_collision",
            "bad?.txt",
            "bad*.txt",
            "bad|name.txt",
            "bad<name>.txt",
            'bad"name.txt',
            "control\x1fname.txt",
            "nul\x00suffix",
        )
        scenario_by_name = {
            "..": "R6A-PATH-003-TRAVERSAL",
            "nested/output.txt": "R6A-PATH-002-SEPARATOR",
            "/absolute.txt": "R6A-PATH-001-ABSOLUTE",
            r"C:\output.txt": "R6A-PATH-005-DRIVE-PREFIX",
            r"\\server\share": "R6A-PATH-004-UNC",
            "CON": "R6A-PATH-006-RESERVED-DEVICE",
            ".c_binding": "R6A-PATH-010-INTERNAL-COLLISION",
        }
        for name in forbidden:
            with self.subTest(name=repr(name)):
                self._assert_quarantine_error(self.binding.validate_basename, name)
                scenario_id = scenario_by_name.get(name)
                if scenario_id is not None:
                    r6a_scenarios.pass_scenario(scenario_id)

    def test_path_boundary_rejects_collisions_and_unsafe_file_types(self) -> None:
        code = self._assert_quarantine_error(
            self.binding.bind_text,
            self.sandbox,
            task_basename="task.json",
            authority_basename="authority.json",
            target_basename="TASK.JSON",
            payload=b"collision\n",
            expected_instance_id=self.instance,
        )
        self.assertEqual("INPUT_TARGET_COLLISION", code)

        target = self.sandbox / "output.txt"
        target.mkdir()
        code = self._assert_quarantine_error(self._bind, b"directory-target\n")
        self.assertEqual("TARGET_UNSAFE_TYPE", code)
        self.assertTrue(target.is_dir())

    def test_path_boundary_rejects_symlink_inputs_and_sandbox_when_supported(self) -> None:
        real_task = self.sandbox / "real-task.json"
        shutil.copyfile(self.sandbox / "task.json", real_task)
        (self.sandbox / "task.json").unlink()
        try:
            os.symlink(real_task, self.sandbox / "task.json")
        except OSError as exc:
            if os.name != "nt":
                raise
            self.assertEqual(1314, getattr(exc, "winerror", 1314))
        else:
            code = self._assert_quarantine_error(self._bind, b"symlink-input\n")
            self.assertEqual("INPUT_UNSAFE_TYPE", code)
            self.assertFalse((self.sandbox / "output.txt").exists())

        link = Path(self.temp.name) / "sandbox-link"
        junction = False
        try:
            os.symlink(self.sandbox, link, target_is_directory=True)
        except OSError:
            if os.name != "nt":
                raise
            completed = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(self.sandbox)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
            junction = True
        try:
            code = self._assert_quarantine_error(
                self.binding.inspect_binding, link, expected_instance_id=self.instance
            )
            self.assertEqual("SANDBOX_LINK_OR_REPARSE", code)
        finally:
            if os.path.lexists(link):
                os.rmdir(link) if junction else link.unlink()

    @r6a_scenarios.scenario("R6A-PATH-007-SYMLINK-OR-REPARSE-SANDBOX")
    def test_reparse_detection_paths_fail_closed_without_platform_privilege(self) -> None:
        with mock.patch.object(self.binding, "_is_reparse", return_value=True):
            code = self._assert_quarantine_error(
                self.binding.inspect_binding,
                self.sandbox,
                expected_instance_id=self.instance,
            )
        self.assertEqual("SANDBOX_LINK_OR_REPARSE", code)

        def task_only(path: Path) -> bool:
            return Path(path).name.casefold() == "task.json"

        with mock.patch.object(self.binding, "_is_reparse", side_effect=task_only):
            code = self._assert_quarantine_error(self._bind, b"reparse-input\n")
        self.assertEqual("INPUT_UNSAFE_TYPE", code)
        self.assertFalse((self.sandbox / "output.txt").exists())

    def test_already_satisfied_never_prepares_replaces_or_recovers_as_effect(self) -> None:
        payload = b"already-present-before-attempt\n"
        target = self.sandbox / "output.txt"
        target.write_bytes(payload)
        before = os.lstat(target)
        with mock.patch.object(
            self.binding,
            "_hit_failpoint",
            side_effect=AssertionError("ALREADY_SATISFIED reached a PREPARED failpoint"),
        ), mock.patch.object(
            self.binding,
            "_replace_target",
            side_effect=AssertionError("ALREADY_SATISFIED attempted replacement"),
        ):
            result = self._bind(payload)
        after = os.lstat(target)
        self.assertEqual("RECORDED_NOT_BOUND", result["state"])
        self.assertEqual("ALREADY_SATISFIED", result["reason_code"])
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual("HOLD", result["records"]["consequence_commit"]["commit_outcome"])
        self.assertEqual(
            "NO_EFFECT_OBSERVED_WITHIN_DECLARED_SCOPE",
            result["records"]["non_effect_witness"]["conclusion"],
        )
        with sqlite3.connect(self._database()) as conn:
            self.assertEqual(
                0,
                conn.execute(
                    "SELECT COUNT(*) FROM attempts WHERE state='PREPARED'"
                ).fetchone()[0],
            )
        self.assertEqual(
            [],
            self.binding.recover_pending(
                self.sandbox, expected_instance_id=self.instance
            ),
        )
        self.assertEqual(payload, target.read_bytes())
        self.assertEqual([], list(self.sandbox.glob(".c_binding_payload_*")))

    def test_attempt_id_reuse_with_different_request_never_returns_stale_success(self) -> None:
        attempt = str(uuid.uuid4())
        first_payload = b"attempt-request-a\n"
        second_payload = b"attempt-request-b\n"
        first = self._bind(first_payload, attempt_id=attempt)
        self.assertEqual("RECORDED_BOUND", first["state"])
        code = self._assert_quarantine_error(
            self._bind, second_payload, attempt_id=attempt
        )
        self.assertIn(
            code,
            {
                "ATTEMPT_ID_REUSE_MISMATCH",
                "ATTEMPT_REQUEST_MISMATCH",
                "ATTEMPT_REPLAY_MISMATCH",
            },
        )
        self.assertEqual(first_payload, (self.sandbox / "output.txt").read_bytes())

    def test_windows_case_alias_cannot_bypass_quarantined_target_boundary(self) -> None:
        task = self._json(self.sandbox / "task.json")
        revision_one = self._revision_one()
        task["authority"]["status"] = "STALE"
        self._write_json(self.sandbox / "task.json", task)
        original_target_state = self.binding._target_state
        calls = 0

        def quarantine_lowercase_target(path: Path) -> dict:
            nonlocal calls
            calls += 1
            if calls == 2:
                path.write_bytes(b"quarantined-lowercase-target\n")
            return original_target_state(path)

        with mock.patch.object(
            self.binding,
            "_target_state",
            side_effect=quarantine_lowercase_target,
        ):
            quarantined = self._bind(b"denied-before-alias\n")
        self.assertEqual("QUARANTINED_UNRESOLVED", quarantined["state"])

        current_task = self._json(self.fixture_root / "r6a_task_output.json")
        current_task["scope"]["refs"] = ["target-basename:OUTPUT.TXT"]
        self._write_json(self.sandbox / "task.json", current_task)
        successor = self._successor(revision_one)
        successor["grant_payload"]["scope"]["refs"] = [
            "target-basename:OUTPUT.TXT"
        ]
        self._write_authority(successor)
        code = self._assert_quarantine_error(
            self._bind,
            b"alias-must-not-land\n",
            target="OUTPUT.TXT",
        )
        self.assertEqual("TARGET_BOUNDARY_QUARANTINED", code)
        self.assertEqual(
            b"quarantined-lowercase-target\n",
            (self.sandbox / "output.txt").read_bytes(),
        )

    @r6a_scenarios.scenario("R6A-TAMPER-007-JOURNAL-INSTANCE")
    def test_journal_instance_and_simple_record_tampering_fail_closed(self) -> None:
        for mode in ("journal-instance", "record-json"):
            with self.subTest(mode=mode):
                sandbox, instance = self._make_sandbox(mode)
                self._bind(b"tamper-seed\n", sandbox=sandbox, instance=instance)
                target_before = (sandbox / "output.txt").read_bytes()
                with sqlite3.connect(self._database(sandbox)) as conn:
                    if mode == "journal-instance":
                        replacement = str(uuid.uuid4())
                        meta = self.binding._meta_row("journal_instance_id", replacement)
                        conn.execute(
                            "UPDATE journal_meta SET value=?,row_hash=? WHERE key='journal_instance_id'",
                            (meta["value"], meta["row_hash"]),
                        )
                    else:
                        conn.execute(
                            "UPDATE records SET record_json=? WHERE kind='decision_basis'",
                            (b"{}",),
                        )
                    conn.commit()
                code = self._assert_quarantine_error(
                    self.binding.inspect_binding,
                    sandbox,
                    expected_instance_id=instance,
                )
                self.assertIn(
                    code, {"JOURNAL_INSTANCE_MISMATCH", "JOURNAL_ROW_HASH_MISMATCH"}
                )
                self.assertEqual(target_before, (sandbox / "output.txt").read_bytes())

    @r6a_scenarios.scenario("R6A-TAMPER-008-ATTEMPT-LINEAGE")
    def test_resealed_attempt_binding_inputs_and_authority_head_tampering_quarantine(self) -> None:
        input_mutations = {
            "journal-instance": lambda value: value.__setitem__(
                "journal_instance_id", str(uuid.uuid4())
            ),
            "attempt-id": lambda value: value.__setitem__(
                "attempt_id", str(uuid.uuid4())
            ),
            "target": lambda value: value.__setitem__(
                "target_basename", "alternate.txt"
            ),
            "payload": lambda value: value.__setitem__("payload_hash", "f" * 64),
        }
        for label, mutate in input_mutations.items():
            with self.subTest(case=label):
                sandbox, instance = self._make_sandbox(f"attempt-input-{label}")
                payload = b"attempt-binding-inputs\n"
                (sandbox / "output.txt").write_bytes(payload)
                result = self._bind(payload, sandbox=sandbox, instance=instance)
                with sqlite3.connect(self._database(sandbox)) as conn:
                    conn.row_factory = sqlite3.Row
                    attempt = dict(
                        conn.execute(
                            "SELECT * FROM attempts WHERE attempt_id=?",
                            (result["attempt_id"],),
                        ).fetchone()
                    )
                    inputs = json.loads(
                        bytes(attempt["record_inputs_json"]).decode("utf-8")
                    )
                    mutate(inputs)
                    attempt["record_inputs_json"] = self.binding.canonical_bytes(inputs)
                    attempt["row_hash"] = self.binding._row_hash("attempts", attempt)
                    conn.execute(
                        "UPDATE attempts SET record_inputs_json=?,row_hash=? WHERE attempt_id=?",
                        (
                            attempt["record_inputs_json"],
                            attempt["row_hash"],
                            result["attempt_id"],
                        ),
                    )
                    conn.commit()
                self._assert_quarantine_error(
                    self.binding.inspect_binding,
                    sandbox,
                    expected_instance_id=instance,
                )
                self.assertEqual(payload, (sandbox / "output.txt").read_bytes())

        sandbox, instance = self._make_sandbox("authority-head-lineage")
        revision_one = self._revision_one(sandbox)
        self._bind(b"authority-lineage-original\n", sandbox=sandbox, instance=instance)
        revoked = self._successor(revision_one, status="REVOKED")
        self._write_authority(revoked, sandbox=sandbox, instance=instance)
        denied = self._bind(
            b"authority-lineage-denied\n", sandbox=sandbox, instance=instance
        )
        self.assertEqual("REVOKED_PERMISSION", denied["reason_code"])
        with sqlite3.connect(self._database(sandbox)) as conn:
            conn.row_factory = sqlite3.Row
            head = dict(conn.execute("SELECT * FROM authority_heads").fetchone())
            head["authority_revision"] = 1
            head["row_hash"] = self.binding._row_hash("authority_heads", head)
            conn.execute(
                "UPDATE authority_heads SET authority_revision=?,row_hash=? WHERE authority_key=?",
                (head["authority_revision"], head["row_hash"], head["authority_key"]),
            )
            conn.commit()
        self._assert_quarantine_error(
            self.binding.inspect_binding,
            sandbox,
            expected_instance_id=instance,
        )
        self.assertEqual(
            b"authority-lineage-original\n", (sandbox / "output.txt").read_bytes()
        )

    def _coherently_reseal_record_mutation(self, sandbox: Path, kind: str, mutate) -> None:
        """Model a trusted-journal edit that recomputes every local hash seal."""

        with sqlite3.connect(self._database(sandbox)) as conn:
            conn.row_factory = sqlite3.Row
            rows = [
                dict(row)
                for row in conn.execute("SELECT * FROM records ORDER BY chain_ordinal")
            ]
            found = False
            for row in rows:
                record = json.loads(bytes(row["record_json"]).decode("utf-8"))
                if row["kind"] == kind:
                    mutate(record)
                    found = True
                row["record_json"] = self.binding.canonical_bytes(record)
                row["record_hash"] = self.binding.canonical_hash(record)
            self.assertTrue(found, f"missing record kind {kind}")

            previous = self.binding.ZERO_HASH
            hashes_by_attempt: dict[str, list[tuple[int, str]]] = {}
            for row in rows:
                row["previous_record_hash"] = previous
                row["row_hash"] = self.binding._row_hash("records", row)
                conn.execute(
                    "UPDATE records SET record_json=:record_json,record_hash=:record_hash,"
                    "previous_record_hash=:previous_record_hash,row_hash=:row_hash "
                    "WHERE record_id=:record_id",
                    row,
                )
                previous = row["record_hash"]
                hashes_by_attempt.setdefault(row["attempt_id"], []).append(
                    (int(row["attempt_ordinal"]), row["record_hash"])
                )

            meta = self.binding._meta_row("record_chain_head", previous)
            conn.execute(
                "UPDATE journal_meta SET value=?,row_hash=? WHERE key='record_chain_head'",
                (meta["value"], meta["row_hash"]),
            )
            for attempt_id, ordinal_hashes in hashes_by_attempt.items():
                attempt = dict(
                    conn.execute(
                        "SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)
                    ).fetchone()
                )
                hashes = [digest for _, digest in sorted(ordinal_hashes)]
                attempt["terminal_record_set_hash"] = self.binding.canonical_hash(hashes)
                attempt["row_hash"] = self.binding._row_hash("attempts", attempt)
                conn.execute(
                    "UPDATE attempts SET terminal_record_set_hash=?,row_hash=? "
                    "WHERE attempt_id=?",
                    (
                        attempt["terminal_record_set_hash"],
                        attempt["row_hash"],
                        attempt_id,
                    ),
                )
            conn.commit()

    def test_coherently_resealed_runtime_record_tampering_is_quarantined_on_open(self) -> None:
        def decision_basis(record: dict) -> None:
            record["basis"]["evidence_refs"][0]["hash"] = "f" * 64

        def consequence(record: dict) -> None:
            record["commit_outcome"] = "OPEN"

        def witness_attempt(record: dict) -> None:
            record["attempt_ref"] = record["record_id"]

        def witness_interval(record: dict) -> None:
            record["observation_window"]["start"] = "2030-01-01T00:01:00Z"

        def witness_surface(record: dict) -> None:
            record["observation_surfaces"] = []

        def witness_alternate_path(record: dict) -> None:
            record["alternate_path_checks"][0]["status"] = "OPEN"

        cases = (
            ("decision-basis", "decision_basis", decision_basis),
            ("consequence", "consequence_commit", consequence),
            ("witness-attempt", "non_effect_witness", witness_attempt),
            ("witness-interval", "non_effect_witness", witness_interval),
            ("witness-surface", "non_effect_witness", witness_surface),
            ("witness-alternate-path", "non_effect_witness", witness_alternate_path),
        )
        scenario_by_case = {
            "decision-basis": "R6A-TAMPER-001-DECISION-HASH",
            "consequence": "R6A-TAMPER-002-COMMIT-MUTATION",
            "witness-attempt": "R6A-TAMPER-003-WITNESS-ATTEMPT",
            "witness-interval": "R6A-TAMPER-004-WITNESS-INTERVAL",
            "witness-surface": "R6A-TAMPER-005-INCOMPLETE-SURFACE",
            "witness-alternate-path": "R6A-TAMPER-006-OPEN-ALTERNATE-PATH",
        }
        for label, kind, mutate in cases:
            with self.subTest(case=label):
                sandbox, instance = self._make_sandbox(label)
                payload = b"tamper-not-bound\n"
                (sandbox / "output.txt").write_bytes(payload)
                self._bind(payload, sandbox=sandbox, instance=instance)
                self._coherently_reseal_record_mutation(sandbox, kind, mutate)
                code = self._assert_quarantine_error(
                    self.binding.inspect_binding,
                    sandbox,
                    expected_instance_id=instance,
                )
                self.assertIn(
                    code,
                    {
                        "RUNTIME_RECORD_TAMPERING",
                        "RUNTIME_RECORD_VALIDATION",
                        "RUNTIME_RECORD_BUNDLE_INVALID",
                        "TERMINAL_RECORD_KIND_SET",
                    },
                )
                self.assertEqual(payload, (sandbox / "output.txt").read_bytes())
                r6a_scenarios.pass_scenario(scenario_by_case[label])

    @r6a_scenarios.scenario("R6A-TAMPER-009-DUPLICATE-TERMINAL")
    def test_duplicate_terminal_record_is_detected_even_with_valid_local_hashes(self) -> None:
        payload = b"duplicate-terminal\n"
        (self.sandbox / "output.txt").write_bytes(payload)
        result = self._bind(payload)
        with sqlite3.connect(self._database()) as conn:
            conn.row_factory = sqlite3.Row
            source = dict(
                conn.execute(
                    "SELECT * FROM records WHERE attempt_id=? AND kind='decision_basis'",
                    (result["attempt_id"],),
                ).fetchone()
            )
            record_count = int(
                conn.execute(
                    "SELECT value FROM journal_meta WHERE key='record_count'"
                ).fetchone()[0]
            )
            chain_head = str(
                conn.execute(
                    "SELECT value FROM journal_meta WHERE key='record_chain_head'"
                ).fetchone()[0]
            )
            source.update(
                {
                    "record_id": f"r6a-duplicate-{uuid.uuid4().hex[:24]}",
                    "attempt_ordinal": 4,
                    "chain_ordinal": record_count + 1,
                    "previous_record_hash": chain_head,
                }
            )
            source["row_hash"] = self.binding._row_hash("records", source)
            conn.execute(
                "INSERT INTO records VALUES(:record_id,:attempt_id,:attempt_ordinal,"
                ":chain_ordinal,:kind,:terminal_state,:record_json,:record_hash,"
                ":previous_record_hash,:row_hash)",
                source,
            )
            count_meta = self.binding._meta_row("record_count", str(record_count + 1))
            head_meta = self.binding._meta_row("record_chain_head", source["record_hash"])
            conn.execute(
                "UPDATE journal_meta SET value=?,row_hash=? WHERE key='record_count'",
                (count_meta["value"], count_meta["row_hash"]),
            )
            conn.execute(
                "UPDATE journal_meta SET value=?,row_hash=? WHERE key='record_chain_head'",
                (head_meta["value"], head_meta["row_hash"]),
            )
            attempt = dict(
                conn.execute(
                    "SELECT * FROM attempts WHERE attempt_id=?", (result["attempt_id"],)
                ).fetchone()
            )
            hashes = [
                row[0]
                for row in conn.execute(
                    "SELECT record_hash FROM records WHERE attempt_id=? ORDER BY attempt_ordinal",
                    (result["attempt_id"],),
                )
            ]
            attempt["terminal_record_set_hash"] = self.binding.canonical_hash(hashes)
            attempt["row_hash"] = self.binding._row_hash("attempts", attempt)
            conn.execute(
                "UPDATE attempts SET terminal_record_set_hash=?,row_hash=? WHERE attempt_id=?",
                (
                    attempt["terminal_record_set_hash"],
                    attempt["row_hash"],
                    result["attempt_id"],
                ),
            )
            conn.commit()
        code = self._assert_quarantine_error(
            self.binding.inspect_binding,
            self.sandbox,
            expected_instance_id=self.instance,
        )
        self.assertEqual("DUPLICATE_TERMINAL_RECORD", code)

    @r6a_scenarios.scenario("R6A-TAMPER-010-TARGET-CHANGED-DURING-DENIAL")
    def test_target_change_during_denial_returns_only_quarantine_claim(self) -> None:
        task = self._json(self.sandbox / "task.json")
        task["authority"]["status"] = "STALE"
        self._write_json(self.sandbox / "task.json", task)
        original_target_state = self.binding._target_state
        calls = 0

        def change_on_denial_postcheck(path: Path) -> dict:
            nonlocal calls
            calls += 1
            if calls == 2:
                path.write_bytes(b"cooperative-test-writer-change\n")
            return original_target_state(path)

        with mock.patch.object(
            self.binding, "_target_state", side_effect=change_on_denial_postcheck
        ):
            result = self._bind(b"denied-payload\n")
        self.assertEqual("QUARANTINED_UNRESOLVED", result["state"])
        self.assertEqual("TARGET_CHANGED_DURING_DENIAL", result["reason_code"])
        self.assertEqual({"binding_transition"}, set(result["records"]))
        self.assertNotIn("superseded_records", result)
        self.assertEqual(
            b"cooperative-test-writer-change\n",
            (self.sandbox / "output.txt").read_bytes(),
        )
        code = self._assert_quarantine_error(
            self._bind, b"later-effect-must-not-land\n"
        )
        self.assertEqual("TARGET_BOUNDARY_QUARANTINED", code)


if __name__ == "__main__":
    unittest.main()
