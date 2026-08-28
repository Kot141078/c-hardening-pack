from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

_TESTS_ROOT = str(Path(__file__).resolve().parent)
if _TESTS_ROOT not in sys.path:
    sys.path.insert(0, _TESTS_ROOT)
import r6a_scenario_registry as r6a_scenarios


class CgamDurableBindingCrashTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        cls.script = cls.root / "tools" / "cgam_durable_binding.py"
        cls.fixture_root = cls.root / "fixtures" / "cgam-durable-binding"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="r6a-crash-")
        self.sandbox = Path(self.temporary.name) / "sandbox"
        self.sandbox.mkdir()
        shutil.copyfile(
            self.fixture_root / "r6a_task_output.json",
            self.sandbox / "task.json",
        )
        shutil.copyfile(
            self.fixture_root / "r6a_authority_revision_1_active.json",
            self.sandbox / "authority.json",
        )
        initial = self._run_json("init", "--sandbox", str(self.sandbox))
        self.assertEqual("INITIALIZED", initial["state"])
        self.instance = initial["journal_instance_id"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _environment(self, failpoint: str | None = None) -> dict[str, str]:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment.pop("R6A_FAILPOINT", None)
        if failpoint is not None:
            environment["R6A_FAILPOINT"] = failpoint
        return environment

    def _command(self, *arguments: str) -> list[str]:
        return [sys.executable, str(self.script), *arguments]

    def _run(
        self,
        *arguments: str,
        expected_returncode: int = 0,
        failpoint: str | None = None,
        timeout: float = 30.0,
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            self._command(*arguments),
            cwd=self.root,
            env=self._environment(failpoint),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            check=False,
            timeout=timeout,
        )
        self.assertEqual(
            expected_returncode,
            completed.returncode,
            msg=(
                f"command={completed.args!r}\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}"
            ),
        )
        return completed

    def _run_json(self, *arguments: str, timeout: float = 30.0) -> Any:
        completed = self._run(*arguments, timeout=timeout)
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self.fail(
                f"command did not emit one JSON value: {completed.stdout!r}; "
                f"stderr={completed.stderr!r}; error={exc}"
            )

    def _load_binding_module(self) -> Any:
        module_name = f"_r6a_crash_test_binding_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(module_name, self.script)
        if spec is None or spec.loader is None:
            self.fail(f"could not load binding module from {self.script}")
        tools_path = str(self.script.parent)
        old_dont_write_bytecode = sys.dont_write_bytecode
        sys.path.insert(0, tools_path)
        sys.dont_write_bytecode = True
        try:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        finally:
            sys.dont_write_bytecode = old_dont_write_bytecode
            del sys.path[0]

    def _bind_arguments(
        self,
        attempt_id: str,
        payload: str,
        *,
        target: str = "output.txt",
    ) -> tuple[str, ...]:
        return (
            "bind",
            "--sandbox",
            str(self.sandbox),
            "--task",
            "task.json",
            "--authority",
            "authority.json",
            "--target",
            target,
            "--payload-text",
            payload,
            "--attempt-id",
            attempt_id,
            "--expected-instance",
            self.instance,
        )

    def _inspect(self) -> dict[str, Any]:
        inspected = self._run_json(
            "inspect",
            "--sandbox",
            str(self.sandbox),
            "--expected-instance",
            self.instance,
        )
        self.assertEqual("JOURNAL_VALID", inspected["state"])
        self.assertEqual(self.instance, inspected["journal_instance_id"])
        self.assertEqual("DELETE", inspected["journal_mode"])
        self.assertEqual(2, inspected["synchronous"])
        self.assertEqual(1, inspected["foreign_keys"])
        self.assertEqual("ok", inspected["integrity_check"])
        return inspected

    def _recover(self) -> list[dict[str, Any]]:
        recovered = self._run_json(
            "recover",
            "--sandbox",
            str(self.sandbox),
            "--expected-instance",
            self.instance,
        )
        self.assertIsInstance(recovered, list)
        return recovered

    def _payload_temps(self) -> list[Path]:
        return sorted(self.sandbox.glob(".c_binding_payload_*"))

    def _authority_temps(self) -> list[Path]:
        return sorted(self.sandbox.glob(".c_binding_authority_*"))

    def _sqlite_transients(self) -> list[Path]:
        internal = self.sandbox / ".c_binding"
        return [
            path
            for path in (
                internal / "binding_state.sqlite3-journal",
                internal / "binding_state.sqlite3-wal",
                internal / "binding_state.sqlite3-shm",
            )
            if path.exists()
        ]

    def _assert_no_temp_residue(self) -> None:
        self.assertEqual([], self._payload_temps())
        self.assertEqual([], self._authority_temps())
        self.assertEqual([], self._sqlite_transients())

    def _exercise_failpoint(
        self,
        failpoint: str,
        exit_code: int,
        *,
        expected_terminal_state: str,
        expected_reason: str,
        target_exists_at_crash: bool,
        temp_exists_at_crash: bool,
        preexisting_target: bytes | None = None,
    ) -> None:
        attempt_id = str(uuid.uuid4())
        payload_text = f"durable-{failpoint}-payload"
        payload = payload_text.encode("utf-8")
        target = self.sandbox / "output.txt"
        if preexisting_target is not None:
            target.write_bytes(preexisting_target)
        crashed = self._run(
            *self._bind_arguments(attempt_id, payload_text),
            expected_returncode=exit_code,
            failpoint=failpoint,
        )
        self.assertEqual("", crashed.stdout)
        self.assertNotIn("Traceback", crashed.stderr)

        self.assertEqual(target_exists_at_crash, target.exists())
        if target_exists_at_crash:
            expected_crash_bytes = (
                payload
                if failpoint in {"R6A-CRASH-003", "R6A-CRASH-004"}
                else preexisting_target
            )
            self.assertEqual(expected_crash_bytes, target.read_bytes())
        temps = self._payload_temps()
        self.assertEqual(1 if temp_exists_at_crash else 0, len(temps))
        if temp_exists_at_crash:
            self.assertEqual(payload, temps[0].read_bytes())
        self.assertEqual([], self._authority_temps())

        before_recovery = self._inspect()
        expected_prepared = 0 if failpoint == "R6A-CRASH-004" else 1
        self.assertEqual(expected_prepared, before_recovery["prepared_count"])
        self.assertEqual(1, before_recovery["attempt_count"])
        self.assertEqual(2 if failpoint == "R6A-CRASH-004" else 0, before_recovery["record_count"])

        recovery_started = datetime.now(timezone.utc)
        recovered = self._recover()
        recovery_finished = datetime.now(timezone.utc)
        if failpoint == "R6A-CRASH-004":
            self.assertEqual([], recovered)
        else:
            self.assertEqual(1, len(recovered))
            self.assertEqual(attempt_id, recovered[0]["attempt_id"])
            self.assertEqual(expected_terminal_state, recovered[0]["state"])
            self.assertEqual(expected_reason, recovered[0]["reason_code"])
            self.assertEqual(self.instance, recovered[0]["journal_instance_id"])
            self.assertTrue(recovered[0]["durable_readback"])
            commit = recovered[0]["records"]["consequence_commit"]
            if expected_terminal_state == "RECOVERED_NOT_BOUND":
                observed = datetime.fromisoformat(
                    commit["created_at"].replace("Z", "+00:00")
                )
                self.assertLessEqual(recovery_started, observed)
                self.assertLessEqual(observed, recovery_finished)
                witness = recovered[0]["records"]["non_effect_witness"]
                observation_start = datetime.fromisoformat(
                    witness["observation_window"]["start"].replace("Z", "+00:00")
                )
                observation_end = datetime.fromisoformat(
                    witness["observation_window"]["end"].replace("Z", "+00:00")
                )
                self.assertLessEqual(recovery_started, observation_start)
                self.assertLessEqual(observation_start, observed)
                self.assertLessEqual(observed, observation_end)
                self.assertLessEqual(observation_end, recovery_finished)
                self.assertEqual(
                    witness["created_at"], witness["observation_window"]["end"]
                )

        replay = self._run_json(*self._bind_arguments(attempt_id, payload_text))
        self.assertEqual(attempt_id, replay["attempt_id"])
        self.assertEqual(expected_terminal_state, replay["state"])
        self.assertEqual(expected_reason, replay["reason_code"])
        self.assertEqual(self.instance, replay["journal_instance_id"])
        self.assertTrue(replay["durable_readback"])
        expected_record_kinds = {"decision_basis", "consequence_commit"}
        if expected_terminal_state == "RECOVERED_NOT_BOUND":
            expected_record_kinds.add("non_effect_witness")
        self.assertEqual(expected_record_kinds, set(replay["records"]))

        expected_target_bytes = (
            preexisting_target
            if expected_terminal_state == "RECOVERED_NOT_BOUND"
            else payload
        )
        self.assertEqual(expected_target_bytes is not None, target.exists())
        if expected_target_bytes is not None:
            self.assertEqual(expected_target_bytes, target.read_bytes())
        self._assert_no_temp_residue()

        final = self._inspect()
        self.assertEqual(0, final["prepared_count"])
        self.assertEqual(0, final["quarantined_count"])
        self.assertEqual(1, final["attempt_count"])
        self.assertEqual(
            3 if expected_terminal_state == "RECOVERED_NOT_BOUND" else 2,
            final["record_count"],
        )

    @r6a_scenarios.scenario("R6A-CRASH-001")
    def test_r6a_crash_001_recovers_before_temp_as_not_bound(self) -> None:
        self._exercise_failpoint(
            "R6A-CRASH-001",
            91,
            expected_terminal_state="RECOVERED_NOT_BOUND",
            expected_reason="CRASH_BEFORE_EFFECT",
            target_exists_at_crash=False,
            temp_exists_at_crash=False,
        )

    @r6a_scenarios.scenario("R6A-CRASH-002", "R6A-PATH-011-NO-TEMP-RESIDUE")
    def test_r6a_crash_002_removes_durable_temp_and_recovers_not_bound(self) -> None:
        self._exercise_failpoint(
            "R6A-CRASH-002",
            92,
            expected_terminal_state="RECOVERED_NOT_BOUND",
            expected_reason="CRASH_BEFORE_EFFECT",
            target_exists_at_crash=True,
            temp_exists_at_crash=True,
            preexisting_target=b"pre-crash-original-bytes",
        )

    @r6a_scenarios.scenario("R6A-CRASH-003", "R6A-EARTH-002-RECOVER-AFTER-REPLACE")
    def test_r6a_crash_003_recovers_replaced_target_as_bound(self) -> None:
        self._exercise_failpoint(
            "R6A-CRASH-003",
            93,
            expected_terminal_state="RECOVERED_BOUND",
            expected_reason="CRASH_AFTER_EFFECT",
            target_exists_at_crash=True,
            temp_exists_at_crash=False,
        )

    @r6a_scenarios.scenario("R6A-CRASH-004")
    def test_r6a_crash_004_preserves_terminal_recorded_bound(self) -> None:
        self._exercise_failpoint(
            "R6A-CRASH-004",
            94,
            expected_terminal_state="RECORDED_BOUND",
            expected_reason="AUTHORIZED_EFFECT",
            target_exists_at_crash=True,
            temp_exists_at_crash=False,
        )

    @r6a_scenarios.scenario("R6A-PATH-008-RECOVERY-IDENTITY-CHANGE")
    def test_crash_002_unexpected_identity_quarantine_removes_regular_temp(self) -> None:
        attempt_id = str(uuid.uuid4())
        payload_text = "payload-must-remain-unbound"
        target = self.sandbox / "output.txt"
        original = b"pre-existing-content"
        target.write_bytes(original)
        original_identity = os.lstat(target)

        self._run(
            *self._bind_arguments(attempt_id, payload_text),
            expected_returncode=92,
            failpoint="R6A-CRASH-002",
        )
        payload_temps = self._payload_temps()
        self.assertEqual(1, len(payload_temps))
        self.assertEqual(payload_text.encode("utf-8"), payload_temps[0].read_bytes())

        replacement = self.sandbox / "replacement.txt"
        replacement.write_bytes(original)
        os.replace(replacement, target)
        replacement_identity = os.lstat(target)
        self.assertNotEqual(
            (original_identity.st_dev, original_identity.st_ino),
            (replacement_identity.st_dev, replacement_identity.st_ino),
        )

        recovered = self._recover()
        self.assertEqual(1, len(recovered))
        self.assertEqual("QUARANTINED_UNRESOLVED", recovered[0]["state"])
        self.assertEqual("UNEXPECTED_TARGET_STATE", recovered[0]["reason_code"])
        self.assertEqual(self.instance, recovered[0]["journal_instance_id"])
        self.assertEqual({"binding_transition"}, set(recovered[0]["records"]))
        self.assertEqual(original, target.read_bytes())
        self._assert_no_temp_residue()

        database = self.sandbox / ".c_binding" / "binding_state.sqlite3"
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            stored = connection.execute(
                "SELECT state,temp_basename FROM attempts WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
        self.assertEqual(("QUARANTINED_UNRESOLVED", None), stored)
        inspected = self._inspect()
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(1, inspected["quarantined_count"])
        self.assertEqual([], self._recover())

    def test_crash_003_recovery_uses_persisted_final_check_time(self) -> None:
        authority_path = self.sandbox / "authority.json"
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        expiry_time = datetime.now(timezone.utc) + timedelta(seconds=8)
        expiry = expiry_time.isoformat().replace("+00:00", "Z")
        authority["grant_payload"]["expires_at"] = expiry
        authority_path.write_text(
            json.dumps(authority, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        attempt_id = str(uuid.uuid4())
        payload_text = "short-lived-authority-payload"
        self._run(
            *self._bind_arguments(attempt_id, payload_text),
            expected_returncode=93,
            failpoint="R6A-CRASH-003",
        )

        database = self.sandbox / ".c_binding" / "binding_state.sqlite3"
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            prepared = connection.execute(
                "SELECT state,record_inputs_json FROM attempts WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
        self.assertIsNotNone(prepared)
        self.assertEqual("PREPARED", prepared[0])
        persisted_inputs = json.loads(prepared[1])
        persisted_final_check = persisted_inputs["checked_at"]
        self.assertLess(
            datetime.fromisoformat(persisted_final_check.replace("Z", "+00:00")),
            expiry_time,
        )
        expiry_deadline = time.monotonic() + 30.0
        while datetime.now(timezone.utc) < expiry_time:
            if time.monotonic() >= expiry_deadline:
                self.fail(
                    "environment UTC did not reach the authority expiry within "
                    "the bounded monotonic wait"
                )
            time.sleep(0.05)

        recovered = self._recover()
        self.assertEqual(1, len(recovered))
        result = recovered[0]
        self.assertEqual("RECOVERED_BOUND", result["state"])
        self.assertEqual("CRASH_AFTER_EFFECT", result["reason_code"])
        commit = result["records"]["consequence_commit"]
        self.assertEqual(persisted_final_check, commit["created_at"])
        self.assertEqual(persisted_final_check, commit["permission_checked_at"])
        self.assertEqual(persisted_final_check, commit["task_contract_checked_at"])
        self.assertEqual(expiry, commit["permission_valid_until"])
        self.assertEqual(
            payload_text.encode("utf-8"),
            (self.sandbox / "output.txt").read_bytes(),
        )
        self._assert_no_temp_residue()
        inspected = self._inspect()
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])

    def test_terminal_attempt_replay_rejects_conflicting_request(self) -> None:
        attempt_id = str(uuid.uuid4())
        original_payload = "immutable-replay-payload"
        original = self._run_json(
            *self._bind_arguments(attempt_id, original_payload)
        )
        self.assertEqual("RECORDED_BOUND", original["state"])
        original_record_set = original["record_set_hash"]

        conflicts = (
            self._bind_arguments(attempt_id, "different-payload"),
            self._bind_arguments(
                attempt_id,
                original_payload,
                target="different-output.txt",
            ),
        )
        for arguments in conflicts:
            with self.subTest(arguments=arguments):
                rejected = self._run(*arguments, expected_returncode=2)
                error = json.loads(rejected.stdout)
                self.assertEqual("ATTEMPT_REPLAY_MISMATCH", error["error_code"])
                self.assertNotIn("Traceback", rejected.stderr)

        task_path = self.sandbox / "task.json"
        original_task = task_path.read_bytes()
        mutated_task = json.loads(original_task)
        mutated_task["updated_at"] = "2026-08-28T00:00:01Z"
        task_path.write_text(
            json.dumps(mutated_task, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        task_conflict = self._run(
            *self._bind_arguments(attempt_id, original_payload),
            expected_returncode=2,
        )
        self.assertEqual(
            "ATTEMPT_REPLAY_MISMATCH",
            json.loads(task_conflict.stdout)["error_code"],
        )
        task_path.write_bytes(original_task)

        authority_path = self.sandbox / "authority.json"
        original_authority = authority_path.read_bytes()
        mutated_authority = json.loads(original_authority)
        mutated_authority["grant_payload"]["updated_at"] = "2026-08-28T00:00:01Z"
        authority_path.write_text(
            json.dumps(mutated_authority, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        authority_conflict = self._run(
            *self._bind_arguments(attempt_id, original_payload),
            expected_returncode=2,
        )
        self.assertEqual(
            "ATTEMPT_REPLAY_MISMATCH",
            json.loads(authority_conflict.stdout)["error_code"],
        )
        authority_path.write_bytes(original_authority)

        exact_replay = self._run_json(
            *self._bind_arguments(attempt_id.upper(), original_payload)
        )
        self.assertEqual("RECORDED_BOUND", exact_replay["state"])
        self.assertEqual(original_record_set, exact_replay["record_set_hash"])
        self.assertEqual(
            original_payload.encode("utf-8"),
            (self.sandbox / "output.txt").read_bytes(),
        )
        self.assertFalse((self.sandbox / "different-output.txt").exists())
        self._assert_no_temp_residue()
        inspected = self._inspect()
        self.assertEqual(1, inspected["attempt_count"])
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])

    def test_cli_rejects_backdating_and_expired_authority_stays_no_effect(self) -> None:
        authority_path = self.sandbox / "authority.json"
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        expired_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        authority["grant_payload"]["expires_at"] = (
            expired_at.isoformat().replace("+00:00", "Z")
        )
        authority_path.write_text(
            json.dumps(authority, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        attempt_id = str(uuid.uuid4())
        payload_text = "backdating-must-not-authorize-this-effect"
        rejected = self._run(
            *self._bind_arguments(attempt_id, payload_text),
            "--checked-at",
            "2026-08-28T00:00:30Z",
            expected_returncode=2,
        )
        self.assertEqual("", rejected.stdout)
        self.assertIn("unrecognized arguments: --checked-at", rejected.stderr)
        self.assertFalse((self.sandbox / "output.txt").exists())
        self.assertEqual(0, self._inspect()["attempt_count"])

        denied = self._run_json(*self._bind_arguments(attempt_id, payload_text))
        self.assertEqual("DENIED", denied["state"])
        self.assertEqual("EXPIRED_PERMISSION", denied["reason_code"])
        commit = denied["records"]["consequence_commit"]
        self.assertEqual("EXPIRED", commit["permission_status"])
        self.assertEqual("NOT_BOUND", commit["effect_state"])
        self.assertEqual("DENY", commit["commit_outcome"])
        self.assertFalse((self.sandbox / "output.txt").exists())
        self._assert_no_temp_residue()
        inspected = self._inspect()
        self.assertEqual(1, inspected["attempt_count"])
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])

    def test_stale_task_and_expired_grant_preserve_complete_denial_evidence(self) -> None:
        task_path = self.sandbox / "task.json"
        authority_path = self.sandbox / "authority.json"
        task = json.loads(task_path.read_text(encoding="utf-8"))
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        task["authority"]["status"] = "STALE"
        authority["grant_payload"]["expires_at"] = (
            (datetime.now(timezone.utc) - timedelta(seconds=1))
            .isoformat()
            .replace("+00:00", "Z")
        )
        task_path.write_text(
            json.dumps(task, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        authority_path.write_text(
            json.dumps(authority, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )

        attempt_id = str(uuid.uuid4())
        denied = self._run_json(
            *self._bind_arguments(attempt_id, "independent-multi-fault-denial")
        )
        self.assertEqual("DENIED", denied["state"])
        self.assertEqual("EXPIRED_PERMISSION", denied["reason_code"])
        self.assertEqual(
            {"decision_basis", "consequence_commit", "non_effect_witness"},
            set(denied["records"]),
        )
        decision = denied["records"]["decision_basis"]
        commit = denied["records"]["consequence_commit"]
        self.assertEqual("STALE", commit["task_contract_status"])
        self.assertEqual("EXPIRED", commit["permission_status"])
        self.assertEqual("NOT_BOUND", commit["effect_state"])
        self.assertEqual("DENY", commit["commit_outcome"])
        preconditions = {
            item["name"]: item["status"] for item in commit["precondition_results"]
        }
        self.assertEqual("FAIL", preconditions["SOURCE_GROUNDING"])
        self.assertEqual("FAIL", preconditions["TIME_WINDOW"])
        self.assertEqual("FAIL", preconditions["BLOCKING_STATE"])

        database = self.sandbox / ".c_binding" / "binding_state.sqlite3"
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            stored = connection.execute(
                "SELECT state,reason_code,temp_basename,record_inputs_json "
                "FROM attempts WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
        self.assertIsNotNone(stored)
        self.assertEqual(("DENIED", "EXPIRED_PERMISSION", None), stored[:3])
        record_inputs = json.loads(stored[3])
        self.assertEqual(
            ["EXPIRED_PERMISSION", "STALE_CONTRACT"],
            record_inputs["validation_reasons"],
        )
        binding = self._load_binding_module()
        context_hash = binding.canonical_hash(
            binding._record_context(
                record_inputs,
                denied["state"],
                denied["reason_code"],
                commit["permission_checked_at"],
            )
        )
        self.assertEqual(context_hash, commit["current_conditions_hash"])
        self.assertEqual(context_hash, commit["current_conditions_ref"]["hash"])
        current_conditions = next(
            artifact
            for artifact in decision["basis"]["evidence_refs"]
            if artifact["artifact_id"] == "R6A:CURRENT_CONDITIONS"
        )
        self.assertEqual(context_hash, current_conditions["hash"])
        self.assertFalse((self.sandbox / "output.txt").exists())
        self._assert_no_temp_residue()
        self.assertEqual([], self._recover())
        inspected = self._inspect()
        self.assertEqual(1, inspected["attempt_count"])
        self.assertEqual(3, inspected["record_count"])
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])

    def test_already_satisfied_guard_precedes_revoked_successor_denial(self) -> None:
        payload_text = "pre-existing-equality-is-not-this-attempts-effect"
        first_attempt = str(uuid.uuid4())
        first = self._run_json(
            *self._bind_arguments(first_attempt, payload_text)
        )
        self.assertEqual("RECORDED_BOUND", first["state"])
        target = self.sandbox / "output.txt"
        before = os.lstat(target)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )

        shutil.copyfile(
            self.fixture_root / "r6a_authority_revision_2_revoked.json",
            self.sandbox / "authority.json",
        )
        second_attempt = str(uuid.uuid4())
        second = self._run_json(
            *self._bind_arguments(second_attempt, payload_text)
        )

        self.assertEqual("RECORDED_NOT_BOUND", second["state"])
        self.assertEqual("ALREADY_SATISFIED", second["reason_code"])
        self.assertEqual(
            {"decision_basis", "consequence_commit", "non_effect_witness"},
            set(second["records"]),
        )
        commit = second["records"]["consequence_commit"]
        self.assertEqual("NOT_BOUND", commit["effect_state"])
        self.assertEqual("HOLD", commit["commit_outcome"])
        self.assertEqual("REVOKED", commit["permission_status"])
        preconditions = {
            item["name"]: item["status"] for item in commit["precondition_results"]
        }
        self.assertEqual("FAIL", preconditions["CURRENT_AUTHORITY"])
        self.assertEqual("FAIL", preconditions["BLOCKING_STATE"])
        after = os.lstat(target)
        self.assertEqual(
            before_identity,
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        )
        self.assertEqual(payload_text.encode("utf-8"), target.read_bytes())
        self._assert_no_temp_residue()

        database = self.sandbox / ".c_binding" / "binding_state.sqlite3"
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            state = connection.execute(
                "SELECT state,temp_basename FROM attempts WHERE attempt_id=?",
                (second_attempt,),
            ).fetchone()
            head_revision = connection.execute(
                "SELECT authority_revision FROM authority_heads"
            ).fetchone()
        self.assertEqual(("RECORDED_NOT_BOUND", None), state)
        self.assertEqual((2,), head_revision)
        inspected = self._inspect()
        self.assertEqual(2, inspected["attempt_count"])
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])

    def test_clock_rollback_still_advances_revocation_before_stale_replay(self) -> None:
        payload_a = b"clock-rollback-revocation-payload-a"
        first = self._run_json(
            *self._bind_arguments(str(uuid.uuid4()), payload_a.decode("utf-8"))
        )
        self.assertEqual("RECORDED_BOUND", first["state"])
        target = self.sandbox / "output.txt"
        self.assertEqual(payload_a, target.read_bytes())

        database = self.sandbox / ".c_binding" / "binding_state.sqlite3"
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            observed_at = connection.execute(
                "SELECT observed_at FROM authority_heads"
            ).fetchone()[0]
        observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        earlier = (observed - timedelta(seconds=1)).isoformat().replace(
            "+00:00", "Z"
        )
        later = (observed + timedelta(seconds=1)).isoformat().replace(
            "+00:00", "Z"
        )

        shutil.copyfile(
            self.fixture_root / "r6a_authority_revision_2_revoked.json",
            self.sandbox / "authority.json",
        )
        binding = self._load_binding_module()
        revoked_attempt = str(uuid.uuid4())
        with mock.patch.object(binding, "_utc_now", return_value=earlier):
            revoked = binding.bind_text(
                self.sandbox,
                task_basename="task.json",
                authority_basename="authority.json",
                target_basename="output.txt",
                payload=payload_a,
                attempt_id=revoked_attempt,
                expected_instance_id=self.instance,
            )
        self.assertEqual("RECORDED_NOT_BOUND", revoked["state"])
        self.assertEqual("ALREADY_SATISFIED", revoked["reason_code"])
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            head = connection.execute(
                "SELECT authority_revision,effective_status,observed_at "
                "FROM authority_heads"
            ).fetchone()
            revoked_inputs = json.loads(
                connection.execute(
                    "SELECT record_inputs_json FROM attempts WHERE attempt_id=?",
                    (revoked_attempt,),
                ).fetchone()[0]
            )
        self.assertEqual((2, "REVOKED", observed_at), head)
        self.assertEqual(
            ["CLOCK_ROLLBACK", "REVOKED_PERMISSION"],
            revoked_inputs["validation_reasons"],
        )

        shutil.copyfile(
            self.fixture_root / "r6a_authority_revision_1_active.json",
            self.sandbox / "authority.json",
        )
        payload_b = b"clock-rollback-stale-replay-payload-b"
        with mock.patch.object(binding, "_utc_now", return_value=later):
            replay = binding.bind_text(
                self.sandbox,
                task_basename="task.json",
                authority_basename="authority.json",
                target_basename="output.txt",
                payload=payload_b,
                attempt_id=str(uuid.uuid4()),
                expected_instance_id=self.instance,
            )
        self.assertEqual("DENIED", replay["state"])
        self.assertEqual("AUTHORITY_ROLLBACK", replay["reason_code"])
        self.assertEqual("NOT_BOUND", replay["records"]["consequence_commit"]["effect_state"])
        self.assertEqual(payload_a, target.read_bytes())
        self._assert_no_temp_residue()
        inspected = self._inspect()
        self.assertEqual(1, inspected["authority_head_count"])
        self.assertEqual(3, inspected["attempt_count"])
        self.assertEqual(8, inspected["record_count"])
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])

    def test_already_satisfied_guard_precedes_structural_task_denial(self) -> None:
        payload_text = "pre-existing-equality-with-malformed-task"
        target = self.sandbox / "output.txt"
        target.write_bytes(payload_text.encode("utf-8"))
        before = os.lstat(target)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        task_path = self.sandbox / "task.json"
        task = json.loads(task_path.read_text(encoding="utf-8"))
        task["source_refs"] = []
        task_path.write_text(
            json.dumps(task, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )

        attempt_id = str(uuid.uuid4())
        result = self._run_json(*self._bind_arguments(attempt_id, payload_text))
        self.assertEqual("RECORDED_NOT_BOUND", result["state"])
        self.assertEqual("ALREADY_SATISFIED", result["reason_code"])
        self.assertEqual(
            {"decision_basis", "consequence_commit", "non_effect_witness"},
            set(result["records"]),
        )
        commit = result["records"]["consequence_commit"]
        witness = result["records"]["non_effect_witness"]
        self.assertEqual("UNKNOWN", commit["task_contract_status"])
        self.assertEqual("VALID", commit["permission_status"])
        self.assertEqual("NOT_BOUND", commit["effect_state"])
        self.assertEqual("HOLD", commit["commit_outcome"])
        preconditions = {
            item["name"]: item["status"] for item in commit["precondition_results"]
        }
        self.assertEqual("FAIL", preconditions["SOURCE_GROUNDING"])
        self.assertEqual("FAIL", preconditions["BLOCKING_STATE"])
        self.assertEqual(
            "NO_EFFECT_OBSERVED_WITHIN_DECLARED_SCOPE", witness["conclusion"]
        )
        binding = self._load_binding_module()
        binding.validate_runtime_bundle(
            result["records"]["decision_basis"], commit, witness
        )

        after = os.lstat(target)
        self.assertEqual(
            before_identity,
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        )
        self.assertEqual(payload_text.encode("utf-8"), target.read_bytes())
        database = self.sandbox / ".c_binding" / "binding_state.sqlite3"
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            stored = connection.execute(
                "SELECT state,temp_basename,record_inputs_json FROM attempts "
                "WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
            authority_heads = connection.execute(
                "SELECT COUNT(*) FROM authority_heads"
            ).fetchone()[0]
        self.assertIsNotNone(stored)
        self.assertEqual(("RECORDED_NOT_BOUND", None), stored[:2])
        self.assertEqual(
            ["SOURCE_PASSPORT_TAMPERING"],
            json.loads(stored[2])["validation_reasons"],
        )
        self.assertEqual(0, authority_heads)
        self._assert_no_temp_residue()
        self.assertEqual([], self._recover())
        inspected = self._inspect()
        self.assertEqual(1, inspected["attempt_count"])
        self.assertEqual(3, inspected["record_count"])
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])

    @r6a_scenarios.scenario("R6A-LOCK-003-NO-HALF-WRITTEN-ENVELOPE")
    def test_authority_writer_handles_partial_writes_and_cleans_failures(self) -> None:
        binding = self._load_binding_module()
        authority_path = self.sandbox / "authority.json"
        envelope = json.loads(authority_path.read_text(encoding="utf-8"))
        real_write = os.write
        write_sizes: list[int] = []

        def partial_write(fd: int, data: Any) -> int:
            offered = len(data)
            count = max(1, offered // 3)
            write_sizes.append(offered)
            return real_write(fd, memoryview(data)[:count])

        with mock.patch.object(binding.os, "write", side_effect=partial_write):
            result = binding.cooperative_write_authority(
                self.sandbox,
                authority_basename="authority.json",
                envelope=envelope,
                expected_instance_id=self.instance,
            )
        self.assertEqual("AUTHORITY_WRITTEN", result["state"])
        self.assertEqual(self.instance, result["journal_instance_id"])
        self.assertGreater(len(write_sizes), 1)
        self.assertEqual(envelope, json.loads(authority_path.read_text(encoding="utf-8")))
        self._assert_no_temp_residue()

        stable_authority = authority_path.read_bytes()
        failure_injections = (
            ("write", binding.os, "write", OSError("injected authority write failure")),
            ("fsync", binding.os, "fsync", OSError("injected authority fsync failure")),
            ("replace", binding.os, "replace", OSError("injected authority replace failure")),
        )
        for stage, owner, attribute, failure in failure_injections:
            with self.subTest(stage=stage):
                with mock.patch.object(owner, attribute, side_effect=failure):
                    with self.assertRaisesRegex(OSError, f"injected authority {stage} failure"):
                        binding.cooperative_write_authority(
                            self.sandbox,
                            authority_basename="authority.json",
                            envelope=envelope,
                            expected_instance_id=self.instance,
                        )
                self.assertEqual(stable_authority, authority_path.read_bytes())
                self._assert_no_temp_residue()

        inspected = self._inspect()
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])

    def test_full_uuid_record_ids_prevent_prefix_collision_and_recover_cleanly(self) -> None:
        first_attempt = "12345678-1234-1234-1234-1234567890ab"
        second_attempt = "12345678-1234-1234-1234-1234deadbeef"
        self.assertEqual(
            first_attempt.replace("-", "")[:24],
            second_attempt.replace("-", "")[:24],
        )

        first = self._run_json(
            *self._bind_arguments(first_attempt, "first-collision-family-payload")
        )
        self._run(
            *self._bind_arguments(second_attempt, "second-collision-family-payload"),
            expected_returncode=93,
            failpoint="R6A-CRASH-003",
        )
        self.assertEqual("RECORDED_BOUND", first["state"])
        self.assertEqual(
            b"second-collision-family-payload",
            (self.sandbox / "output.txt").read_bytes(),
        )
        crashed = self._inspect()
        self.assertEqual(1, crashed["prepared_count"])

        recovered = self._recover()
        self.assertEqual(1, len(recovered))
        second = recovered[0]
        self.assertEqual(second_attempt, second["attempt_id"])
        self.assertEqual("RECOVERED_BOUND", second["state"])
        self.assertEqual("CRASH_AFTER_EFFECT", second["reason_code"])
        first_ids = {record["record_id"] for record in first["records"].values()}
        second_ids = {record["record_id"] for record in second["records"].values()}
        self.assertTrue(first_ids.isdisjoint(second_ids))
        self.assertEqual(
            b"second-collision-family-payload",
            (self.sandbox / "output.txt").read_bytes(),
        )
        self.assertEqual([], self._recover())
        self._assert_no_temp_residue()
        inspected = self._inspect()
        self.assertEqual(2, inspected["attempt_count"])
        self.assertEqual(4, inspected["record_count"])
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])

    def test_concurrent_fresh_initializers_share_one_valid_journal_instance(self) -> None:
        race_sandbox = Path(self.temporary.name) / "initialize-race-sandbox"
        race_sandbox.mkdir()
        barrier_root = Path(self.temporary.name) / "initialize-race-barrier"
        barrier_root.mkdir()
        go = barrier_root / "go"
        race_program = "\n".join(
            (
                "import json, sys, time",
                "from pathlib import Path",
                "sys.path.insert(0, sys.argv[1])",
                "import cgam_durable_binding as binding",
                "sandbox, ready, go = map(Path, sys.argv[2:5])",
                "ready.touch()",
                "deadline = time.monotonic() + 15.0",
                "while not go.exists():",
                "    if time.monotonic() >= deadline:",
                "        raise TimeoutError('initialize race barrier timed out')",
                "    time.sleep(0.005)",
                "print(json.dumps(binding.initialize_binding(sandbox), sort_keys=True))",
            )
        )
        processes: list[subprocess.Popen[str]] = []
        try:
            for index in range(2):
                ready = barrier_root / f"ready-{index}"
                processes.append(
                    subprocess.Popen(
                        [
                            sys.executable,
                            "-B",
                            "-c",
                            race_program,
                            str(self.script.parent),
                            str(race_sandbox),
                            str(ready),
                            str(go),
                        ],
                        cwd=self.root,
                        env=self._environment(),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        encoding="utf-8",
                    )
                )
            deadline = time.monotonic() + 15.0
            ready_paths = [barrier_root / f"ready-{index}" for index in range(2)]
            while time.monotonic() < deadline:
                for process in processes:
                    if process.poll() is not None:
                        stdout, stderr = process.communicate()
                        self.fail(
                            "initializer exited before shared start: "
                            f"rc={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
                        )
                if all(path.exists() for path in ready_paths):
                    break
                time.sleep(0.01)
            else:
                self.fail("concurrent initializers did not reach the shared start barrier")
            go.touch()

            results: list[dict[str, Any]] = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=20.0)
                self.assertEqual(
                    0,
                    process.returncode,
                    msg=f"stdout={stdout!r}; stderr={stderr!r}",
                )
                results.append(json.loads(stdout))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.communicate(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=5.0)

        self.assertEqual(["INITIALIZED", "INITIALIZED"], [item["state"] for item in results])
        instances = {item["journal_instance_id"] for item in results}
        self.assertEqual(1, len(instances))
        instance = instances.pop()
        inspected = self._run_json(
            "inspect",
            "--sandbox",
            str(race_sandbox),
            "--expected-instance",
            instance,
        )
        self.assertEqual("JOURNAL_VALID", inspected["state"])
        self.assertEqual(instance, inspected["journal_instance_id"])
        self.assertEqual("DELETE", inspected["journal_mode"])
        self.assertEqual(2, inspected["synchronous"])
        self.assertEqual(1, inspected["foreign_keys"])
        self.assertEqual("ok", inspected["integrity_check"])
        sentinel = json.loads(
            (race_sandbox / ".c_binding" / "binding.lock").read_text(encoding="utf-8")
        )
        self.assertEqual("R6A_CGAM_BINDING_LOCK_v0.1", sentinel["magic"])
        self.assertEqual(instance, sentinel["journal_instance_id"])
        with contextlib.closing(sqlite3.connect(
            race_sandbox / ".c_binding" / "binding_state.sqlite3"
        )) as connection, connection:
            stored_instance = connection.execute(
                "SELECT value FROM journal_meta WHERE key='journal_instance_id'"
            ).fetchone()
        self.assertEqual((instance,), stored_instance)

    def test_pre_establishment_authority_temp_collision_repeats_without_database(self) -> None:
        fresh_sandbox = Path(self.temporary.name) / "reserved-temp-collision-sandbox"
        fresh_sandbox.mkdir()
        reserved_temp = fresh_sandbox / ".c_binding_authority_preexisting"
        reserved_bytes = b"caller-pre-existing-reserved-name"
        reserved_temp.write_bytes(reserved_bytes)

        for attempt in range(2):
            with self.subTest(attempt=attempt):
                rejected = self._run(
                    "init",
                    "--sandbox",
                    str(fresh_sandbox),
                    expected_returncode=2,
                )
                error = json.loads(rejected.stdout)
                self.assertEqual("AUTHORITY_TEMP_COLLISION", error["error_code"])
                self.assertEqual(reserved_bytes, reserved_temp.read_bytes())
                self.assertFalse(
                    (fresh_sandbox / ".c_binding" / "binding_state.sqlite3").exists()
                )
                self.assertEqual(
                    [],
                    list((fresh_sandbox / ".c_binding").glob("binding_state.sqlite3-*")),
                )

    def test_expected_instance_never_reinitializes_empty_internal_directory(self) -> None:
        empty_sandbox = Path(self.temporary.name) / "empty-established-sandbox"
        empty_sandbox.mkdir()
        internal = empty_sandbox / ".c_binding"
        internal.mkdir()
        retained_instance = str(uuid.uuid4())

        for attempt in range(2):
            with self.subTest(attempt=attempt):
                rejected = self._run(
                    "init",
                    "--sandbox",
                    str(empty_sandbox),
                    "--expected-instance",
                    retained_instance,
                    expected_returncode=2,
                )
                error = json.loads(rejected.stdout)
                self.assertEqual(
                    "JOURNAL_MISSING_AFTER_ESTABLISHMENT", error["error_code"]
                )
                self.assertEqual([], list(internal.iterdir()))

    def test_runtime_identity_domain_failure_is_durable_no_effect(self) -> None:
        oversized_identity = "a:" + ("x" * 304)
        self.assertEqual(306, len(oversized_identity))
        task_path = self.sandbox / "task.json"
        authority_path = self.sandbox / "authority.json"
        task = json.loads(task_path.read_text(encoding="utf-8"))
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        task["human_anchor_ref"] = oversized_identity
        authority["grant_payload"]["human_anchor_ref"] = oversized_identity
        task_path.write_text(
            json.dumps(task, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        authority_path.write_text(
            json.dumps(authority, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )

        attempt_id = str(uuid.uuid4())
        denied = self._run_json(
            *self._bind_arguments(attempt_id, "runtime-domain-probe")
        )
        self.assertEqual("DENIED", denied["state"])
        self.assertEqual("RUNTIME_IDENTITY_REFERENCE_INVALID", denied["reason_code"])
        self.assertEqual(
            {"decision_basis", "consequence_commit", "non_effect_witness"},
            set(denied["records"]),
        )
        commit = denied["records"]["consequence_commit"]
        decision = denied["records"]["decision_basis"]
        self.assertEqual("NOT_BOUND", commit["effect_state"])
        self.assertEqual("DENY", commit["commit_outcome"])
        self.assertLessEqual(len(decision["basis"]["human_anchor_ref"]), 256)
        self.assertNotEqual(
            oversized_identity, decision["basis"]["human_anchor_ref"]
        )
        self.assertFalse((self.sandbox / "output.txt").exists())
        self._assert_no_temp_residue()
        self.assertEqual([], self._recover())
        inspected = self._inspect()
        self.assertEqual(1, inspected["attempt_count"])
        self.assertEqual(3, inspected["record_count"])
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])

    def test_255_utf8_byte_portable_basename_has_bounded_runtime_effect_id(self) -> None:
        target_basename = "ab" + ("界" * 83) + ".txt"
        self.assertEqual(255, len(target_basename.encode("utf-8")))
        target_ref = f"target-basename:{target_basename}"
        runtime_target_ref = f"sandbox-basename:{target_basename}"
        task_path = self.sandbox / "task.json"
        authority_path = self.sandbox / "authority.json"
        task = json.loads(task_path.read_text(encoding="utf-8"))
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        task["scope"]["refs"] = [target_ref]
        authority["grant_payload"]["scope"]["refs"] = [target_ref]
        task_path.write_text(
            json.dumps(task, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        authority_path.write_text(
            json.dumps(authority, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )

        payload_text = "maximum-portable-basename-payload"
        result = self._run_json(
            *self._bind_arguments(
                str(uuid.uuid4()), payload_text, target=target_basename
            )
        )
        self.assertEqual("RECORDED_BOUND", result["state"])
        self.assertEqual("AUTHORIZED_EFFECT", result["reason_code"])
        commit = result["records"]["consequence_commit"]
        self.assertEqual("BOUND", commit["effect_state"])
        self.assertEqual(runtime_target_ref, commit["target_effect"]["target_ref"])
        self.assertTrue(
            commit["target_effect"]["effect_id"].startswith(
                "WRITE_SANDBOX_TEXT_V1:"
            )
        )
        self.assertLessEqual(len(commit["target_effect"]["effect_id"]), 256)
        self.assertEqual(
            payload_text.encode("utf-8"),
            (self.sandbox / target_basename).read_bytes(),
        )
        self._assert_no_temp_residue()
        self.assertEqual([], self._recover())
        inspected = self._inspect()
        self.assertEqual(1, inspected["attempt_count"])
        self.assertEqual(2, inspected["record_count"])
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])

    def test_aggregate_record_inputs_are_bounded_and_reopen_after_effect(self) -> None:
        task_path = self.sandbox / "task.json"
        authority_path = self.sandbox / "authority.json"
        task = json.loads(task_path.read_text(encoding="utf-8"))
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        task["scope"]["summary"] = "T" * 600_000
        authority["grant_payload"]["scope"]["summary"] = "A" * 600_000
        task_path.write_text(
            json.dumps(task, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        authority_path.write_text(
            json.dumps(authority, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        binding = self._load_binding_module()
        self.assertLess(task_path.stat().st_size, binding.MAX_JSON_BYTES)
        self.assertLess(authority_path.stat().st_size, binding.MAX_JSON_BYTES)

        attempt_id = str(uuid.uuid4())
        result = self._run_json(
            *self._bind_arguments(attempt_id, "bounded-aggregate-inputs")
        )
        self.assertEqual("RECORDED_BOUND", result["state"])
        self.assertEqual("AUTHORIZED_EFFECT", result["reason_code"])
        self.assertEqual(
            b"bounded-aggregate-inputs",
            (self.sandbox / "output.txt").read_bytes(),
        )
        database = self.sandbox / ".c_binding" / "binding_state.sqlite3"
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            state, reason, inputs_size = connection.execute(
                "SELECT state,reason_code,length(record_inputs_json) "
                "FROM attempts WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
        self.assertEqual(("RECORDED_BOUND", "AUTHORIZED_EFFECT"), (state, reason))
        self.assertGreater(inputs_size, binding.MAX_JSON_BYTES)
        self.assertLessEqual(inputs_size, binding.MAX_RECORD_INPUTS_BYTES)
        self.assertEqual([], self._recover())
        inspected = self._inspect()
        self.assertEqual(1, inspected["attempt_count"])
        self.assertEqual(2, inspected["record_count"])
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])
        self._assert_no_temp_residue()

    def test_preexisting_canonical_payload_temp_is_never_adopted_or_removed(self) -> None:
        attempt_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        reserved_temp = self.sandbox / f".c_binding_payload_{attempt_id}"
        reserved_bytes = b"caller-owned-preexisting-payload-temp"
        reserved_temp.write_bytes(reserved_bytes)
        before = os.lstat(reserved_temp)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )

        for attempt in range(2):
            with self.subTest(attempt=attempt):
                rejected = self._run(
                    *self._bind_arguments(attempt_id, "must-not-be-written"),
                    expected_returncode=2,
                )
                error = json.loads(rejected.stdout)
                self.assertEqual("PAYLOAD_TEMP_COLLISION", error["error_code"])
                after = os.lstat(reserved_temp)
                self.assertEqual(
                    before_identity,
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                )
                self.assertEqual(reserved_bytes, reserved_temp.read_bytes())
                self.assertFalse((self.sandbox / "output.txt").exists())
                inspected = self._inspect()
                self.assertEqual(0, inspected["authority_head_count"])
                self.assertEqual(0, inspected["attempt_count"])
                self.assertEqual(0, inspected["record_count"])
                self.assertEqual(0, inspected["prepared_count"])
                self.assertEqual(0, inspected["quarantined_count"])
                self.assertEqual([], self._sqlite_transients())

    def test_recovered_not_bound_window_encloses_actual_target_observation(self) -> None:
        attempt_id = str(uuid.uuid4())
        self._run(
            *self._bind_arguments(attempt_id, "observed-recovery-payload"),
            expected_returncode=91,
            failpoint="R6A-CRASH-001",
        )
        binding = self._load_binding_module()
        actual_target_state = binding._target_state
        observations: list[tuple[datetime, datetime]] = []

        def observed_target_state(path: Path) -> dict[str, Any]:
            started = datetime.now(timezone.utc)
            result = actual_target_state(path)
            finished = datetime.now(timezone.utc)
            observations.append((started, finished))
            return result

        with mock.patch.object(
            binding, "_target_state", side_effect=observed_target_state
        ):
            recovered = binding.recover_pending(
                self.sandbox, expected_instance_id=self.instance
            )
        self.assertEqual(1, len(recovered))
        self.assertEqual("RECOVERED_NOT_BOUND", recovered[0]["state"])
        self.assertEqual(1, len(observations))
        observed_start, observed_end = observations[0]
        witness = recovered[0]["records"]["non_effect_witness"]
        commit = recovered[0]["records"]["consequence_commit"]
        window_start = datetime.fromisoformat(
            witness["observation_window"]["start"].replace("Z", "+00:00")
        )
        window_end = datetime.fromisoformat(
            witness["observation_window"]["end"].replace("Z", "+00:00")
        )
        commit_time = datetime.fromisoformat(
            commit["created_at"].replace("Z", "+00:00")
        )
        self.assertLessEqual(window_start, observed_start)
        self.assertLessEqual(observed_start, observed_end)
        self.assertLessEqual(observed_end, window_end)
        self.assertLessEqual(window_start, commit_time)
        self.assertLessEqual(commit_time, window_end)
        self.assertEqual(witness["created_at"], witness["observation_window"]["end"])
        self._assert_no_temp_residue()
        self.assertEqual([], self._recover())

    def test_abrupt_authority_writer_crash_orphan_is_recovered_on_restart(self) -> None:
        original_authority = (self.sandbox / "authority.json").read_bytes()
        crash_program = "\n".join(
            (
                "import json, os, sys",
                "from pathlib import Path",
                "sys.path.insert(0, sys.argv[1])",
                "import cgam_durable_binding as binding",
                "sandbox = Path(sys.argv[2])",
                "envelope = json.loads((sandbox / 'authority.json').read_text(encoding='utf-8'))",
                "binding.os.replace = lambda *args: os._exit(95)",
                "binding.cooperative_write_authority(",
                "    sandbox, authority_basename='authority.json', envelope=envelope,",
                "    expected_instance_id=sys.argv[3]",
                ")",
            )
        )
        crashed = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                crash_program,
                str(self.script.parent),
                str(self.sandbox),
                self.instance,
            ],
            cwd=self.root,
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            check=False,
            timeout=30.0,
        )
        self.assertEqual(
            95,
            crashed.returncode,
            msg=f"stdout={crashed.stdout!r}; stderr={crashed.stderr!r}",
        )
        self.assertEqual("", crashed.stdout)
        orphan_temps = self._authority_temps()
        self.assertEqual(1, len(orphan_temps))
        orphan_bytes = orphan_temps[0].read_bytes()
        self.assertEqual(original_authority, (self.sandbox / "authority.json").read_bytes())

        wrong_instance = self._run(
            "inspect",
            "--sandbox",
            str(self.sandbox),
            "--expected-instance",
            str(uuid.uuid4()),
            expected_returncode=2,
        )
        self.assertEqual(
            "JOURNAL_INSTANCE_MISMATCH",
            json.loads(wrong_instance.stdout)["error_code"],
        )
        self.assertEqual(1, len(self._authority_temps()))
        self.assertEqual(orphan_bytes, self._authority_temps()[0].read_bytes())
        self.assertEqual(original_authority, (self.sandbox / "authority.json").read_bytes())

        inspected = self._inspect()
        self.assertEqual("JOURNAL_VALID", inspected["state"])
        self.assertEqual(original_authority, (self.sandbox / "authority.json").read_bytes())
        self._assert_no_temp_residue()
        self.assertEqual([], self._recover())

    @r6a_scenarios.scenario(
        "R6A-LOCK-001-SECOND-WRITER-BLOCKS",
        "R6A-LOCK-002-SUCCESSOR-ORDERED",
    )
    def test_cross_process_lock_blocks_then_accepts_successor_revision(self) -> None:
        first_attempt = str(uuid.uuid4())
        first = self._run_json(
            *self._bind_arguments(first_attempt, "revision-one-payload")
        )
        self.assertEqual("RECORDED_BOUND", first["state"])

        revision_two = json.loads(
            (self.sandbox / "authority.json").read_text(encoding="utf-8")
        )
        revision_two["authority_revision"] = 2
        revision_two["previous_grant_hash"] = first["records"][
            "consequence_commit"
        ]["permission_grant_ref"]["hash"]
        revision_two["grant_payload"]["updated_at"] = "2026-08-28T00:01:00Z"
        revision_input = self.sandbox / "revision-two-input.json"
        revision_input.write_text(
            json.dumps(revision_two, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )

        writer: subprocess.Popen[str] | None = None
        successor: subprocess.Popen[str] | None = None
        try:
            writer = subprocess.Popen(
                self._command(
                    "write-authority",
                    "--sandbox",
                    str(self.sandbox),
                    "--authority",
                    "authority.json",
                    "--envelope-basename",
                    revision_input.name,
                    "--expected-instance",
                    self.instance,
                    "--hold-seconds",
                    "3.0",
                ),
                cwd=self.root,
                env=self._environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                if writer.poll() is not None:
                    stdout, stderr = writer.communicate()
                    self.fail(
                        "authority writer exited before the held-lock probe: "
                        f"rc={writer.returncode}, stdout={stdout!r}, stderr={stderr!r}"
                    )
                try:
                    current = json.loads(
                        (self.sandbox / "authority.json").read_text(encoding="utf-8")
                    )
                except (OSError, json.JSONDecodeError):
                    current = {}
                if current.get("authority_revision") == 2:
                    break
                time.sleep(0.02)
            else:
                self.fail("authority writer did not publish revision two while holding the lock")

            successor_attempt = str(uuid.uuid4())
            successor_started = time.monotonic()
            successor = subprocess.Popen(
                self._command(
                    *self._bind_arguments(successor_attempt, "revision-two-payload")
                ),
                cwd=self.root,
                env=self._environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            time.sleep(0.25)
            self.assertIsNone(writer.poll(), "authority writer did not retain the common lock")
            self.assertIsNone(successor.poll(), "successor did not block on the common lock")

            writer_stdout, writer_stderr = writer.communicate(timeout=10.0)
            self.assertEqual(
                0,
                writer.returncode,
                msg=f"stdout={writer_stdout!r}; stderr={writer_stderr!r}",
            )
            successor_stdout, successor_stderr = successor.communicate(timeout=15.0)
            successor_elapsed = time.monotonic() - successor_started
            self.assertEqual(
                0,
                successor.returncode,
                msg=f"stdout={successor_stdout!r}; stderr={successor_stderr!r}",
            )
            self.assertGreaterEqual(successor_elapsed, 1.5)
            writer_result = json.loads(writer_stdout)
            successor_result = json.loads(successor_stdout)
        finally:
            for process in (successor, writer):
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.communicate(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=5.0)

        self.assertEqual("AUTHORITY_WRITTEN", writer_result["state"])
        self.assertEqual(self.instance, writer_result["journal_instance_id"])
        self.assertEqual("RECORDED_BOUND", successor_result["state"])
        self.assertEqual("AUTHORIZED_EFFECT", successor_result["reason_code"])
        self.assertEqual(self.instance, successor_result["journal_instance_id"])
        self.assertEqual(
            b"revision-two-payload", (self.sandbox / "output.txt").read_bytes()
        )
        self._assert_no_temp_residue()

        database = self.sandbox / ".c_binding" / "binding_state.sqlite3"
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            head_revision = connection.execute(
                "SELECT authority_revision FROM authority_heads"
            ).fetchone()
        self.assertEqual((2,), head_revision)
        inspected = self._inspect()
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])
        self.assertEqual(2, inspected["attempt_count"])
        self.assertEqual([], self._recover())

    def test_cooperative_writer_rejects_rollback_and_equivocation_without_effect(self) -> None:
        first = self._run_json(
            *self._bind_arguments(str(uuid.uuid4()), "accepted-revision-one")
        )
        self.assertEqual("RECORDED_BOUND", first["state"])

        revision_two_input = self.sandbox / "revision-two-publication.json"
        shutil.copyfile(
            self.fixture_root / "r6a_authority_revision_2_revoked.json",
            revision_two_input,
        )
        published = self._run_json(
            "write-authority",
            "--sandbox",
            str(self.sandbox),
            "--authority",
            "authority.json",
            "--envelope-basename",
            revision_two_input.name,
            "--expected-instance",
            self.instance,
        )
        self.assertEqual("AUTHORITY_WRITTEN", published["state"])
        second = self._run_json(
            *self._bind_arguments(str(uuid.uuid4()), "accepted-revision-two")
        )
        self.assertEqual("DENIED", second["state"])
        self.assertEqual("REVOKED_PERMISSION", second["reason_code"])
        target = self.sandbox / "output.txt"
        self.assertEqual(b"accepted-revision-one", target.read_bytes())
        stable_authority = (self.sandbox / "authority.json").read_bytes()
        before = os.lstat(target)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )

        stale_input = self.sandbox / "stale-revision-one-publication.json"
        shutil.copyfile(
            self.fixture_root / "r6a_authority_revision_1_active.json",
            stale_input,
        )
        rollback = self._run(
            "write-authority",
            "--sandbox",
            str(self.sandbox),
            "--authority",
            "authority.json",
            "--envelope-basename",
            stale_input.name,
            "--expected-instance",
            self.instance,
            expected_returncode=2,
        )
        self.assertEqual(
            "AUTHORITY_ROLLBACK", json.loads(rollback.stdout)["error_code"]
        )
        self.assertEqual(stable_authority, (self.sandbox / "authority.json").read_bytes())

        equivocal = json.loads(stable_authority)
        equivocal["grant_payload"]["updated_at"] = "2026-08-28T00:01:01Z"
        equivocal_input = self.sandbox / "equivocal-revision-two-publication.json"
        equivocal_input.write_text(
            json.dumps(equivocal, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        equivocation = self._run(
            "write-authority",
            "--sandbox",
            str(self.sandbox),
            "--authority",
            "authority.json",
            "--envelope-basename",
            equivocal_input.name,
            "--expected-instance",
            self.instance,
            expected_returncode=2,
        )
        self.assertEqual(
            "AUTHORITY_EQUIVOCATION",
            json.loads(equivocation.stdout)["error_code"],
        )
        self.assertEqual(stable_authority, (self.sandbox / "authority.json").read_bytes())

        binding = self._load_binding_module()
        current = json.loads(stable_authority)
        revision_gap = json.loads(stable_authority)
        revision_gap["authority_revision"] = 4
        revision_gap["previous_grant_hash"] = binding.canonical_hash(
            current["grant_payload"]
        )
        gap_input = self.sandbox / "revision-gap-publication.json"
        gap_input.write_bytes(binding.canonical_bytes(revision_gap) + b"\n")
        gap = self._run(
            "write-authority",
            "--sandbox",
            str(self.sandbox),
            "--authority",
            "authority.json",
            "--envelope-basename",
            gap_input.name,
            "--expected-instance",
            self.instance,
            expected_returncode=2,
        )
        self.assertEqual(
            "AUTHORITY_REVISION_GAP", json.loads(gap.stdout)["error_code"]
        )
        self.assertEqual(stable_authority, (self.sandbox / "authority.json").read_bytes())

        wrong_predecessor = json.loads(stable_authority)
        wrong_predecessor["authority_revision"] = 3
        wrong_predecessor["previous_grant_hash"] = "f" * 64
        predecessor_input = self.sandbox / "wrong-predecessor-publication.json"
        predecessor_input.write_bytes(
            binding.canonical_bytes(wrong_predecessor) + b"\n"
        )
        predecessor = self._run(
            "write-authority",
            "--sandbox",
            str(self.sandbox),
            "--authority",
            "authority.json",
            "--envelope-basename",
            predecessor_input.name,
            "--expected-instance",
            self.instance,
            expected_returncode=2,
        )
        self.assertEqual(
            "AUTHORITY_PREDECESSOR_MISMATCH",
            json.loads(predecessor.stdout)["error_code"],
        )
        self.assertEqual(stable_authority, (self.sandbox / "authority.json").read_bytes())
        after = os.lstat(target)
        self.assertEqual(
            before_identity,
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        )
        self.assertEqual(b"accepted-revision-one", target.read_bytes())
        self._assert_no_temp_residue()
        inspected = self._inspect()
        self.assertEqual(2, inspected["attempt_count"])
        self.assertEqual(5, inspected["record_count"])
        self.assertEqual(0, inspected["prepared_count"])
        self.assertEqual(0, inspected["quarantined_count"])
        database = self.sandbox / ".c_binding" / "binding_state.sqlite3"
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            head_revision = connection.execute(
                "SELECT authority_revision FROM authority_heads"
            ).fetchone()
        self.assertEqual((2,), head_revision)
        self.assertEqual([], self._recover())

    def test_cooperative_successor_waits_for_initial_journal_head_without_deadlock(self) -> None:
        revision_two_input = self.sandbox / "premature-revision-two.json"
        shutil.copyfile(
            self.fixture_root / "r6a_authority_revision_2_revoked.json",
            revision_two_input,
        )
        original_authority = (self.sandbox / "authority.json").read_bytes()
        premature = self._run(
            "write-authority",
            "--sandbox",
            str(self.sandbox),
            "--authority",
            "authority.json",
            "--envelope-basename",
            revision_two_input.name,
            "--expected-instance",
            self.instance,
            expected_returncode=2,
        )
        self.assertEqual(
            "AUTHORITY_HEAD_UNESTABLISHED",
            json.loads(premature.stdout)["error_code"],
        )
        self.assertEqual(original_authority, (self.sandbox / "authority.json").read_bytes())
        self.assertFalse((self.sandbox / "output.txt").exists())
        initial_inspect = self._inspect()
        self.assertEqual(0, initial_inspect["authority_head_count"])
        self.assertEqual(0, initial_inspect["attempt_count"])
        self.assertEqual(0, initial_inspect["record_count"])
        self._assert_no_temp_residue()

        bound = self._run_json(
            *self._bind_arguments(str(uuid.uuid4()), "establish-revision-one")
        )
        self.assertEqual("RECORDED_BOUND", bound["state"])
        published = self._run_json(
            "write-authority",
            "--sandbox",
            str(self.sandbox),
            "--authority",
            "authority.json",
            "--envelope-basename",
            revision_two_input.name,
            "--expected-instance",
            self.instance,
        )
        self.assertEqual("AUTHORITY_WRITTEN", published["state"])
        self.assertEqual(
            2,
            json.loads(
                (self.sandbox / "authority.json").read_text(encoding="utf-8")
            )["authority_revision"],
        )
        final_inspect = self._inspect()
        self.assertEqual(1, final_inspect["authority_head_count"])
        self.assertEqual(1, final_inspect["attempt_count"])
        self.assertEqual(2, final_inspect["record_count"])
        self.assertEqual(0, final_inspect["prepared_count"])
        self._assert_no_temp_residue()


if __name__ == "__main__":
    unittest.main()
