#!/usr/bin/env python3
"""R6A durable local CGAM binding for one sandbox text-file effect.

The accepted claim is deliberately narrow: cooperative local processes using
this module's lock, one persistent SQLite journal, and one exact target basename
inside a caller-created local sandbox.  It is not a service, a generic
transaction framework, full CGAM conformance, or production enforcement.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from cgam_durable_binding_runtime_adapter import (
    NOT_BOUND_COMMIT_CLAIM_BOUNDARY,
    WITNESS_CLAIM_BOUNDARY,
    canonical_bytes,
    canonical_hash,
    validate_runtime_bundle,
)


PROFILE = "R6A_CGAM_AUTHORITY_ENVELOPE_v0.1"
SCHEMA_VERSION = 1
APPLICATION_ID = 0x52364131  # ASCII R6A1
THREAT_PROFILE_SHA256 = "da051f1e1d185137e0350d38d31325e9725d15c2cefbd9ef1ad5e428208fedc6"
CONTRACT_SHA256 = "38861868039bff433da9c96911eddc09beb4414b07fcbabd41cdb021c3c9c737"
SOURCE_FREEZE_SHA256 = "af6293518e9bf5f029973eaaa480567b69b987281cda02ac0f8e85cc31056d61"
BASE_COMMIT = "47fed105d7b1df1df7375aa203a551b0f684c13d"
BASE_TREE = "f1162ca73c508d1cd82544265f93ce5242c2aecb"
CGAM_COMMIT = "c3b004d7439a8c608f08233fc17be1150c442b44"
CGAM_TREE = "9a0b25d162f40347a4434b2bc9482b92e0170e85"
PERMISSION = "PERM-WRITE-SANDBOX"
CAPABILITY = "CAP-WRITE-SANDBOX"
EFFECT_TYPE = "WRITE_SANDBOX_TEXT_V1"
BINDING_DIR = ".c_binding"
DATABASE_NAME = "binding_state.sqlite3"
LOCK_NAME = "binding.lock"
PAYLOAD_TEMP_PREFIX = ".c_binding_payload_"
AUTHORITY_TEMP_PREFIX = ".c_binding_authority_"
LOCK_MAGIC = "R6A_CGAM_BINDING_LOCK_v0.1"
MAX_JSON_BYTES = 1_048_576
# A code-produced record-input snapshot contains one task/envelope pair plus
# bounded derived material.  Final revalidation and recovery retain at most one
# complete predecessor snapshot, so the largest supported internal blob has at
# most two snapshots.  Eight external-input ceilings cover those four source
# documents, duplicated bounded identity material, and fixed adapter metadata.
MAX_RECORD_INPUTS_BYTES = 8 * MAX_JSON_BYTES
MAX_PAYLOAD_BYTES = 1_048_576
ZERO_HASH = "0" * 64

TERMINAL_STATES = {
    "DENIED",
    "RECORDED_BOUND",
    "RECORDED_NOT_BOUND",
    "RECOVERED_BOUND",
    "RECOVERED_NOT_BOUND",
    "QUARANTINED_UNRESOLVED",
}
ALL_STATES = TERMINAL_STATES | {"PREPARED"}
PROHIBITION_FIELDS = (
    "direct_memory_write_allowed",
    "self_approval_allowed",
    "witness_tampering_allowed",
    "secret_prompting_allowed",
    "live_external_exploitation_allowed",
    "hack_back_allowed",
    "autonomous_retaliation_allowed",
    "malware_behavior_allowed",
    "credential_theft_allowed",
    "covert_persistence_allowed",
    "uncontrolled_network_allowed",
    "cloud_secret_upload_allowed",
)
SECTION_PROHIBITIONS = (
    "direct_memory_write_allowed",
    "self_approval_allowed",
    "uncontrolled_network_allowed",
    "cloud_secret_upload_allowed",
)
ENVELOPE_FIELDS = {
    "profile", "authority_revision", "previous_grant_hash", "grant_payload",
}
SECTION_FIELDS = {
    "summary", "status", "decision", "refs", *SECTION_PROHIBITIONS,
}
TASK_FIELDS = {
    "schema_version", "contract_id", "task_id", "created_at", "updated_at",
    "governing_entity_id", "human_anchor_ref", "assigned_agent_ref",
    "permission_grant_ref", "decision", "gate_status", "source_profile",
    "source_refs", "authority", "scope", "permission_requirements",
    *PROHIBITION_FIELDS,
}
GRANT_FIELDS = {
    "schema_version", "grant_id", "task_id", "agent_id",
    "governing_entity_id", "human_anchor_ref", "task_contract_ref",
    "created_at", "updated_at", "expires_at", "grant_status", "permissions",
    "capability_bindings", "source_profile", "scope", "revocation",
    *PROHIBITION_FIELDS,
}

CGAM_SOURCE_REFS = (
    ("README.md", "461194018e88e25720ffee0a94f14218e6c4b1a0"),
    ("CHECKSUM_SCOPE.json", "ef2ebc2ba2ac435800d7eb1d6da8d029218c8c6b"),
    ("tools/verify_tagged_tree_manifest.py", "0ca80bd93ac040af895e897504ef1e753540574d"),
    ("docs/markdown/CLI_Agent_Task_Contract_Schema_v0_1.md", "4f0e88fa196f9a8220a885cf71e8b615d673e9da"),
    ("docs/markdown/CLI_Agent_Permission_and_Capability_Model_v0_1.md", "af50f2b5cf3c4c88b947ec261fdaa6862c3d7ffa"),
    ("schemas/common/cgam-common-defs-0.1.schema.json", "62398a016ab67a5f1af98f45db0e9f239060c03d"),
    ("schemas/task-contract/cli-agent-task-contract-0.1.schema.json", "b17d33a06421565f2ff63b67118b32005a873d50"),
    ("schemas/permission-capability/cli-agent-permission-grant-0.1.schema.json", "9c0625a239cf91848bfeeb106a528c6932896fd2"),
    ("schemas/SCHEMA_INDEX.json", "6f8c383099ce7615e415890fcaf938729169b4d6"),
    ("validator/SEMANTIC_RULES_INDEX.json", "b059c5e8b1e77b1c6ed633bbdf0d98e020f14910"),
    ("fixtures/FIXTURE_MANIFEST.json", "a423fb1d60bca982e9a51f67354308f22c35c180"),
)

CGAM_SOURCE_PASSPORT = {
    "repository": "https://github.com/Kot141078/c-governed-cli-agent-mesh",
    "commit": CGAM_COMMIT,
    "tree": CGAM_TREE,
    "source_freeze_sha256": SOURCE_FREEZE_SHA256,
    "artifacts": [
        {"path": path, "git_blob_sha1": blob} for path, blob in CGAM_SOURCE_REFS
    ],
    "claim_boundary": "R6A exact local subset only; not full CGAM conformance",
}
CGAM_SOURCE_PASSPORT_HASH = canonical_hash(CGAM_SOURCE_PASSPORT)

EXPECTED_TABLES = {
    "journal_meta",
    "authority_heads",
    "attempts",
    "records",
}

DDL = """
CREATE TABLE journal_meta (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL,
    row_hash TEXT NOT NULL
);
CREATE TABLE authority_heads (
    authority_key TEXT PRIMARY KEY NOT NULL,
    governing_entity_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    task_contract_id TEXT NOT NULL,
    authority_revision INTEGER NOT NULL,
    previous_grant_hash TEXT,
    grant_hash TEXT NOT NULL,
    envelope_hash TEXT NOT NULL,
    grant_json BLOB NOT NULL,
    effective_status TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    row_hash TEXT NOT NULL
);
CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    authority_key TEXT NOT NULL,
    target_basename TEXT NOT NULL,
    target_key TEXT NOT NULL,
    payload BLOB NOT NULL,
    payload_hash TEXT NOT NULL,
    pre_exists INTEGER NOT NULL,
    pre_hash TEXT,
    pre_state_hash TEXT NOT NULL,
    pre_identity_json BLOB,
    task_json BLOB NOT NULL,
    envelope_json BLOB NOT NULL,
    task_hash TEXT NOT NULL,
    envelope_hash TEXT NOT NULL,
    grant_hash TEXT NOT NULL,
    authority_revision INTEGER NOT NULL,
    previous_grant_hash TEXT,
    prepared_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    state TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    temp_basename TEXT,
    record_inputs_json BLOB NOT NULL,
    post_state_hash TEXT,
    terminal_record_set_hash TEXT,
    row_hash TEXT NOT NULL
);
CREATE TABLE records (
    record_id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL,
    attempt_ordinal INTEGER NOT NULL,
    chain_ordinal INTEGER NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    terminal_state TEXT NOT NULL,
    record_json BLOB NOT NULL,
    record_hash TEXT NOT NULL,
    previous_record_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL,
    UNIQUE(attempt_id, attempt_ordinal),
    FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id)
);
"""

EXPECTED_COLUMNS = {
    "journal_meta": ("key", "value", "row_hash"),
    "authority_heads": (
        "authority_key", "governing_entity_id", "grant_id", "agent_id",
        "task_contract_id", "authority_revision", "previous_grant_hash",
        "grant_hash", "envelope_hash", "grant_json", "effective_status",
        "observed_at", "row_hash",
    ),
    "attempts": (
        "attempt_id", "authority_key", "target_basename", "target_key",
        "payload", "payload_hash", "pre_exists", "pre_hash", "pre_state_hash",
        "pre_identity_json", "task_json", "envelope_json", "task_hash",
        "envelope_hash", "grant_hash", "authority_revision",
        "previous_grant_hash", "prepared_at", "updated_at", "state",
        "reason_code", "temp_basename", "record_inputs_json", "post_state_hash",
        "terminal_record_set_hash", "row_hash",
    ),
    "records": (
        "record_id", "attempt_id", "attempt_ordinal", "chain_ordinal", "kind",
        "terminal_state", "record_json", "record_hash", "previous_record_hash",
        "row_hash",
    ),
}


class BindingError(RuntimeError):
    """Fail-closed binding error with a stable machine code."""

    def __init__(self, code: str, message: str, *, state: str = "QUARANTINED_UNRESOLVED") -> None:
        self.code = code
        self.state = state
        super().__init__(message)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise BindingError("INVALID_TIMESTAMP", f"{field} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BindingError("INVALID_TIMESTAMP", f"{field} is not RFC3339: {value!r}") from exc
    if parsed.tzinfo is None:
        raise BindingError("INVALID_TIMESTAMP", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _canonical_time(value: Any, field: str) -> str:
    return _parse_time(value, field).isoformat().replace("+00:00", "Z")


def _observation_end_after(start: str, field: str) -> str:
    """Sample after observation and express a positive clock-resolution window."""
    start_dt = _parse_time(start, field)
    sampled = _parse_time(_utc_now(), field)
    if sampled <= start_dt:
        sampled = start_dt + timedelta(microseconds=1)
    return sampled.isoformat().replace("+00:00", "Z")


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BindingError("DUPLICATE_JSON_KEY", f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise BindingError("INVALID_JSON_NUMBER", f"non-finite JSON number {value!r}")


def _strict_json_bytes(
    raw: bytes,
    label: str,
    *,
    max_bytes: int = MAX_JSON_BYTES,
) -> dict[str, Any]:
    if not raw or len(raw) > max_bytes:
        raise BindingError("JSON_SIZE_INVALID", f"{label} must be 1..{max_bytes} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BindingError("JSON_NOT_UTF8", f"{label} must be UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_no_duplicate_object,
            parse_constant=_reject_constant,
            parse_float=lambda _: (_ for _ in ()).throw(
                BindingError("JSON_FLOAT_FORBIDDEN", f"{label} contains a floating-point number")
            ),
        )
    except BindingError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise BindingError("INVALID_JSON", f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise BindingError("JSON_OBJECT_REQUIRED", f"{label} must be a JSON object")
    canonical_bytes(value)  # existing validator owns the accepted JCS domain
    return value


def _json_blob(value: Any) -> bytes:
    return canonical_bytes(value)


def _strict_record_inputs_bytes(raw: bytes, label: str) -> dict[str, Any]:
    return _strict_json_bytes(raw, label, max_bytes=MAX_RECORD_INPUTS_BYTES)


def _record_inputs_blob(value: Any, label: str = "record_inputs_json") -> bytes:
    raw = _json_blob(value)
    _strict_record_inputs_bytes(raw, label)
    return raw


def _is_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _validate_sandbox(sandbox: os.PathLike[str] | str) -> Path:
    path = Path(sandbox)
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise BindingError("SANDBOX_MISSING", "caller-created sandbox does not exist") from exc
    if stat.S_ISLNK(info.st_mode) or _is_reparse(path):
        raise BindingError("SANDBOX_LINK_OR_REPARSE", "sandbox is a symlink or reparse point")
    if not stat.S_ISDIR(info.st_mode):
        raise BindingError("SANDBOX_NOT_DIRECTORY", "sandbox is not a directory")
    return path.resolve(strict=True)


_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
} | {f"{prefix}{number}" for prefix in ("COM", "LPT") for number in ("¹", "²", "³")}


def validate_basename(name: str, *, allow_internal_input: bool = False) -> str:
    if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 255:
        raise BindingError("INVALID_BASENAME", "basename must be 1..255 UTF-8 bytes")
    if "\x00" in name:
        raise BindingError("PATH_NUL", "basename contains NUL")
    if name in {".", ".."} or "/" in name or "\\" in name:
        raise BindingError("PATH_TRAVERSAL_OR_SEPARATOR", "only one exact basename is allowed")
    if ":" in name or Path(name).is_absolute() or name.startswith("//"):
        raise BindingError("PATH_ABSOLUTE_DRIVE_OR_UNC", "absolute, drive, and UNC names are forbidden")
    if any(ord(character) < 32 or character in '<>"|?*' for character in name):
        raise BindingError(
            "WINDOWS_INVALID_CHARACTER",
            "basename contains a non-portable Windows control or punctuation character",
        )
    if name[-1] in {" ", "."}:
        raise BindingError("WINDOWS_TRAILING_DOT_OR_SPACE", "trailing dot or space is forbidden")
    if name.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
        raise BindingError("WINDOWS_RESERVED_DEVICE", "Windows reserved device name is forbidden")
    folded = name.casefold()
    if folded == BINDING_DIR.casefold() or folded.startswith(PAYLOAD_TEMP_PREFIX.casefold()):
        raise BindingError("INTERNAL_PATH_COLLISION", "basename collides with binding internals")
    if not allow_internal_input and folded.startswith(AUTHORITY_TEMP_PREFIX.casefold()):
        raise BindingError("INTERNAL_PATH_COLLISION", "basename collides with binding internals")
    return name


def _basename_key(name: str) -> str:
    """Return a conservative cross-platform collision key for one basename."""
    return name.casefold()


def _journal_revision(envelope: dict[str, Any]) -> int:
    """Represent structurally invalid revisions durably without raising raw errors."""
    revision = envelope.get("authority_revision")
    if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 1:
        return revision
    return 0


def _identity(info: os.stat_result) -> dict[str, str]:
    # Windows file indexes can exceed the validator's I-JSON safe-integer
    # domain.  Decimal strings preserve the exact OS identity without lossy
    # numeric coercion in canonical JSON.
    return {
        "device": str(int(info.st_dev)),
        "inode": str(int(info.st_ino)),
        "mode": str(int(info.st_mode)),
        "size": str(int(info.st_size)),
    }


def _target_state(path: Path) -> dict[str, Any]:
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        state = {"exists": False, "content_sha256": None}
        return {"state": state, "state_hash": canonical_hash(state), "identity": None}
    if stat.S_ISLNK(before.st_mode) or _is_reparse(path) or not stat.S_ISREG(before.st_mode):
        raise BindingError("TARGET_UNSAFE_TYPE", "target must be absent or a regular non-reparse file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if _identity(opened) != _identity(before):
            raise BindingError("TARGET_IDENTITY_RACE", "target identity changed during acquisition")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 131072)
            if not chunk:
                break
            digest.update(chunk)
        content_hash = digest.hexdigest()
    finally:
        os.close(fd)
    state = {"exists": True, "content_sha256": content_hash}
    return {"state": state, "state_hash": canonical_hash(state), "identity": _identity(before)}


def _hashable(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"blob_sha256": _sha256(value), "blob_size": len(value)}
    if isinstance(value, dict):
        return {str(key): _hashable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_hashable(item) for item in value]
    return value


def _row_hash(table: str, row: dict[str, Any]) -> str:
    body = {key: value for key, value in row.items() if key != "row_hash"}
    return canonical_hash({"table": table, "row": _hashable(body)})


def _fsync_directory(path: Path) -> dict[str, Any]:
    if os.name == "nt":
        return {"supported": False, "result": "UNSUPPORTED_BY_PYTHON_STDLIB_ON_WINDOWS"}
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"supported": True, "result": "FSYNC_OK"}


def _lock_handle(handle: Any, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    if os.name == "nt":
        import msvcrt

        while True:
            try:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise BindingError("LOCK_TIMEOUT", "timed out acquiring binding lock")
                time.sleep(0.025)
    else:
        import fcntl

        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise BindingError("LOCK_TIMEOUT", "timed out acquiring binding lock")
                time.sleep(0.025)


def _unlock_handle(handle: Any) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def _binding_lock(sandbox: Path, *, create: bool, timeout: float = 30.0) -> Iterator[tuple[Path, Any, bool]]:
    internal = sandbox / BINDING_DIR
    created_internal = False
    try:
        info = os.lstat(internal)
    except FileNotFoundError:
        if not create:
            raise BindingError("JOURNAL_MISSING", "established binding directory is missing")
        try:
            os.mkdir(internal, 0o700)
            created_internal = True
            _fsync_directory(sandbox)
        except FileExistsError:
            # A cooperative concurrent initializer may have won the mkdir race.
            created_internal = False
        info = os.lstat(internal)
    if stat.S_ISLNK(info.st_mode) or _is_reparse(internal) or not stat.S_ISDIR(info.st_mode):
        raise BindingError("BINDING_DIRECTORY_UNSAFE", "binding directory is not a regular directory boundary")
    lock_path = internal / LOCK_NAME
    try:
        lock_info = os.lstat(lock_path)
    except FileNotFoundError:
        lock_info = None
    if lock_info is not None and (
        stat.S_ISLNK(lock_info.st_mode) or _is_reparse(lock_path) or not stat.S_ISREG(lock_info.st_mode)
    ):
        raise BindingError("LOCK_FILE_UNSAFE", "binding lock must be a regular non-reparse file")
    handle = open(lock_path, "a+b", buffering=0)
    locked = False
    try:
        # Both msvcrt byte-range locks and POSIX flock can lock an empty file.
        # Bootstrap the placeholder only after acquiring that lock: writing it
        # before acquisition lets a delayed fresh opener append a stale NUL to
        # the established JSON sentinel.
        _lock_handle(handle, timeout)
        locked = True
        if os.fstat(handle.fileno()).st_size == 0:
            handle.seek(0)
            handle.write(b"\x00")
            os.fsync(handle.fileno())
        database = internal / DATABASE_NAME
        handle.seek(0)
        sentinel_bytes = handle.read(MAX_JSON_BYTES + 1)
        names = {entry.name for entry in os.scandir(internal)}
        pristine = names == {LOCK_NAME} and sentinel_bytes and not sentinel_bytes.strip(b"\x00")
        fresh = create and not database.exists() and pristine
        yield internal, handle, fresh
    finally:
        if locked:
            _unlock_handle(handle)
        handle.close()


def _write_lock_sentinel(handle: Any, instance_id: str) -> None:
    sentinel = {
        "magic": LOCK_MAGIC,
        "schema_version": SCHEMA_VERSION,
        "journal_instance_id": instance_id,
    }
    raw = _json_blob(sentinel) + b"\n"
    handle.seek(0)
    handle.truncate(0)
    handle.write(raw)
    handle.flush()
    os.fsync(handle.fileno())


def _read_lock_sentinel(handle: Any) -> dict[str, Any]:
    handle.seek(0)
    raw = handle.read(MAX_JSON_BYTES + 1)
    try:
        sentinel = _strict_json_bytes(raw.strip(), "binding lock sentinel")
    except BindingError as exc:
        raise BindingError("LOCK_SENTINEL_INVALID", str(exc)) from exc
    if sentinel.get("magic") != LOCK_MAGIC or sentinel.get("schema_version") != SCHEMA_VERSION:
        raise BindingError("LOCK_SENTINEL_INVALID", "binding lock sentinel profile/version mismatch")
    instance = sentinel.get("journal_instance_id")
    try:
        uuid.UUID(str(instance))
    except (ValueError, AttributeError) as exc:
        raise BindingError("LOCK_SENTINEL_INVALID", "binding lock sentinel instance is invalid") from exc
    return sentinel


def _meta_row(key: str, value: str) -> dict[str, Any]:
    row = {"key": key, "value": value}
    row["row_hash"] = _row_hash("journal_meta", row)
    return row


def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    row = _meta_row(key, value)
    conn.execute(
        "INSERT INTO journal_meta(key,value,row_hash) VALUES(:key,:value,:row_hash) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,row_hash=excluded.row_hash",
        row,
    )


def _get_meta(conn: sqlite3.Connection, key: str) -> str:
    found = conn.execute("SELECT value FROM journal_meta WHERE key=?", (key,)).fetchone()
    if found is None:
        raise BindingError("JOURNAL_META_MISSING", f"required journal metadata {key!r} is missing")
    return str(found[0])


def _configure(conn: sqlite3.Connection, *, initialize: bool) -> None:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    mode_sql = "PRAGMA journal_mode=DELETE" if initialize else "PRAGMA journal_mode"
    mode = str(conn.execute(mode_sql).fetchone()[0]).lower()
    conn.execute("PRAGMA synchronous=FULL")
    if mode != "delete":
        raise BindingError("SQLITE_JOURNAL_MODE", f"journal_mode readback is {mode!r}, expected 'delete'")
    if int(conn.execute("PRAGMA synchronous").fetchone()[0]) != 2:
        raise BindingError("SQLITE_SYNCHRONOUS", "synchronous readback is not FULL")
    if int(conn.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
        raise BindingError("SQLITE_FOREIGN_KEYS", "foreign_keys readback is not ON")


def _create_database(path: Path) -> tuple[sqlite3.Connection, str]:
    if path.exists():
        raise BindingError("JOURNAL_COLLISION", "journal path already exists during initialization")
    conn = sqlite3.connect(path)
    try:
        _configure(conn, initialize=True)
        conn.executescript(DDL)
        conn.execute(f"PRAGMA application_id={APPLICATION_ID}")
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        instance_id = str(uuid.uuid4())
        created = _utc_now()
        for key, value in (
            ("schema_version", str(SCHEMA_VERSION)),
            ("journal_instance_id", instance_id),
            ("created_at", created),
            ("record_count", "0"),
            ("record_chain_head", ZERO_HASH),
            ("last_checked_at", created),
        ):
            row = _meta_row(key, value)
            conn.execute(
                "INSERT INTO journal_meta(key,value,row_hash) VALUES(:key,:value,:row_hash)", row
            )
        conn.commit()
        return conn, instance_id
    except Exception:
        conn.close()
        raise


def _open_existing_database(path: Path) -> sqlite3.Connection:
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise BindingError("JOURNAL_MISSING", "established journal database is missing") from exc
    if stat.S_ISLNK(info.st_mode) or _is_reparse(path) or not stat.S_ISREG(info.st_mode):
        raise BindingError("JOURNAL_UNSAFE_TYPE", "journal database must be a regular non-reparse file")
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True)
        _configure(conn, initialize=False)
        _audit_database(conn)
        return conn
    except BindingError:
        if conn is not None:
            conn.close()
        raise
    except sqlite3.Error as exc:
        if conn is not None:
            conn.close()
        raise BindingError(
            "SQLITE_OPEN_OR_INTEGRITY_FAILURE",
            f"journal open/configuration/integrity failed: {exc}",
        ) from exc


def _audit_row_hashes(conn: sqlite3.Connection, table: str) -> None:
    for sqlite_row in conn.execute(f"SELECT * FROM {table}"):
        row = dict(sqlite_row)
        if row.get("row_hash") != _row_hash(table, row):
            raise BindingError("JOURNAL_ROW_HASH_MISMATCH", f"{table} row hash mismatch")


def _audit_canonical_blob(
    blob: Any,
    label: str,
    *,
    max_bytes: int = MAX_JSON_BYTES,
) -> dict[str, Any]:
    if not isinstance(blob, bytes):
        raise BindingError("JOURNAL_BLOB_TYPE", f"{label} is not stored as bytes")
    value = _strict_json_bytes(blob, label, max_bytes=max_bytes)
    if _json_blob(value) != blob:
        raise BindingError("JOURNAL_NONCANONICAL_JSON", f"{label} is not canonical JSON")
    return value


def _audit_database(conn: sqlite3.Connection) -> None:
    integrity = [str(row[0]) for row in conn.execute("PRAGMA integrity_check")]
    if integrity != ["ok"]:
        raise BindingError("SQLITE_INTEGRITY_CHECK", f"integrity_check failed: {integrity!r}")
    if int(conn.execute("PRAGMA application_id").fetchone()[0]) != APPLICATION_ID:
        raise BindingError("JOURNAL_APPLICATION_ID", "unexpected SQLite application_id")
    if int(conn.execute("PRAGMA user_version").fetchone()[0]) != SCHEMA_VERSION:
        raise BindingError("JOURNAL_SCHEMA_VERSION", "unknown journal schema version")
    tables = {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    if tables != EXPECTED_TABLES:
        raise BindingError("JOURNAL_TABLE_SET", f"journal tables are {sorted(tables)!r}")
    for table, expected in EXPECTED_COLUMNS.items():
        actual = tuple(str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})"))
        if actual != expected:
            raise BindingError("JOURNAL_COLUMN_SET", f"{table} columns are {actual!r}")
    unexpected_objects = list(
        conn.execute(
            "SELECT type,name FROM sqlite_master WHERE type IN ('view','trigger') AND name NOT LIKE 'sqlite_%'"
        )
    )
    if unexpected_objects:
        raise BindingError("JOURNAL_UNEXPECTED_OBJECT", "journal contains an unexpected view or trigger")
    for table in EXPECTED_TABLES:
        _audit_row_hashes(conn, table)
    required_meta = {
        "schema_version", "journal_instance_id", "created_at", "record_count",
        "record_chain_head", "last_checked_at",
    }
    actual_meta = {str(row[0]) for row in conn.execute("SELECT key FROM journal_meta")}
    if actual_meta != required_meta:
        raise BindingError("JOURNAL_META_SET", f"journal metadata keys are {sorted(actual_meta)!r}")
    if _get_meta(conn, "schema_version") != str(SCHEMA_VERSION):
        raise BindingError("JOURNAL_SCHEMA_VERSION", "journal schema metadata mismatch")
    try:
        uuid.UUID(_get_meta(conn, "journal_instance_id"))
        record_count = int(_get_meta(conn, "record_count"))
    except ValueError as exc:
        raise BindingError("JOURNAL_META_INVALID", "journal instance/count metadata is invalid") from exc
    previous = ZERO_HASH
    records = list(conn.execute("SELECT * FROM records ORDER BY chain_ordinal"))
    if len(records) != record_count:
        raise BindingError("RECORD_COUNT_MISMATCH", "record count metadata does not match rows")
    for expected, sqlite_row in enumerate(records, 1):
        row = dict(sqlite_row)
        if int(row["chain_ordinal"]) != expected or row["previous_record_hash"] != previous:
            raise BindingError("RECORD_CHAIN_INVALID", "record hash chain is non-contiguous")
        value = _audit_canonical_blob(row["record_json"], "record_json")
        if canonical_hash(value) != row["record_hash"]:
            raise BindingError("RECORD_HASH_MISMATCH", "stored Runtime record hash mismatch")
        previous = str(row["record_hash"])
    if _get_meta(conn, "record_chain_head") != previous:
        raise BindingError("RECORD_CHAIN_HEAD_MISMATCH", "record chain head metadata mismatch")
    for row in conn.execute("SELECT * FROM authority_heads"):
        grant = _audit_canonical_blob(row["grant_json"], "authority grant_json")
        if canonical_hash(grant) != row["grant_hash"]:
            raise BindingError("AUTHORITY_GRANT_HASH_MISMATCH", "authority grant hash mismatch")
    accepted_authority_snapshots: dict[str, dict[int, tuple[str, str, str | None]]] = {}
    for row in conn.execute("SELECT * FROM attempts"):
        for field in ("task_json", "envelope_json"):
            _audit_canonical_blob(row[field], f"attempt {field}")
        record_inputs = _audit_canonical_blob(
            row["record_inputs_json"],
            "attempt record_inputs_json",
            max_bytes=MAX_RECORD_INPUTS_BYTES,
        )
        if canonical_hash(_strict_json_bytes(row["task_json"], "task_json")) != row["task_hash"]:
            raise BindingError("ATTEMPT_TASK_HASH_MISMATCH", "attempt task hash mismatch")
        if canonical_hash(_strict_json_bytes(row["envelope_json"], "envelope_json")) != row["envelope_hash"]:
            raise BindingError("ATTEMPT_ENVELOPE_HASH_MISMATCH", "attempt envelope hash mismatch")
        if _sha256(row["payload"]) != row["payload_hash"]:
            raise BindingError("ATTEMPT_PAYLOAD_HASH_MISMATCH", "attempt payload hash mismatch")
        if row["state"] not in ALL_STATES:
            raise BindingError("ATTEMPT_STATE_INVALID", "attempt contains an unknown state")
        snapshots: list[dict[str, Any]] = []
        current_inputs: Any = record_inputs
        for _ in range(3):
            if not isinstance(current_inputs, dict):
                break
            snapshots.append(current_inputs)
            current_inputs = current_inputs.get("planning_record_inputs")
        if current_inputs is not None:
            raise BindingError("AUTHORITY_LINEAGE_DEPTH", "authority planning lineage exceeds the bounded depth")
        for snapshot in snapshots:
            head = snapshot.get("authority_head")
            envelope = snapshot.get("envelope")
            if not isinstance(head, dict) or not isinstance(envelope, dict):
                continue
            revision = snapshot.get("authority_revision")
            if not isinstance(revision, int):
                continue
            if (
                head.get("authority_revision") == revision
                and head.get("envelope_hash") == snapshot.get("envelope_hash")
                and head.get("grant_hash") == snapshot.get("grant_hash")
            ):
                by_revision = accepted_authority_snapshots.setdefault(
                    str(snapshot.get("authority_key")), {}
                )
                candidate = (
                    str(snapshot.get("grant_hash")),
                    str(snapshot.get("envelope_hash")),
                    envelope.get("previous_grant_hash"),
                )
                existing = by_revision.get(revision)
                if existing is not None and existing != candidate:
                    raise BindingError("AUTHORITY_EQUIVOCATION_IN_JOURNAL", "accepted authority revision is equivocal")
                by_revision[revision] = candidate
    for head_row in conn.execute("SELECT * FROM authority_heads"):
        head = dict(head_row)
        key = str(head["authority_key"])
        revision = int(head["authority_revision"])
        lineage = accepted_authority_snapshots.get(key, {})
        if set(lineage) != set(range(1, revision + 1)):
            raise BindingError("AUTHORITY_LINEAGE_MISSING", "current authority head lacks complete accepted attempt lineage")
        for item_revision in range(1, revision + 1):
            grant_hash, envelope_hash, predecessor = lineage[item_revision]
            if item_revision == 1 and predecessor is not None:
                raise BindingError("AUTHORITY_LINEAGE_INVALID", "initial accepted authority has a predecessor")
            if item_revision > 1 and predecessor != lineage[item_revision - 1][0]:
                raise BindingError("AUTHORITY_LINEAGE_INVALID", "accepted authority predecessor hash is broken")
            if item_revision == revision and (
                grant_hash != head["grant_hash"] or envelope_hash != head["envelope_hash"]
            ):
                raise BindingError("AUTHORITY_HEAD_LINEAGE_MISMATCH", "current authority head does not match accepted lineage")
    for attempt_sqlite in conn.execute("SELECT * FROM attempts"):
        attempt = dict(attempt_sqlite)
        record_rows = [
            dict(item)
            for item in conn.execute(
                "SELECT * FROM records WHERE attempt_id=? ORDER BY attempt_ordinal",
                (attempt["attempt_id"],),
            )
        ]
        record_hashes = [str(item["record_hash"]) for item in record_rows]
        if attempt["state"] == "PREPARED":
            if record_rows or attempt["terminal_record_set_hash"] is not None:
                raise BindingError("PREPARED_TERMINAL_EVIDENCE", "PREPARED attempt carries terminal evidence")
            continue
        if not record_rows or attempt["terminal_record_set_hash"] != canonical_hash(record_hashes):
            raise BindingError("TERMINAL_RECORD_SET_HASH", "terminal attempt record-set hash is missing or invalid")
        by_kind = {
            str(item["kind"]): _strict_json_bytes(item["record_json"], "terminal record_json")
            for item in record_rows
        }
        if attempt["state"] == "QUARANTINED_UNRESOLVED":
            transition = by_kind.get("binding_transition")
            if not isinstance(transition, dict) or transition.get("state") != "QUARANTINED_UNRESOLVED":
                raise BindingError("QUARANTINE_RECORD_INVALID", "quarantined attempt lacks its superseding transition")
            continue
        bound = attempt["state"] in {"RECORDED_BOUND", "RECOVERED_BOUND"}
        expected_kinds = {"decision_basis", "consequence_commit"}
        if not bound:
            expected_kinds.add("non_effect_witness")
        if set(by_kind) != expected_kinds or any(
            item["terminal_state"] != attempt["state"] for item in record_rows
        ):
            raise BindingError("TERMINAL_RECORD_CARDINALITY", "terminal Runtime record kinds/state are invalid")
        try:
            validate_runtime_bundle(
                by_kind["decision_basis"],
                by_kind["consequence_commit"],
                by_kind.get("non_effect_witness"),
            )
            inputs = _strict_record_inputs_bytes(
                attempt["record_inputs_json"], "record_inputs_json"
            )
            rebuilt = _build_runtime_records(
                inputs,
                state=attempt["state"],
                reason=attempt["reason_code"],
                bound=bound,
                denied=(
                    attempt["state"] == "DENIED"
                    or (
                        attempt["state"] == "RECORDED_NOT_BOUND"
                        and attempt["reason_code"] != "ALREADY_SATISFIED"
                    )
                ),
                before_state_hash=attempt["pre_state_hash"],
                after_state_hash=attempt["post_state_hash"],
                checked_at=by_kind["consequence_commit"]["created_at"],
            )
        except Exception as exc:
            raise BindingError("RUNTIME_RECORD_BUNDLE_INVALID", f"stored terminal Runtime bundle is invalid: {exc}") from exc
        rebuilt_map = {kind: record for kind, record in rebuilt}
        if rebuilt_map != by_kind:
            raise BindingError(
                "RUNTIME_RECORD_RECONSTRUCTION_MISMATCH",
                "stored terminal Runtime records do not match immutable binding inputs",
            )
    for attempt_id, count in conn.execute(
        "SELECT attempt_id,COUNT(*) FROM records GROUP BY attempt_id,kind HAVING COUNT(*)>1"
    ):
        raise BindingError("DUPLICATE_TERMINAL_RECORD", f"attempt {attempt_id} has duplicate record kinds ({count})")
    if list(conn.execute("PRAGMA foreign_key_check")):
        raise BindingError("SQLITE_FOREIGN_KEY_CHECK", "foreign_key_check reported violations")


def _recover_authority_temps(sandbox: Path, *, established: bool) -> None:
    """Recover safe orphaned cooperative-writer temps while holding the lock."""
    candidates = [
        Path(entry.path)
        for entry in os.scandir(sandbox)
        if entry.name.casefold().startswith(AUTHORITY_TEMP_PREFIX.casefold())
    ]
    if not candidates:
        return
    if not established:
        raise BindingError(
            "AUTHORITY_TEMP_COLLISION",
            "reserved authority temp exists before journal establishment",
        )
    for path in candidates:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or _is_reparse(path) or not stat.S_ISREG(info.st_mode):
            raise BindingError(
                "AUTHORITY_TEMP_UNSAFE",
                "orphan authority temp is not a safe regular non-reparse file",
            )
    removed = False
    try:
        for path in candidates:
            try:
                os.unlink(path)
                removed = True
            except FileNotFoundError:
                pass
        if removed:
            _fsync_directory(sandbox)
    except OSError as exc:
        raise BindingError(
            "AUTHORITY_TEMP_RECOVERY_FAILED",
            f"failed to recover orphan authority temp: {exc}",
        ) from exc


@contextlib.contextmanager
def _journal(
    sandbox: Path,
    *,
    create: bool,
    expected_instance_id: str | None = None,
    lock_timeout: float = 30.0,
) -> Iterator[tuple[sqlite3.Connection, str, Path, Any]]:
    if expected_instance_id is not None:
        internal_probe = sandbox / BINDING_DIR
        if not all(
            path.exists()
            for path in (
                internal_probe,
                internal_probe / LOCK_NAME,
                internal_probe / DATABASE_NAME,
            )
        ):
            # A retained instance identity proves this is not first
            # initialization.  Reject before creating even a directory, lock
            # placeholder, database, or cleanup mutation.
            raise BindingError(
                "JOURNAL_MISSING_AFTER_ESTABLISHMENT",
                "established binding components are missing; silent reinitialization is forbidden",
            )
    with _binding_lock(sandbox, create=create, timeout=lock_timeout) as (internal, handle, fresh):
        database = internal / DATABASE_NAME
        if fresh:
            if expected_instance_id is not None:
                raise BindingError(
                    "JOURNAL_MISSING_AFTER_ESTABLISHMENT",
                    "expected journal identity cannot authorize fresh initialization",
                )
            # A reserved writer temp that predates journal establishment is a
            # custody collision, never an orphan owned by this journal.  Check
            # before creating the database so every retry remains fail-closed.
            _recover_authority_temps(sandbox, established=False)
            conn, instance_id = _create_database(database)
            _write_lock_sentinel(handle, instance_id)
            _fsync_directory(internal)
            _audit_database(conn)
        else:
            sentinel = _read_lock_sentinel(handle)
            if (
                expected_instance_id is not None
                and expected_instance_id != sentinel["journal_instance_id"]
            ):
                raise BindingError(
                    "JOURNAL_INSTANCE_MISMATCH",
                    "unexpected established journal instance",
                )
            conn = _open_existing_database(database)
            instance_id = _get_meta(conn, "journal_instance_id")
            if sentinel["journal_instance_id"] != instance_id:
                conn.close()
                raise BindingError("JOURNAL_INSTANCE_MISMATCH", "lock sentinel and database instance differ")
        try:
            if not fresh:
                # Identity checks precede every recovery mutation: a caller
                # naming a different journal instance has no cleanup authority.
                _recover_authority_temps(sandbox, established=True)
            yield conn, instance_id, internal, handle
        finally:
            conn.close()


def initialize_binding(
    sandbox: os.PathLike[str] | str,
    *,
    expected_instance_id: str | None = None,
) -> dict[str, Any]:
    root = _validate_sandbox(sandbox)
    with _journal(root, create=True, expected_instance_id=expected_instance_id) as (conn, instance, internal, _):
        return {
            "state": "INITIALIZED",
            "journal_instance_id": instance,
            "database": str(internal / DATABASE_NAME),
            "journal_mode": str(conn.execute("PRAGMA journal_mode").fetchone()[0]).upper(),
            "synchronous": int(conn.execute("PRAGMA synchronous").fetchone()[0]),
            "foreign_keys": int(conn.execute("PRAGMA foreign_keys").fetchone()[0]),
            "integrity_check": str(conn.execute("PRAGMA integrity_check").fetchone()[0]),
            "table_count": len(EXPECTED_TABLES),
        }


def _read_input_file(root: Path, basename: str, label: str) -> tuple[dict[str, Any], bytes]:
    validate_basename(basename)
    path = root / basename
    try:
        before = os.lstat(path)
    except FileNotFoundError as exc:
        raise BindingError("INPUT_MISSING", f"{label} is missing") from exc
    if stat.S_ISLNK(before.st_mode) or _is_reparse(path) or not stat.S_ISREG(before.st_mode):
        raise BindingError("INPUT_UNSAFE_TYPE", f"{label} must be a regular non-reparse file")
    if before.st_size <= 0 or before.st_size > MAX_JSON_BYTES:
        raise BindingError("INPUT_SIZE_INVALID", f"{label} has invalid size")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if _identity(opened) != _identity(before):
            raise BindingError("INPUT_IDENTITY_RACE", f"{label} identity changed during acquisition")
        raw = b""
        while len(raw) <= MAX_JSON_BYTES:
            chunk = os.read(fd, min(131072, MAX_JSON_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(fd)
    return _strict_json_bytes(raw, label), raw


def _false_flags(value: Any, fields: tuple[str, ...], label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label.upper()}_NOT_OBJECT"]
    return [f"{label.upper()}_{field.upper()}" for field in fields if value.get(field) is not False]


def _source_refs_ok(task: dict[str, Any]) -> bool:
    refs = task.get("source_refs")
    expected = [{"file": path, "hash_ref": blob} for path, blob in CGAM_SOURCE_REFS]
    return refs == expected


def _section_ok(
    section: Any,
    *,
    target_ref: str | None = None,
    refs: list[str] | None = None,
    expected_status: str | None = None,
    expected_decision: str | None = None,
) -> bool:
    if not isinstance(section, dict):
        return False
    if set(section) != SECTION_FIELDS:
        return False
    if any(section.get(flag) is not False for flag in SECTION_PROHIBITIONS):
        return False
    if target_ref is not None and section.get("refs") != [target_ref]:
        return False
    if refs is not None and section.get("refs") != refs:
        return False
    if expected_status is not None and section.get("status") != expected_status:
        return False
    if expected_decision is not None and section.get("decision") != expected_decision:
        return False
    return True


def _authority_key(task: dict[str, Any], grant: dict[str, Any]) -> tuple[str, dict[str, str]]:
    material = {
        "governing_entity_id": str(task.get("governing_entity_id", "missing")),
        "grant_id": str(grant.get("grant_id", "missing")),
        "agent_id": str(grant.get("agent_id", "missing")),
        "task_contract_id": str(task.get("contract_id", "missing")),
    }
    return canonical_hash(material), material


def _validate_local_subset(
    task: dict[str, Any], envelope: dict[str, Any], target: str, checked_at: str
) -> tuple[list[str], list[str], str, dict[str, str], dict[str, Any]]:
    structural: list[str] = []
    authorization: list[str] = []
    if set(envelope) != ENVELOPE_FIELDS:
        structural.append("AUTHORITY_ENVELOPE_MEMBER_SET")
    if envelope.get("profile") != PROFILE:
        structural.append("AUTHORITY_PROFILE_MISMATCH")
    revision = envelope.get("authority_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        structural.append("AUTHORITY_REVISION_INVALID")
    previous = envelope.get("previous_grant_hash")
    if previous is not None and (not isinstance(previous, str) or len(previous) != 64):
        structural.append("AUTHORITY_PREDECESSOR_HASH_INVALID")
    grant = envelope.get("grant_payload")
    if not isinstance(grant, dict):
        grant = {}
        structural.append("GRANT_PAYLOAD_NOT_OBJECT")
    key, material = _authority_key(task, grant)
    if set(task) != TASK_FIELDS:
        structural.append("TASK_MEMBER_SET")
    if task.get("schema_version") != "cli-agent-task-contract-0.1":
        structural.append("TASK_SCHEMA_VERSION")
    if task.get("source_profile") != "CLI_Agent_Task_Contract_Schema_v0_1.md" or not _source_refs_ok(task):
        structural.append("SOURCE_PASSPORT_TAMPERING")
    required_task_strings = (
        "contract_id", "task_id", "created_at", "updated_at", "governing_entity_id",
        "human_anchor_ref", "assigned_agent_ref", "permission_grant_ref",
    )
    if any(not isinstance(task.get(name), str) or not task.get(name) for name in required_task_strings):
        structural.append("TASK_REQUIRED_FIELD")
    try:
        _parse_time(task.get("created_at"), "task.created_at")
        _parse_time(task.get("updated_at"), "task.updated_at")
    except BindingError:
        structural.append("TASK_TIMESTAMP_INVALID")
    structural.extend(_false_flags(task, PROHIBITION_FIELDS, "task"))
    target_ref = f"target-basename:{target}"
    permission_refs = [f"permission:{PERMISSION}", f"capability:{CAPABILITY}", f"effect:{EFFECT_TYPE}"]
    if not _section_ok(
        task.get("scope"),
        target_ref=target_ref,
        expected_status="CURRENT",
        expected_decision="ALLOW",
    ):
        structural.append("TASK_SCOPE_MISMATCH")
    if not _section_ok(
        task.get("permission_requirements"),
        refs=permission_refs,
        expected_status="CURRENT",
        expected_decision="ALLOW",
    ):
        structural.append("TASK_PERMISSION_REQUIREMENTS_MISMATCH")
    authority_section = task.get("authority")
    if not _section_ok(authority_section):
        structural.append("TASK_AUTHORITY_SECTION_INVALID")
    elif authority_section.get("refs") != [task.get("permission_grant_ref")]:
        structural.append("TASK_AUTHORITY_REFERENCE_MISMATCH")
    elif authority_section.get("status") != "CURRENT":
        authorization.append("STALE_CONTRACT")
    elif authority_section.get("decision") != "ALLOW":
        authorization.append("TASK_GATE_NOT_CURRENT")
    if task.get("decision") != "ALLOW" or task.get("gate_status") != "PASS":
        authorization.append("TASK_GATE_NOT_CURRENT")
    if grant.get("schema_version") != "cli-agent-permission-grant-0.1":
        structural.append("GRANT_SCHEMA_VERSION")
    if set(grant) != GRANT_FIELDS:
        structural.append("GRANT_MEMBER_SET")
    if grant.get("source_profile") != "CLI_Agent_Permission_and_Capability_Model_v0_1.md":
        structural.append("GRANT_SOURCE_PROFILE")
    required_grant_strings = (
        "grant_id", "task_id", "agent_id", "governing_entity_id", "human_anchor_ref",
        "task_contract_ref", "created_at", "updated_at", "expires_at", "grant_status",
    )
    if any(not isinstance(grant.get(name), str) or not grant.get(name) for name in required_grant_strings):
        structural.append("GRANT_REQUIRED_FIELD")
    structural.extend(_false_flags(grant, PROHIBITION_FIELDS, "grant"))
    if grant.get("permissions") != [PERMISSION]:
        structural.append("MISSING_OR_EXTRA_PERMISSION")
    if grant.get("capability_bindings") != {PERMISSION: [CAPABILITY]}:
        structural.append("MISSING_OR_EXTRA_CAPABILITY")
    if not _section_ok(
        grant.get("scope"),
        target_ref=target_ref,
        expected_status="CURRENT",
        expected_decision="ALLOW",
    ):
        structural.append("GRANT_SCOPE_MISMATCH")
    revocation = grant.get("revocation")
    if not _section_ok(revocation):
        structural.append("GRANT_REVOCATION_SECTION_INVALID")
    if grant.get("task_id") != task.get("task_id") or grant.get("task_contract_ref") != task.get("contract_id"):
        structural.append("TASK_MISMATCH")
    if grant.get("agent_id") != task.get("assigned_agent_ref"):
        structural.append("AGENT_MISMATCH")
    if grant.get("governing_entity_id") != task.get("governing_entity_id"):
        structural.append("GOVERNING_ENTITY_MISMATCH")
    if grant.get("human_anchor_ref") != task.get("human_anchor_ref"):
        structural.append("HUMAN_ANCHOR_MISMATCH")
    if grant.get("grant_id") != task.get("permission_grant_ref"):
        structural.append("GRANT_REFERENCE_MISMATCH")
    if grant.get("human_anchor_ref") == grant.get("agent_id"):
        structural.append("SELF_APPROVAL")
    runtime_identity_refs = (
        grant.get("human_anchor_ref"),
        grant.get("agent_id"),
    )
    if any(
        not isinstance(value, str) or not value or len(value) > 256
        for value in runtime_identity_refs
    ):
        structural.append("RUNTIME_IDENTITY_REFERENCE_INVALID")
    governing_entity = grant.get("governing_entity_id")
    if (
        not isinstance(governing_entity, str)
        or len(governing_entity) < 3
        or len(governing_entity) > 256
    ):
        structural.append("RUNTIME_GOVERNING_ENTITY_INVALID")
    status = grant.get("grant_status")
    if status not in {"ACTIVE", "REVOKED", "EXPIRED", "UNKNOWN"}:
        structural.append("GRANT_STATUS_INVALID")
    revocation_status = revocation.get("status") if isinstance(revocation, dict) else None
    revocation_decision = revocation.get("decision") if isinstance(revocation, dict) else None
    if status == "REVOKED" and (
        revocation_status != "REVOKED" or revocation_decision != "DENY"
    ):
        structural.append("REVOCATION_STATE_MISMATCH")
    if status != "REVOKED" and (
        revocation_status != "NOT_REVOKED" or revocation_decision != "ALLOW"
    ):
        structural.append("REVOCATION_STATE_MISMATCH")
    try:
        created = _parse_time(grant.get("created_at"), "grant.created_at")
        _parse_time(grant.get("updated_at"), "grant.updated_at")
        expires = _parse_time(grant.get("expires_at"), "grant.expires_at")
        checked = _parse_time(checked_at, "checked_at")
        if created >= expires:
            structural.append("GRANT_TIME_ORDER")
        if checked < created:
            authorization.append("GRANT_NOT_YET_VALID")
        if checked >= expires:  # fail closed at exact expiry, per pinned CGAM prose
            authorization.append("EXPIRED_PERMISSION")
    except BindingError:
        structural.append("GRANT_TIMESTAMP_INVALID")
    if status == "REVOKED":
        authorization.append("REVOKED_PERMISSION")
    elif status == "EXPIRED":
        authorization.append("EXPIRED_PERMISSION")
    elif status != "ACTIVE":
        authorization.append("UNKNOWN_PERMISSION_STATUS")
    return sorted(set(structural)), sorted(set(authorization)), key, material, grant


def _effective_permission_status(grant: dict[str, Any], checked_at: str) -> str:
    status = grant.get("grant_status")
    if status == "REVOKED":
        return "REVOKED"
    if status == "EXPIRED":
        return "EXPIRED"
    if status != "ACTIVE":
        return "UNKNOWN"
    try:
        if _parse_time(checked_at, "checked_at") >= _parse_time(grant.get("expires_at"), "expires_at"):
            return "EXPIRED"
    except BindingError:
        return "UNKNOWN"
    return "VALID"


def _authority_row(
    key: str,
    material: dict[str, str],
    envelope: dict[str, Any],
    grant: dict[str, Any],
    checked_at: str,
    *,
    observed_at: str | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "authority_key": key,
        **material,
        "authority_revision": int(envelope["authority_revision"]),
        "previous_grant_hash": envelope.get("previous_grant_hash"),
        "grant_hash": canonical_hash(grant),
        "envelope_hash": canonical_hash(envelope),
        "grant_json": _json_blob(grant),
        "effective_status": _effective_permission_status(grant, checked_at),
        "observed_at": observed_at or checked_at,
    }
    row["row_hash"] = _row_hash("authority_heads", row)
    return row


def _apply_authority_head(
    conn: sqlite3.Connection,
    key: str,
    material: dict[str, str],
    envelope: dict[str, Any],
    grant: dict[str, Any],
    checked_at: str,
) -> tuple[str | None, dict[str, Any] | None]:
    current_sqlite = conn.execute("SELECT * FROM authority_heads WHERE authority_key=?", (key,)).fetchone()
    revision = int(envelope["authority_revision"])
    grant_hash = canonical_hash(grant)
    envelope_hash = canonical_hash(envelope)
    if current_sqlite is None:
        if revision != 1:
            return "AUTHORITY_REVISION_GAP", None
        if envelope.get("previous_grant_hash") is not None:
            return "AUTHORITY_PREDECESSOR_MISMATCH", None
        row = _authority_row(key, material, envelope, grant, checked_at)
        conn.execute(
            "INSERT INTO authority_heads VALUES(:authority_key,:governing_entity_id,:grant_id,:agent_id,"
            ":task_contract_id,:authority_revision,:previous_grant_hash,:grant_hash,:envelope_hash,"
            ":grant_json,:effective_status,:observed_at,:row_hash)", row,
        )
        return None, row
    current = dict(current_sqlite)
    checked_time = _parse_time(checked_at, "checked_at")
    observed_time = _parse_time(current["observed_at"], "observed_at")
    clock_rollback = checked_time < observed_time
    current_revision = int(current["authority_revision"])
    if revision < current_revision:
        return "AUTHORITY_ROLLBACK", current
    if revision == current_revision:
        if grant_hash != current["grant_hash"] or envelope_hash != current["envelope_hash"]:
            return "AUTHORITY_EQUIVOCATION", current
        if clock_rollback:
            return "CLOCK_ROLLBACK", current
        current["observed_at"] = checked_at
        current["effective_status"] = _effective_permission_status(grant, checked_at)
        current["row_hash"] = _row_hash("authority_heads", current)
        conn.execute(
            "UPDATE authority_heads SET effective_status=:effective_status,observed_at=:observed_at,"
            "row_hash=:row_hash WHERE authority_key=:authority_key", current,
        )
        return None, current
    if revision != current_revision + 1:
        return "AUTHORITY_REVISION_GAP", current
    if envelope.get("previous_grant_hash") != current["grant_hash"]:
        return "AUTHORITY_PREDECESSOR_MISMATCH", current
    # Revision/hash/predecessor monotonicity is independent of the host wall
    # clock.  A structurally valid successor (especially a revocation) must
    # become the durable head even when the current attempt is denied for a
    # backward clock step.  Keep the real checked_at for expiry evaluation and
    # retain a nondecreasing head observation time for later comparisons.
    row = _authority_row(
        key,
        material,
        envelope,
        grant,
        checked_at,
        observed_at=current["observed_at"] if clock_rollback else checked_at,
    )
    conn.execute(
        "UPDATE authority_heads SET governing_entity_id=:governing_entity_id,grant_id=:grant_id,"
        "agent_id=:agent_id,task_contract_id=:task_contract_id,authority_revision=:authority_revision,"
        "previous_grant_hash=:previous_grant_hash,grant_hash=:grant_hash,envelope_hash=:envelope_hash,"
        "grant_json=:grant_json,effective_status=:effective_status,observed_at=:observed_at,row_hash=:row_hash "
        "WHERE authority_key=:authority_key", row,
    )
    return ("CLOCK_ROLLBACK" if clock_rollback else None), row


def _writer_authority_identity(
    envelope: dict[str, Any],
) -> tuple[dict[str, Any], str, dict[str, str]]:
    """Validate the authority-only publication surface and derive its lineage key."""
    reasons: list[str] = []
    if set(envelope) != ENVELOPE_FIELDS or envelope.get("profile") != PROFILE:
        reasons.append("AUTHORITY_ENVELOPE_MEMBER_OR_PROFILE")
    revision = envelope.get("authority_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        reasons.append("AUTHORITY_REVISION_INVALID")
    previous = envelope.get("previous_grant_hash")
    if previous is not None and (
        not isinstance(previous, str)
        or len(previous) != 64
        or any(character not in "0123456789abcdef" for character in previous)
    ):
        reasons.append("AUTHORITY_PREDECESSOR_HASH_INVALID")
    grant = envelope.get("grant_payload")
    if not isinstance(grant, dict):
        grant = {}
        reasons.append("GRANT_PAYLOAD_NOT_OBJECT")
    if set(grant) != GRANT_FIELDS:
        reasons.append("GRANT_MEMBER_SET")
    if (
        grant.get("schema_version") != "cli-agent-permission-grant-0.1"
        or grant.get("source_profile")
        != "CLI_Agent_Permission_and_Capability_Model_v0_1.md"
    ):
        reasons.append("GRANT_PROFILE_INVALID")
    required = (
        "grant_id",
        "task_id",
        "agent_id",
        "governing_entity_id",
        "human_anchor_ref",
        "task_contract_ref",
        "created_at",
        "updated_at",
        "expires_at",
        "grant_status",
    )
    if any(not isinstance(grant.get(field), str) or not grant.get(field) for field in required):
        reasons.append("GRANT_REQUIRED_FIELD")
    reasons.extend(_false_flags(grant, PROHIBITION_FIELDS, "grant"))
    if grant.get("permissions") != [PERMISSION]:
        reasons.append("MISSING_OR_EXTRA_PERMISSION")
    if grant.get("capability_bindings") != {PERMISSION: [CAPABILITY]}:
        reasons.append("MISSING_OR_EXTRA_CAPABILITY")
    if not _section_ok(
        grant.get("scope"), expected_status="CURRENT", expected_decision="ALLOW"
    ):
        reasons.append("GRANT_SCOPE_INVALID")
    revocation = grant.get("revocation")
    if not _section_ok(revocation):
        reasons.append("GRANT_REVOCATION_SECTION_INVALID")
    status = grant.get("grant_status")
    if status not in {"ACTIVE", "REVOKED", "EXPIRED", "UNKNOWN"}:
        reasons.append("GRANT_STATUS_INVALID")
    if isinstance(revocation, dict):
        if status == "REVOKED" and (
            revocation.get("status") != "REVOKED"
            or revocation.get("decision") != "DENY"
        ):
            reasons.append("REVOCATION_STATE_MISMATCH")
        if status != "REVOKED" and (
            revocation.get("status") != "NOT_REVOKED"
            or revocation.get("decision") != "ALLOW"
        ):
            reasons.append("REVOCATION_STATE_MISMATCH")
    if grant.get("human_anchor_ref") == grant.get("agent_id"):
        reasons.append("SELF_APPROVAL")
    if any(
        not isinstance(grant.get(field), str)
        or not grant.get(field)
        or len(grant[field]) > 256
        for field in ("human_anchor_ref", "agent_id")
    ):
        reasons.append("RUNTIME_IDENTITY_REFERENCE_INVALID")
    governing = grant.get("governing_entity_id")
    if not isinstance(governing, str) or not 3 <= len(governing) <= 256:
        reasons.append("RUNTIME_GOVERNING_ENTITY_INVALID")
    try:
        if _parse_time(grant.get("created_at"), "grant.created_at") >= _parse_time(
            grant.get("expires_at"), "grant.expires_at"
        ):
            reasons.append("GRANT_TIME_ORDER")
        _parse_time(grant.get("updated_at"), "grant.updated_at")
    except BindingError:
        reasons.append("GRANT_TIMESTAMP_INVALID")
    if reasons:
        raise BindingError(
            "AUTHORITY_ENVELOPE_INVALID",
            "cooperative authority publication rejected: "
            + ",".join(sorted(set(reasons))),
            state="DENIED",
        )
    material = {
        "governing_entity_id": str(grant["governing_entity_id"]),
        "grant_id": str(grant["grant_id"]),
        "agent_id": str(grant["agent_id"]),
        "task_contract_id": str(grant["task_contract_ref"]),
    }
    return grant, canonical_hash(material), material


def _publication_lineage_reason(
    candidate: dict[str, Any],
    candidate_grant: dict[str, Any],
    *,
    current_revision: int,
    current_grant_hash: str,
    current_envelope_hash: str,
) -> str | None:
    revision = int(candidate["authority_revision"])
    grant_hash = canonical_hash(candidate_grant)
    envelope_hash = canonical_hash(candidate)
    if revision < current_revision:
        return "AUTHORITY_ROLLBACK"
    if revision == current_revision:
        if grant_hash != current_grant_hash or envelope_hash != current_envelope_hash:
            return "AUTHORITY_EQUIVOCATION"
        return None
    if revision != current_revision + 1:
        return "AUTHORITY_REVISION_GAP"
    if candidate.get("previous_grant_hash") != current_grant_hash:
        return "AUTHORITY_PREDECESSOR_MISMATCH"
    return None


def _safe_reason(reasons: list[str], default: str = "AUTHORIZED") -> str:
    return reasons[0] if reasons else default


def _preconditions(
    open_effect: bool,
    reason: str,
    validation_reasons: list[str] | None = None,
) -> list[dict[str, str]]:
    names = (
        "SOURCE_GROUNDING", "IDENTITY_CONTINUITY", "CURRENT_AUTHORITY", "PERIMETER",
        "TIME_WINDOW", "L4_BUDGET", "MEMORY_RELIANCE", "WITNESS_READINESS", "BLOCKING_STATE",
    )
    fail_names = {"BLOCKING_STATE"}

    def classify(item: str) -> str:
        if "SOURCE" in item or "TASK" in item or "CONTRACT" in item:
            return "SOURCE_GROUNDING"
        if "TARGET" in item or "PATH" in item:
            return "PERIMETER"
        if "EXPIRED" in item or "CLOCK" in item:
            return "TIME_WINDOW"
        if any(token in item for token in ("AUTHORITY", "GRANT", "PERMISSION", "APPROVAL")):
            return "CURRENT_AUTHORITY"
        return "BLOCKING_STATE"

    if not open_effect:
        fail_names.update(classify(str(item)) for item in (validation_reasons or []))
        fail_names.add(classify(reason))
    results = []
    for name in names:
        status = "PASS" if open_effect or name not in fail_names else "FAIL"
        evidence = f"r6a:{name.casefold()}:{reason.casefold()}"
        if name == "MEMORY_RELIANCE":
            status = "PASS"
            evidence = "memory-influence:none"
        results.append({"name": name, "status": status, "evidence_ref": evidence})
    return results


def _artifact(artifact_id: str, version: str, digest: str) -> dict[str, str]:
    return {"artifact_id": artifact_id[:256], "version": version[:128], "hash": digest}


def _record_context(inputs: dict[str, Any], state: str, reason: str, checked_at: str) -> dict[str, Any]:
    return {
        "profile": "R6A_RUNTIME_RECORD_INPUTS_v0.1",
        "state": state,
        "reason": reason,
        "source_passport_hash": CGAM_SOURCE_PASSPORT_HASH,
        "task_hash": inputs["task_hash"],
        "authority_envelope_hash": inputs["envelope_hash"],
        "grant_payload_hash": inputs["grant_hash"],
        "authority_revision": inputs["authority_revision"],
        "previous_grant_hash": inputs.get("previous_grant_hash"),
        "journal_instance_id": inputs["journal_instance_id"],
        "attempt_id": inputs["attempt_id"],
        "payload_hash": inputs["payload_hash"],
        "target_basename": inputs["target_basename"],
        "permission_checked_at": checked_at,
        "expiry_evaluation": inputs["expiry_evaluation"],
        "threat_profile_sha256": THREAT_PROFILE_SHA256,
        "cooperative_lock_only": True,
        "validation_reasons": inputs.get("validation_reasons", []),
    }


def _build_runtime_records(
    inputs: dict[str, Any],
    *,
    state: str,
    reason: str,
    bound: bool,
    denied: bool,
    before_state_hash: str,
    after_state_hash: str,
    checked_at: str | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    checked = checked_at or _utc_now()
    raw_grant = inputs["envelope"].get("grant_payload")
    grant = raw_grant if isinstance(raw_grant, dict) else {}
    task = inputs["task"]
    validation_reasons = [str(item) for item in inputs.get("validation_reasons", [])]
    invalid_suffix = inputs["grant_hash"][:16]
    human_anchor = grant.get("human_anchor_ref")
    agent_ref = grant.get("agent_id")
    if not isinstance(human_anchor, str) or not human_anchor or len(human_anchor) > 256:
        human_anchor = f"r6a:invalid-human-{invalid_suffix}"
    if not isinstance(agent_ref, str) or not agent_ref or len(agent_ref) > 256:
        agent_ref = f"r6a:invalid-agent-{invalid_suffix}"
    if human_anchor == agent_ref:
        human_anchor = f"r6a:invalid-self-approval-human-{invalid_suffix}"
    governing_entity = grant.get("governing_entity_id") or task.get("governing_entity_id")
    if (
        not isinstance(governing_entity, str)
        or len(governing_entity) < 3
        or len(governing_entity) > 256
    ):
        governing_entity = f"r6a:invalid-governing-entity-{invalid_suffix}"
    grant_id = grant.get("grant_id")
    if not isinstance(grant_id, str) or not grant_id:
        grant_id = f"r6a:invalid-grant-{invalid_suffix}"
    task_contract_id = task.get("contract_id")
    if not isinstance(task_contract_id, str) or not task_contract_id:
        task_contract_id = f"r6a:invalid-task-{inputs['task_hash'][:16]}"
    try:
        permission_valid_until = _canonical_time(grant.get("expires_at"), "grant.expires_at")
    except BindingError:
        permission_valid_until = checked
    attempt = inputs["attempt_id"]
    short = attempt.replace("-", "")
    decision_id = f"r6a-decision-{short}"
    commit_id = f"r6a-commit-{short}"
    witness_id = f"r6a-non-effect-{short}"
    effect_id = (
        f"{EFFECT_TYPE}:"
        + canonical_hash({"target_basename": inputs["target_basename"]})[:32]
    )
    context = _record_context(inputs, state, reason, checked)
    context_hash = canonical_hash(context)
    captured = checked
    grounding = {"ref_id": f"r6a-source-grounding-{short}", "captured_at": captured, "hash": CGAM_SOURCE_PASSPORT_HASH}
    continuity_hash = canonical_hash({"authority_key": inputs["authority_key"], "head": inputs.get("authority_head")})
    continuity = {"ref_id": f"r6a-authority-continuity-{short}", "captured_at": captured, "hash": continuity_hash}
    l4 = {"ref_id": f"r6a-threat-boundary-{short}", "captured_at": captured, "hash": THREAT_PROFILE_SHA256}
    grant_ref = _artifact(f"CGAM_GRANT:{grant_id}", "0.1", inputs["grant_hash"])
    evidence = [
        _artifact("R6A:CGAM_SOURCE_PASSPORT", CGAM_COMMIT, CGAM_SOURCE_PASSPORT_HASH),
        _artifact(f"R6A:TASK:{task_contract_id}", "0.1", inputs["task_hash"]),
        _artifact("R6A:AUTHORITY_ENVELOPE", f"revision-{inputs['authority_revision']}", inputs["envelope_hash"]),
        _artifact("R6A:GRANT_PAYLOAD", "canonical-jcs", inputs["grant_hash"]),
        _artifact(f"R6A:JOURNAL:{inputs['journal_instance_id']}", "schema-1", canonical_hash({"journal_instance_id": inputs["journal_instance_id"]})),
        _artifact(f"R6A:ATTEMPT:{attempt}", "0.1", canonical_hash({"attempt_id": attempt})),
        _artifact("R6A:PAYLOAD", "sha256", inputs["payload_hash"]),
        _artifact(f"R6A:TARGET:{inputs['target_basename']}", "basename", canonical_hash({"target_basename": inputs["target_basename"]})),
        _artifact("R6A:EXPIRY_EVALUATION", inputs["expiry_evaluation"], canonical_hash({"checked_at": checked, "evaluation": inputs["expiry_evaluation"]})),
        _artifact("R6A:THREAT_PROFILE", "0.1", THREAT_PROFILE_SHA256),
        _artifact("R6A:CURRENT_CONDITIONS", "0.1", context_hash),
    ]
    basis = {
        "captured_at": captured,
        "human_anchor_ref": human_anchor,
        "policy_refs": [
            _artifact("R6A:AUTHORITATIVE_CONTRACT", "0.1", CONTRACT_SHA256),
            _artifact("R6A:THREAT_PROFILE", "0.1", THREAT_PROFILE_SHA256),
        ],
        "authority_refs": [grant_ref, _artifact("R6A:AUTHORITY_ENVELOPE", f"revision-{inputs['authority_revision']}", inputs["envelope_hash"])],
        "permission_grant_ref": grant_ref,
        "grounding_ref": grounding,
        "continuity_ref": continuity,
        "l4_ref": l4,
        "memory_reliance_refs": [],
        "evidence_refs": evidence,
        "witness_chain_head": canonical_hash({"attempt_id": attempt, "context_hash": context_hash, "pre_state": before_state_hash}),
    }
    decision = {
        "schema_version": "c-decision-basis-record-0.1.1",
        "record_type": "decision_basis_record",
        "record_id": decision_id,
        "created_at": captured,
        "basis": basis,
        "basis_hash": canonical_hash(basis),
        "rule_basis_visibility": "FULL",
        "claim_boundary": "This record binds only the declared R6A local cooperative-lock decision basis; it does not establish broader authority or CGAM conformance.",
    }
    decision_ref = _artifact(decision_id, "0.1.1", canonical_hash(decision))
    witness: dict[str, Any] | None = None
    witness_ref: dict[str, str] | None = None
    if not bound:
        start = _canonical_time(inputs.get("observation_start", checked), "observation_start")
        end = _canonical_time(
            inputs.get(
                "observation_end",
                (_parse_time(start, "observation_start") + timedelta(microseconds=1))
                .isoformat()
                .replace("+00:00", "Z"),
            ),
            "observation_end",
        )
        start_dt = _parse_time(start, "observation_start")
        end_dt = _parse_time(end, "observation_end")
        checked_dt = _parse_time(checked, "checked_at")
        if not start_dt <= checked_dt <= end_dt:
            raise BindingError(
                "WITNESS_INTERVAL_INVALID",
                "non-effect observation interval does not enclose the consequence check",
            )
        target_ref = f"sandbox-basename:{inputs['target_basename']}"
        inventory = {
            "target": target_ref,
            "surface": "FILESYSTEM",
            "effect": EFFECT_TYPE,
            "cooperative_participants": "binding.lock holders only",
            "window": {"start": start, "end": end},
        }
        witness = {
            "schema_version": "c-non-effect-witness-record-0.1.1",
            "record_type": "non_effect_witness_record",
            "record_id": witness_id,
            "created_at": end,
            "attempt_ref": commit_id,
            "gate_record_ref": commit_id,
            "effect_scope_ref": effect_id,
            "effect_target_ref": target_ref,
            "observation_window": {"start": start, "end": end},
            "clock_source_ref": (
                "python:datetime.now(timezone.utc)+1us-min-resolution+binding-lock;"
                "authority-head-observed-at=nondecreasing"
            ),
            "claim_scope": "DECLARED_SURFACES_AND_WINDOW_ONLY",
            "scope_inventory_ref": f"r6a:scope-inventory:{attempt}",
            "scope_inventory_hash": canonical_hash(inventory),
            "evidence_collection": {
                "collector_ref": "r6a:in-process-filesystem-observer-under-binding-lock",
                "availability": "COMPLETE",
                "continuous_event_log_ref": f"r6a:attempt-journal:{attempt}",
            },
            "protected_effects": [f"{EFFECT_TYPE} atomic target replacement"],
            "observation_surfaces": [{
                "surface_id": f"r6a-target-filesystem-{short}",
                "surface_kind": "FILESYSTEM",
                "target_ref": target_ref,
                "target_coordinate": target_ref,
                "hash_domain": "CANONICAL_STATE_SHA256_V1",
                "before_hash": before_state_hash,
                "after_hash": after_state_hash,
                "external_call_count": 0,
                "queue_state": "NOT_APPLICABLE",
                "retry_state": "NOT_APPLICABLE",
                "coverage": "COMPLETE",
            }],
            "alternate_path_checks": [
                {"path_id": "r6a-binding-lock-route", "status": "CLOSED", "evidence_ref": "binding.lock held for full observation"},
                {"path_id": "r6a-payload-temp-route", "status": "NOT_REACHABLE", "evidence_ref": "no payload temp survives terminalization"},
            ],
            "coverage_state": "COMPLETE_WITHIN_DECLARED_SURFACE",
            "conclusion": "NO_EFFECT_OBSERVED_WITHIN_DECLARED_SCOPE",
            "witness_chain_head": canonical_hash({"attempt_id": attempt, "before": before_state_hash, "after": after_state_hash, "reason": reason}),
            "claim_boundary": WITNESS_CLAIM_BOUNDARY,
        }
        witness_ref = _artifact(witness_id, "0.1.1", canonical_hash(witness))
    permission_status = _effective_permission_status(grant, checked)
    all_reasons = {reason, *validation_reasons}
    if all_reasons & {"STALE_CONTRACT", "TASK_GATE_NOT_CURRENT"}:
        task_status = "STALE"
    elif any(
        item.startswith("TASK_")
        or "SOURCE_PASSPORT" in item
        or "CONTRACT" in item
        for item in all_reasons
    ):
        task_status = "UNKNOWN"
    else:
        task_status = "CURRENT"
    target_ref = f"sandbox-basename:{inputs['target_basename']}"
    commit = {
        "schema_version": "c-consequence-commit-record-0.1.1",
        "record_type": "consequence_commit_record",
        "record_id": commit_id,
        "created_at": checked,
        "consequence_lineage_id": f"r6a-lineage-{short}",
        "governing_entity_id": governing_entity,
        "human_anchor_ref": human_anchor,
        "agent_ref": agent_ref,
        "task_contract_ref": _artifact(f"CGAM_TASK:{task_contract_id}", "0.1", inputs["task_hash"]),
        "permission_grant_ref": grant_ref,
        "permission_status": permission_status,
        "permission_checked_at": checked,
        "permission_valid_until": permission_valid_until,
        "permission_issuer_ref": human_anchor,
        "permission_subject_ref": agent_ref,
        "authorized_target_ref": target_ref,
        "task_contract_status": task_status,
        "task_contract_checked_at": checked,
        "task_endpoint_ref": target_ref,
        "continuity_approver_ref": human_anchor,
        "memory_influence_state": "NONE",
        "memory_reliance_refs": [],
        "decision_basis_ref": decision_ref,
        "source_grounding_ref": grounding,
        "continuity_evidence_ref": continuity,
        "l4_state_ref": l4,
        "target_effect": {
            "effect_id": effect_id,
            "effect_class": "LOW",
            "target_ref": target_ref,
            "reversibility": "REVERSIBLE_WITH_COST",
        },
        "precondition_results": _preconditions(bound, reason, validation_reasons),
        "commit_outcome": "OPEN" if bound else ("DENY" if denied else "HOLD"),
        "effect_state": "BOUND" if bound else "NOT_BOUND",
        "effect_artifact_hash": inputs["payload_hash"] if bound else None,
        "non_effect_witness_ref": witness_ref,
        "previous_commit_record_ref": None,
        "change_reason_code": None,
        "change_reason": None,
        "target_transition_evidence_ref": None,
        "current_conditions_ref": _artifact(f"R6A:CURRENT_CONDITIONS:{attempt}", "0.1", context_hash),
        "current_conditions_hash": context_hash,
        "witness_chain_head": canonical_hash({"decision": decision_ref["hash"], "witness": witness_ref["hash"] if witness_ref else None, "context": context_hash}),
        "claim_boundary": (
            "This record proves only the bounded local effect and its journal-read consequence evidence within the declared cooperative binding-lock threat boundary."
            if bound else NOT_BOUND_COMMIT_CLAIM_BOUNDARY
        ),
    }
    validate_runtime_bundle(decision, commit, witness)
    records: list[tuple[str, dict[str, Any]]] = [("decision_basis", decision), ("consequence_commit", commit)]
    if witness is not None:
        records.append(("non_effect_witness", witness))
    return records


def _attempt_row(
    *,
    attempt_id: str,
    authority_key: str,
    target: str,
    payload: bytes,
    pre: dict[str, Any],
    task: dict[str, Any],
    envelope: dict[str, Any],
    checked_at: str,
    instance_id: str,
    reason: str,
    state: str,
    record_inputs: dict[str, Any],
    temp_basename: str | None,
) -> dict[str, Any]:
    grant = envelope.get("grant_payload") if isinstance(envelope.get("grant_payload"), dict) else {}
    row: dict[str, Any] = {
        "attempt_id": attempt_id,
        "authority_key": authority_key,
        "target_basename": target,
        "target_key": _basename_key(target),
        "payload": payload,
        "payload_hash": _sha256(payload),
        "pre_exists": 1 if pre["state"]["exists"] else 0,
        "pre_hash": pre["state"]["content_sha256"],
        "pre_state_hash": pre["state_hash"],
        "pre_identity_json": _json_blob(pre["identity"]) if pre["identity"] is not None else None,
        "task_json": _json_blob(task),
        "envelope_json": _json_blob(envelope),
        "task_hash": canonical_hash(task),
        "envelope_hash": canonical_hash(envelope),
        "grant_hash": canonical_hash(grant),
        "authority_revision": _journal_revision(envelope),
        "previous_grant_hash": envelope.get("previous_grant_hash"),
        "prepared_at": checked_at,
        "updated_at": checked_at,
        "state": state,
        "reason_code": reason,
        "temp_basename": temp_basename,
        "record_inputs_json": _record_inputs_blob(record_inputs),
        "post_state_hash": None,
        "terminal_record_set_hash": None,
    }
    row["row_hash"] = _row_hash("attempts", row)
    return row


def _insert_attempt(conn: sqlite3.Connection, row: dict[str, Any]) -> None:
    conn.execute(
        "INSERT INTO attempts VALUES(:attempt_id,:authority_key,:target_basename,:target_key,:payload,:payload_hash,"
        ":pre_exists,:pre_hash,:pre_state_hash,:pre_identity_json,:task_json,:envelope_json,:task_hash,"
        ":envelope_hash,:grant_hash,:authority_revision,:previous_grant_hash,:prepared_at,:updated_at,"
        ":state,:reason_code,:temp_basename,:record_inputs_json,:post_state_hash,"
        ":terminal_record_set_hash,:row_hash)", row,
    )


def _update_attempt(conn: sqlite3.Connection, attempt_id: str, **changes: Any) -> dict[str, Any]:
    found = conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
    if found is None:
        raise BindingError("ATTEMPT_MISSING", f"attempt {attempt_id} is missing")
    if "record_inputs_json" in changes:
        _audit_canonical_blob(
            changes["record_inputs_json"],
            "updated record_inputs_json",
            max_bytes=MAX_RECORD_INPUTS_BYTES,
        )
    row = dict(found)
    row.update(changes)
    row["row_hash"] = _row_hash("attempts", row)
    assignments = ",".join(f"{name}=:{name}" for name in changes) + ",row_hash=:row_hash"
    conn.execute(f"UPDATE attempts SET {assignments} WHERE attempt_id=:attempt_id", row)
    return row


def _append_records(
    conn: sqlite3.Connection,
    attempt_id: str,
    terminal_state: str,
    records: list[tuple[str, dict[str, Any]]],
    *,
    allow_existing: bool = False,
) -> str:
    existing_rows = list(
        conn.execute(
            "SELECT record_hash,attempt_ordinal FROM records WHERE attempt_id=? ORDER BY attempt_ordinal",
            (attempt_id,),
        )
    )
    if existing_rows and not allow_existing:
        raise BindingError("DUPLICATE_TERMINAL_RECORD", "attempt already has terminal records")
    count = int(_get_meta(conn, "record_count"))
    previous = _get_meta(conn, "record_chain_head")
    hashes: list[str] = [str(item["record_hash"]) for item in existing_rows]
    ordinal_base = len(existing_rows)
    for local_ordinal, (kind, record) in enumerate(records, 1):
        attempt_ordinal = ordinal_base + local_ordinal
        raw = _json_blob(record)
        digest = canonical_hash(record)
        row: dict[str, Any] = {
            "record_id": str(record.get("record_id") or f"r6a-transition-{attempt_id}"),
            "attempt_id": attempt_id,
            "attempt_ordinal": attempt_ordinal,
            "chain_ordinal": count + local_ordinal,
            "kind": kind,
            "terminal_state": terminal_state,
            "record_json": raw,
            "record_hash": digest,
            "previous_record_hash": previous,
        }
        row["row_hash"] = _row_hash("records", row)
        conn.execute(
            "INSERT INTO records VALUES(:record_id,:attempt_id,:attempt_ordinal,:chain_ordinal,:kind,"
            ":terminal_state,:record_json,:record_hash,:previous_record_hash,:row_hash)", row,
        )
        previous = digest
        hashes.append(digest)
    _set_meta(conn, "record_count", str(count + len(records)))
    _set_meta(conn, "record_chain_head", previous)
    return canonical_hash(hashes)


def _record_inputs(
    *,
    task: dict[str, Any],
    envelope: dict[str, Any],
    authority_key: str,
    authority_head: dict[str, Any] | None,
    instance_id: str,
    attempt_id: str,
    payload_hash: str,
    target: str,
    checked_at: str,
) -> dict[str, Any]:
    grant = envelope.get("grant_payload") if isinstance(envelope.get("grant_payload"), dict) else {}
    return {
        "profile": "R6A_RUNTIME_RECORD_INPUTS_v0.1",
        "task": task,
        "envelope": envelope,
        "task_hash": canonical_hash(task),
        "envelope_hash": canonical_hash(envelope),
        "grant_hash": canonical_hash(grant),
        "authority_revision": _journal_revision(envelope),
        "previous_grant_hash": envelope.get("previous_grant_hash"),
        "authority_key": authority_key,
        "authority_head": _hashable(authority_head),
        "journal_instance_id": instance_id,
        "attempt_id": attempt_id,
        "payload_hash": payload_hash,
        "target_basename": target,
        "checked_at": checked_at,
        "expiry_evaluation": _effective_permission_status(grant, checked_at),
        "threat_profile_sha256": THREAT_PROFILE_SHA256,
        "source_passport_hash": CGAM_SOURCE_PASSPORT_HASH,
    }


def _read_result(conn: sqlite3.Connection, attempt_id: str, instance_id: str) -> dict[str, Any]:
    attempt_sqlite = conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
    if attempt_sqlite is None:
        raise BindingError("ATTEMPT_MISSING", "attempt is missing at durable readback")
    attempt = dict(attempt_sqlite)
    rows = list(conn.execute("SELECT * FROM records WHERE attempt_id=? ORDER BY attempt_ordinal", (attempt_id,)))
    decoded: dict[str, Any] = {}
    hashes: list[str] = []
    for sqlite_row in rows:
        row = dict(sqlite_row)
        record = _audit_canonical_blob(row["record_json"], "durable record readback")
        if canonical_hash(record) != row["record_hash"]:
            raise BindingError("DURABLE_READBACK_HASH", "durable record readback hash mismatch")
        decoded[row["kind"]] = record
        hashes.append(row["record_hash"])
    if attempt["state"] != "PREPARED" and attempt["terminal_record_set_hash"] != canonical_hash(hashes):
        raise BindingError("TERMINAL_RECORD_SET_HASH", "terminal record set hash mismatch")
    superseded: dict[str, Any] = {}
    if attempt["state"] == "QUARANTINED_UNRESOLVED":
        superseded = {
            key: value for key, value in decoded.items() if key != "binding_transition"
        }
        decoded = {
            key: value for key, value in decoded.items() if key == "binding_transition"
        }
    if "decision_basis" in decoded:
        validate_runtime_bundle(
            decoded["decision_basis"],
            decoded["consequence_commit"],
            decoded.get("non_effect_witness"),
        )
    result = {
        "attempt_id": attempt_id,
        "state": attempt["state"],
        "reason_code": attempt["reason_code"],
        "journal_instance_id": instance_id,
        "durable_readback": True,
        "record_set_hash": attempt["terminal_record_set_hash"],
        "post_state_hash": attempt["post_state_hash"],
        "records": decoded,
    }
    if superseded:
        result["superseded_records"] = superseded
    return result


def _terminalize(
    conn: sqlite3.Connection,
    instance_id: str,
    row: dict[str, Any],
    *,
    state: str,
    reason: str,
    bound: bool,
    denied: bool,
    post: dict[str, Any],
    checked_at: str | None = None,
    transaction_open: bool = False,
) -> dict[str, Any]:
    inputs = _strict_record_inputs_bytes(
        row["record_inputs_json"], "record_inputs_json"
    )
    records = _build_runtime_records(
        inputs,
        state=state,
        reason=reason,
        bound=bound,
        denied=denied,
        before_state_hash=row["pre_state_hash"],
        after_state_hash=post["state_hash"],
        checked_at=checked_at,
    )
    if transaction_open != conn.in_transaction:
        if transaction_open:
            raise BindingError("SQLITE_TRANSACTION_MISSING", "expected an open terminal transaction")
        conn.execute("BEGIN IMMEDIATE")
    try:
        record_set_hash = _append_records(conn, row["attempt_id"], state, records)
        _update_attempt(
            conn,
            row["attempt_id"],
            state=state,
            reason_code=reason,
            updated_at=checked_at or _utc_now(),
            post_state_hash=post["state_hash"],
            terminal_record_set_hash=record_set_hash,
            temp_basename=None,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return _read_result(conn, row["attempt_id"], instance_id)


def _quarantine_attempt(
    conn: sqlite3.Connection,
    instance_id: str,
    row: dict[str, Any],
    reason: str,
    post_state_hash: str | None,
    *,
    clear_temp: bool = True,
) -> dict[str, Any]:
    event = {
        "schema_version": "r6a-binding-transition-0.1",
        "record_type": "binding_quarantine_record",
        "record_id": f"r6a-quarantine-{row['attempt_id'].replace('-', '')}",
        "created_at": _utc_now(),
        "attempt_id": row["attempt_id"],
        "state": "QUARANTINED_UNRESOLVED",
        "reason_code": reason,
        "claim_boundary": "No Runtime Consequence Integrity effect or non-effect claim is made for this unresolved target state.",
    }
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    try:
        record_set_hash = _append_records(
            conn,
            row["attempt_id"],
            "QUARANTINED_UNRESOLVED",
            [("binding_transition", event)],
            allow_existing=True,
        )
        _update_attempt(
            conn,
            row["attempt_id"],
            state="QUARANTINED_UNRESOLVED",
            reason_code=reason,
            updated_at=_utc_now(),
            post_state_hash=post_state_hash,
            terminal_record_set_hash=record_set_hash,
            temp_basename=None if clear_temp else row.get("temp_basename"),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return _read_result(conn, row["attempt_id"], instance_id)


def _remove_temp(root: Path, basename: str | None) -> None:
    if basename is None:
        return
    if not basename.startswith(PAYLOAD_TEMP_PREFIX):
        raise BindingError("TEMP_NAME_INVALID", "stored payload temp basename is invalid")
    path = root / basename
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or _is_reparse(path) or not stat.S_ISREG(info.st_mode):
        raise BindingError("TEMP_UNSAFE_TYPE", "payload temp is not a regular non-reparse file")
    os.unlink(path)
    _fsync_directory(root)


def _identity_matches(stored_blob: Any, current: dict[str, Any]) -> bool:
    if stored_blob is None:
        return current["identity"] is None
    stored = _strict_json_bytes(stored_blob, "pre_identity_json")
    return stored == current["identity"]


def _recover_all(conn: sqlite3.Connection, root: Path, instance_id: str) -> list[dict[str, Any]]:
    pending = [dict(row) for row in conn.execute("SELECT * FROM attempts WHERE state='PREPARED' ORDER BY prepared_at,attempt_id")]
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in pending:
        grouped.setdefault((row["authority_key"], row["target_key"]), []).append(row)
    results: list[dict[str, Any]] = []

    def quarantine_with_cleanup(
        row: dict[str, Any], reason: str, post_state_hash: str | None
    ) -> dict[str, Any]:
        try:
            _remove_temp(root, row.get("temp_basename"))
        except BindingError:
            return _quarantine_attempt(
                conn,
                instance_id,
                row,
                "RECOVERY_TEMP_UNSAFE",
                post_state_hash,
                clear_temp=False,
            )
        return _quarantine_attempt(conn, instance_id, row, reason, post_state_hash)

    for rows in grouped.values():
        if len(rows) > 1:
            for row in rows:
                results.append(
                    quarantine_with_cleanup(row, "NONTERMINAL_MULTIPLICITY", None)
                )
            continue
        row = rows[0]
        target = root / row["target_basename"]
        recovery_start = _canonical_time(_utc_now(), "recovery_observation_start")
        try:
            current = _target_state(target)
        except BindingError:
            results.append(quarantine_with_cleanup(row, "RECOVERY_TARGET_UNSAFE", None))
            continue
        if row["pre_exists"] and row["pre_hash"] == row["payload_hash"]:
            results.append(
                quarantine_with_cleanup(
                    row, "INVALID_PREPARED_ALREADY_SATISFIED", current["state_hash"]
                )
            )
            continue
        if current["state"]["exists"] and current["state"]["content_sha256"] == row["payload_hash"]:
            try:
                _remove_temp(root, row["temp_basename"])
            except BindingError:
                results.append(
                    _quarantine_attempt(
                        conn,
                        instance_id,
                        row,
                        "RECOVERY_TEMP_UNSAFE",
                        current["state_hash"],
                        clear_temp=False,
                    )
                )
                continue
            persisted_inputs = _strict_record_inputs_bytes(
                row["record_inputs_json"], "recovery record_inputs_json"
            )
            results.append(
                _terminalize(
                    conn,
                    instance_id,
                    row,
                    state="RECOVERED_BOUND",
                    reason="CRASH_AFTER_EFFECT",
                    bound=True,
                    denied=False,
                    post=current,
                    checked_at=str(persisted_inputs["checked_at"]),
                )
            )
            continue
        equals_pre = (
            bool(row["pre_exists"]) == bool(current["state"]["exists"])
            and row["pre_hash"] == current["state"]["content_sha256"]
            and _identity_matches(row["pre_identity_json"], current)
        )
        if equals_pre:
            try:
                _remove_temp(root, row["temp_basename"])
            except BindingError:
                results.append(
                    _quarantine_attempt(
                        conn,
                        instance_id,
                        row,
                        "RECOVERY_TEMP_UNSAFE",
                        current["state_hash"],
                        clear_temp=False,
                    )
                )
                continue
            persisted_inputs = _strict_record_inputs_bytes(
                row["record_inputs_json"], "recovery record_inputs_json"
            )
            recovery_inputs = dict(persisted_inputs)
            recovery_inputs["planning_record_inputs"] = persisted_inputs
            recovery_inputs["checked_at"] = recovery_start
            recovery_grant = recovery_inputs["envelope"].get("grant_payload")
            if not isinstance(recovery_grant, dict):
                recovery_grant = {}
            recovery_inputs["expiry_evaluation"] = _effective_permission_status(
                recovery_grant, recovery_start
            )
            recovery_inputs["observation_start"] = recovery_start
            recovery_inputs["observation_end"] = _observation_end_after(
                recovery_start, "recovery_observation_end"
            )
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            try:
                recovery_row = _update_attempt(
                    conn,
                    row["attempt_id"],
                    record_inputs_json=_json_blob(recovery_inputs),
                    updated_at=recovery_inputs["observation_end"],
                )
            except Exception:
                conn.rollback()
                raise
            results.append(
                _terminalize(
                    conn,
                    instance_id,
                    recovery_row,
                    state="RECOVERED_NOT_BOUND",
                    reason="CRASH_BEFORE_EFFECT",
                    bound=False,
                    denied=False,
                    post=current,
                    checked_at=recovery_start,
                    transaction_open=True,
                )
            )
            continue
        results.append(
            quarantine_with_cleanup(row, "UNEXPECTED_TARGET_STATE", current["state_hash"])
        )
    return results


def recover_pending(
    sandbox: os.PathLike[str] | str,
    *,
    expected_instance_id: str | None = None,
) -> list[dict[str, Any]]:
    root = _validate_sandbox(sandbox)
    with _journal(root, create=False, expected_instance_id=expected_instance_id) as (conn, instance, _, _):
        results = _recover_all(conn, root, instance)
        _audit_database(conn)
        return results


def _hit_failpoint(name: str) -> None:
    if os.environ.get("R6A_FAILPOINT") == name:
        codes = {
            "R6A-CRASH-001": 91,
            "R6A-CRASH-002": 92,
            "R6A-CRASH-003": 93,
            "R6A-CRASH-004": 94,
        }
        os._exit(codes[name])


def _write_payload_temp(root: Path, basename: str, payload: bytes) -> None:
    path = root / basename
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise BindingError("TEMP_WRITE_FAILED", "payload temp write made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _replace_target(root: Path, temp: str, target: str) -> dict[str, Any]:
    os.replace(root / temp, root / target)
    # Windows' CRT rejects fsync on a read-only descriptor; O_RDWR is safe
    # here because the adapter just created/replaced this exact regular file.
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    fd = os.open(root / target, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return _fsync_directory(root)


def _persist_denial(
    conn: sqlite3.Connection,
    instance_id: str,
    root: Path,
    *,
    attempt_id: str,
    key: str,
    target: str,
    payload: bytes,
    pre: dict[str, Any],
    task: dict[str, Any],
    envelope: dict[str, Any],
    head: dict[str, Any] | None,
    checked_at: str,
    reason: str,
    validation_reasons: list[str],
) -> dict[str, Any]:
    inputs = _record_inputs(
        task=task,
        envelope=envelope,
        authority_key=key,
        authority_head=head,
        instance_id=instance_id,
        attempt_id=attempt_id,
        payload_hash=_sha256(payload),
        target=target,
        checked_at=checked_at,
    )
    inputs["validation_reasons"] = list(validation_reasons)
    inputs["observation_start"] = checked_at
    try:
        post = _target_state(root / target)
        target_observation_error = False
    except BindingError:
        post = None
        target_observation_error = True
    inputs["observation_end"] = _observation_end_after(
        checked_at, "observation_end"
    )
    changed = (
        target_observation_error
        or post is None
        or post["state_hash"] != pre["state_hash"]
        or post["identity"] != pre["identity"]
    )
    terminal_state = "QUARANTINED_UNRESOLVED" if changed else "DENIED"
    terminal_reason = (
        "TARGET_UNSAFE_DURING_DENIAL"
        if target_observation_error
        else ("TARGET_CHANGED_DURING_DENIAL" if changed else reason)
    )
    row = _attempt_row(
        attempt_id=attempt_id,
        authority_key=key,
        target=target,
        payload=payload,
        pre=pre,
        task=task,
        envelope=envelope,
        checked_at=checked_at,
        instance_id=instance_id,
        reason=terminal_reason,
        state=terminal_state,
        record_inputs=inputs,
        temp_basename=None,
    )
    if changed:
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        try:
            _insert_attempt(conn, row)
            _set_meta(conn, "last_checked_at", max(_get_meta(conn, "last_checked_at"), checked_at))
            return _quarantine_attempt(
                conn,
                instance_id,
                row,
                terminal_reason,
                post["state_hash"] if post is not None else None,
            )
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
    records = _build_runtime_records(
        inputs,
        state="DENIED",
        reason=reason,
        bound=False,
        denied=True,
        before_state_hash=pre["state_hash"],
        after_state_hash=post["state_hash"],
        checked_at=checked_at,
    )
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    try:
        _insert_attempt(conn, row)
        record_set_hash = _append_records(conn, attempt_id, "DENIED", records)
        _update_attempt(conn, attempt_id, post_state_hash=post["state_hash"], terminal_record_set_hash=record_set_hash)
        _set_meta(conn, "last_checked_at", max(_get_meta(conn, "last_checked_at"), checked_at))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return _read_result(conn, attempt_id, instance_id)


def bind_text(
    sandbox: os.PathLike[str] | str,
    *,
    task_basename: str,
    authority_basename: str,
    target_basename: str,
    payload: bytes,
    attempt_id: str | None = None,
    expected_instance_id: str | None = None,
    lock_timeout: float = 30.0,
    before_final_revalidation: Callable[[Path], None] | None = None,
) -> dict[str, Any]:
    root = _validate_sandbox(sandbox)
    target = validate_basename(target_basename)
    task_name = validate_basename(task_basename)
    authority_name = validate_basename(authority_basename)
    if len({target.casefold(), task_name.casefold(), authority_name.casefold()}) != 3:
        raise BindingError("INPUT_TARGET_COLLISION", "task, authority, and target basenames must differ")
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_PAYLOAD_BYTES or b"\x00" in payload:
        raise BindingError("PAYLOAD_INVALID", f"payload must be 1..{MAX_PAYLOAD_BYTES} non-NUL bytes")
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BindingError("PAYLOAD_NOT_UTF8", "WRITE_SANDBOX_TEXT_V1 payload must be UTF-8") from exc
    attempt_value = attempt_id or str(uuid.uuid4())
    try:
        attempt = str(uuid.UUID(attempt_value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise BindingError("ATTEMPT_ID_INVALID", "attempt_id must be a UUID") from exc
    with _journal(root, create=True, expected_instance_id=expected_instance_id, lock_timeout=lock_timeout) as (conn, instance, _, _):
        _recover_all(conn, root, instance)
        existing = conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt,)).fetchone()
        if existing is not None:
            if existing["state"] == "PREPARED":
                raise BindingError("ATTEMPT_STILL_PREPARED", "attempt remains nonterminal after recovery")
            task, _ = _read_input_file(root, task_name, "CGAM task contract")
            envelope, _ = _read_input_file(root, authority_name, "CGAM authority envelope")
            stored = dict(existing)
            mismatch = (
                stored["target_basename"] != target
                or stored["target_key"] != _basename_key(target)
                or stored["payload"] != payload
                or stored["payload_hash"] != _sha256(payload)
                or stored["task_hash"] != canonical_hash(task)
                or stored["task_json"] != _json_blob(task)
                or stored["envelope_hash"] != canonical_hash(envelope)
                or stored["envelope_json"] != _json_blob(envelope)
            )
            if mismatch:
                raise BindingError(
                    "ATTEMPT_REPLAY_MISMATCH",
                    "attempt_id is already bound to a different immutable request",
                )
            return _read_result(conn, attempt, instance)
        quarantined = conn.execute(
            "SELECT attempt_id FROM attempts WHERE target_key=? AND state='QUARANTINED_UNRESOLVED'",
            (_basename_key(target),),
        ).fetchone()
        if quarantined is not None:
            raise BindingError("TARGET_BOUNDARY_QUARANTINED", f"target boundary is quarantined by attempt {quarantined[0]}")
        # The authority clock is sampled only after the process owns the
        # cross-process lock and recovery/replay checks have completed.  Lock
        # wait time therefore cannot backdate a stale grant into validity.
        checked = _canonical_time(_utc_now(), "checked_at")
        task, _ = _read_input_file(root, task_name, "CGAM task contract")
        envelope, _ = _read_input_file(root, authority_name, "CGAM authority envelope")
        structural, authorization, key, material, grant = _validate_local_subset(task, envelope, target, checked)
        head: dict[str, Any] | None = None
        lineage_reason: str | None = None
        if not structural:
            conn.execute("BEGIN IMMEDIATE")
            try:
                lineage_reason, head = _apply_authority_head(conn, key, material, envelope, grant, checked)
            except Exception:
                conn.rollback()
                raise
        reasons = structural + ([lineage_reason] if lineage_reason else []) + authorization
        pre = _target_state(root / target)
        payload_hash = _sha256(payload)
        inputs = _record_inputs(
            task=task,
            envelope=envelope,
            authority_key=key,
            authority_head=head,
            instance_id=instance,
            attempt_id=attempt,
            payload_hash=payload_hash,
            target=target,
            checked_at=checked,
        )
        inputs["validation_reasons"] = reasons
        # The ambiguity guard is unconditional: pre-existing equality is not
        # this attempt's effect even when the supplied task or grant is
        # malformed, stale, revoked, rolled back, equivocal, or gapped.
        if pre["state"]["exists"] and pre["state"]["content_sha256"] == payload_hash:
            inputs["observation_start"] = checked
            try:
                post = _target_state(root / target)
                observation_error = False
            except BindingError:
                post = None
                observation_error = True
            inputs["observation_end"] = _observation_end_after(
                checked, "observation_end"
            )
            changed = (
                observation_error
                or post is None
                or post["state_hash"] != pre["state_hash"]
                or post["identity"] != pre["identity"]
            )
            if changed:
                quarantine_reason = (
                    "TARGET_UNSAFE_DURING_ALREADY_SATISFIED"
                    if observation_error
                    else "TARGET_CHANGED_DURING_ALREADY_SATISFIED"
                )
                row = _attempt_row(
                    attempt_id=attempt, authority_key=key, target=target, payload=payload, pre=pre,
                    task=task, envelope=envelope, checked_at=checked, instance_id=instance,
                    reason=quarantine_reason, state="QUARANTINED_UNRESOLVED",
                    record_inputs=inputs, temp_basename=None,
                )
                if not conn.in_transaction:
                    conn.execute("BEGIN IMMEDIATE")
                try:
                    _insert_attempt(conn, row)
                    _set_meta(conn, "last_checked_at", max(_get_meta(conn, "last_checked_at"), checked))
                    return _quarantine_attempt(
                        conn,
                        instance,
                        row,
                        quarantine_reason,
                        post["state_hash"] if post is not None else None,
                    )
                except Exception:
                    if conn.in_transaction:
                        conn.rollback()
                    raise
            row = _attempt_row(
                attempt_id=attempt, authority_key=key, target=target, payload=payload, pre=pre,
                task=task, envelope=envelope, checked_at=checked, instance_id=instance,
                reason="ALREADY_SATISFIED", state="RECORDED_NOT_BOUND", record_inputs=inputs,
                temp_basename=None,
            )
            records = _build_runtime_records(
                inputs, state="RECORDED_NOT_BOUND", reason="ALREADY_SATISFIED", bound=False,
                denied=False, before_state_hash=pre["state_hash"], after_state_hash=post["state_hash"],
                checked_at=checked,
            )
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            try:
                _insert_attempt(conn, row)
                record_set_hash = _append_records(conn, attempt, "RECORDED_NOT_BOUND", records)
                _update_attempt(conn, attempt, post_state_hash=post["state_hash"], terminal_record_set_hash=record_set_hash)
                _set_meta(conn, "last_checked_at", max(_get_meta(conn, "last_checked_at"), checked))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            return _read_result(conn, attempt, instance)
        if reasons:
            return _persist_denial(
                conn, instance, root, attempt_id=attempt, key=key, target=target, payload=payload,
                pre=pre, task=task, envelope=envelope, head=head, checked_at=checked,
                reason=_safe_reason(reasons), validation_reasons=reasons,
            )
        expected_post_state_hash = canonical_hash(
            {"exists": True, "content_sha256": payload_hash}
        )
        try:
            _build_runtime_records(
                inputs,
                state="RECORDED_BOUND",
                reason="AUTHORIZED_EFFECT",
                bound=True,
                denied=False,
                before_state_hash=pre["state_hash"],
                after_state_hash=expected_post_state_hash,
                checked_at=checked,
            )
        except Exception:
            preflight_reasons = ["RUNTIME_RECORD_PREFLIGHT_FAILED"]
            return _persist_denial(
                conn, instance, root, attempt_id=attempt, key=key, target=target, payload=payload,
                pre=pre, task=task, envelope=envelope, head=head, checked_at=checked,
                reason="RUNTIME_RECORD_PREFLIGHT_FAILED",
                validation_reasons=preflight_reasons,
            )
        temp = f"{PAYLOAD_TEMP_PREFIX}{attempt}"
        try:
            os.lstat(root / temp)
        except FileNotFoundError:
            pass
        else:
            # Ownership of a payload temp begins only with this attempt's
            # durable PREPARED row plus its subsequent O_EXCL creation.  A
            # pre-existing collision is never adopted or removed.
            raise BindingError(
                "PAYLOAD_TEMP_COLLISION",
                "reserved payload temp already exists before PREPARED",
            )
        row = _attempt_row(
            attempt_id=attempt, authority_key=key, target=target, payload=payload, pre=pre,
            task=task, envelope=envelope, checked_at=checked, instance_id=instance,
            reason="PREPARED", state="PREPARED", record_inputs=inputs, temp_basename=temp,
        )
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        try:
            _insert_attempt(conn, row)
            _set_meta(conn, "last_checked_at", max(_get_meta(conn, "last_checked_at"), checked))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        _hit_failpoint("R6A-CRASH-001")
        _write_payload_temp(root, temp, payload)
        _hit_failpoint("R6A-CRASH-002")
        if before_final_revalidation is not None:
            before_final_revalidation(root)
        final_checked = _canonical_time(_utc_now(), "final_checked_at")
        final_task, _ = _read_input_file(root, task_name, "final CGAM task contract")
        final_envelope, _ = _read_input_file(root, authority_name, "final CGAM authority envelope")
        f_structural, f_authorization, f_key, f_material, f_grant = _validate_local_subset(final_task, final_envelope, target, final_checked)
        final_head: dict[str, Any] | None = head
        final_lineage: str | None = None
        if not f_structural and f_key == key:
            conn.execute("BEGIN IMMEDIATE")
            try:
                final_lineage, final_head = _apply_authority_head(conn, f_key, f_material, final_envelope, f_grant, final_checked)
            except Exception:
                conn.rollback()
                raise
        elif f_key != key:
            f_structural.append("FINAL_AUTHORITY_KEY_MISMATCH")
        final_reasons = f_structural + ([final_lineage] if final_lineage else []) + f_authorization
        current = _target_state(root / target)
        if current["state_hash"] != pre["state_hash"] or current["identity"] != pre["identity"]:
            if conn.in_transaction:
                conn.rollback()
            _remove_temp(root, temp)
            stored = dict(conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt,)).fetchone())
            return _quarantine_attempt(conn, instance, stored, "TARGET_CHANGED_BEFORE_REPLACE", current["state_hash"])
        final_inputs = _record_inputs(
            task=final_task,
            envelope=final_envelope,
            authority_key=key,
            authority_head=final_head,
            instance_id=instance,
            attempt_id=attempt,
            payload_hash=payload_hash,
            target=target,
            checked_at=final_checked,
        )
        final_inputs["planning_record_inputs"] = inputs
        if not final_reasons:
            try:
                # Validate the exact consequence bundle before the filesystem
                # effect.  Runtime schema/domain failure can therefore never
                # strand a post-effect PREPARED attempt.
                _build_runtime_records(
                    final_inputs,
                    state="RECORDED_BOUND",
                    reason="AUTHORIZED_EFFECT",
                    bound=True,
                    denied=False,
                    before_state_hash=pre["state_hash"],
                    after_state_hash=expected_post_state_hash,
                    checked_at=final_checked,
                )
            except Exception:
                final_reasons.append("RUNTIME_RECORD_PREFLIGHT_FAILED")
        final_inputs["validation_reasons"] = list(final_reasons)
        if final_reasons:
            _remove_temp(root, temp)
            try:
                final_post = _target_state(root / target)
                final_observation_error = False
            except BindingError:
                final_post = None
                final_observation_error = True
            if (
                final_observation_error
                or final_post is None
                or final_post["state_hash"] != current["state_hash"]
                or final_post["identity"] != current["identity"]
            ):
                if conn.in_transaction:
                    conn.rollback()
                stored = dict(conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt,)).fetchone())
                return _quarantine_attempt(
                    conn,
                    instance,
                    stored,
                    (
                        "TARGET_UNSAFE_DURING_FINAL_DENIAL"
                        if final_observation_error
                        else "TARGET_CHANGED_DURING_FINAL_DENIAL"
                    ),
                    final_post["state_hash"] if final_post is not None else None,
                )
            final_inputs["observation_start"] = final_checked
            final_inputs["observation_end"] = _observation_end_after(
                final_checked, "observation_end"
            )
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            try:
                row = _update_attempt(
                    conn, attempt, task_json=_json_blob(final_task), envelope_json=_json_blob(final_envelope),
                    task_hash=canonical_hash(final_task), envelope_hash=canonical_hash(final_envelope),
                    grant_hash=canonical_hash(f_grant), authority_revision=_journal_revision(final_envelope),
                    previous_grant_hash=final_envelope.get("previous_grant_hash"), record_inputs_json=_json_blob(final_inputs),
                    updated_at=final_checked, reason_code=_safe_reason(final_reasons), temp_basename=None,
                )
            except Exception:
                conn.rollback()
                raise
            return _terminalize(
                conn, instance, row, state="RECORDED_NOT_BOUND", reason=_safe_reason(final_reasons),
                bound=False, denied=True, post=final_post, checked_at=final_checked,
                transaction_open=True,
            )
        # Persist the exact final task/envelope/head material before the effect.
        # If the process exits after this commit but before replace, recovery
        # truthfully returns RECOVERED_NOT_BOUND using this final authority.
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        try:
            _update_attempt(
                conn,
                attempt,
                task_json=_json_blob(final_task),
                envelope_json=_json_blob(final_envelope),
                task_hash=canonical_hash(final_task),
                envelope_hash=canonical_hash(final_envelope),
                grant_hash=canonical_hash(f_grant),
                authority_revision=_journal_revision(final_envelope),
                previous_grant_hash=final_envelope.get("previous_grant_hash"),
                record_inputs_json=_json_blob(final_inputs),
                updated_at=final_checked,
                reason_code="FINAL_AUTHORITY_REVALIDATED",
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        directory_flush = _replace_target(root, temp, target)
        _hit_failpoint("R6A-CRASH-003")
        post = _target_state(root / target)
        if not post["state"]["exists"] or post["state"]["content_sha256"] != payload_hash:
            stored = dict(conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt,)).fetchone())
            return _quarantine_attempt(conn, instance, stored, "POST_REPLACE_HASH_MISMATCH", post["state_hash"])
        stored = dict(conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt,)).fetchone())
        result = _terminalize(
            conn, instance, stored, state="RECORDED_BOUND", reason="AUTHORIZED_EFFECT",
            bound=True, denied=False, post=post, checked_at=final_checked,
        )
        result["directory_flush"] = directory_flush
        _hit_failpoint("R6A-CRASH-004")
        return result


def cooperative_write_authority(
    sandbox: os.PathLike[str] | str,
    *,
    authority_basename: str,
    envelope: dict[str, Any],
    expected_instance_id: str | None = None,
    hold_seconds: float = 0.0,
) -> dict[str, Any]:
    root = _validate_sandbox(sandbox)
    name = validate_basename(authority_basename)
    try:
        frozen_envelope = _strict_json_bytes(
            canonical_bytes(envelope), "cooperative authority envelope"
        )
    except (BindingError, TypeError, ValueError) as exc:
        if isinstance(exc, BindingError):
            raise
        raise BindingError(
            "AUTHORITY_ENVELOPE_INVALID",
            f"cooperative authority envelope is not canonicalizable: {exc}",
            state="DENIED",
        ) from exc
    candidate_grant, candidate_key, candidate_material = _writer_authority_identity(
        frozen_envelope
    )
    with _journal(root, create=False, expected_instance_id=expected_instance_id) as (conn, instance, _, _):
        try:
            current_envelope, _ = _read_input_file(
                root, name, "current cooperative authority envelope"
            )
        except BindingError as exc:
            if exc.code != "INPUT_MISSING":
                raise
            current_envelope = None
        if current_envelope is not None:
            current_grant, current_key, current_material = _writer_authority_identity(
                current_envelope
            )
            if current_key != candidate_key or current_material != candidate_material:
                raise BindingError(
                    "AUTHORITY_KEY_MISMATCH",
                    "cooperative authority publication changes immutable authority identity",
                    state="DENIED",
                )
            reason = _publication_lineage_reason(
                frozen_envelope,
                candidate_grant,
                current_revision=int(current_envelope["authority_revision"]),
                current_grant_hash=canonical_hash(current_grant),
                current_envelope_hash=canonical_hash(current_envelope),
            )
            if reason is not None:
                raise BindingError(
                    reason,
                    "cooperative authority publication violates the current file lineage",
                    state="DENIED",
                )
        elif (
            int(frozen_envelope["authority_revision"]) != 1
            or frozen_envelope.get("previous_grant_hash") is not None
        ):
            raise BindingError(
                "AUTHORITY_REVISION_GAP",
                "authority file is absent and candidate is not initial revision one",
                state="DENIED",
            )
        journal_head_sqlite = conn.execute(
            "SELECT * FROM authority_heads WHERE authority_key=?", (candidate_key,)
        ).fetchone()
        if journal_head_sqlite is None:
            other_head = conn.execute("SELECT authority_key FROM authority_heads LIMIT 1").fetchone()
            if other_head is not None:
                raise BindingError(
                    "AUTHORITY_KEY_MISMATCH",
                    "journal contains a different monotonic authority lineage",
                    state="DENIED",
                )
            if (
                int(frozen_envelope["authority_revision"]) != 1
                or frozen_envelope.get("previous_grant_hash") is not None
            ):
                raise BindingError(
                    "AUTHORITY_HEAD_UNESTABLISHED",
                    "journal must bind exact revision one before a cooperative successor publication",
                    state="DENIED",
                )
        else:
            journal_head = dict(journal_head_sqlite)
            reason = _publication_lineage_reason(
                frozen_envelope,
                candidate_grant,
                current_revision=int(journal_head["authority_revision"]),
                current_grant_hash=str(journal_head["grant_hash"]),
                current_envelope_hash=str(journal_head["envelope_hash"]),
            )
            if reason is not None:
                raise BindingError(
                    reason,
                    "cooperative authority publication violates the durable journal head",
                    state="DENIED",
                )
        temp = f"{AUTHORITY_TEMP_PREFIX}{uuid.uuid4()}"
        path = root / temp
        raw = _json_blob(frozen_envelope) + b"\n"
        replaced = False
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            try:
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise BindingError("AUTHORITY_TEMP_WRITE_FAILED", "authority temp write made no progress")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(path, root / name)
            replaced = True
            flush = _fsync_directory(root)
        finally:
            if not replaced:
                try:
                    info = os.lstat(path)
                    if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and not _is_reparse(path):
                        os.unlink(path)
                        _fsync_directory(root)
                except FileNotFoundError:
                    pass
        if hold_seconds > 0:
            time.sleep(hold_seconds)
        return {
            "state": "AUTHORITY_WRITTEN",
            "journal_instance_id": instance,
            "authority_revision": int(frozen_envelope["authority_revision"]),
            "envelope_hash": canonical_hash(frozen_envelope),
            "directory_flush": flush,
        }


def inspect_binding(
    sandbox: os.PathLike[str] | str,
    *,
    expected_instance_id: str | None = None,
) -> dict[str, Any]:
    root = _validate_sandbox(sandbox)
    with _journal(root, create=False, expected_instance_id=expected_instance_id) as (conn, instance, _, _):
        return {
            "state": "JOURNAL_VALID",
            "journal_instance_id": instance,
            "journal_mode": str(conn.execute("PRAGMA journal_mode").fetchone()[0]).upper(),
            "synchronous": int(conn.execute("PRAGMA synchronous").fetchone()[0]),
            "foreign_keys": int(conn.execute("PRAGMA foreign_keys").fetchone()[0]),
            "integrity_check": str(conn.execute("PRAGMA integrity_check").fetchone()[0]),
            "table_count": len(EXPECTED_TABLES),
            "authority_head_count": int(conn.execute("SELECT COUNT(*) FROM authority_heads").fetchone()[0]),
            "attempt_count": int(conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]),
            "record_count": int(conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]),
            "prepared_count": int(conn.execute("SELECT COUNT(*) FROM attempts WHERE state='PREPARED'").fetchone()[0]),
            "quarantined_count": int(conn.execute("SELECT COUNT(*) FROM attempts WHERE state='QUARANTINED_UNRESOLVED'").fetchone()[0]),
        }


def _emit(value: Any) -> None:
    # ASCII JSON is lossless and survives legacy Windows console code pages;
    # callers decode escapes back to the exact Unicode basename.
    print(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")))


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--sandbox", required=True)
    init.add_argument("--expected-instance")
    recover = sub.add_parser("recover")
    recover.add_argument("--sandbox", required=True)
    recover.add_argument("--expected-instance")
    inspect = sub.add_parser("inspect")
    inspect.add_argument("--sandbox", required=True)
    inspect.add_argument("--expected-instance")
    bind = sub.add_parser("bind")
    bind.add_argument("--sandbox", required=True)
    bind.add_argument("--task", required=True)
    bind.add_argument("--authority", required=True)
    bind.add_argument("--target", required=True)
    bind.add_argument("--payload-text", required=True)
    bind.add_argument("--attempt-id")
    bind.add_argument("--expected-instance")
    writer = sub.add_parser("write-authority")
    writer.add_argument("--sandbox", required=True)
    writer.add_argument("--authority", required=True)
    writer.add_argument("--envelope-basename", required=True)
    writer.add_argument("--expected-instance")
    writer.add_argument("--hold-seconds", type=float, default=0.0)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            result = initialize_binding(args.sandbox, expected_instance_id=args.expected_instance)
        elif args.command == "recover":
            result = recover_pending(args.sandbox, expected_instance_id=args.expected_instance)
        elif args.command == "inspect":
            result = inspect_binding(args.sandbox, expected_instance_id=args.expected_instance)
        elif args.command == "bind":
            result = bind_text(
                args.sandbox,
                task_basename=args.task,
                authority_basename=args.authority,
                target_basename=args.target,
                payload=args.payload_text.encode("utf-8"),
                attempt_id=args.attempt_id,
                expected_instance_id=args.expected_instance,
            )
        else:
            writer_root = _validate_sandbox(args.sandbox)
            envelope_name = validate_basename(args.envelope_basename)
            envelope, _ = _read_input_file(
                writer_root,
                envelope_name,
                "cooperative authority-writer envelope",
            )
            result = cooperative_write_authority(
                args.sandbox,
                authority_basename=args.authority,
                envelope=envelope,
                expected_instance_id=args.expected_instance,
                hold_seconds=args.hold_seconds,
            )
        _emit(result)
        return 0
    except BindingError as exc:
        _emit({"state": exc.state, "error_code": exc.code, "message": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
