#!/usr/bin/env python3
"""Fail closed if the runtime review dependency lock loses exact hashes."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements-runtime-integrity.lock"
DIRECT = ROOT / "requirements-runtime-integrity.txt"
EXPECTED = {
    "attrs": ("25.3.0", 1),
    "jcs": ("0.2.1", 1),
    "jsonschema": ("4.23.0", 1),
    "jsonschema-specifications": ("2025.4.1", 1),
    "referencing": ("0.35.1", 1),
    "rfc3339-validator": ("0.1.4", 1),
    "rpds-py": ("0.26.0", 4),
    "six": ("1.17.0", 1),
    "typing-extensions": ("4.15.0", 1),
}


def main() -> int:
    text = LOCK.read_text(encoding="utf-8")
    logical = text.replace("\\\n", " ")
    entries: dict[str, tuple[str, list[str]]] = {}
    for line in logical.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)\s+(.+)$", line)
        if not match:
            raise SystemExit(f"malformed lock entry: {line}")
        name, version, tail = match.groups()
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)", tail)
        entries[name.casefold().replace("_", "-")] = (version, hashes)
    failures = []
    if set(entries) != set(EXPECTED):
        failures.append(f"package set differs: {sorted(entries)}")
    for name, (version, hash_count) in EXPECTED.items():
        actual = entries.get(name)
        if actual is None or actual[0] != version or len(actual[1]) != hash_count or len(set(actual[1])) != hash_count:
            failures.append(f"{name}: expected version={version} unique_hashes={hash_count}, observed={actual}")
    direct = {
        line.split("==", 1)[0].casefold().replace("_", "-")
        for line in DIRECT.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    if not direct.issubset(entries):
        failures.append(f"direct requirements absent from lock: {sorted(direct - set(entries))}")
    print(f"RUNTIME_DEPENDENCY_LOCK packages={len(EXPECTED)} pass={0 if failures else 1} fail={len(failures)}")
    for failure in failures:
        print(failure, file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
