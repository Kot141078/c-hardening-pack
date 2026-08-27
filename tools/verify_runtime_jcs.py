#!/usr/bin/env python3
"""Verify the runtime RFC 8785/I-JSON golden vectors in Python."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "validate_runtime_integrity_extension.py"
VECTORS = ROOT / "canonicalization" / "runtime-jcs-golden-vectors.json"


def load_validator():
    spec = importlib.util.spec_from_file_location("runtime_jcs_validator", VALIDATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("validator module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    validator = load_validator()
    vectors = validator.load_json(VECTORS)
    passed = 0
    failures: list[str] = []
    for vector in vectors["positive_vectors"]:
        try:
            value = validator.loads_json_strict(vector["input_json"], vector["id"])
            canonical = validator.jcs_bytes(value)
            if canonical.hex() != vector["canonical_utf8_hex"]:
                raise AssertionError("canonical bytes differ")
            if hashlib.sha256(canonical).hexdigest() != vector["sha256"]:
                raise AssertionError("SHA-256 differs")
            passed += 1
        except Exception as exc:  # verifier must aggregate all vector failures
            failures.append(f"{vector['id']}: {exc}")
    for vector in vectors["negative_vectors"]:
        try:
            value = validator.loads_json_strict(vector["input_json"], vector["id"])
            validator.jcs_bytes(value)
        except validator.JSONDomainError:
            passed += 1
        else:
            failures.append(f"{vector['id']}: out-of-domain JSON was accepted")
    total = len(vectors["positive_vectors"]) + len(vectors["negative_vectors"])
    print(f"RUNTIME_JCS_PYTHON vectors={total} pass={passed} fail={len(failures)}")
    for failure in failures:
        print(failure, file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
