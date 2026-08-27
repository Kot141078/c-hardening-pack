from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "CHECKSUM_DOMAIN.json"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def fail(message: str) -> None:
    raise ValueError(message)


def safe_file(relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        fail(f"Unsafe manifest path: {relative!r}")
    resolved = (ROOT / path).resolve()
    if ROOT.resolve() not in resolved.parents:
        fail(f"Manifest path escapes repository: {relative!r}")
    return resolved


def crlf_bytes(data: bytes, relative: str) -> bytes:
    if b"\r\n" in data:
        if data.replace(b"\r\n", b"").find(b"\r") >= 0:
            fail(f"Mixed or bare-CR text is not admissible: {relative}")
        return data
    if b"\r" in data:
        fail(f"Bare-CR text is not admissible: {relative}")
    return data.replace(b"\n", b"\r\n")


def lf_bytes(data: bytes, relative: str) -> bytes:
    without_crlf = data.replace(b"\r\n", b"")
    if b"\r" in without_crlf or (b"\r\n" in data and b"\n" in without_crlf):
        fail(f"Mixed or bare-CR text is not admissible: {relative}")
    return data.replace(b"\r\n", b"\n")


def manifest_entries(path: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or not SHA256_RE.fullmatch(parts[0]):
            fail(f"Malformed checksum line {path.relative_to(ROOT)}:{line_number}")
        relative = parts[1].lstrip("*").strip()
        if relative in seen:
            fail(f"Duplicate checksum path in {path.relative_to(ROOT)}: {relative}")
        seen.add(relative)
        entries.append((parts[0].lower(), relative))
    return entries


def main() -> int:
    try:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        if config.get("schema_version") != "checksum-domain.v1":
            fail("Unsupported checksum-domain schema_version")
        checked = 0
        for declaration in config["manifests"]:
            if declaration.get("hash_algorithm") != "sha256" or declaration.get("default_mode") != "raw_bytes":
                fail(f"Unsupported checksum mode in {declaration.get('path')!r}")
            path_modes = declaration.get("path_modes")
            if not isinstance(path_modes, dict) or set(path_modes) != {"lf_text_bytes", "crlf_text_bytes"}:
                fail(f"Unsupported path_modes in {declaration.get('path')!r}")
            manifest_path = safe_file(declaration["path"])
            entries = manifest_entries(manifest_path)
            if len(entries) != declaration["expected_entries"]:
                fail(f"Entry count mismatch for {declaration['path']}")
            crlf_paths = set(path_modes["crlf_text_bytes"])
            lf_paths = set(path_modes["lf_text_bytes"])
            entry_paths = {relative for _, relative in entries}
            if not (crlf_paths | lf_paths) <= entry_paths:
                fail(f"Declared text path is absent from {declaration['path']}")
            if crlf_paths & lf_paths:
                fail(f"Conflicting text modes in {declaration['path']}")
            for expected, relative in entries:
                data = safe_file(relative).read_bytes()
                if relative in crlf_paths:
                    data = crlf_bytes(data, relative)
                elif relative in lf_paths:
                    data = lf_bytes(data, relative)
                actual = hashlib.sha256(data).hexdigest()
                if actual != expected:
                    fail(f"Checksum mismatch in {declaration['path']}: {relative}")
                checked += 1
        print(f"PASS checksum-domain.v1: {checked} manifest entries")
        return 0
    except (OSError, KeyError, TypeError, json.JSONDecodeError, ValueError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
