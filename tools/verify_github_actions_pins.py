
#!/usr/bin/env python3
"""Fail closed unless every external runtime-workflow action uses an accepted immutable SHA."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
RUNTIME_WORKFLOW = WORKFLOW_ROOT / "runtime-integrity-extension.yml"
EXPECTED_ACTION_SHAS = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
}
USES_LINE_PATTERN = re.compile(
    r'''^\s*(?:-\s*)?(?:\{\s*)?(?:uses|"uses"|'uses')\s*:\s*'''
    r'''(?P<value>"[^"]*"|'[^']*'|[^\s#},]+)?'''
)
FLOW_USES_PATTERN = re.compile(
    r'''(?:^|[,{}]\s*)(?:uses|"uses"|'uses')\s*:\s*'''
    r'''(?P<value>"[^"]*"|'[^']*'|[^\s#},]+)?'''
)
IMMUTABLE_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
YAML_KEY_ESCAPE_PATTERN = re.compile(r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})")
YAML_ANCHOR_OR_ALIAS_PATTERN = re.compile(r"(?:^|[\s\[\]{},:])[&*][A-Za-z0-9_-]+")


def decoded_value(match: re.Match[str]) -> str:
    value = match.group("value") or ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return value


def uses_values(line: str) -> list[str]:
    if "{" in line:
        return [decoded_value(match) for match in FLOW_USES_PATTERN.finditer(line)]
    match = USES_LINE_PATTERN.match(line)
    return [] if match is None else [decoded_value(match)]


def validate_workflow_text(text: str, *, path: str = "<memory>") -> tuple[list[str], set[str]]:
    issues: list[str] = []
    seen: set[str] = set()
    lines = text.splitlines()
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if YAML_KEY_ESCAPE_PATTERN.search(line):
            issues.append(f"{path}:{index + 1}: escaped YAML mapping keys are outside the accepted workflow subset")
        if YAML_ANCHOR_OR_ALIAS_PATTERN.search(line):
            issues.append(f"{path}:{index + 1}: YAML anchors and aliases are outside the accepted workflow subset")
        if re.match(r"^\s*(?:-\s*)?\?", line):
            issues.append(f"{path}:{index + 1}: explicit YAML mapping keys are outside the accepted workflow subset")
        values = uses_values(line)
        if not values and re.search(r"(?:^|[,{]\s*|\s)(?:uses|\"uses\"|'uses')\s*:", line):
            issues.append(f"{path}:{index + 1}: unrecognized uses-key syntax")
        for value in values:
            if value.startswith("./"):
                continue
            if "@" not in value:
                issues.append(f"{path}:{index + 1}: external Action reference lacks an immutable ref: {value}")
                continue
            action, ref = value.rsplit("@", 1)
            seen.add(action)
            expected = EXPECTED_ACTION_SHAS.get(action)
            if expected is None:
                issues.append(f"{path}:{index + 1}: unapproved external Action: {action}")
            elif not IMMUTABLE_SHA_PATTERN.fullmatch(ref):
                issues.append(f"{path}:{index + 1}: mutable or malformed Action ref: {value}")
            elif ref != expected:
                issues.append(
                    f"{path}:{index + 1}: Action SHA differs from verified accepted commit: {value}"
                )
            previous = lines[index - 1] if index else ""
            if not re.fullmatch(
                rf"\s*#\s+.*{re.escape(action)}.*source run \d+\s*",
                previous,
            ):
                issues.append(
                    f"{path}:{index + 1}: external Action pin lacks an adjacent action/source-run comment"
                )
    return issues, seen


def audit_repository(root: Path | None = None) -> tuple[list[str], int, int]:
    # R3 is a runtime-only successor.  The checksum-owned integrity workflow is
    # an explicit forbidden path and remains outside this verifier's authority.
    workflows = [RUNTIME_WORKFLOW] if root is None else sorted({*root.glob("*.yml"), *root.glob("*.yaml")})
    issues: list[str] = []
    seen: set[str] = set()
    external_refs = 0
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        workflow_issues, workflow_seen = validate_workflow_text(
            text,
            path=workflow.relative_to(ROOT).as_posix(),
        )
        issues.extend(workflow_issues)
        seen.update(workflow_seen)
        external_refs += len([
            value
            for line in text.splitlines()
            for value in uses_values(line)
            if not value.startswith("./")
        ])
    missing = sorted(set(EXPECTED_ACTION_SHAS) - seen)
    if missing:
        issues.append(f"required accepted Actions are absent from the workflow set: {missing}")
    return issues, len(workflows), external_refs


def main() -> int:
    issues, workflow_count, external_refs = audit_repository()
    for item in issues:
        print(item)
    print(
        f"GITHUB_ACTION_PINNING workflows={workflow_count} external_refs={external_refs} "
        f"pass={int(not issues)} fail={len(issues)}"
    )
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
