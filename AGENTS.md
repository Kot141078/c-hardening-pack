# Repository Guidelines

## Purpose and Structure

This repository integrates bounded hardening layers for `c = a + b`. Preserve the additive architecture: baseline vectors and specifications remain stable while runtime-integrity extensions, policies, schemas, fixtures, and evidence are added explicitly. Key areas include `integration/`, schemas and fixtures at the root, `tools/`, vector suites, manifests, signatures, and generated `build/` reports.

## Canonical Verification

Run commands from the repository root:

```bash
python tools/verify_integrity.py --strict --verify-git-history
python tools/validate_runtime_integrity.py \
  --fixture runtime_integrity_fixture.json \
  --schema runtime_integrity.schema.json \
  --spec C_RUNTIME_INTEGRITY_SPEC.md \
  --policy c_runtime_integrity_policy_v0_1.json \
  --output build/runtime_integrity_result.json \
  --cleanroom-report build/cleanroom_report.json \
  --strict \
  --cleanroom
```

CI also exercises UTF-8 guards, minimum-baseline checks, vector replay, delta application, and result-integrity validation. Run the relevant negative fixtures for any semantic, authority, recovery, or consequence-path change.

## Style and Compatibility

Match existing Markdown and JSON formatting. Use stable IDs, deterministic ordering, canonical serialization, UTF-8, and 4-space Python indentation. Do not edit preserved baselines, oracle outputs, signed evidence, or historical manifests unless the task explicitly authorizes their replacement and all dependent hashes are regenerated.

## Engineering and Claim Boundaries

Novelty does not justify a new ledger, policy engine, transaction framework, identity stack, queue, lock, or validator when a mature primitive suffices. Reject paths must remain fail-closed and state-preserving where specified.

Keep these distinctions explicit:

- model, agent, or validator != `c`
- capability or permission != current authority
- local resource envelope != full L4
- signature or hash != truth
- replay, restart, or durable bytes != continuity

## Commits and Pull Requests

Use concise imperative subjects consistent with repository history. PRs must identify the requirement or failure mode, changed evidence surface, exact commands run, negative controls, hashes affected, remaining limitations, and rollback path. Passing tests do not authorize merge, release, publication, deployment, or the next gate.
