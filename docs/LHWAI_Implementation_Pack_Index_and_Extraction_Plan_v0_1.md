# LHWAI Implementation Pack Index and Extraction Plan v0.1

## Schemas, fixtures, validator CLI, and conformance artifacts for Long-Horizon Witness Anchoring and Interpretation

**Author:** Ivan Kotov  
**Date:** 2026-05-22  
**Status:** Draft implementation-pack index v0.1  
**Layer:** LHWAI / L4 Witness / ARL / Continuity Bundle / CLI Agent Mesh / GitHub-Zenodo release discipline  
**Document class:** implementation pack index / schema extraction plan / validator plan  
**Assertion class:** `C-A10` control-layer artifact

---

## 0. Executive definition

This document turns the Long-Horizon Witness Anchoring and Interpretation Profile into implementation artifacts.

The normative profile defines:

```text
witness epochs
digest ladder
anchor packets
external commitments
interpretation profiles
semantic freeze
challenge records
validation reports
red-line failures
conformance levels
```

This implementation pack defines the files needed to make those rules testable.

---

## 1. Package layout

Recommended layout:

```text
docs/witness/long-horizon/
  Long_Horizon_Witness_Anchoring_and_Interpretation_Profile_v0_1.md
  LHWAI_Implementation_Pack_Index_and_Extraction_Plan_v0_1.md
  schemas/
    long_horizon_witness_anchor_packet.schema.json
    witness_interpretation_profile.schema.json
    witness_interpretation_challenge_record.schema.json
    witness_anchor_validation_report.schema.json
    key_epoch_record.schema.json
  fixtures/
    valid_anchor_packet_minimal.yaml
    valid_interpretation_profile_minimal.yaml
    valid_interpretation_challenge_policy_migration.yaml
    valid_validation_report_pass_with_gaps.yaml
    invalid_public_low_entropy_hash.yaml
    invalid_agent_self_exoneration.yaml
    invalid_missing_interpretation_profile.yaml
  conformance/
    LHWAI_Test_Matrix_v0_1.md
    LHWAI_Red_Line_Failure_Cases_v0_1.md
  tools/
    lhwai_validate.py
    lhwai_make_epoch_digest.py
    lhwai_make_anchor_packet.py
```

---

## 2. Required schemas

| Schema | Purpose | Priority |
|---|---|---:|
| `long_horizon_witness_anchor_packet.schema.json` | Validate anchor packet shape. | P0 |
| `witness_interpretation_profile.schema.json` | Validate semantic decoder profile. | P0 |
| `witness_interpretation_challenge_record.schema.json` | Validate reinterpretation/challenge records. | P0 |
| `witness_anchor_validation_report.schema.json` | Validate later audit reports. | P0 |
| `key_epoch_record.schema.json` | Validate key rotation and revocation epochs. | P1 |

---

## 3. Fixture requirements

### 3.1 Valid fixtures

| Fixture | Must demonstrate |
|---|---|
| `valid_anchor_packet_minimal.yaml` | epoch digest + interpretation profile hash + packet hash |
| `valid_interpretation_profile_minimal.yaml` | schema/policy/reason-code registry hashes |
| `valid_interpretation_challenge_policy_migration.yaml` | append-only reinterpretation under new policy |
| `valid_validation_report_pass_with_gaps.yaml` | validation with declared missing/disputed events |

### 3.2 Invalid fixtures

| Fixture | Must fail because |
|---|---|
| `invalid_public_low_entropy_hash.yaml` | public anchor leaks guessable sensitive payload |
| `invalid_agent_self_exoneration.yaml` | agent validates its own contested high-risk event |
| `invalid_missing_interpretation_profile.yaml` | anchor packet lacks required interpretation context |
| `invalid_silent_reclassification.yaml` | old event reclassified without challenge record |
| `invalid_key_rotation_reset.yaml` | key rotation treated as historical reset |

---

## 4. Validator CLI requirements

A minimal validator CLI SHOULD support:

```text
lhwai validate-anchor <anchor_packet>
lhwai validate-profile <interpretation_profile>
lhwai validate-challenge <challenge_record>
lhwai validate-report <validation_report>
lhwai validate-fixture-suite <fixtures_dir>
lhwai make-epoch-digest <event_manifest>
lhwai make-anchor-packet <epoch_digest> <profile>
```

The validator MUST check:

1. schema validity;
2. required hashes present;
3. interpretation profile references present;
4. privacy flags present;
5. no raw content in public packet;
6. low-entropy public hash risk field present;
7. no self-certifying compromised agent;
8. key epoch references where required;
9. gap status declared;
10. red-line failures.

---

## 5. Acceptance criteria

The implementation pack is minimally acceptable when:

```text
all P0 schemas exist
all P0 fixtures exist
validator rejects all invalid fixtures
validator accepts valid fixtures
README explains local-only vs external commitment modes
conformance levels LHWAI-0..5 are machine-checkable at declaration level
```

---

## 6. Integration points

| Area | Integration |
|---|---|
| L4 Runtime Enforcement | budget/hard-stop events enter witness epochs |
| Memory Drift Profile | memory promotion/compaction/quarantine emits witness refs |
| Human Anchor Drift | anchor drift challenges create interpretation challenge records |
| 90-Day Evidence Pack | monthly validation report and anchor packets included |
| GitHub/Zenodo release | redacted manifest / signed tag / DOI metadata used as external commitment |
| CLI Agent Mesh | package ledger and compromised-agent quarantine bind to anchor packets |

---

## 7. Bridge set

### Explicit bridge

LHWAI gives the long-horizon witness rules. This implementation pack makes them testable without redefining L4 Witness, ARL, or Continuity Bundle.

### Quiet bridge I — cybernetics

A witness system cannot regulate historical drift if validation is manual folklore. The validator closes the loop by making the record checkable.

### Quiet bridge II — information theory

A schema is a decoder contract. Without schemas and fixture failures, a digest is only a number. With schemas, it becomes verifiable structure.

### Earth paragraph

A signed inspection note is useful. A binder with the note, drawing version, photo index, batch ticket, and later validation checklist is stronger. The implementation pack is that binder.

---

## 8. Open issues

| ID | Issue | Priority |
|---|---:|---:|
| `OI-LHWAI-IMPL-001` | Write JSON schemas. | P0 |
| `OI-LHWAI-IMPL-002` | Produce first fixture suite. | P0 |
| `OI-LHWAI-IMPL-003` | Implement validator CLI. | P1 |
| `OI-LHWAI-IMPL-004` | Add CI check for fixtures. | P1 |
| `OI-LHWAI-IMPL-005` | Add release/DOI external commitment example. | P2 |
