# Runtime Integrity Traceability Matrix v0.1.1

**Status:** Development matrix
**Date:** 2026-08-27
**Parent:** `Runtime_Consequence_Integrity_Profile_for_c_v0_1.md`

## 1. Purpose

This matrix prevents the runtime-integrity extension from becoming a duplicate theory layer.

Each new object must close a specific residual gap while leaving the parent layer authoritative.

| Requirement | Native antecedent | Residual gap | Extension object or fixture | Failure test |
|---|---|---|---|---|
| Revalidate at consequence commit | AGL; Initiation Gates | No compact final machine record | `consequence_commit_record` | stale authority plus `OPEN` must fail |
| Prove scoped absence of effect | L4 Witness; CGAM refusal semantics | `DENY` alone does not inspect downstream state | `non_effect_witness_record` linked to the commit attempt | open alternate route or an observation interval excluding the commit `created_at` attempt must fail |
| Bind exact rule and authority basis | AGL; CGAM permission; witness refs | Source provenance does not freeze the decision rule basis | `decision_basis_record` | mismatched canonical basis hash must fail |
| Requalify memory at use time | Memory Gate; CGAM memory record | Admission does not establish present purpose, consent, freshness or authority | `memory_reliance_record` | revoked memory plus `USE` must fail |
| Distinguish endpoint similarity from lineage | Beacon; SER; Continuity Bundle | No paired machine fixture proving snapshot insufficiency | `continuity_history_cases.json` | endpoint-equal histories must retain different classifications |
| Separate viability from identity | L4; Beacon; Continuity Bundle | Independence not expressed as cross-layer executable rule | continuity cases and carry-cost profile | resource restoration must not repair lineage |
| Account for idle presence cost | L4 runtime enforcement | Passive continuity overhead is not grouped explicitly | `continuity_carry_cost_profile.json` | carry dimensions cannot be identity-bearing |
| Detect boundary extraction by use | Capability restrictions; Memory Gate; L4 budgets | Repeated-query leakage is not a first-class record | `boundary_probe_record` | high-risk budget-exceeded probe plus `ALLOW` must fail |
| Preserve synthesis disagreement | Judge concept; evidence discipline | Model outputs can be flattened into a single verdict | `judge_deliberation_record` | majority voting or one model family must fail |
| Bound external influence claims | citation/provenance practices | Vague "inspired by" or "derived from" statements | `external_construct_intake_record` | code reuse without license clearance must fail |
| Preserve history under changed conditions | append-only witness; ARL correction discipline | Old decision may be silently overwritten | previous-record links | changed condition must create a new linked record |
| Rebind a changed consequence target | AGL revalidation; CGAM task/grant separation | An old target basis can be replayed at a new endpoint | `consequence_lineage_id`, transition evidence, new endpoint-B basis/commit | missing grant, task, transition, lineage, immutable predecessor, or current-target binding must fail |
| Validate the complete predecessor history | append-only witness discipline | A locally valid edge may hide a longer cycle or missing predecessor | trusted-registry DAG audit | self, two-node, longer cycle, missing node, alias, timestamp, lineage, and effect-intent mutations must fail |
| Make JSON hashes interoperable | exact evidence hashing | language-default JSON serialization may disagree | RFC 8785/I-JSON profile and Python/Node golden vectors | duplicate keys, non-finite values, lone surrogates, unsafe integer-valued numbers, or byte mismatch must fail |
| Bind Judge to independently expected state | Judge evidence discipline | a tracked passport/context can self-assert its review target | caller-supplied context hash and event bindings | missing, mismatched, or temporally invalid context must fail |
| Preserve relation-specific provenance ceilings | citation/provenance practices | a same-source but unrelated proof artifact can elevate a relation | typed relation proof contracts | mismatched license, mapping, transformation, dependency, removal, provenance, or manual gate must fail |
| Inventory every evidence artifact | evidence custody and fail-closed registries | directly referenced evidence could remain outside the logical-ID registry | exact evidence artifact inventory with JCS hash and in-file logical IDs | orphan, missing, duplicate-path, duplicate-logical-ID, or registry/inventory mismatch must fail |

## 2. Object dependencies

```text
decision_basis_record
  <- policy refs
  <- authority refs
  <- permission grant
  <- AGL grounding
  <- Beacon / continuity evidence
  <- L4 state
  <- memory_reliance_record(s)
  <- evidence refs
  <- witness head

consequence_commit_record
  <- decision_basis_record
  <- final preconditions
  <- effect target
  -> effect state
  -> non_effect_witness_record when NOT_BOUND
```

## 3. Non-entailment matrix

| Known state | Does not establish |
|---|---|
| valid identity credential | current action authority |
| valid planning approval | valid commit-time authority |
| `DENY` log | absence of downstream effect |
| same endpoint hash | same entity lineage |
| archive present | bounded resume |
| resources restored | identity restored |
| lineage preserved | L4 viability |
| memory admitted | memory usable now |
| multiple model agreement | factual truth |
| public citation | derivation or dependency |
| interface adaptation | ontology absorption |

## 4. Stop rule

Do not add a new object merely because a neighbouring framework has one.

A new object is allowed only when:

1. an existing native layer is identified;
2. the residual machine-evidence gap is explicit;
3. no current schema already carries the required semantics;
4. at least one positive and one negative fixture are defined;
5. the object has a claim boundary;
6. the object can be removed without changing the ontology of `c`.

## 5. Implementation placement

Initial coordination home:

```text
Kot141078/c-hardening-pack
```

Possible future implementation bindings, only after separate owner authorization:

```text
CGAM:
  task contract
  permission grant
  memory gate
  witness event

TAP-SEC:
  trusted time
  witness sequencer
  metabolic / L4 state
  memory admission
  release and recovery paths

Advanced Global Intelligence:
  Beacon
  Continuity Bundle
  AGL publication alignment
```

No cross-repository canonical migration is authorized by this draft. CGAM and TAP-SEC binding were not started.
