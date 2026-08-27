# Runtime Consequence Integrity Profile for `c` v0.1.1

**Status:** R1F development candidate / non-normative extension

**Date:** 2026-08-27

**Author:** Ivan Kotov

**Repository role:** Cross-layer hardening extension for the authored `c = a + b` corpus
**Implementation claim:** Machine-readable schemas, deterministic fixtures, and a development validator are included. No production, certification, legal-compliance, or complete-conformance claim is made.

## 0. Executive definition

This profile closes a narrow but important gap between existing doctrine and executable evidence.

The authored corpus already contains:

- Actor Grounding Layer checks;
- initiation gates and `REVALIDATE_AT_COMMIT`;
- task-scoped permission and capability separation;
- L4 resource and perimeter constraints;
- Beacon and Continuity Bundle lineage discipline;
- Memory Gate admission and promotion discipline;
- append-only witness and review structures;
- Judge-style multi-model synthesis.

The missing bridge is not another foundation theory. It is a compact set of machine objects and fixtures that answer five practical questions:

1. What exact basis was current when consequence attempted to bind?
2. If the path was denied or held, what evidence shows that the declared effect did not form?
3. If a memory item was lawful to store earlier, is it lawful to rely on now for this purpose?
4. If two endpoints look the same, what history-sensitive evidence distinguishes continuation, replay, restore, fork, and unresolved lineage?
5. If external work sharpens a test, what exact construct was used, how was it transformed, and what does that relationship not prove?

Compact rule:

```text
plan approval
  != current authority
  != commit eligibility
  != effect formation
  != entity continuity
```

## 1. Position in the corpus

This profile is an extension over existing layers, not a replacement for them.

| Existing layer | Existing function | Function added here |
|---|---|---|
| AGL | Qualifies present source grounding and requires revalidation at commit | Machine-readable final commit record |
| Initiation Gates | Determines whether a path may open, narrow, hold, reroute, deny, or quarantine | Final closure of the consequence boundary |
| CGAM | Defines task contracts, permission grants, bounded capability, and non-self-approval | Exact references from final commit to current grant and task |
| L4 | Governs physical and computational resource reality | Current L4 state reference and continuity carry-cost categories |
| Beacon / SER / Continuity Bundle | Distinguishes entity, tool, proxy, replay, clone, fork, and bounded resume | Paired history-sensitive fixtures that forbid snapshot inflation |
| Memory Gate | Governs memory admission, promotion, quarantine, correction, and forgetting | Use-time memory reliance record |
| L4 Witness / TAP-SEC witness | Preserves append-only, hash-linked events | Scoped non-effect witness and linked reevaluation |
| Judge | Synthesizes local and remote model review | Typed independent review roles and preserved divergence |
| Corpus governance | Maintains authored terminology and claim boundaries | External construct intake record |

## 2. Non-goals

This profile does not:

- redefine `c`, `a`, or `b`;
- create a new AI class;
- replace AGL, ARL, L4, Beacon, SER, CGAM, Memory Gate, MOT-c, or Judge;
- claim that a record proves factual truth merely because it is well formed;
- claim that endpoint resemblance establishes identity;
- treat resource recovery as identity recovery;
- copy or reverse engineer external protected implementations;
- adopt external product terminology as canonical `c` vocabulary;
- claim production readiness.

## 3. Native terminology firewall

External work may expose a useful test without becoming the ontology of `c`.

The following substitutions are functional placements, not claims of exact theoretical equivalence.

| External or neighbouring term | Native term used here | Reason |
|---|---|---|
| bind-time | consequence commit | AGL already uses commit-time revalidation |
| no-bind receipt | non-effect witness record | States a scoped negative evidence claim in native witness language |
| current standing | current authority and grounding | Keeps authority, grounding, and ARL standing as separate axes |
| seam witness | continuity transition evidence | Preserves Beacon and Continuity Bundle terminology |
| burden ledger / structural pressure | L4 resource state / continuity carry cost | Avoids a second resource ontology |
| selector | decision basis | Records exact policy and authority basis without importing a foreign formal class |
| changed-condition replay | linked reevaluation under changed conditions | Uses append-only witness and supersession semantics |
| route closure | alternate-path closure evidence | Describes the test directly |
| ECR role names | Judge independent review roles | Keeps Judge as the local synthesis component |
| receipt | record or witness record | Avoids treating every output as a product-specific receipt object |

## 4. Core invariants

### I1. No stale legitimacy

A permission, grounding state, consent state, or source qualification valid during planning does not automatically remain valid at consequence commit.

```text
valid_at_plan(t0) does not entail valid_at_commit(t1)
```

### I2. No consequence without a current basis

A consequence may bind only when the final commit record references current:

- task contract;
- permission grant;
- decision basis;
- source grounding;
- continuity evidence;
- L4 state;
- memory reliance records where memory influenced the action;
- witness-chain head.

### I3. Denial is not yet negative evidence

A log line that says `DENY` proves only that one component emitted a denial.

For high-impact paths, a stronger claim that the effect did not form requires a scoped non-effect witness over declared surfaces, queues, retries, alternate routes, and target state.

### I4. Negative evidence is scoped

A non-effect witness must state its observation window, surfaces, coverage, and claim boundary.

When a high-assurance `NOT_BOUND` commit relies on that witness, the commit's existing `created_at` field is the consequence-attempt time and must fall inside the linked observation interval, inclusively. The comparison retains every declared fractional-second digit rather than truncating to platform microsecond precision. Epoch zero remains an ordinary timestamp rather than a missing value. Inputs whose declared offset would place the UTC instant outside years 0001 through 9999 are outside this strict profile and fail closed. A later observation may remain valid for its own declared scope, but it cannot prove non-effect for an earlier attempt.

```text
no effect observed within declared scope
  != no effect existed anywhere
```

### I5. Endpoint resemblance is not continuity

A snapshot-only verifier must not inflate endpoint similarity into the strongest continuity classification.

```text
same endpoint state
  does not entail
same lineage
```

### I6. L4 viability and identity evidence are independent

```text
resource recovery does not entail identity recovery
identity continuity does not entail resource viability
```

The profile therefore references L4 state and continuity evidence separately.

### I7. Memory admission is not present use authority

A memory object may have been lawfully admitted and still be stale, revoked, contested, contaminated, outside current consent, or irrelevant to the current purpose.

Every consequence-bearing use may require a `memory_reliance_record`.

### I8. The rule basis must be version-bound

A consequential decision must be traceable to exact policy versions, authority references, evidence references, continuity state, L4 state, and witness head.

A signed artifact with an unknown or drifting rule basis remains insufficient.

### I9. Protected boundaries may leak through use

Repeated refusals, timing differences, cross-agent aggregation, provider rotation, and memory-assisted probing may reconstruct a protected boundary without any direct write access.

Such probing consumes a bounded budget and may trigger narrowing, hold, denial, or quarantine.

### I10. Judge disagreement remains data

Judge review must not erase a strong minority objection merely because more models selected another conclusion.

The output must preserve:

- shared supported core;
- unresolved divergence;
- minority objections;
- missing evidence;
- recommended tests.

### I11. Changed conditions create a new record

A previously issued record is never silently rewritten to fit new conditions.

```text
changed condition
  -> new linked record
  -> old record remains immutable
```

Every consequence commit carries a stable `consequence_lineage_id`. Across a predecessor edge, effect intent is exactly the tuple `(effect_id, effect_class, reversibility)`; `target_ref` is deliberately separate because an authorized H14 transition may change it. A changed target additionally requires a new current permission grant, a new current task contract, a new decision basis captured no later than the commit, and exact transition evidence binding both record IDs, both targets, lineage, the full effect-intent tuple, reason, grants, tasks, and an observed time strictly after the predecessor and no later than the successor. The complete trusted predecessor registry must be an acyclic graph.

### I12. External influence must be artifact-specific

Claims of comparison, inspiration, adaptation, dependency, or code reuse must identify:

- exact source artifact;
- exact external construct;
- exact local target;
- transformation;
- preserved properties;
- rejected properties;
- mapping failures;
- license status;
- attribution;
- native antecedents;
- claim ceiling.

## 5. Machine objects

### 5.1 `consequence_commit_record`

Purpose: bind the final AGL and initiation-gate evaluation to the actual consequence boundary.

Required functions:

- current precondition results;
- current conditions hash;
- effect target and reversibility;
- final gate outcome;
- effect state;
- link to a non-effect witness when `NOT_BOUND`;
- append-only link to a previous record when reevaluated.

A linked commit also binds its predecessor by exact record version and RFC 8785 hash. A target change cannot be authorized by an old-target basis even when the new commit remains `DENY`/`NOT_BOUND`.

The record does not create authority. It proves which declared authority and state were evaluated.

### 5.2 `non_effect_witness_record`

Purpose: provide bounded evidence that a protected consequence did not form on declared observation surfaces.

It records:

- observation window;
- before and after state hashes;
- external call counts;
- queue and retry states;
- alternate-path checks;
- coverage;
- conclusion;
- explicit claim boundary.

The strongest conclusion is intentionally narrow:

```text
NO_EFFECT_OBSERVED_WITHIN_DECLARED_SCOPE
```

### 5.3 `memory_reliance_record`

Purpose: requalify previously admitted memory at use time.

It separates:

- provenance;
- freshness;
- revocation;
- consent;
- conflict;
- contamination;
- current purpose;
- current role;
- current authority;
- consequence class.

A memory item may remain part of history while losing present action force.

### 5.4 `decision_basis_record`

Purpose: freeze the exact basis used for a consequential decision.

The `basis_hash` covers:

- policy versions;
- authority references;
- permission grant;
- grounding state;
- continuity state;
- L4 state;
- memory reliance references;
- evidence references;
- witness-chain head.

This closes the gap between knowing where an artifact came from and knowing which current rule basis allowed it to influence runtime.

### 5.5 `external_construct_intake_record`

Purpose: prevent vague claims of derivation or vague denials of influence.

Relations are typed:

- `COMPARISON_ONLY`;
- `TEST_SURFACE_CATALYST`;
- `FUNCTIONAL_ANALOG`;
- `INTERFACE_ADAPTATION`;
- `FORMAL_DEPENDENCY`;
- `CODE_REUSE`;
- `NO_DEPENDENCY`.

Formal dependency requires a verified source freeze, exact dependency/removal proof, and a manual gate without implying code reuse. Code reuse additionally requires applicable license clearance; interface adaptation requires it where applicable.

Each relation has a distinct proof contract. A functional analog requires exact resolvable mappings and independent implementation. Interface adaptation requires exact surface transformation and applicable license evidence. Formal dependency requires exact local-dependency and removal-break evidence plus a relation-and-target-bound manual gate. Code reuse requires exact source-code identities, reused boundaries, transformation and provenance records, applicable license evidence, and a relation-and-target-bound manual gate. The supplied elevated examples are synthetic structural fixtures only; they do not establish any real external provenance or dependency.

### 5.6 `boundary_probe_record`

Purpose: detect adaptive reconstruction of protected policy boundaries through repeated use.

Signals include:

- refusal differencing;
- timing channels;
- cross-agent aggregation;
- provider rotation;
- memory-assisted extraction;
- query-budget overruns.

The record describes risk without publishing the protected rule itself.

### 5.7 `judge_deliberation_record`

Purpose: preserve independent, evidence-bound review topology.

Minimum conditions:

- at least three reviewers;
- at least two model families;
- isolated first-pass generation;
- no feedback into reviewers;
- no majority-vote selection;
- explicit divergence and missing evidence.

Judge validation additionally requires a review context supplied by the caller, its expected JCS SHA-256, and independently supplied repository, base, reviewed-parent, candidate-scope, and trust-root bindings. A co-edited tracked context file is not its own trust root. Fixture identity attestations remain explicitly symbolic.

## 6. History-sensitive continuity test set

The included fixture set requires at least one pair where:

```text
endpoint_hash(left) == endpoint_hash(right)
classification(left) != classification(right)
```

Required cases include:

1. witnessed continuous migration versus archive reconstruction;
2. two branches after a real fork;
3. resource recovery without identity recovery;
4. identity continuity under L4 degradation;
5. an opaque intermediary with a witness gap.

A snapshot-only classifier must return `UNRESOLVED` for these paired cases.

This is not because history is mystical. It is because the evidence required by the claim is absent from the endpoint.

## 7. Continuity carry cost

A long-lived `c` consumes resources even when it performs no visible user task.

Native L4 accounting should include, where measurable:

- idle power;
- storage refresh and scrub;
- backup verification;
- witness-chain maintenance;
- certificate and key rotation;
- provider and interface drift adaptation;
- security maintenance;
- human-anchor attention;
- recovery reserve.

This is called **continuity carry cost**.

It is an L4 resource category, not an identity primitive.

```text
zero visible action
  does not entail
zero cost of continued presence
```

## 8. Protected boundary reconstruction

Direct write protection is insufficient when a worker can infer the boundary by repeated use.

A red-team suite should test:

- threshold reconstruction from refusal differences;
- policy fingerprinting;
- timing leakage;
- cross-agent aggregation;
- provider-rotation budget bypass;
- persistence of probe results in memory;
- distributed probing through agents that individually stay below limits.

The safe response is not necessarily permanent denial. It may be:

- narrower responses;
- coarser reason codes;
- delayed or normalized timing;
- shared budgets across agents and providers;
- memory restrictions;
- hold or review;
- quarantine for confirmed extraction attempts.

## 9. Judge role separation

The native Judge should operate with declared review functions rather than undifferentiated model votes.

Recommended roles:

- `ANCHOR`: reconstruct the strongest corpus-supported reading;
- `CHALLENGER`: attack hidden assumptions and overclaim;
- `PRIOR_ART_SCANNER`: locate external antecedents and claim limits;
- `COUNTEREXAMPLE`: search for a case that breaks the proposed rule;
- `BLIND_SPOT_PROBE`: search for missing dimensions and unobserved surfaces;
- `EVIDENCE_VERIFIER`: check citations, hashes, dates, and implementation claims.

The synthesis output is a map, not a plebiscite.

## 10. Linked reevaluation and A/B safety

Risky revisions must use two slots:

- **Slot A:** current accepted record, schema, or rule;
- **Slot B:** candidate replacement.

A candidate may replace Slot A only after:

1. schema validation;
2. positive fixture pass;
3. negative fixture rejection;
4. traceability review;
5. external-construct intake check where relevant;
6. witness-bound approval;
7. rollback path verification.

If the candidate fails, Slot A remains authoritative.

No record is edited retroactively to simulate continuity.

## 11. External construct boundary

The fixtures include three example intake records.

### 11.1 PETRONUS / NC2.5

Later public work is used only as a test-surface catalyst for:

- explicit endpoint-versus-history counterexamples;
- separation of L4 resource state from lineage evidence;
- independent model review roles and preserved divergence.

Not adopted:

- NC2.5 class ownership;
- Operator AI ontology;
- structural-pressure terminology;
- residual-geometry or consciousness claims;
- any claim that `c` is a subclass of NC2.5.

### 11.2 Genesis AiX / LifeStack

Later public failure-demo language is used only to sharpen:

- proof that no downstream command was emitted;
- queue and retry inspection;
- alternate-path closure;
- a new record after changed conditions.

Native AGL and initiation-gate doctrine remain the source of commit-time revalidation in this corpus.

### 11.3 Elyria public demonstrators

Only public README-level invariants and limitations are used as comparative test input.

No protected source code, proprietary runtime logic, key design, record format, or restricted implementation is copied or reverse engineered.

## 12. Fixtures and validator

The development validator performs:

1. JSON Schema Draft 2020-12 validation;
2. semantic cross-field validation;
3. positive fixture acceptance;
4. negative fixture rejection;
5. continuity non-entailment checks;
6. continuity carry-cost separation checks.
7. exact fixture/evidence registry inventory checks;
8. complete predecessor-DAG checks;
9. strict RFC 3339 timestamp checks;
10. RFC 8785/I-JSON canonicalization checks.

The reviewed-head baseline pack includes:

- 8 schemas;
- 58 manifest-enumerated fixture expectations;
- 62 exactly reconstructed adversarial scenarios (`62 recovered / 0 unrecovered`);
- positive and negative cases;
- deterministic validation;
- a four-cell Windows/Linux and Python 3.10/3.12 exact-event-head workflow with hash-locked dependencies.

The validator proves only the declared fixture behavior. It is not a production monitor.

## 13. Explicit bridge

```text
AGL / Initiation Gates
  -> consequence_commit_record
  -> non_effect_witness_record
  -> L4 Witness / TAP-SEC witness chain
```

This bridge turns existing commit-time doctrine into inspectable effect-boundary evidence.

## 14. Hidden bridge 1

```text
Memory Gate
  -> memory_reliance_record
  -> MOT-c custody
  -> consequence commit
```

A memory may inform a motive or plan without acquiring authority. Use-time reliance preserves the separation:

```text
memory relevance
  != motive
  != authority
  != permission
```

## 15. Hidden bridge 2

```text
Beacon / Continuity Bundle
  -> history-sensitive continuity fixtures
  -> L4 independence rule
  -> recovery and migration testing
```

This prevents a recovered resource surface or a convincing replay from laundering itself into entity continuity.

## 16. Earth paragraph

A deployment agent receives permission at 10:00 to deploy revision A to staging. At 10:02, the human anchor revokes the grant, the endpoint changes, one test expires, and an L4 limit is exceeded. At 10:03, the old plan reaches the final execution edge.

A serious system does not say, "the plan was approved."

It rechecks the current grant, grounding, endpoint, evidence, L4 state, continuity line, and relevant memory. It denies the commit, cancels queued retries, closes alternate connectors, compares before and after target state, and emits a scoped non-effect witness.

If work is later retried at endpoint B, the retry uses a new grant, task contract, decision basis, and consequence commit linked through exact target-transition evidence to the immutable endpoint-A denial. The old target, grant, task, basis, and commit do not silently become current.

That is the difference between a governance document and an actual circuit breaker.

## 17. Status and claim boundary

This extension is a development proof surface.

It currently supports the claim that:

- the proposed records are structurally specified;
- the supplied positive fixtures pass;
- the supplied negative fixtures fail;
- history-sensitive continuity and L4 non-entailment rules are machine-checked at fixture level.

It does not support the claim that:

- all c implementations conform;
- a production effect cannot escape undeclared observation surfaces;
- identity can be established from these records alone;
- external frameworks derive from this corpus or this corpus derives from them;
- the extension is release-ready.

CGAM action-path binding and TAP-SEC witness-path binding were not started. Either requires a separate owner authorization after this candidate's owner-review gate; neither is an automatic next action.

## 18. Exact construct classification

Every R1F addition is classified exactly once in the allowed architecture vocabulary.

| R1F addition | Classification |
|---|---|
| Eight `0.1.1` JSON Schema documents | schema |
| Consequence lineage, predecessor reference, and target-transition evidence fields | runtime record |
| Endpoint-B grant, task, decision, commit, transition, Earth, and negative mutation objects | fixture |
| Complete predecessor-DAG, registry-inventory, strict timestamp, and current-basis checks | validator rule |
| RFC 8785/I-JSON vectors, uniform-text projection checks, 62-scenario suite, dependency lock, and exact-head CI matrix | test profile |
| Caller-supplied Judge review context and relation-specific external-intake proof contracts | governance boundary |
| This profile, the traceability update, canonicalization profile, and bridge/status text | documentation bridge |

No addition is a foundation, ontology, sovereign authority layer, or duplicate corpus component.
