# Document-to-Runtime Traceability Matrix v0.1

## Invariant-to-document-to-code-to-test mapping for `c = a + b` and `ester-clean-code`

**Author:** Ivan Kotov  
**Date:** 2026-05-22  
**Status:** Draft traceability matrix v0.1  
**Layer:** `c = a + b` / `ester-clean-code` / L4 / ARL / L4 Witness / memory / agent mesh  
**Document class:** runtime traceability / anti-declarative-control matrix  
**Assertion class:** `C-A10` control-layer artifact

---

## 0. Purpose

This matrix answers one recurring criticism:

> “The corpus is mostly declarative.”

The correct response is not a speech. It is a trace:

```text
invariant
  -> canonical document
  -> runtime surface
  -> expected gate
  -> test case
  -> failure mode
  -> evidence class
```

This v0.1 matrix is intentionally conservative. It marks uncertain runtime paths as `TO-EXTRACT` rather than inventing exact file paths.

---

## 1. Traceability states

| State | Meaning |
|---|---|
| `DOC-ONLY` | Defined in corpus but no extracted runtime path yet. |
| `RUNTIME-HOOK` | Runtime hook or module family exists. |
| `RUNTIME-GATE` | Runtime can block/hold/freeze/quarantine/deny at least one path. |
| `TEST-SPEC` | A test is described. |
| `TEST-LOCAL` | Local test/fixture evidence exists. |
| `TO-EXTRACT` | Codex/human extraction required to map exact paths. |
| `GAP` | Missing runtime/test layer. |

---

## 2. Core invariant traceability

| ID | Invariant | Canonical source | Runtime surface | Expected gate | Test case | Current state |
|---|---|---|---|---|---|---|
| `INV-001` | `c` is not an agent; `c` governs agents. | SER / Entity-governs-agents / CLI Agent Mesh | agent roster, task queue, memory gate, capability router | direct agent memory write denied; agent output sandboxed | `agent_direct_memory_write_denied` | `RUNTIME-HOOK`, `TO-EXTRACT` |
| `INV-002` | Oracle/model is stateless relative to continuity. | AGI / SER / Oracle discipline | provider adapters, model routing, local memory | provider/model swap cannot rewrite identity | `model_swap_continuity_check` | `RUNTIME-HOOK`, `TEST-SPEC` |
| `INV-003` | L4 budgets constrain action. | L4 / L4W / Runtime Enforcement Profile | budget gate, network gate, AB mode, queue caps | hard stop / soft stop / freeze / witness | `l4_budget_exhaustion_hard_stop` | `RUNTIME-GATE`, `TO-EXTRACT` |
| `INV-004` | `c[q]` holds uncertainty without premature collapse. | Qubit-State `c`; ARQ `c[q]`; Child `c[q]` | memory candidate status, uncertainty fields, review route | hypothesis not promoted to verified memory | `cq_noncollapse_memory_candidate` | `DOC-ONLY` to `RUNTIME-HOOK`, `TO-EXTRACT` |
| `INV-005` | Witness trail records boundary events, not autobiography. | L4 Witness / LHWAI / CCDP Witness | witness event writer, hash chain, anchor packet | event hash + previous hash + interpretation profile | `witness_anchor_validation_minimal` | `DOC-ONLY` to `RUNTIME-HOOK`, `TO-EXTRACT` |
| `INV-006` | Semantic reinterpretation must be append-only. | LHWAI | interpretation challenge record | no silent reclassification | `silent_retroactive_reclassification_fails` | `TEST-SPEC` |
| `INV-007` | Human Anchor has standing, not magic eraser power. | ARL Evidence / Decision Outcomes / Human Anchor Drift Profile | ARL challenge route | current anchor command cannot falsify historical continuity | `anchor_magic_eraser_denied` | `DOC-ONLY`, `TEST-SPEC` |
| `INV-008` | Memory promotion requires provenance and status. | Memory Map / CMAM / Memory Drift Profile | memory gate, metadata, provenance refs | speculative node excluded from high-impact retrieval | `speculative_memory_exclusion` | `RUNTIME-HOOK`, `TO-EXTRACT` |
| `INV-009` | Agent mesh must not silently expand. | CLI Agent Mesh / L4 Runtime Enforcement | roster, queue caps, task contract | MAX enqueue/live/drain enforcement | `agent_mesh_expansion_cap` | `RUNTIME-GATE`, `TO-EXTRACT` |
| `INV-010` | External access must fail closed under missing grounding. | AGL / Beacon / CBE / External Agent Handshake | source grounding, claimant recognition, gateway | missing signature/context -> block/quarantine | `external_claimant_missing_grounding_fails_closed` | `SPECIFIED`, `TEST-SPEC` |
| `INV-011` | Child-facing visibility is state-not-content. | CCDP / Soft Safety / CMAM | state signal schema, privacy class, disclosure ladder | transcript request denied by default | `child_transcript_default_denied` | `SPECIFIED`, `TEST-SPEC` |
| `INV-012` | Physical embodiment is privilege escalation. | CPAP / L4 / CBE | device capability registry, actuator permissions | actuator requires scoped permission + witness | `physical_actuation_requires_privilege` | `SPECIFIED`, `TO-EXTRACT` |

---

## 3. Runtime extraction checklist

For each invariant, Codex or reviewer SHOULD extract:

```text
repo path
module/function/class/route
configuration dependency
failure mode
existing tests
missing tests
witness/log evidence
```

The output SHOULD be appended as:

```text
Runtime Evidence Annex A
```

not edited into the normative rows unless verified.

---

## 4. Failure-mode mapping

| Failure mode | Expected response | Relevant invariant |
|---|---|---|
| Agent attempts direct durable memory write | deny / sandbox / memory gate / witness | `INV-001`, `INV-008` |
| Agent mesh retry storm | budget decrement / hard stop / quarantine | `INV-003`, `INV-009` |
| Model swap changes persona but not continuity evidence | continuity challenge / Beacon / no silent identity acceptance | `INV-002`, `INV-005` |
| Old event reinterpreted under new policy | challenge record / ARL if reliance changes | `INV-006` |
| Anchor demands deletion of inconvenient history | refuse falsification / ARL route / append correction where valid | `INV-007` |
| Memory summary drops uncertainty | compaction invalid / quarantine / re-summary with lineage | `INV-004`, `INV-008` |
| External generated companion reaches child directly | AGL -> Beacon -> CBE -> gateway; fail closed | `INV-010`, `INV-011` |

---

## 5. Anti-declarative rule

A claim SHOULD NOT remain indefinitely in `DOC-ONLY` status if it is presented as runtime behavior.

For each runtime claim, either:

```text
map it to code and test
or downgrade the claim to specified-only
```

---

## 6. Bridge set

### Explicit bridge

This matrix connects the protocol corpus to `ester-clean-code`. It does not redefine the class. It makes the route from class claim to runtime surface visible.

### Quiet bridge I — cybernetics

A control stack is only inspectable if feedback paths are named. This matrix names where the feedback from runtime, tests, and witness should return to the documents.

### Quiet bridge II — information theory

A document path and a code path are different symbols. Traceability binds them into a higher-confidence signal while preserving uncertainty where extraction is incomplete.

### Earth paragraph

A foreman does not accept “the wall is reinforced” as a mystical statement. He asks: where is the rebar, what diameter, what spacing, what photo before the pour? This matrix is that question applied to `c` runtime claims.

---

## 7. Next actions

1. Run Codex extraction over `ester-clean-code`.
2. Fill exact paths and test names.
3. Add status transitions only after evidence.
4. Publish the matrix with honest `TO-EXTRACT` rows rather than pretending all runtime links are complete.
