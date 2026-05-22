# Claim-to-Evidence-and-Test Matrix v0.1

## `c = a + b` class claims, evidence surfaces, conformance tests, and maturity status

**Author:** Ivan Kotov  
**Date:** 2026-05-22  
**Status:** Draft control matrix v0.1  
**Layer:** `c = a + b` / L4 / SER / ARL / L4 Witness / `c[q]` / `ester-clean-code`  
**Document class:** claim registry / evidence matrix / anti-washing control artifact  
**Assertion class:** `C-A10` control-layer artifact

---

## 0. Executive definition

This matrix maps major public and technical claims about the `c = a + b` class to evidence, tests, runtime surfaces, and maturity status.

It exists to prevent two opposite errors:

```text
underclaiming: "this is only an attempt / only documents / only a chatbot skeleton"
overclaiming:  "the ecosystem is already externally validated and industrially mature"
```

The correct discipline is:

```text
claim
  -> definition source
  -> runtime surface
  -> test / fixture
  -> witness / evidence artifact
  -> maturity status
  -> remaining gap
```

---

## 1. Status vocabulary

| Status | Meaning |
|---|---|
| `DEFINED` | The concept/class/invariant is formally stated in the corpus. |
| `SPECIFIED` | Operational rules, fields, states, or conformance requirements are described. |
| `IMPLEMENTED-SKELETON` | A runtime surface or reference spine exists, but it is not yet industrially hardened. |
| `IMPLEMENTED-GATE` | A runtime gate blocks, holds, freezes, or routes at least one real path. |
| `TEST-SPECIFIED` | Test cases or conformance criteria are described. |
| `TESTED-LOCAL` | Local test/fixture/log evidence exists. |
| `EXTERNALLY-VALIDATED` | Independent audit, fork, deployment, or reviewer evidence exists. |
| `RESERVED` | Corpus recognizes the domain but intentionally avoids premature doctrine. |
| `GAP` | Missing or insufficiently connected layer. |

A claim may have several statuses at once:

```text
DEFINED + SPECIFIED + IMPLEMENTED-SKELETON + TEST-SPECIFIED
```

does not equal:

```text
EXTERNALLY-VALIDATED
```

---

## 2. Core claims matrix

| ID | Claim | Definition source | Runtime / artifact surface | Test / evidence surface | Current status | Remaining gap |
|---|---|---|---|---|---|---|
| `C-001` | `c = a + b` defines the origin of the class. | AGI v1.1 / parent protocol | `ester-clean-code` as executable skeleton; public corpus | DOI / GitHub release / corpus map | `DEFINED` | External adoption and citation growth. |
| `C-002` | `c` is not an agent, tool, oracle, or model instance. | SER / Beacon / Entity-governs-agents | Agent mesh boundaries, memory gate, runtime delegation | Direct-agent memory-write denial tests | `DEFINED`, `SPECIFIED`, `IMPLEMENTED-SKELETON` | Full conformance suite and independent replay. |
| `C-003` | L4 binds `c` to cost, time, energy, scarcity, risk, and irreversibility. | L4 Reality Boundary / L4 Witness / posts | Budget gates, network/offline gates, AB modes, resource policies | L4 budget exhaustion tests | `DEFINED`, `SPECIFIED`, `PARTIAL-IMPLEMENTATION` | Unified L4 Runtime Enforcement Profile and stress evidence. |
| `C-004` | `c[q]` means controlled non-collapse under uncertainty. | Qubit-State `c`; ARQ `c[q]`; CCDP child `c[q]` | Memory promotion gates, ambiguity markers, review paths | Non-collapse fixture: hypothesis must not become verified memory | `DEFINED`, `SPECIFIED` | Runtime-wide `c[q]` validator and drift tests. |
| `C-005` | Witness is a boundary/evidence system, not an autobiography. | L4 Witness / LHWAI / CCDP Witness | Hash chains, anchor packets, interpretation profiles | Anchor validation report; silent reinterpretation failure test | `DEFINED`, `SPECIFIED` | JSON schemas, validator CLI, implementation fixtures. |
| `C-006` | ARL handles disputes through standing, admissibility, freeze, quarantine, review, and re-entry. | ARL package / GTARL / CCDP | Freeze/hold/quarantine semantics; review route hooks | ARL freeze/re-entry test | `DEFINED`, `SPECIFIED` | Runtime replay evidence across multi-agent disputes. |
| `C-007` | Human Anchor `a` is origin and accountability source, not a magic eraser. | ARL Evidence/Standing; Decision Outcomes; Pre-Lineage; Continuity Bundle | Anchor standing, post-anchor reserved domain, continuity challenge | Human-anchor drift scenario tests | `DEFINED`, `DISTRIBUTED-SPECIFIED` | Consolidated Human Anchor Drift Profile and test pack. |
| `C-008` | Memory is governed by class, status, provenance, uncertainty, and witnessability. | Memory Map / CMAM / Continuity Bundle / CLI Agent Mesh | JSON/Chroma/cards plus memory gate, class inventory, witness refs | Memory promotion / compaction / quarantine tests | `SPECIFIED`, `IMPLEMENTED-SKELETON` | Memory Continuity and Semantic Drift runtime profile. |
| `C-009` | Child-facing `c` must signal state, not content. | CCDP / Soft Safety / CMAM / Red-Black | State-signal schema, minimal disclosure, sealed zones | CCDP conformance tests | `DEFINED`, `SPECIFIED` | Specialist review / jurisdictional annex / implementation fixtures. |
| `C-010` | `ester-clean-code` is a cleaned executable skeleton of `c`, not the whole theory. | Public repo / manifest / package docs | Source tree, routes, memory, agent, witness, L4-related modules | Smoke tests / 90-day evidence pack | `IMPLEMENTED-SKELETON` | Hardened runtime, external audit, long-run logs. |

---

## 3. Claim maturity distinction

A critic may correctly say:

```text
this implementation is early
this ecosystem is not externally validated
this requires years of long-term evidence
```

A critic may not correctly infer:

```text
the class is only an attempt
there is no class definition
there is no architecture
there is only JSON + Chroma
there is only documents
```

unless they identify the missing invariant or failing path.

---

## 4. Evidence classes

| Evidence class | Meaning | Examples |
|---|---|---|
| `EV-DOC` | normative or architectural document | protocol, profile, matrix |
| `EV-DOI` | frozen archival/public object | Zenodo DOI, release asset |
| `EV-HASH` | integrity evidence | SHA256SUMS, signed tag, anchor packet |
| `EV-CODE` | runtime source surface | module, route, listener, gate |
| `EV-CONFIG` | inspectable runtime configuration | policy yaml, budget config, AB mode |
| `EV-TEST` | local test or fixture | unit test, conformance fixture |
| `EV-WITNESS` | witness-compatible event | chain event, anchor, validation report |
| `EV-AUDIT` | independent review | external audit, fork report, reproducible run |
| `EV-DEPLOY` | long-running deployment proof | 90-day/180-day continuity pack |

---

## 5. Minimum reviewer rule

A reviewer challenging a claim SHOULD provide:

```text
claim_id
criticized assertion
searched documents
searched runtime surfaces
missing invariant or failing path
test case or counterexample
classification: conceptual absence / packaging gap / implementation gap / validation gap
```

A criticism without this structure is not invalid, but it remains a heuristic red-team signal rather than a technical finding.

---

## 6. Red-line overclaim failures

The corpus or its defenders MUST NOT claim:

1. industrial maturity without deployment evidence;
2. external validation without external validators;
3. full L4 hard enforcement without unified governor tests;
4. memory stability without drift tests;
5. witness long-horizon conformance without anchors and validation reports;
6. child-safety deployment without specialist and jurisdictional review;
7. legal or clinical authority where the corpus only defines protocol handoff.

---

## 7. Bridge set

### Explicit bridge

The matrix links abstract class claims to runtime and evidence. It preserves `c = a + b` as origin while preventing the code skeleton, documents, or public posts from being mistaken for the whole class alone.

### Quiet bridge I — cybernetics

A system cannot regulate what it cannot distinguish. The matrix distinguishes definition, specification, runtime, test, witness, and external validation so critique can land at the correct control layer.

### Quiet bridge II — information theory

A claim gains useful entropy only when it points to verifiable artifacts. Otherwise, both praise and criticism become noisy narrative.

### Earth paragraph

A building claim is not accepted because someone says “strong structure.” It points to drawings, steel size, concrete batch, inspection note, and load test. This matrix is the structural inspection sheet for the `c` corpus.

---

## 8. Next actions

1. Maintain this matrix during every hardening release.
2. Add exact repo paths and test IDs after Codex extraction.
3. Link each high-impact public claim to a row in this matrix.
4. Refuse both hype and dismissal when evidence class is lower than the claim requires.
