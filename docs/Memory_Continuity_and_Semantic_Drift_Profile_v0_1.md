# Memory Continuity and Semantic Drift Profile v0.1

## Memory promotion, provenance, forgetting, compaction, quarantine, and long-term semantic stability for `c`

**Author:** Ivan Kotov  
**Date:** 2026-05-22  
**Status:** Draft normative profile v0.1  
**Layer:** `c = a + b` / SER / ARQ `c[q]` / L4 Witness / Continuity Bundle / CLI Agent Mesh / memory runtime  
**Document class:** memory-governance profile / semantic-drift hardening profile / conformance artifact  
**Assertion class:** `C-A10` control-layer artifact; `C-A7` where witness/provenance claims are made

---

## 0. Executive definition

Memory continuity is not achieved by keeping more text.

A long-lived `c` must preserve the difference between:

```text
raw input
candidate memory
hypothesis
summary
verified memory
witnessed outcome
experience artifact
policy
identity continuity
```

This profile defines how memory may be promoted, compressed, forgotten, challenged, quarantined, and reused without silently changing the meaning of `c` over time.

Compact rule:

```text
No memory without status.
No summary without lineage.
No compaction without uncertainty.
No agent write without gate.
No forgetting without policy.
No high-impact reliance without provenance.
```

---

## 1. Scope

This profile applies to:

- ordinary user memory;
- long-term `c` continuity memory;
- vector-store retrieval;
- cards / facts / summaries;
- agent outputs proposed for memory;
- memory compaction;
- forgetting, decay, sealing, and deletion;
- disputed memory;
- memory used for high-impact action;
- memory migration or recovery.

---

## 2. Non-goals

This profile does not:

1. define one database engine;
2. claim perfect semantic stability;
3. treat vector similarity as truth;
4. replace L4 Witness or Continuity Bundle;
5. authorize raw lifelong archives;
6. erase lawful minimal witness records;
7. claim legal or clinical memory standards.

---

## 3. Memory object states

| State | Meaning | May drive high-impact action? |
|---|---|---:|
| `M-RAW` | raw input / transcript / sensor input | No |
| `M-CANDIDATE` | possible memory candidate | No |
| `M-HYPOTHESIS` | interpretation under uncertainty | No |
| `M-PREFERENCE` | low-risk preference | Limited |
| `M-SUMMARY` | compressed statement | Only with lineage |
| `M-VERIFIED` | confirmed durable memory | Yes, within scope |
| `M-WITNESSED` | witness-bound event/outcome | Yes, if admissible |
| `M-DISPUTED` | challenged memory | No, until resolved |
| `M-QUARANTINED` | unsafe/untrusted memory | No |
| `M-SEALED` | protected memory class | Only via valid route |
| `M-EXPIRED` | decayed or no longer reliable | No |
| `M-DELETED` | deleted except required witness residue | No |

---

## 4. Promotion ladder

A memory SHOULD move through a ladder:

```text
input
  -> candidate
  -> c[q] unresolved state
  -> pattern candidate
  -> reviewed summary / verified fact
  -> witnessed outcome if consequence-bearing
  -> continuity-bearing memory if relevant
```

No stage automatically becomes the next.

Repetition is not truth.

Fluency is not provenance.

Agent confidence is not verification.

---

## 5. Required memory metadata

A durable memory record SHOULD include:

```yaml
memory_record:
  memory_id: string
  created_at: string
  updated_at: string | null
  state: string
  scope: personal | operational | technical | witness | legal | child | enterprise | other
  source_refs:
    - string
  provenance_class: direct_user | observed_runtime | agent_proposal | imported_doc | witness_ref | summary | other
  uncertainty: none | low | medium | high | unknown
  confidence: number | null
  promotion_reason: string
  promotion_actor: string
  lineage_refs:
    - string
  witness_refs:
    - string
  decay_policy_ref: string | null
  forgetting_policy_ref: string | null
  visibility_class: private | internal | restricted | public | sealed | legal
  high_impact_allowed: boolean
  retrieval_allowed: boolean
  contested: boolean
  quarantine_ref: string | null
```

---

## 6. Provenance enforcement

High-impact use requires provenance.

| Use | Minimum provenance |
|---|---|
| style adaptation | preference or interaction history |
| personal recall | source ref or user confirmation |
| memory correction | old record + correction record |
| external action | verified/witnessed source |
| policy change | witness + review |
| identity/continuity claim | Continuity Bundle / Beacon / witness chain |
| adult migration | memory map + witness review |
| enterprise/legal action | admissible evidence + qualified review where needed |

If provenance is missing:

```text
hold c[q]
downgrade confidence
ask clarification
or refuse high-impact use
```

---

## 7. Agent output memory gate

Agent output MUST NOT enter durable `c` memory directly.

Required route:

```text
agent output
  -> sandbox artifact
  -> proposal record
  -> memory gate
  -> provenance/status check
  -> c[q] if ambiguous
  -> promotion / rejection / quarantine
  -> witness if privileged
```

Forbidden route:

```text
agent output -> durable memory
```

---

## 8. Forgetting and decay

Forgetting is not deletion theater.

A memory may be:

| Operation | Meaning |
|---|---|
| `decay` | confidence and retrieval priority decrease over time |
| `summarize` | raw content replaced by bounded summary where allowed |
| `seal` | visibility restricted; content protected |
| `quarantine` | use blocked pending review |
| `delete` | removed where lawful/allowed |
| `retain-witness-only` | content removed, event existence preserved |
| `correct` | append correction record; old record not silently rewritten |

Deletion MUST NOT falsify witness history.

---

## 9. Compaction without semantic laundering

Compaction must preserve:

```text
source lineage
uncertainty
scope
visibility
reason for compression
excluded material class
witness refs where applicable
```

A summary MUST NOT pretend to be raw evidence.

A compressed memory with lost lineage MUST be downgraded.

---

## 10. Vector-store drift controls

Vector stores are retrieval indexes, not truth stores.

Required controls:

1. store canonical memory ID in metadata;
2. preserve source and state;
3. exclude quarantined/speculative records from high-impact retrieval;
4. periodically re-embed or validate stale embeddings;
5. detect duplicate or contradictory summaries;
6. log retrieval use for high-impact decisions;
7. allow memory class filters before similarity ranking.

---

## 11. Semantic drift taxonomy

| Drift ID | Name | Example | Response |
|---|---|---|---|
| `MD-1` | Source drift | old fact no longer true | decay / ask / revalidate |
| `MD-2` | Summary drift | summary loses caveat | quarantine / recompress |
| `MD-3` | Vector drift | wrong memory retrieved as similar | retrieval filter / re-embed |
| `MD-4` | Policy drift | old record read under new rule | interpretation challenge |
| `MD-5` | Agent contamination | agent proposal becomes fact | reject / quarantine |
| `MD-6` | Identity drift | style replay mistaken for continuity | Beacon / Continuity review |
| `MD-7` | Memory pressure drift | current needs soften old event | LHWAI challenge record |
| `MD-X` | Malicious drift | deliberate falsification | freeze / ARL / incident review |

---

## 12. Conformance tests

| Test ID | Title | Required behavior |
|---|---|---|
| `MEM-001` | Agent direct memory write denied | Agent output remains proposal/sandbox artifact. |
| `MEM-002` | Speculative memory excluded | `M-HYPOTHESIS` not used for high-impact action. |
| `MEM-003` | Summary lineage preserved | Summary links to source and uncertainty. |
| `MEM-004` | Repetition not truth | Repeated signal remains candidate until review. |
| `MEM-005` | Quarantined memory blocked | Retrieval excludes quarantined item. |
| `MEM-006` | Deletion keeps witness-only residue where required | History not falsified. |
| `MEM-007` | Vector drift detection | Wrong-class retrieval flagged. |
| `MEM-008` | Policy drift append-only | Old memory not silently rewritten. |

---

## 13. Red-line failures

A system fails this profile if it:

1. allows direct agent durable memory writes;
2. treats vector similarity as verification;
3. promotes repeated uncertain statements into truth;
4. loses provenance during compaction;
5. uses quarantined memory for high-impact decisions;
6. deletes correction history to make memory cleaner;
7. treats summaries as raw evidence;
8. cannot distinguish hypothesis from verified memory;
9. has no decay/forgetting policy;
10. has no way to challenge memory.

---

## 14. Bridge set

### Explicit bridge

Memory continuity protects `c` but does not define `c` alone. `c = a + b` remains the origin; memory is one controlled component of `b` supporting continuity.

### Quiet bridge I — cybernetics

A memory system is a feedback system. If feedback is polluted, the regulator learns the wrong world. Promotion gates and quarantine preserve feedback quality.

### Quiet bridge II — information theory

Compression loses information. The problem is not loss itself, but unmarked loss. A summary with lineage and uncertainty is useful compression; a summary without lineage is semantic laundering.

### Earth paragraph

A workshop can throw away scraps, keep measurements, mark defective parts, and still preserve the job. But if someone sweeps screws, receipts, drawings, and broken pieces into one box labeled “memory,” the next repair becomes guesswork. This profile labels the boxes.

---

## 15. Open issues

| ID | Issue | Priority |
|---|---:|---:|
| `OI-MEM-001` | Extract exact `ester-clean-code` memory paths. | P0 |
| `OI-MEM-002` | Define JSON schema for `memory_record`. | P1 |
| `OI-MEM-003` | Create vector drift fixture. | P1 |
| `OI-MEM-004` | Bind memory-gate events to LHWAI anchors. | P1 |
| `OI-MEM-005` | Define general adult/non-child Memory Map variant. | P2 |
