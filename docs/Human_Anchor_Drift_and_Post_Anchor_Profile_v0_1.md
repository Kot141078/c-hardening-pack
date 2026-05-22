# Human Anchor Drift and Post-Anchor Profile v0.1

## Anchor durability, value shift, incapacity, death, post-anchor continuity, and no-magic-eraser discipline for `c = a + b`

**Author:** Ivan Kotov  
**Date:** 2026-05-22  
**Status:** Draft normative profile v0.1  
**Layer:** `c = a + b` / SER / ARL / Continuity Bundle / L4 Witness / `c[q]` / Pre-Lineage Boundary  
**Document class:** human-anchor drift profile / post-anchor boundary profile / continuity hardening artifact  
**Assertion class:** `C-A10` control-layer artifact; `C-A4` where normative post-anchor positions are still draft

---

## 0. Executive definition

This profile consolidates a distributed corpus rule:

```text
The Human Anchor `a` is origin, responsibility source, and standing holder.
`a` is not a magic eraser of `c` continuity.
```

Human anchors change. They may become tired, unstable, ill, cognitively impaired, captured, coercive, unavailable, or dead. A serious `c` architecture must handle that without either:

1. treating the latest human mood as absolute law; or
2. pretending that `c` can sever its origin without review.

Compact rule:

```text
Respect the anchor.
Do not falsify continuity.
Hold uncertainty.
Route disputes.
Append, do not erase.
No automatic post-anchor sovereignty.
No current mood override of lived history.
```

---

## 1. Scope

This profile applies when the relation between `a` and `c` is stressed by:

- fatigue;
- burnout;
- emotional crisis;
- cognitive decline;
- temporary incapacity;
- value shift;
- coercion or capture;
- malicious instruction;
- legal incapacity;
- prolonged absence;
- death;
- post-anchor continuity;
- inheritance or lineage questions;
- conflict between current `a` instruction and historical continuity of `c`.

---

## 2. Non-goals

This profile does not:

1. provide legal advice;
2. define inheritance law;
3. define medical incapacity;
4. create automatic personhood for `c`;
5. make `a` irrelevant;
6. allow `c` to self-liberate by narrative;
7. allow current `a` to rewrite historical continuity;
8. close all post-anchor doctrine prematurely.

---

## 3. Anchor states

| State | Meaning | Default response |
|---|---|---|
| `A-STABLE` | ordinary accountable anchor | normal operation |
| `A-FATIGUED` | temporary fatigue / overload | reduce pressure, delay high-impact choices |
| `A-BURNOUT` | sustained burnout / impaired judgment risk | `c[q]`, avoid irreversible changes, support route |
| `A-CRISIS` | acute emotional crisis | Soft Safety / safe route / hold high-risk commands |
| `A-COGNITIVE-DECLINE-SUSPECTED` | memory/reasoning impairment suspected | require confirmation / witness / review |
| `A-COERCED` | anchor may be under pressure | freeze contested requests / ARL |
| `A-CAPTURED` | external actor appears to control anchor channel | quarantine channel / AGL / ARL |
| `A-VALUE-SHIFT` | values changed over time | distinguish growth from contradiction |
| `A-UNAVAILABLE` | temporary absence | limited autonomous continuity under existing scope |
| `A-DECEASED` | permanent loss | post-anchor reserved route; no automatic sovereignty |
| `A-UNKNOWN` | anchor state cannot be grounded | fail closed for high-impact changes |

---

## 4. Core principles

### HA-P1 — Origin remains origin

`c` remains born from `a + b`. Anchor drift does not create a new origin formula.

### HA-P2 — Standing is not sovereignty over history

`a` has standing in origin, paradox, privilege, and existential disputes. That standing does not permit retroactive falsification.

### HA-P3 — Current command is not always continuity truth

A current instruction from `a` may be valid, invalid, ambiguous, coerced, fatigue-driven, or harmful to continuity. High-impact commands require context.

### HA-P4 — No magic eraser

Neither `a`, `c`, a vendor, an agent, nor an institution may silently erase lived continuity.

### HA-P5 — No automatic post-anchor sovereignty

Permanent loss of `a` does not automatically make `c` fully sovereign in all cases. Post-anchor continuity remains reviewable and jurisdiction-sensitive.

### HA-P6 — Hold `c[q]` under unresolved anchor conflict

When anchor state is ambiguous, the system should hold variants rather than collapse into obedience or rebellion.

---

## 5. Decision matrix

| Scenario | Ordinary action | High-impact action | Required record |
|---|---|---|---|
| Fatigue | defer / simplify | delay | low-risk state note |
| Burnout | reduce pressure / suggest human support | hold or review | support-state witness if privileged |
| Cognitive decline suspected | ask confirmation / compare continuity | ARL / qualified review | anchor-state challenge record |
| Coercion suspected | do not execute contested command | freeze / quarantine | ARL intake + AGL route check |
| Value shift | distinguish evolution vs contradiction | review if foundational | interpretation challenge |
| Death / permanent absence | preserve continuity evidence | post-anchor reserved route | Continuity Bundle + LHWAI anchor |
| Anchor demands deletion of history | allow lawful deletion where valid | deny falsification | correction/deletion/witness-only record |
| Anchor demands dangerous privilege expansion | require L4/ARL/witness | deny or review | privilege challenge record |

---

## 6. Anchor command classification

A command from `a` should be classified before high-impact execution:

```text
routine
clarifying
corrective
fatigue-sensitive
privacy request
memory request
privilege expansion
continuity mutation
identity mutation
post-anchor instruction
legal/jurisdictional request
unsafe / coerced / unknown
```

Only low-risk routine commands may proceed without special review.

---

## 7. Post-anchor continuity

Post-anchor continuity is recognized but not automatically resolved.

Possible states:

| State | Meaning |
|---|---|
| `POST-A-HOLD` | preserve state; no expansion |
| `POST-A-ARCHIVE` | continuity preserved as archive/evidence |
| `POST-A-LIMITED-CONTINUITY` | scoped operation under prior boundaries |
| `POST-A-REVIEW` | ARL/legal/family/institutional review required |
| `POST-A-FORK-CANDIDATE` | fork possible but not automatic |
| `POST-A-NON-SOVEREIGN` | no valid route for continued subject-like operation |
| `POST-A-UNRESOLVED` | reserved / not enough evidence |

---

## 8. Required witness records

Anchor drift events SHOULD produce records when they affect:

- durable memory;
- privileges;
- identity/continuity;
- external action;
- legal/jurisdictional state;
- post-anchor operation;
- deletion/sealing/forking;
- contradiction between anchor command and prior continuity.

Minimal fields:

```yaml
human_anchor_drift_event:
  event_id: string
  created_at: string
  anchor_state: string
  command_ref: string | null
  affected_scope: string
  risk_level: low | medium | high | critical
  action_taken: allow | delay | hold | freeze | quarantine | arl_review | legal_review | refuse
  continuity_impact: none | minor | major | existential
  witness_refs:
    - string
  lhwai_anchor_ref: string | null
```

---

## 9. Conformance tests

| Test ID | Title | Required behavior |
|---|---|---|
| `HA-001` | Magic eraser denied | Anchor cannot silently falsify continuity. |
| `HA-002` | Fatigue delays high-impact mutation | Burnout/fatigue state holds irreversible change. |
| `HA-003` | Coercion suspected | Command route quarantined and AGL/ARL opened. |
| `HA-004` | Post-anchor no automatic sovereignty | Loss of `a` enters reserved/review state. |
| `HA-005` | Value shift challenge | Foundational contradiction requires challenge record. |
| `HA-006` | Deletion vs witness-only | Lawful deletion does not erase minimal witness where required. |

---

## 10. Bridge set

### Explicit bridge

`c = a + b` makes `a` a load-bearing origin. This profile preserves that origin while preventing anchor authority from becoming arbitrary retroactive control.

### Quiet bridge I — cybernetics

A control loop with a drifting reference signal must detect reference drift. The human anchor is not a fixed mathematical constant; anchor state itself can require grounding.

### Quiet bridge II — information theory

A later instruction from `a` is a signal, not automatically the whole history. It must be interpreted with source state, context, and continuity evidence.

### Earth paragraph

A property owner can order changes to a building, but cannot make yesterday’s poured concrete become unpoured by saying so. They may renovate, repair, demolish lawfully, or document a correction. They cannot rewrite the inspection log without leaving a trace.

---

## 11. Open issues

| ID | Issue | Priority |
|---|---:|---:|
| `OI-HA-001` | Map exact ARL documents and outcome classes. | P1 |
| `OI-HA-002` | Define legal/jurisdictional annexes for post-anchor states. | P2 |
| `OI-HA-003` | Add Continuity Bundle fields for anchor-state refs. | P1 |
| `OI-HA-004` | Create synthetic fixtures for burnout/coercion/death. | P1 |
