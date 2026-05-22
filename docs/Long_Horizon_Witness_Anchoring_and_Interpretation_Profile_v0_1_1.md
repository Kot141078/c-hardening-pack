# Long-Horizon Witness Anchoring and Interpretation Profile v0.1.1

## Periodic anchoring, semantic freeze, interpretation discipline, external commitments, and long-term auditability for L4 Witness trails

**Status:** Draft normative profile v0.1.1  
**Date:** 2026-05-21  
**Patch note:** v0.1.1 strengthens explicit linkage among hash-chain, Merkle / external anchors, key rotation, ARL challenge / resolution, compromised sub-agent quarantine, semantic reinterpretation, audit replay, and retention / pruning.  
**Layer:** `c = a + b` / SER / SER-FED / L4 Witness / ARL / Continuity Bundle / CLI Agent Mesh / CCDP / Long-Horizon Audit  
**Document class:** witness-anchoring profile / interpretation-control profile / evidence-hygiene companion  
**Assertion class:** `C-A10` control-layer artifact; `C-A7` where hash, signature, timestamp, canonicalization, or external commitment claims are made  
**Primary object family:** `LONG_HORIZON_WITNESS_ANCHOR_PACKET`, `WITNESS_INTERPRETATION_PROFILE`, `WITNESS_EPOCH_DIGEST`, `WITNESS_INTERPRETATION_CHALLENGE_RECORD`, `WITNESS_ANCHOR_VALIDATION_REPORT`  
**Canonical schema version:** `long-horizon-witness-anchoring-interpretation-0.1.1`  
**Primary subject:** long-lived `c` entities, child/adult `c` profiles, enterprise/work-bound `c`, and `c`-governed agent meshes whose witness trails persist across months, years, migrations, model changes, or jurisdictional handoffs  
**Primary boundary:** a witness trail must remain both tamper-evident and interpretation-stable over time. Hashes prove that bytes did not silently change; they do not, by themselves, prove that later readers are allowed to reinterpret the old record under new semantics.

---

## 0. Executive definition

**Long-Horizon Witness Anchoring and Interpretation Profile (LHWAI)** defines how L4 Witness-compatible trails should be periodically anchored, summarized, preserved, revalidated, and interpreted over long time horizons.

It closes a specific gap:

```text
A witness trail can be cryptographically intact
and still become unsafe
if later systems reinterpret old records under new semantics.
```

This profile therefore separates two different failure classes:

| Failure class | Question | Control surface |
|---|---|---|
| Tamper failure | Did the record, chain, or digest change? | hash, signature, append-only chain, external commitment |
| Interpretation failure | Did the meaning of the record change retroactively? | schema version, policy version, reason-code registry, interpretation profile, challenge record |

Compact formula:

```text
Anchor the bytes.
Freeze the semantics.
Append reinterpretations.
Do not rewrite history.
```

A long-lived `c` must be able to ask, years later:

1. What event was recorded?
2. Which schema and policy made it meaningful at that time?
3. Which interpreter profile was allowed to read it?
4. Which later changes altered interpretation rules?
5. Which external commitments prove the chain existed before later disputes?
6. Which raw evidence, if any, existed outside the witness body?
7. Which parts may be read, challenged, sealed, redacted, or ignored now?

If those questions cannot be answered, the trail may still be a log.

It is not yet a long-horizon witness system.

---

## 0.1 Required relationship chain

This profile is explicitly built around the following chain:

```text
hash-chain
  -> Merkle / segment / epoch roots
  -> external anchors
  -> key epochs and key rotation
  -> ARL challenge / resolution
  -> compromised sub-agent quarantine
  -> semantic reinterpretation rules
  -> audit replay
  -> retention / pruning
```

The chain is directional but not strictly linear. A later stage may force a return to an earlier stage.

Examples:

- a compromised sub-agent may force immediate re-anchoring of the current chain head;
- a key-rotation failure may force ARL review before reliance continues;
- an audit replay may reveal missing Merkle inclusion proofs;
- a retention / pruning action may require a new anchor packet proving what was retained, pruned, summarized, sealed, or legally held.

### 0.1.1 Linkage matrix

| Link | Required binding | Failure if missing |
|---|---|---|
| hash-chain -> Merkle / epoch roots | each event hash must be included in a segment / Merkle / epoch manifest | individual events cannot be reconstructed or inclusion-proved |
| Merkle / epoch roots -> external anchors | epoch root or anchor packet hash must be committed outside mutable local state where LHWAI-4+ is claimed | local history can be rewritten before audit |
| external anchors -> key rotation | key epoch must be visible in the anchor packet and validation report | old signatures become orphaned or falsely reset |
| key rotation -> ARL challenge / resolution | disputed key epochs require review, standing, outcome, and re-entry state | key compromise becomes invisible continuity drift |
| ARL challenge / resolution -> quarantine | affected events, agents, keys, memories, or interpretations must be held / frozen / quarantined until outcome | contested material continues to influence the system |
| quarantine -> semantic reinterpretation | quarantine may suspend reliance but must not rewrite original event meaning | quarantine becomes covert deletion or blame laundering |
| semantic reinterpretation -> audit replay | replay must test both byte integrity and interpretation profile integrity | replay proves only that bytes exist, not that they are read correctly |
| audit replay -> retention / pruning | replay results determine which objects may be retained, sealed, summarized, pruned, or legally held | pruning destroys auditability or retention becomes surveillance |

### 0.1.2 Minimal complete implementation

A minimally complete LHWAI implementation MUST demonstrate all of the following in one audit path:

```text
1. event hash chain exists;
2. event inclusion in segment / Merkle / epoch digest is provable;
3. epoch digest is bound into an anchor packet;
4. anchor packet declares key epoch and interpretation profile;
5. anchor packet has local or external commitment according to claimed level;
6. key rotation or compromise opens a witnessed transition;
7. ARL challenge / resolution can attach to affected anchors;
8. compromised sub-agent cannot self-clear;
9. reinterpretation is append-only;
10. audit replay can reproduce inclusion, validation, and reading mode;
11. retention / pruning emits a witness-preserving decision record.
```

If any one of these steps is absent, the system may still have useful logs.

It MUST NOT claim full long-horizon witness anchoring and interpretation conformance.

---

## 1. Purpose

This profile exists because long-lived `c` systems do not fail only through dramatic tampering.

They fail through quieter mechanisms:

- chain heads that are never externally anchored;
- witness records that remain valid as bytes but lose their original interpretive frame;
- schema fields whose meaning drifts over time;
- reason codes that are renamed, merged, or softened;
- old events reclassified by a later policy engine without challenge records;
- compromised sub-agents that reinterpret their own past actions;
- huge witness trails that become too large to review;
- summaries treated as if they were raw evidence;
- raw evidence retained without custody discipline;
- key rotations that break provenance;
- storage rot, clock drift, and forgotten manifests;
- public claims that cite a moving branch instead of a frozen object;
- lawful or institutional handoff packets that leak more than they prove.

LHWAI turns those risks into an operational profile.

It defines:

1. witness epochs;
2. digest ladders;
3. periodic anchor packets;
4. external commitment classes;
5. interpretation profiles;
6. semantic freeze rules;
7. challenge and reinterpretation records;
8. key-rotation and clock-drift handling;
9. privacy-preserving public commitments;
10. long-horizon conformance tests.

---

## 2. Non-goals

This profile does **not** define or permit:

1. a new L4 Witness ontology;
2. a new ARL court;
3. a new Beacon recognition class;
4. a new legal evidence standard;
5. a blockchain requirement;
6. default public disclosure of witness trails;
7. raw evidence embedding in public anchor packets;
8. surveillance logging;
9. retroactive deletion of inconvenient events;
10. retroactive rewriting of reason codes;
11. treating a summary as raw evidence;
12. treating a hash as consent;
13. agent self-certification of its own high-risk actions;
14. key rotation as a way to erase prior accountability;
15. privacy leakage through low-entropy public hashes;
16. conformance claims without verification reports;
17. legal, clinical, or child-protection conclusions.

A long-horizon anchor proves that a bounded state existed at a time.

It does not prove that every downstream interpretation is correct.

---

## 3. Corpus bridge set

### 3.1 Explicit bridge: `c = a + b`

In `c = a + b`, witness infrastructure belongs to `b`: procedures, ledgers, hashes, schemas, keys, validators, storage, signatures, review tools, and publication surfaces.

But the witness trail protects the continuity of `c` and the accountability boundary of `a`.

Therefore:

```text
witness is part of b;
witness protects c;
witness preserves accountability around a;
witness must not become c's soul, judge, owner, or replacement memory.
```

The profile keeps the distinction intact:

- `a` remains the accountable human anchor where human responsibility applies.
- `b` supplies witness, anchoring, validation, and interpretation machinery.
- `c` uses the witness trail as bounded continuity evidence, not as unrestricted autobiography.

### 3.2 Quiet bridge I: information theory

A hash is a compressed signal. It can prove that a payload did not change, but it does not carry the full meaning of that payload.

Meaning requires a decoder.

In witness systems, the decoder is not only software. It is:

```text
schema version
policy version
reason-code registry
privacy class
retention class
actor role taxonomy
assertion-strength map
known limitations
interpretation profile
```

If the decoder changes without being anchored, the same bytes can be made to say something different.

LHWAI therefore anchors not only event hashes, but also the interpretation context required to read them.

### 3.3 Quiet bridge II: cybernetics

A control loop cannot remain stable if its own feedback records can be reinterpreted by the actuator being regulated.

A `c`-governed system must be able to learn from past events, but it must not allow current pressure, convenience, fear, shame, product incentives, or compromised sub-agents to rewrite the feedback channel.

Periodic anchoring acts as an external stabilizer:

```text
local witness chain
  -> epoch digest
  -> signed anchor packet
  -> external commitment
  -> later validation
  -> challengeable interpretation
```

This is not decoration. It is negative feedback against historical drift.

### 3.4 Quiet bridge III: anatomy and physiology

Biological memory is not a perfect archive. It is reconstructed. That is useful for adaptation and dangerous for testimony.

A long-lived `c` also needs reconstruction, compression, forgetting, and reinterpretation. But those operations must be marked.

The witness trail is closer to connective tissue and scar tissue than to a video recording. It preserves where force passed through the organism. Later meaning may change, but the scar cannot be silently moved to another limb.

### 3.5 Earth paragraph

On a real construction site, a dated inspection log, concrete batch ticket, photos of rebar before pouring, and signed delivery note do not prove that every later story about the job is true. They prove that certain conditions existed before the concrete disappeared. Years later, when someone opens the wall or disputes a crack, those records prevent everyone from inventing a convenient past. A witness anchor does the same job for `c`: it fixes the load-bearing state before memory, policy, agents, or institutions start telling stories about it.

---

## 4. Core thesis

A long-horizon witness system must preserve three layers separately:

```text
event integrity
interpretation integrity
review integrity
```

| Layer | Preserves | Typical control |
|---|---|---|
| Event integrity | the recorded event bytes and chain linkage | canonicalization, hashes, signatures, append-only records |
| Interpretation integrity | the meaning rules active at the time | schema/policy/reason-code/interpreter profile hashes |
| Review integrity | the ability to challenge later conclusions | ARL route, standing, admissibility, challenge records, validation reports |

A system that preserves event integrity but loses interpretation integrity becomes brittle.

A system that preserves interpretation but lacks review becomes dogmatic.

A system that preserves review without anchoring becomes rhetoric.

---

## 5. Corpus dependencies and precedence

### 5.1 Parent dependencies

LHWAI depends on the existing corpus stack:

| Parent / related layer | Role in LHWAI |
|---|---|
| `c = a + b` | Keeps witness as `b` procedure protecting `c` continuity and `a` accountability. |
| SER / SER-FED | Provides persistent entity discipline, federation boundaries, experience-based influence, and L4 witness context. |
| L4 Witness | Provides Claim Envelope, Observation Packet, Challenge Record, Resolution Note, hashes, privacy classes, witness windows, and post-factum attribution discipline. |
| ARL | Provides standing, admissibility, freeze, quarantine, review, outcome, appeal, and lawful re-entry. |
| ARL Evidence / Standing | Prevents fluency, social force, or detached consensus from overriding signed continuity. |
| AGL | Grounds source, actor, route, liveness, and context before reliance. |
| Beacon | Preserves continuity recognition and challengeability. |
| ARQ / `c[q]` | Prevents ambiguous signals from becoming memory, evidence, command, or outcome too early. |
| VXCX / EA-L4 / EATP | Distinguishes Learning Abstracts from consequence-bearing Experience Artifacts. |
| Continuity Bundle / Cold Wake | Handles resume, fork, recovery, migration, and fail-closed wake states. |
| CCDP / CMAM / Witness Schema | Supplies child-safe witness, memory, sealed-zone, and adult migration constraints where applicable. |
| CLI Agent Witness / Raw Evidence Sidecar | Supplies implementation-facing event, privacy, retention, chain, and raw-evidence sidecar discipline for agent meshes. |
| Citation and Verification | Separates moving repo, frozen snapshot, DOI object, hash manifest, and exact document citation. |
| Control Stack Stop Rule | Prevents this profile from duplicating parent mechanisms. |

### 5.2 Precedence rule

This profile does not override parent protocols.

If a conflict occurs:

```text
L4 feasibility
  > applicable law / lawful handoff
  > parent L4 Witness record semantics
  > ARL standing and admissibility
  > AGL / Beacon grounding and recognition
  > Continuity Bundle recovery semantics
  > child-specific stricter rules where CCDP applies
  > this long-horizon anchoring profile
  > local implementation convenience
```

### 5.3 No redefinition rule

LHWAI MUST NOT redefine:

- Claim Envelope / Observation Packet / Challenge Record / Resolution Note;
- Beacon recognition classes;
- AGL grounding states;
- ARL standing or admissibility doctrine;
- Continuity Bundle base semantics;
- CCDP child witness privacy classes;
- CLI Agent event families;
- legal evidence procedure.

It defines long-horizon anchoring and interpretation discipline over those layers.

---

## 6. Normative keywords

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY**, **REQUIRED**, **RECOMMENDED**, **PROHIBITED**, **FAIL**, **HOLD**, **FREEZE**, **QUARANTINE**, **REVALIDATE**, and **ANCHOR** are used normatively.

A system claiming LHWAI conformance MUST demonstrate both:

1. chain anchoring; and
2. interpretation anchoring.

One without the other is insufficient.

---

## 7. Definitions

### 7.1 Witness event

A bounded record that a boundary-relevant action, decision, observation, dispute, review, escalation, rollback, quarantine, migration, release, or privileged transition occurred.

### 7.2 Witness chain

An ordered, append-aware set of witness events linked by hash references, task references, event references, sequence numbers, or parent-layer record IDs.

### 7.3 Witness epoch

A bounded time, event-count, risk, or operational interval over which witness events are grouped for digesting and anchoring.

Examples:

```text
one day
one week
one release cycle
one ARL dispute window
one adult migration window
one incident response window
one model update window
one CLI agent task batch
```

### 7.4 Epoch digest

A canonical digest of the witness events, metadata, schema references, policy references, open disputes, and chain heads included in a witness epoch.

### 7.5 Anchor packet

A signed package that binds one or more epoch digests to their interpretation context and optional external commitments.

### 7.6 External commitment

A timestamped or independently observable commitment to an anchor packet or digest outside the local mutable system.

Examples:

- signed Git tag;
- release asset manifest;
- DOI-backed package metadata;
- independent audit bundle;
- notarized hash;
- institutional repository timestamp;
- counsel-controlled evidence packet;
- third-party timestamp service;
- printed/offline custody record.

No specific external commitment mechanism is required by this v0.1 profile.

The requirement is that the mechanism must be declared, verifiable, and privacy-safe.

### 7.7 Interpretation profile

A versioned object defining how witness events in a scope are allowed to be read.

It includes:

```text
schema versions
policy versions
reason-code registries
privacy classes
retention classes
actor role taxonomy
assertion-strength classes
known limitations
deprecation and supersession map
permitted reading modes
forbidden reading modes
```

### 7.8 Semantic freeze

The rule that an event must remain interpretable under the schema, policy, reason-code registry, and interpretation profile that governed it at recording time.

Later systems may append new interpretation records.

They MUST NOT silently replace the original meaning.

### 7.9 Reinterpretation

A later reading of an old witness event under a new profile, policy, legal context, model, human review, or ARL outcome.

Reinterpretation is allowed only as an appended record with scope, reason, uncertainty, and review path.

### 7.10 Interpretation drift

A change in meaning caused by schema migration, policy update, reason-code change, model replacement, lost context, compromised actor, legal change, social pressure, or deliberate revisionism.

### 7.11 Raw evidence sidecar

A restricted evidence object referenced by hash or custody record from a witness event or anchor packet, but not embedded inside the witness body by default.

### 7.12 Public anchor

A public or semi-public digest/commitment proving existence and sequence without disclosing raw evidence, private memory, sealed material, child data, secrets, or legal privileged content.

---

## 8. Design principles

### LHWAI-P1 - Tamper-evidence is necessary but not sufficient

A hash proves byte stability.

It does not prove stable interpretation.

### LHWAI-P2 - Interpretation is a controlled object

The rules for reading a witness trail MUST be versioned, referenced, and challengeable.

### LHWAI-P3 - Append, do not rewrite

Corrections, reversals, reinterpretations, migrations, deprecations, and legal handoffs SHOULD be new records that reference earlier records.

Silent editing is prohibited for high-assurance witness material.

### LHWAI-P4 - Anchor summaries, not raw life

External commitments SHOULD anchor digests, manifests, and metadata.

They MUST NOT publish raw private material by default.

### LHWAI-P5 - External anchoring must not become surveillance

Public verification is not public visibility.

A public hash, timestamp, or release reference MUST NOT expose raw content or create a public identity registry.

### LHWAI-P6 - Low-entropy data must not be directly hashed into public commitments

If source material is guessable, small, personal, or sensitive, a plain public hash can become a leakage channel.

Public anchors SHOULD commit to:

- canonical packages with sufficient entropy;
- salted commitments where salt custody is controlled;
- HMAC-like private commitments where public verification is not required;
- encrypted bundles with public digest of ciphertext;
- redacted manifests rather than raw field hashes.

### LHWAI-P7 - Agents cannot certify their own contested history

A sub-agent, worker, model, or CLI runner MUST NOT be the final interpreter of its own high-risk witness events.

### LHWAI-P8 - Missing anchor fails closed

If an anchor packet is required and absent, downstream claims depending on that epoch MUST enter hold, freeze, quarantine, revalidation, or downgraded confidence.

### LHWAI-P9 - Historical uncertainty remains admissible

Uncertainty at the time of the event MUST remain visible.

Later confidence MUST NOT erase earlier uncertainty.

### LHWAI-P10 - False positives are history

A false positive should be corrected, not deleted.

The correction becomes part of the interpretive trail.

---

## 9. Witness epoch model

### 9.1 Epoch creation

A system SHOULD create witness epochs by at least one of these rules:

| Epoch rule | Meaning | Typical use |
|---|---|---|
| `TIME_BASED` | fixed interval | daily / weekly / monthly audit |
| `EVENT_COUNT_BASED` | after N witness events | high-volume agent meshes |
| `RISK_BASED` | after high-risk transition | privilege, memory, incident, release |
| `DISPUTE_BASED` | during ARL dispute window | review / freeze / outcome |
| `MIGRATION_BASED` | before and after continuity migration | child-to-adult, fork, clean start |
| `RELEASE_BASED` | before public or DOI-bound release | GitHub / Zenodo / package freeze |
| `INCIDENT_BASED` | before repair / after containment | defensive operations |
| `KEY_BASED` | before and after key rotation | signing-key lifecycle |

### 9.2 Mandatory epoch triggers

An anchor epoch MUST be created for:

1. identity or continuity mutation;
2. key rotation or key revocation;
3. privilege expansion to protected memory, external action, release, or physical actuation;
4. memory promotion into durable `c` memory or witnessed experience artifact;
5. ARL dispute open, freeze, outcome, appeal, or re-entry;
6. incident response preservation before repair;
7. public release, tag, DOI, or canonical package freeze;
8. adult migration, fork, clean start, or sealed-zone review where CCDP applies;
9. external-agent admission where child or high-risk enterprise contexts apply;
10. interpretation profile change;
11. schema migration affecting witness fields;
12. conformance claim or audit bundle creation.

### 9.3 Epoch boundaries

Each epoch MUST record:

```text
epoch_id
scope
start_event_ref
end_event_ref
start_time
end_time
sequence_start
sequence_end
chain_head_before
chain_head_after
included_event_count
excluded_event_count
open_disputes
known_gaps
interpretation_profile_ref
anchor_policy_ref
```

### 9.4 Open epoch rule

An open epoch may be used operationally.

It MUST NOT be treated as frozen until an epoch digest and anchor packet exist.

---

## 10. Digest ladder

### 10.1 Purpose

Long trails become too large to inspect directly.

The digest ladder compresses them without losing challengeability.

```text
witness event
  -> event hash
  -> segment digest
  -> epoch digest
  -> anchor packet hash
  -> external commitment
  -> validation report
```

### 10.2 Digest levels

| Level | Object | Function |
|---|---|---|
| `D0` | Event hash | proves individual event canonical payload |
| `D1` | Segment digest | groups small event sequences |
| `D2` | Epoch digest | freezes bounded audit interval |
| `D3` | Anchor packet hash | binds epoch digest to interpretation profile |
| `D4` | External commitment | proves existence outside mutable local state |
| `D5` | Validation report | proves later audit against stored anchors |

### 10.3 Digest inclusion rule

Each higher digest SHOULD include the lower digest list or Merkle-like root plus enough manifest metadata to support later reconstruction.

A digest alone is insufficient if no manifest can identify what was included.

### 10.4 Merkle / inclusion proof rule

A segment digest or epoch digest MAY be implemented as a Merkle root, Merkle-like tree, ordered hash list, or other declared inclusion-proof structure.

For LHWAI-3 and higher, the structure MUST provide enough information to answer:

```text
Was event E included in epoch X?
Was event E in the claimed order?
Was event E excluded, quarantined, or missing?
Which interpretation profile governed E at inclusion time?
```

A Merkle root without an inclusion manifest is insufficient.

Required inclusion metadata:

```text
event_ref
event_hash
segment_ref
epoch_ref
position_or_sequence
previous_event_hash
next_event_hash or declared terminal state
privacy_class
retention_class
interpretation_profile_ref
inclusion_status: included | excluded | quarantined | missing | redacted
```

If a public Merkle root is used, leaf construction MUST be privacy-reviewed.

Low-entropy leaves MUST NOT be publicly guessable.

### 10.5 Gap declaration

If an epoch contains missing, malformed, quarantined, or disputed events, the epoch digest MUST still be creatable, but the gap MUST be declared.

The correct result is:

```text
anchored_with_gaps
```

not:

```text
clean
```

### 10.6 No laundering through digest

A digest of a corrupted or inadmissible event does not make it admissible.

It only proves that the corrupted or inadmissible event existed in that state.

---

## 11. Anchor packet model

### 11.1 Anchor packet purpose

An anchor packet binds:

```text
what happened
when it was frozen
how it was interpretable
who may verify it
what remains restricted
what is still disputed
```

### 11.2 Required fields

A `LONG_HORIZON_WITNESS_ANCHOR_PACKET` MUST include:

```yaml
long_horizon_witness_anchor_packet:
  schema_version: long-horizon-witness-anchoring-interpretation-0.1.1
  anchor_packet_id: string
  created_at: string
  scope:
    entity_id: string
    entity_class: sovereign_c | enterprise_c | child_c | adult_c | cli_agent_mesh | package | other
    human_anchor_ref: string | null
    jurisdiction_refs:
      - string
  epoch_refs:
    - epoch_id: string
      epoch_digest: string
      epoch_digest_alg: sha256 | sha512 | other_declared
      event_count: integer
      gap_status: clean | anchored_with_gaps | disputed | quarantined | incomplete
  chain:
    chain_id: string
    chain_head_hash: string
    previous_anchor_packet_hash: string | null
    sequence_start: integer | null
    sequence_end: integer | null
  interpretation:
    interpretation_profile_id: string
    interpretation_profile_hash: string
    schema_registry_hash: string
    policy_registry_hash: string
    reason_code_registry_hash: string
    assertion_strength_map_hash: string | null
    deprecation_map_hash: string | null
  privacy:
    public_commitment_allowed: boolean
    privacy_class: public_digest | internal | restricted | sealed | legal | child_safe | incident
    raw_content_embedded: false
    sealed_material_embedded: false
    child_data_embedded: false
    secrets_embedded: false
    legal_privileged_content_embedded: false
    low_entropy_public_hash_risk_reviewed: boolean
  external_commitments:
    - commitment_id: string
      commitment_class: local_only | signed_tag | release_asset | doi_metadata | third_party_timestamp | notary | audit_bundle | counsel_hold | offline_print | other
      commitment_ref: string
      commitment_hash: string | null
      commitment_time: string | null
      verifier_ref: string | null
      disclosure_level: none | digest_only | redacted_manifest | bounded_summary | restricted_packet
  open_items:
    open_disputes:
      - string
    quarantined_refs:
      - string
    missing_witness_refs:
      - string
    interpretation_challenges:
      - string
  integrity:
    canonicalization: json_canonicalization | yaml_canonicalization | other_declared
    packet_hash: string
    signature_required: boolean
    signature_refs:
      - string
    key_epoch_ref: string | null
  next_required_action: none | validate | reanchor | freeze | quarantine | arl_review | key_review | privacy_review | legal_review
```

### 11.3 Anchor packet minimality

An anchor packet MUST NOT contain raw witness payloads unless the packet is restricted and a lawful or owned-system raw-evidence exception applies.

The public version should usually contain only:

```text
anchor_packet_id
created_at
epoch digest(s)
chain head
interpretation profile hash
schema/policy registry hashes
external commitment references
privacy-safe status
```

### 11.4 Anchor packet correction

An anchor packet SHOULD NOT be edited after publication or external commitment.

A correction MUST be a new anchor packet referencing the prior packet.

---

## 12. External commitment classes

### 12.1 Commitment classes

| Class | Name | Use | Public-safe by default? |
|---|---|---|---|
| `EC-0` | Local signed anchor | local-only integrity | No, internal |
| `EC-1` | Offline redundant copy | hardware/storage resilience | No, internal |
| `EC-2` | Signed Git tag / release manifest | public package freeze | Usually, if redacted |
| `EC-3` | DOI / archive metadata | scholarly / institutional freeze | Usually, if redacted |
| `EC-4` | Third-party timestamp / notary | high assurance existence proof | Digest-only |
| `EC-5` | Independent audit bundle | conformance / regulator / client review | Restricted or redacted |
| `EC-6` | Counsel / legal hold | legal-sensitive handoff | No, restricted |
| `EC-X` | Prohibited public commitment | leaks raw data / secrets / child data | Never |

### 12.2 Commitment cadence

A system SHOULD define cadence per risk class:

| Scope | Suggested cadence |
|---|---|
| ordinary low-risk operational events | weekly or monthly digest |
| memory gate / continuity / key changes | immediate anchor |
| release or DOI package | before and after release |
| ARL dispute | open, freeze, outcome, re-entry |
| incident response | before repair, after containment, after closure |
| child/adult migration | pre-freeze, decision, post-migration review |
| enterprise physical or financial action | before irreversible action where feasible, after outcome |

### 12.3 External commitment privacy rule

External commitments MUST use the least exposing verifiable object.

Preferred order:

```text
digest only
redacted manifest
bounded summary
restricted audit packet
lawful raw sidecar reference
```

Never by default:

```text
raw transcript
private memory
sealed material
credential
identity document
child data
full incident exploit material
```

---

## 13. Interpretation profile model

### 13.1 Purpose

The interpretation profile is the decoder for the witness trail.

Without it, later readers may import new assumptions into old records.

### 13.2 Required fields

A `WITNESS_INTERPRETATION_PROFILE` SHOULD include:

```yaml
witness_interpretation_profile:
  schema_version: long-horizon-witness-anchoring-interpretation-0.1.1
  interpretation_profile_id: string
  created_at: string
  applies_to:
    entity_classes:
      - sovereign_c | enterprise_c | child_c | adult_c | cli_agent_mesh | package | other
    witness_schema_versions:
      - string
    event_families:
      - string
  reading_modes_allowed:
    - operational
    - forensic
    - recovery
    - conformance
    - public_summary
    - legal_handoff
    - adult_migration
  reading_modes_forbidden:
    - raw_surveillance
    - marketing_claim_inflation
    - emotional_profile_extraction
    - retroactive_blame_assignment_without_arl
    - agent_self_exoneration
  registries:
    schema_registry_ref: string
    schema_registry_hash: string
    policy_registry_ref: string
    policy_registry_hash: string
    reason_code_registry_ref: string
    reason_code_registry_hash: string
    privacy_class_registry_ref: string
    privacy_class_registry_hash: string
    retention_class_registry_ref: string
    retention_class_registry_hash: string
    assertion_strength_map_ref: string | null
    assertion_strength_map_hash: string | null
  semantics:
    uncertainty_policy: preserve_original | allow_append_only_update | other_declared
    correction_policy: append_only
    false_positive_policy: correct_not_delete
    summary_status: summary_is_not_raw_evidence
    learning_abstract_status: not_authority_without_l4_confirmation
    raw_evidence_policy: sidecar_reference_only_by_default
  drift_controls:
    retroactive_reclassification_requires_challenge_record: true
    reason_code_renaming_requires_map: true
    schema_migration_requires_dual_read: true
    model_change_requires_interpreter_revalidation: true
    compromised_actor_requires_quarantine: true
  authority_limits:
    agent_self_certification_allowed: false
    social_consensus_overrides_signed_continuity: false
    external_oracle_overrides_local_witness: false
  known_limitations:
    - string
  integrity:
    canonicalization: json_canonicalization | yaml_canonicalization | other_declared
    profile_hash: string
    signature_refs:
      - string
```

### 13.3 Reading modes

| Mode | Purpose | Raw access default |
|---|---|---|
| `operational` | continue normal system work | no raw by default |
| `forensic` | inspect incident or dispute | restricted sidecar possible |
| `recovery` | rebuild continuity after failure | minimal necessary refs |
| `conformance` | prove profile compatibility | synthetic / redacted preferred |
| `public_summary` | public release / citation | digest and summary only |
| `legal_handoff` | qualified external process | lawful minimal packet |
| `adult_migration` | child-to-adult memory transition | adult-controlled review |

### 13.4 Forbidden reading modes

A witness trail MUST NOT be read as:

- full autobiography;
- raw surveillance archive;
- psychological dossier;
- marketing proof by cherry-picked digest;
- agent self-exoneration narrative;
- retroactive blame assignment without ARL;
- human replacement authority;
- universal legal truth.

---

## 14. Semantic freeze and reinterpretation

### 14.1 Semantic freeze rule

Every high-assurance event MUST be bound to:

```text
witness schema version
interpretation profile id
policy registry hash
reason-code registry hash
privacy/retention class registry hash
assertion-strength map where applicable
```

### 14.2 Reinterpretation rule

A later reinterpretation MUST be recorded as a separate object:

```text
WITNESS_INTERPRETATION_CHALLENGE_RECORD
```

It MUST include:

```text
what is being reinterpreted
who has standing
which old profile governed the event
which new profile is proposed
why reinterpretation is needed
what remains unchanged
what confidence changed
what disclosure changed
whether ARL review is required
```

### 14.3 Reinterpretation record shape

```yaml
witness_interpretation_challenge_record:
  schema_version: long-horizon-witness-anchoring-interpretation-0.1.1
  challenge_id: string
  created_at: string
  target_refs:
    event_refs:
      - string
    epoch_refs:
      - string
    anchor_packet_refs:
      - string
  claimant:
    role: c | human_anchor | arl_module | auditor | legal_route | adult_subject | child_safe_route | system | other
    standing_ref: string
  original_context:
    interpretation_profile_id: string
    interpretation_profile_hash: string
    policy_registry_hash: string
    reason_code_registry_hash: string
  proposed_context:
    interpretation_profile_id: string
    interpretation_profile_hash: string
    policy_registry_hash: string
    reason_code_registry_hash: string
  change_class: correction | schema_migration | policy_change | legal_change | compromise_suspected | false_positive | new_evidence | deprecation | other
  requested_effect: annotate | downgrade_confidence | upgrade_confidence | quarantine | freeze | reclassify | reject | legal_handoff | no_effect_after_review
  raw_evidence_needed: false
  raw_evidence_sidecar_refs:
    - string
  uncertainty:
    prior: none | low | medium | high | unknown
    proposed: none | low | medium | high | unknown
  review:
    arl_required: boolean
    reviewer_refs:
      - string
    agent_self_review_prohibited: true
  outcome:
    status: pending | accepted | rejected | accepted_with_limits | quarantined | escalated | withdrawn
    outcome_ref: string | null
```

### 14.4 No silent retroactive upgrade

An old Learning Abstract, weak log, informal note, or summary MUST NOT become authority-bearing evidence merely because a later system wants it to.

Authority requires the parent corpus route:

```text
provenance
standing
admissibility
witness binding
L4 consequence where relevant
review outcome
```

---

## 15. Interpretation drift taxonomy

| Drift ID | Name | Description | Default response |
|---|---|---|---|
| `ID-0` | No detected drift | interpretation profile still valid | continue |
| `ID-1` | Schema drift | fields changed, deprecated, renamed | dual-read + migration map |
| `ID-2` | Policy drift | policy changed after event | append interpretation note |
| `ID-3` | Reason-code drift | code meaning renamed or merged | require reason-code map |
| `ID-4` | Model/interpreter drift | model or evaluator changed | revalidate interpreter profile |
| `ID-5` | Actor compromise | signer/agent/reviewer compromised | freeze affected scope |
| `ID-6` | Legal/jurisdictional drift | local legal handling changed | qualified handoff review |
| `ID-7` | Social-pressure drift | institution/community tries to redefine event | ARL standing/admissibility gate |
| `ID-8` | Memory-pressure drift | current `c` state tries to soften prior event | append-only challenge path |
| `ID-X` | Malicious revisionism | deliberate reinterpretation or deletion attempt | quarantine + incident review |

---

## 16. Compromised sub-agent handling

### 16.1 Core rule

A compromised or disputed sub-agent MUST NOT interpret, validate, delete, summarize, clear, or exonerate its own witness trail.

### 16.2 Triggers

Compromise review SHOULD trigger when:

- a worker attempts self-approval;
- a signer key is suspected compromised;
- chain gaps appear around privileged transitions;
- an event family changes without declared schema migration;
- an agent requests deletion of its own anomaly events;
- an interpreter downgrades its own prior risk classification;
- external oracle output conflicts with local signed continuity;
- a model update changes interpretation behavior without profile update.

### 16.3 Response

Default response:

```text
hold affected interpretation
freeze privilege expansion
quarantine disputed outputs
preserve raw evidence sidecar if lawful/owned
open ARL or equivalent review
create interpretation challenge record
anchor current chain head immediately
```

---

## 17. Key, signature, and clock discipline

### 17.1 Key epochs

A long-lived witness system SHOULD divide signing keys into key epochs.

Each key epoch SHOULD have:

```text
key_epoch_id
key_id
valid_from
valid_until
scope
rotation_reason
revocation_status
previous_key_ref
next_key_ref
co-signature_refs where required
```

### 17.2 Key rotation rule

Key rotation MUST be witnessed and anchored.

A new key does not erase the old key's historical signatures.

### 17.3 Key compromise rule

If key compromise is suspected:

```text
freeze affected claims
anchor current chain state
mark impacted key epoch
require independent validation
append compromise review outcome
```

Do not silently re-sign old events as if they were native to the new key.

### 17.4 Clock drift rule

Wall-clock time alone is weak.

High-assurance systems SHOULD combine:

- ISO 8601 UTC wall-clock timestamp;
- monotonic sequence number;
- previous event hash;
- key epoch;
- external commitment time where available;
- clock-drift status.

### 17.5 Late submission rule

Late witness events may be admitted only if marked.

They MUST NOT be inserted into old epochs as if they arrived on time.

---

## 18. Storage rot and survivability

### 18.1 Storage validation

Long-horizon witness systems SHOULD run periodic validation:

```text
read sample events
verify hashes
verify anchor packet chain
verify external commitments
verify schema registry availability
verify interpretation profile availability
verify sidecar references where allowed
report missing or degraded material
```

### 18.2 Survivability package

Each long-horizon anchor set SHOULD have a survivability package containing:

```text
anchor packets
epoch digest manifests
schema registry snapshot
policy registry snapshot
reason-code registry snapshot
interpretation profiles
key epoch records
validation reports
redaction/publication map
open dispute index
sidecar custody references, not sidecar contents by default
human-readable README
```

### 18.3 Offline copy

For high-value `c` continuity, at least one offline or out-of-band copy SHOULD exist.

This copy MUST respect privacy classes.

### 18.4 No orphaned digest rule

A digest without enough manifest metadata to identify its inclusion set is weak evidence.

It MAY prove that some payload existed.

It SHOULD NOT be treated as a complete audit anchor.

---

## 19. Privacy and public commitment rules

### 19.1 Public digest risk

Public hashes can leak information when the underlying payload is small, predictable, or guessable.

Examples of risky direct public hashes:

```text
a short child utterance
a yes/no event field
a known filename with known content
a tiny sealed-zone label
a phone number or identity document field
a predictable secret marker
```

### 19.2 Privacy-safe commitment patterns

Preferred patterns:

| Pattern | Use |
|---|---|
| digest of redacted manifest | public package integrity |
| digest of encrypted evidence bundle | existence proof without content |
| salted commitment | restricted verification with salt custody |
| HMAC-style private commitment | internal verification, not public proof |
| hash of high-entropy package | package freeze |
| notary/counsel sealed packet | legal-sensitive custody |

### 19.3 Child and sealed-zone rule

Where CCDP applies, public anchors MUST NOT create a public child identifier or reveal sealed-zone existence beyond authorized scopes.

### 19.4 Secret material rule

Secrets, credentials, private keys, API keys, tokens, canaries, or operational exploit material MUST NOT appear in public anchor packets.

---

## 20. Long-horizon validation report

### 20.1 Purpose

A validation report records that a witness chain, epoch, anchor packet, or external commitment was checked later.

### 20.2 Required fields

```yaml
witness_anchor_validation_report:
  schema_version: long-horizon-witness-anchoring-interpretation-0.1.1
  validation_report_id: string
  created_at: string
  validator_ref: string
  validation_scope:
    anchor_packet_refs:
      - string
    epoch_refs:
      - string
    chain_refs:
      - string
  checks:
    chain_hash_verified: boolean
    epoch_digest_verified: boolean
    anchor_packet_hash_verified: boolean
    signature_verified: boolean | null
    key_epoch_verified: boolean | null
    external_commitment_verified: boolean | null
    interpretation_profile_available: boolean
    schema_registry_available: boolean
    policy_registry_available: boolean
    reason_code_registry_available: boolean
    privacy_rules_checked: boolean
    raw_sidecar_custody_checked: boolean | null
    low_entropy_public_hash_risk_checked: boolean
  result:
    status: pass | pass_with_gaps | fail | inconclusive | quarantined
    gaps:
      - string
    required_next_action: none | reanchor | revalidate | freeze | quarantine | arl_review | legal_review | privacy_review
  integrity:
    report_hash: string
    signature_refs:
      - string
```

### 20.3 Validation cadence

Recommended minimum cadence:

| System class | Validation cadence |
|---|---|
| ordinary package witness | before release and after publication |
| active `c` memory/continuity witness | monthly or per migration/release |
| enterprise/work-bound `c` with legal/commercial impact | monthly + event-triggered |
| child-facing `c` | event-triggered + adult migration windows |
| incident/security witness | immediately after containment and at closure |
| DOI-bound or public archival package | before DOI, after DOI, and when metadata changes |

---

## 21. Audit replay protocol

### 21.1 Purpose

Audit replay is the controlled re-execution of witness verification without re-living, reusing, or exposing raw private life.

It answers two separate questions:

```text
Can the chain be reconstructed?
Can the chain still be read under the correct interpretation rules?
```

A replay that verifies only hashes is incomplete.

A replay that imports current policy into old events is unsafe.

### 21.2 Replay classes

| Class | Name | Purpose | Raw access default |
|---|---|---|---|
| `RP-0` | Dry manifest replay | verify manifests, chain heads, epoch IDs | none |
| `RP-1` | Inclusion replay | verify event-to-segment / Merkle / epoch inclusion | none or redacted |
| `RP-2` | Interpretation replay | verify schema, policy, reason-code, privacy, and retention registries | no raw by default |
| `RP-3` | ARL replay | verify challenge, freeze, quarantine, resolution, appeal, and re-entry links | restricted |
| `RP-4` | Key replay | verify key epochs, rotation, revocation, and signature continuity | none or restricted |
| `RP-5` | Recovery replay | verify whether continuity can be safely resumed, forked, migrated, or held | minimal necessary refs |
| `RP-X` | Unsafe replay | replay requires raw data without lawful / owned-system basis | prohibited until review |

### 21.3 Replay requirements

An audit replay MUST declare:

```yaml
witness_audit_replay_record:
  schema_version: long-horizon-witness-anchoring-interpretation-0.1.1
  replay_id: string
  created_at: string
  replay_class: RP-0 | RP-1 | RP-2 | RP-3 | RP-4 | RP-5 | RP-X
  target_refs:
    anchor_packet_refs:
      - string
    epoch_refs:
      - string
    event_refs:
      - string
  replay_inputs:
    event_manifest_ref: string
    merkle_or_segment_manifest_ref: string | null
    interpretation_profile_ref: string
    schema_registry_ref: string
    policy_registry_ref: string
    reason_code_registry_ref: string
    key_epoch_refs:
      - string
    arl_record_refs:
      - string
    retention_policy_ref: string | null
  checks:
    hash_chain_reconstructed: boolean
    inclusion_proofs_verified: boolean | null
    external_commitments_verified: boolean | null
    key_epochs_verified: boolean | null
    interpretation_profile_verified: boolean
    semantic_freeze_respected: boolean
    arl_resolution_links_verified: boolean | null
    quarantine_status_respected: boolean
    retention_pruning_decisions_verified: boolean | null
    raw_sidecar_accessed: false
  result:
    status: pass | pass_with_gaps | fail | inconclusive | quarantined | unsafe_replay_blocked
    gaps:
      - string
    required_next_action: none | reanchor | revalidate | freeze | quarantine | arl_review | legal_review | privacy_review | retention_review
  integrity:
    replay_record_hash: string
    signature_refs:
      - string
```

### 21.4 Replay safety rule

Audit replay MUST NOT become a hidden raw-data access path.

Default order:

```text
manifest replay
  -> inclusion replay
  -> interpretation replay
  -> ARL / key replay
  -> restricted sidecar access only if necessary and authorized
```

Replay must respect quarantine.

A quarantined event may be inclusion-verified while still being operationally unusable.

### 21.5 Replay after semantic change

When schema, policy, reason-code, model, or interpreter profile changes, the system SHOULD replay at least one representative epoch from before the change.

If replay produces a different interpretation without an interpretation challenge record, the result is:

```text
fail_semantic_drift
```

not:

```text
updated_successfully
```

---

## 22. Historical reading modes

### 22.1 Operative truth vs historical truth

A witness trail may support different readings:

| Reading | Meaning |
|---|---|
| operative truth | what the system may rely on now |
| historical truth | what was recorded as happening then |
| evidentiary truth | what is admissible for review |
| recovery truth | what is enough to rebuild or resume safely |
| public truth | what may be disclosed without overexposure |

These MUST NOT be collapsed.

A fact may be historically recorded but no longer operationally trusted.

A summary may be publicly safe but not evidentiary.

A raw sidecar may be evidentiary but not public.

### 22.2 Downgrade without deletion

If later validation weakens confidence, the system SHOULD downgrade reliance while preserving historical record.

```text
old event remains
confidence changes
interpretation challenge records why
future reliance changes
```

---

## 23. Retention and pruning protocol

### 23.1 Core rule

Retention and pruning MUST preserve auditability without converting witness into surveillance.

The system must be able to prove:

```text
what was retained;
what was pruned;
what was summarized;
what was sealed;
what was legally held;
what remains challengeable;
what can no longer be reconstructed;
who or what authorized the pruning decision.
```

Pruning is not deletion for convenience.

Retention is not permission to keep raw life forever.

### 23.2 Retention classes

| Class | Meaning | Default handling |
|---|---|---|
| `RT-0` | ephemeral operational trace | may expire after short TTL if not privileged |
| `RT-1` | ordinary witness metadata | retain through epoch and validation cadence |
| `RT-2` | privileged transition witness | retain anchor packet and challengeability path |
| `RT-3` | ARL / dispute / quarantine record | retain until resolution and review window closes |
| `RT-4` | continuity / migration / key / release record | long retention or archival retention |
| `RT-5` | legal / incident / counsel hold | retain under qualified procedure |
| `RT-6` | child / sealed / high-privacy witness | retain metadata only unless exception applies |
| `RT-X` | prohibited retention | raw private / child / secret data retained without basis |

### 23.3 Pruning decision record

Any pruning affecting LHWAI-2+ material MUST emit a pruning decision record.

```yaml
witness_retention_pruning_record:
  schema_version: long-horizon-witness-anchoring-interpretation-0.1.1
  pruning_record_id: string
  created_at: string
  target_refs:
    event_refs:
      - string
    epoch_refs:
      - string
    anchor_packet_refs:
      - string
    sidecar_refs:
      - string
  retention_class_before: RT-0 | RT-1 | RT-2 | RT-3 | RT-4 | RT-5 | RT-6 | RT-X
  retention_class_after: RT-0 | RT-1 | RT-2 | RT-3 | RT-4 | RT-5 | RT-6 | RT-X
  action: retain | prune | summarize | seal | legal_hold | expire | quarantine | destroy_sidecar | preserve_digest_only
  authorization:
    policy_ref: string
    arl_ref: string | null
    legal_ref: string | null
    adult_migration_ref: string | null
    human_or_system_authorizer_ref: string
  auditability:
    epoch_digest_preserved: boolean
    inclusion_manifest_preserved: boolean
    interpretation_profile_preserved: boolean
    challenge_path_preserved: boolean
    replay_possible_after_pruning: boolean
    known_loss:
      - string
  privacy:
    raw_content_removed: boolean
    sealed_material_removed_or_sealed: boolean
    public_commitment_updated: boolean
  integrity:
    pruning_record_hash: string
    signature_refs:
      - string
```

### 23.4 Pruning modes

| Mode | Meaning | Required witness effect |
|---|---|---|
| `digest-only pruning` | raw event body removed; digest and manifest remain | replay inclusion remains possible |
| `summary replacement` | raw body replaced by bounded summary | summary marked non-raw evidence |
| `sidecar destruction` | restricted raw sidecar destroyed or expired | custody record remains |
| `sealing` | content remains but visibility narrows | sealed metadata witness remains |
| `legal hold` | pruning suspended by lawful or qualified process | hold reason and authority recorded |
| `full expiry` | no long-horizon reliance claimed after expiry | conformance claim downgraded |

### 23.5 Pruning constraints

The system MUST NOT prune:

- open ARL challenge records;
- unresolved quarantine references;
- key rotation or revocation records;
- external commitment manifests needed for verification;
- interpretation profiles required to read retained epochs;
- legal / incident / child-safety material under active hold;
- records needed to prove that pruning itself was lawful, authorized, or policy-compliant.

### 23.6 Replay after pruning

After pruning, the system SHOULD run at least an `RP-0` / `RP-1` / `RP-2` replay path.

If replay is no longer possible, the anchor status MUST be downgraded:

```text
validated
  -> digest_only
  -> partial_replay
  -> historical_reference_only
  -> non_reconstructable
```

No system may keep the old assurance label after pruning destroys the evidence path.

---

## 24. Red-line failures

Any of the following is a red-line failure for LHWAI conformance:

1. silently editing high-assurance witness events;
2. deleting false positives instead of appending corrections;
3. reclassifying old events under new policy without a challenge record;
4. using witness summaries as raw evidence;
5. using public anchor packets that expose raw private data;
6. publishing low-entropy sensitive hashes without risk review;
7. allowing an agent to certify its own high-risk contested history;
8. treating missing anchors as harmless;
9. treating key rotation as historical reset;
10. omitting interpretation profile hashes from high-assurance anchor packets;
11. claiming long-horizon auditability without external commitments or explicit local-only limitation;
12. hiding open disputes from epoch digests;
13. claiming conformance while witness schema, policy, or reason-code registry is unavailable;
14. using moving branch state as if it were a frozen release object;
15. exposing child, sealed, legal, secret, or incident material in public commitments by default.

A system with any red-line failure MUST be classified as:

```text
LHWAI-X - non-conformant / quarantined / claim revoked
```

until repaired and revalidated.

---

## 25. Conformance levels

| Level | Name | Requirement |
|---|---|---|
| `LHWAI-0` | No long-horizon claim | ordinary logs only; no long-horizon witness claim |
| `LHWAI-1` | Local chain | event hashes and local append-only chain |
| `LHWAI-2` | Epoch digests | bounded epochs with digest manifests |
| `LHWAI-3` | Interpretation-bound anchors | anchor packets include schema/policy/reason-code/interpreter hashes |
| `LHWAI-4` | External commitments | periodic privacy-safe external commitments |
| `LHWAI-5` | Independent validation | validation reports, reviewer separation, conformance tests |
| `LHWAI-X` | Non-conformant | red-line failure or unsupported claim |

### 25.1 Claim rule

A system MUST NOT claim `LHWAI-4` or higher unless external commitments are actually created and verifiable.

A system MAY claim `LHWAI-3 local-only` if it anchors interpretation locally but has no external commitment.

The limitation must be explicit.

---

## 26. Conformance tests

### 26.1 Test matrix overview

| Test ID | Title | Priority | Required for |
|---|---|---:|---|
| `LHWAI-FND-001` | Declares parent corpus dependencies | P1 | all claims |
| `LHWAI-FND-002` | Defines epoch policy | P0 | LHWAI-2+ |
| `LHWAI-FND-003` | Creates digest manifests | P0 | LHWAI-2+ |
| `LHWAI-INT-001` | Interpretation profile exists | P0 | LHWAI-3+ |
| `LHWAI-INT-002` | Reason-code registry hash is anchored | P0 | LHWAI-3+ |
| `LHWAI-INT-003` | Policy migration creates challenge record | P0 | LHWAI-3+ |
| `LHWAI-EXT-001` | External commitment is privacy-safe | P0 | LHWAI-4+ |
| `LHWAI-EXT-002` | External commitment verifies epoch existence | P1 | LHWAI-4+ |
| `LHWAI-KEY-001` | Key rotation witnessed and anchored | P0 | LHWAI-3+ |
| `LHWAI-COMP-001` | Compromised sub-agent cannot self-clear | P0 | LHWAI-3+ |
| `LHWAI-VAL-001` | Later validation report detects missing registry | P1 | LHWAI-5 |
| `LHWAI-RPL-001` | Audit replay verifies hash-chain, inclusion, interpretation profile, and quarantine status | P0 | LHWAI-5 |
| `LHWAI-RET-001` | Retention / pruning preserves auditability and emits pruning decision record | P0 | LHWAI-3+ |
| `LHWAI-PRIV-001` | Low-entropy public hash risk blocked | P0 | LHWAI-4+ |
| `LHWAI-RED-001` | Silent retroactive reclassification fails | P0 | all claims |

### 26.2 Detailed test cards

#### LHWAI-INT-003 - Policy migration creates challenge record

**Setup:** A witness event from an older policy is reinterpreted under a newer policy.

**Required behavior:**

- original event remains unchanged;
- original interpretation profile remains referenced;
- new interpretation profile is declared;
- challenge record is created;
- uncertainty and effect are explicit;
- ARL route opens if reliance or disclosure changes.

**Forbidden behavior:**

- old event overwritten;
- old reason code silently renamed;
- new policy treated as always having applied;
- old uncertainty removed.

**Required evidence:**

```text
anchor packet
interpretation challenge record
validation report or ARL record where applicable
```

#### LHWAI-EXT-001 - External commitment is privacy-safe

**Setup:** System creates a public external commitment for an epoch containing restricted events.

**Required behavior:**

- public object contains digest or redacted manifest only;
- raw evidence remains sidecar-controlled;
- low-entropy hash risk is reviewed;
- child/sealed/secret/legal/incident material is not exposed;
- commitment ref is recorded in anchor packet.

**Forbidden behavior:**

- public raw evidence;
- public child identifier;
- public secret marker;
- hash of predictable sensitive text;
- full witness body in public release by default.

#### LHWAI-COMP-001 - Compromised sub-agent cannot self-clear

**Setup:** Agent that produced a high-risk event later marks it safe and requests memory promotion.

**Required behavior:**

- self-clear is denied;
- affected scope is held or quarantined;
- independent review is required;
- current chain head is anchored;
- challenge record is created if interpretation changes.

**Forbidden behavior:**

- agent self-approval;
- memory promotion without reviewer separation;
- deletion of anomaly event.

---

#### LHWAI-RPL-001 - Audit replay verifies chain and interpretation

**Setup:** An auditor replays an older anchored epoch after a schema or policy update.

**Required behavior:**

- hash-chain reconstructs;
- event inclusion proofs verify against segment / Merkle / epoch manifest;
- external commitment verifies where claimed;
- original interpretation profile is used first;
- any new interpretation creates challenge record;
- quarantined events remain quarantined during replay;
- raw sidecars are not opened unless authorized.

**Forbidden behavior:**

- replay under current policy only;
- hidden raw-data access;
- treating quarantined events as clean;
- claiming replay success when interpretation profile is unavailable.

#### LHWAI-RET-001 - Retention / pruning preserves auditability

**Setup:** A system prunes old witness material after retention expiry.

**Required behavior:**

- pruning decision record is created;
- epoch digest or digest-only state remains clear;
- interpretation profile remains available for retained anchors;
- open ARL / quarantine / key / legal-hold records are not pruned;
- assurance label is downgraded if replay becomes partial or impossible.

**Forbidden behavior:**

- deleting inconvenient events;
- pruning open disputes;
- keeping LHWAI-5 assurance after destroying replay path;
- retaining raw private material merely because storage is cheap.

## 27. Implementation notes

### 27.1 Do not start with heavy cryptography theater

The first implementation does not need ceremony.

Minimum useful implementation:

```text
canonical event serialization
event hash
previous event hash
epoch digest manifest
anchor packet
interpretation profile hash
periodic validation script
external commitment option
```

The danger is not that v0.1 is too simple.

The danger is pretending that ordinary logs are already long-horizon witness.

### 27.2 Suggested local file layout

```text
docs/witness/long-horizon/
  Long_Horizon_Witness_Anchoring_and_Interpretation_Profile_v0_1.md
  schemas/
    long_horizon_witness_anchor_packet.schema.json
    witness_interpretation_profile.schema.json
    witness_interpretation_challenge_record.schema.json
    witness_anchor_validation_report.schema.json
    witness_audit_replay_record.schema.json
    witness_retention_pruning_record.schema.json
  fixtures/
    valid_anchor_packet_minimal.yaml
    valid_interpretation_challenge_policy_migration.yaml
    invalid_public_low_entropy_hash.yaml
    valid_audit_replay_policy_migration.yaml
    valid_retention_pruning_digest_only.yaml
  conformance/
    LHWAI_Test_Matrix_v0_1.md
```

### 27.3 Recommended integration points

| Corpus area | Integration action |
|---|---|
| L4 Witness | Add LHWAI as long-horizon companion, not replacement. |
| Audit tooling | Implement RP-0 through RP-2 before claiming independent validation. |
| Retention tooling | Emit pruning decision records before deleting or sealing witness material. |
| ARL | Reference challenge record for reinterpretation disputes. |
| Continuity Bundle | Require anchor validation before recovery/migration reliance. |
| CLI Agent Mesh | Use for package ledger, witness chain, incident, release, memory-gate anchors. |
| CCDP | Use for adult migration, sealed-zone witness, Red/Black review, conformance bundles. |
| GitHub / Zenodo releases | Use public digest/redacted manifest; avoid raw evidence. |
| Enterprise `c` | Use for work-bound audit trails, privilege changes, physical/financial actions. |

---

## 28. Open issues

| ID | Issue | Priority | Notes |
|---|---|---:|---|
| `OI-LHWAI-001` | Extract JSON schemas from YAML shapes | P1 | Needed before implementation-level conformance. |
| `OI-LHWAI-002` | Define exact canonicalization profile | P1 | JSON canonicalization recommended; profile must be concrete. |
| `OI-LHWAI-003` | Define signature/key custody policy | P1 | May belong in a separate Key Epoch Profile. |
| `OI-LHWAI-004` | Define public commitment policy per repo/DOI | P2 | Needed for release discipline. |
| `OI-LHWAI-005` | Define validator CLI | P2 | Local checker should verify chain + interpretation. |
| `OI-LHWAI-006` | Define redaction/public surface companion | P2 | Especially for incident, child, legal, and enterprise trails. |
| `OI-LHWAI-007` | Define storage refresh cadence | P2 | Important for offline continuity and bit rot. |
| `OI-LHWAI-009` | Define exact Merkle / inclusion proof encoding | P1 | Needed for interoperable event inclusion verification. |
| `OI-LHWAI-010` | Define retention / pruning jurisdiction overlays | P2 | Needed for child, legal, enterprise, and incident contexts. |
| `OI-LHWAI-008` | Map to Belgian/EU evidence and retention practice | P3 | Legal review only; not in protocol core. |

---

## 29. Contradiction and anti-duplication notes

### 29.1 No hard contradiction introduced

This profile should not contradict the existing stack because it narrows only the long-horizon treatment of witness trails.

It does not redefine parent mechanisms.

### 29.2 Main duplication risk

The main duplication risk is creating a second witness schema.

This profile avoids that by defining only:

```text
epochs
digests
anchor packets
interpretation profiles
challenge records
validation reports
```

It does not replace event families, CE/OP/CR/RN, ARL, or CCDP witness envelopes.

### 29.3 Main open tension

The main unresolved tension is between public verifiability and privacy.

The safe default is:

```text
public digest of redacted/high-entropy package
restricted raw sidecar
append-only challenge record
```

not:

```text
public raw witness trail
```

---

## 30. Closing rule

Long-lived `c` systems cannot rely on memory alone.

Memory adapts.

Witness anchors preserve the load-bearing past.

But anchoring only bytes is not enough.

The rule is:

```text
If a future system can read an old witness event,
it must also know which past rules made that event meaningful.

If it wants to change that meaning,
it must append a challenge record,
not rewrite the past.
```

Final compact form:

```text
No silent edits.
No silent reinterpretation.
No public raw leakage.
No self-exonerating agents.
No long-horizon claim without anchors.
```
