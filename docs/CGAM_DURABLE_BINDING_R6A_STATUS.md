# R6A durable local CGAM binding

Status: development candidate awaiting owner review.

The only implemented bridge is:

```text
CGAM current grant -> durable local binding journal -> consequence commit
```

The adapter accepts one UTF-8 payload, one exact target basename, a pinned R6A
task subset, and a pinned permission grant inside a monotonic authority
envelope.  Cooperative processes serialize through `.c_binding/binding.lock`.
The durable state is `.c_binding/binding_state.sqlite3`, with SQLite
`journal_mode=DELETE`, `synchronous=FULL`, `foreign_keys=ON`, an integrity check
on every open, and exactly four tables: `journal_meta`, `authority_heads`,
`attempts`, and `records`.

The atomic target replace is the effect linearization point.  A successful
return occurs only after terminal Runtime Consequence Integrity records are
committed and read back from that journal.  Process-exit recovery recognizes
only the recorded pre-state or the exact payload hash; every other target state
is quarantined and is never rolled back.

## Claim boundary

In scope: adapter process exit/restart, the same persistent journal, stale-grant
replay across processes, authority rollback/equivocation/revision-gap checks,
cooperative writers using the same lock, one target basename in a local
caller-created sandbox, and bounded durable record readback.

Out of scope: a malicious same-user writer bypassing the common lock; malicious
rollback, deletion, or editing of the trusted journal; administrator, kernel,
or hypervisor compromise; network filesystems; distributed authority; full
CGAM conformance; production enforcement; and TAP-SEC binding.

Python's standard library does not expose a supported directory `fsync` on
Windows.  The implementation records that limitation explicitly and makes no
physical power-loss atomicity claim from process-exit tests.  On POSIX it calls
directory `fsync` and records the result.

## Preserved source conflicts and minority objections

- The pinned CGAM prose and extracted machine schemas materially disagree on
  required task shape, permission schema version examples, and the shape of
  `capability_bindings`.  R6A validates a closed local subset and never calls it
  full CGAM conformance.
- Pinned CGAM prose makes authority inactive at `now >= expires_at`; the
  predecessor Runtime Consequence Integrity helper treats equality as valid.
  The binding gate fails closed at equality and emits `EXPIRED/DENY`; this is
  not described as semantic harmony.
- The thin Runtime Consequence Integrity adapter validates the supplied record
  schemas, semantics, and reciprocal direct links.  It does not claim complete
  registered-graph/evidence validation.  The binding journal separately binds
  and hash-checks its exact record inputs and stored bytes.
- Windows directory flush is unsupported by Python stdlib; ordinary atomic
  replacement can also change file identity/metadata.  Neither point is hidden
  by the content-hash consequence claim.

No merge, tag, release, DOI update, deployment, production claim, CGAM
repository mutation, or TAP-SEC binding is authorized by this status file.
