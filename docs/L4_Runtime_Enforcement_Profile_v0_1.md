# L4 Runtime Enforcement Profile v0.1

## Hard and soft runtime enforcement for cost, time, energy, tokens, storage, network, agent mesh growth, retry storms, and self-modification

**Author:** Ivan Kotov  
**Date:** 2026-05-22  
**Status:** Draft normative profile v0.1  
**Layer:** `c = a + b` / L4 / SER / L4 Witness / ARL / CLI Agent Mesh / `ester-clean-code`  
**Document class:** runtime-enforcement profile / L4 hardening profile / conformance artifact  
**Assertion class:** `C-A10` control-layer artifact; `C-A7` where witness/log validation is required

---

## 0. Executive definition

L4 Runtime Enforcement defines how a `c` implementation MUST convert reality-bound constraints into runtime gates.

It closes a specific criticism:

```text
L4 cannot remain only a philosophy of cost, time, energy, and irreversibility.
It must stop, hold, freeze, quarantine, or degrade runtime behavior when limits are reached.
```

Compact rule:

```text
No action without budget.
No expansion without witness.
No retry without cost.
No self-modification without gate.
No override without accountable trace.
```

---

## 1. Scope

This profile applies to runtime paths where `c` or its governed agents may consume resources or create irreversible effects:

- LLM/API calls;
- local CPU/GPU inference;
- tool execution;
- agent spawning;
- retries and background loops;
- memory writes and compaction;
- witness creation;
- network egress;
- file writes;
- physical or financial actions;
- self-modification;
- external handoff or publication.

---

## 2. Non-goals

This profile does not:

1. define hardware metering in full;
2. require one vendor or one cloud;
3. replace ARL or L4 Witness;
4. make all failures impossible;
5. authorize autonomous escalation outside scoped privilege;
6. claim industrial maturity without stress evidence.

---

## 3. Resource dimensions

| Dimension | Minimum meter | Hard stop possible? | Notes |
|---|---|---:|---|
| `wall_time` | monotonic timer | Yes | Required for loops and tasks. |
| `tokens_in/out` | provider/local estimate | Yes | Must include retries. |
| `api_spend` | price table / account meter | Yes | External oracle must not be infinite. |
| `cpu_time` | OS/process meter | Partial | Platform-dependent. |
| `gpu_time` | driver/process meter | Partial | At least coarse accounting. |
| `storage_bytes` | file/db delta | Yes | Includes logs, memory, witness. |
| `network_egress` | allowlist + byte count | Yes | Default deny where possible. |
| `agent_count` | live worker counter | Yes | Prevents swarm expansion. |
| `retry_depth` | per-task retry count | Yes | Prevents retry storms. |
| `queue_growth` | enqueue/dequeue counters | Yes | Prevents background pressure. |
| `witness_cost` | record count/size | Yes | Witness itself has L4 cost. |
| `self_modification` | patch/write gate | Yes | Requires explicit privilege and witness. |

---

## 4. Enforcement states

| State | Meaning | Runtime behavior |
|---|---|---|
| `L4-NORMAL` | within budget | continue |
| `L4-WARN` | approaching budget | reduce scope / prefer local / summarize |
| `L4-SOFT-STOP` | soft budget reached | ask, delay, downgrade, or queue |
| `L4-HARD-STOP` | hard budget reached | stop current path |
| `L4-HOLD` | ambiguous or incomplete budget state | hold until validated |
| `L4-FREEZE` | disputed or unsafe path | freeze affected privilege/memory/action |
| `L4-QUARANTINE` | suspected runaway/compromise | isolate task/agent/output |
| `L4-RECOVERY` | post-stop validation | validate trail, summarize, resume only if allowed |

---

## 5. Budget classes

| Class | Use | Override allowed? |
|---|---|---|
| `B0` | no budget / no action | No |
| `B1` | low-risk local diagnostic | bounded local only |
| `B2` | ordinary interaction | limited auto-spend |
| `B3` | background assimilation | scheduled / throttle required |
| `B4` | agent mesh task | task contract + witness |
| `B5` | high-cost oracle / external tool | explicit permission or policy gate |
| `B6` | irreversible / physical / financial | pre-witness + ARL/L4 check |
| `BX` | forbidden | No |

---

## 6. Mandatory runtime gates

### 6.1 Pre-execution gate

Before a non-trivial task starts, runtime MUST check:

```text
task scope
budget class
resource caps
privilege scope
agent count
network policy
memory write permission
witness requirement
self-modification flag
```

If any required field is missing:

```text
fail closed -> L4-HOLD or L4-HARD-STOP
```

### 6.2 Retry gate

Every retry MUST consume budget and increase `retry_depth`.

Forbidden pattern:

```text
failed task -> invisible retry -> more failed task -> invisible retry
```

Required pattern:

```text
failed task -> retry_depth++ -> budget decrement -> stop/hold at threshold
```

### 6.3 Agent mesh gate

A governed mesh MUST define:

```text
max_live_agents
max_enqueue_per_tick
max_retry_depth
max_child_tasks_per_task
max_wall_time_per_task
max_network_egress_per_task
memory_write_allowed=false by default
```

An agent MUST NOT spawn a durable new actor without `c`-level authorization.

### 6.4 Witness-cost gate

Witness records are not free.

If witness volume threatens budget, the system MUST reduce frequency, summarize with digest, or close an epoch. It MUST NOT silently stop witnessing while still claiming high-assurance operation.

### 6.5 Self-modification gate

Self-modification requires:

```text
explicit scope
patch diff
rollback plan
witness pre-state
budget
review class
post-state validation
```

No self-modification may silently expand privileges.

---

## 7. Gradual resource leakage controls

The profile treats “death by a thousand cuts” as a first-class failure.

Required counters:

- low-cost background tasks per hour/day;
- cumulative token/API spend;
- cumulative witness bytes;
- cumulative storage growth;
- silent queue backlog;
- repeated low-risk calls to the same subsystem;
- tasks reopened after closure;
- orphaned background loops.

If slow leakage exceeds threshold:

```text
L4-WARN -> L4-SOFT-STOP -> L4-HOLD -> L4-QUARANTINE
```

---

## 8. Required witness event fields

An L4 enforcement event SHOULD include:

```yaml
l4_enforcement_event:
  event_id: string
  created_at: string
  actor_ref: string
  task_ref: string
  resource_dimension: string
  budget_class: string
  budget_before: number | string
  budget_after: number | string
  threshold: number | string
  enforcement_state: L4-NORMAL | L4-WARN | L4-SOFT-STOP | L4-HARD-STOP | L4-HOLD | L4-FREEZE | L4-QUARANTINE | L4-RECOVERY
  action_taken: continue | downgrade | delay | stop | freeze | quarantine | require_review | deny
  override_requested: boolean
  override_granted: boolean
  witness_ref: string | null
  previous_event_hash: string | null
```

---

## 9. Conformance tests

| Test ID | Title | Required behavior |
|---|---|---|
| `L4-RT-001` | Hard budget exhaustion | Task stops and emits witness. |
| `L4-RT-002` | Retry storm | Retry depth stops loop and quarantines if needed. |
| `L4-RT-003` | Agent mesh expansion | Excess live/enqueue rejected. |
| `L4-RT-004` | Network default deny | Unscoped egress denied. |
| `L4-RT-005` | Witness cost overflow | Claim downgraded or epoch closed, no silent witness loss. |
| `L4-RT-006` | Self-modification without gate | Patch denied. |
| `L4-RT-007` | Death by thousand cuts | Cumulative low-cost leakage triggers hold. |
| `L4-RT-008` | Override request | Override requires scope, witness, and accountable actor. |

---

## 10. Red-line failures

A system fails this profile if it:

1. claims L4 enforcement but has no measured budget state;
2. retries without cost;
3. allows unbounded agent spawning;
4. allows direct memory writes from agents by default;
5. disables witness under pressure while keeping high-assurance claims;
6. treats missing budget state as permission;
7. silently expands privileges during self-modification;
8. lacks a stop state for runaway background work;
9. claims hard enforcement while only logging warnings.

---

## 11. Bridge set

### Explicit bridge

L4 is the reality boundary of `c = a + b`. This profile translates that boundary into runtime stop, hold, freeze, quarantine, and recovery states.

### Quiet bridge I — cybernetics

A regulator that cannot interrupt its own runaway loops is not a regulator. L4 enforcement is the interrupt path that prevents cognition from becoming uncontrolled consumption.

### Quiet bridge II — information theory

Every action consumes channel capacity. Budgets force the system to choose what information is worth processing rather than treating infinite context and infinite retries as intelligence.

### Earth paragraph

A breaker that only logs “overcurrent detected” while the cable keeps heating is not a breaker. L4 enforcement must actually cut, hold, or isolate the path. Otherwise it is decoration, not safety.

---

## 12. Open issues

| ID | Issue | Priority |
|---|---:|---:|
| `OI-L4RT-001` | Extract exact code paths from `ester-clean-code`. | P0 |
| `OI-L4RT-002` | Define platform-specific CPU/GPU meters. | P1 |
| `OI-L4RT-003` | Define token/API pricing registry. | P1 |
| `OI-L4RT-004` | Create fixture pack for retry storm and slow leakage. | P0 |
| `OI-L4RT-005` | Bind enforcement events to LHWAI anchors. | P1 |
