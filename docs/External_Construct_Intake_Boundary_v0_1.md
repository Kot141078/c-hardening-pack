# External Construct Intake Boundary v0.1

**Status:** Development governance note  
**Date:** 2026-08-27  
**Applies to:** research comparison, red-team intake, interface adaptation, formal dependency, and code reuse

## 1. Rule

External work enters the `c` corpus only through an artifact-specific record.

Topic overlap is not dependency.

Public engagement is not derivation.

Attribution is not ontology transfer.

A useful later test does not erase an earlier native antecedent.

## 2. Required intake fields

Every intake record must identify:

1. exact source artifact;
2. public date and persistent identifier where available;
3. exact construct, not a field-wide theme;
4. exact local target;
5. relation type;
6. transformation;
7. preserved properties;
8. rejected properties;
9. mapping failures;
10. terminology substitutions;
11. license status;
12. attribution;
13. native antecedents;
14. independent prior art;
15. claim ceiling.

## 3. Relation types

| Relation | Meaning |
|---|---|
| `COMPARISON_ONLY` | Used to compare boundaries; no local construct changed |
| `TEST_SURFACE_CATALYST` | A later external formulation caused a new fixture or red-team test |
| `FUNCTIONAL_ANALOG` | Similar function, independently implemented and differently situated |
| `INTERFACE_ADAPTATION` | A bounded interface shape is adapted with license clearance |
| `FORMAL_DEPENDENCY` | The local proof or implementation requires the external construct |
| `CODE_REUSE` | Source code is reused under an explicit compatible license |
| `NO_DEPENDENCY` | Record exists to close a public ambiguity and state non-dependency |

## 4. Claim discipline

The strongest relation must not be selected for rhetorical convenience.

For example:

```text
Later public paper sharpens an endpoint-equality test
  -> TEST_SURFACE_CATALYST

It does not automatically become:
  -> FORMAL_DEPENDENCY
```

Likewise:

```text
Two systems both revalidate authority before action
  -> possible FUNCTIONAL_ANALOG

It does not establish:
  -> common ontology
  -> derivation
  -> ownership transfer
```

## 5. Protected implementation rule

When an external repository declares restricted use or prohibits copying, derivation, reverse engineering, or deployment:

- inspect only public descriptive surfaces needed for comparison;
- do not copy code;
- do not recreate protected record layouts;
- do not infer hidden implementation details;
- preserve the limitation in the intake record;
- implement only independently derived native requirements.

## 6. Native antecedent rule

An intake record must not overwrite existing chronology.

Where the `c` corpus already contains the principle, the relation must say so.

Examples in this extension:

- AGL already requires commit-time revalidation;
- Initiation Gates already block stale legitimacy;
- Beacon and Continuity Bundle already separate continuity from resemblance and replay;
- Memory Gate already separates evidence, candidate memory, and durable memory;
- L4 already separates resource reality from narrative confidence.

A later external source may still be useful as:

- a sharper counterexample;
- a better negative fixture;
- a clearer limitation contract;
- an independent test vocabulary.

That is useful without becoming foundational dependency.

## 7. Terminology rule

External terms may appear in:

- source title;
- source-construct description;
- terminology-substitution table;
- comparison notes.

They must not silently become native canonical terms.

## 8. Earth paragraph

A structural engineer may learn a useful crack-test pattern from another laboratory. That does not mean the building, the load model, or the entire structural system derives from that laboratory.

The honest record says:

- which crack pattern was useful;
- which test was added;
- which standard already governed the building;
- which material assumptions do not transfer;
- and which claims remain outside the evidence.

The same discipline applies here.
