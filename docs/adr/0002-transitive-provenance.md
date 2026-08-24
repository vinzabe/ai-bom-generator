# 2. Model the lineage as a DAG and analyse it transitively

Date: 2026-08-24
Status: Accepted

## Context
ML supply-chain risk is almost never in the artifact itself — it is inherited. A
model declared Apache-2.0 can be a fine-tune of a merge whose training data was
CC-BY-NC, or whose base weights have no declared origin. A flat component list
(the usual SBOM shape) records the declaration and misses the inheritance.

## Options considered
- **A. Flat component list with declared licenses.** Rejected: reports the
  artifact's own claim, which is precisely the thing that hides the problem.
- **B. One-level parent check.** Catches the immediate base model, misses anything
  deeper — and in practice the leaked/NC ancestor is 2-4 hops up.
- **C. Full transitive DAG analysis with hop distance (chosen).**

## Decision
Components carry `derived_from` edges. `ancestors()` does a cycle-safe BFS
returning each ancestor with its hop distance; `analyze()` flags restrictive
licenses, undeclared sources, and undeclared licenses anywhere in the lineage,
attributed to the specific ancestor and its distance. `effective_licenses()`
returns the union across the lineage — the set the artifact must comply with.

## Consequences
- Findings are actionable: "CC-BY-NC 1 hop up at research-corpus" tells you exactly
  what to replace.
- Hop distance lets a policy differentiate direct from distant inheritance.
- Cycle-safety is explicitly tested — a malformed graph terminates rather than
  hanging.
- Limitation: it analyses the graph you *declare*. An undeclared ancestor is
  invisible, which is why `undeclared-source` is itself a finding. Stated as the
  central non-goal in the threat model.
