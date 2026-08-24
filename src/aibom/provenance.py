"""Transitive provenance and license analysis.

The whole value is following derivation edges to the root, so a restrictive
license or undeclared origin several hops up is surfaced against the artifact you
actually ship.
"""
from __future__ import annotations

import dataclasses

from .model import Component, Graph

# Licenses that restrict commercial/derivative use — a finding if in the lineage
# of a model you intend to ship commercially.
RESTRICTIVE = frozenset({
    "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-ND-4.0", "GPL-3.0-only",
    "AGPL-3.0-only", "CC-BY-NC-ND-4.0", "research-only", "non-commercial",
})


@dataclasses.dataclass(frozen=True, slots=True)
class LineageFinding:
    component_id: str            # the artifact this affects
    kind: str                    # "restrictive-license" | "undeclared-source" | ...
    ancestor_id: str             # where in the lineage the issue is
    hops: int                    # distance from the artifact
    detail: str


def ancestors(graph: Graph, component_id: str) -> list[tuple[Component, int]]:
    """All transitive ancestors with their hop distance (cycle-safe)."""
    by_id = graph.by_id()
    out: list[tuple[Component, int]] = []
    seen: set[str] = set()
    start = by_id.get(component_id)
    if start is None:
        return []
    queue: list[tuple[str, int]] = [(pid, 1) for pid in start.derived_from]
    while queue:
        pid, hops = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        comp = by_id.get(pid)
        if comp is None:
            continue
        out.append((comp, hops))
        queue.extend((p, hops + 1) for p in comp.derived_from)
    return out


def analyze(graph: Graph, component_id: str) -> list[LineageFinding]:
    findings: list[LineageFinding] = []
    for comp, hops in ancestors(graph, component_id):
        if comp.license in RESTRICTIVE:
            findings.append(LineageFinding(
                component_id, "restrictive-license", comp.id, hops,
                f"{comp.name} is {comp.license} ({hops} hop(s) up)"))
        if not comp.source_declared:
            findings.append(LineageFinding(
                component_id, "undeclared-source", comp.id, hops,
                f"{comp.name} has no declared source ({hops} hop(s) up)"))
        if not comp.license_declared:
            findings.append(LineageFinding(
                component_id, "undeclared-license", comp.id, hops,
                f"{comp.name} has no declared license ({hops} hop(s) up)"))
    findings.sort(key=lambda f: f.hops)
    return findings


def effective_licenses(graph: Graph, component_id: str) -> set[str]:
    """Every license in the artifact's lineage — the set it must comply with."""
    by_id = graph.by_id()
    licenses = set()
    start = by_id.get(component_id)
    if start and start.license:
        licenses.add(start.license)
    for comp, _ in ancestors(graph, component_id):
        if comp.license:
            licenses.add(comp.license)
    return licenses
