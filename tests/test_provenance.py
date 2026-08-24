from pathlib import Path

from aibom.loader import load_graph
from aibom.provenance import analyze, ancestors, effective_licenses

G = load_graph(Path(__file__).parent / "fixtures" / "graph.json")


def test_transitive_ancestors_reach_root():
    ids = {c.id for c, _ in ancestors(G, "ship")}
    assert {"merge", "base", "leak", "clean-data", "nc-data"} <= ids


def test_hop_distance():
    hops = {c.id: h for c, h in ancestors(G, "ship")}
    assert hops["merge"] == 1 and hops["base"] == 2 and hops["leak"] == 3


def test_restrictive_license_flagged_transitively():
    findings = analyze(G, "ship")
    assert any(f.kind == "restrictive-license" and f.ancestor_id == "nc-data"
               for f in findings)


def test_undeclared_source_flagged():
    findings = analyze(G, "ship")
    assert any(f.kind == "undeclared-source" and f.ancestor_id == "leak"
               for f in findings)


def test_effective_licenses_union():
    lic = effective_licenses(G, "ship")
    assert "Apache-2.0" in lic and "CC-BY-NC-4.0" in lic


def test_cycle_safe():
    from aibom.model import Component, ComponentType, Graph
    a = Component("a", "a", ComponentType.MODEL, derived_from=("b",))
    b = Component("b", "b", ComponentType.MODEL, derived_from=("a",))
    # should terminate despite the cycle
    assert len(ancestors(Graph((a, b)), "a")) <= 2
