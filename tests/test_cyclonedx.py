from pathlib import Path

from aibom.cyclonedx import to_cyclonedx
from aibom.loader import load_graph

G = load_graph(Path(__file__).parent / "fixtures" / "graph.json")


def test_valid_cyclonedx_shape():
    doc = to_cyclonedx(G)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert len(doc["components"]) == 6


def test_ml_component_types_present():
    doc = to_cyclonedx(G)
    types = {c["type"] for c in doc["components"]}
    assert "machine-learning-model" in types and "data" in types


def test_dependencies_capture_provenance():
    doc = to_cyclonedx(G)
    deps = {d["ref"]: set(d["dependsOn"]) for d in doc["dependencies"]}
    assert deps["ship"] == {"merge", "nc-data"}


def test_licenses_emitted():
    doc = to_cyclonedx(G)
    base = next(c for c in doc["components"] if c["bom-ref"] == "base")
    assert base["licenses"][0]["license"]["id"] == "Apache-2.0"
