"""Emit a CycloneDX-ML (1.5) SBOM document from the component graph.

CycloneDX is the de-facto SBOM standard; the 1.5 spec adds ML-BOM component types
(machine-learning-model, data). We emit the subset that captures components,
licenses, and provenance dependencies.
"""
from __future__ import annotations

import json

from .model import Graph


def to_cyclonedx(graph: Graph) -> dict[str, object]:
    components = []
    dependencies = []
    for c in graph.components:
        comp: dict[str, object] = {
            "type": c.type.value, "bom-ref": c.id, "name": c.name,
            "version": c.version,
        }
        if c.license:
            comp["licenses"] = [{"license": {"id": c.license}}]
        if c.source:
            comp["externalReferences"] = [
                {"type": "distribution", "url": c.source}]
        components.append(comp)
        if c.derived_from:
            dependencies.append({"ref": c.id, "dependsOn": list(c.derived_from)})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"tools": [{"name": "aibom", "version": "1.0.0"}]},
        "components": components,
        "dependencies": dependencies,
    }


def to_json(graph: Graph) -> str:
    return json.dumps(to_cyclonedx(graph), indent=2)
