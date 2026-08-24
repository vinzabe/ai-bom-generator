"""Load a component graph from JSON."""
from __future__ import annotations

import json
from pathlib import Path

from .model import Component, ComponentType, Graph


def load_graph(path: Path | str) -> Graph:
    data = json.loads(Path(path).read_text())
    comps = tuple(Component(
        id=c["id"], name=c["name"], type=ComponentType(c["type"]),
        version=c.get("version", "1.0"), license=c.get("license", ""),
        source=c.get("source", ""),
        derived_from=tuple(c.get("derived_from", [])))
        for c in data.get("components", []))
    return Graph(comps)
