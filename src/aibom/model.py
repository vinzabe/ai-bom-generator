"""The component graph: models, datasets, and their provenance edges."""
from __future__ import annotations

import dataclasses
import enum


class ComponentType(enum.Enum):
    MODEL = "machine-learning-model"
    DATASET = "data"


@dataclasses.dataclass(frozen=True, slots=True)
class Component:
    id: str
    name: str
    type: ComponentType
    version: str = "1.0"
    license: str = ""            # SPDX id or "" if undeclared
    source: str = ""            # where it came from, "" if undeclared
    # ids of components this one is derived from (base models, training data)
    derived_from: tuple[str, ...] = ()

    @property
    def license_declared(self) -> bool:
        return bool(self.license)

    @property
    def source_declared(self) -> bool:
        return bool(self.source)


@dataclasses.dataclass(frozen=True, slots=True)
class Graph:
    components: tuple[Component, ...]

    def by_id(self) -> dict[str, Component]:
        return {c.id: c for c in self.components}

    def roots(self) -> tuple[Component, ...]:
        """Components nothing else derives from — the shippable artifacts."""
        referenced = {p for c in self.components for p in c.derived_from}
        return tuple(c for c in self.components if c.id not in referenced)
