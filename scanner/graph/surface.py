from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class NodeKind(StrEnum):
    PAGE = "page"
    API = "api"
    FORM = "form"
    SCRIPT = "script"
    ROUTE = "route"
    PARAMETER = "parameter"
    AUTH = "auth"


@dataclass(frozen=True)
class SurfaceNode:
    id: str
    kind: NodeKind
    label: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SurfaceEdge:
    source: str
    target: str
    relation: str


@dataclass
class AttackSurfaceGraph:
    nodes: dict[str, SurfaceNode] = field(default_factory=dict)
    edges: list[SurfaceEdge] = field(default_factory=list)

    def add_node(self, kind: NodeKind, label: str, **metadata: str) -> str:
        node_id = f"{kind.value}:{label}"
        self.nodes.setdefault(node_id, SurfaceNode(id=node_id, kind=kind, label=label, metadata=metadata))
        return node_id

    def add_edge(self, source: str, target: str, relation: str) -> None:
        edge = SurfaceEdge(source=source, target=target, relation=relation)
        if edge not in self.edges:
            self.edges.append(edge)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for node in self.nodes.values():
            counts[node.kind.value] = counts.get(node.kind.value, 0) + 1
        counts["edges"] = len(self.edges)
        return counts
