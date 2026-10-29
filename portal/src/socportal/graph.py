"""Disposição do grafo de dependências (SVG desenhado no template, sem JavaScript).

Camadas por profundidade: quem depende de outros fica em cima, as dependências em
baixo. Chega para as dezenas de serviços de um SOC; não é um motor de grafos.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

NODE_W, NODE_H, GAP_X, GAP_Y, PAD = 176, 50, 28, 74, 16


@dataclass
class Node:
    id: str
    name: str
    status: str
    x: float
    y: float

    @property
    def cx(self) -> float:
        return self.x + NODE_W / 2


def _depths(deps: dict[str, list[str]]) -> dict[str, int]:
    memo: dict[str, int] = {}

    def depth(node: str, stack: frozenset[str]) -> int:
        if node in memo:
            return memo[node]
        children = [d for d in deps.get(node, []) if d in deps and d not in stack]
        value = 0 if not children else 1 + max(depth(c, stack | {node}) for c in children)
        memo[node] = value
        return value

    for n in deps:
        depth(n, frozenset())
    return memo


def layout(services: list[Any], states: dict[str, str], edges: list[dict[str, str]]) -> dict[str, Any]:
    deps = {s.id: list(s.depends_on) for s in services}
    depths = _depths(deps)
    top = max(depths.values(), default=0)
    rows: dict[int, list[Any]] = {}
    for s in services:
        rows.setdefault(top - depths[s.id], []).append(s)
    widest = max((len(r) for r in rows.values()), default=1)
    width = PAD * 2 + widest * NODE_W + (widest - 1) * GAP_X
    nodes: dict[str, Node] = {}
    for row_idx in sorted(rows):
        row = rows[row_idx]
        row_w = len(row) * NODE_W + (len(row) - 1) * GAP_X
        x0 = (width - row_w) / 2
        for i, s in enumerate(row):
            nodes[s.id] = Node(
                s.id, s.name, states.get(s.id, "unknown"), x0 + i * (NODE_W + GAP_X), PAD + row_idx * (NODE_H + GAP_Y)
            )
    paths = []
    for e in edges:
        a, b = nodes.get(e["from"]), nodes.get(e["to"])
        if not a or not b:
            continue
        x1, y1 = a.cx, a.y + NODE_H
        x2, y2 = b.cx, b.y
        if y2 <= y1:  # mesma linha (ciclo): liga pelos lados
            x1, y1, x2, y2 = a.x + NODE_W, a.y + NODE_H / 2, b.x, b.y + NODE_H / 2
            d = f"M{x1:.0f} {y1:.0f} L{x2:.0f} {y2:.0f}"
        else:
            mid = (y1 + y2) / 2
            d = f"M{x1:.0f} {y1:.0f} C{x1:.0f} {mid:.0f} {x2:.0f} {mid:.0f} {x2:.0f} {y2 - 4:.0f}"
        paths.append({"d": d, "status": e["status"], "from": e["from"], "to": e["to"]})
    height = PAD * 2 + (len(rows) or 1) * NODE_H + (max(len(rows) - 1, 0)) * GAP_Y
    return {
        "width": width,
        "height": height,
        "nodes": list(nodes.values()),
        "edges": paths,
        "node_w": NODE_W,
        "node_h": NODE_H,
    }
