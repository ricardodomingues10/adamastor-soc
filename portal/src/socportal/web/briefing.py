"""A "maré" do portal: o estado de todas as ferramentas do SOC numa frase simples.

O desenho do horizonte (wave_path) é o mesmo do VulnFlux, para as duas aplicações parecerem uma só.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

CALM, CHOPPY, STORM = "calm", "choppy", "storm"
SEA_LABEL = {CALM: "Mar calmo", CHOPPY: "Mar agitado", STORM: "Tempestade"}


@dataclass
class Todo:
    text: str
    href: str
    action: str
    level: str


@dataclass
class Briefing:
    level: str = CALM
    headline: str = ""
    sub: str = ""
    todo: list[Todo] = field(default_factory=list)

    @property
    def label(self) -> str:
        return SEA_LABEL[self.level]


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def build(inv: dict[str, Any]) -> Briefing:
    nodes = list(inv["nodes"].values())
    down = [n for n in nodes if n["status"] == "fail"]
    warn = [n for n in nodes if n["status"] == "warn"]
    outdated = [n for n in nodes if n.get("outdated")]
    todo: list[Todo] = []
    for n in down:
        todo.append(Todo(f"{n['name']} não está a responder", f"/s/{n['id']}", "Ver detalhe", STORM))
    for n in warn:
        msg = str(n["state"].message or "tem um aviso")
        msg = msg if len(msg) <= 70 else msg[:69] + "…"
        todo.append(Todo(f"{n['name']}: {msg}", f"/s/{n['id']}", "Ver detalhe", CHOPPY))
    if outdated:
        names = ", ".join(n["name"] for n in outdated[:3]) + (" e outras" if len(outdated) > 3 else "")
        todo.append(Todo(f"Há versão nova de {names}", "/estado", "Ver versões", CHOPPY))

    level = STORM if down else CHOPPY if todo else CALM
    b = Briefing(level=level, todo=todo)
    total = inv["total"]
    if level == CALM:
        b.headline = "Todas as ferramentas estão a funcionar."
        b.sub = (
            f"{_plural(total, 'ferramenta vigiada', 'ferramentas vigiadas')}, todas a responder e atualizadas."
            if total
            else "Ainda não há ferramentas ligadas. Começa por ligar a primeira."
        )
    elif level == STORM:
        b.headline = (
            f"{down[0]['name']} está em baixo." if len(down) == 1 else f"{len(down)} ferramentas estão em baixo."
        )
        b.sub = "As outras continuam a funcionar. Abre o detalhe para ver o erro e desde quando."
    else:
        b.headline = f"{_plural(len(todo), 'coisa precisa', 'coisas precisam')} de atenção."
        working = _plural(inv["active"], "ferramenta a funcionar", "ferramentas a funcionar")
        b.sub = f"{working} de {total}. Nada está em baixo."
    return b


def wave_path(level: str, width: int = 2400, height: int = 84, phase: float = 0.0, line: bool = False) -> str:
    amp = {CALM: 2.5, CHOPPY: 6.0, STORM: 10.0}.get(level, 2.5)
    waves = {CALM: 4, CHOPPY: 6, STORM: 10}.get(level, 4)
    base = height * (0.42 if line else 0.5)
    pts = []
    steps = 160
    for i in range(steps + 1):
        x = width * i / steps
        t = 2 * math.pi * waves * i / steps + phase
        y = base - amp * (math.sin(t) + 0.35 * math.sin(2 * t + 1.3))
        pts.append(f"{x:.1f},{y:.1f}")
    d = "M" + " L".join(pts)
    return d if line else f"{d} L{width},{height} L0,{height} Z"
