"""Vista da página inicial escolhida pela equipa: grelha ou mapa, e a posição de cada nó no mapa.

data_dir/layout.json, partilhado por toda a gente (decide-se uma vez como o SOC se vê). Os nós sem
posição guardada ficam numa posição automática, por camadas.
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any

VIEWS = ("grelha", "mapa")
NODE_W, NODE_H = 240, 250  # tamanho de referência de um nó, com folga para as ligações
GAP_X, GAP_Y = 48, 40
PER_ROW = 4  # nós por linha na posição automática (o mapa fica perto da proporção do ecrã)
_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,80}$")
MAX_COORD = 20_000


class LayoutStore:
    def __init__(self, data_dir: Path) -> None:
        self.path = Path(data_dir) / "layout.json"
        self._lock = threading.Lock()

    def read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        view = data.get("view") if data.get("view") in VIEWS else "grelha"
        positions = {}
        for k, v in (data.get("positions") or {}).items():
            if isinstance(v, dict) and _ID.match(str(k)):
                try:
                    positions[k] = {"x": int(v["x"]), "y": int(v["y"])}
                except (KeyError, TypeError, ValueError):
                    continue
        return {"view": view, "positions": positions}

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": 1, **data}, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)

    def set_view(self, view: str) -> None:
        if view not in VIEWS:
            raise ValueError("vista desconhecida")
        with self._lock:
            data = self.read()
            data["view"] = view
            self._write(data)

    def move(self, positions: dict[str, Any]) -> int:
        """Guarda as posições recebidas (só ids válidos e coordenadas dentro de limites)."""
        clean = {}
        for k, v in positions.items():
            if not _ID.match(str(k)) or not isinstance(v, dict):
                continue
            try:
                x, y = int(round(float(v["x"]))), int(round(float(v["y"])))
            except (KeyError, TypeError, ValueError):
                continue
            clean[k] = {"x": max(0, min(MAX_COORD, x)), "y": max(0, min(MAX_COORD, y))}
        with self._lock:
            data = self.read()
            data["positions"].update(clean)
            self._write(data)
        return len(clean)

    def reset(self) -> None:
        with self._lock:
            data = self.read()
            data["positions"] = {}
            self._write(data)


def place(inv: dict[str, Any], saved: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    """Posição de cada nó: a guardada, ou automática (uma linha por camada, externos no fim)."""
    rows: list[list[str]] = []
    for layer in inv["layers"]:
        ids = [n["id"] for n in layer["nodes"] if n["status"] != "off"]
        if ids:
            rows.append(ids)
    off = [n["id"] for n in inv["nodes"].values() if n["status"] == "off"]
    if off:
        rows.append(off)
    out: dict[str, dict[str, int]] = {}
    y = 0
    for row in rows:
        for start in range(0, len(row), PER_ROW):
            for i, nid in enumerate(row[start : start + PER_ROW]):
                out[nid] = {"x": i * (NODE_W + GAP_X), "y": y}
            y += NODE_H + GAP_Y
    ext = [e["id"] for e in inv["externals"]]
    for i, eid in enumerate(ext):
        out[eid] = {"x": (i % 6) * 190, "y": y + (i // 6) * 52}
    for k, v in saved.items():
        if k in out:
            out[k] = v
    return out
