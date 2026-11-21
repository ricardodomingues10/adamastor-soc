"""Ligações entre serviços alteradas na interface: data_dir/links.json.

O portal.yaml (e os serviços criados na interface) declaram as ligações; aqui fica o que se mudou
por cima disso, sem tocar no ficheiro: o "por onde" e o "o que passa" de uma ligação, ligações
novas e ligações escondidas do mapa. Cada ligação identifica-se por "origem>destino".
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

VIA_SUGGESTIONS = [
    "API REST",
    "soc-status/1",
    "SSH",
    "socket GMP",
    "HTTPS",
    "webhook",
    "base de dados",
    "ficheiro partilhado",
    "syslog",
    "e-mail",
]


def key(a: str, b: str) -> str:
    return f"{a}>{b}"


class LinkStore:
    def __init__(self, data_dir: Path) -> None:
        self.path = Path(data_dir) / "links.json"
        self._lock = threading.Lock()

    def read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        return {
            "changes": dict(data.get("changes") or {}),
            "removed": list(data.get("removed") or []),
            "added": list(data.get("added") or []),
        }

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": 1, **data}, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)

    def save(self, a: str, b: str, via: str, what: str, *, declared: bool) -> None:
        """Altera uma ligação existente (declared) ou acrescenta uma nova."""
        via, what = via.strip()[:60] or "API REST", what.strip()[:200]
        with self._lock:
            data = self.read()
            k = key(a, b)
            data["removed"] = [r for r in data["removed"] if r != k]
            if declared:
                data["changes"][k] = {"via": via, "what": what}
            else:
                data["added"] = [x for x in data["added"] if key(x["from"], x["to"]) != k]
                data["added"].append({"from": a, "to": b, "via": via, "what": what})
            self._write(data)

    def remove(self, a: str, b: str) -> None:
        with self._lock:
            data = self.read()
            k = key(a, b)
            before = len(data["added"])
            data["added"] = [x for x in data["added"] if key(x["from"], x["to"]) != k]
            if len(data["added"]) == before and k not in data["removed"]:
                data["removed"].append(k)  # declarada no portal.yaml: só se esconde
            data["changes"].pop(k, None)
            self._write(data)

    def restore(self, a: str, b: str) -> None:
        """Volta ao que está declarado (desfaz alterações e reaparece se estava escondida)."""
        with self._lock:
            data = self.read()
            k = key(a, b)
            data["changes"].pop(k, None)
            data["removed"] = [r for r in data["removed"] if r != k]
            self._write(data)
