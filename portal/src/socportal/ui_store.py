"""Serviços criados na interface: data_dir/services.json + credenciais em data_dir/secrets/.

As credenciais escritas no formulário ficam num ficheiro por probe (0600) e o serviço
guarda só a referência (token_file), como no portal.yaml. Nunca voltam a aparecer na
interface. Em produção, preferir Docker secrets e o portal.yaml.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from socportal.registry import PortalConfig, RegistryError, ServiceDef, _short


class ServiceStore:
    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / "services.json"
        self.secrets_dir = data_dir / "secrets"
        self._lock = threading.Lock()

    def _read(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as exc:
            raise RegistryError(f"{self.path} ilegível: {exc}") from exc
        return list(data.get("services", [])) if isinstance(data, dict) else []

    def _write(self, services: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": 1, "services": services}, indent=2, ensure_ascii=False))
        os.replace(tmp, self.path)

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._read()

    def get(self, service_id: str) -> dict[str, Any] | None:
        return next((s for s in self.list() if s.get("id") == service_id), None)

    def secret_path(self, service_id: str, index: int) -> Path:
        return self.secrets_dir / f"{service_id}.{index}.token"

    def write_secret(self, service_id: str, index: int, value: str) -> str:
        self.secrets_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.secret_path(service_id, index)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(value.strip())
        return str(path)

    def drop_secrets(self, service_id: str, keep: set[int] | None = None) -> None:
        if not self.secrets_dir.exists():
            return
        for path in self.secrets_dir.glob(f"{service_id}.*.token"):
            idx = path.name.split(".")[-2]
            if keep is None or not idx.isdigit() or int(idx) not in keep:
                path.unlink(missing_ok=True)

    def save(self, service: ServiceDef, current: PortalConfig, *, replace: str | None = None) -> None:
        """Valida o serviço junto com todos os outros (ids únicos, dependências) e grava."""
        with self._lock:
            items = [s for s in self._read() if s.get("id") != (replace or service.id)]
            data = service.model_dump(exclude={"origin"}, exclude_none=True)
            others = [s.model_dump() for s in current.services if s.origin == "file"]
            others += [{**s, "origin": "ui"} for s in items]
            try:
                PortalConfig.model_validate({"services": [*others, {**data, "origin": "ui"}]})
            except ValueError as exc:
                raise RegistryError(_short(exc)) from exc
            items.append(data)
            self._write(items)

    def delete(self, service_id: str) -> bool:
        with self._lock:
            items = self._read()
            kept = [s for s in items if s.get("id") != service_id]
            if len(kept) == len(items):
                return False
            # Quem dependia dele deixa de depender (senão a configuração ficava inválida)
            for s in kept:
                if service_id in s.get("depends_on", []):
                    s["depends_on"] = [d for d in s["depends_on"] if d != service_id]
            self._write(kept)
        self.drop_secrets(service_id)
        return True
