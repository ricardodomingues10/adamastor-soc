"""Armazenamento em ficheiros JSON (sem base de dados).

Estrutura em data_dir:
    hosts.json              lista de hosts
    state.json              estado auxiliar (saúde das dependências, Greenbone, lotes)
    runs/<id>.json          uma execução por ficheiro
    artifacts/<id>/...      ficheiros brutos de cada execução (raw, convertido, resposta DD)

Todas as escritas são atómicas (ficheiro temporário + fsync + os.replace): um crash a
meio nunca deixa um JSON truncado. O acesso é serializado com um lock, por isso a
aplicação deve correr num único processo (o scheduler também vive nele).

A interface pública (métodos desta classe) é o contrato para uma futura versão com
Postgres: trocar a implementação não deve obrigar a mexer no resto.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
import threading
from collections.abc import Iterable
from datetime import timedelta
from pathlib import Path
from typing import Any

from vulnflux.errors import ErrorKind
from vulnflux.models import Host, Run, RunStatus, Source, utcnow

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")


class DuplicateHostError(ValueError):
    pass


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _dump(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str).encode("utf-8")


class JsonStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.runs_dir = self.data_dir / "runs"
        self.artifacts_dir = self.data_dir / "artifacts"
        self._hosts_path = self.data_dir / "hosts.json"
        self._state_path = self.data_dir / "state.json"
        self._lock = threading.RLock()
        self._hosts: dict[str, Host] = {}
        self._runs: dict[str, Run] = {}
        self._state: dict[str, Any] = {}
        for d in (self.data_dir, self.runs_dir, self.artifacts_dir):
            d.mkdir(parents=True, exist_ok=True)
        self._load()

    # ------------------------------------------------------------------ carga
    def _load(self) -> None:
        with self._lock:
            if self._hosts_path.exists():
                raw = json.loads(self._hosts_path.read_text("utf-8"))
                for item in raw.get("hosts", []):
                    host = Host.model_validate(item)
                    self._hosts[host.id] = host
            if self._state_path.exists():
                self._state = json.loads(self._state_path.read_text("utf-8"))
            for path in self.runs_dir.glob("*.json"):
                try:
                    run = Run.model_validate_json(path.read_text("utf-8"))
                except (ValueError, OSError):
                    # Ficheiro corrompido/manual: não impede o arranque.
                    continue
                self._runs[run.id] = run

    # ------------------------------------------------------------------ hosts
    def _persist_hosts(self) -> None:
        hosts = sorted(self._hosts.values(), key=lambda h: h.name)
        _atomic_write(self._hosts_path, _dump({"version": 1, "hosts": [h.model_dump(mode="json") for h in hosts]}))

    def list_hosts(self) -> list[Host]:
        with self._lock:
            return sorted((h.model_copy() for h in self._hosts.values()), key=lambda h: h.name)

    def get_host(self, host_id: str) -> Host | None:
        with self._lock:
            host = self._hosts.get(host_id)
            return host.model_copy() if host else None

    def get_host_by_name(self, name: str) -> Host | None:
        with self._lock:
            for host in self._hosts.values():
                if host.name == name:
                    return host.model_copy()
            return None

    def save_host(self, host: Host) -> Host:
        with self._lock:
            for other in self._hosts.values():
                if other.name == host.name and other.id != host.id:
                    raise DuplicateHostError(f"já existe um host com o nome {host.name}")
            host = host.model_copy(update={"updated_at": utcnow()})
            self._hosts[host.id] = host
            self._persist_hosts()
            return host.model_copy()

    def save_hosts(self, hosts: Iterable[Host]) -> list[Host]:
        """Grava vários hosts numa única escrita (importação em lote)."""
        with self._lock:
            saved = []
            names = {h.name: h.id for h in self._hosts.values()}
            for host in hosts:
                if host.name in names and names[host.name] != host.id:
                    raise DuplicateHostError(f"já existe um host com o nome {host.name}")
                host = host.model_copy(update={"updated_at": utcnow()})
                self._hosts[host.id] = host
                names[host.name] = host.id
                saved.append(host.model_copy())
            self._persist_hosts()
            return saved

    def delete_host(self, host_id: str) -> bool:
        with self._lock:
            if self._hosts.pop(host_id, None) is None:
                return False
            self._persist_hosts()
            return True

    # ------------------------------------------------------------------ runs
    def save_run(self, run: Run) -> Run:
        with self._lock:
            self._runs[run.id] = run.model_copy(deep=True)
            _atomic_write(self.runs_dir / f"{run.id}.json", run.model_dump_json(indent=2).encode("utf-8"))
            return run

    def get_run(self, run_id: str) -> Run | None:
        with self._lock:
            run = self._runs.get(run_id)
            return run.model_copy(deep=True) if run else None

    def list_runs(
        self,
        *,
        host_id: str | None = None,
        source: Source | None = None,
        statuses: Iterable[RunStatus] | None = None,
        error_kind: ErrorKind | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Run]:
        status_set = set(statuses) if statuses else None
        with self._lock:
            runs = [
                r
                for r in self._runs.values()
                if (host_id is None or r.host_id == host_id)
                and (source is None or r.source == source)
                and (status_set is None or r.status in status_set)
                and (error_kind is None or r.error_kind == error_kind)
            ]
            runs.sort(key=lambda r: r.created_at, reverse=True)
            sliced = runs[offset : offset + limit if limit is not None else None]
            return [r.model_copy(deep=True) for r in sliced]

    def count_runs(self, **filters: Any) -> int:
        return len(self.list_runs(**filters))

    def last_run(self, host_id: str, source: Source, *, good_only: bool = False) -> Run | None:
        statuses = [RunStatus.SUCCESS, RunStatus.WARNING] if good_only else None
        runs = self.list_runs(host_id=host_id, source=source, statuses=statuses, limit=1)
        return runs[0] if runs else None

    def latest_matrix(self) -> dict[tuple[str, Source], Run]:
        """Última execução por (host, fonte), para a matriz do dashboard."""
        with self._lock:
            latest: dict[tuple[str, Source], Run] = {}
            for run in self._runs.values():
                key = (run.host_id, run.source)
                if key not in latest or run.created_at > latest[key].created_at:
                    latest[key] = run
            return {k: v.model_copy(deep=True) for k, v in latest.items()}

    def active_run(self, host_id: str, source: Source) -> Run | None:
        runs = self.list_runs(host_id=host_id, source=source, statuses=[RunStatus.QUEUED, RunStatus.RUNNING], limit=1)
        return runs[0] if runs else None

    def recover_interrupted(self) -> int:
        """No arranque: execuções que estavam em curso quando o processo parou."""
        count = 0
        for run in self.list_runs(statuses=[RunStatus.QUEUED, RunStatus.RUNNING]):
            run.status = RunStatus.INTERRUPTED
            run.error_kind = ErrorKind.TRANSIENT
            run.error_message = "O VulnFlux reiniciou durante a execução"
            run.finished_at = utcnow()
            self.save_run(run)
            count += 1
        return count

    def purge_older_than(self, days: int) -> int:
        cutoff = utcnow() - timedelta(days=days)
        removed = 0
        with self._lock:
            for run in list(self._runs.values()):
                if run.created_at < cutoff and run.status.finished:
                    self._runs.pop(run.id, None)
                    (self.runs_dir / f"{run.id}.json").unlink(missing_ok=True)
                    adir = self.artifacts_dir / run.id
                    if adir.is_dir():
                        for f in adir.iterdir():
                            f.unlink(missing_ok=True)
                        adir.rmdir()
                    removed += 1
        return removed

    # ------------------------------------------------------------------ artefactos
    def write_artifact(self, run_id: str, name: str, data: bytes) -> str:
        if not _SAFE_NAME.match(name) or not _SAFE_NAME.match(run_id):
            raise ValueError(f"nome de artefacto inválido: {name!r}")
        _atomic_write(self.artifacts_dir / run_id / name, data)
        return name

    def artifact_path(self, run_id: str, name: str) -> Path | None:
        """Caminho seguro para um artefacto (sem path traversal)."""
        if not _SAFE_NAME.match(name) or not _SAFE_NAME.match(run_id):
            return None
        path = (self.artifacts_dir / run_id / name).resolve()
        if self.artifacts_dir.resolve() not in path.parents or not path.is_file():
            return None
        return path

    # ------------------------------------------------------------------ estado
    def get_state(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return json.loads(json.dumps(self._state.get(key, default), default=str))

    def set_state(self, key: str, value: Any) -> None:
        with self._lock:
            self._state[key] = json.loads(json.dumps(value, default=str))
            _atomic_write(self._state_path, _dump(self._state))
