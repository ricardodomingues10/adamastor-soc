"""Armazenamento em ficheiros JSON (sem base de dados).

Estrutura em data_dir:
    hosts.json              lista de hosts
    state.json              estado auxiliar (saúde das dependências, Greenbone, lotes)
    servers/<host_id>.json  último relatório de cada servidor + histórico curto (tendências)
    patch_cycles.json       ciclos de atualização por anéis
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
from bisect import bisect_left, insort
from collections.abc import Iterable, Iterator
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


def _order_key(run: Run) -> tuple[Any, str]:
    return (run.created_at, run.id)


_STATE_KEY = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,80}$")


def _dump(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str).encode("utf-8")


class JsonStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.runs_dir = self.data_dir / "runs"
        self.artifacts_dir = self.data_dir / "artifacts"
        self._hosts_path = self.data_dir / "hosts.json"
        self._state_path = self.data_dir / "state.json"  # formato antigo: migrado para state/ no arranque
        self._state_dir = self.data_dir / "state"
        self._lock = threading.RLock()
        self._hosts: dict[str, Host] = {}
        self._runs: dict[str, Run] = {}
        # Índices por data (do mais antigo para o mais recente): o painel pede "a última execução de cada
        # host e fonte" centenas de vezes por página; sem índice era um varrimento completo de cada vez.
        self._order: list[Run] = []
        self._by_key: dict[tuple[str, Source], list[Run]] = {}
        self._state: dict[str, Any] = {}
        for d in (self.data_dir, self.runs_dir, self.artifacts_dir, self._state_dir):
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
            self._load_state()
            for path in self.runs_dir.glob("*.json"):
                try:
                    run = Run.model_validate_json(path.read_text("utf-8"))
                except (ValueError, OSError):
                    # Ficheiro corrompido/manual: não impede o arranque.
                    continue
                self._runs[run.id] = run
            self._reindex()

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        """Para "ler, decidir e gravar" sem que outra thread grave pelo meio (o lock é reentrante)."""
        with self._lock:
            yield

    # ------------------------------------------------------------------ índices
    def _reindex(self) -> None:
        self._order = sorted(self._runs.values(), key=_order_key)
        self._by_key = {}
        for run in self._order:
            self._by_key.setdefault((run.host_id, run.source), []).append(run)

    @staticmethod
    def _remove_from(items: list[Run], run: Run) -> None:
        i = bisect_left(items, _order_key(run), key=_order_key)
        while i < len(items) and _order_key(items[i]) == _order_key(run):
            if items[i].id == run.id:
                del items[i]
                return
            i += 1

    def _index_add(self, run: Run) -> None:
        insort(self._order, run, key=_order_key)
        insort(self._by_key.setdefault((run.host_id, run.source), []), run, key=_order_key)

    def _index_remove(self, run: Run) -> None:
        self._remove_from(self._order, run)
        self._remove_from(self._by_key.get((run.host_id, run.source), []), run)

    def _matching(
        self,
        host_id: str | None,
        source: Source | None,
        status_set: set[RunStatus] | None,
        error_kind: ErrorKind | None,
    ) -> Iterator[Run]:
        """Execuções que passam o filtro, da mais recente para a mais antiga (sem cópias)."""
        base = self._by_key.get((host_id, source), []) if host_id is not None and source is not None else self._order
        for r in reversed(base):
            if (
                (host_id is None or r.host_id == host_id)
                and (source is None or r.source == source)
                and (status_set is None or r.status in status_set)
                and (error_kind is None or r.error_kind == error_kind)
            ):
                yield r

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
            old = self._runs.get(run.id)
            if old is not None:
                self._index_remove(old)
            stored = run.model_copy(deep=True)
            self._runs[run.id] = stored
            self._index_add(stored)
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
            out: list[Run] = []
            skipped = 0
            for r in self._matching(host_id, source, status_set, error_kind):
                if skipped < offset:
                    skipped += 1
                    continue
                out.append(r.model_copy(deep=True))
                if limit is not None and len(out) >= limit:
                    break
            return out

    def count_runs(
        self,
        *,
        host_id: str | None = None,
        source: Source | None = None,
        statuses: Iterable[RunStatus] | None = None,
        error_kind: ErrorKind | None = None,
    ) -> int:
        status_set = set(statuses) if statuses else None
        with self._lock:
            return sum(1 for _ in self._matching(host_id, source, status_set, error_kind))

    def last_run(self, host_id: str, source: Source, *, good_only: bool = False) -> Run | None:
        statuses = [RunStatus.SUCCESS, RunStatus.WARNING] if good_only else None
        runs = self.list_runs(host_id=host_id, source=source, statuses=statuses, limit=1)
        return runs[0] if runs else None

    def latest_matrix(self) -> dict[tuple[str, Source], Run]:
        """Última execução por (host, fonte), para a matriz do dashboard."""
        with self._lock:
            return {k: runs[-1].model_copy(deep=True) for k, runs in self._by_key.items() if runs}

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
                    self._index_remove(run)
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

    # ------------------------------------------------------------------ servidores
    SERVER_HISTORY = 120  # verificações guardadas por servidor (30 dias a cada 6 h)

    def _server_path(self, host_id: str) -> Path:
        if not _SAFE_NAME.match(host_id):
            raise ValueError(f"id inválido: {host_id!r}")
        return self.data_dir / "servers" / f"{host_id}.json"

    def get_server(self, host_id: str) -> dict[str, Any]:
        """{"report": último relatório ou None, "history": [...], "unreachable": {...} ou None}."""
        with self._lock:
            path = self._server_path(host_id)
            if not path.exists():
                return {"report": None, "history": [], "unreachable": None}
            try:
                return json.loads(path.read_text("utf-8"))
            except (ValueError, OSError):
                return {"report": None, "history": [], "unreachable": None}

    def save_server_report(self, host_id: str, report: dict[str, Any]) -> None:
        with self._lock:
            data = self.get_server(host_id)
            data["report"] = report
            data["unreachable"] = None
            m = report.get("metrics") or {}
            point = {
                "at": report.get("checked_at"),
                "status": report.get("status"),
                "score": report.get("score"),
                "mem": m.get("mem_pct"),
                "disk": m.get("disk_max_pct"),
                "load": m.get("load_per_cpu"),
                "sec": (report.get("updates") or {}).get("security"),
                "upd": (report.get("updates") or {}).get("total"),
            }
            data["history"] = ([*data.get("history", []), point])[-self.SERVER_HISTORY :]
            _atomic_write(self._server_path(host_id), _dump(data))

    def mark_server_unreachable(self, host_id: str, message: str, at: Any) -> None:
        with self._lock:
            data = self.get_server(host_id)
            data["unreachable"] = {"message": message, "at": str(at)}
            data["history"] = ([*data.get("history", []), {"at": str(at), "status": "fail"}])[-self.SERVER_HISTORY :]
            _atomic_write(self._server_path(host_id), _dump(data))

    def delete_server(self, host_id: str) -> None:
        with self._lock, contextlib.suppress(FileNotFoundError, ValueError):
            self._server_path(host_id).unlink()

    def list_cycles(self) -> list[dict[str, Any]]:
        with self._lock:
            path = self.data_dir / "patch_cycles.json"
            if not path.exists():
                return []
            try:
                return json.loads(path.read_text("utf-8")).get("cycles", [])
            except (ValueError, OSError):
                return []

    def get_cycle(self, cycle_id: str) -> dict[str, Any] | None:
        return next((c for c in self.list_cycles() if c.get("id") == cycle_id), None)

    def save_cycle(self, cycle: dict[str, Any], keep: int = 30) -> None:
        with self._lock:
            cycles = [c for c in self.list_cycles() if c.get("id") != cycle.get("id")]
            cycles.insert(0, json.loads(json.dumps(cycle, default=str)))
            cycles.sort(key=lambda c: c.get("created_at") or "", reverse=True)
            _atomic_write(self.data_dir / "patch_cycles.json", _dump({"version": 1, "cycles": cycles[:keep]}))

    # ------------------------------------------------------------------ estado
    # Um ficheiro por chave em state/: gravar o estado do vigilante não reescreve a saúde, o inventário
    # WordPress e tudo o resto (antes era um state.json único, reescrito inteiro a cada alteração).
    def _state_file(self, key: str) -> Path:
        if not _STATE_KEY.match(key):
            raise ValueError(f"chave de estado inválida: {key!r}")
        return self._state_dir / f"{key}.json"

    def _load_state(self) -> None:
        if self._state_path.exists():
            try:
                old = json.loads(self._state_path.read_text("utf-8"))
            except (ValueError, OSError):
                old = {}
            for key, value in old.items() if isinstance(old, dict) else []:
                if _STATE_KEY.match(key) and not self._state_file(key).exists():
                    _atomic_write(self._state_file(key), _dump(value))
            self._state_path.replace(self._state_path.with_name("state.json.migrado"))
        for path in self._state_dir.glob("*.json"):
            try:
                self._state[path.stem] = json.loads(path.read_text("utf-8"))
            except (ValueError, OSError):
                continue  # uma chave corrompida não impede o arranque

    def get_state(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return json.loads(json.dumps(self._state.get(key, default), default=str))

    def set_state(self, key: str, value: Any) -> None:
        data = json.loads(json.dumps(value, default=str))
        payload = _dump(data)  # serializa fora do lock
        with self._lock:
            self._state[key] = data
            _atomic_write(self._state_file(key), payload)
