"""Ciclo de verificação: corre as probes, agrega o estado e regista as transições.

O portal não guarda nada que não possa reconstruir: o estado (state.json) e os eventos
servem para mostrar o último valor conhecido logo após um reinício e o histórico de
quedas/recuperações. Apagar o data_dir só faz perder esse histórico.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

from socportal.config import Settings
from socportal.probes import FAIL, OFF, OK, UNKNOWN, WARN, Prober, ProbeResult, norm_status, worst
from socportal.registry import PortalConfig, Registry, ServiceDef
from socportal.versions import LatestVersions, is_outdated

log = logging.getLogger(__name__)

MAX_EVENTS = 300


def utcnow() -> datetime:
    return datetime.now(UTC)


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def evaluate_freshness(item: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Recalcula a idade de uma lista/feed no momento em que é mostrada.

    ok até max_age_hours; aviso até 3x; depois falha. 'off' do produtor mantém-se
    (ex.: Greenbone on-demand adormecido: os feeds só atualizam na janela de scan).
    """
    now = now or utcnow()
    out = dict(item)
    updated = _parse_dt(item.get("updated_at"))
    max_age = item.get("max_age_hours")
    out["age_hours"] = round((now - updated).total_seconds() / 3600, 1) if updated else None
    producer = norm_status(item.get("status")) if item.get("status") else UNKNOWN
    if producer == OFF:
        out["status"] = OFF
    elif updated is not None and isinstance(max_age, int | float) and max_age > 0:
        age = out["age_hours"]
        out["status"] = OK if age <= max_age else (WARN if age <= 3 * max_age else FAIL)
        if producer == FAIL:  # o produtor sabe de um erro (ex.: download falhou hoje)
            out["status"] = worst([out["status"], WARN])
    else:
        out["status"] = producer
    return out


@dataclass
class ServiceState:
    id: str
    status: str = UNKNOWN
    message: str = "ainda não verificado"
    since: str | None = None
    checked_at: str | None = None
    version: str | None = None
    latency_ms: int | None = None
    probes: list[dict[str, Any]] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)
    freshness: list[dict[str, Any]] = field(default_factory=list)
    dependencies: dict[str, str] = field(default_factory=dict)
    jobs: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServiceState:
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


class Monitor:
    def __init__(
        self,
        settings: Settings,
        registry: Registry | None = None,
        prober: Prober | None = None,
        versions: LatestVersions | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry or Registry(settings.config_file, settings.data_dir / "services.json")
        self.prober = prober or Prober(settings, session)
        self.versions = versions or LatestVersions(settings, session)
        self.session = session or requests.Session()
        self.state_path = settings.data_dir / "state.json"
        self.events_path = settings.data_dir / "events.json"
        self.states: dict[str, ServiceState] = {}
        self.events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self.components: dict[str, dict[str, dict[str, Any]]] = {}
        self.last_cycle: str | None = None
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._load()

    @property
    def config(self) -> PortalConfig:
        return self.registry.config

    # ------------------------------------------------------------------ persistência
    def _load(self) -> None:
        try:
            data = json.loads(self.state_path.read_text())
            self.states = {k: ServiceState.from_dict(v) for k, v in data.get("services", {}).items()}
            self.last_cycle = data.get("last_cycle")
        except (OSError, ValueError, TypeError):
            self.states = {}
        with contextlib.suppress(OSError, ValueError, TypeError):
            self.events.extend(json.loads(self.events_path.read_text())[-MAX_EVENTS:])

    def _write(self, path: Path, payload: Any) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = Path(f"{path}.tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1, default=str))
            os.replace(tmp, path)
        except OSError:
            log.warning("não foi possível gravar %s", path)

    def _persist(self) -> None:
        self._write(
            self.state_path,
            {"last_cycle": self.last_cycle, "services": {k: v.to_dict() for k, v in self.states.items()}},
        )
        self._write(self.events_path, list(self.events))

    # ------------------------------------------------------------------ ciclo
    def run_once(self) -> dict[str, ServiceState]:
        self.registry.reload()
        config = self.config
        results: dict[str, list[ProbeResult]] = {s.id: [] for s in config.services}

        direct = [(s, p) for s in config.services for p in s.probes if p.type != "soc-component"]
        with ThreadPoolExecutor(max_workers=max(1, min(8, len(direct)))) as pool:
            futures = [(s.id, pool.submit(self.prober.run, s.resolve(p))) for s, p in direct]
            for sid, fut in futures:
                results[sid].append(fut.result())

        components: dict[str, dict[str, dict[str, Any]]] = {}
        for sid, res_list in results.items():
            for r in res_list:
                if r.components:
                    components.setdefault(sid, {}).update(r.components)
        for s in config.services:
            for p in s.probes:
                if p.type == "soc-component":
                    results[s.id].append(self.prober.run(p, components))

        now = utcnow().isoformat()
        with self._lock:
            self.components = components
            for s in config.services:
                self._apply(s, results[s.id], now)
            for gone in set(self.states) - {s.id for s in config.services}:
                del self.states[gone]
            self.last_cycle = now
        self._refresh_versions(config)
        self._persist()
        return self.states

    def _apply(self, service: ServiceDef, results: list[ProbeResult], now: str) -> None:
        prev = self.states.get(service.id)
        state = ServiceState(id=service.id)
        if not results:
            state.status, state.message = UNKNOWN, "sem verificações configuradas (só link)"
        else:
            state.status = worst([r.status for r in results])
            bad = next((r for r in results if r.status not in (OK, OFF)), None)
            state.message = (bad or results[0]).message
            if bad and len(results) > 1:
                state.message = f"{bad.probe}: {bad.message}"
        state.version = next((r.version for r in results if r.version), None)
        state.latency_ms = next((r.latency_ms for r in results if r.latency_ms is not None), None)
        state.probes = [r.to_dict() for r in results]
        state.checks = [c for r in results for c in r.checks]
        state.freshness = [f for r in results for f in r.freshness]
        state.dependencies = {k: v for r in results for k, v in r.dependencies.items()}
        state.jobs = [j for r in results for j in r.jobs]
        state.checked_at = now
        state.since = prev.since if prev and prev.status == state.status and prev.since else now
        self.states[service.id] = state
        old = prev.status if prev else UNKNOWN
        # Primeira verificação a dar ok não é notícia; a dar falha é.
        first_and_fine = old == UNKNOWN and state.status in (OK, OFF, UNKNOWN)
        if old != state.status and not first_and_fine:
            self._event(service, old, state)

    def _event(self, service: ServiceDef, old: str, state: ServiceState) -> None:
        event = {
            "at": state.checked_at,
            "service": service.id,
            "name": service.name,
            "from": old,
            "to": state.status,
            "message": state.message,
        }
        self.events.appendleft(event)
        levels = {FAIL} if self.settings.webhook_level == "fail" else {FAIL, WARN}
        if old in levels or state.status in levels:
            self._notify(event)

    def _notify(self, event: dict[str, Any]) -> None:
        url = self.settings.webhook_url.get_secret_value()
        if not url:
            return
        labels = {OK: "OK", WARN: "AVISO", FAIL: "EM BAIXO", OFF: "adormecido", UNKNOWN: "desconhecido"}
        text = f"[{labels.get(event['to'], event['to'])}] {event['name']}: {event['message']}"
        if event["to"] == OK:
            text = f"[RECUPERADO] {event['name']} (estava {labels.get(event['from'], event['from'])})"
        try:
            self.session.post(url, json={"text": text, **event}, timeout=10, verify=self.settings.verify())
        except requests.RequestException as exc:
            log.warning("webhook falhou: %s", exc.__class__.__name__)

    def _refresh_versions(self, config: PortalConfig) -> None:
        for s in config.services:
            if s.latest and s.latest.github and self.versions.due(s.latest.github):
                self.versions.refresh(s.latest.github)

    # ------------------------------------------------------------------ leitura (UI)
    def latest_for(self, service: ServiceDef) -> dict[str, Any] | None:
        if not (service.latest and service.latest.github):
            return None
        return self.versions.get(service.latest.github)

    def outdated(self, service: ServiceDef) -> bool | None:
        state = self.states.get(service.id)
        latest = self.latest_for(service)
        if not state or not latest or not latest.get("version"):
            return None
        return is_outdated(state.version, latest["version"])

    def state(self, service_id: str) -> ServiceState:
        return self.states.get(service_id) or ServiceState(id=service_id)

    def edges(self) -> list[dict[str, str]]:
        """Ligação S -> D. O estado é o que S reporta sobre D (se reportar), senão o de D."""
        out = []
        for s in self.config.services:
            reported = self.state(s.id).dependencies
            for dep in s.depends_on:
                status = reported.get(dep) or self.state(dep).status
                out.append({"from": s.id, "to": dep, "status": status})
        return out

    def freshness(self) -> list[dict[str, Any]]:
        now = utcnow()
        rows = []
        for s in self.config.services:
            for item in self.state(s.id).freshness:
                row = evaluate_freshness(item, now)
                row["service"], row["service_name"] = s.id, s.name
                rows.append(row)
        return rows

    def summary(self) -> dict[str, Any]:
        counts = {OK: 0, WARN: 0, FAIL: 0, OFF: 0, UNKNOWN: 0}
        outdated = 0
        for s in self.config.services:
            counts[self.state(s.id).status] = counts.get(self.state(s.id).status, 0) + 1
            if self.outdated(s):
                outdated += 1
        fresh = self.freshness()
        return {
            "counts": counts,
            "outdated": outdated,
            "stale_feeds": sum(1 for f in fresh if f["status"] in (WARN, FAIL)),
            "feeds": len(fresh),
            "last_cycle": self.last_cycle,
            "config_error": self.registry.error,
        }

    # ------------------------------------------------------------------ thread
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="sp-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def trigger(self) -> None:
        self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                log.exception("ciclo de verificação falhou")
            self._wake.wait(timeout=max(10, self.settings.poll_seconds))
            self._wake.clear()
