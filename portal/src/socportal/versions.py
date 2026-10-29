"""Versão mais recente de cada serviço (releases do GitHub), em cache no data_dir.

Consultado poucas vezes por dia: sem token o GitHub permite 60 pedidos/hora por IP.
Sem acesso à Internet a comparação fica "desconhecida" e nada mais é afetado.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import requests
from packaging.version import InvalidVersion, Version

from socportal.config import Settings

log = logging.getLogger(__name__)


def clean(tag: str | None) -> str | None:
    if not tag:
        return None
    tag = tag.strip()
    for prefix in ("release-", "release/", "v", "V"):
        if tag.startswith(prefix):
            tag = tag[len(prefix) :]
    return tag or None


def is_outdated(current: str | None, latest: str | None) -> bool | None:
    """True/False quando as duas versões são comparáveis; None quando não são."""
    try:
        cur = Version(clean(current) or "")
        new = Version(clean(latest) or "")
    except InvalidVersion:
        return None
    return cur < new


class LatestVersions:
    def __init__(self, settings: Settings, session: requests.Session | None = None) -> None:
        self.settings = settings
        self.session = session or requests.Session()
        self.path = settings.data_dir / "versions.json"
        self._lock = threading.Lock()
        self.cache: dict[str, dict[str, Any]] = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(f"{self.path}.tmp")
        tmp.write_text(json.dumps(self.cache, indent=2))
        os.replace(tmp, self.path)

    def get(self, repo: str) -> dict[str, Any] | None:
        return self.cache.get(f"github:{repo}")

    def due(self, repo: str, now: datetime | None = None) -> bool:
        entry = self.get(repo)
        if not entry or not entry.get("checked_at"):
            return True
        now = now or datetime.now(UTC)
        age = now - datetime.fromisoformat(entry["checked_at"])
        # Depois de um erro tenta mais cedo, mas não em cada ciclo
        limit = self.settings.versions_hours if entry.get("version") else min(1.0, self.settings.versions_hours)
        return age > timedelta(hours=limit)

    def refresh(self, repo: str) -> dict[str, Any]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = self.settings.github_token.get_secret_value()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        entry: dict[str, Any] = dict(self.get(repo) or {})
        entry["checked_at"] = datetime.now(UTC).isoformat()
        try:
            resp = self.session.get(
                f"https://api.github.com/repos/{repo}/releases/latest",
                headers=headers,
                timeout=self.settings.http_timeout,
                verify=self.settings.verify(),
            )
            if resp.status_code == 200:
                data = resp.json()
                entry.update(
                    version=clean(data.get("tag_name")),
                    published_at=data.get("published_at"),
                    url=data.get("html_url"),
                    error=None,
                )
            elif resp.status_code == 404:
                entry.update(error="sem releases publicadas")
            elif resp.status_code in (403, 429):
                entry.update(error="limite da API do GitHub (SP_GITHUB_TOKEN)")
            else:
                entry.update(error=f"GitHub respondeu {resp.status_code}")
        except requests.RequestException as exc:
            entry.update(error=f"GitHub inacessível ({exc.__class__.__name__})")
        with self._lock:
            self.cache[f"github:{repo}"] = entry
            try:
                self._save()
            except OSError:
                log.warning("não foi possível gravar %s", self.path)
        return entry
