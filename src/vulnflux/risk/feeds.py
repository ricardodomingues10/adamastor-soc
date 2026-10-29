"""Feeds públicos de ameaça: download diário, cache local e consulta por CVE.

Fontes (todas configuráveis; um URL vazio desliga a fonte; file:// lê um ficheiro
local, para servidores sem Internet com um espelho interno):

  kev         Catálogo KEV da CISA (JSON)
  epss        Pontuações EPSS do dia (CSV gzip, FIRST/Empirical Security)
  exploitdb   Índice do Exploit-DB (CSV, coluna `codes` com os CVE)
  metasploit  Metadados dos módulos do Metasploit (JSON, `references`)
  nuclei      Lista de templates de CVE do Nuclei (JSON por linha)

Cada fonte é independente: se o download de uma falhar, fica a cópia anterior e o
erro aparece no portal e na página Prioridades. Nada aqui fala com o DefectDojo.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import os
import re
import shutil
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

from vulnflux.config import Settings
from vulnflux.models import utcnow
from vulnflux.risk.score import Intel
from vulnflux.store import JsonStore

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
MAX_DOWNLOAD = 400 * 1024 * 1024  # o maior (Metasploit) anda pelas dezenas de MB

FEED_NAMES = {
    "kev": "CISA KEV · vulnerabilidades exploradas",
    "epss": "EPSS · probabilidade de exploração",
    "exploitdb": "Exploit-DB · exploits públicos",
    "metasploit": "Metasploit · módulos de exploit",
    "nuclei": "Nuclei · templates de CVE",
}


class FeedError(Exception):
    pass


def _date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


@dataclass
class FeedMeta:
    id: str
    name: str
    url: str
    fetched_at: str | None = None
    source_date: str | None = None
    count: int | None = None
    error: str | None = None
    error_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


# ---------------------------------------------------------------------------- download


def fetch(url: str, dest: Path, settings: Settings, session: requests.Session | None = None) -> None:
    """Descarrega para dest (atómico). file:// copia um ficheiro local."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    if url.startswith("file://"):
        src = Path(urlsplit(url).path)
        if not src.is_file():
            raise FeedError(f"ficheiro local {src} não existe")
        shutil.copyfile(src, tmp)
        os.replace(tmp, dest)
        return
    session = session or requests.Session()
    try:
        with session.get(url, stream=True, timeout=(15, settings.risk_download_timeout)) as resp:
            if resp.status_code == 404:
                raise FeedError("404 (ainda não publicado?)")
            if resp.status_code != 200:
                raise FeedError(f"HTTP {resp.status_code}")
            size = 0
            with open(tmp, "wb") as fh:
                for chunk in resp.iter_content(1024 * 256):
                    size += len(chunk)
                    if size > MAX_DOWNLOAD:
                        raise FeedError("ficheiro maior do que o esperado")
                    fh.write(chunk)
    except requests.RequestException as exc:
        tmp.unlink(missing_ok=True)
        raise FeedError(f"inacessível ({exc.__class__.__name__})") from exc
    except FeedError:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, dest)


# ---------------------------------------------------------------------------- parsers


def parse_kev(path: Path) -> tuple[dict[str, dict[str, Any]], str | None]:
    data = json.loads(path.read_text(encoding="utf-8"))
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise FeedError("JSON do KEV sem 'vulnerabilities'")
    out: dict[str, dict[str, Any]] = {}
    for v in vulns:
        cve = str(v.get("cveID", "")).upper()
        if not CVE_RE.fullmatch(cve):
            continue
        out[cve] = {
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            "name": v.get("vulnerabilityName"),
        }
    released = data.get("dateReleased")
    return out, str(released) if released else None


def epss_header(path: Path) -> tuple[str | None, str | None]:
    """Primeira linha: #model_version:v2025.03.14,score_date:2026-10-29T12:55:00+0000"""
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        first = fh.readline().strip()
    if not first.startswith("#"):
        return None, None
    meta = dict(part.split(":", 1) for part in first[1:].split(",") if ":" in part)
    return meta.get("model_version"), meta.get("score_date")


def read_epss(path: Path, wanted: set[str] | None = None) -> dict[str, tuple[float, float]]:
    """CVE → (epss, percentil). Com `wanted`, só guarda esses (o ficheiro tem ~300 mil)."""
    out: dict[str, tuple[float, float]] = {}
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        lines = (line for line in fh if not line.startswith("#"))
        for row in csv.DictReader(lines):
            cve = (row.get("cve") or "").upper()
            if wanted is not None and cve not in wanted:
                continue
            try:
                out[cve] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
    return out


def parse_exploitdb(path: Path) -> dict[str, str]:
    """CVE → 'exploitdb-verified' ou 'exploitdb'."""
    out: dict[str, str] = {}
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "codes" not in reader.fieldnames:
            raise FeedError("CSV do Exploit-DB sem a coluna 'codes'")
        for row in reader:
            verified = str(row.get("verified", "")).strip() == "1"
            for cve in CVE_RE.findall(row.get("codes") or ""):
                if verified:
                    out[cve.upper()] = "exploitdb-verified"
                else:
                    out.setdefault(cve.upper(), "exploitdb")
    return out


def parse_metasploit(path: Path) -> set[str]:
    """CVE com módulo do tipo exploit (os auxiliary não contam como arma)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise FeedError("JSON do Metasploit inesperado")
    out: set[str] = set()
    for module in data.values():
        if not isinstance(module, dict) or module.get("type") != "exploit":
            continue
        for ref in module.get("references") or []:
            m = CVE_RE.fullmatch(str(ref).strip())
            if m:
                out.add(m.group(0).upper())
    return out


def parse_nuclei(path: Path) -> set[str]:
    out: set[str] = set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except ValueError:
                continue
            m = CVE_RE.fullmatch(str(item.get("ID", "")).strip())
            if m:
                out.add(m.group(0).upper())
    return out


# ---------------------------------------------------------------------------- cache


class FeedCache:
    """Ficheiros em data_dir/risk/. Índices pequenos em JSON; o EPSS fica em .csv.gz."""

    def __init__(self, settings: Settings, store: JsonStore, session: requests.Session | None = None) -> None:
        self.settings = settings
        self.store = store
        self.session = session or requests.Session()
        self.dir = settings.data_dir / "risk"
        self.dir.mkdir(parents=True, exist_ok=True)

    # ---- metadados (store.state["risk_feeds"]) ----
    def metas(self) -> dict[str, dict[str, Any]]:
        return self.store.get_state("risk_feeds", {}) or {}

    def _save_meta(self, meta: FeedMeta) -> None:
        all_meta = self.metas()
        all_meta[meta.id] = meta.to_dict()
        self.store.set_state("risk_feeds", all_meta)

    def _meta(self, fid: str, url: str) -> FeedMeta:
        prev = self.metas().get(fid) or {}
        known = {k: v for k, v in prev.items() if k in FeedMeta.__dataclass_fields__}
        known.update(id=fid, name=FEED_NAMES[fid], url=url)
        return FeedMeta(**known)

    def urls(self) -> dict[str, str]:
        return self.urls_for(self.settings)

    @staticmethod
    def urls_for(s: Settings) -> dict[str, str]:
        return {
            "kev": s.risk_kev_url,
            "epss": s.risk_epss_url,
            "exploitdb": s.risk_exploitdb_url,
            "metasploit": s.risk_metasploit_url,
            "nuclei": s.risk_nuclei_url,
        }

    # ---- atualização ----
    def update_all(self, today: date | None = None) -> dict[str, FeedMeta]:
        out = {}
        for fid, url in self.urls().items():
            if not url:
                continue
            out[fid] = self.update(fid, url, today)
        return out

    def update(self, fid: str, url: str, today: date | None = None) -> FeedMeta:
        meta = self._meta(fid, url)
        handler: dict[str, Callable[[str, date], tuple[int, str | None]]] = {
            "kev": self._update_kev,
            "epss": self._update_epss,
            "exploitdb": self._update_exploitdb,
            "metasploit": self._update_metasploit,
            "nuclei": self._update_nuclei,
        }
        try:
            count, source_date = handler[fid](url, today or datetime.now(UTC).date())
        except (FeedError, OSError, ValueError, KeyError) as exc:
            msg = str(exc) if isinstance(exc, FeedError) else f"{exc.__class__.__name__}: {exc}"
            log.warning("feed %s: %s", fid, msg)
            meta.error, meta.error_at = msg[:300], utcnow().isoformat()
            self._save_meta(meta)
            return meta
        meta.fetched_at = utcnow().isoformat()
        meta.count, meta.source_date, meta.error, meta.error_at = count, source_date, None, None
        self._save_meta(meta)
        return meta

    def _write_index(self, name: str, data: Any) -> None:
        tmp = self.dir / f"{name}.json.tmp"
        tmp.write_text(json.dumps(data, separators=(",", ":")))
        os.replace(tmp, self.dir / f"{name}.json")

    def _update_kev(self, url: str, today: date) -> tuple[int, str | None]:
        raw = self.dir / "kev.raw.json"
        fetch(url, raw, self.settings, self.session)
        data, released = parse_kev(raw)
        if not data:
            raise FeedError("catálogo KEV vazio")
        self._write_index("kev", data)
        raw.unlink(missing_ok=True)
        return len(data), released

    def _update_epss(self, url: str, today: date) -> tuple[int, str | None]:
        dest = self.dir / "epss.csv.gz"
        part = self.dir / "epss.download.csv.gz"
        last_error: FeedError | None = None
        # O ficheiro do dia é publicado ao longo do dia (UTC): tenta hoje e os 2 dias anteriores
        candidates = [url.replace("{date}", (today - timedelta(days=d)).isoformat()) for d in range(3)]
        for candidate in dict.fromkeys(candidates):
            try:
                fetch(candidate, part, self.settings, self.session)
                _, score_date = epss_header(part)
                count = len(read_epss(part))
                if count == 0:
                    raise FeedError("ficheiro EPSS sem linhas")
                os.replace(part, dest)
                return count, score_date
            except (FeedError, OSError, EOFError, gzip.BadGzipFile) as exc:
                part.unlink(missing_ok=True)
                last_error = exc if isinstance(exc, FeedError) else FeedError(f"ficheiro inválido ({exc})")
        raise last_error or FeedError("sem URL")

    def _update_exploitdb(self, url: str, today: date) -> tuple[int, str | None]:
        raw = self.dir / "exploitdb.raw.csv"
        fetch(url, raw, self.settings, self.session)
        data = parse_exploitdb(raw)
        self._write_index("exploitdb", data)
        raw.unlink(missing_ok=True)
        return len(data), None

    def _update_metasploit(self, url: str, today: date) -> tuple[int, str | None]:
        raw = self.dir / "metasploit.raw.json"
        fetch(url, raw, self.settings, self.session)
        data = sorted(parse_metasploit(raw))
        self._write_index("metasploit", data)
        raw.unlink(missing_ok=True)
        return len(data), None

    def _update_nuclei(self, url: str, today: date) -> tuple[int, str | None]:
        raw = self.dir / "nuclei.raw.json"
        fetch(url, raw, self.settings, self.session)
        data = sorted(parse_nuclei(raw))
        self._write_index("nuclei", data)
        raw.unlink(missing_ok=True)
        return len(data), None

    # ---- consulta ----
    def _read_index(self, name: str, default: Any) -> Any:
        path = self.dir / f"{name}.json"
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return default

    def available(self) -> bool:
        return any((self.dir / f).exists() for f in ("kev.json", "epss.csv.gz", "exploitdb.json"))

    def lookup(self, cves: Iterable[str]) -> dict[str, Intel]:
        wanted = {c.upper() for c in cves}
        if not wanted:
            return {}
        kev = self._read_index("kev", {})
        edb = self._read_index("exploitdb", {})
        msf = set(self._read_index("metasploit", []))
        nuc = set(self._read_index("nuclei", []))
        epss_path = self.dir / "epss.csv.gz"
        try:
            epss = read_epss(epss_path, wanted) if epss_path.exists() else {}
        except (OSError, EOFError, gzip.BadGzipFile):
            epss = {}
        out = {}
        for cve in wanted:
            k = kev.get(cve)
            exploits = set()
            if cve in msf:
                exploits.add("metasploit")
            if cve in nuc:
                exploits.add("nuclei")
            if cve in edb:
                exploits.add(edb[cve])
            e = epss.get(cve)
            out[cve] = Intel(
                epss=e[0] if e else None,
                epss_percentile=e[1] if e else None,
                kev=k is not None,
                kev_date=_date(k.get("date_added")) if k else None,
                kev_due=_date(k.get("due_date")) if k else None,
                ransomware=bool(k and k.get("ransomware")),
                exploits=frozenset(exploits),
            )
        return out


def gzip_bytes(text: str) -> bytes:
    """Utilitário para testes e fixtures."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(text.encode())
    return buf.getvalue()
