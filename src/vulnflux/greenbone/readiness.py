"""Gate de prontidão do Greenbone, via GMP (python-gvm).

Responde a uma pergunta: "posso lançar scans agora sem risco de um falso limpo?"

Um Greenbone acabado de arrancar aceita ligações muito antes de estar pronto: os
feeds ainda estão a ser carregados no Postgres, os VTs ainda não estão no Redis e as
scan configs podem nem existir. Um scan lançado nessa janela corre com cobertura
parcial e parece limpo. Este módulo só devolve READY quando tudo isto está resolvido.

Três estados:
  READY      - pode lançar scans
  NOT_READY  - ainda a arrancar/sincronizar; voltar a tentar mais tarde
  FAILED     - problema que esperar não resolve (credenciais, config inexistente
               depois de os feeds estarem carregados); alertar um humano
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError, GvmResponseError, GvmServerError
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

log = logging.getLogger(__name__)

# O gvmd responde 4xx (GvmResponseError) ou 5xx (GvmServerError, ex.: scanner em baixo).
# Ambos são respostas válidas de um gvmd vivo e são tratados como falha da verificação.
GMP_ERRORS = (GvmResponseError, GvmServerError)

# UUIDs fixos dos objetos que vêm com o feed da Community Edition
OPENVAS_DEFAULT_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"
FULL_AND_FAST_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"

REQUIRED_FEEDS = ("NVT", "SCAP", "CERT", "GVMD_DATA")


class Status(StrEnum):
    READY = "ready"
    NOT_READY = "not_ready"
    FAILED = "failed"


@dataclass(frozen=True)
class ReadinessConfig:
    socket_path: str
    username: str
    password: str
    scanner_id: str = OPENVAS_DEFAULT_SCANNER
    scan_config_id: str = FULL_AND_FAST_CONFIG
    # Abaixo disto a scan config ainda não tem os VTs carregados. Valor conservador:
    # o Full and fast da Community tem bastante mais. Ajustar depois de ver o valor real.
    min_nvts: int = 10_000
    max_feed_age_days: float = 7.0
    # Feed velho reduz cobertura mas não invalida o scan: por omissão é aviso.
    block_on_stale_feed: bool = False
    connect_timeout: float = 60.0


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str
    # Uma falha permanente não se resolve a esperar (ex.: config apagada).
    permanent: bool = False


@dataclass
class Readiness:
    status: Status
    checks: list[Check] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    gmp_version: str | None = None
    feed_versions: dict[str, str] = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return self.status is Status.READY

    def summary(self) -> str:
        failed = [f"{c.name}: {c.detail}" for c in self.checks if not c.ok]
        parts = [self.status.value]
        if failed:
            parts.append("; ".join(failed))
        if self.warnings:
            parts.append("avisos: " + "; ".join(self.warnings))
        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Formato para gravar na base de estado / mostrar no dashboard."""
        return {
            "status": self.status.value,
            "gmp_version": self.gmp_version,
            "feed_versions": self.feed_versions,
            "warnings": self.warnings,
            "checks": [c.__dict__ for c in self.checks],
        }


# ---------------------------------------------------------------------------
# Avaliação (pura em relação às respostas GMP: testável com um gmp falso)
# ---------------------------------------------------------------------------


def parse_feed_timestamp(version: str) -> datetime | None:
    """As versões dos feeds são timestamps YYYYMMDDhhmm (ex.: 202610290512)."""
    digits = "".join(ch for ch in (version or "") if ch.isdigit())
    if len(digits) < 8:
        return None
    try:
        if len(digits) >= 12:
            return datetime.strptime(digits[:12], "%Y%m%d%H%M").replace(tzinfo=UTC)
        return datetime.strptime(digits[:8], "%Y%m%d").replace(tzinfo=UTC)
    except ValueError:
        return None


def _check_feeds(gmp: Any, cfg: ReadinessConfig, now: datetime, result: Readiness) -> None:
    try:
        resp = gmp.get_feeds()
    except GMP_ERRORS as exc:
        result.checks.append(Check("feeds", False, f"get_feeds falhou: {exc}"))
        return

    owner = resp.findtext("feed_owner_set")
    if owner is not None and owner.strip() == "0":
        result.checks.append(
            Check(
                "feed_owner",
                False,
                "feed import owner não definido: data objects (scan configs, port lists) não são importados",
                permanent=True,
            )
        )

    seen: set[str] = set()
    for feed in resp.findall("feed"):
        ftype = (feed.findtext("type") or "?").strip()
        version = (feed.findtext("version") or "").strip()
        seen.add(ftype)
        result.feed_versions[ftype] = version

        if feed.find("currently_syncing") is not None:
            result.checks.append(Check(f"feed:{ftype}", False, "a sincronizar/carregar"))
            continue
        if feed.find("sync_not_available") is not None:
            err = (feed.findtext("sync_not_available/error") or "indisponível").strip()
            result.checks.append(Check(f"feed:{ftype}", False, f"sync indisponível: {err}"))
            continue

        ts = parse_feed_timestamp(version)
        if ts is None:
            result.warnings.append(f"feed {ftype}: versão '{version}' não interpretável")
            result.checks.append(Check(f"feed:{ftype}", True, f"versão {version}"))
            continue

        age_days = (now - ts).total_seconds() / 86400
        if age_days > cfg.max_feed_age_days:
            msg = f"feed {ftype} com {age_days:.1f} dias (versão {version})"
            if cfg.block_on_stale_feed:
                result.checks.append(Check(f"feed:{ftype}", False, msg))
                continue
            result.warnings.append(msg)
        result.checks.append(Check(f"feed:{ftype}", True, f"versão {version}, {age_days:.1f} dias"))

    for missing in sorted(set(REQUIRED_FEEDS) - seen):
        result.checks.append(Check(f"feed:{missing}", False, "feed ausente da resposta do gvmd"))


def _check_scan_config(gmp: Any, cfg: ReadinessConfig, feeds_settled: bool, result: Readiness) -> None:
    try:
        resp = gmp.get_scan_config(cfg.scan_config_id)
    except GMP_ERRORS as exc:
        # Config inexistente com feeds ainda a carregar é normal; com feeds estáveis
        # significa que os data objects não foram importados (ex.: feed owner).
        result.checks.append(
            Check(
                "scan_config",
                False,
                f"{cfg.scan_config_id} não disponível: {exc}",
                permanent=feeds_settled,
            )
        )
        return

    config = resp.find("config")
    name = (config.findtext("name") if config is not None else None) or cfg.scan_config_id
    raw = (config.findtext("nvt_count") if config is not None else None) or ""
    try:
        nvt_count = int(raw.strip())
    except ValueError:
        result.checks.append(Check("scan_config", False, f"'{name}': nvt_count ilegível ({raw!r})"))
        return

    if nvt_count < cfg.min_nvts:
        result.checks.append(
            Check(
                "scan_config",
                False,
                f"'{name}' só tem {nvt_count} NVTs (mínimo {cfg.min_nvts}); VTs ainda a carregar",
            )
        )
    else:
        result.checks.append(Check("scan_config", True, f"'{name}' com {nvt_count} NVTs"))


def _check_scanner(gmp: Any, cfg: ReadinessConfig, result: Readiness) -> None:
    try:
        resp = gmp.verify_scanner(cfg.scanner_id)
    except GMP_ERRORS as exc:
        result.checks.append(Check("scanner", False, f"verify_scanner falhou: {exc}"))
        return
    version = (resp.findtext("version") or "?").strip()
    result.checks.append(Check("scanner", True, f"OpenVAS responde (versão {version})"))


def evaluate(gmp: Any, cfg: ReadinessConfig, now: datetime | None = None) -> Readiness:
    """Corre todas as verificações sobre um `gmp` já autenticado.

    Não pára na primeira falha: o dashboard deve mostrar o quadro completo.
    """
    now = now or datetime.now(UTC)
    result = Readiness(status=Status.NOT_READY)

    try:
        result.gmp_version = (gmp.get_version().findtext("version") or "").strip() or None
    except GMP_ERRORS as exc:
        result.warnings.append(f"get_version falhou: {exc}")

    _check_feeds(gmp, cfg, now, result)
    feeds_settled = all(c.ok for c in result.checks if c.name.startswith("feed:"))
    _check_scan_config(gmp, cfg, feeds_settled, result)
    _check_scanner(gmp, cfg, result)

    failures = [c for c in result.checks if not c.ok]
    if not failures:
        result.status = Status.READY
    elif any(c.permanent for c in failures):
        result.status = Status.FAILED
    else:
        result.status = Status.NOT_READY
    return result


# ---------------------------------------------------------------------------
# Ligação real e espera
# ---------------------------------------------------------------------------

GmpFactory = Callable[[ReadinessConfig], Any]


@contextmanager
def _default_gmp(cfg: ReadinessConfig) -> Iterator[Any]:
    conn = UnixSocketConnection(path=cfg.socket_path, timeout=cfg.connect_timeout)
    with Gmp(connection=conn, transform=EtreeCheckCommandTransform()) as gmp:
        yield gmp


def probe(cfg: ReadinessConfig, now: datetime | None = None, gmp_factory: GmpFactory = _default_gmp) -> Readiness:
    """Uma tentativa: liga, autentica, avalia. Nunca lança exceção."""
    try:
        with gmp_factory(cfg) as gmp:
            try:
                gmp.authenticate(cfg.username, cfg.password)
            except GvmResponseError as exc:  # só 4xx; 5xx cai no except geral
                # Credenciais erradas não se resolvem a esperar.
                return Readiness(Status.FAILED, [Check("auth", False, f"autenticação falhou: {exc}", permanent=True)])
            return evaluate(gmp, cfg, now)
    except (GvmError, OSError) as exc:
        # Socket inexistente / recusado / timeout: o gvmd ainda está a arrancar.
        return Readiness(Status.NOT_READY, [Check("gvmd", False, f"gvmd não responde: {exc}")])


def wait_until_ready(
    cfg: ReadinessConfig,
    timeout_s: float = 3 * 3600,
    interval_s: float = 60,
    *,
    probe_fn: Callable[[ReadinessConfig], Readiness] = probe,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    failed_grace_s: float = 900,
) -> Readiness:
    """Espera até READY ou FAILED, ou até esgotar o tempo (devolve NOT_READY).

    O timeout por omissão (3 h) cobre um primeiro arranque com carga completa de feeds.
    Num arranque normal, com volumes já populados, fica pronto em minutos.

    `failed_grace_s`: logo após o arranque, o gvmd pode ainda não ter começado a
    carregar os feeds e reportá-los como estáveis com a scan config em falta, o que
    parece uma falha permanente. Durante esta janela, só a falha de autenticação
    termina a espera; as outras falhas "permanentes" são tratadas como NOT_READY.
    """
    started = clock()
    deadline = started + timeout_s
    attempt = 0
    last_summary = None
    while True:
        attempt += 1
        result = probe_fn(cfg)
        summary = result.summary()
        if summary != last_summary:
            log.info("greenbone prontidão (tentativa %d): %s", attempt, summary)
            last_summary = summary
        if result.status is Status.READY:
            return result
        if result.status is Status.FAILED:
            auth_failed = any(c.name == "auth" and not c.ok for c in result.checks)
            if auth_failed or clock() - started >= failed_grace_s:
                return result
        if clock() + interval_s > deadline:
            result.checks.append(
                Check("timeout", False, f"não ficou pronto em {timeout_s:.0f}s ({attempt} tentativas)")
            )
            log.warning("greenbone não ficou pronto: %s", result.summary())
            return result
        sleep(interval_s)
