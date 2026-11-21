"""Vigilante: deteta novas versões e vulnerabilidades dos componentes instalados e avisa as equipas.

Corre a cada VF_WATCH_INTERVAL_MINUTES (15 por omissão). A primeira vez que vê um componente ou
uma fonte guarda o estado sem alertar (senão o primeiro arranque enviava centenas de emails);
daí em diante alerta só o que é novo, uma única vez por evento.

  vulnerabilidade que afeta a versão instalada em algum site → ticket (≥ VF_TICKET_MIN_SEVERITY) + email
  nova versão de um componente desatualizado em algum site, ou de uma ferramenta do SOC → email
  aviso novo num feed RSS → email

Um envio que falhe fica pendente e é repetido nas verificações seguintes (até 5 tentativas).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from vulnflux.collectors.wpscan_tokens import TokenPool
from vulnflux.config import Settings
from vulnflux.errors import VFError
from vulnflux.models import utcnow
from vulnflux.store import JsonStore
from vulnflux.watch import notify, sources
from vulnflux.watch.sources import Observations, Release, Vulnerability
from vulnflux.wordpress import inventory
from vulnflux.wordpress.vulndb import Budget, VulnCache, affects, version_lt

log = logging.getLogger(__name__)

STATE = "watch_state"
EVENTS = "watch_events"
LAST = "watch_last"
MAX_EVENTS = 300
MAX_ATTEMPTS = 5
MAX_SEEN = 50_000


class _SeenSet:
    """Conjunto de ids vistos que regista a data em que cada um apareceu."""

    def __init__(self, store: dict[str, str], today: str) -> None:
        self.store, self.today = store, today

    def __contains__(self, key: object) -> bool:
        return key in self.store

    def add(self, key: str) -> None:
        self.store.setdefault(key, self.today)

    def update(self, keys: Any) -> None:
        for k in keys:
            self.add(k)


def severity_of(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score > 0 else "info"


def _installed(inv: dict[str, dict[str, Any]]) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for e in inv.values():
        if e.get("wordpress"):
            out.add(("wordpress", "core"))
        for kind, key in (("theme", "themes"), ("plugin", "plugins")):
            out.update((kind, slug) for slug in e.get(key) or {})
    return out


def _site_list(store: JsonStore, rows: list[tuple[str, dict[str, Any], str | None]]) -> tuple[list[dict], list[str]]:
    sites, teams = [], set()
    for hid, entry, version in rows:
        host = store.get_host(hid)
        sites.append({"host_id": hid, "name": entry.get("name") or (host.name if host else hid), "version": version})
        if host:
            teams.update(notify.teams_of(host.tags))
    return sites, sorted(teams)


def gather(
    store: JsonStore, settings: Settings, inv: dict[str, dict[str, Any]], state: dict[str, Any], pool: TokenPool | None
) -> Observations:
    obs = Observations()
    installed = _installed(inv)
    if settings.watch_wporg and installed:
        sources.wporg_core(obs)
        for kind, slug in sorted(installed):
            if kind in ("plugin", "theme"):
                sources.wporg_component(obs, kind, slug)

    # WPScan: a cache partilhada (alimentada pelos lotes) não custa nada. Com quota de sobra acima da
    # reserva para o lote noturno, refresca primeiro os componentes usados por mais sites.
    cache = VulnCache(settings)
    if pool is not None and settings.watch_wpscan_refresh > 0:
        pool.refresh()
        budget = Budget()
        popular = inventory.popularity(inv)
        stale = [(n, k) for k, n in popular.items() if not cache.fresh(cache.get(*k))]
        for _n, (kind, slug) in sorted(stale, reverse=True)[: settings.watch_wpscan_refresh]:
            total = pool.total_remaining()
            if total is not None and total <= settings.watch_wpscan_reserve:
                break
            cache.lookup(kind, slug, pool, budget)
        obs.requests += budget.used
    wanted = {inventory_key for inventory_key in inventory.unique_components(inv)}
    entries = [e for e in cache.entries.values() if (e.get("kind"), e.get("slug")) in wanted]
    sources.wpscan_from_cache(obs, entries)

    if settings.watch_wordfence_token.get_secret_value():
        last = state.get("last_wordfence")
        due = not last or utcnow() - datetime.fromisoformat(last) >= timedelta(minutes=settings.watch_wordfence_minutes)
        if due:
            sources.wordfence(obs, settings, installed)
            state["last_wordfence"] = utcnow().isoformat()

    for repo in [r.strip() for r in settings.watch_github_repos.replace(";", ",").split(",") if r.strip()]:
        if "/" in repo:
            sources.github_release(obs, settings, repo)
    for name, url in sources.parse_feeds(settings.watch_rss_feeds):
        sources.rss(obs, name, url)
    return obs


def detect(
    store: JsonStore, inv: dict[str, dict[str, Any]], obs: Observations, state: dict[str, Any], known_ids: set[str]
) -> list[dict[str, Any]]:
    """Compara as observações com o estado anterior. Atualiza `state`; devolve os eventos novos."""
    versions: dict[str, str] = state.setdefault("versions", {})
    now = utcnow().isoformat()
    today = now[:10]
    raw_seen = state.get("seen") or {}
    # ids já vistos, com a data em que apareceram (versões antigas guardavam só a lista)
    seen_at: dict[str, str] = raw_seen if isinstance(raw_seen, dict) else dict.fromkeys(raw_seen, today)
    seen = _SeenSet(seen_at, today)
    baselined: set[str] = set(state.get("baselined", []))
    ready: set[str] = set(state.get("ready_sources", []))
    events: list[dict[str, Any]] = []

    def add(event: dict[str, Any]) -> None:
        if event["id"] not in known_ids:
            known_ids.add(event["id"])
            events.append({"detected_at": now, "attempts": 0, **event})

    # ---- versões: a mais alta vista por componente, de qualquer fonte
    best: dict[tuple[str, str], Release] = {}
    for r in obs.releases:
        cur = best.get((r.kind, r.slug))
        if (
            cur is None
            or version_lt(cur.version.lstrip("v"), r.version.lstrip("v"))
            or (cur.source != "wordpress.org" and r.source == "wordpress.org" and cur.version == r.version)
        ):
            best[(r.kind, r.slug)] = r
    for (kind, slug), r in best.items():
        key = f"{kind}:{slug}"
        prev = versions.get(key)
        versions[key] = r.version if prev is None or version_lt(prev.lstrip("v"), r.version.lstrip("v")) else prev
        if prev is None or not version_lt(prev.lstrip("v"), r.version.lstrip("v")):
            continue  # primeira observação (estado inicial) ou nada de novo
        if kind == "tool":
            add(
                {
                    "id": f"release:{key}:{r.version}",
                    "kind": "versão",
                    "severity": "info",
                    "title": f"Nova versão de {slug}: {r.version}",
                    "component_kind": "ferramenta",
                    "slug": slug,
                    "version": r.version,
                    "previous": prev,
                    "source": r.source,
                    "sites": [],
                    "teams": [],
                    "references": [r.url] if r.url else [],
                    "action": "rever as notas da versão e planear a atualização (anel canário primeiro).",
                }
            )
            continue
        lookup_slug = "wordpress" if kind == "wordpress" else slug
        rows = [
            row for row in inventory.sites_using(inv, kind, lookup_slug) if row[2] and version_lt(row[2], r.version)
        ]
        if not rows:
            continue  # nenhum site desatualizado: nada a pedir a ninguém
        sites, teams = _site_list(store, rows)
        label = "WordPress" if kind == "wordpress" else f"{'plugin' if kind == 'plugin' else 'tema'} {slug}"
        add(
            {
                "id": f"release:{key}:{r.version}",
                "kind": "versão",
                "severity": "info",
                "title": f"Nova versão do {label}: {r.version} ({len(sites)} site(s) desatualizado(s))",
                "component_kind": kind,
                "slug": slug,
                "version": r.version,
                "previous": prev,
                "source": r.source,
                "sites": sites,
                "teams": teams,
                "references": [r.url] if r.url else [],
                "action": f"atualizar para {r.version} nos sites listados.",
            }
        )

    # ---- vulnerabilidades: só as novas, e só se afetarem a versão de algum site
    by_component: dict[str, list[Vulnerability]] = {}
    for v in obs.vulns:
        by_component.setdefault(f"{v.source}:{v.kind}:{v.slug}", []).append(v)
    for comp in obs.observed | set(by_component):
        vulns = by_component.get(comp, [])
        source = comp.split(":", 1)[0]
        new_component = comp not in baselined
        baselined.add(comp)
        if new_component and source not in ready:
            # Primeira vez que esta fonte corre: tudo o que já existia é estado inicial, sem alertas
            seen.update(v.vuln_id for v in vulns)
            continue
        for v in vulns:
            if v.vuln_id in seen:
                continue
            seen.add(v.vuln_id)
            lookup_slug = "wordpress" if v.kind == "wordpress" else v.slug
            vuln_dict = {"fixed_in": v.fixed_in, "introduced_in": v.introduced_in}
            rows = inventory.sites_using(inv, v.kind, lookup_slug)
            if v.ranges:
                rows = [row for row in rows if sources.in_ranges(row[2], v.ranges)]
            else:
                rows = [row for row in rows if affects(row[2], vuln_dict)]
            if not rows:
                continue
            sites, teams = _site_list(store, rows)
            ident = v.cves[0] if v.cves else v.vuln_id
            name = "WordPress" if v.kind == "wordpress" else v.slug
            add(
                {
                    "id": f"vuln:{v.kind}:{v.slug}:{ident}",
                    "kind": "vulnerabilidade",
                    "severity": severity_of(v.score),
                    "title": (
                        f"Componente novo com vulnerabilidade conhecida: {v.title} — {len(sites)} site(s)"
                        if new_component
                        else f"{v.title} — {len(sites)} site(s) afetado(s)"
                    ),
                    "component_kind": v.kind,
                    "slug": v.slug,
                    "version": None,
                    "fixed_in": v.fixed_in,
                    "source": v.source,
                    "cves": v.cves,
                    "score": v.score,
                    "sites": sites,
                    "teams": teams,
                    "references": [x for x in [v.url, *v.cves] if x],
                    "action": (
                        f"atualizar {name} para {v.fixed_in} ou superior."
                        if v.fixed_in
                        else "sem correção publicada: desativar o componente ou mitigar (WAF) até haver correção."
                    ),
                }
            )

    # ---- avisos RSS (o primeiro contacto com um feed é só estado inicial)
    feeds_known: set[str] = set(state.get("feeds", []))
    installed_slugs = {slug for _k, slug in _installed(inv) if len(slug) > 4}
    for a in obs.advisories:
        if a.feed not in feeds_known:
            seen.add(a.item_id)
            continue
        if a.item_id in seen:
            continue
        seen.add(a.item_id)
        lowered = a.title.lower()
        match = sorted(s for s in installed_slugs if s.replace("-", " ") in lowered or s in lowered)
        add(
            {
                "id": f"aviso:{a.item_id}"[:300],
                "kind": "aviso",
                "severity": "medium" if match else "info",
                "title": f"{a.feed}: {a.title}",
                "component_kind": "feed",
                "slug": ", ".join(match) or a.feed,
                "source": a.feed,
                "sites": [],
                "teams": [],
                "references": [a.url] if a.url else [],
                "action": "avaliar se se aplica" + (f" (menciona {', '.join(match)})." if match else "."),
            }
        )
    state["feeds"] = sorted(feeds_known | {a.feed for a in obs.advisories})

    # Corta pelos mais antigos (não por ordem alfabética), para nunca voltar a alertar o que é recente
    keep = sorted(seen_at.items(), key=lambda kv: kv[1], reverse=True)[:MAX_SEEN]
    state["seen"] = dict(keep)
    state["baselined"] = sorted(baselined)
    state["ready_sources"] = sorted(ready | {c.split(":", 1)[0] for c in obs.observed | set(by_component)})
    return events


def dispatch(store: JsonStore, settings: Settings, events: list[dict[str, Any]]) -> dict[str, int]:
    """Envia o que estiver por enviar: tickets um a um, emails agrupados por destinatários."""
    sent = {"tickets": 0, "emails": 0, "failed": 0}
    ticket_min = notify.SEV_ORDER.get(settings.ticket_min_severity, 3)
    email_min = notify.SEV_ORDER.get(settings.watch_email_min_severity, 0)
    now = utcnow().isoformat()

    for e in events:
        wants_ticket = e["kind"] == "vulnerabilidade" and notify.SEV_ORDER.get(e["severity"], 0) >= ticket_min
        if (
            wants_ticket
            and notify.ticket_configured(settings)
            and not e.get("ticket")
            and e.get("attempts", 0) < MAX_ATTEMPTS
        ):
            try:
                e["ticket"] = notify.open_ticket(settings, e)
                e["ticket_at"] = now
                e.pop("ticket_error", None)
                sent["tickets"] += 1
            except VFError as exc:
                e["ticket_error"] = exc.message
                e["attempts"] = e.get("attempts", 0) + 1
                sent["failed"] += 1

    if not notify.email_configured(settings):
        return sent
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for e in events:
        if e.get("email_at") or notify.SEV_ORDER.get(e["severity"], 0) < email_min:
            continue
        if e.get("email_attempts", 0) >= MAX_ATTEMPTS:
            continue
        to = tuple(notify.recipients(settings, e.get("teams", [])))
        if to:
            groups.setdefault(to, []).append(e)
    for to, group in groups.items():
        subject, body = notify.render_digest(group)
        try:
            notify.send_email(settings, list(to), subject, body)
        except VFError as exc:
            for e in group:
                e["email_error"] = exc.message
                e["email_attempts"] = e.get("email_attempts", 0) + 1
            sent["failed"] += 1
            continue
        for e in group:
            e["email_at"] = now
            e["email_to"] = list(to)
            e.pop("email_error", None)
        sent["emails"] += 1
    return sent


def run_watch(store: JsonStore, settings: Settings, *, pool: TokenPool | None = None) -> dict[str, Any]:
    started = utcnow()
    inv = inventory.load(store)
    state = store.get_state(STATE, {}) or {}
    if pool is None and settings.wpscan_tokens() and settings.watch_wpscan_refresh > 0:
        pool = TokenPool(settings, store)
    obs = gather(store, settings, inv, state, pool)
    with store.locked():
        stored: list[dict[str, Any]] = store.get_state(EVENTS, []) or []
        known = {e["id"] for e in stored}
        new = detect(store, inv, obs, state, known)
        store.set_state(STATE, state)
        stored = new + stored
        store.set_state(EVENTS, stored[:MAX_EVENTS])
    # Os envios ficam fora do lock (SMTP/webhook podem demorar); pendentes de antes também seguem.
    pending = [e for e in stored[:MAX_EVENTS] if _pending(e, settings)]
    sent = dispatch(store, settings, pending)
    with store.locked():
        current = store.get_state(EVENTS, []) or []
        by_id = {e["id"]: e for e in pending}
        store.set_state(EVENTS, [by_id.get(e["id"], e) for e in current])
    summary = {
        "at": started.isoformat(),
        "seconds": round((utcnow() - started).total_seconds(), 1),
        "components": len(_installed(inv)),
        "sites": len(inv),
        "requests": obs.requests,
        "new_events": len(new),
        "errors": obs.errors[:20],
        **sent,
    }
    store.set_state(LAST, summary)
    if new:
        log.info("vigilante: %d eventos novos", len(new))
    return summary


def _pending(e: dict[str, Any], settings: Settings) -> bool:
    ticket_min = notify.SEV_ORDER.get(settings.ticket_min_severity, 3)
    email_min = notify.SEV_ORDER.get(settings.watch_email_min_severity, 0)
    sev = notify.SEV_ORDER.get(e.get("severity", "info"), 0)
    needs_ticket = (
        e.get("kind") == "vulnerabilidade"
        and sev >= ticket_min
        and not e.get("ticket")
        and e.get("attempts", 0) < MAX_ATTEMPTS
        and notify.ticket_configured(settings)
    )
    needs_email = (
        sev >= email_min
        and not e.get("email_at")
        and e.get("email_attempts", 0) < MAX_ATTEMPTS
        and notify.email_configured(settings)
    )
    return needs_ticket or needs_email


def send_test(settings: Settings) -> list[str]:
    """Envia um alerta de teste por cada canal configurado. Devolve o que foi enviado."""
    event = {
        "id": f"teste:{utcnow().isoformat()}",
        "kind": "vulnerabilidade",
        "severity": "info",
        "title": "Teste de alertas do VulnFlux",
        "component_kind": "teste",
        "slug": "teste",
        "source": "VulnFlux",
        "sites": [],
        "teams": [],
        "references": [],
        "action": "nenhuma: é só um teste do canal.",
    }
    done = []
    if notify.email_configured(settings):
        to = notify.recipients(settings, [])
        notify.send_email(settings, to, "[SOC] Teste de alertas", notify.render_event(event))
        done.append("email")
    if notify.ticket_configured(settings):
        done.append(f"ticket ({notify.open_ticket(settings, event)})")
    return done
