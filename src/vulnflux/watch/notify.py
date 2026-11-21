"""Alertas: email (SMTP) e ticket (por email para o service desk, ou webhook REST, ex.: n8n).

Encaminhamento por equipa: um host com a etiqueta "equipa:web" recebe os alertas no endereço
definido para "web" em VF_WATCH_ROUTES ("web=web@exemplo.pt,dev@exemplo.pt; infra=infra@exemplo.pt").
Sem equipa (ou sem rota para ela), vai para VF_WATCH_EMAIL_TO.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import requests

from vulnflux.config import Settings
from vulnflux.errors import ErrorKind, VFError

log = logging.getLogger(__name__)

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_PT = {"info": "Info", "low": "Baixa", "medium": "Média", "high": "Alta", "critical": "Crítica"}
TEAM_TAG = "equipa:"


def parse_routes(value: str) -> dict[str, list[str]]:
    routes: dict[str, list[str]] = {}
    for part in value.replace("\n", ";").split(";"):
        if "=" not in part:
            continue
        team, emails = part.split("=", 1)
        addrs = [e.strip() for e in emails.replace(" ", ",").split(",") if "@" in e]
        if team.strip() and addrs:
            routes[team.strip().lower()] = addrs
    return routes


def split_addrs(value: str) -> list[str]:
    return [e.strip() for e in value.replace(";", ",").replace(" ", ",").split(",") if "@" in e]


def teams_of(tags: list[str]) -> list[str]:
    return sorted({t[len(TEAM_TAG) :].strip().lower() for t in tags if t.lower().startswith(TEAM_TAG)})


def recipients(settings: Settings, teams: list[str]) -> list[str]:
    routes = parse_routes(settings.watch_routes)
    out: list[str] = []
    for team in teams:
        for addr in routes.get(team, []):
            if addr not in out:
                out.append(addr)
    if not out:
        out = split_addrs(settings.watch_email_to)
    return out


def email_configured(settings: Settings) -> bool:
    return bool(settings.smtp_host and settings.smtp_from)


def send_email(settings: Settings, to: list[str], subject: str, body: str) -> None:
    if not email_configured(settings):
        raise VFError(ErrorKind.CONFIG, "SMTP não configurado (VF_SMTP_HOST e VF_SMTP_FROM)")
    if not to:
        raise VFError(ErrorKind.CONFIG, "sem destinatários (VF_WATCH_EMAIL_TO ou VF_WATCH_ROUTES)")
    if settings.smtp_user and not (settings.smtp_starttls or settings.smtp_ssl):
        raise VFError(ErrorKind.CONFIG, "SMTP com utilizador sem TLS: a password iria em claro")
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject.replace("\n", " ")[:200]
    msg.set_content(body)
    try:
        if settings.smtp_ssl:
            server: smtplib.SMTP = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, timeout=30, context=ssl.create_default_context()
            )
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30)
        with server:
            if settings.smtp_starttls and not settings.smtp_ssl:
                server.starttls(context=ssl.create_default_context())
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password.get_secret_value())
            server.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise VFError(ErrorKind.DEPENDENCY, f"envio de email falhou: {exc.__class__.__name__}: {exc}") from exc


def ticket_configured(settings: Settings) -> bool:
    if settings.ticket_mode == "email":
        return bool(settings.ticket_email) and email_configured(settings)
    if settings.ticket_mode == "webhook":
        return bool(settings.ticket_webhook_url)
    return False


def open_ticket(settings: Settings, event: dict[str, Any]) -> str:
    """Abre um ticket para o evento. Devolve uma referência (id devolvido pelo webhook, ou "email")."""
    subject = f"[SOC][{SEV_PT.get(event['severity'], event['severity'])}] {event['title']}"
    if settings.ticket_mode == "email":
        send_email(settings, [settings.ticket_email], subject, render_event(event, ticket=True))
        return "email"
    if settings.ticket_mode == "webhook":
        headers = {"Content-Type": "application/json"}
        token = settings.ticket_webhook_token.get_secret_value()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        payload = {
            "event_id": event["id"],  # chave de idempotência: o mesmo evento nunca abre dois tickets
            "title": subject,
            "severity": event["severity"],
            "kind": event["kind"],
            "component": {"type": event["component_kind"], "slug": event["slug"], "version": event.get("version")},
            "teams": event.get("teams", []),
            "sites": event.get("sites", []),
            "references": event.get("references", []),
            "description": render_event(event, ticket=True),
        }
        try:
            resp = requests.post(settings.ticket_webhook_url, json=payload, headers=headers, timeout=30)
        except requests.RequestException as exc:
            raise VFError(ErrorKind.DEPENDENCY, f"webhook de tickets inacessível: {exc.__class__.__name__}") from exc
        if resp.status_code >= 300:
            raise VFError(ErrorKind.DEPENDENCY, f"webhook de tickets respondeu {resp.status_code}")
        try:
            data = resp.json()
            return str(data.get("id") or data.get("ticket") or data.get("number") or "ok")
        except ValueError:
            return "ok"
    raise VFError(ErrorKind.CONFIG, "sistema de tickets não configurado (VF_TICKET_MODE)")


def render_event(event: dict[str, Any], *, ticket: bool = False) -> str:
    lines = [event["title"], ""]
    lines.append(f"Gravidade: {SEV_PT.get(event['severity'], event['severity'])}")
    lines.append(f"Componente: {event['component_kind']} {event['slug']}")
    if event.get("version"):
        lines.append(f"Versão: {event['version']}")
    if event.get("fixed_in"):
        lines.append(f"Corrigido em: {event['fixed_in']}")
    lines.append(f"Fonte: {event.get('source', '')}")
    if event.get("teams"):
        lines.append(f"Equipa(s): {', '.join(event['teams'])}")
    sites = event.get("sites") or []
    if sites:
        lines += ["", f"Sites afetados ({len(sites)}):"]
        lines += [f"  - {s['name']} ({s.get('version') or 'versão desconhecida'})" for s in sites[:50]]
        if len(sites) > 50:
            lines.append(f"  … e mais {len(sites) - 50}")
    refs = event.get("references") or []
    if refs:
        lines += ["", "Referências:"] + [f"  {r}" for r in refs[:10]]
    lines += ["", "Ação recomendada: " + event.get("action", "avaliar e atualizar.")]
    if ticket:
        lines += ["", f"ID do alerta: {event['id']}"]
    return "\n".join(lines)


def render_digest(events: list[dict[str, Any]]) -> tuple[str, str]:
    vulns = [e for e in events if e["kind"] == "vulnerabilidade"]
    rels = [e for e in events if e["kind"] == "versão"]
    adv = [e for e in events if e["kind"] == "aviso"]
    parts = []
    if vulns:
        parts.append(f"{len(vulns)} vulnerabilidade(s)")
    if rels:
        parts.append(f"{len(rels)} nova(s) versão(ões)")
    if adv:
        parts.append(f"{len(adv)} aviso(s)")
    worst = max((SEV_ORDER.get(e["severity"], 0) for e in events), default=0)
    sev = next(k for k, v in SEV_ORDER.items() if v == worst)
    subject = f"[SOC][{SEV_PT[sev]}] Vigilância: " + ", ".join(parts)
    body = []
    for e in sorted(events, key=lambda e: -SEV_ORDER.get(e["severity"], 0)):
        body.append(render_event(e))
        body.append("-" * 60)
    return subject, "\n".join(body)
