"""Validação e normalização de hosts (formulário e importação em lote).

O nome canónico é o hostname em minúsculas, sem esquema, porta nem caminho. É ele
que liga as fontes no DefectDojo, por isso tem de ser estável e único:
"https://WWW.scml.pt/noticias" e "www.scml.pt" são o mesmo host.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from vulnflux.models import Host
from vulnflux.risk.context import (
    CRITICALITY,
    DATA_CLASS,
    DEFAULT_CRITICALITY,
    DEFAULT_DATA_CLASS,
    DEFAULT_EXPOSURE,
    EXPOSURE,
    normalize,
)

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TAG = re.compile(r"^[\w.-]{1,40}$")


class HostValidationError(ValueError):
    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


def _valid_hostname(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        pass
    if len(name) > 253 or "." not in name:
        return False
    return all(_LABEL.match(label) for label in name.split("."))


def normalize_name(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        raise ValueError("obrigatório")
    if "://" in raw:
        raw = urlsplit(raw).hostname or ""
    else:
        raw = raw.split("/", 1)[0]
        # host:porta (mas não IPv6 entre parênteses retos)
        if raw.count(":") == 1:
            raw = raw.split(":", 1)[0]
    raw = raw.strip("[]").rstrip(".")
    if not _valid_hostname(raw):
        raise ValueError(f"'{value}' não é um hostname ou IP válido")
    return raw


def normalize_url(value: str | None) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise ValueError("só http:// ou https://")
    if not parts.hostname or not _valid_hostname(parts.hostname.rstrip(".")):
        raise ValueError(f"'{value}' não tem um hostname válido")
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc.lower(), path, parts.query, ""))


def normalize_target(value: str | None) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None
    # Greenbone aceita hostname, IP ou CIDR; validamos os dois primeiros e CIDR.
    try:
        ipaddress.ip_network(raw, strict=False)
        return raw
    except ValueError:
        pass
    short = raw.lower().rstrip(".")
    if "." not in short and _LABEL.match(short):
        return short  # nome curto da rede local / serviço do compose (ex.: alvo-vulneravel)
    return normalize_name(raw)


def parse_tags(value: str | list[str] | None) -> list[str]:
    if not value:
        return []
    items = value if isinstance(value, list) else re.split(r"[,\s]+", value)
    tags: list[str] = []
    for item in items:
        tag = item.strip().lower()
        if not tag:
            continue
        if not _TAG.match(tag):
            raise ValueError(f"etiqueta inválida: '{item}'")
        if tag not in tags:
            tags.append(tag)
    return tags


def _truthy(value: object) -> bool:
    return str(value).lower() in ("1", "true", "on", "yes", "sim")


def host_from_form(form: dict[str, object], existing: Host | None = None) -> Host:
    """Constrói um Host a partir dos campos do formulário, com erros por campo."""
    errors: dict[str, str] = {}

    def take(key: str) -> str:
        value = form.get(key)
        return str(value).strip() if value is not None else ""

    url = name = target = None
    tags: list[str] = []
    try:
        url = normalize_url(take("url"))
    except ValueError as exc:
        errors["url"] = str(exc)
    name_input = take("name") or (url or "")
    try:
        name = normalize_name(name_input)
    except ValueError as exc:
        # Com um URL inválido, o erro já aparece no campo do URL.
        if take("name") or "url" not in errors:
            errors["name"] = str(exc) if name_input else "indica um nome ou um URL"
    try:
        target = normalize_target(take("scan_target"))
    except ValueError as exc:
        errors["scan_target"] = str(exc)
    try:
        tags = parse_tags(take("tags"))
    except ValueError as exc:
        errors["tags"] = str(exc)

    wpscan = _truthy(form.get("wpscan_enabled"))
    greenbone = _truthy(form.get("greenbone_enabled"))
    if wpscan and not url and "url" not in errors:
        errors["url"] = "o WPScan precisa de um URL"
    server = _ssh_fields(form, existing, errors)
    gb_profile = (
        take("greenbone_profile") if "greenbone_profile" in form else (existing.greenbone_profile if existing else "")
    )
    if gb_profile not in ("", "rapido", "descoberta", "completo"):
        errors["greenbone_profile"] = "perfil inválido"
    if not wpscan and not greenbone and not server["ssh_enabled"]:
        errors["sources"] = "ativa pelo menos uma fonte"

    environment = take("environment")
    if len(environment) > 100:
        errors["environment"] = "máximo 100 caracteres"
    notes = take("notes")
    if len(notes) > 2000:
        errors["notes"] = "máximo 2000 caracteres"

    # Contexto de risco: campo ausente (ex.: importação antiga) mantém o valor atual
    context: dict[str, str] = {}
    for key, allowed, default in (
        ("criticality", CRITICALITY, DEFAULT_CRITICALITY),
        ("exposure", EXPOSURE, DEFAULT_EXPOSURE),
        ("data_class", DATA_CLASS, DEFAULT_DATA_CLASS),
    ):
        current = getattr(existing, key) if existing else default
        try:
            context[key] = normalize(take(key), allowed, current) if key in form else current
        except ValueError as exc:
            errors[key] = str(exc)

    if errors:
        raise HostValidationError(errors)

    data = {
        "name": name,
        "url": url,
        "scan_target": target if target != name else None,
        "environment": environment,
        "wpscan_enabled": wpscan,
        "greenbone_enabled": greenbone,
        # O formulário envia sempre o campo (hidden "off" + checkbox "on"); a importação
        # em lote não o envia e os hosts novos ficam ativos.
        "enabled": _truthy(form["enabled"]) if "enabled" in form else True,
        "tags": tags,
        "notes": notes,
        **context,
        **server,
        "greenbone_profile": gb_profile,
    }
    if existing:
        return existing.model_copy(update=data)
    return Host(**data)


PATCH_MODES = {"verificar": "Só verificar", "seguranca": "Atualizações de segurança", "tudo": "Todas as atualizações"}
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def _ssh_fields(form: dict[str, object], existing: Host | None, errors: dict[str, str]) -> dict[str, object]:
    """Campos de servidor (SSH). Ausentes do formulário = mantém o atual (importação em lote, formulários antigos)."""
    keys = ("ssh_enabled", "ssh_address", "ssh_port", "ssh_user", "patch_ring", "patch_mode", "patch_reboot", "lynis")
    cur = {k: getattr(existing, k) for k in keys} if existing else {k: Host.model_fields[k].default for k in keys}
    if "ssh_enabled" not in form:
        return cur
    out = dict(cur)
    out["ssh_enabled"] = _truthy(form.get("ssh_enabled"))
    out["patch_reboot"] = _truthy(form.get("patch_reboot"))
    out["lynis"] = _truthy(form.get("lynis"))
    address = str(form.get("ssh_address") or "").strip().lower().rstrip(".")
    if address:
        # IP, FQDN ou nome curto da rede local / do compose (ex.: lab-server)
        try:
            ipaddress.ip_address(address.strip("[]"))
        except ValueError:
            if not all(_LABEL.match(label) for label in address.split(".")) or len(address) > 253:
                errors["ssh_address"] = f"'{address}' não é um IP nem um nome de servidor válido"
    out["ssh_address"] = address
    try:
        port = int(str(form.get("ssh_port") or "22"))
        if not 1 <= port <= 65535:
            raise ValueError
        out["ssh_port"] = port
    except ValueError:
        errors["ssh_port"] = "porta inválida"
    user = str(form.get("ssh_user") or "vulnflux").strip()
    if not _USER.match(user):
        errors["ssh_user"] = "nome de utilizador inválido"
    out["ssh_user"] = user
    try:
        ring = int(str(form.get("patch_ring") or "2"))
        if ring not in (0, 1, 2, 3):
            raise ValueError
        out["patch_ring"] = ring
    except ValueError:
        errors["patch_ring"] = "anel de 0 a 3"
    mode = str(form.get("patch_mode") or "verificar")
    if mode not in PATCH_MODES:
        errors["patch_mode"] = "modo inválido"
    out["patch_mode"] = mode
    return out


@dataclass
class BulkResult:
    hosts: list[Host] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)


def parse_bulk(
    text: str,
    *,
    default_environment: str,
    wpscan: bool,
    greenbone: bool,
    existing_names: set[str],
) -> BulkResult:
    """Uma linha por host: `url-ou-host [; ambiente] [; etiquetas] [; criticidade] [; exposição] [; dados]`.

    Linhas vazias e começadas por # são ignoradas. Hosts já existentes ou repetidos
    no texto são reportados como duplicados e não importados.
    """
    result = BulkResult()
    seen = set(existing_names)
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in re.split(r"[;\t]", line)]
        entry = parts[0]
        environment = parts[1] if len(parts) > 1 and parts[1] else default_environment
        tags = parts[2] if len(parts) > 2 else ""
        extra = {
            key: parts[i]
            for i, key in ((3, "criticality"), (4, "exposure"), (5, "data_class"))
            if len(parts) > i and parts[i]
        }
        form = {
            **extra,
            "url": entry if wpscan else "",
            "name": entry,
            "environment": environment,
            "tags": tags,
            "wpscan_enabled": wpscan,
            "greenbone_enabled": greenbone,
        }
        try:
            host = host_from_form(form)
        except HostValidationError as exc:
            result.errors.append(f"linha {lineno} ({entry}): {exc}")
            continue
        if host.name in seen:
            result.duplicates.append(host.name)
            continue
        seen.add(host.name)
        result.hosts.append(host)
    return result
