"""Formulário de serviço: modelo do catálogo → valores do formulário → ServiceDef."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from socportal.catalog import FUNCTIONS, TEMPLATES_BY_ID
from socportal.registry import ProbeDef, ServiceDef, _short
from socportal.ui_store import ServiceStore

PROBE_SLOTS = 3
PROBE_FIELDS = (
    "type",
    "name",
    "url",
    "token_env",
    "auth_header",
    "auth_scheme",
    "expect",
    "contains",
    "version_path",
    "version_regex",
    "service",
    "component",
)


class FormError(ValueError):
    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


def slugify(text: str) -> str:
    norm = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "-", norm.lower()).strip("-")
    return slug[:40] or "servico"


def _probe_values(p: dict[str, Any]) -> dict[str, str]:
    return {
        "type": p.get("type", ""),
        "name": p.get("name", ""),
        "url": p.get("url") or "",
        "token_env": p.get("token_env") or "",
        "auth_header": p.get("auth_header", "Authorization"),
        "auth_scheme": p.get("auth_scheme", "Bearer"),
        "expect": ", ".join(str(c) for c in p.get("expect_status", [200])),
        "contains": p.get("contains") or "",
        "version_path": p.get("version_path") or "",
        "version_regex": p.get("version_regex") or "",
        "service": p.get("service") or "",
        "component": p.get("component") or "",
        "has_token": bool(p.get("token_file")),
    }


def values_from_template(template_id: str | None) -> dict[str, Any]:
    t = TEMPLATES_BY_ID.get(template_id or "") or TEMPLATES_BY_ID["generic-http"]
    return {
        "template": t["id"],
        "name": t["name"] if t["id"] not in ("generic-http", "generic-tcp", "generic-soc-status") else "",
        "id": "" if t["id"].startswith("generic-") else t["id"],
        "group": "",
        "function": t.get("function") or "",
        "description": t.get("description", ""),
        "link": t.get("link", ""),
        "api_url": t.get("api_url", ""),
        "location": "",
        "latest": t.get("latest", ""),
        "depends_on": [],
        "probes": [_probe_values(p) for p in t.get("probes", [])],
        "setup": t.get("setup", ""),
    }


def values_from_service(s: ServiceDef) -> dict[str, Any]:
    return {
        "template": s.template or "",
        "name": s.name,
        "id": s.id,
        "group": s.group,
        "function": s.function or "",
        "description": s.description,
        "link": s.link or "",
        "api_url": s.api_url or "",
        "location": s.location,
        "latest": (s.latest.github if s.latest else "") or "",
        "depends_on": list(s.depends_on),
        "probes": [_probe_values(p.model_dump()) for p in s.probes],
        "setup": (TEMPLATES_BY_ID.get(s.template or "") or {}).get("setup", ""),
    }


def values_from_form(form: Any) -> dict[str, Any]:
    """Valores tal como vieram (para voltar a mostrar o formulário com os erros)."""
    v: dict[str, Any] = {
        k: str(form.get(k, "")).strip()
        for k in ("template", "name", "id", "group", "function", "description", "link", "api_url", "location", "latest")
    }
    v["depends_on"] = [str(x) for x in form.getlist("depends_on")]
    v["probes"] = []
    for i in range(PROBE_SLOTS):
        pv = {f: str(form.get(f"p{i}_{f}", "")).strip() for f in PROBE_FIELDS}
        pv["has_token"] = form.get(f"p{i}_has_token") == "1"
        v["probes"].append(pv)
    return v


@dataclass
class Built:
    service: ServiceDef
    secrets: dict[int, str] = field(default_factory=dict)  # slot → credencial nova a gravar


def build_service(
    form: Any, store: ServiceStore, existing: ServiceDef | None = None, *, for_test: bool = False
) -> Built:
    v = values_from_form(form)
    errors: dict[str, str] = {}
    sid = existing.id if existing else (v["id"] or slugify(v["name"]))
    if not v["name"]:
        errors["name"] = "obrigatório"
    probes: list[ProbeDef] = []
    secrets: dict[int, str] = {}
    old = {i: p for i, p in enumerate(existing.probes)} if existing else {}
    for i, pv in enumerate(v["probes"]):
        if not pv["type"]:
            continue
        try:
            expect = [int(x) for x in re.split(r"[,\s]+", pv["expect"]) if x] or [200]
        except ValueError:
            errors[f"p{i}"] = "códigos esperados: números separados por vírgulas"
            continue
        data: dict[str, Any] = {
            "type": pv["type"],
            "name": pv["name"],
            "url": pv["url"] or None,
            "auth_header": pv["auth_header"] or "Authorization",
            "auth_scheme": pv["auth_scheme"],
            "expect_status": expect,
            "contains": pv["contains"] or None,
            "version_path": pv["version_path"] or None,
            "version_regex": pv["version_regex"] or None,
            "service": pv["service"] or None,
            "component": pv["component"] or None,
            "token_env": pv["token_env"] or None,
        }
        new_token = str(form.get(f"p{i}_token", "")).strip()
        clear = form.get(f"p{i}_clear_token") == "on"
        if new_token:
            secrets[i] = new_token
            data["token_file"] = str(store.secret_path(sid, i))
        elif not clear and i in old and old[i].token_file:
            data["token_file"] = old[i].token_file
        try:
            probe = ProbeDef(**data)
            if for_test and new_token:
                probe._inline_token = new_token
            probes.append(probe)
        except ValidationError as exc:
            errors[f"p{i}"] = _short(exc)
    if errors:
        raise FormError(errors)
    try:
        service = ServiceDef(
            id=sid,
            name=v["name"],
            group=v["group"] or (FUNCTIONS.get(v["function"], {}).get("name") or "Serviços"),
            function=v["function"] or None,
            template=v["template"] or None,
            description=v["description"],
            link=v["link"] or None,
            api_url=v["api_url"] or None,
            location=v["location"],
            probes=probes,
            latest={"github": v["latest"]} if v["latest"] else None,
            depends_on=[d for d in v["depends_on"] if d != sid],
            origin="ui",
        )
    except ValidationError as exc:
        field_errors: dict[str, str] = {}
        for err in exc.errors():
            key = str(err["loc"][0]) if err["loc"] else "geral"
            field_errors[key] = err["msg"].removeprefix("Value error, ")
        raise FormError(field_errors) from exc
    return Built(service, secrets)
