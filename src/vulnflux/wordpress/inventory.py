"""Inventário WordPress: que versão, tema e plugins tem cada site, segundo a última enumeração.

Serve a página /wordpress (cobertura e orçamento de pedidos) e o vigilante de atualizações, que
cruza cada nova versão ou vulnerabilidade publicada com os sites que usam o componente.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from vulnflux.models import utcnow
from vulnflux.store import JsonStore
from vulnflux.wordpress.vulndb import affects, components, version_lt

STATE_KEY = "wp_inventory"


def site_entry(raw: dict[str, Any], *, url: str, name: str, vulns: int, mode: str) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "url": url,
        "name": name,
        "scanned_at": utcnow().isoformat(),
        "mode": mode,
        "wordpress": None,
        "themes": {},
        "plugins": {},
        "vulnerabilities": vulns,
    }
    for kind, slug, version, node in components(raw):
        if kind == "wordpress":
            entry["wordpress"] = version
            continue
        item = {"version": version, "latest": node.get("latest_version")}
        entry["themes" if kind == "theme" else "plugins"][slug] = item
    return entry


def record(store: JsonStore, host_id: str, entry: dict[str, Any]) -> None:
    with store.locked():
        data = store.get_state(STATE_KEY, {}) or {}
        data[host_id] = entry
        store.set_state(STATE_KEY, data)


def load(store: JsonStore) -> dict[str, dict[str, Any]]:
    data = store.get_state(STATE_KEY, {}) or {}
    hosts = {h.id for h in store.list_hosts()}
    return {hid: e for hid, e in data.items() if hid in hosts}


def unique_components(inventory: dict[str, dict[str, Any]]) -> dict[tuple[str, str], list[str]]:
    """{(tipo, slug): [host_id, ...]}. O WordPress conta por versão (cada versão é um pedido)."""
    out: dict[tuple[str, str], list[str]] = {}
    for hid, e in inventory.items():
        if e.get("wordpress"):
            out.setdefault(("wordpress", e["wordpress"]), []).append(hid)
        for kind, key in (("theme", "themes"), ("plugin", "plugins")):
            for slug in e.get(key) or {}:
                out.setdefault((kind, slug), []).append(hid)
    return out


def sites_using(
    inventory: dict[str, dict[str, Any]], kind: str, slug: str, vuln: dict[str, Any] | None = None
) -> list[tuple[str, dict[str, Any], str | None]]:
    """(host_id, entrada, versão instalada) dos sites com o componente (e afetados, se `vuln`)."""
    out = []
    for hid, e in inventory.items():
        if kind == "wordpress":
            version = e.get("wordpress")
            if not version:
                continue
        else:
            item = (e.get("themes" if kind == "theme" else "plugins") or {}).get(slug)
            if item is None:
                continue
            version = item.get("version")
        if vuln is not None and not affects(version, vuln):
            continue
        out.append((hid, e, version))
    return out


def outdated(inventory: dict[str, dict[str, Any]], latest: dict[tuple[str, str], str]) -> list[dict[str, Any]]:
    """Componentes instalados abaixo da última versão conhecida."""
    rows = []
    for hid, e in inventory.items():
        for kind, key in (("theme", "themes"), ("plugin", "plugins")):
            for slug, item in (e.get(key) or {}).items():
                new = latest.get((kind, slug)) or item.get("latest")
                have = item.get("version")
                if new and have and version_lt(have, new):
                    rows.append(
                        {
                            "host_id": hid,
                            "site": e.get("name"),
                            "kind": kind,
                            "slug": slug,
                            "version": have,
                            "latest": new,
                        }
                    )
        core = latest.get(("wordpress", "core"))
        if core and e.get("wordpress") and version_lt(e["wordpress"], core):
            rows.append(
                {
                    "host_id": hid,
                    "site": e.get("name"),
                    "kind": "wordpress",
                    "slug": "wordpress",
                    "version": e["wordpress"],
                    "latest": core,
                }
            )
    return rows


def popularity(inventory: dict[str, dict[str, Any]]) -> Counter[tuple[str, str]]:
    return Counter({k: len(v) for k, v in unique_components(inventory).items()})
