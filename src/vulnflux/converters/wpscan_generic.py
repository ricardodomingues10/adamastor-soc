"""Converte o JSON do WPScan para o formato Generic Findings Import do DefectDojo.

Porquê não usar o parser "Wpscan" do DefectDojo: rebentava com 500 em relatórios com
interesting_findings e obrigava a pré-processar com jq. Aqui controlamos o formato:
core, plugins e temas vão num único import, com `unique_id_from_tool` estável para a
deduplicação funcionar entre execuções.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

# Limites de colunas do DefectDojo (o parser genérico rejeita valores maiores)
_MAX_TITLE = 500
_MAX_COMPONENT = 500


def severity_from_cvss(cvss: Any) -> str:
    """Severidade a partir do CVSS, quando a API o devolve; senão Medium (como o DD)."""
    score: float | None = None
    if isinstance(cvss, dict):
        cvss = cvss.get("score")
    try:
        score = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        score = None
    if score is None:
        return "Medium"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def _cves(refs: dict[str, Any]) -> list[str]:
    out = []
    for value in refs.get("cve", []) or []:
        value = str(value).strip().upper()
        if not value:
            continue
        out.append(value if value.startswith("CVE-") else f"CVE-{value}")
    return out


def _references(refs: dict[str, Any]) -> str:
    lines = []
    for url in refs.get("url", []) or []:
        lines.append(f"- {url}")
    for wpid in refs.get("wpvulndb", []) or []:
        lines.append(f"- https://wpscan.com/vulnerability/{wpid}")
    for cve in _cves(refs):
        lines.append(f"- https://nvd.nist.gov/vuln/detail/{cve}")
    return "\n".join(lines)


def _vuln_finding(
    vuln: dict[str, Any],
    *,
    component_type: str,
    component_name: str,
    component_version: str | None,
    target_url: str,
    location: str | None,
    report_date: str | None,
) -> dict[str, Any]:
    refs = vuln.get("references") or {}
    wpids = refs.get("wpvulndb") or []
    vuln_id = str(wpids[0]) if wpids else vuln.get("title", "")
    title = str(vuln.get("title") or "Vulnerabilidade WordPress")
    cves = _cves(refs)

    desc = [f"**Componente:** {component_type} `{component_name}`"]
    if component_version:
        desc.append(f"**Versão detetada:** {component_version}")
    if location:
        desc.append(f"**Localização:** {location}")
    if vuln.get("vuln_type"):
        desc.append(f"**Tipo:** {vuln['vuln_type']}")
    if vuln.get("fixed_in"):
        desc.append(f"**Corrigido em:** {vuln['fixed_in']}")
    if cves:
        desc.append(f"**CVE:** {', '.join(cves)}")

    finding: dict[str, Any] = {
        "title": title[:_MAX_TITLE],
        "severity": severity_from_cvss(vuln.get("cvss")),
        "description": "\n\n".join(desc),
        "references": _references(refs),
        "component_name": component_name[:_MAX_COMPONENT],
        "unique_id_from_tool": f"wpscan:{component_type}:{component_name}:{vuln_id}"[:500],
        "vuln_id_from_tool": vuln_id[:500],
        "dynamic_finding": True,
        "static_finding": False,
        "endpoints": [target_url],
        "tags": ["wpscan", component_type],
        "fix_available": bool(vuln.get("fixed_in")),
    }
    if component_version:
        finding["component_version"] = str(component_version)[:100]
    if vuln.get("fixed_in"):
        finding["mitigation"] = f"Atualizar {component_name} para a versão {vuln['fixed_in']} ou superior."
        finding["fix_version"] = str(vuln["fixed_in"])[:100]
    if cves:
        finding["vulnerability_ids"] = cves
    cvss = vuln.get("cvss")
    if isinstance(cvss, dict) and cvss.get("vector", "").startswith("CVSS:3"):
        finding["cvssv3"] = cvss["vector"]
    if report_date:
        finding["date"] = report_date
    return finding


def _version_number(node: dict[str, Any] | None) -> str | None:
    if not node:
        return None
    version = node.get("version")
    if isinstance(version, dict):
        return version.get("number")
    return None


def convert(raw: dict[str, Any], *, include_interesting: bool = False) -> dict[str, Any]:
    """Devolve {"findings": [...]} pronto para reimport como Generic Findings Import."""
    target_url = str(raw.get("target_url") or raw.get("effective_url") or "")
    report_date = None
    if raw.get("start_time"):
        try:
            report_date = datetime.fromtimestamp(int(raw["start_time"]), UTC).date().isoformat()
        except (TypeError, ValueError, OSError):
            report_date = None

    findings: dict[str, dict[str, Any]] = {}

    def add(finding: dict[str, Any]) -> None:
        # O WPScan repete vulnerabilidades (mesmo id) dentro do mesmo componente.
        findings.setdefault(finding["unique_id_from_tool"], finding)

    version = raw.get("version") or {}
    for vuln in version.get("vulnerabilities") or []:
        add(
            _vuln_finding(
                vuln,
                component_type="core",
                component_name="wordpress",
                component_version=version.get("number"),
                target_url=target_url,
                location=None,
                report_date=report_date,
            )
        )

    themes: dict[str, Any] = {}
    main_theme = raw.get("main_theme")
    if isinstance(main_theme, dict) and main_theme.get("slug"):
        themes[main_theme["slug"]] = main_theme
    for slug, node in (raw.get("themes") or {}).items():
        themes.setdefault(slug, node)

    for kind, nodes in (("plugin", raw.get("plugins") or {}), ("theme", themes)):
        for slug, node in nodes.items():
            for vuln in (node or {}).get("vulnerabilities") or []:
                add(
                    _vuln_finding(
                        vuln,
                        component_type=kind,
                        component_name=slug,
                        component_version=_version_number(node),
                        target_url=target_url,
                        location=node.get("location"),
                        report_date=report_date,
                    )
                )

    if include_interesting:
        for item in raw.get("interesting_findings") or []:
            url = str(item.get("url") or target_url)
            entries = item.get("interesting_entries") or []
            desc = f"**Tipo:** {item.get('type', '?')}\n\n**URL:** {url}"
            if entries:
                desc += "\n\n**Detalhes:**\n" + "\n".join(f"- {e}" for e in entries)
            uid = f"wpscan:interesting:{item.get('type', '')}:{url}"[:500]
            add(
                {
                    "title": f"WPScan: {item.get('to_s') or item.get('type') or url}"[:_MAX_TITLE],
                    "severity": "Info",
                    "description": desc,
                    "references": _references(item.get("references") or {}),
                    "unique_id_from_tool": uid,
                    "dynamic_finding": True,
                    "static_finding": False,
                    "endpoints": [url],
                    "tags": ["wpscan", "interesting"],
                }
            )

    return {"findings": list(findings.values())}


def severity_counts(generic: dict[str, Any]) -> dict[str, int]:
    counts = Counter(f.get("severity", "Info") for f in generic.get("findings", []))
    return {sev: counts.get(sev, 0) for sev in SEVERITIES}
