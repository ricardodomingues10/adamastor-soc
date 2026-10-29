"""Converte o JSON do WPScan para o formato Generic Findings Import do DefectDojo.

Porquê não usar o parser "Wpscan" do DefectDojo: rebentava com 500 em relatórios com
interesting_findings e obrigava a pré-processar com jq. Aqui controlamos o formato:
core, plugins, temas, timthumbs, ficheiros expostos (backups de configuração, exports da
BD, pastas de backup) e utilizadores enumerados vão num único import, com
`unique_id_from_tool` estável para a deduplicação funcionar entre execuções.
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


def _references(refs: dict[str, Any], *, uuid: str | None = None) -> str:
    lines = []
    if uuid:
        lines.append(f"- https://wpscan.com/vulnerability/{uuid}")
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
    # WPScan 3.8: id em references.wpvulndb; 4.x: também em "uuid"
    vuln_id = str(wpids[0]) if wpids else str(vuln.get("uuid") or vuln.get("title", ""))
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
        "references": _references(refs, uuid=None if wpids else vuln.get("uuid")),
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


def _exposure_finding(
    *,
    kind: str,
    url: str,
    node: dict[str, Any],
    severity: str,
    title: str,
    impact: str,
    mitigation: str,
    report_date: str | None,
) -> dict[str, Any]:
    desc = [f"**URL:** {url}", impact]
    if node.get("found_by"):
        desc.append(f"**Detetado por:** {node['found_by']} (confiança {node.get('confidence', '?')}%)")
    entries = node.get("interesting_entries") or []
    if entries:
        desc.append("**Conteúdo:**\n" + "\n".join(f"- {e}" for e in entries))
    finding: dict[str, Any] = {
        "title": f"{title}: {url}"[:_MAX_TITLE],
        "severity": severity,
        "description": "\n\n".join(desc),
        "mitigation": mitigation,
        "unique_id_from_tool": f"wpscan:{kind}:{url}"[:500],
        "vuln_id_from_tool": f"wpscan-{kind.replace('_', '-')}",
        "cwe": 530,  # Exposure of Backup File to an Unauthorized Control Sphere
        "dynamic_finding": True,
        "static_finding": False,
        "endpoints": [url],
        "tags": ["wpscan", kind],
    }
    if report_date:
        finding["date"] = report_date
    return finding


def convert(raw: dict[str, Any], *, include_interesting: bool = False, include_users: bool = True) -> dict[str, Any]:
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

    # Timthumbs vulneráveis (script de redimensionamento com historial de RCE)
    for url, node in (raw.get("timthumbs") or {}).items():
        node = node or {}
        for vuln in node.get("vulnerabilities") or []:
            add(
                _vuln_finding(
                    vuln,
                    component_type="timthumb",
                    component_name=url,  # pode haver vários timthumbs no mesmo site
                    component_version=_version_number(node),
                    target_url=target_url,
                    location=url,
                    report_date=report_date,
                )
            )

    # Ficheiros expostos: backups do wp-config e exports da base de dados
    exposures = (
        (
            "config_backups",
            "config_backup",
            "High",
            "Backup do ficheiro de configuração acessível",
            "Um backup do wp-config.php acessível expõe credenciais da base de dados e chaves secretas.",
            "Remover o ficheiro do servidor, rodar as credenciais da BD e as chaves/salts do WordPress.",
        ),
        (
            "db_exports",
            "db_export",
            "High",
            "Export da base de dados acessível",
            "Um dump da base de dados acessível publicamente pode expor utilizadores, hashes e dados pessoais.",
            "Remover o ficheiro do servidor e avaliar a exposição de dados pessoais (RGPD).",
        ),
    )
    for key, kind, severity, title, impact, mitigation in exposures:
        for url, node in (raw.get(key) or {}).items():
            add(
                _exposure_finding(
                    kind=kind,
                    url=url,
                    node=node or {},
                    severity=severity,
                    title=title,
                    impact=impact,
                    mitigation=mitigation,
                    report_date=report_date,
                )
            )

    # Pastas de backup (WPScan 4.x): o próprio WPScan indica a severidade
    for url, node in (raw.get("backup_folders") or {}).items():
        node = node or {}
        sev = str(node.get("severity") or "medium").capitalize()
        add(
            _exposure_finding(
                kind="backup_folder",
                url=url,
                node=node,
                severity=sev if sev in SEVERITIES else "Medium",
                title="Pasta de backup acessível",
                impact="Uma pasta de backups acessível pode conter cópias do site, da BD ou de configurações.",
                mitigation="Remover a pasta do diretório público ou bloquear o acesso no servidor web.",
                report_date=report_date,
            )
        )

    # Utilizadores enumerados: um único finding por site, com a lista atual
    users = raw.get("users") or {}
    if include_users and users:
        lines = []
        for name, node in sorted(users.items()):
            node = node or {}
            found = node.get("found_by") or "?"
            uid = node.get("id")
            lines.append(f"- `{name}`" + (f" (ID {uid})" if uid is not None else "") + f" — {found}")
        finding = {
            "title": f"Enumeração de utilizadores possível ({len(users)} encontrados)",
            "severity": "Low",
            "description": (
                "O WPScan conseguiu obter nomes de utilizador do WordPress sem autenticação. "
                "Facilita ataques de força bruta e phishing dirigido.\n\n**Utilizadores:**\n" + "\n".join(lines)
            ),
            "mitigation": (
                "Bloquear a enumeração (ex.: /?author=N e /wp-json/wp/v2/users), garantir que os "
                "nomes de utilizador não coincidem com o nome público e ativar 2FA e limite de tentativas."
            ),
            # id estável: a lista muda, mas o finding é o mesmo (atualizado em vez de duplicado)
            "unique_id_from_tool": f"wpscan:users:{target_url}"[:500],
            "vuln_id_from_tool": "wpscan-user-enumeration",
            "cwe": 200,
            "dynamic_finding": True,
            "static_finding": False,
            "endpoints": [target_url],
            "tags": ["wpscan", "users"],
        }
        if report_date:
            finding["date"] = report_date
        add(finding)

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
