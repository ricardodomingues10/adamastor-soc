"""Relatório de um servidor → findings no formato Generic Findings Import do DefectDojo.

Vira finding o que é risco de segurança e tem correção: verificações de hardening que falham e
atualizações de segurança pendentes. A saúde (memória, disco) fica no painel, não no DefectDojo.
O unique_id_from_tool é estável, por isso um problema corrigido fecha sozinho na importação seguinte.
"""

from __future__ import annotations

from typing import Any

SEV = {"alta": "High", "media": "Medium", "baixa": "Low"}


def to_generic(host_name: str, report: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for c in report.get("hardening", []):
        if c["status"] not in ("fail", "warn"):
            continue
        sev = SEV.get(c.get("severity") or "", "Low")
        if c["status"] == "warn" and sev == "High":
            sev = "Medium"
        findings.append(
            {
                "title": f"Hardening: {c['name']}"[:500],
                "severity": sev,
                "description": (
                    f"**Servidor:** {host_name}\n\n**Encontrado:** {c.get('value') or '—'}\n\n"
                    f"**Esperado:** {c.get('expected') or '—'}\n\nGrupo: {c.get('group') or '—'}"
                ),
                "mitigation": c.get("fix") or "",
                "component_name": c.get("group") or "sistema",
                "unique_id_from_tool": f"vulnflux:server:{c['id']}",
                "vuln_id_from_tool": c["id"],
                "static_finding": False,
                "dynamic_finding": True,
                "tags": ["vulnflux", "hardening"],
            }
        )
    upd = report.get("updates") or {}
    sec = [p for p in upd.get("packages", []) if p.get("security")]
    if sec:
        lines = "\n".join(f"- {p['name']} {p.get('old') or ''} → {p['new']}" for p in sec[:150])
        findings.append(
            {
                "title": f"Atualizações de segurança pendentes ({len(sec)} pacotes)",
                "severity": "High" if len(sec) >= 10 else "Medium",
                "description": f"**Servidor:** {host_name} ({report.get('os') or '?'})\n\n{lines}",
                "mitigation": (
                    "Aplicar pelo anel de atualizações do VulnFlux ou: apt-get upgrade / dnf upgrade --security"
                ),
                "component_name": "pacotes",
                "unique_id_from_tool": "vulnflux:server:updates-security",
                "vuln_id_from_tool": "updates-security",
                "static_finding": False,
                "dynamic_finding": True,
                "tags": ["vulnflux", "patching"],
            }
        )
    if upd.get("reboot"):
        findings.append(
            {
                "title": "Reinício pendente (atualizações à espera de aplicar)",
                "severity": "Low",
                "description": f"**Servidor:** {host_name}\n\nKernel em uso {report.get('kernel') or '?'}.",
                "mitigation": "Reiniciar numa janela de manutenção.",
                "component_name": "kernel",
                "unique_id_from_tool": "vulnflux:server:reboot",
                "vuln_id_from_tool": "reboot",
                "static_finding": False,
                "dynamic_finding": True,
                "tags": ["vulnflux", "patching"],
            }
        )
    return {"findings": findings}


def severity_counts(generic: dict[str, Any]) -> dict[str, int]:
    out = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in generic["findings"]:
        out[f["severity"]] = out.get(f["severity"], 0) + 1
    return out
