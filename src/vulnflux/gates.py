"""Gates antes do import: decidem se é seguro fechar findings antigos."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GateDecision:
    close_old_findings: bool
    warnings: list[str] = field(default_factory=list)


def decide_close_old(
    *,
    current_total: int,
    previous_total: int | None,
    threshold: float,
    min_previous: int,
) -> GateDecision:
    """Fecha findings antigos só se o resultado for plausível face ao anterior.

    Uma queda abrupta (ex.: de 40 para 2 findings) costuma significar um scan parcial
    (API sem dados, site atrás de WAF, scan interrompido sem erro). Nesse caso importa
    na mesma, para não perder findings novos, mas sem fechar nada e com aviso.
    """
    if previous_total is None or previous_total < min_previous:
        return GateDecision(close_old_findings=True)
    if previous_total == 0:
        return GateDecision(close_old_findings=True)
    drop = (previous_total - current_total) / previous_total
    if drop > threshold:
        return GateDecision(
            close_old_findings=False,
            warnings=[
                f"queda de {drop:.0%} nos findings ({previous_total} → {current_total}): "
                "importado sem fechar findings antigos; confirmar manualmente"
            ],
        )
    return GateDecision(close_old_findings=True)
