"""Contexto de negócio de cada host (inventário do VulnFlux).

Três perguntas, respondidas por quem conhece o serviço:
  criticidade  quanto custa ao negócio se este serviço for comprometido
  exposição    quem lhe consegue chegar (alcançabilidade)
  dados        que dados trata: dados pessoais elevam a criticidade mínima

A criticidade efetiva é a maior entre a indicada e a mínima imposta pelos dados:
um site "médio" que trata dados de saúde (categorias especiais do RGPD, art. 9.º)
conta como crítico.
"""

from __future__ import annotations

CRITICALITY = {
    "critico": "Crítico",
    "alto": "Alto",
    "medio": "Médio",
    "baixo": "Baixo",
}
EXPOSURE = {
    "internet": "Internet (público)",
    "dmz": "DMZ / parceiros",
    "interno": "Rede interna",
    "isolado": "Isolado / segmentado",
}
DATA_CLASS = {
    "publico": "Só informação pública",
    "interno": "Informação interna",
    "pessoais": "Dados pessoais",
    "sensiveis": "Dados pessoais sensíveis (saúde, sociais)",
}

DEFAULT_CRITICALITY = "medio"
# Por omissão um host novo é tratado como exposto: os hosts do VulnFlux são, na maioria,
# sites públicos, e o erro conservador é priorizar a mais.
DEFAULT_EXPOSURE = "internet"
DEFAULT_DATA_CLASS = "interno"

_ORDER = ["baixo", "medio", "alto", "critico"]
_DATA_FLOOR = {"pessoais": "alto", "sensiveis": "critico"}

# Mapeamento para o campo business_criticality do Product no DefectDojo
DD_BUSINESS_CRITICALITY = {"critico": "very high", "alto": "high", "medio": "medium", "baixo": "low"}

_ALIASES = {
    "crítico": "critico",
    "critical": "critico",
    "high": "alto",
    "médio": "medio",
    "medium": "medio",
    "low": "baixo",
    "público": "publico",
    "public": "publico",
    "internal": "interno",
    "sensível": "sensiveis",
    "sensivel": "sensiveis",
    "sensíveis": "sensiveis",
    "pessoal": "pessoais",
    "isolated": "isolado",
}


def normalize(value: str | None, allowed: dict[str, str], default: str) -> str:
    """Aceita a chave, o rótulo, acentos e sinónimos em inglês. Lança ValueError."""
    raw = (value or "").strip().lower()
    if not raw:
        return default
    raw = _ALIASES.get(raw, raw)
    if raw in allowed:
        return raw
    for key, label in allowed.items():
        if raw == label.lower():
            return key
    raise ValueError(f"'{value}' inválido (usa: {', '.join(allowed)})")


def effective_criticality(criticality: str, data_class: str) -> str:
    floor = _DATA_FLOOR.get(data_class)
    if floor and _ORDER.index(floor) > _ORDER.index(criticality):
        return floor
    return criticality
