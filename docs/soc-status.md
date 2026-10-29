# Contrato `soc-status/1`

Formato que um serviço do SOC publica para o Portal SOC o mostrar com todo o detalhe:
estado, dependências, listas/feeds com idade e tarefas agendadas. O VulnFlux publica-o
em `GET /api/status`. Qualquer serviço novo (um coletor, um worker de auditoria de
servidores, um conector do MISP) pode publicar o mesmo formato e entra no portal sem
alterações ao portal — basta um probe `soc-status` no `portal.yaml`.

Serviços que não publicam o contrato (DefectDojo, MISP, aplicações de terceiros) usam
os probes `http`, `tcp`, `defectdojo` ou `misp`.

## Pedido

```
GET /api/status
Authorization: Bearer <token>
Accept: application/json
```

- Sem token configurado no serviço: `404` (endpoint desligado).
- Token errado: `401`.
- O pedido nunca deve fazer chamadas a terceiros: devolve o último estado conhecido.

## Resposta

```json
{
  "schema": "soc-status/1",
  "service": "vulnflux",
  "version": "0.2.0",
  "status": "ok | warn | fail | off | unknown",
  "message": "texto curto para o mosaico",
  "generated_at": "2026-10-29T17:35:30+00:00",
  "checks": [
    {"id": "defectdojo", "name": "DefectDojo", "status": "ok", "message": "12 ms", "checked_at": "…"}
  ],
  "dependencies": {"defectdojo": "ok", "greenbone": "off"},
  "freshness": [
    {"id": "risk_kev", "name": "CISA KEV", "updated_at": "…", "max_age_hours": 48,
     "status": "ok", "message": "1482 entradas"}
  ],
  "components": {
    "greenbone": {"name": "Greenbone", "status": "off", "message": "parado (on-demand)",
                  "version": "GMP 22.6", "checks": [], "freshness": []}
  },
  "jobs": [
    {"id": "wpscan_batch", "name": "Lote WPScan", "next_run": "…", "last_status": "ok", "last_finished": "…"}
  ]
}
```

| Campo | Significado |
|---|---|
| `status` | `ok` funciona; `warn` funciona com problemas (ex.: uma dependência em baixo); `fail` não funciona; `off` parado de propósito (não é erro); `unknown` ainda sem dados |
| `dependencies` | o que **este** serviço vê de cada dependência. O portal usa-o para colorir as ligações do grafo (chave = `id` do serviço no `portal.yaml`) |
| `freshness` | listas e feeds com a data dos dados (`updated_at`) e a idade máxima aceitável. O portal recalcula a idade a cada pedido: ok até `max_age_hours`, aviso até 3×, depois falha. `status: off` mantém-se (ex.: feeds de um scanner on-demand) e `status: fail` indica que a última atualização falhou |
| `components` | partes que o serviço verifica por dentro e que o portal mostra como serviços próprios, com um probe `soc-component` (ex.: o Greenbone, que não tem HTTP) |
| `jobs` | tarefas agendadas, com o resultado da última |

Campos desconhecidos são ignorados; campos em falta são tratados como vazios.
