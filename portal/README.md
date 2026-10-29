# Portal SOC

Página de entrada do SOC: um mosaico por serviço com o link para a interface, o estado
real (não só "responde"), a versão em uso face à última release, as ligações entre
serviços e a idade de cada lista ou feed (Greenbone, WPScan, KEV, EPSS, exploits).

## Porque é um serviço à parte

- **Não depende de nada local.** Fala com cada serviço só por HTTP(S) ou TCP. Não usa o
  socket do Docker, não partilha volumes nem base de dados. Corre numa VM própria, ao lado
  de um serviço ou no portátil.
- **Mudar um serviço de máquina é editar um URL** no `portal.yaml`. O ficheiro é relido
  sozinho quando muda; se ficar inválido, o portal continua com a última versão boa e
  mostra o erro no topo.
- **Uma queda não arrasta as outras.** Cada verificação é independente, com timeout próprio.
  Um serviço em baixo aparece a vermelho; os outros continuam a ser verificados.
- **Sem estado importante.** O `data_dir` guarda o último estado conhecido, o histórico de
  quedas/recuperações e a cache das versões. Apagá-lo só faz perder o histórico.

## Como verifica cada serviço

| Probe | Para quê |
|---|---|
| `soc-status` | Serviços que publicam o contrato [`soc-status/1`](../docs/soc-status.md): estado, dependências, listas e tarefas. O VulnFlux publica-o. |
| `soc-component` | Parte reportada por outro serviço. O Greenbone não tem HTTP no laboratório: o VulnFlux verifica-o por GMP e reporta os feeds. |
| `defectdojo` | API v2 com token (de preferência um utilizador só de leitura) e versão da aplicação. |
| `misp` | `/servers/getVersion.json` com a chave da API. |
| `http` | Qualquer interface web: código esperado e, opcionalmente, um texto na resposta. |
| `tcp` | Bases de dados ou serviços sem HTTP (`host:porta`). |

A versão mais recente vem das releases do GitHub (`latest.github: owner/repo`), consultada
de 12 em 12 horas. Sem Internet aparece "última: ?" e nada mais é afetado.

Estados: **OK**, **Atenção** (funciona com problemas), **Em baixo**, **Adormecido** (parado
de propósito, ex.: Greenbone on-demand fora da janela de scan) e **Por verificar**.

## Instalação

```bash
cd portal
cp portal.example.yaml portal.yaml      # serviços, URLs, dependências
cp .env.example .env && chmod 600 .env  # SP_ADMIN_PASSWORD, proxy, webhook
mkdir -p secrets
echo -n '<token só de leitura do DefectDojo>' > secrets/sp_dd_token
echo -n '<VF_STATUS_TOKEN do VulnFlux>'      > secrets/sp_vulnflux_status_token
docker compose pull && docker compose up -d
```

No VulnFlux, define `VF_STATUS_TOKEN` (o mesmo valor) para ativar `/api/status`.

O portal publica em `127.0.0.1:8090`; expõe-no através do proxy reverso com HTTPS
(`SP_COOKIE_SECURE=true`).

Diagnóstico sem browser:

```bash
docker compose exec portal soc-portal check          # tabela
docker compose exec portal soc-portal check --json   # tudo, em JSON
```

## Alertas

`SP_WEBHOOK_URL` recebe um POST JSON `{"text": "...", "service": ..., "from": ..., "to": ...}`
quando um serviço cai e quando recupera (`SP_WEBHOOK_LEVEL=warn` inclui os avisos). Funciona
com Teams, Slack, Mattermost ou um coletor do SIEM.

`GET /api/summary` (sessão ou `Authorization: Bearer <SP_API_TOKEN>`) devolve o estado de
todos os serviços, as listas e as ligações, para integrar noutro sistema.

## Acrescentar um serviço

**Pela interface (Catálogo):** o catálogo lista as 14 funções de um SOC (SIEM, endpoints,
rede, vulnerabilidades, threat intel, incidentes, análise, SOAR, forense, inventário,
superfície externa, identidade, segredos, monitorização), mostra quais já estão cobertas e
traz modelos prontos: Wazuh, OpenSearch, Graylog, QRadar, Sentinel, Defender, Suricata,
Zeek, Security Onion, Check Point, MISP, OpenCTI, TheHive, DFIR-IRIS, Cortex, Shuffle, n8n,
Velociraptor, GLPI, CMDB, Atalaia Cert, Avi, Nginx Proxy Manager, Keycloak, Vault,
Vaultwarden, Grafana, Zabbix, Uptime Kuma, e genéricos (HTTP, TCP, soc-status).

O modelo preenche o formulário; ajustas o link, a credencial e as dependências, carregas
em **Testar verificações** (corre já, a partir do portal, sem gravar) e depois em
**Adicionar ao portal**. Os serviços criados assim ficam em `data_dir/services.json` e
as credenciais em `data_dir/secrets/` (0600), nunca no JSON nem na página. Editam-se e
removem-se na página do serviço. Os do `portal.yaml` só se mudam no ficheiro.

Nos probes, um caminho começado por `/` é relativo ao "URL das verificações" do serviço
(ou ao link). Opções do probe `http`: `auth_header`/`auth_scheme` (Bearer, Token, Basic com
`utilizador:password`, ou só o token, ex. o cabeçalho `SEC` do QRadar), `version_path`
(caminho no JSON, ex. `version.number`) e `version_regex`.

**No `portal.yaml`** (configuração como código):

```yaml
  - id: misp
    name: MISP
    group: Threat intelligence
    link: https://misp.soc.exemplo.pt
    location: vm-soc-misp01
    probes:
      - type: misp
        url: https://misp.soc.exemplo.pt
        token_file: /run/secrets/sp_misp_key
      - type: tcp
        name: Base de dados
        url: db-misp01.soc.exemplo.pt:3306
    latest:
      github: MISP/MISP
```

Um serviço novo feito por nós (por exemplo, o worker de auditoria de servidores) deve
publicar `soc-status/1`: entra no portal com as suas listas e tarefas sem tocar no portal.

## Desenvolvimento

```bash
pip install -e ".[dev]"
pytest
ruff check src tests && ruff format --check src tests
SP_DATA_DIR=/tmp/sp SP_CONFIG_FILE=portal.example.yaml SP_ADMIN_PASSWORD=dev SP_COOKIE_SECURE=false soc-portal
```
