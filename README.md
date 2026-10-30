# VulnFlux

Orquestrador de scans de vulnerabilidades para os sites WordPress e hosts da organização.
Junta **WPScan** e **Greenbone/OpenVAS**, envia os resultados para o **DefectDojo** e mostra
numa única página web o que correu, o que falhou e porquê.

![Painel](docs/painel.png)

## O que faz

- **Gestão de hosts pela web**: adicionar, editar, desativar ou importar uma lista colada. Não há base de dados; o estado fica em ficheiros JSON.
- **WPScan diário com rotação de hosts e de chaves**: em cada lote analisa os N hosts com a tentativa mais antiga. Usa várias chaves da API, escolhe sempre a que tem mais pedidos restantes e, se uma esgotar a meio de um scan, repete com a seguinte.
- **Greenbone on-demand**: liga a stack, espera que os feeds estejam carregados, analisa e desliga.
- **Um product por host no DefectDojo**, com um test por fonte. Os findings do WPScan e do Greenbone ficam juntos sem se fecharem uns aos outros.
- **Nada é importado sem validação**: scans vazios, interrompidos, sem dados da API ou com uma queda abrupta de findings nunca fecham findings reais.
- **Visibilidade total**: matriz host × fonte, linha temporal de passos por execução, erros agrupados por causa e artefactos brutos para download.
- **Prioridade por risco sem o DefectDojo Pro**: todos os dias cruza cada CVE com o catálogo KEV da CISA, o EPSS e os exploits públicos (Exploit-DB, Metasploit, Nuclei), junta a exposição e a criticidade do host e escreve no DefectDojo uma prioridade P1–P4 com data de correção.
- **Portal SOC** (serviço à parte, em `portal/`): uma página com todos os serviços do SOC, as ligações entre eles, erros, versões desatualizadas e a idade de cada lista/feed.

## Arquitetura

```
                 ┌──────────────────────── VulnFlux (container) ────────────────────────┐
  Browser ──────▶│  Web (FastAPI + HTMX)   Motor (agendador + 2 filas)   Estado (JSON)    │
                 │        │                      │                                        │
                 │        ▼                      ▼                                        │
                 │  Hosts ──▶ Coletores ──▶ Validação ──▶ Normalização ──▶ Gate ──▶ Import ─┼──▶ DefectDojo
                 └───────────────┬───────────────┬────────────────────────────────────────┘
                                 │               │
                         WPScan CLI + API     GMP (socket) + gb-ctl (SSH restrito)
                                                 │
                                          Greenbone on-demand
```

| Componente | Ficheiro |
|---|---|
| Configuração (`VF_*`) | `src/vulnflux/config.py` |
| Armazenamento em ficheiros | `src/vulnflux/store.py` |
| Validação de hosts | `src/vulnflux/hosts.py` |
| WPScan (CLI, validação, quota) | `src/vulnflux/collectors/wpscan.py` |
| WPScan → Generic Findings | `src/vulnflux/converters/wpscan_generic.py` |
| Greenbone (GMP, prontidão, ciclo de vida) | `src/vulnflux/greenbone/` |
| Gates | `src/vulnflux/gates.py` |
| DefectDojo | `src/vulnflux/defectdojo.py` |
| Pipelines | `src/vulnflux/pipeline.py` |
| Agendamento e filas | `src/vulnflux/engine.py` |
| Interface web | `src/vulnflux/web/` |
| Prioridade por risco (feeds, modelo, DefectDojo) | `src/vulnflux/risk/` |
| Estado para o Portal SOC (`/api/status`) | `src/vulnflux/status.py` |
| Portal SOC (serviço separado) | `portal/` |
| Greenbone sem UI + gb-ctl | `deploy/greenbone/` |

## Arranque rápido

```bash
git clone https://github.com/ricardodomingues10/vuln-flux && cd vuln-flux
cp .env.example .env && chmod 600 .env
# preencher no mínimo: VF_ADMIN_PASSWORD, VF_DD_URL, VF_DD_TOKEN, VF_WPSCAN_API_TOKENS
docker compose pull        # imagem pronta, publicada pelo CI em ghcr.io
docker compose up -d
```

Para construir localmente, usa `docker compose up -d --build`. O build precisa de acesso
ao apt do Debian, ao PyPI e ao RubyGems.

### Laboratório completo (WSL / portátil)

Um único comando constrói e arranca **VulnFlux + Greenbone + DefectDojo**. O token da API
do DefectDojo é obtido automaticamente e o utilizador GMP é criado no arranque do gvmd.

```bash
git clone https://github.com/ricardodomingues10/vuln-flux && cd vuln-flux
./scripts/lab.sh up        # 1.ª vez: cria o .env.lab com passwords aleatórias
nano .env.lab              # preencher VF_WPSCAN_API_TOKENS
./scripts/lab.sh restart
./scripts/lab.sh status    # serviços, URLs, credenciais, progresso dos feeds
```

| Serviço | URL | Credenciais |
|---|---|---|
| Portal SOC | http://localhost:8090 | `./scripts/lab.sh creds` |
| VulnFlux | http://localhost:8080 | `./scripts/lab.sh creds` |
| DefectDojo | http://localhost:8081 | `./scripts/lab.sh creds` |
| Greenbone | sem UI (GMP via socket) | utilizador `orchestrator` |

Requisitos:
- Docker Compose 2.20 ou superior.
- Cerca de 12 GB de RAM para o WSL. Define em `%UserProfile%\.wslconfig` com `[wsl2] memory=12GB swap=8GB` e corre `wsl --shutdown`.
- Cerca de 25 GB de disco.

No primeiro arranque, o Greenbone demora 30 a 90 minutos a carregar os feeds. O VulnFlux espera
sozinho pelo gate de prontidão. Outros comandos úteis: `logs <serviço>`, `rebuild` (depois de
alterar o código), `gb` (diagnóstico do Greenbone: feeds, erros, OOM, CPU, gate), `gb-restart`,
`portal` (o que o Portal SOC vê), `risk` (descarrega os feeds e recalcula as prioridades já),
`atalaia up` (clona o Atalaia Cert ao lado, gera os segredos e junta-o ao laboratório e ao portal;
também `atalaia pipeline`, `status`, `logs` e `down`),
`down` e `reset` (apaga todos os dados). Um `.env.lab` antigo ganha sozinho as chaves novas
(portal e token de estado) no próximo `up` ou `restart`.

No laboratório, o Greenbone fica sempre ligado. O ciclo on-demand com gb-ctl/SSH é só para produção.

### Servidor atrás de proxy ou sem Internet

- **Com proxy:** define `HTTP_PROXY`, `HTTPS_PROXY` e `NO_PROXY` no `.env`. Servem para o build e
  para a execução. O WPScan precisa de chegar a `wpscan.com`, a `data.wpscan.org` e aos sites.
  O `NO_PROXY` tem de incluir o DefectDojo e os destinos internos.
- **Pull da imagem por proxy:** o daemon do Docker precisa do seu próprio proxy, em
  `/etc/systemd/system/docker.service.d/proxy.conf`.
- **Sem acesso ao registo de imagens:** descarrega o artefacto `vulnflux-image` da última
  execução do CI (Actions) noutra máquina e carrega-o no servidor com
  `gunzip -c vulnflux-image.tar.gz | docker load`.

A interface fica em `http://127.0.0.1:8080`. Para a expor, publica-a através do Nginx Proxy
Manager com HTTPS. O cookie de sessão só é enviado por HTTPS (`VF_COOKIE_SECURE=true`).

Com o Greenbone na mesma máquina, segue primeiro o `deploy/greenbone/README.md` e arranca com:

```bash
docker compose -f docker-compose.yml -f docker-compose.greenbone.yml up -d --build
```

## Como funciona

### Pipelines

Cada execução (um host × uma fonte) passa por passos registados com início, fim e detalhe:

| WPScan | Greenbone |
|---|---|
| Preparar (BD de metadados) | Preparar task (target/task `vulnflux:<host>`) |
| Scan (`--format json --no-update`) | Scan (estado e progresso a cada 30 s) |
| Validar | Recolher report (XML) |
| Converter (Generic Findings) | Validar |
| Gate | Gate |
| Importar no DefectDojo | Importar no DefectDojo |

### O que bloqueia um import

| Situação | Tipo de erro |
|---|---|
| WPScan sem JSON, exit code diferente de 0/5, `scan_aborted` | Dados / Permanente |
| API do WPScan com erro, sem resposta (429 silencioso) ou quota a 0 durante o scan | Quota / Dependência |
| Report do Greenbone diferente de `Done`, task interrompida ou parada | Dados |
| Greenbone sem hosts analisados (alvo inacessível) | Dados |
| Greenbone não pronto (feeds a sincronizar, VTs por carregar, scanner em baixo) | Dependência |

Uma **queda abrupta** (por omissão, mais de 50% face à última execução boa, com pelo menos 5
findings antes) não bloqueia o import. Importa sem `close_old_findings` e marca a execução
como *Com avisos*.

### Modelo no DefectDojo

```
Product type  = ambiente do host       (ex.: Sites_Publicos_PRD)
Product       = nome canónico do host  (ex.: www.exemplo.pt)
Engagement    = VF_DD_ENGAGEMENT       (VulnFlux)
Test          = "WPScan" | "Greenbone"
```

O reimport usa sempre `auto_create_context=true`, `close_old_findings_product_scope=false`
e `do_not_reactivate=false`. Um finding que volte a aparecer é reaberto.

### O que o WPScan analisa e importa

O scan corre com `--enumerate vp,vt,tt,cb,dbe,bf,u1-10 --plugins-detection mixed`. É
configurável com `VF_WPSCAN_ENUMERATE` e `VF_WPSCAN_PLUGINS_DETECTION`. Sem `-e`, o WPScan
4.x não analisa plugins nem utilizadores. Tudo vai num único import (test "WPScan"):

| Resultado do WPScan | Finding no DefectDojo | Severidade |
|---|---|---|
| Vulnerabilidades do core, de plugins e de temas | um por vulnerabilidade e componente, com CVE, versão detetada e versão corrigida | pelo CVSS (Medium sem CVSS) |
| Timthumbs vulneráveis | um por vulnerabilidade e ficheiro | pelo CVSS |
| Backup do `wp-config` acessível (`cb`) | um por URL | High |
| Export da base de dados acessível (`dbe`) | um por URL | High |
| Pasta de backup acessível (`bf`) | um por URL, com o conteúdo listado | a indicada pelo WPScan |
| Utilizadores enumerados (`u`) | um por site, com a lista de usernames | Low (`VF_WPSCAN_INCLUDE_USERS`) |
| Interesting findings | um por item | Info (`VF_WPSCAN_INCLUDE_INTERESTING`) |

O JSON bruto de cada scan fica guardado como artefacto da execução.

### Chaves WPScan

`VF_WPSCAN_API_TOKENS` aceita várias chaves, separadas por vírgulas. O funcionamento é este:

1. No início de cada lote, consulta o estado de todas as chaves. O endpoint de status não gasta quota.
2. Para cada scan, escolhe a chave com mais pedidos restantes. As inválidas ou abaixo de `VF_WPSCAN_MIN_QUOTA` ficam de fora.
3. Depois do scan, atualiza a quota dessa chave com o valor que o próprio WPScan devolve.
4. Se a chave esgotar a meio do scan, marca-a como esgotada e repete o scan com a seguinte. O resultado parcial nunca é importado.
5. Quando todas esgotam, os hosts restantes do lote ficam como *Ignorado* (quota) e entram no lote seguinte.

O estado de cada chave (plano, pedidos restantes, scans feitos, última verificação) aparece
em **Definições**. As chaves nunca são gravadas em disco nem mostradas: o estado usa uma
impressão digital e os últimos 4 caracteres.

### Prioridade por risco

O DefectDojo OSS já tem, em cada finding, os campos `epss_score`, `epss_percentile`,
`known_exploited`, `ransomware_used`, `kev_date` e `planned_remediation_date`. O Pro só
acrescenta quem os preenche. No VulnFlux esse papel é de um job diário (`VF_RISK_CRON`,
06:17) e de um recálculo do host no fim de cada import:

1. **Feeds** (cada um independente; se um falhar fica a cópia anterior e o erro aparece):
   catálogo KEV da CISA, EPSS do dia, índice do Exploit-DB, módulos do Metasploit e
   templates de CVE do Nuclei.
2. **Contexto do inventário**: cada host tem criticidade, exposição (internet, DMZ, interno,
   isolado) e dados tratados. Dados pessoais elevam a criticidade a pelo menos Alto e dados
   sensíveis (saúde, sociais) a Crítico.
3. **Modelo v1** (`src/vulnflux/risk/score.py`):

   ```
   ameaça   = 0,30·CVSS/10 + 0,30·EPSS percentil + 0,25·exploit + 0,15·KEV
   contexto = exposição × criticidade efetiva
   risco    = 100 × ameaça × contexto        P1 ≥ 70 · P2 ≥ 50 · P3 ≥ 30 · P4
   KEV exposto à Internet → P1 · KEV na DMZ → pelo menos P2
   ```

   Sem CVE (backups expostos, utilizadores enumerados) conta a severidade do scanner.
   Info não é priorizado.
4. **DefectDojo**: tags `risk:p1`…`risk:p4`, `risk:kev`, `risk:ransomware`,
   `risk:exploit-<fonte>`, os campos EPSS/KEV e a data planeada de correção pelo SLA
   (`VF_RISK_SLA_DAYS`, por omissão 7/30/90/180 dias; o prazo da CISA ganha se for antes).
   No Product ficam `business_criticality` e `internet_accessible`.

Regras de convivência: a severidade do scanner nunca muda, as tags que não começam por
`risk:` ficam, uma data planeada alterada à mão no DefectDojo é respeitada, e só há PATCH
quando algo muda (duas passagens seguidas = zero escritas). Sem Internet, aponta os
`VF_RISK_*_URL` para um espelho interno ou para `file:///caminho`.

A página **Prioridades** mostra os findings mais urgentes com as razões da nota, o estado
de cada feed e as últimas execuções.

### Servidores: saúde, hardening e atualizações

Página **Servidores**: cada servidor ligado por SSH, sem agente, com o estado de saúde, a pontuação de
hardening, as atualizações pendentes e os anéis de atualização.

![Servidores](docs/servidores.png)

![Detalhe de um servidor](docs/servidor-detalhe.png)

**Ligar um servidor** (uma vez, um minuto):

1. Escolher o perfil: *Só verificar* (só leitura, recomendado) ou *Verificar e atualizar*.
2. Colar no servidor, como administrador, a linha que a página mostra. Cria a conta `vulnflux` sem
   palavra-passe, instala a chave própria do VulnFlux (ed25519 gerada em `/data/ssh`, com `no-pty` e
   sem túneis) e um sudo limitado aos comandos exatos da recolha, validado com `visudo`. O script pode
   ser lido antes (`/servers/bootstrap.sh`).
3. *Adicionar servidor* (ou, num host que já existe, ligar "Servidor (SSH)") e *Verificar*.

A chave do servidor é fixada na primeira ligação. Se mudar, a ligação para até alguém carregar em
*Aceitar a nova chave*.

**O que é verificado** (a cada 6 h, `VF_SERVERS_CRON`):

| Área | Verificações |
|---|---|
| Saúde | memória, swap, disco e inodes por partição, carga por CPU, serviços falhados, OOM nos últimos 7 dias, uptime |
| Hardening | SSH efetivo (`sshd -T`: root, palavra-passe, vazias, X11, tentativas), firewall (ufw, firewalld, nftables, iptables), SELinux/AppArmor, auditd, NTP, atualizações automáticas, contas UID 0, permissões de `/etc/shadow`, `passwd`, `sudoers`, sysctl do kernel (ASLR, redirects, syncookies, kptr/dmesg, symlinks) e o índice do Lynis, se estiver instalado |
| Atualizações | pendentes e de segurança (apt, dnf/yum, zypper), reinício pendente |

A pontuação pesa a gravidade (alta 3, média 2, baixa 1). Cada verificação que falha mostra o valor
encontrado, o esperado e o comando para corrigir. As verificações de hardening falhadas e as
atualizações de segurança vão para o DefectDojo (test "Servidor (hardening e atualizações)", no mesmo
product do host) e fecham sozinhas quando corrigidas. A saúde fica no painel. Os limiares estão em
`VF_SERVERS_MEM_PCT`, `_DISK_PCT`, `_SWAP_PCT` e `_LOAD_PER_CPU`.

**Atualizações por anéis** (`VF_PATCH_CRON`, terça às 03:41 por omissão):

| Anel | Para quem | Portão |
|---|---|---|
| 0 · Canário | laboratório e testes | começa logo |
| 1 · Piloto | uma amostra de cada tipo | anel 0 bem + `VF_PATCH_SOAK_HOURS` (24 h) |
| 2 · Geral | a maioria | anel 1 bem + observação |
| 3 · Críticos | produção crítica | anel 2 bem + observação + **aprovação** na página |

Em cada servidor a atualização faz:

1. **Pré-verificação:** espaço livre em `/` e `/var`, sudo e o que há para atualizar.
2. **Atualizar:** só segurança (`unattended-upgrade` ou `--security`) ou tudo, conforme o modo do servidor.
3. **Reiniciar:** só se a atualização o pedir e "reiniciar sozinho" estiver ligado; espera que o servidor volte.
4. **Pós-verificação:** um serviço que deixe de arrancar é uma falha.

Se um servidor falha, o ciclo para antes do anel seguinte. *Repetir o anel que falhou* retoma-o.
Servidores em "Só verificar" (o modo por omissão) nunca são alterados.

No laboratório, `./scripts/lab.sh servers demo` cria um servidor Debian de demonstração, liga-o com o
comando de bootstrap e corre a primeira verificação. `servers ligar` mostra o comando para ligar um
servidor teu.

### Tipos de erro

| Tipo | Significado | O que acontece |
|---|---|---|
| Transitório | timeout, 5xx, lock | entra no lote seguinte |
| Dependência em baixo | DefectDojo, gvmd ou API indisponíveis | o lote é ignorado sem gastar quota |
| Dados inválidos | resultado não passou a validação | não importa |
| Quota esgotada | token WPScan sem pedidos | o host entra no lote seguinte |
| Permanente | não é WordPress, redireciona, credenciais erradas | é preciso rever o host |
| Configuração | falta um token ou um URL | é preciso rever o `.env` |

## Interface

- **Painel**: KPIs das últimas 24 h, estado das dependências, últimos lotes e agenda, execuções em curso, matriz host × fonte (atualiza sozinha) e falhas recentes.
- **Hosts**: lista com filtro (tecla `/`), adicionar ou editar num modal, contexto de risco (criticidade, exposição, dados), importação em lote (`url ; ambiente ; etiquetas ; criticidade ; exposição ; dados`), exportação JSON, ativar/desativar e “Correr agora” por fonte.
- **Execuções**: filtros por fonte, estado, tipo de erro e host. O detalhe mostra os passos, o erro com o detalhe técnico, os avisos, as estatísticas do DefectDojo (novos/fechados/reabertos) e os artefactos.
- **Prioridades**: contagens P1–P4, findings mais urgentes com as razões e o link para o DefectDojo, feeds de ameaça e o modelo explicado.
- **Erros**: falhas agrupadas por causa, com contagem e hosts afetados.
- **Definições**: configuração efetiva (com os segredos ocultos), agenda e ações manuais.

## Configuração

Toda a configuração está no `.env.example`, comentado. Os valores mais importantes:

| Variável | Omissão | Notas |
|---|---|---|
| `VF_ADMIN_PASSWORD` | — | obrigatória |
| `VF_DD_URL` / `VF_DD_TOKEN` | — | token de um utilizador com permissão de import |
| `VF_DD_CA_BUNDLE` | — | CA interna, se o DefectDojo usar um certificado privado |
| `VF_WPSCAN_API_TOKENS` | — | uma ou várias chaves; sem nenhuma, os scans WPScan nem arrancam |
| `VF_WPSCAN_CRON` / `VF_WPSCAN_BATCH_SIZE` | `37 2 * * *` / `4` | plano free: 25 pedidos/dia |
| `VF_GREENBONE_ENABLED` | `false` | |
| `VF_GREENBONE_SSH_HOST` | — | vazio = Greenbone sempre ligado, sem start/stop |
| `VF_RISK_CRON` / `VF_RISK_SLA_DAYS` | `17 6 * * *` / `7,30,90,180` | prioridades: job diário e SLA de P1 a P4 |
| `VF_RISK_KEV_URL`, `VF_RISK_EPSS_URL`, … | fontes oficiais | vazio desliga a fonte; aceita `file://` |
| `VF_DD_PUBLIC_URL` | `VF_DD_URL` | URL do DefectDojo para os links no browser |
| `VF_STATUS_TOKEN` | — | ativa `/api/status` para o Portal SOC |

Os segredos também podem vir de Docker secrets: `/run/secrets/vf_dd_token` preenche `VF_DD_TOKEN`.

## Portal SOC

Serviço próprio, em `portal/`, com imagem e compose separados
(`ghcr.io/ricardodomingues10/soc-portal`). Monitoriza por HTTP: não partilha rede, volumes
nem base de dados com ninguém, por isso corre em qualquer máquina e acompanha os serviços
quando estes passarem para máquinas dedicadas (DefectDojo, MISP, …). Os serviços são
descritos no `portal.yaml`; mudar um serviço de máquina é mudar um URL. Ver `portal/README.md`
e o contrato de estado em `docs/soc-status.md`.

## Dados e backups

Tudo vive no volume `/data`:

```
/data/hosts.json          hosts (exportável também pela interface)
/data/state.json          saúde, lotes, estado do Greenbone
/data/runs/<id>.json      uma execução por ficheiro
/data/artifacts/<id>/     JSON/XML brutos, ficheiro enviado e resposta do DefectDojo
/data/wpscan-home/        BD de metadados do WPScan
```

As escritas são atómicas (ficheiro temporário + `fsync` + `rename`). Execuções com mais de
`VF_RETENTION_DAYS` são apagadas todos os dias às 04:11. Para fazer backup, basta copiar o volume.

A aplicação corre num único processo, com o agendador e as filas lá dentro. Não a escales
para mais réplicas.

## Migrar do n8n

1. Importa a lista de sites em **Hosts → Importar lista**, com o mesmo ambiente que o `lista_sites` usava.
2. Confirma que os nomes canónicos são iguais aos `product_name` atuais no DefectDojo. Se forem, os findings continuam nos mesmos products.
3. Os tests passam a chamar-se "WPScan" e "Greenbone". Os antigos (`WPSCAN-CORE-ON-DEMAND`, `WPSCAN-ON-DEMAND`, "Greenbone scan") deixam de ser atualizados e podem ser fechados no DefectDojo depois do primeiro ciclo bom.
4. Desliga os workflows do n8n e os agendamentos `criar_tasks_usc.sh` / `correr_tasks_usc.sh`.

## Desenvolvimento

```bash
pip install -e ".[dev]"
pytest                       # VulnFlux
(cd portal && pip install -e ".[dev]" && pytest)   # Portal SOC
ruff check src tests scripts && ruff format --check src tests scripts
shellcheck deploy/greenbone/gb-ctl.sh

# Interface com dados de demonstração (sem scanners)
python scripts/seed_demo.py vf-demo-data
VF_DATA_DIR=vf-demo-data VF_ADMIN_PASSWORD=demo VF_COOKIE_SECURE=false python -m vulnflux
```

A interface não tem build: HTML (Jinja2) em `src/vulnflux/web/templates/`, uma folha de estilos
em `static/css/app.css` (cores em variáveis no topo, com modo escuro automático) e o HTMX
servido localmente. Não depende de nenhum CDN. A CSP é estrita: não há scripts nem estilos inline.

## Limitações conhecidas

- Se o VulnFlux reiniciar a meio de um lote do Greenbone, as execuções ficam como *Interrompido* e as tasks continuam a correr no gvmd. O lote seguinte deteta a task ativa e reporta *Transitório*.
- Há um único utilizador de administração, configurado por variável de ambiente.
- Não há envio de alertas por email. O painel é a fonte de verdade.
