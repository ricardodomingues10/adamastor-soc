# WordPress: análise com chaves gratuitas, chave paga e vigilante de atualizações

## Os dois modos de análise

| | `partilhado` (por omissão) | `por_site` |
|---|---|---|
| Enumeração (plugins, temas, versões) | WPScan **sem chave**, não gasta quota | WPScan com `--api-token` |
| Vulnerabilidades | 1 pedido à API por componente único, em cache `VF_WPSCAN_CACHE_HOURS` para todos os sites | 1 pedido por componente **em cada site** |
| Custo para 50 sites com 30 plugins em comum | ~30 pedidos no primeiro dia, depois só os que expiram | ~1 500 pedidos por ronda |
| Para quem | chaves gratuitas (25 pedidos/dia cada) | chave paga |
| Lote | todos os sites (`VF_WPSCAN_SHARED_BATCH_SIZE=0`) | `VF_WPSCAN_BATCH_SIZE` sites |

Muda-se com `VF_WPSCAN_MODE=partilhado` ou `VF_WPSCAN_MODE=por_site`. Os findings no DefectDojo
têm o mesmo formato nos dois modos.

### Como funciona o modo partilhado

1. **Enumerar**: `wpscan` sem chave, com o perfil do lote (abaixo). Sem chave, `vp`/`vt`
   ("só os vulneráveis") não listam nada, por isso enumera-se tudo o que se encontra.
2. **Vulnerabilidades**: para cada componente (`wordpress <versão>`, `plugin <slug>`, `theme <slug>`):
   - cache válida → usa-a (0 pedidos);
   - expirada ou inexistente → pede à API v3 (`/plugins/<slug>`, `/themes/<slug>`, `/wordpresses/<versão>`)
     com a chave com mais quota; 429 marca a chave como esgotada e passa à seguinte;
   - sem quota em nenhuma chave → usa a cache antiga (aviso) ou fica **por verificar**.
3. **Versões**: a comparação `introduced_in`/`fixed_in` é feita localmente, com as mesmas regras do WPScan.
   Componente sem versão conhecida conta todas as vulnerabilidades (como o WPScan).
4. **Import**: se algum componente ficou por verificar ou com dados antigos, o import **não fecha
   findings antigos** desse site e a execução fica como *Aviso*. O lote seguinte completa-o.

A cache está em `data/wp_vulndb.json`. A página **WordPress** mostra quantos componentes faltam
atualizar e a quota disponível; se faltarem mais do que a quota de um dia, a cache vai-se
completando ao longo dos dias. Antes de cada lote, os componentes já conhecidos são
refrescados por ordem justa (primeiro os nunca obtidos, depois os mais antigos), para que os sites do
fim da lista não fiquem sempre sem dados.

### Quantas chaves preciso?

Pedidos por dia ≈ componentes únicos ÷ (`VF_WPSCAN_CACHE_HOURS` ÷ 24). Com 120 componentes únicos e
cache de 72 h, são ~40 pedidos/dia: duas chaves gratuitas. A página mostra os componentes únicos.

## Que hosts são WordPress

Todos os dias antes do lote (`VF_WP_DETECT_CRON`) e a pedido na página **WordPress**, cada host com URL
ou nome de domínio é visitado: página inicial (cabeçalho `Link` da API, `meta generator`, `/wp-content/`),
depois `/wp-json/` e `/wp-login.php` se a página não chegar para decidir. O resultado fica com as
evidências. Os que não são WordPress saem do lote; os que são e não têm o WPScan ativo ficam com um botão
para o ativar. Um host sem resposta continua no lote (pode ser só um problema de rede).

## Enumeração: o que se encontra e o que pode escapar

| Perfil | Como procura | Tempo por site | Quando |
|---|---|---|---|
| `rapido` | só o que a página revela: HTML, scripts e estilos (`--plugins-detection passive`, `-e ap,at`) | minutos | todos os dias |
| `completo` | também testa os ~1 500 plugins e temas mais populares e os timthumbs nos caminhos conhecidos (`mixed`, `-e p,t,tt`) | dezenas de minutos | semanal (`VF_WPSCAN_DEEP_CRON`) e a pedido |
| `exaustivo` | testa todos os plugins do diretório, mais de 100 000 caminhos (`aggressive`, `-e ap`) | horas, e o WAF nota | só a pedido, um site de cada vez |

Os perfis `completo` e `exaustivo` fazem uma pausa de `VF_WPSCAN_THROTTLE_MS` (150 ms) entre pedidos,
para não sobrecarregar o site nem disparar o WAF; põe o IP do scanner na lista de permissões do WAF.

Um plugin pode escapar quando não deixa rasto na página pública (só funciona no painel de
administração, ou carrega os ficheiros só em algumas páginas) e não está entre os populares, ou quando
um WAF ou CDN esconde os caminhos. Para não perder o que a análise completa encontrou, os plugins que
ela viu continuam a ser verificados nas rápidas durante `VF_WPSCAN_CARRY_DAYS` dias.

A única forma de ter a lista completa e exata (incluindo plugins inativos) é perguntar ao próprio
WordPress: `wp plugin list --format=json` por SSH, ou `/wp-json/wp/v2/plugins` com uma *application
password* de leitura. Isso precisa de acesso a cada site; ainda não está ligado.

## Vigilante de atualizações e vulnerabilidades

Corre a cada `VF_WATCH_INTERVAL_MINUTES` (15 por omissão) e cruza o que sai de novo com o inventário
de cada site (a última enumeração).

| Fonte | O que dá | Custo |
|---|---|---|
| wordpress.org | versão atual do núcleo e de cada plugin/tema do diretório oficial | grátis |
| WPScan | vulnerabilidades novas dos componentes instalados, incluindo plugins premium | cache grátis; com quota acima de `VF_WATCH_WPSCAN_RESERVE` refresca até `VF_WATCH_WPSCAN_REFRESH` componentes por verificação |
| Wordfence Intelligence | feed de vulnerabilidades (`VF_WATCH_WORDFENCE_TOKEN`, chave gratuita) | 1 pedido a cada `VF_WATCH_WORDFENCE_MINUTES` |
| GitHub | releases das ferramentas do SOC (`VF_WATCH_GITHUB_REPOS`) | 60 pedidos/h sem token |
| RSS/Atom | avisos de CERT ou fornecedores (`VF_WATCH_RSS_FEEDS`) | grátis |

"Tempo real" aqui é *polling*: o atraso máximo é o intervalo (15 min) mais o tempo que a fonte demora
a publicar. Nenhuma destas fontes oferece notificações push gratuitas.

A primeira verificação **só regista o estado** (versões e vulnerabilidades já conhecidas), para não
enviar centenas de alertas. Daí em diante, cada novidade gera um evento, uma única vez:

| Evento | Quando | Canal |
|---|---|---|
| Vulnerabilidade | nova e afeta a versão instalada em pelo menos um site | ticket se gravidade ≥ `VF_TICKET_MIN_SEVERITY` (alta), e email |
| Versão | nova versão e há sites abaixo dela; ou nova release de uma ferramenta do SOC | email |
| Aviso | item novo num feed RSS (gravidade média se mencionar um plugin instalado) | email |

### Email e encaminhamento por equipa

`VF_SMTP_*` configura o servidor. Cada host pode ter a etiqueta `equipa:<nome>`; `VF_WATCH_ROUTES`
diz para onde vai cada equipa (`web=web@exemplo.pt; infra=infra@exemplo.pt`). Sem equipa ou sem rota,
vai para `VF_WATCH_EMAIL_TO`. Os eventos de uma verificação seguem num único email por grupo de
destinatários. `VF_WATCH_EMAIL_MIN_SEVERITY=medium` deixa de fora as novas versões.

### Tickets

- `VF_TICKET_MODE=email`: envia para `VF_TICKET_EMAIL` (a maioria dos service desks, incluindo o SMAX,
  cria tickets a partir de email).
- `VF_TICKET_MODE=webhook`: `POST` JSON para `VF_TICKET_WEBHOOK_URL` com `Authorization: Bearer
  VF_TICKET_WEBHOOK_TOKEN`. Um workflow n8n recebe e cria o ticket em qualquer ferramenta (SMAX,
  Jira, GLPI, ServiceNow). O corpo:

```json
{
  "event_id": "vuln:plugin:contact-form-7:CVE-2026-0001",
  "title": "[SOC][Crítica] CF7 < 5.8.5 - RCE — 3 site(s) afetado(s)",
  "severity": "critical",
  "kind": "vulnerabilidade",
  "component": {"type": "plugin", "slug": "contact-form-7", "version": null},
  "teams": ["web"],
  "sites": [{"host_id": "…", "name": "a.exemplo.pt", "version": "5.7.1"}],
  "references": ["https://wpscan.com/vulnerability/…", "CVE-2026-0001"],
  "description": "texto pronto para o corpo do ticket"
}
```

`event_id` é a chave de idempotência: usa-a no workflow para não duplicar tickets. A resposta pode
trazer `id`, `ticket` ou `number`, que aparece na página.

Um envio que falhe fica marcado na página e é repetido nas verificações seguintes (até 5 tentativas).
**Enviar alerta de teste** na página WordPress testa os canais configurados.
