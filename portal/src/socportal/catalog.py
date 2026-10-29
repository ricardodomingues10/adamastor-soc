"""Catálogo do SOC: as funções que um SOC precisa de ter e modelos prontos para cada serviço.

As funções servem para o portal mostrar a cobertura ("que capacidades já temos?").
Os modelos preenchem o formulário de novo serviço com verificações sensatas; os URLs
de exemplo e as credenciais são sempre do utilizador. As verificações marcadas como
"vida" só confirmam que o serviço responde (aceitam 401/403 sem credencial); as que
leem a versão precisam de uma credencial de leitura.

Os caminhos dos probes são relativos ao "URL da API" do serviço (ou ao link): o mesmo
modelo serve para o laboratório e para produção.
"""

from __future__ import annotations

from typing import Any

# Funções SOC, pela ordem do ciclo: ver → saber → decidir → responder → sustentar
FUNCTIONS: dict[str, dict[str, str]] = {
    "siem": {
        "name": "SIEM e recolha de logs",
        "why": "Centraliza eventos de servidores, rede, AD e cloud; correlação e alertas.",
    },
    "edr": {
        "name": "Endpoints (EDR/XDR)",
        "why": "Telemetria e resposta nos postos e servidores: processos, ficheiros, isolamento.",
    },
    "ndr": {
        "name": "Rede (IDS/NDR)",
        "why": "Deteção no tráfego: assinaturas, anomalias, metadados de ligações.",
    },
    "vuln": {
        "name": "Gestão de vulnerabilidades",
        "why": "Scans, achados consolidados, prioridade por risco e prazos de correção.",
    },
    "cti": {
        "name": "Threat intelligence",
        "why": "Indicadores e contexto de ameaças, partilha com a comunidade (CERT.PT, RNCSIRT).",
    },
    "cases": {
        "name": "Gestão de incidentes",
        "why": "Casos, tarefas, evidências e linha temporal de cada incidente.",
    },
    "analysis": {
        "name": "Análise de observáveis",
        "why": "Enriquecimento automático de IPs, domínios, hashes e anexos.",
    },
    "soar": {
        "name": "Automação (SOAR)",
        "why": "Playbooks: triagem, enriquecimento, notificações e contenção sem trabalho manual.",
    },
    "dfir": {
        "name": "Forense e resposta",
        "why": "Recolha remota de artefactos e caça a ameaças em larga escala.",
    },
    "assets": {
        "name": "Inventário e CMDB",
        "why": "Saber o que existe, quem é o dono e quão crítico é: base do contexto de risco.",
    },
    "surface": {
        "name": "Superfície externa e certificados",
        "why": "O que está exposto à Internet, certificados a expirar, entrada pública (AVI).",
    },
    "identity": {
        "name": "Identidade e acesso",
        "why": "SSO e MFA para as ferramentas do SOC; contas de serviço controladas.",
    },
    "secrets": {
        "name": "Cofre de segredos",
        "why": "Tokens e passwords das integrações fora de ficheiros e de scripts.",
    },
    "observability": {
        "name": "Monitorização e métricas",
        "why": "Disponibilidade dos serviços, métricas e painéis operacionais.",
    },
}


def _live(path: str = "/", ok: tuple[int, ...] = (200, 301, 302, 401, 403), name: str = "Interface") -> dict[str, Any]:
    return {"type": "http", "name": name, "url": path, "expect_status": list(ok)}


TEMPLATES: list[dict[str, Any]] = [
    # --- SIEM -------------------------------------------------------------------
    {
        "id": "wazuh",
        "name": "Wazuh",
        "function": "siem",
        "description": "SIEM/XDR open source: agentes, SCA, deteção de vulnerabilidades e regras",
        "link": "https://wazuh.exemplo.pt",
        "api_url": "https://wazuh-manager.exemplo.pt:55000",
        "probes": [
            {"type": "http", "name": "API do manager", "url": "/", "expect_status": [200, 401]},
        ],
        "latest": "wazuh/wazuh",
        "setup": "Verificação de vida (a API responde 401 sem JWT). O dashboard fica no link.",
    },
    {
        "id": "opensearch",
        "name": "OpenSearch / Wazuh indexer",
        "function": "siem",
        "description": "Armazenamento e pesquisa de eventos (também serve o Elasticsearch)",
        "api_url": "https://indexer.exemplo.pt:9200",
        "probes": [
            {
                "type": "http",
                "name": "Cluster",
                "url": "/",
                "auth_scheme": "Basic",
                "version_path": "version.number",
            }
        ],
        "latest": "opensearch-project/OpenSearch",
        "setup": "Credencial no formato utilizador:password (um utilizador só de leitura).",
    },
    {
        "id": "graylog",
        "name": "Graylog",
        "function": "siem",
        "description": "Recolha e pesquisa de logs",
        "link": "https://graylog.exemplo.pt",
        "probes": [
            {"type": "http", "name": "Load balancer status", "url": "/api/system/lbstatus", "contains": "ALIVE"},
        ],
        "latest": "Graylog2/graylog2-server",
        "setup": "O lbstatus não precisa de credencial.",
    },
    {
        "id": "qradar",
        "name": "IBM QRadar",
        "function": "siem",
        "description": "SIEM (em avaliação)",
        "link": "https://qradar.exemplo.pt",
        "probes": [
            {
                "type": "http",
                "name": "API",
                "url": "/api/system/about",
                "auth_header": "SEC",
                "auth_scheme": "",
                "version_path": "external_version",
            }
        ],
        "setup": "Token de serviço autorizado (Admin → Authorized Services), enviado no cabeçalho SEC. "
        "Confirma o campo da versão na tua versão do QRadar.",
    },
    {
        "id": "sentinel",
        "name": "Microsoft Sentinel",
        "function": "siem",
        "description": "SIEM na cloud (em avaliação): só atalho, sem verificação",
        "link": "https://portal.azure.com/#browse/microsoft.securityinsightsarg%2Fsentinel",
        "probes": [],
        "setup": "Serviço cloud: o portal guarda só o atalho. O estado vem do Azure Service Health.",
    },
    # --- Endpoints / rede --------------------------------------------------------------
    {
        "id": "defender",
        "name": "Microsoft Defender XDR",
        "function": "edr",
        "description": "EDR/XDR na cloud: só atalho",
        "link": "https://security.microsoft.com",
        "probes": [],
        "setup": "Serviço cloud: só atalho.",
    },
    {
        "id": "velociraptor",
        "name": "Velociraptor",
        "function": "dfir",
        "description": "Forense remoto e caça a ameaças nos endpoints",
        "link": "https://velociraptor.exemplo.pt:8889",
        "probes": [_live("/app/index.html")],
        "latest": "Velocidex/velociraptor",
        "setup": "Verificação de vida da interface.",
    },
    {
        "id": "suricata",
        "name": "Sensor Suricata",
        "function": "ndr",
        "description": "IDS de rede; os alertas seguem para o SIEM",
        "probes": [{"type": "tcp", "name": "Sensor (SSH)", "url": "sensor-ids01.exemplo.pt:22"}],
        "latest": "OISF/suricata",
        "setup": "Sem HTTP: confirma que o sensor está acessível. A frescura dos eventos vê-se no SIEM.",
    },
    {
        "id": "zeek",
        "name": "Sensor Zeek",
        "function": "ndr",
        "description": "Metadados de rede (ligações, DNS, TLS, HTTP) para o SIEM",
        "probes": [{"type": "tcp", "name": "Sensor (SSH)", "url": "sensor-ndr01.exemplo.pt:22"}],
        "latest": "zeek/zeek",
        "setup": "Sem HTTP: verificação de acesso ao sensor.",
    },
    {
        "id": "securityonion",
        "name": "Security Onion",
        "function": "ndr",
        "description": "Plataforma de deteção de rede (Suricata, Zeek, pesquisa e casos)",
        "link": "https://so.exemplo.pt",
        "probes": [_live("/")],
        "latest": "Security-Onion-Solutions/securityonion",
        "setup": "Verificação de vida da consola.",
    },
    {
        "id": "checkpoint",
        "name": "Check Point (gestão)",
        "function": "ndr",
        "description": "Firewall e IPS: servidor de gestão / SmartConsole web",
        "link": "https://checkpoint-mgmt.exemplo.pt",
        "probes": [_live("/", name="Servidor de gestão")],
        "setup": "Verificação de vida do servidor de gestão.",
    },
    # --- Vulnerabilidades ---------------------------------------------------------------
    {
        "id": "vulnflux",
        "name": "VulnFlux",
        "function": "vuln",
        "description": "Scans WPScan e Greenbone, prioridades por risco e importação para o DefectDojo",
        "link": "https://vulnflux.exemplo.pt",
        "probes": [{"type": "soc-status", "name": "Estado", "url": "/api/status"}],
        "latest": "ricardodomingues10/vuln-flux",
        "setup": "Credencial = VF_STATUS_TOKEN do VulnFlux.",
    },
    {
        "id": "defectdojo",
        "name": "DefectDojo",
        "function": "vuln",
        "description": "Findings, prioridades e SLA de correção",
        "link": "https://defectdojo.exemplo.pt",
        "probes": [{"type": "defectdojo", "name": "API v2", "url": "/"}],
        "latest": "DefectDojo/django-DefectDojo",
        "setup": "Token da API de um utilizador só de leitura (perfil → API v2 Key).",
    },
    {
        "id": "greenbone",
        "name": "Greenbone",
        "function": "vuln",
        "description": "Scanner de rede; verificado pelo VulnFlux por GMP",
        "probes": [
            {"type": "soc-component", "name": "Via VulnFlux (GMP)", "service": "vulnflux", "component": "greenbone"}
        ],
        "setup": "Precisa do serviço VulnFlux no portal (é ele que reporta o Greenbone).",
    },
    # --- Threat intel / casos / análise / automação ----------------------------------------
    {
        "id": "misp",
        "name": "MISP",
        "function": "cti",
        "description": "Partilha de indicadores e eventos de ameaça",
        "link": "https://misp.exemplo.pt",
        "probes": [{"type": "misp", "name": "API", "url": "/"}],
        "latest": "MISP/MISP",
        "setup": "Chave da API de um utilizador só de leitura (Event Actions → Automation).",
    },
    {
        "id": "opencti",
        "name": "OpenCTI",
        "function": "cti",
        "description": "Plataforma de threat intelligence (STIX2), ligada ao MISP",
        "link": "https://opencti.exemplo.pt",
        "probes": [_live("/")],
        "latest": "OpenCTI-Platform/opencti",
        "setup": "Verificação de vida da interface.",
    },
    {
        "id": "thehive",
        "name": "TheHive",
        "function": "cases",
        "description": "Gestão de casos e alertas de segurança",
        "link": "https://thehive.exemplo.pt",
        "probes": [_live("/api/status", ok=(200, 401), name="API")],
        "setup": "Verificação de vida. Com uma chave de API (Bearer) dá para ler a versão em versions.TheHive.",
    },
    {
        "id": "iris",
        "name": "DFIR-IRIS",
        "function": "cases",
        "description": "Gestão de casos e resposta a incidentes (alternativa ao TheHive)",
        "link": "https://iris.exemplo.pt",
        "probes": [_live("/login")],
        "latest": "dfir-iris/iris-web",
        "setup": "Verificação de vida da interface.",
    },
    {
        "id": "cortex",
        "name": "Cortex",
        "function": "analysis",
        "description": "Analisadores e respondedores para observáveis (com TheHive/MISP)",
        "link": "https://cortex.exemplo.pt",
        "probes": [_live("/api/status", ok=(200, 401), name="API")],
        "latest": "TheHive-Project/Cortex",
        "setup": "Verificação de vida. A resposta 200 traz a versão em versions.Cortex.",
    },
    {
        "id": "shuffle",
        "name": "Shuffle",
        "function": "soar",
        "description": "SOAR open source: playbooks e integrações",
        "link": "https://shuffle.exemplo.pt",
        "probes": [_live("/")],
        "latest": "Shuffle/Shuffle",
        "setup": "Verificação de vida da interface.",
    },
    {
        "id": "n8n",
        "name": "n8n",
        "function": "soar",
        "description": "Automação de workflows (reconciliação de certificados, AD, relatórios)",
        "link": "https://n8n.exemplo.pt",
        "probes": [{"type": "http", "name": "Saúde", "url": "/healthz", "contains": "ok"}],
        "latest": "n8n-io/n8n",
        "setup": "O /healthz não precisa de credencial.",
    },
    # --- Inventário / superfície ---------------------------------------------------------
    {
        "id": "glpi",
        "name": "GLPI",
        "function": "assets",
        "description": "Inventário e CMDB",
        "link": "https://glpi.exemplo.pt",
        "probes": [_live("/")],
        "latest": "glpi-project/glpi",
        "setup": "Verificação de vida.",
    },
    {
        "id": "cmdb",
        "name": "CMDB",
        "function": "assets",
        "description": "CMDB existente (fonte de criticidade e responsáveis)",
        "link": "https://cmdb.exemplo.pt",
        "probes": [_live("/")],
        "setup": "Ajusta o caminho para um endpoint de saúde, se existir.",
    },
    {
        "id": "atalaia-cert",
        "name": "Atalaia Cert",
        "function": "surface",
        "description": "Monitorização e reconciliação de certificados",
        "link": "https://atalaia.exemplo.pt",
        "probes": [_live("/")],
        "setup": "Verificação de vida. Se a aplicação publicar soc-status/1, troca para esse probe e "
        "os certificados a expirar aparecem como listas no portal.",
    },
    {
        "id": "avi",
        "name": "VMware Avi (NSX ALB)",
        "function": "surface",
        "description": "Balanceamento e publicação dos serviços expostos",
        "link": "https://avi-controller.exemplo.pt",
        "probes": [
            {"type": "http", "name": "Controlador", "url": "/api/initial-data", "version_path": "version.Version"}
        ],
        "setup": "O /api/initial-data responde sem credencial na maioria das versões; confirma no teu controlador.",
    },
    # --- Identidade / segredos / observabilidade -------------------------------------------
    {
        "id": "keycloak",
        "name": "Keycloak",
        "function": "identity",
        "description": "SSO e MFA para as ferramentas do SOC",
        "link": "https://sso.exemplo.pt",
        "probes": [{"type": "http", "name": "Realm", "url": "/realms/master", "contains": "realm"}],
        "latest": "keycloak/keycloak",
        "setup": "Ajusta o realm. Não precisa de credencial.",
    },
    {
        "id": "vault",
        "name": "HashiCorp Vault / OpenBao",
        "function": "secrets",
        "description": "Cofre de segredos das integrações",
        "api_url": "https://vault.exemplo.pt:8200",
        "probes": [
            {
                "type": "http",
                "name": "Saúde",
                "url": "/v1/sys/health",
                "expect_status": [200, 429],
                "version_path": "version",
            }
        ],
        "latest": "hashicorp/vault",
        "setup": "Sem credencial. 503 = selado (fica em baixo, como deve).",
    },
    {
        "id": "vaultwarden",
        "name": "Vaultwarden",
        "function": "secrets",
        "description": "Gestor de passwords da equipa",
        "link": "https://cofre.exemplo.pt",
        "probes": [{"type": "http", "name": "Saúde", "url": "/alive"}],
        "latest": "dani-garcia/vaultwarden",
        "setup": "Sem credencial.",
    },
    {
        "id": "grafana",
        "name": "Grafana",
        "function": "observability",
        "description": "Painéis e métricas",
        "link": "https://grafana.exemplo.pt",
        "probes": [{"type": "http", "name": "Saúde", "url": "/api/health", "version_path": "version"}],
        "latest": "grafana/grafana",
        "setup": "O /api/health não precisa de credencial.",
    },
    {
        "id": "zabbix",
        "name": "Zabbix",
        "function": "observability",
        "description": "Monitorização de infraestrutura",
        "link": "https://zabbix.exemplo.pt",
        "probes": [_live("/")],
        "setup": "Verificação de vida da interface.",
    },
    {
        "id": "uptime-kuma",
        "name": "Uptime Kuma",
        "function": "observability",
        "description": "Disponibilidade de sites e serviços",
        "link": "https://status.exemplo.pt",
        "probes": [_live("/")],
        "latest": "louislam/uptime-kuma",
        "setup": "Verificação de vida.",
    },
    {
        "id": "npm",
        "name": "Nginx Proxy Manager",
        "function": "surface",
        "description": "Proxy reverso e certificados das ferramentas internas",
        "link": "https://npm.exemplo.pt",
        "probes": [
            {
                "type": "http",
                "name": "API",
                "url": "/api/",
                "contains": "OK",
                "version_regex": r'"major":\s*(\d+),\s*"minor":\s*(\d+),\s*"revision":\s*(\d+)',
            }
        ],
        "latest": "NginxProxyManager/nginx-proxy-manager",
        "setup": "O /api/ responde sem credencial e traz a versão.",
    },
    # --- Genéricos -------------------------------------------------------------------------
    {
        "id": "generic-http",
        "name": "Outro serviço web",
        "function": None,
        "description": "Qualquer aplicação com HTTP",
        "link": "https://servico.exemplo.pt",
        "probes": [_live("/")],
        "setup": "Ajusta o caminho, os códigos aceites e, se houver, a credencial e a versão.",
    },
    {
        "id": "generic-soc-status",
        "name": "Serviço com soc-status/1",
        "function": None,
        "description": "Serviço feito por nós que publica o contrato do portal",
        "link": "https://servico.exemplo.pt",
        "probes": [{"type": "soc-status", "name": "Estado", "url": "/api/status"}],
        "setup": "Ver docs/soc-status.md.",
    },
    {
        "id": "generic-tcp",
        "name": "Serviço sem HTTP",
        "function": None,
        "description": "Base de dados, sensor ou serviço só com porta TCP",
        "probes": [{"type": "tcp", "name": "Porta", "url": "host.exemplo.pt:5432"}],
        "setup": "Confirma só que a porta aceita ligações.",
    },
]

TEMPLATES_BY_ID = {t["id"]: t for t in TEMPLATES}


def coverage(services: list[Any]) -> list[dict[str, Any]]:
    """Por função SOC: os serviços que a cobrem (pelo campo function, ou pelo modelo usado)."""
    out = []
    for fid, meta in FUNCTIONS.items():
        covering = [
            s
            for s in services
            if (s.function or (TEMPLATES_BY_ID.get(s.template or s.id) or {}).get("function")) == fid
        ]
        out.append({"id": fid, **meta, "services": covering})
    return out
