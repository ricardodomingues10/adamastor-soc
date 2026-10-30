"""Gera o mapa da infraestrutura do Adamastor SOC (HTML interativo + draw.io) a partir do compose resolvido."""
import json, html, sys
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).parent
CFG = json.load(open(sys.argv[1]))
SV = CFG["services"]

KINDS = {
    "web": "Browser → serviço",
    "api": "API / HTTP",
    "sock": "Socket Unix",
    "db": "Base de dados",
    "vol": "Volume partilhado",
    "ssh": "SSH",
    "scan": "Varrimento de rede",
    "ext": "Sistema externo",
    "dep": "Ordem de arranque",
}

ZONES_LAB = [
    dict(id="host", x=250, y=110, w=1000, h=830, label="Máquina do laboratório (WSL) · Docker · projeto vulnflux-lab · 8 redes segmentadas por função", cls="host"),
    dict(id="z-atalaia", x=270, y=150, w=250, h=270, label="Atalaia Cert · perfil atalaia", cls="zone"),
    dict(id="z-portal", x=270, y=440, w=250, h=110, label="Portal e backups", cls="zone"),
    dict(id="z-servers", x=270, y=570, w=250, h=110, label="Servidores · perfil servers", cls="zone"),
    dict(id="z-alvos", x=270, y=700, w=250, h=220, label="Rede alvos · internal, sem saída", cls="alvos"),
    dict(id="z-vulnflux", x=545, y=150, w=280, h=270, label="VulnFlux · motor de risco", cls="zone"),
    dict(id="z-dd", x=850, y=150, w=380, h=400, label="DefectDojo · gestão de findings", cls="zone"),
    dict(id="z-gb", x=545, y=570, w=685, h=350, label="Greenbone Community · scanner de rede", cls="zone"),
    dict(id="z-ext-l", x=10, y=150, w=225, h=410, label="Sistemas do cliente e Internet (Atalaia)", cls="ext"),
    dict(id="z-ext-r", x=1265, y=110, w=225, h=760, label="Internet e serviços externos", cls="ext"),
]

W, H = 150, 46

def c(id, x, y, label=None, sub="", zone="", notes=(), warn=False, run_once=False, w=W, h=H):
    s = SV[id]
    img = s.get("image", "")
    ports = [f"{p.get('host_ip','')}:{p.get('published')}→{p['target']}" for p in s.get("ports", [])]
    vols = []
    for v in s.get("volumes", []):
        src = v.get("source", "")
        if v.get("type") == "bind":
            src = src.replace("/home/claude/certs-watch", "certs-watch").replace("/home/claude/adamastor-soc/", "")
        vols.append(f"{src} → {v['target']}{' (só leitura)' if v.get('read_only') else ''}")
    return dict(id=id, label=label or id, sub=sub, x=x, y=y, w=w, h=h, zone=zone, type="container",
                image=img, profile=", ".join(s.get("profiles") or []) or "sempre", ports=ports, vols=vols,
                secrets=[x["source"] for x in s.get("secrets", [])], nets=list(s.get("networks", {}) or {"default": None}),
                notes=list(notes), warn=warn, run_once=run_once)

def x_(id, x, y, label, sub="", notes=(), w=205, h=44, type="external", warn=False):
    return dict(id=id, label=label, sub=sub, x=x, y=y, w=w, h=h, zone="", type=type, image="", profile="",
                ports=[], vols=[], secrets=[], nets=[], notes=list(notes), warn=warn, run_once=False)

LATEST = "Imagem fixada por digest; o Dependabot propõe as subidas."
ONCE = "Corre ao arrancar e termina."
FEED = "Contentor de feed: copia os dados da imagem para o volume e termina. Atualiza-se com um pull da imagem."

N_LAB = [
    x_("browser", 640, 30, "Browser do analista", "Windows / WSL · só localhost", type="user"),
    # Atalaia
    c("atalaia-web", 320, 190, sub="interface e API · :8088", zone="z-atalaia",
      notes=["Código do repositório certs-watch (build local).", "Monta trust/, import/ e branding/ só de leitura.", "9 segredos Docker (BD, admin, UCMDB, SMAX, SMTP, Avi)."]),
    c("atalaia-worker", 320, 270, sub="recolha e alertas agendados", zone="z-atalaia",
      notes=["Faz todas as ligações para fora: CMDB, tickets, CT, TLS, SMTP, Avi.", "Partilha a base de dados com o atalaia-web (sem API entre os dois)."]),
    c("atalaia-db", 320, 350, sub="PostgreSQL 16", zone="z-atalaia", notes=["Volume atalaia_pgdata. Sem backup automático."]),
    # Portal
    c("backup", 400, 480, sub="diário · 02:30", zone="z-portal", w=110, run_once=False,
      notes=["pg_dump do DefectDojo e do Atalaia, tar do estado do VulnFlux e do portal, para .lab/backups.",
             "Guarda 14 dias; ./scripts/lab.sh backup [agora | lista | restaurar].", "Restauro verificado no CI."]),
    c("sonda", 320, 730, sub="nmap · descoberta", zone="z-alvos",
      notes=["nmap -sS a todas as portas TCP, a pedido do VulnFlux (perfil descoberta).",
             "Mesmo ponto da rede que o scanner: redes alvos e saida.", "Só NET_RAW, sistema de ficheiros só de leitura, token."]),
    c("portal", 280, 480, label="portal", sub="Adamastor · :8090", zone="z-portal", w=110,
      notes=["Configuração em deploy/portal/portal.lab.yaml (só leitura).", "Lê os tokens de lab_secrets (só leitura) para consultar as APIs.", "Estado em portal_data."]),
    # Servers
    c("lab-server", 320, 610, sub="Debian + SSH · alvo de hardening", zone="z-servers",
      notes=["Configuração fraca de propósito: SSH com palavra-passe, sem firewall, sem auditd.", "Chaves do host e conta vulnflux no volume lab_server_keys."]),
    # Alvos
    c("alvo-vulneravel", 320, 830, sub="Metasploitable 2", zone="z-alvos", warn=True,
      notes=["Vulnerável de propósito (vsftpd e UnrealIRCd com backdoor, distcc, Samba…).", "Só na rede alvos (internal): sem saída e sem portas publicadas.", "Do SOC, só o ospd-openvas e a sonda lhe chegam (verificado no workflow Greenbone).", "Imagem fixada por digest."]),
    # VulnFlux
    c("vulnflux", 610, 200, sub="motor de risco · :8080", zone="z-vulnflux",
      notes=["Orquestra Greenbone, WPScan e servidores; escreve prioridades P1–P4 no DefectDojo.", "Processo único; estado em ficheiros JSON no volume lab_data (sem base de dados nem backup).", "Lê o token do DefectDojo e as palavras-passe em lab_secrets (só leitura)."]),
    c("dd-token", 610, 320, sub="obtém o token do DefectDojo", zone="z-vulnflux", run_once=True,
      notes=[ONCE, "Pede o token do admin à API do DefectDojo e grava-o em lab_secrets."]),
    # DefectDojo
    c("dd-nginx", 870, 190, sub="proxy · :8081", zone="z-dd", notes=["Serve a interface e a API v2; ficheiros de media em dd_media.", LATEST]),
    c("dd-uwsgi", 870, 280, sub="aplicação Django", zone="z-dd", warn=True, notes=[LATEST]),
    c("dd-valkey", 1060, 280, sub="fila do Celery", zone="z-dd", notes=["Versão fixada por digest."]),
    c("dd-celeryworker", 870, 370, sub="tarefas em segundo plano", zone="z-dd", warn=True, notes=["Deduplicação, SLA, importações pesadas.", LATEST]),
    c("dd-celerybeat", 1060, 370, sub="agendador", zone="z-dd", warn=True, notes=[LATEST]),
    c("dd-initializer", 870, 460, sub="migrações e admin", zone="z-dd", run_once=True, warn=True, notes=[ONCE, LATEST]),
    c("dd-postgres", 1060, 460, sub="PostgreSQL 18.6", zone="z-dd", notes=["Versão fixada por digest. Volume dd_postgres. Sem backup automático."]),
    # Greenbone
    c("gvmd", 565, 610, sub="gestor · GMP", zone="z-gb", warn=True, notes=["Tasks, alvos, port lists, scan configs e reports.", "Sem interface web no laboratório: só o VulnFlux fala com ele.", LATEST]),
    c("pg-gvm", 745, 610, sub="PostgreSQL do gvmd", zone="z-gb", warn=True, notes=[LATEST]),
    c("pg-gvm-migrator", 925, 610, sub="migra a versão da BD", zone="z-gb", run_once=True, warn=True, notes=[ONCE, LATEST]),
    c("ospd-openvas", 565, 700, sub="scanner · OSP", zone="z-gb", warn=True,
      notes=["Aqui corre o openvas, que gera o tráfego do scan.", "Redes gb (interna), alvos e saida (sem comunicação entre contentores).", "NET_ADMIN e NET_RAW; seccomp e apparmor desativados.", "Limites: --max-scans e memória mínima livre.", LATEST]),
    c("redis-server", 745, 700, sub="estado dos scans", zone="z-gb", warn=True, notes=["Só por socket Unix (redis_socket_vol).", LATEST]),
    c("openvasd", 925, 700, sub="Notus · :80", zone="z-gb", warn=True, notes=["Modo service_notus: verificações locais por versão de pacote.", LATEST]),
    c("configure-openvas", 1065, 700, sub="escreve openvas.conf", zone="z-gb", run_once=True, warn=True,
      notes=[ONCE, "Aponta o openvas para http://openvasd:80 (table_driven_lsc)."]),
]
feeds = [("vulnerability-tests", "NVTs"), ("notus-data", "avisos Notus"), ("gpg-data", "chaves de assinatura"), ("scap-data", "CVE, CPE"),
         ("cert-bund-data", "avisos CERT-Bund"), ("dfn-cert-data", "avisos DFN-CERT"), ("data-objects", "configs e políticas"), ("report-formats", "formatos de report")]
for i, (f, sub) in enumerate(feeds):
    N_LAB.append(c(f, 565 + 160 * (i % 4), 790 + 65 * (i // 4), sub=f"feed · {sub}", zone="z-gb", run_once=True, h=42, notes=[FEED]))

N_LAB += [
    x_("ext-cmdb", 20, 190, "CMDB do cliente", "UCMDB · REST, SQL ou ficheiro"),
    x_("ext-tickets", 20, 250, "Sistema de tickets", "SMAX · Jira · ServiceNow · GLPI"),
    x_("ext-ct", 20, 310, "Certificate Transparency", "crt.sh e logs CT"),
    x_("ext-tls", 20, 370, "Sites e servidores TLS", "certificado servido, porta 443…"),
    x_("ext-smtp", 20, 430, "Servidor SMTP", "avisos por email"),
    x_("ext-avi", 20, 490, "Avi Controller", "certificados dos VIPs (API)"),
    x_("ext-wpscan", 1275, 150, "WPScan API", "vulnerabilidades WordPress"),
    x_("ext-wp", 1275, 205, "Sites WordPress", "alvos do WPScan"),
    x_("ext-kev", 1275, 260, "CISA KEV", "exploradas no terreno"),
    x_("ext-epss", 1275, 315, "EPSS", "probabilidade de exploração"),
    x_("ext-edb", 1275, 370, "Exploit-DB", "exploits públicos (GitLab)"),
    x_("ext-msf", 1275, 425, "Metasploit", "metadados dos módulos (GitHub)"),
    x_("ext-nuclei", 1275, 480, "Nuclei templates", "cves.json (GitHub)"),
    x_("ext-github", 1275, 560, "GitHub releases", "versões de cada serviço"),
    x_("ext-webhook", 1275, 615, "Webhook de alertas", "opcional, só falhas"),
    x_("ext-gbreg", 1275, 800, "Registo Greenbone", "imagens e feeds (pull)"),
    x_("ext-siem", 1275, 690, "SIEM", "syslog, ficheiro, /api/exposure",
       notes=["Recebe os eventos (P1/KEV, servidores, falhas) e importa a lista de exposição como watchlist.",
              "Cruza a exposição com alertas de WAF, IDS e EDR."]),
]

E_LAB = [
    # browser
    ("browser", "vulnflux", "web", "http://127.0.0.1:8080", "Hosts, scans, servidores, risco"),
    ("browser", "dd-nginx", "web", "http://127.0.0.1:8081", "findings, produtos, SLA"),
    ("browser", "atalaia-web", "web", "http://127.0.0.1:8088", "certificados e renovações"),
    ("browser", "portal", "web", "http://127.0.0.1:8090", "inventário, estado, catálogo"),
    # portal
    ("portal", "vulnflux", "api", "HTTP /api/status", "estado, componentes (Greenbone, servidores), frescura das listas"),
    ("portal", "dd-nginx", "api", "HTTP", "sonda de disponibilidade e versão"),
    ("portal", "atalaia-web", "api", "HTTP /api/status (token)", "estado do Atalaia e dos certificados"),
    ("dd-token", "portal", "vol", "lab_secrets (só leitura no portal)", "tokens para as APIs"),
    ("portal", "ext-github", "ext", "HTTPS api.github.com", "compara a versão instalada com a última release"),
    ("portal", "ext-webhook", "ext", "HTTPS POST", "avisa quando um serviço falha"),
    # vulnflux
    ("vulnflux", "dd-nginx", "api", "API REST v2 (token)", "importa findings, escreve P1–P4 e prazos"),
    ("vulnflux", "gvmd", "sock", "GMP · gvmd_socket_vol", "cria alvos, port lists, scan configs e tasks; lê reports e o estado dos feeds"),
    ("vulnflux", "lab-server", "ssh", "SSH :22 · chave dedicada, host key fixada", "saúde, hardening, atualizações por anéis"),
    ("vulnflux", "ext-wpscan", "ext", "HTTPS (chave API)", "vulnerabilidades de plugins e temas"),
    ("vulnflux", "ext-wp", "ext", "HTTPS", "scan WPScan dos sites registados"),
    ("vulnflux", "ext-kev", "ext", "HTTPS diário", "lista KEV para a prioridade"),
    ("vulnflux", "ext-epss", "ext", "HTTPS diário", "pontuações EPSS"),
    ("vulnflux", "ext-edb", "ext", "HTTPS diário", "CVE com exploit público"),
    ("vulnflux", "ext-msf", "ext", "HTTPS diário", "CVE com módulo Metasploit"),
    ("vulnflux", "ext-nuclei", "ext", "HTTPS diário", "CVE com template Nuclei"),
    ("vulnflux", "sonda", "api", "HTTP :8000 (token) · rede sonda", "pede a descoberta de portas antes do Greenbone"),
    ("sonda", "alvo-vulneravel", "scan", "nmap -sS -p- · rede alvos", "portas TCP abertas"),
    ("vulnflux", "ext-siem", "ext", "syslog RFC 5424 · JSON/ECS", "eventos P1/KEV, servidores, falhas"),
    ("ext-siem", "vulnflux", "ext", "HTTPS /api/exposure (token)", "watchlist de exposição"),
    ("vulnflux", "ext-webhook", "ext", "HTTPS POST", "alertas P1/KEV para pessoas (Teams)"),
    ("backup", "dd-postgres", "db", "pg_dump · rede dd", "backup diário do DefectDojo"),
    ("backup", "atalaia-db", "db", "pg_dump · rede atalaia", "backup diário do Atalaia"),
    ("vulnflux", "backup", "vol", "lab_data (só leitura)", "estado do VulnFlux no backup"),
    ("portal", "backup", "vol", "portal_data (só leitura)", "estado do portal no backup"),
    ("dd-token", "dd-nginx", "api", "API v2 /api-token-auth", "obtém o token do admin"),
    ("dd-token", "vulnflux", "vol", "lab_secrets", "entrega o token do DefectDojo"),
    # defectdojo
    ("dd-nginx", "dd-uwsgi", "api", "uwsgi", "pedidos da interface e da API"),
    ("dd-nginx", "dd-uwsgi", "vol", "dd_media", "anexos e relatórios"),
    ("dd-uwsgi", "dd-postgres", "db", "PostgreSQL :5432", "findings, produtos, utilizadores"),
    ("dd-uwsgi", "dd-valkey", "db", "Redis :6379", "envia tarefas ao Celery"),
    ("dd-celeryworker", "dd-valkey", "db", "Redis :6379", "consome tarefas"),
    ("dd-celeryworker", "dd-postgres", "db", "PostgreSQL :5432", "deduplicação, SLA, importações"),
    ("dd-celerybeat", "dd-valkey", "db", "Redis :6379", "tarefas periódicas"),
    ("dd-initializer", "dd-postgres", "db", "PostgreSQL :5432", "migrações e criação do admin"),
    # greenbone
    ("gvmd", "pg-gvm", "sock", "psql_socket_vol", "base de dados do gvmd"),
    ("pg-gvm-migrator", "pg-gvm", "vol", "psql_data_vol", "migra os dados entre versões do PostgreSQL"),
    ("gvmd", "ospd-openvas", "sock", "OSP · ospd_openvas_socket_vol", "manda arrancar scans e recolhe resultados"),
    ("ospd-openvas", "redis-server", "sock", "redis_socket_vol", "base de conhecimento do scan"),
    ("ospd-openvas", "openvasd", "api", "HTTP :80", "verificações Notus (versões de pacotes)"),
    ("configure-openvas", "ospd-openvas", "vol", "openvas_data_vol", "openvas.conf e configuração de logs"),
    ("configure-openvas", "openvasd", "vol", "openvas_data_vol", "openvas.conf"),
    ("ospd-openvas", "alvo-vulneravel", "scan", "rede alvos · TCP/UDP", "descoberta de portas e testes NVT"),
    ("vulnerability-tests", "ospd-openvas", "vol", "vt_data_vol", "NVTs"),
    ("vulnerability-tests", "gvmd", "vol", "vt_data_vol", "metadados dos NVTs"),
    ("notus-data", "ospd-openvas", "vol", "notus_data_vol", "avisos Notus"),
    ("notus-data", "openvasd", "vol", "notus_data_vol", "avisos Notus"),
    ("gpg-data", "ospd-openvas", "vol", "gpg_data_vol", "verifica a assinatura dos feeds"),
    ("gpg-data", "openvasd", "vol", "gpg_data_vol", "verifica a assinatura dos feeds"),
    ("scap-data", "gvmd", "vol", "scap_data_vol", "CVE e CPE"),
    ("cert-bund-data", "gvmd", "vol", "cert_data_vol", "avisos CERT-Bund"),
    ("dfn-cert-data", "gvmd", "vol", "cert_data_vol", "avisos DFN-CERT"),
    ("data-objects", "gvmd", "vol", "data_objects_vol", "scan configs, port lists, políticas"),
    ("report-formats", "gvmd", "vol", "data_objects_vol", "formatos de report"),
    ("ext-gbreg", "vulnerability-tests", "ext", "docker pull", "feeds novos chegam como imagens novas"),
    # atalaia
    ("atalaia-web", "atalaia-db", "db", "PostgreSQL :5432", "certificados, utilizadores, auditoria"),
    ("atalaia-worker", "atalaia-db", "db", "PostgreSQL :5432", "resultados das recolhas e fila de trabalho"),
    ("atalaia-worker", "ext-cmdb", "ext", "REST · SQL · ficheiro", "certificados registados na CMDB"),
    ("atalaia-worker", "ext-tickets", "ext", "API REST", "abre pedidos de renovação"),
    ("atalaia-worker", "ext-ct", "ext", "HTTPS", "certificados emitidos para os domínios"),
    ("atalaia-worker", "ext-tls", "ext", "TLS :443…", "certificado realmente servido"),
    ("atalaia-worker", "ext-smtp", "ext", "SMTP", "avisos de expiração"),
    ("atalaia-worker", "ext-avi", "ext", "API REST", "certificados dos virtual services"),
]
# Ordem de arranque, tirada do compose
for n in N_LAB:
    if n["type"] == "container":
        for d in SV[n["id"]].get("depends_on", {}):
            E_LAB.append((n["id"], d, "dep", "depends_on: " + SV[n["id"]]["depends_on"][d].get("condition", "service_started"), "só arranca depois deste"))

# --- Produção (o que os ficheiros docker-compose.yml, docker-compose.greenbone.yml e portal/compose.yaml descrevem)
ZONES_PROD = [
    dict(id="p-host", x=250, y=110, w=760, h=470, label="Servidor do SOC (Linux) · produção", cls="host"),
    dict(id="p-z-docker", x=270, y=150, w=250, h=410, label="Docker · VulnFlux e portal", cls="zone"),
    dict(id="p-z-gb", x=545, y=150, w=445, h=410, label="Mesmo host · controlo do Greenbone", cls="zone"),
    dict(id="p-z-ext", x=1040, y=110, w=440, h=620, label="Fora do servidor do SOC", cls="ext"),
]
def p(id, x, y, label, sub, notes=(), warn=False, type="container", image="", ports=(), vols=(), secrets=(), w=W, h=H):
    return dict(id=id, label=label, sub=sub, x=x, y=y, w=w, h=h, zone="", type=type, image=image, profile="", ports=list(ports),
                vols=list(vols), secrets=list(secrets), nets=[], notes=list(notes), warn=warn, run_once=False)
N_PROD = [
    x_("p-browser", 640, 30, "Analistas", "browser · rede interna", type="user"),
    p("p-vulnflux", 320, 220, "vulnflux", "motor de risco · :8080", image="ghcr.io/ricardodomingues10/vulnflux:latest",
      ports=["127.0.0.1:8080→8080"], vols=["vulnflux_data → /data", "gb_gvmd_socket → /run/gvmd (externo)"], secrets=["vf_gbctl_key", "vf_gbctl_known_hosts"], warn=True,
      notes=["Imagem :latest do GHCR por omissão (VF_IMAGE_TAG para fixar).", "Porta só em 127.0.0.1: o repositório não define proxy reverso nem TLS à frente."]),
    p("p-portal", 320, 440, "soc-portal", "Adamastor SOC · :8090", image="ghcr.io/ricardodomingues10/soc-portal:latest",
      ports=["127.0.0.1:8090→8080"], warn=True, notes=["Configuração em portal/portal.yaml.", "Mesma nota: só 127.0.0.1, sem proxy reverso definido."]),
    p("p-sshd", 570, 330, "sshd do host", "utilizador gbctl", type="container",
      notes=["Chave dedicada com forced command: só pode correr o gb-ctl.sh.", "O VulnFlux chega-lhe por host.docker.internal."]),
    p("p-gbctl", 570, 450, "gb-ctl.sh", "start · stop · update · status", notes=["Liga, desliga e atualiza a stack; responde numa linha JSON.", "Não sabe nada de GMP nem de scans."]),
    p("p-gvmd", 800, 220, "Stack Greenbone", "gvmd, ospd-openvas, feeds…", w=170, warn=True,
      notes=["Os mesmos ~22 contentores do laboratório, noutro projeto Compose.", "Só arranca quando há scans (o orquestrador desliga-a no fim).", LATEST]),
    p("p-redes", 1275, 400, "Redes a analisar", "servidores, postos, rede do cliente", type="external", w=195,
      notes=["O scanner corre no próprio servidor do SOC: vê o que a rede deste servidor vê."]),
    x_("p-dd", 1060, 150, "DefectDojo", "instância própria · API v2", notes=["O compose de produção não o inclui: aponta para uma instância existente."]),
    x_("p-atalaia", 1060, 210, "Atalaia Cert", "repositório certs-watch, servidor próprio"),
    x_("p-servers", 1060, 270, "Servidores Linux", "SSH sem agente"),
    x_("p-wp", 1060, 330, "Sites WordPress", "WPScan"),
    x_("p-feeds", 1060, 390, "Feeds de risco", "KEV · EPSS · Exploit-DB · Metasploit · Nuclei"),
    x_("p-wpscan", 1060, 450, "WPScan API", "chave API"),
    x_("p-github", 1060, 530, "GitHub", "releases e imagens no GHCR"),
    x_("p-webhook", 1060, 590, "Webhook de alertas", "opcional"),
    x_("p-gbreg", 1060, 650, "Registo Greenbone", "imagens e feeds"),
    x_("p-cmdb", 1275, 210, "CMDB e tickets", "via Atalaia", w=195),
]
E_PROD = [
    ("p-browser", "p-vulnflux", "web", "127.0.0.1:8080 (precisa de túnel ou proxy)", "interface do VulnFlux"),
    ("p-browser", "p-portal", "web", "127.0.0.1:8090 (precisa de túnel ou proxy)", "portal do SOC"),
    ("p-browser", "p-dd", "web", "HTTPS", "interface do DefectDojo"),
    ("p-vulnflux", "p-sshd", "ssh", "SSH · host.docker.internal · vf_gbctl_key", "pede start, stop, update, status"),
    ("p-sshd", "p-gbctl", "ssh", "forced command", "só estes quatro verbos"),
    ("p-gbctl", "p-gvmd", "api", "docker compose", "liga, desliga, puxa imagens novas"),
    ("p-vulnflux", "p-gvmd", "sock", "GMP · gb_gvmd_socket (volume externo)", "tasks, scans, reports, feeds"),
    ("p-gvmd", "p-redes", "scan", "rede do host", "varrimento de rede"),
    ("p-gvmd", "p-gbreg", "ext", "docker pull", "imagens e feeds novos"),
    ("p-vulnflux", "p-dd", "ext", "HTTPS · API v2 (token)", "importa findings, escreve P1–P4 e prazos"),
    ("p-vulnflux", "p-servers", "ssh", "SSH :22 · chave dedicada", "saúde, hardening, atualizações"),
    ("p-vulnflux", "p-wp", "ext", "HTTPS", "scans WPScan"),
    ("p-vulnflux", "p-wpscan", "ext", "HTTPS", "base de vulnerabilidades WordPress"),
    ("p-vulnflux", "p-feeds", "ext", "HTTPS diário", "sinais de prioridade"),
    ("p-portal", "p-vulnflux", "api", "HTTP /api/status", "estado e frescura"),
    ("p-portal", "p-dd", "ext", "HTTPS", "sonda e versão"),
    ("p-portal", "p-atalaia", "ext", "HTTPS /api/status", "estado dos certificados"),
    ("p-portal", "p-github", "ext", "HTTPS", "últimas releases"),
    ("p-portal", "p-webhook", "ext", "HTTPS POST", "alertas de falha"),
    ("p-atalaia", "p-cmdb", "ext", "REST · SQL · API", "inventário e renovações"),
    ("p-github", "p-vulnflux", "ext", "docker pull ghcr.io", "imagem do VulnFlux"),
]

def pack(nodes, edges, zones):
    return dict(nodes=nodes, zones=zones, edges=[dict(id=f"e{i}", f=a, t=b, k=k, via=v, what=w) for i, (a, b, k, v, w) in enumerate(edges)])

DATA = dict(kinds=KINDS, views=dict(lab=pack(N_LAB, E_LAB, ZONES_LAB), producao=pack(N_PROD, E_PROD, ZONES_PROD)),
            counts=dict(volumes=len(CFG.get("volumes", {})), secrets=len(CFG.get("secrets", {})), networks=len(CFG.get("networks", {}))))

ids = {n["id"] for v in DATA["views"].values() for n in v["nodes"]}
for v in DATA["views"].values():
    for e in v["edges"]:
        assert e["f"] in ids and e["t"] in ids, e
assert {n["id"] for n in N_LAB if n["type"] == "container"} == set(SV), set(SV) ^ {n["id"] for n in N_LAB}

tpl = (HERE / "template.html").read_text()
(HERE / "adamastor-infra.html").write_text(tpl.replace("/*DATA*/null", json.dumps(DATA, ensure_ascii=False)))

# --- draw.io (abre em diagrams.net; o Visio importa .drawio/.vsdx via diagrams.net)
COL = {"web": "#3d4a5c", "api": "#2f6fd6", "sock": "#8a4fd0", "db": "#b87406", "vol": "#6b7a8c", "ssh": "#0f8f7a", "scan": "#d0453a", "ext": "#a3477a", "dep": "#9aa3ad"}
def drawio_page(name, view, pid):
    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    for z in view["zones"]:
        st = {"host": "rounded=1;arcSize=2;fillColor=#f4f6f9;strokeColor=#5b6b7f;", "zone": "rounded=1;arcSize=4;fillColor=#ffffff;strokeColor=#aab4c0;",
              "alvos": "rounded=1;arcSize=4;fillColor=#fdf1ef;strokeColor=#d0453a;dashed=1;", "ext": "rounded=1;arcSize=4;fillColor=none;strokeColor=#aab4c0;dashed=1;"}[z["cls"]]
        cells.append(f'<mxCell id="{pid}{z["id"]}" value="{escape(z["label"])}" style="{st}verticalAlign=top;align=left;spacingLeft=8;fontSize=11;fontStyle=1;" vertex="1" parent="1"><mxGeometry x="{z["x"]}" y="{z["y"]}" width="{z["w"]}" height="{z["h"]}" as="geometry"/></mxCell>')
    for n in view["nodes"]:
        fill = {"container": "#ffffff", "external": "#f7f3f6", "user": "#eef3fb"}[n["type"]]
        stroke = "#d0453a" if n["warn"] else "#5b6b7f"
        dash = "dashed=1;" if n["run_once"] else ""
        val = escape(f'<b>{n["label"]}</b><br><font style="font-size:10px">{n["sub"]}</font>', {'"': "&quot;"})
        tip = escape("\n".join([n["image"]] + n["ports"] + n["vols"] + n["notes"]), {'"': "&quot;"})
        cells.append(f'<mxCell id="{pid}{n["id"]}" value="{val}" tooltip="{tip}" style="rounded=1;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};{dash}fontSize=12;" vertex="1" parent="1"><mxGeometry x="{n["x"]}" y="{n["y"]}" width="{n["w"]}" height="{n["h"]}" as="geometry"/></mxCell>')
    for e in view["edges"]:
        if e["k"] == "dep":
            continue
        dash = "dashed=1;" if e["k"] in ("vol", "ext") else ""
        cells.append(f'<mxCell id="{pid}{e["id"]}" value="{escape(e["via"], {chr(34): "&quot;"})}" tooltip="{escape(e["what"], {chr(34): "&quot;"})}" style="edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;strokeColor={COL[e["k"]]};fontColor={COL[e["k"]]};fontSize=9;{dash}endArrow=block;endSize=5;labelBackgroundColor=#ffffff;" edge="1" parent="1" source="{pid}{e["f"]}" target="{pid}{e["t"]}"><mxGeometry relative="1" as="geometry"/></mxCell>')
    return f'<diagram id="{pid}" name="{escape(name)}"><mxGraphModel dx="1500" dy="960" grid="1" gridSize="10" page="1" pageWidth="1500" pageHeight="960"><root>{"".join(cells)}</root></mxGraphModel></diagram>'
(HERE / "adamastor-infra.drawio").write_text('<mxfile host="Adamastor SOC">' + drawio_page("Laboratório", DATA["views"]["lab"], "L") + drawio_page("Produção", DATA["views"]["producao"], "P") + "</mxfile>")
print("nós", sum(len(v["nodes"]) for v in DATA["views"].values()), "ligações", sum(len(v["edges"]) for v in DATA["views"].values()))
