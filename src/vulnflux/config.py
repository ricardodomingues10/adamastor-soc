"""Configuração do VulnFlux.

Tudo vem de variáveis de ambiente com prefixo VF_ (ver .env.example). Segredos podem
vir de Docker secrets: um ficheiro /run/secrets/vf_dd_token preenche VF_DD_TOKEN.
"""

from __future__ import annotations

import os
import re
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_SECRETS_DIR = "/run/secrets"

DEFAULT_ENVIRONMENTS = [
    "Sites_PRD",
    "Sites_TST",
    "Apps_TST",
    "Development",
]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VF_",
        env_file=".env",
        env_file_encoding="utf-8",
        secrets_dir=_SECRETS_DIR if os.path.isdir(_SECRETS_DIR) else None,
        extra="ignore",
    )

    # --- Geral -------------------------------------------------------------------
    data_dir: Path = Path("/data")
    timezone: str = "Europe/Lisbon"
    base_url: str = ""  # usado em links de alertas; vazio = relativo
    retention_days: int = 180
    # Separados por vírgulas; são sugestões no formulário e o product type no DefectDojo
    environments: str = ",".join(DEFAULT_ENVIRONMENTS)

    # --- Interface web -----------------------------------------------------------
    admin_user: str = "admin"
    admin_password: SecretStr = SecretStr("")
    secret_key: SecretStr = SecretStr("")  # vazio = gerado e guardado em data_dir
    cookie_secure: bool = True  # False só para testes locais sem HTTPS
    session_hours: int = 12
    # Token para /api/status (lido pelo Portal SOC). Vazio = endpoint desligado (404).
    status_token: SecretStr = SecretStr("")
    # Token para /api/exposure e /api/events (lidos pelo SIEM). Diferente do de estado: quem só vigia
    # se o serviço está de pé não fica a saber que vulnerabilidades exploráveis há em cada host.
    exposure_token: SecretStr = SecretStr("")

    # --- DefectDojo --------------------------------------------------------------
    dd_url: str = ""
    dd_token: SecretStr = SecretStr("")
    dd_engagement: str = "VulnFlux"
    dd_default_product_type: str = "Sites_PRD"
    dd_verify_tls: bool = True
    dd_ca_bundle: str = ""  # caminho para a CA interna, se aplicável
    dd_timeout: int = 120
    dd_import_retries: int = 3

    # --- WPScan --------------------------------------------------------------------
    wpscan_api_token: SecretStr = SecretStr("")
    # Várias chaves para rotação, separadas por vírgulas, espaços ou linhas.
    # Junta-se a VF_WPSCAN_API_TOKEN (que continua a funcionar sozinha).
    wpscan_api_tokens: SecretStr = SecretStr("")
    wpscan_cron: str = "37 2 * * *"
    wpscan_batch_size: int = 4
    wpscan_min_quota: int = 5
    wpscan_timeout: int = 1800
    wpscan_disable_tls_checks: bool = False
    wpscan_include_interesting: bool = False
    # O WPScan 4.x sem -e não enumera plugins, utilizadores nem backups: só versão e tema.
    # vp/vt = plugins/temas vulneráveis, tt = timthumbs, cb = backups de configuração,
    # dbe = exports da BD, bf = pastas de backup, u1-10 = utilizadores com ID 1 a 10
    wpscan_enumerate: str = "vp,vt,tt,cb,dbe,bf,u1-10"
    # passive (só o HTML), mixed (HTML + localizações conhecidas) ou aggressive
    wpscan_plugins_detection: str = "mixed"
    # Utilizadores enumerados viram um finding Low por site (com a lista de usernames)
    wpscan_include_users: bool = True
    wpscan_extra_args: str = ""
    # Modo de análise:
    #   partilhado — enumera cada site sem chave (não gasta quota) e pede à API as vulnerabilidades de cada
    #                plugin, tema e versão do WordPress uma só vez, em cache para todos os sites. Cabe nas
    #                chaves gratuitas (25 pedidos/dia) mesmo com dezenas de sites.
    #   por_site   — o scan clássico com --api-token, um pedido por componente em cada site. Para chaves pagas.
    wpscan_mode: str = "partilhado"
    wpscan_api_url: str = "https://wpscan.com/api/v3"
    # Validade da cache de vulnerabilidades por componente (horas). Depois disso volta a perguntar à API.
    wpscan_cache_hours: int = 24
    # Enumeração no modo partilhado: "p"/"t" (populares) em vez de "vp"/"vt", que sem chave não listam nada.
    wpscan_shared_enumerate: str = "p,t,tt,cb,dbe,bf,u1-10"
    # Sites por lote no modo partilhado; 0 = todos (a enumeração não gasta quota).
    wpscan_shared_batch_size: int = 0

    # Endereço do Portal SOC, para a ligação "Abrir o Portal SOC" na barra lateral (vazio = sem ligação)
    portal_url: str = ""

    # --- Vigilante de atualizações e vulnerabilidades (vulnflux.watch) -----------------
    watch_enabled: bool = True
    watch_interval_minutes: int = 15
    watch_wporg: bool = True  # versões do núcleo, plugins e temas no wordpress.org
    # Componentes a refrescar no WPScan por verificação, só com quota acima da reserva (para o lote).
    watch_wpscan_refresh: int = 3
    watch_wpscan_reserve: int = 10
    # Wordfence Intelligence (chave gratuita em wordfence.com): feed de vulnerabilidades.
    watch_wordfence_token: SecretStr = SecretStr("")
    watch_wordfence_url: str = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
    watch_wordfence_minutes: int = 360
    # Ferramentas do SOC cujas releases são vigiadas (owner/repo do GitHub).
    watch_github_repos: str = (
        "n8n-io/n8n,greenbone/gvmd,greenbone/openvas-scanner,DefectDojo/django-DefectDojo,MISP/MISP,"
        "DependencyTrack/dependency-track,grafana/grafana,aquasecurity/trivy,wpscanteam/wpscan"
    )
    watch_github_token: SecretStr = SecretStr("")
    # Feeds RSS/Atom de avisos: "Nome=https://...; Outro=https://..."
    watch_rss_feeds: str = ""
    # Alertas por email: destino por omissão e rotas por equipa (etiqueta "equipa:<nome>" no host).
    watch_email_to: str = ""
    watch_routes: str = ""  # "web=web@exemplo.pt; infra=infra@exemplo.pt,noc@exemplo.pt"
    watch_email_min_severity: str = "info"  # info inclui as novas versões
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_starttls: bool = True
    smtp_ssl: bool = False
    smtp_user: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_from: str = ""
    # Tickets: "" (desligado), "email" (para o endereço do service desk) ou "webhook" (POST JSON, ex.: n8n)
    ticket_mode: str = ""
    ticket_email: str = ""
    ticket_webhook_url: str = ""
    ticket_webhook_token: SecretStr = SecretStr("")
    ticket_min_severity: str = "high"

    # --- Greenbone -----------------------------------------------------------------
    greenbone_enabled: bool = False
    greenbone_cron: str = "13 1 26 * *"
    greenbone_socket: str = "/run/gvmd/gvmd.sock"
    greenbone_user: str = "orchestrator"
    greenbone_password: SecretStr = SecretStr("")
    greenbone_concurrency: int = 3
    # Prazo de um scan, contado só enquanto o gvmd o está a correr (o tempo em fila não conta).
    greenbone_scan_timeout_hours: float = 8
    # Sem progresso durante este tempo, o scan é dado como parado (ex.: preso em 98% num teste web).
    greenbone_stall_hours: float = 3
    # Scan parado por prazo ou sem progresso: importa o que já encontrou, sem fechar findings antigos.
    greenbone_import_partial: bool = True
    # O OpenVAS repete todos os testes em cada vhost que descobre (nomes no certificado, DNS reverso):
    # num servidor com 20 vhosts o scan demora 20 vezes mais. Desligado nas configs geridas pelo VulnFlux.
    greenbone_expand_vhosts: bool = False
    # Tempo máximo de cada teste (o OpenVAS usa 320 s). Um WAF que bloqueia o scanner faz cada teste
    # esperar até ao limite: com milhares de testes, é o que leva um scan a passar das 8 horas.
    greenbone_plugins_timeout: int = 120
    # Teste de host vivo do target: vazio = o da scan config (ICMP). "Consider Alive" para hosts que
    # não respondem a ping (atrás de firewall); ver os valores em docs/greenbone.md.
    greenbone_alive_test: str = ""
    greenbone_poll_seconds: int = 30
    greenbone_min_qod: int = 70
    greenbone_levels: str = "hml"  # h=high m=medium l=low g=log (Info no DD)
    greenbone_scan_config_id: str = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast
    greenbone_port_list_id: str = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"  # All IANA assigned TCP
    greenbone_scanner_id: str = "08b69003-5fc2-4037-a479-93b440211c73"  # OpenVAS Default
    # Perfis de scan: "rapido" (portas comuns, sem crawling CGI, mais testes em paralelo) e "completo"
    # (Full and fast + todas as portas IANA) ou "descoberta" (nmap → só as portas abertas).
    # Cada host pode escolher; vazio = este.
    greenbone_profile: str = "rapido"
    greenbone_max_checks: int = 10  # testes em paralelo por host (o gvmd usa 4 por omissão)
    greenbone_fast_ports: str = (
        "T:20-23,25,53,69,80-81,88,110-111,113,119,123,135,137-139,143,161,179,199,389,427,443-445,465,"
        "500,512-515,548,554,587,623,631,636,873,902,990,993,995,1025-1030,1080,1099,1194,1352,1433-1434,"
        "1521,1524,1723,1883,2000,2049,2121,2181,2375-2376,2483-2484,3000,3128,3268-3269,3306,3389,3632,"
        "4369,4443,4444,4848,5000,5060-5061,5432,5555,5601,5672,5900-5910,5984-5986,6000-6001,6379,"
        "6443,6660-6669,6697,7001-7002,7070,7443,7474,7547,8000-8010,8020,8080-8090,8180-8181,8443,8787,"
        "8834,8880,8888,9000-9001,9042,9090-9100,9200,9300,9418,9443,10000,10250,11211,15672,27017-27018,"
        "50000,50070"
    )
    # Perfil "descoberta": a sonda (nmap no mesmo ponto da rede que o scanner) encontra as portas TCP
    # abertas e o Greenbone testa só essas. Sem sonda (URL vazio) ou se falhar, usa o perfil rápido.
    greenbone_discovery_url: str = ""  # ex.: http://sonda:8000
    greenbone_discovery_token: SecretStr = SecretStr("")
    greenbone_discovery_timeout: int = 1800
    greenbone_discovery_udp: str = "53,69,123,137,161,500,623,1900,5353"
    greenbone_min_nvts: int = 10_000
    greenbone_max_feed_age_days: float = 7
    greenbone_block_on_stale_feed: bool = False
    greenbone_ready_timeout_hours: float = 3
    # Ciclo de vida on-demand (vazio = Greenbone sempre ligado, sem start/stop)
    greenbone_ssh_host: str = ""
    greenbone_ssh_user: str = "gbctl"
    greenbone_ssh_port: int = 22
    greenbone_ssh_key: str = "/run/secrets/vf_gbctl_key"
    greenbone_ssh_known_hosts: str = "/run/secrets/vf_gbctl_known_hosts"
    greenbone_update_before_scan: bool = True
    greenbone_stop_after: bool = True

    # --- Prioridade por risco (KEV, EPSS, exploits + contexto do inventário) ------------
    risk_enabled: bool = True
    risk_cron: str = "17 6 * * *"
    # URL vazio desliga a fonte; file:///caminho lê um espelho local (servidores sem Internet)
    risk_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    risk_epss_url: str = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
    risk_exploitdb_url: str = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    risk_metasploit_url: str = (
        "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
    )
    risk_nuclei_url: str = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
    risk_download_timeout: int = 300
    # Dias para corrigir por prioridade: P1, P2, P3, P4
    risk_sla_days: str = "7,30,90,180"
    # Recalcular as prioridades de um host logo a seguir a cada import (com os feeds em cache)
    risk_after_import: bool = True
    # Escrever criticidade e exposição no Product do DefectDojo
    risk_sync_products: bool = True
    # URL do DefectDojo para links no browser (se diferente do VF_DD_URL interno)
    dd_public_url: str = ""

    # --- Servidores (saúde, hardening e atualizações por SSH) --------------------------
    servers_enabled: bool = True
    servers_cron: str = "23 */6 * * *"  # verificação de todos os servidores
    servers_concurrency: int = 4
    servers_ssh_timeout: int = 20  # ligação
    servers_command_timeout: int = 600  # recolha (o Lynis demora)
    servers_import_dd: bool = True  # hardening falhado e atualizações de segurança viram findings
    # Limiares de saúde (percentagem de uso): aviso, crítico
    servers_mem_pct: str = "85,95"
    servers_disk_pct: str = "80,90"
    servers_swap_pct: str = "50,80"
    servers_load_per_cpu: str = "1.5,3"
    # Ciclos de atualização por anéis: 0 canário → 1 piloto → 2 geral → 3 críticos (com aprovação)
    patch_cron: str = "41 3 * * 2"  # início de um ciclo (vazio = só manual)
    patch_soak_hours: float = 24  # tempo de observação entre anéis
    patch_ring3_approval: bool = True
    patch_timeout: int = 3600
    patch_min_free_mb: int = 500  # pré-verificação: espaço livre mínimo em / e /var

    # --- Eventos (alertas para pessoas e para o SIEM; ver vulnflux/events.py) ----------------
    events_enabled: bool = True
    events_syslog: str = ""  # udp://siem:514 ou tcp://siem:514 (RFC 5424, mensagem JSON/ECS)
    events_webhook_url: SecretStr = SecretStr("")  # Teams, Slack, Mattermost… (campo "text")
    events_max_per_run: int = 20  # acima disto vai um evento de resumo

    # --- Gates -----------------------------------------------------------------------
    gate_drop_threshold: float = 0.5  # queda > 50% face à última execução boa
    gate_drop_min_previous: int = 5  # só avalia quedas se antes havia >= N findings

    @field_validator("greenbone_alive_test")
    @classmethod
    def _alive_test(cls, v: str) -> str:
        allowed = (
            "Scan Config Default",
            "ICMP Ping",
            "TCP-ACK Service Ping",
            "TCP-SYN Service Ping",
            "ARP Ping",
            "ICMP & TCP-ACK Service Ping",
            "ICMP & ARP Ping",
            "TCP-ACK Service & ARP Ping",
            "ICMP, TCP-ACK Service & ARP Ping",
            "Consider Alive",
        )
        v = (v or "").strip()
        if v and v not in allowed:
            raise ValueError(f"VF_GREENBONE_ALIVE_TEST tem de ser vazio ou um de: {', '.join(allowed)}")
        return v

    @field_validator("wpscan_mode")
    @classmethod
    def _wpscan_mode(cls, v: str) -> str:
        v = (v or "").strip().lower().replace("-", "_")
        v = {"shared": "partilhado", "per_site": "por_site", "premium": "por_site"}.get(v, v)
        if v not in ("partilhado", "por_site"):
            raise ValueError("VF_WPSCAN_MODE tem de ser partilhado ou por_site")
        return v

    @field_validator("ticket_mode")
    @classmethod
    def _ticket_mode(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in ("", "email", "webhook"):
            raise ValueError("VF_TICKET_MODE tem de ser vazio, email ou webhook")
        return v

    @field_validator("ticket_min_severity", "watch_email_min_severity")
    @classmethod
    def _severity(cls, v: str) -> str:
        v = (v or "").strip().lower()
        v = {
            "critica": "critical",
            "crítica": "critical",
            "alta": "high",
            "media": "medium",
            "média": "medium",
            "baixa": "low",
        }.get(v, v)
        if v not in ("info", "low", "medium", "high", "critical"):
            raise ValueError("gravidade tem de ser info, low, medium, high ou critical")
        return v

    @field_validator("dd_url")
    @classmethod
    def _strip_slash(cls, v: str) -> str:
        return v.rstrip("/")

    # --- Derivados ---------------------------------------------------------------------
    @property
    def environment_list(self) -> list[str]:
        return [x.strip() for x in self.environments.split(",") if x.strip()]

    def sla_days(self) -> dict[str, int]:
        """VF_RISK_SLA_DAYS → {"P1": 7, ...}. Valores em falta ou inválidos usam a omissão."""
        defaults = [7, 30, 90, 180]
        parts = [p.strip() for p in self.risk_sla_days.split(",")]
        out = {}
        for i, prio in enumerate(("P1", "P2", "P3", "P4")):
            try:
                value = int(parts[i])
            except (IndexError, ValueError):
                value = defaults[i]
            out[prio] = value if value > 0 else defaults[i]
        return out

    @staticmethod
    def _pair(raw: str, default: tuple[float, float]) -> tuple[float, float]:
        try:
            a, b = (float(x) for x in raw.split(",", 1))
            return (a, b) if 0 < a <= b else default
        except ValueError:
            return default

    def server_thresholds(self) -> dict[str, tuple[float, float]]:
        return {
            "mem": self._pair(self.servers_mem_pct, (85, 95)),
            "disk": self._pair(self.servers_disk_pct, (80, 90)),
            "swap": self._pair(self.servers_swap_pct, (50, 80)),
            "load": self._pair(self.servers_load_per_cpu, (1.5, 3)),
        }

    @property
    def dd_browser_url(self) -> str:
        return (self.dd_public_url or self.dd_url).rstrip("/")

    @property
    def greenbone_lifecycle_enabled(self) -> bool:
        return bool(self.greenbone_ssh_host)

    def wpscan_tokens(self) -> list[str]:
        """Todas as chaves WPScan configuradas, sem duplicados, pela ordem dada."""
        raw = self.wpscan_api_token.get_secret_value() + "," + self.wpscan_api_tokens.get_secret_value()
        tokens: list[str] = []
        for item in re.split(r"[\s,;]+", raw):
            item = item.strip()
            if item and item not in tokens:
                tokens.append(item)
        return tokens

    @property
    def dd_configured(self) -> bool:
        return bool(self.dd_url and self.dd_token.get_secret_value())

    def dd_verify(self) -> bool | str:
        if not self.dd_verify_tls:
            return False
        return self.dd_ca_bundle or True

    def resolved_secret_key(self) -> str:
        """Chave das sessões: a configurada, ou uma gerada e persistida no data_dir."""
        configured = self.secret_key.get_secret_value()
        if configured:
            return configured
        path = self.data_dir / ".secret_key"
        if path.exists():
            return path.read_text().strip()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        key = secrets.token_urlsafe(48)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(key)
        return key

    def public_view(self) -> dict[str, object]:
        """Configuração efetiva para a página de definições, com segredos mascarados."""
        out: dict[str, object] = {}
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, SecretStr):
                if name == "secret_key" and not value.get_secret_value():
                    out[name] = "gerado automaticamente"
                elif name == "wpscan_api_tokens" and value.get_secret_value():
                    out[name] = f"definido ({len(self.wpscan_tokens())} chaves no total)"
                else:
                    out[name] = "definido" if value.get_secret_value() else "por definir"
            elif isinstance(value, Path):
                out[name] = str(value)
            else:
                out[name] = value
        return out


@lru_cache
def get_settings() -> Settings:
    return Settings()
