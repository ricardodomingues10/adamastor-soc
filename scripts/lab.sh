#!/usr/bin/env bash
# Ambiente de laboratório VulnFlux: Portal SOC + VulnFlux + Greenbone + DefectDojo.
#
#   ./scripts/lab.sh up          gera o .env.lab (1.ª vez), constrói e arranca tudo
#   ./scripts/lab.sh status      estado dos serviços, URLs e progresso do Greenbone
#   ./scripts/lab.sh creds       mostra as credenciais de acesso
#   ./scripts/lab.sh portal      o que o Portal SOC vê agora (estado, versões, feeds)
#   ./scripts/lab.sh risk        descarrega KEV/EPSS/exploits e recalcula as prioridades
#   ./scripts/lab.sh gb          diagnóstico do Greenbone (feeds, erros, OOM, CPU, gate)
#   ./scripts/lab.sh gb-tasks    scans do VulnFlux no gvmd: estado e progresso
#   ./scripts/lab.sh gb-restart  reinicia o gvmd (se o carregamento dos feeds parar)
#   ./scripts/lab.sh logs [svc]  logs (ex.: vulnflux, gvmd, dd-uwsgi)
#   ./scripts/lab.sh down        pára tudo (mantém os dados)
#   ./scripts/lab.sh reset       pára e APAGA todos os dados do laboratório
#   ./scripts/lab.sh rebuild     reconstrói o VulnFlux e o portal depois de alterações ao código

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE=".env.lab"
COMPOSE=(docker compose -f compose.lab.yaml --env-file "$ENV_FILE")

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m! %s\033[0m\n' "$*" >&2; }
die() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-; }

check_prereqs() {
  command -v docker >/dev/null || die "docker não encontrado. Instala o Docker Desktop (integração WSL) ou o Docker Engine no WSL."
  docker info >/dev/null 2>&1 || die "sem acesso ao daemon do Docker (está a correr? o teu utilizador tem permissão? tenta: sudo $0 $*)"
  local v
  v="$(docker compose version --short 2>/dev/null | sed 's/^v//')" || die "precisa do plugin docker compose v2"
  if [ "$(printf '%s\n2.20.0\n' "$v" | sort -V | head -n1)" != "2.20.0" ]; then
    die "docker compose $v é demasiado antigo: o laboratório precisa de >= 2.20 (include)"
  fi
  local mem_kb
  mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  if [ "${mem_kb:-0}" -lt 10000000 ]; then
    warn "o WSL tem $((mem_kb / 1024 / 1024)) GB de RAM. Greenbone + DefectDojo precisam de ~10-12 GB."
    warn "aumenta em %UserProfile%\\.wslconfig: [wsl2] memory=12GB  swap=8GB  e corre 'wsl --shutdown'."
  fi
}

init_env() {
  if [ -f "$ENV_FILE" ]; then
    return
  fi
  bold "A criar $ENV_FILE"
  cp lab.env.example "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  local key value
  for key in VF_ADMIN_PASSWORD GB_ADMIN_PASSWORD DD_ADMIN_PASSWORD DD_DATABASE_PASSWORD SP_ADMIN_PASSWORD; do
    value="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"
    sed -i "s|^${key}=GERAR$|${key}=${value}|" "$ENV_FILE"
  done
  for key in DD_SECRET_KEY DD_CREDENTIAL_AES_256_KEY VF_STATUS_TOKEN; do
    value="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)"
    sed -i "s|^${key}=GERAR$|${key}=${value}|" "$ENV_FILE"
  done
  info "passwords e segredos gerados (ver: $0 creds)"
}

# .env.lab criado por uma versão anterior: acrescenta as chaves novas (portal, estado)
upgrade_env() {
  local key value added=0
  for key in SP_ADMIN_USER SP_ADMIN_PASSWORD VF_STATUS_TOKEN PORTAL_PORT; do
    grep -q "^${key}=" "$ENV_FILE" && continue
    case "$key" in
      SP_ADMIN_USER) value="admin" ;;
      PORTAL_PORT) value="8090" ;;
      VF_STATUS_TOKEN) value="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)" ;;
      *) value="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)" ;;
    esac
    printf '%s=%s\n' "$key" "$value" >>"$ENV_FILE"
    added=1
  done
  [ "$added" = 1 ] && info "$ENV_FILE atualizado com as chaves do Portal SOC"
  return 0
}

require_tokens() {
  if [ -z "$(env_get VF_WPSCAN_API_TOKENS)" ] && [ -z "$(env_get VF_WPSCAN_API_TOKEN)" ]; then
    warn "VF_WPSCAN_API_TOKENS está vazio em $ENV_FILE: os scans WPScan vão falhar até o preencheres."
    warn "edita $ENV_FILE e corre '$0 restart'."
  fi
}

show_creds() {
  bold "Acessos"
  info "Portal SOC  http://localhost:$(env_get PORTAL_PORT)   utilizador $(env_get SP_ADMIN_USER)   password $(env_get SP_ADMIN_PASSWORD)"
  info "VulnFlux    http://localhost:$(env_get VF_PORT)   utilizador $(env_get VF_ADMIN_USER)   password $(env_get VF_ADMIN_PASSWORD)"
  info "DefectDojo  http://localhost:$(env_get DD_PORT)   utilizador admin   password $(env_get DD_ADMIN_PASSWORD)"
  info "Greenbone   (sem UI)   utilizador GMP $(env_get GB_ADMIN_USER)   password $(env_get GB_ADMIN_PASSWORD)"
}

gb_progress() {
  # Linhas mais recentes do gvmd sobre carregamento de feeds (o 1.º arranque demora)
  "${COMPOSE[@]}" logs --no-color --tail=400 gvmd 2>/dev/null \
    | grep -E -i "updating|update of|sync|loading|nvts|scap|cert|done" | tail -n 3 | sed 's/^/    /' || true
}

# --- Portas no Windows (WSL + Docker Desktop) ---------------------------------------
# O Docker Desktop abre as portas publicadas no Windows. Falha se a porta estiver em uso
# ou dentro de uma gama reservada pelo Hyper-V (netsh ... excludedportrange). Quando o
# interop do WSL está disponível, verificamos isso no Windows antes de arrancar.

WIN_EXCLUDED=""
WIN_LISTENING=""

load_windows_ports() {
  command -v netsh.exe >/dev/null 2>&1 || return 1
  WIN_EXCLUDED="$(netsh.exe interface ipv4 show excludedportrange protocol=tcp 2>/dev/null \
    | tr -d '\r' | awk '$1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ {print $1, $2}')"
  WIN_LISTENING="$(netstat.exe -ano -p tcp 2>/dev/null | tr -d '\r' \
    | awk '$4 == "LISTENING" {n = split($2, a, ":"); print a[n]}' | sort -un)"
  return 0
}

port_blocked_on_windows() {
  local port="$1" start end
  while read -r start end; do
    [ -n "$start" ] && [ "$port" -ge "$start" ] && [ "$port" -le "$end" ] && return 0
  done <<<"$WIN_EXCLUDED"
  grep -qx "$port" <<<"$WIN_LISTENING" && return 0
  return 1
}

free_windows_port() {
  local port="$1"
  while port_blocked_on_windows "$port"; do
    port=$((port + 1))
  done
  echo "$port"
}

ensure_ports() {
  load_windows_ports || return 0
  local var current new
  for var in VF_PORT DD_PORT PORTAL_PORT; do
    current="$(env_get "$var")"
    [ -n "$current" ] || continue
    # Ignora a porta que este próprio laboratório já tem aberta (restart)
    if docker ps --format '{{.Ports}}' 2>/dev/null | grep -q "127.0.0.1:${current}->"; then
      continue
    fi
    if port_blocked_on_windows "$current"; then
      new="$(free_windows_port "$((current + 1))")"
      sed -i "s/^${var}=.*/${var}=${new}/" "$ENV_FILE"
      warn "$var=$current está em uso ou reservada no Windows: passou para $new (em $ENV_FILE)"
    fi
  done
}

# Corre o compose e, se falhar por porta ocupada no Windows/Docker Desktop, explica como resolver
compose_up() {
  local log rc=0
  log="$(mktemp)"
  "${COMPOSE[@]}" up -d "$@" 2>&1 | tee "$log" || rc=$?
  if grep -q -E "ports are not available|port is already allocated|address already in use" "$log"; then
    local port
    port="$(grep -o -E '127\.0\.0\.1:[0-9]+' "$log" | head -n1 | cut -d: -f2)"
    echo
    warn "a porta ${port:-?} está ocupada ou reservada no Windows."
    local var="VF_PORT" suggestion
    [ "${port:-}" = "$(env_get DD_PORT)" ] && var="DD_PORT"
    [ "${port:-}" = "$(env_get PORTAL_PORT)" ] && var="PORTAL_PORT"
    if load_windows_ports && [ -n "${port:-}" ]; then
      suggestion="$(free_windows_port "$((port + 1))")"
    else
      suggestion=$(( ${port:-8000} + 1000 ))
    fi
    warn "muda-a com: sed -i 's/^${var}=.*/${var}=${suggestion}/' $ENV_FILE && $0 restart"
    warn "(portas reservadas, no PowerShell: netsh interface ipv4 show excludedportrange protocol=tcp)"
  fi
  rm -f "$log"
  return "$rc"
}

# O arranque do gvmd só cria o utilizador GMP se não existir: se GB_ADMIN_PASSWORD mudar
# no .env.lab depois do 1.º arranque, alinhamos aqui a password (idempotente).
sync_gb_password() {
  local user pass
  user="$(env_get GB_ADMIN_USER)"
  pass="$(env_get GB_ADMIN_PASSWORD)"
  [ -n "$user" ] && [ -n "$pass" ] || return 0
  "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx gvmd || return 0

  for _ in $(seq 1 30); do
    if "${COMPOSE[@]}" exec -T -u gvmd gvmd gvmd --user="$user" --new-password="$pass" >/dev/null 2>&1; then
      info "password do utilizador GMP '$user' alinhada com o $ENV_FILE"
      return 0
    fi
    sleep 5   # o gvmd pode ainda estar a criar o utilizador / a migrar a BD
  done
  warn "não foi possível alinhar a password do Greenbone (o gvmd ainda está a arrancar?). Corre '$0 restart' mais tarde."
}

# Tasks "vulnflux:*" no gvmd: estado, progresso e report em curso
gb_tasks() {
  "${COMPOSE[@]}" exec -T vulnflux python - <<'PY' 2>/dev/null || warn "VulnFlux não está a correr: não foi possível consultar o gvmd"
from vulnflux.config import get_settings
from vulnflux.greenbone.scanner import GreenboneClient

with GreenboneClient(get_settings()).session() as gmp:
    tasks = gmp.get_tasks(filter_string='name~"vulnflux:" rows=-1').findall("task")
    if not tasks:
        print("    nenhuma task do VulnFlux")
    for t in tasks:
        cur = t.find("current_report/report")
        last = t.find("last_report/report")
        rep = cur.get("id") if cur is not None else (last.get("id") if last is not None else "-")
        print(f"    {t.findtext('name'):40} {t.findtext('status'):12} {t.findtext('progress') or '-':>4}%  report {rep}")
PY
}

# Diagnóstico do Greenbone: estado dos containers, reinícios/OOM, CPU, logs dos feeds e
# o que o gvmd reporta por GMP. Serve para distinguir "lento mas a avançar" de "parado".
gb_diag() {
  local -a gb_services=(gvmd pg-gvm pg-gvm-migrator redis-server ospd-openvas openvasd configure-openvas
    vulnerability-tests notus-data scap-data cert-bund-data dfn-cert-data data-objects report-formats gpg-data)
  local svc ids

  bold "1. Containers do Greenbone"
  "${COMPOSE[@]}" ps -a --format 'table {{.Service}}\t{{.State}}\t{{.Status}}' \
    | awk -v list=" ${gb_services[*]} " 'NR==1 || index(list, " " $1 " ")'
  echo
  info "Esperado: data containers 'running (healthy)'; pg-gvm-migrator, configure-openvas e gpg-data 'exited (0)';"
  info "gvmd, pg-gvm, redis-server, ospd-openvas e openvasd 'running'."
  echo

  bold "2. Reinícios e falta de memória (OOM)"
  ids="$("${COMPOSE[@]}" ps -aq "${gb_services[@]}" 2>/dev/null | tr '\n' ' ')"
  if [ -n "${ids// /}" ]; then
    # shellcheck disable=SC2086
    docker inspect -f '{{.Name}}  reinícios={{.RestartCount}}  oom={{.State.OOMKilled}}  exit={{.State.ExitCode}}' $ids \
      | sed 's|^/vulnflux-lab-||; s|-1  |  |' | awk '{ if ($2 != "reinícios=0" || $3 != "oom=false" || ($4 != "exit=0")) print "  ! " $0; else print "    " $0 }'
  fi
  free -h 2>/dev/null | awk 'NR<=2 {print "    " $0}'
  echo

  bold "3. Atividade agora (CPU alta no gvmd/pg-gvm = está a importar feeds)"
  ids="$("${COMPOSE[@]}" ps -q gvmd pg-gvm ospd-openvas redis-server 2>/dev/null | tr '\n' ' ')"
  # shellcheck disable=SC2086
  [ -n "${ids// /}" ] && docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' $ids \
    | sed 's|vulnflux-lab-||; s|-1 | |' | sed 's/^/    /'
  echo

  bold "4. gvmd: feeds (últimas linhas relevantes)"
  "${COMPOSE[@]}" logs --no-color --no-log-prefix --tail=2000 gvmd 2>/dev/null \
    | grep -i -E "scap|cert|data object|report format|port list|scan config|nvt|feed|sync|updat|lock" | tail -n 12 | sed 's/^/    /'
  echo

  bold "5. Erros e avisos recentes"
  for svc in gvmd pg-gvm ospd-openvas openvasd; do
    "${COMPOSE[@]}" logs --no-color --no-log-prefix --tail=3000 "$svc" 2>/dev/null \
      | grep -i -E "error|fatal|fail|killed|out of memory|panic|could not|denied" \
      | grep -v -i -E "error_log|0 errors" | tail -n 4 | sed "s/^/    [$svc] /"
  done
  echo

  bold "6. Estado por GMP (o mesmo gate que o VulnFlux usa)"
  "${COMPOSE[@]}" exec -T vulnflux python - <<'PY' 2>/dev/null || warn "VulnFlux não está a correr: não foi possível consultar o gvmd por GMP"
from vulnflux.config import get_settings
from vulnflux.greenbone.readiness import probe
from vulnflux.pipeline import readiness_config

r = probe(readiness_config(get_settings()))
print(f"    estado: {r.status.value}")
for c in r.checks:
    print(f"    {'OK ' if c.ok else '...'} {c.name:16} {c.detail}")
for w in r.warnings:
    print(f"    aviso: {w}")
PY
  echo

  bold "7. Scans do VulnFlux no gvmd (continuam mesmo que o VulnFlux reinicie)"
  gb_tasks
  echo
  info "Se o passo 3 mostrar CPU ~0% no gvmd e pg-gvm durante >30 min com feeds 'a sincronizar',"
  info "o import está parado: corre '$0 gb-restart' (reinicia gvmd e retoma o carregamento)."
}

cmd="${1:-help}"
shift || true

case "$cmd" in
  up)
    check_prereqs "$cmd"
    init_env
    upgrade_env
    require_tokens
    ensure_ports
    bold "A construir e arrancar (a primeira vez descarrega vários GB de imagens e feeds)"
    compose_up --build "$@"
    sync_gb_password
    echo
    show_creds
    echo
    bold "Próximos passos"
    info "1. O DefectDojo demora 2-5 min a inicializar; o VulnFlux arranca quando o token estiver obtido."
    info "2. O Greenbone carrega os feeds no 1.º arranque (30-90 min). O VulnFlux espera sozinho pelo gate de prontidão."
    info "3. Acompanha com: $0 status"
    ;;
  status)
    "${COMPOSE[@]}" ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}'
    echo
    show_creds
    echo
    bold "Greenbone (últimas mensagens dos feeds)"
    gb_progress
    ;;
  creds) show_creds ;;
  portal)
    # O que o Portal SOC vê agora (as mesmas verificações do painel)
    "${COMPOSE[@]}" exec -T portal soc-portal check "$@"
    ;;
  risk)
    # Descarrega KEV/EPSS/exploits e recalcula as prioridades no DefectDojo (como o job diário)
    "${COMPOSE[@]}" exec -T vulnflux python -m vulnflux.labtools risk "$@"
    ;;
  gb) gb_diag ;;
  gb-tasks) gb_tasks ;;
  gb-restart)
    "${COMPOSE[@]}" restart gvmd
    info "gvmd reiniciado. Acompanha com: $0 gb   (ou: $0 logs gvmd)"
    ;;
  logs) "${COMPOSE[@]}" logs -f --tail=100 "$@" ;;
  restart)
    upgrade_env
    ensure_ports
    compose_up "$@"
    sync_gb_password
    show_creds
    ;;
  rebuild) compose_up --build vulnflux dd-token portal ;;
  down) "${COMPOSE[@]}" down ;;
  reset)
    read -r -p "Apagar TODOS os dados do laboratório (hosts, execuções, DefectDojo, feeds do Greenbone)? [escreve 'sim'] " ans
    [ "$ans" = "sim" ] || die "cancelado"
    "${COMPOSE[@]}" down -v
    info "dados apagados. O $ENV_FILE foi mantido."
    ;;
  help | -h | --help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "comando desconhecido: $cmd (ver: $0 help)" ;;
esac
