#!/usr/bin/env bash
# Ambiente de laboratório VulnFlux: Portal SOC + VulnFlux + Greenbone + DefectDojo.
#
#   ./scripts/lab.sh up          gera o .env.lab (1.ª vez), constrói e arranca tudo
#   ./scripts/lab.sh status      estado dos serviços, URLs e progresso do Greenbone
#   ./scripts/lab.sh creds       mostra as credenciais de acesso
#   ./scripts/lab.sh portal      o que o Portal SOC vê agora (estado, versões, feeds)
#   ./scripts/lab.sh risk        descarrega KEV/EPSS/exploits e recalcula as prioridades
#   ./scripts/lab.sh atalaia up  junta o Atalaia Cert ao laboratório (status | logs | down)
#   ./scripts/lab.sh servers demo   servidor de demonstração ligado à página Servidores
#   ./scripts/lab.sh servers check  verifica agora todos os servidores
#   ./scripts/lab.sh servers ligar  mostra o comando para ligar um servidor teu
#   ./scripts/lab.sh alvo up        alvos vulneráveis de laboratório, já registados em Hosts (sem scan)
#   ./scripts/lab.sh alvo scan [descoberta|rapido|completo]  o mesmo e corre logo o scan Greenbone
#   ./scripts/lab.sh alvo down      desliga o alvo vulnerável
#   ./scripts/lab.sh backup      backup já (lista | restaurar PASTA); há um automático todos os dias
#   ./scripts/lab.sh gb          diagnóstico do Greenbone (feeds, erros, OOM, CPU, gate)
#   ./scripts/lab.sh gb-tasks    scans do VulnFlux no gvmd: estado e progresso
#   ./scripts/lab.sh gb-restart  reinicia o gvmd (se o carregamento dos feeds parar)
#   ./scripts/lab.sh logs [svc]  logs (ex.: vulnflux, gvmd, dd-uwsgi)
#   ./scripts/lab.sh down        pára tudo (mantém os dados)
#   ./scripts/lab.sh reset       pára e APAGA todos os dados do laboratório
#   ./scripts/lab.sh rebuild     reconstrói o VulnFlux e o portal depois de alterações ao código
#   ./scripts/lab.sh update      atualiza tudo (código, imagens), verifica e volta atrás se algo não arrancar

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE=".env.lab"
# Os backups ficam com o dono de quem corre o lab.sh (não root)
export BACKUP_UID="${BACKUP_UID:-$(id -u)}" BACKUP_GID="${BACKUP_GID:-$(id -g)}"
# Pastas montadas no contentor de backup: criadas já, senão o Docker cria-as como root
mkdir -p .lab/backups .lab/atalaia/secrets
COMPOSE=(docker compose -f compose.lab.yaml --env-file "$ENV_FILE")

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '\033[33m! %s\033[0m\n' "$*" >&2; }
die() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# Segredo aleatório. Sem "tr </dev/urandom | head": com pipefail, o SIGPIPE do tr faz o
# script terminar em silêncio a meio (foi o que acontecia no upgrade_env).
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' < <(head -c 1024 /dev/urandom) | cut -c "1-$1"; }

# Nunca falha (chave em falta = vazio): com pipefail, um grep sem resultado terminava o script
env_get() { { grep -E "^$1=" "$ENV_FILE" 2>/dev/null || true; } | tail -n1 | cut -d= -f2-; }

env_set() {
  if grep -q "^$1=" "$ENV_FILE" 2>/dev/null; then
    sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
  else
    [ -s "$ENV_FILE" ] && [ -n "$(tail -c1 "$ENV_FILE")" ] && echo >>"$ENV_FILE"
    printf '%s=%s\n' "$1" "$2" >>"$ENV_FILE"
  fi
}

# Serviços opcionais ligados no .env.lab entram em todos os comandos (up, restart, status…)
[ "$(env_get ATALAIA_ENABLED)" = "true" ] && COMPOSE+=(--profile atalaia)
[ "$(env_get SERVERS_DEMO)" = "true" ] && COMPOSE+=(--profile servers)
[ "$(env_get ALVOS_ENABLED)" = "true" ] && COMPOSE+=(--profile alvos)

check_prereqs() {
  command -v docker >/dev/null || die "docker não encontrado. Instala o Docker Desktop (integração WSL) ou o Docker Engine no WSL."
  docker info >/dev/null 2>&1 || die "sem acesso ao daemon do Docker (está a correr? o teu utilizador tem permissão? tenta: sudo $0 $*)"
  local v
  v="$(docker compose version --short 2>/dev/null | sed 's/^v//')" || die "precisa do plugin docker compose v2"
  if [ "$(printf '%s\n2.24.0\n' "$v" | sort -V | head -n1)" != "2.24.0" ]; then
    die "docker compose $v é demasiado antigo: o laboratório precisa de >= 2.24 (include, !override)"
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
    value="$(rand 20)"
    sed -i "s|^${key}=GERAR$|${key}=${value}|" "$ENV_FILE"
  done
  for key in DD_SECRET_KEY DD_CREDENTIAL_AES_256_KEY VF_STATUS_TOKEN ATALAIA_STATUS_TOKEN SONDA_TOKEN; do
    value="$(rand 32)"
    sed -i "s|^${key}=GERAR$|${key}=${value}|" "$ENV_FILE"
  done
  info "passwords e segredos gerados (ver: $0 creds)"
}

# .env.lab criado por uma versão anterior: acrescenta as chaves novas (portal, estado)
upgrade_env() {
  local key value added=0
  # Garante que o ficheiro acaba em nova linha (senão a 1.ª chave nova colava-se à última)
  [ -s "$ENV_FILE" ] && [ -n "$(tail -c1 "$ENV_FILE")" ] && echo >>"$ENV_FILE"
  for key in SP_ADMIN_USER SP_ADMIN_PASSWORD VF_STATUS_TOKEN PORTAL_PORT ATALAIA_STATUS_TOKEN ATALAIA_PORT SONDA_TOKEN; do
    grep -q "^${key}=" "$ENV_FILE" && continue
    case "$key" in
      SP_ADMIN_USER) value="admin" ;;
      PORTAL_PORT) value="8090" ;;
      ATALAIA_PORT) value="8088" ;;
      VF_STATUS_TOKEN | ATALAIA_STATUS_TOKEN | SONDA_TOKEN) value="$(rand 32)" ;;
      *) value="$(rand 20)" ;;
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
  if [ "$(env_get ATALAIA_ENABLED)" = "true" ]; then
    info "Atalaia     http://localhost:$(env_get ATALAIA_PORT)   utilizador admin   password $(cat "$ATALAIA_SECRETS/admin_password" 2>/dev/null || echo '?')"
  fi
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
  for var in VF_PORT DD_PORT PORTAL_PORT ATALAIA_PORT; do
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
    [ "${port:-}" = "$(env_get ATALAIA_PORT)" ] && var="ATALAIA_PORT"
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

# --- Atalaia Cert (repositório certs-watch, ao lado deste) ---------------------------
ATALAIA_REPO="https://github.com/ricardodomingues10/certs-watch"
ATALAIA_SECRETS="$ROOT/.lab/atalaia/secrets"
ATALAIA_SECRET_NAMES=(db_password admin_password ucmdb_user ucmdb_password smax_user smax_password smtp_password avi_user avi_password)

atalaia_setup() {
  local dir name src
  dir="$(env_get ATALAIA_DIR)"
  dir="${dir:-$(cd "$ROOT/.." && pwd)/certs-watch}"
  if [ ! -d "$dir/.git" ] && [ ! -f "$dir/Dockerfile" ]; then
    bold "A clonar o Atalaia Cert para $dir"
    git clone "$ATALAIA_REPO" "$dir"
  else
    info "Atalaia Cert em $dir (atualiza com: git -C $dir pull)"
  fi
  env_set ATALAIA_DIR "$dir"
  env_set ATALAIA_SECRETS "$ATALAIA_SECRETS"
  env_set ATALAIA_ENV_FILE "$ROOT/.lab/atalaia/atalaia.env"
  [ -n "$(env_get ATALAIA_STATUS_TOKEN)" ] || env_set ATALAIA_STATUS_TOKEN "$(rand 32)"
  [ -n "$(env_get ATALAIA_PORT)" ] || env_set ATALAIA_PORT 8088

  mkdir -p "$ATALAIA_SECRETS"
  chmod 700 "$ROOT/.lab" "$ROOT/.lab/atalaia" 2>/dev/null || true
  for name in "${ATALAIA_SECRET_NAMES[@]}"; do
    [ -f "$ATALAIA_SECRETS/$name" ] && continue
    src="$dir/secrets/$name"
    if [ -s "$src" ]; then
      cp "$src" "$ATALAIA_SECRETS/$name"       # segredos reais que já tenhas no certs-watch
    elif [ "$name" = db_password ] || [ "$name" = admin_password ]; then
      rand 24 | tr -d '\n' >"$ATALAIA_SECRETS/$name"
    else
      : >"$ATALAIA_SECRETS/$name"               # opcionais: vazio = funcionalidade desligada
    fi
  done
  # O contentor corre como UID 10001 e tem de conseguir ler os segredos
  if [ "$(id -u)" = 0 ]; then
    chown 10001:10001 "$ATALAIA_SECRETS"/* && chmod 400 "$ATALAIA_SECRETS"/*
    # o PostgreSQL lê a password como o utilizador dele (UID 70), não como 10001
    chmod 444 "$ATALAIA_SECRETS/db_password"
  else
    chmod 644 "$ATALAIA_SECRETS"/*
  fi

  if [ ! -f "$ROOT/.lab/atalaia/atalaia.env" ]; then
    if [ -f "$dir/.env" ]; then
      cp "$dir/.env" "$ROOT/.lab/atalaia/atalaia.env"
      info "configuração copiada de $dir/.env"
    else
      cp "$dir/.env.example" "$ROOT/.lab/atalaia/atalaia.env"
      warn "sem $dir/.env: usei o .env.example. Ajusta UCMDB, domínios CT, etc. em .lab/atalaia/atalaia.env"
    fi
  fi
  env_set ATALAIA_ENABLED true
}

OWN_IMAGES=(vulnflux:lab soc-portal:lab atalaia-cert:lab)

wait_healthy() { # url, segundos
  local url="$1" deadline=$((SECONDS + $2))
  while [ $SECONDS -lt $deadline ]; do
    curl -fsS -o /dev/null --max-time 5 "$url" 2>/dev/null && return 0
    sleep 3
  done
  return 1
}

update_cmd() {
  local pull=1 prev
  [ "${1:-}" = "--sem-git" ] && pull=0
  prev="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo '?')"
  bold "1/5 Código"
  if [ "$pull" = 1 ] && git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]; then
      warn "há alterações locais ao código: não faço git pull (usa --sem-git para atualizar só as imagens)"
    else
      git -C "$ROOT" pull --ff-only || die "git pull falhou (ramo divergente?): resolve à mão e volta a correr"
    fi
  fi
  info "versão: $prev → $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo '?')"
  upgrade_env
  ensure_atalaia
  local adir
  adir="$(env_get ATALAIA_DIR)"
  if [ "$pull" = 1 ] && [ -n "$adir" ] && [ -d "$adir/.git" ]; then
    git -C "$adir" pull --ff-only || warn "não consegui atualizar o Atalaia Cert em $adir (alterações locais?)"
  fi
  bold "2/5 Guardar as imagens atuais (para voltar atrás)"
  local img
  for img in "${OWN_IMAGES[@]}"; do
    if docker image inspect "$img" >/dev/null 2>&1; then
      docker tag "$img" "${img%:*}:rollback" && info "$img → ${img%:*}:rollback"
    fi
  done
  bold "3/5 Imagens novas (DefectDojo, Greenbone, PostgreSQL…) e build do VulnFlux, portal e Atalaia"
  "${COMPOSE[@]}" pull --ignore-buildable --quiet || warn "algumas imagens não foram descarregadas (sem Internet?)"
  "${COMPOSE[@]}" build --pull
  bold "4/5 Arrancar"
  compose_up
  sync_gb_password
  bold "5/5 Verificar"
  local ok=1
  if wait_healthy "http://127.0.0.1:$(env_get VF_PORT)/healthz" 180; then info "VulnFlux responde"; else warn "VulnFlux não respondeu"; ok=0; fi
  if wait_healthy "http://127.0.0.1:$(env_get PORTAL_PORT)/healthz" 120; then info "Portal responde"; else warn "Portal não respondeu"; ok=0; fi
  if [ "$(env_get ATALAIA_ENABLED)" = "true" ]; then
    if wait_healthy "http://127.0.0.1:$(env_get ATALAIA_PORT)/healthz" 180; then info "Atalaia Cert responde"; else warn "Atalaia Cert não respondeu (vê: $0 atalaia logs)"; fi
  fi
  if [ "$ok" = 1 ]; then
    "${COMPOSE[@]}" exec -T portal soc-portal check || true
    info "Atualizado. Se algo correr mal mais tarde: $0 rollback"
    return 0
  fi
  warn "a atualização não arrancou: a voltar às imagens anteriores"
  rollback_cmd
  die "voltei atrás. Vê os logs ($0 logs vulnflux) antes de tentar de novo. Código anterior: git checkout $prev"
}

rollback_cmd() {
  local img n=0
  for img in "${OWN_IMAGES[@]}"; do
    if docker image inspect "${img%:*}:rollback" >/dev/null 2>&1; then
      docker tag "${img%:*}:rollback" "$img" && n=$((n + 1))
    fi
  done
  [ "$n" -gt 0 ] || die "não há imagens guardadas (o 'update' guarda-as antes de atualizar)"
  compose_up --no-build
  info "$n imagens repostas"
}

alvo_cmd() {
  local sub="${1:-up}" profile="${2:-descoberta}" extra=()
  [ "$sub" = up ] && extra=(--sem-scan)
  case "$sub" in
    up | scan)
      env_set ALVOS_ENABLED true
      COMPOSE+=(--profile alvos)
      bold "Alvo vulnerável de laboratório (Metasploitable 2), só acessível dentro da rede do laboratório"
      "${COMPOSE[@]}" up -d alvo-vulneravel alvo-web
      [ "$sub" = scan ] && info "scan Greenbone, perfil $profile (o VulnFlux espera que os feeds estejam carregados)"
      "${COMPOSE[@]}" exec -T vulnflux python -m vulnflux.labtools gb-scan alvo-web.lab alvo-web "$profile" 300 "${extra[@]}"
      "${COMPOSE[@]}" exec -T vulnflux python -m vulnflux.labtools gb-scan alvo-vulneravel.lab alvo-vulneravel "$profile" 300 "${extra[@]}"
      ;;
    down)
      "${COMPOSE[@]}" --profile alvos stop alvo-vulneravel alvo-web
      env_set ALVOS_ENABLED false
      ;;
    *) die "uso: $0 alvo up | scan [descoberta|rapido|completo] | down" ;;
  esac
}

backup_cmd() {
  local sub="${1:-agora}" dir="${2:-}"
  mkdir -p .lab/backups && chmod 700 .lab/backups
  case "$sub" in
    agora)
      "${COMPOSE[@]}" up -d backup >/dev/null
      "${COMPOSE[@]}" exec -T backup sh /backup.sh agora
      find .lab/backups -maxdepth 1 -type d -name '20*' | sort | tail -n1 | xargs du -sh
      ;;
    lista)
      find .lab/backups -maxdepth 1 -type d -name '20*' | sort | while read -r d; do printf '  %s  %s\n' "$(du -sh "$d" | cut -f1)" "$(basename "$d")"; done
      [ -f .lab/backups/ultimo.json ] && info "último: $(cat .lab/backups/ultimo.json)"
      ;;
    restaurar)
      [ -n "$dir" ] && [ -f ".lab/backups/$dir/MANIFESTO.txt" ] || die "uso: $0 backup restaurar AAAAMMDD-HHMM (ver: $0 backup lista)"
      (cd ".lab/backups/$dir" && sha256sum -c --quiet MANIFESTO.txt) || die "o backup $dir está corrompido (sha256 não bate)"
      if [ "${3:-}" != "--sim" ]; then
        read -r -p "Substituir os dados atuais pelos de $dir? [escreve 'sim'] " ans
        [ "$ans" = "sim" ] || die "cancelado"
      fi
      local project img
      project="$("${COMPOSE[@]}" config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
      img="$("${COMPOSE[@]}" config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["backup"]["image"])')"
      bold "A restaurar $dir"
      local running=() svc
      for svc in vulnflux portal dd-nginx dd-uwsgi dd-celerybeat dd-celeryworker atalaia-web atalaia-worker; do
        if "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx "$svc"; then running+=("$svc"); fi
      done
      [ ${#running[@]} -eq 0 ] || "${COMPOSE[@]}" stop "${running[@]}"
      "${COMPOSE[@]}" up -d dd-postgres backup
      "${COMPOSE[@]}" exec -T backup sh -c "PGPASSWORD=\"\$DD_DATABASE_PASSWORD\" pg_restore -h dd-postgres -U defectdojo -d defectdojo --clean --if-exists --no-owner /backups/$dir/defectdojo.dump"
      if [ -f ".lab/backups/$dir/atalaia.dump" ] && [ "$(env_get ATALAIA_ENABLED)" != "false" ]; then
        "${COMPOSE[@]}" up -d atalaia-db
        "${COMPOSE[@]}" exec -T backup sh -c "PGPASSWORD=\"\$(cat /src/atalaia_secrets/db_password)\" pg_restore -h atalaia-db -U certwatch -d certwatch --clean --if-exists --no-owner /backups/$dir/atalaia.dump"
      fi
      local vol src
      for pair in lab_data:vulnflux portal_data:portal; do
        vol="${pair%%:*}" src="${pair##*:}"
        docker run --rm -v "${project}_${vol}:/r" -v "$ROOT/.lab/backups/$dir:/b:ro" --entrypoint sh "$img" \
          -c "find /r -mindepth 1 -delete && tar -xzf /b/$src.tar.gz -C /r"
      done
      docker run --rm -v "${project}_lab_secrets:/src/lab_secrets" -v "${project}_lab_server_keys:/src/lab_server_keys" \
        -v "$ROOT/.lab/backups/$dir:/b:ro" --entrypoint sh "$img" -c "tar -xzf /b/segredos.tar.gz -C /src"
      # Primeiro as aplicações com base de dados; o VulnFlux e o portal só depois de o DefectDojo
      # responder (a verificação de saúde que fazem ao arrancar ficaria com o DefectDojo "em falha")
      local first=() last=()
      for svc in "${running[@]}"; do
        case "$svc" in vulnflux | portal) last+=("$svc") ;; *) first+=("$svc") ;; esac
      done
      wait_http() { for _ in $(seq 1 90); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$1")" = 200 ] && return 0; sleep 2; done; warn "$1 ainda não responde"; }
      [ ${#first[@]} -eq 0 ] || "${COMPOSE[@]}" up -d --no-deps "${first[@]}"
      wait_http "http://127.0.0.1:$(env_get DD_PORT)/login"
      [ ${#last[@]} -eq 0 ] || "${COMPOSE[@]}" up -d --no-deps "${last[@]}"
      wait_http "http://127.0.0.1:$(env_get VF_PORT)/healthz"
      info "restaurado a partir de $dir"
      ;;
    *) die "uso: $0 backup [agora | lista | restaurar AAAAMMDD-HHMM]" ;;
  esac
}

servers_cmd() {
  local sub="${1:-}"
  case "$sub" in
    demo)
      env_set SERVERS_DEMO true
      COMPOSE+=(--profile servers)
      bold "Servidor de demonstração (Debian com SSH, configuração por omissão)"
      "${COMPOSE[@]}" up -d --build lab-server
      info "a ligar o servidor ao VulnFlux (conta vulnflux, chave do VulnFlux, sudo limitado, perfil atualizar)"
      "${COMPOSE[@]}" exec -T vulnflux python -m vulnflux.labtools bootstrap atualizar \
        | "${COMPOSE[@]}" exec -T lab-server sh
      # guardar a ligação no volume: sobrevive a recriar o container
      "${COMPOSE[@]}" exec -T lab-server sh -c 'cp /home/vulnflux/.ssh/authorized_keys /keys/vulnflux.authorized_keys;
        [ -f /etc/sudoers.d/vulnflux ] && cp /etc/sudoers.d/vulnflux /keys/vulnflux.sudoers; touch /keys/vulnflux.passwd'
      "${COMPOSE[@]}" exec -T vulnflux python -m vulnflux.labtools add-server lab-server.lab lab-server 0 seguranca \
        || warn "a primeira verificação falhou: vê a execução na página Servidores"
      info "Abre http://localhost:$(env_get VF_PORT)/servers"
      ;;
    check)
      "${COMPOSE[@]}" exec -T vulnflux python -c "import requests" >/dev/null
      info "a pedir a verificação de todos os servidores (página Servidores → Verificar todos)"
      "${COMPOSE[@]}" exec -T vulnflux python - <<'PY'
import os
from vulnflux.labtools import _session
s = _session("http://127.0.0.1:8080", os.environ.get("VF_ADMIN_USER", "admin"), os.environ["VF_ADMIN_PASSWORD"])
r = s.post("http://127.0.0.1:8080/actions/servers/check", timeout=15)
print(r.status_code, r.headers.get("HX-Trigger", ""))
PY
      ;;
    ligar)
      "${COMPOSE[@]}" exec -T vulnflux python -c "
from vulnflux.config import get_settings
from vulnflux.servers import bootstrap, ssh
pub = ssh.public_key(get_settings())
print('Só verificar:'); print(bootstrap.one_liner(pub)); print()
print('Verificar e atualizar:'); print(bootstrap.one_liner(pub, mode='atualizar'))"
      ;;
    *) die "uso: $0 servers demo | check | ligar" ;;
  esac
}

# O Atalaia Cert faz parte do SOC: instala-se e arranca sozinho com up/restart/update
# (desligar: ATALAIA_ENABLED=false no .env.lab, ou "atalaia down").
ensure_atalaia() {
  [ "$(env_get ATALAIA_ENABLED)" = "false" ] && return 0
  atalaia_setup
  case " ${COMPOSE[*]} " in *" atalaia "*) ;; *) COMPOSE+=(--profile atalaia) ;; esac
}

atalaia_cmd() {
  local sub="${1:-up}"
  case "$sub" in
    up)
      check_prereqs atalaia
      upgrade_env
      atalaia_setup
      COMPOSE=(docker compose -f compose.lab.yaml --env-file "$ENV_FILE" --profile atalaia)
      ensure_ports
      bold "A construir e arrancar o Atalaia Cert"
      compose_up --build atalaia-db atalaia-worker atalaia-web
      "${COMPOSE[@]}" up -d --no-deps portal >/dev/null 2>&1 || true   # relê o token do Atalaia
      echo
      show_creds
      info "No Portal SOC aparece em Superfície externa e certificados (pode levar 1 min)."
      info "1.ª execução do pipeline: $0 atalaia pipeline"
      ;;
    pipeline) "${COMPOSE[@]}" exec -T atalaia-worker python -m certwatch.cli run pipeline ;;
    status)
      "${COMPOSE[@]}" ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}' atalaia-db atalaia-worker atalaia-web
      ;;
    logs) "${COMPOSE[@]}" logs -f --tail=100 atalaia-web atalaia-worker ;;
    down)
      "${COMPOSE[@]}" stop atalaia-web atalaia-worker atalaia-db
      env_set ATALAIA_ENABLED false
      info "Atalaia parado (os dados ficam). Volta com: $0 atalaia up"
      ;;
    *) die "uso: $0 atalaia [up|pipeline|status|logs|down]" ;;
  esac
}

cmd="${1:-help}"
shift || true

case "$cmd" in
  up)
    check_prereqs "$cmd"
    init_env
    upgrade_env
    require_tokens
    ensure_atalaia
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
  atalaia) atalaia_cmd "$@" ;;
  servers) servers_cmd "$@" ;;
  alvo) alvo_cmd "$@" ;;
  backup) backup_cmd "$@" ;;
  update) update_cmd "$@" ;;
  rollback) rollback_cmd ;;
  gb-restart)
    "${COMPOSE[@]}" restart gvmd
    info "gvmd reiniciado. Acompanha com: $0 gb   (ou: $0 logs gvmd)"
    ;;
  logs) "${COMPOSE[@]}" logs -f --tail=100 "$@" ;;
  restart)
    upgrade_env
    ensure_atalaia
    ensure_ports
    compose_up "$@"
    sync_gb_password
    show_creds
    ;;
  rebuild)
    upgrade_env
    ensure_atalaia
    compose_up --build vulnflux dd-token portal
    [ "$(env_get ATALAIA_ENABLED)" = "true" ] && compose_up --build atalaia-web atalaia-worker
    ;;
  down) "${COMPOSE[@]}" down ;;
  reset)
    read -r -p "Apagar TODOS os dados do laboratório (hosts, execuções, DefectDojo, feeds do Greenbone)? [escreve 'sim'] " ans
    [ "$ans" = "sim" ] || die "cancelado"
    "${COMPOSE[@]}" down -v
    info "dados apagados. O $ENV_FILE foi mantido."
    ;;
  help | -h | --help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "comando desconhecido: $cmd (ver: $0 help)" ;;
esac
