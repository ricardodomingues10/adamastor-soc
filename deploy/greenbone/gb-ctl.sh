#!/usr/bin/env bash
# gb-ctl.sh — controlo do ciclo de vida do Greenbone, chamado pelo orchestrator.
#
# Instalar em /opt/greenbone/gb-ctl.sh (root:root, 0755) e usar como forced command
# de uma chave SSH dedicada, para que o orchestrator só consiga executar estes verbos:
#
#   start   - arranca a stack (pela ordem e health checks definidos no compose)
#   stop    - pára todos os containers (volumes e dados ficam intactos)
#   update  - puxa imagens novas (core + feeds) e recria o que mudou
#   status  - estado de cada serviço em JSON
#
# Este script não sabe nada de GMP, scans ou feeds: só liga, desliga e atualiza.
# Tudo o que é lógica (esperar pela prontidão, validar feeds) vive no orchestrator.
#
# Saída: uma única linha JSON no stdout. Exit code 0 = ok, 1 = erro, 2 = uso inválido.

set -Eeuo pipefail

COMPOSE_DIR="${GB_COMPOSE_DIR:-/opt/greenbone}"
LOG_FILE="${GB_LOG_FILE:-/var/log/greenbone/gb-ctl.log}"
LOCK_FILE="${GB_LOCK_FILE:-/run/lock/gb-ctl.lock}"
PULL_TIMEOUT="${GB_PULL_TIMEOUT:-1800}"
UP_TIMEOUT="${GB_UP_TIMEOUT:-900}"
STOP_TIMEOUT="${GB_STOP_TIMEOUT:-300}"

ACTION="unknown"

log() {
  printf '%s [%s] %s\n' "$(date -Is)" "$ACTION" "$*" >>"$LOG_FILE" 2>/dev/null || true
}

# emit <ok:true|false> <message> [json_extra]
emit() {
  local ok="$1" msg="$2" extra="${3:-null}"
  jq -cn --arg action "$ACTION" --argjson ok "$ok" --arg msg "$msg" \
    --argjson extra "$extra" --arg ts "$(date -Is)" \
    '{action: $action, ok: $ok, message: $msg, ts: $ts, data: $extra}'
}

on_error() {
  local line="$1" cmd="$2"
  log "ERRO linha ${line}: ${cmd}"
  emit false "falhou na linha ${line}: ${cmd}"
  exit 1
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

# Array (e não função) para poder ser usado com `timeout`, que não executa funções bash.
COMPOSE=(docker compose --project-directory "$COMPOSE_DIR" -f "$COMPOSE_DIR/compose.yaml")

services_json() {
  # `docker compose ps --format json` devolve NDJSON nas versões recentes e um array
  # nas antigas; normaliza para um array com os campos relevantes.
  "${COMPOSE[@]}" ps -a --format json \
    | jq -cs 'if length == 1 and (.[0] | type) == "array" then .[0] else . end
              | map({service: .Service, state: .State, health: (.Health // ""),
                     exit_code: .ExitCode, image: .Image})'
}

# --- Verbo: vem do forced command (SSH_ORIGINAL_COMMAND) ou do argumento ---------
REQUEST="${SSH_ORIGINAL_COMMAND:-${1:-}}"
# Só aceita exatamente uma palavra da lista; qualquer outra coisa é rejeitada.
case "$REQUEST" in
  start | stop | update | status) ACTION="$REQUEST" ;;
  *)
    ACTION="invalid"
    log "pedido rejeitado: '${REQUEST}'"
    emit false "verbo inválido (permitidos: start, stop, update, status)"
    exit 2
    ;;
esac

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

# status é só leitura: não precisa de lock
if [[ "$ACTION" != "status" ]]; then
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    log "outra operação em curso"
    emit false "outra operação gb-ctl em curso"
    exit 1
  fi
fi

log "início"

case "$ACTION" in
  start)
    timeout "$UP_TIMEOUT" "${COMPOSE[@]}" up -d --no-recreate >>"$LOG_FILE" 2>&1
    emit true "stack arrancada (prontidão é verificada pelo orchestrator via GMP)" "$(services_json)"
    ;;
  stop)
    timeout "$STOP_TIMEOUT" "${COMPOSE[@]}" stop >>"$LOG_FILE" 2>&1
    emit true "stack parada" "$(services_json)"
    ;;
  update)
    timeout "$PULL_TIMEOUT" "${COMPOSE[@]}" pull --quiet >>"$LOG_FILE" 2>&1
    timeout "$UP_TIMEOUT" "${COMPOSE[@]}" up -d --remove-orphans >>"$LOG_FILE" 2>&1
    # Remove só imagens "dangling" (as versões antigas que perderam a tag com o pull),
    # para os feeds diários não encherem o disco. Não toca em imagens com tag.
    docker image prune -f >>"$LOG_FILE" 2>&1 || true
    emit true "imagens atualizadas e stack recriada" "$(services_json)"
    ;;
  status)
    emit true "estado atual" "$(services_json)"
    ;;
esac

log "fim ok"
