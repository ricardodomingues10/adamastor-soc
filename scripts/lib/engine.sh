# shellcheck shell=bash disable=SC2034  # ENGINE, ENGINE_NAME e COMPOSE_BIN são usados por quem faz source
# Motor de contentores do laboratório: Docker ou Podman.
#
#   VF_ENGINE=docker | podman | auto (omissão: Docker se responder, senão Podman)
#
# Com Podman, o "docker compose" (plugin v2 ou docker-compose) fala com a API compatível do Podman
# pelo socket (DOCKER_HOST); o "podman compose" também serve, porque delega no mesmo binário. Os
# outros comandos (ps, inspect, run, tag) usam o cliente podman ligado ao MESMO socket, para verem os
# mesmos contentores e volumes (rootful ou rootless, conforme o socket).
#
# Define: ENGINE_NAME, ENGINE (array: cliente do motor) e COMPOSE_BIN (array: compose).

_engine_is_podman_shim() { docker info 2>/dev/null | grep -qi 'podman'; }

podman_socket() {
  if [ -n "${DOCKER_HOST:-}" ]; then
    return 0
  fi
  local sock unit_scope=()
  if [ "$(id -u)" = 0 ]; then
    sock=/run/podman/podman.sock
  else
    sock="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
    unit_scope=(--user)
  fi
  if [ ! -S "$sock" ]; then
    systemctl "${unit_scope[@]}" start podman.socket >/dev/null 2>&1 || true
  fi
  if [ ! -S "$sock" ]; then
    # Sem systemd (WSL, contentores): serviço da API em segundo plano
    mkdir -p "$(dirname "$sock")"
    nohup podman system service --time=0 "unix://$sock" >/dev/null 2>&1 &
    for _ in $(seq 1 20); do
      [ -S "$sock" ] && break
      sleep 0.5
    done
  fi
  [ -S "$sock" ] || return 1
  export DOCKER_HOST="unix://$sock"
}

engine_detect() {
  local want="${VF_ENGINE:-auto}"
  if [ "$want" = auto ]; then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && ! _engine_is_podman_shim; then
      want=docker
    elif command -v podman >/dev/null 2>&1; then
      want=podman
    else
      want=docker
    fi
  fi
  ENGINE_NAME="$want"
  case "$ENGINE_NAME" in
    docker)
      ENGINE=(docker)
      COMPOSE_BIN=(docker compose)
      ;;
    podman)
      if ! podman_socket; then
        printf '\033[31m✗ %s\033[0m\n' "não consegui abrir o socket da API do Podman (systemctl --user enable --now podman.socket)" >&2
        return 1
      fi
      ENGINE=(podman --remote --url "$DOCKER_HOST")
      if docker compose version >/dev/null 2>&1; then
        COMPOSE_BIN=(docker compose)
      elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_BIN=(docker-compose)
      else
        COMPOSE_BIN=(podman compose)
      fi
      ;;
    *)
      printf '\033[31m✗ VF_ENGINE=%s: usa docker ou podman\033[0m\n' "$ENGINE_NAME" >&2
      return 1
      ;;
  esac
  export ENGINE_NAME
}

# Versão do compose (sem o "v"); vazio se não houver.
compose_version() { "${COMPOSE_BIN[@]}" version --short 2>/dev/null | sed 's/^v//' | head -n1; }
