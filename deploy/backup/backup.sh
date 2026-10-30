#!/bin/sh
# Backups do laboratório do Adamastor SOC (corre no contentor "backup", imagem postgres).
#
#   backup.sh ciclo      um backup por dia à BACKUP_HORA; apaga os com mais de BACKUP_DIAS dias
#   backup.sh agora      um backup já
#
# Cada backup é uma pasta /backups/AAAAMMDD-HHMM com:
#   defectdojo.dump   pg_dump -Fc do DefectDojo (findings, produtos, SLA)
#   atalaia.dump      pg_dump -Fc do Atalaia (se estiver ligado)
#   vulnflux.tar.gz   estado do VulnFlux (hosts, execuções, servidores, prioridades)
#   portal.tar.gz     estado do portal
#   segredos.tar.gz   tokens do laboratório e chaves do servidor de demonstração (pasta 0700)
#   MANIFESTO.txt     sha256 de cada ficheiro
# /backups/ultimo.json diz quando foi o último e se correu bem.
#
# O Greenbone não entra: os dados dele são feeds públicos e tasks que o VulnFlux recria,
# e os resultados já estão no DefectDojo.
set -eu

DIAS="${BACKUP_DIAS:-14}"
HORA="${BACKUP_HORA:-02:30}"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') backup: $*"; }

estado() { # ok|falhou pasta mensagem
  printf '{"estado":"%s","quando":"%s","pasta":"%s","mensagem":"%s"}\n' "$1" "$(date -Iseconds)" "$2" "$3" >/backups/ultimo.json.tmp
  mv /backups/ultimo.json.tmp /backups/ultimo.json
  chown "${BACKUP_UID:-0}:${BACKUP_GID:-0}" /backups/ultimo.json
}

um_backup() {
  dir="/backups/$(date +%Y%m%d-%H%M)"
  mkdir -p "$dir.parcial" && chmod 700 "$dir.parcial"
  avisos=""
  log "a começar em $dir"
  PGPASSWORD="${DD_DATABASE_PASSWORD}" pg_dump -h dd-postgres -U defectdojo -d defectdojo -Fc -f "$dir.parcial/defectdojo.dump"
  if [ -s /src/atalaia_secrets/db_password ] && getent hosts atalaia-db >/dev/null 2>&1; then
    PGPASSWORD="$(cat /src/atalaia_secrets/db_password)" pg_dump -h atalaia-db -U certwatch -d certwatch -Fc -f "$dir.parcial/atalaia.dump"
  else
    avisos="Atalaia desligado (sem atalaia.dump)"
  fi
  tar -czf "$dir.parcial/vulnflux.tar.gz" -C /src/vulnflux .
  tar -czf "$dir.parcial/portal.tar.gz" -C /src/portal .
  tar -czf "$dir.parcial/segredos.tar.gz" -C /src lab_secrets lab_server_keys
  (cd "$dir.parcial" && sha256sum ./*.dump ./*.tar.gz >MANIFESTO.txt)
  mv "$dir.parcial" "$dir"
  chown -R "${BACKUP_UID:-0}:${BACKUP_GID:-0}" "$dir"
  find /backups -maxdepth 1 -type d -name '20*' -mtime +"$DIAS" -exec rm -rf {} +
  log "concluído: $(du -sh "$dir" | cut -f1) ${avisos:+· $avisos}"
  estado ok "$(basename "$dir")" "$avisos"
}

tentar() {
  if ! um_backup; then
    log "FALHOU"
    rm -rf /backups/*.parcial
    estado falhou "" "ver os logs do contentor backup"
    return 1
  fi
}

case "${1:-ciclo}" in
  agora) tentar ;;
  ciclo)
    log "backups diários às $HORA, guardados $DIAS dias"
    while true; do
      agora=$(date +%s)
      alvo=$(date -d "$(date +%Y-%m-%d) $HORA" +%s 2>/dev/null || date -D '%Y-%m-%d %H:%M' -d "$(date +%Y-%m-%d) $HORA" +%s)
      [ "$alvo" -le "$agora" ] && alvo=$((alvo + 86400))
      sleep $((alvo - agora))
      tentar || true
    done ;;
  *) echo "uso: backup.sh ciclo|agora" >&2; exit 2 ;;
esac
