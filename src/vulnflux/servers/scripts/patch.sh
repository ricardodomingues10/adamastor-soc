# VulnFlux · aplicar atualizações (perfil "atualizar" do comando de ligação).
# VF_MODE=seguranca: só atualizações de segurança · VF_MODE=tudo: todas.
# VF_SEC_PKGS: pacotes de segurança (fallback no Debian/Ubuntu sem unattended-upgrades).
# Linhas "@@chave valor" são para o VulnFlux; o resto é a saída do gestor de pacotes (fica no registo).
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
has() { command -v "$1" >/dev/null 2>&1; }
MODE=${VF_MODE:-seguranca}
rc=0
if has apt-get; then
  echo "@@pkg apt"
  sudo -n apt-get update -qq || { echo "@@error sem permissão para apt-get (perfil atualizar em falta)"; exit 3; }
  OPTS="-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
  if [ "$MODE" = tudo ]; then
    # shellcheck disable=SC2086
    sudo -n apt-get $OPTS dist-upgrade; rc=$?
  elif has unattended-upgrade && sudo -n -l unattended-upgrade >/dev/null 2>&1; then
    echo "@@method unattended-upgrade"
    sudo -n unattended-upgrade -v; rc=$?
  elif [ -n "${VF_SEC_PKGS:-}" ]; then
    echo "@@method only-upgrade"
    # shellcheck disable=SC2086
    sudo -n apt-get $OPTS install --only-upgrade $VF_SEC_PKGS; rc=$?
  else
    echo "@@method nada"
  fi
elif has dnf || has yum; then
  P=dnf; has dnf || P=yum
  echo "@@pkg $P"
  if [ "$MODE" = tudo ]; then sudo -n "$P" -y upgrade; rc=$?
  else sudo -n "$P" -y upgrade --security; rc=$?; fi
elif has zypper; then
  echo "@@pkg zypper"
  if [ "$MODE" = tudo ]; then sudo -n zypper --non-interactive update; rc=$?
  else sudo -n zypper --non-interactive patch --category security; rc=$?; fi
else
  echo "@@error gestor de pacotes não suportado"; exit 4
fi
echo "@@rc $rc"
if [ -f /var/run/reboot-required ]; then echo "@@reboot 1"
elif has needs-restarting; then needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ] && echo "@@reboot 1" || echo "@@reboot 0"
else echo "@@reboot 0"; fi
echo "@@end 1"
