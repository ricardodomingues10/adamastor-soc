#!/bin/sh
# Chaves do host geradas no primeiro arranque e guardadas no volume (a chave não muda entre rebuilds:
# o VulnFlux fixa-a na primeira ligação e recusaria uma chave nova).
set -eu
mkdir -p /run/sshd /keys
for t in rsa ecdsa ed25519; do
  [ -f "/keys/ssh_host_${t}_key" ] || ssh-keygen -q -t "$t" -N "" -f "/keys/ssh_host_${t}_key"
  ln -sf "/keys/ssh_host_${t}_key" "/etc/ssh/ssh_host_${t}_key"
  ln -sf "/keys/ssh_host_${t}_key.pub" "/etc/ssh/ssh_host_${t}_key.pub"
done
# A conta do VulnFlux sobrevive a recriar o container (home no volume)
if [ -f /keys/vulnflux.passwd ] && ! id vulnflux >/dev/null 2>&1; then
  useradd --system --create-home --shell /bin/sh vulnflux
  mkdir -p /home/vulnflux/.ssh && cp /keys/vulnflux.authorized_keys /home/vulnflux/.ssh/authorized_keys
  chown -R vulnflux: /home/vulnflux/.ssh && chmod 700 /home/vulnflux/.ssh && chmod 600 /home/vulnflux/.ssh/authorized_keys
  [ -f /keys/vulnflux.sudoers ] && install -m 0440 /keys/vulnflux.sudoers /etc/sudoers.d/vulnflux
fi
exec /usr/sbin/sshd -D -e
