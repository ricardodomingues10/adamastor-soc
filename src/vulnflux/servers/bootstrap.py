"""Comando de ligação de um servidor: cria a conta do VulnFlux, instala a chave pública e um sudo limitado.

Corre-se uma vez no servidor, como root (o comando de uma linha que a página mostra). Dois perfis:

  verificar  só leitura: o sudo permite apenas os comandos exatos da recolha (sshd -T, ufw status,
             apt-get update -qq, ...). É o perfil por omissão.
  atualizar  também aplica atualizações e reinicia (apt-get, dnf, systemctl reboot). Quem pode instalar
             pacotes é, na prática, root: só para servidores em que o VulnFlux deve mesmo atualizar.

A chave fica com restrições (sem pty, sem encaminhamentos) e o sudoers é validado com visudo antes de
ser instalado: um erro nunca deixa o sudo do servidor estragado.
"""

from __future__ import annotations

import base64
import shlex

# Comandos exatos que a recolha chama com "sudo -n" (scripts/collect.sh). Argumentos fixos.
READ_COMMANDS = [
    ("sshd", "-T"),
    ("journalctl", "-k --since -7d -q"),
    ("ufw", "status"),
    ("nft", "list ruleset"),
    ("iptables", "-S INPUT"),
    ("apt-get", "update -qq"),
    ("dnf", "-q makecache"),
    ("yum", "-q makecache"),
    ("lynis", "audit system --quick --no-colors --quiet"),
    ("cat", "/var/log/lynis-report.dat"),
]
# Perfil atualizar: comandos com quaisquer argumentos
PATCH_COMMANDS = ["apt-get", "dnf", "yum", "zypper", "unattended-upgrade", "needs-restarting", "systemctl reboot"]


def script(pubkey: str, *, user: str = "vulnflux", mode: str = "verificar") -> str:
    if mode not in ("verificar", "atualizar"):
        raise ValueError(mode)
    reads = "\n".join(f"add {shlex.quote(c)} {shlex.quote(a)}" for c, a in READ_COMMANDS)
    patches = "\n".join(
        f"add {shlex.quote(c.split()[0])} {shlex.quote(' '.join(c.split()[1:]))}" for c in PATCH_COMMANDS
    )
    return f"""#!/bin/sh
# VulnFlux · ligação deste servidor (perfil: {mode})
set -eu
[ "$(id -u)" = 0 ] || {{ echo "Corra como root (sudo sh)" >&2; exit 1; }}
U={shlex.quote(user)}
KEY={shlex.quote(pubkey)}
if ! id "$U" >/dev/null 2>&1; then
  if command -v useradd >/dev/null 2>&1; then useradd --system --create-home --shell /bin/sh "$U"
  else adduser -S -D -h "/home/$U" -s /bin/sh "$U"; fi
fi
H=$(getent passwd "$U" | cut -d: -f6)
G=$(id -gn "$U")
mkdir -p "$H/.ssh"
printf '%s\\n' "no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty $KEY" > "$H/.ssh/authorized_keys"
chown -R "$U:$G" "$H/.ssh"; chmod 700 "$H/.ssh"; chmod 600 "$H/.ssh/authorized_keys"
# A conta não tem palavra-passe: só entra com a chave
passwd -l "$U" >/dev/null 2>&1 || true

L=""
add() {{ # comando, argumentos exatos
  b=$(command -v "$1" 2>/dev/null) || return 0
  L="$L${{L:+, }}$b${{2:+ $2}}"   # sem argumentos = quaisquer argumentos (só no perfil atualizar)
}}
{reads}
{patches if mode == "atualizar" else "# perfil verificar: sem comandos de atualização"}
if command -v sudo >/dev/null 2>&1; then
  T=$(mktemp)
  {{
    echo "# Gerado pelo VulnFlux (perfil {mode}). Apagar este ficheiro retira o acesso."
    echo "Defaults:$U !requiretty"
    echo "Defaults:$U env_keep += \\"DEBIAN_FRONTEND NEEDRESTART_MODE\\""
    echo "$U ALL=(root) NOPASSWD: $L"
  }} > "$T"
  if visudo -cf "$T" >/dev/null; then
    install -m 0440 -o root -g root "$T" /etc/sudoers.d/vulnflux
  else
    echo "Aviso: sudoers gerado não passou no visudo; ficou sem sudo (a recolha funciona com menos detalhe)." >&2
  fi
  rm -f "$T"
else
  echo "Aviso: sudo não está instalado; a recolha funciona com menos detalhe." >&2
fi
echo "VulnFlux: servidor ligado (conta $U, perfil {mode}). Volte à página Servidores e carregue em Verificar."
"""


def one_liner(pubkey: str, *, user: str = "vulnflux", mode: str = "verificar") -> str:
    """Uma linha para colar no servidor: o script em base64 (sem aspas a escapar), executado por root."""
    b64 = base64.b64encode(script(pubkey, user=user, mode=mode).encode()).decode()
    return f"echo {b64} | base64 -d | sudo sh"


def remove_script(user: str = "vulnflux") -> str:
    u = shlex.quote(user)
    return f"sudo sh -c 'rm -f /etc/sudoers.d/vulnflux; userdel -r {u} 2>/dev/null || deluser --remove-home {u}'"
