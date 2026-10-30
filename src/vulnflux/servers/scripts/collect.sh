# VulnFlux · recolha de saúde, hardening e atualizações. Só leitura: não altera nada no servidor.
# Corre como o utilizador de serviço; usa "sudo -n" apenas nos comandos que o sudoers do VulnFlux permite
# (sem palavra-passe) e, quando não pode, regista o que ficou por ver em vez de falhar.
# Saída: uma linha "chave<TAB>valor" por facto.
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
o() { printf '%s\t%s\n' "$1" "$2"; }
has() { command -v "$1" >/dev/null 2>&1; }
S() { sudo -n "$@" 2>/dev/null; }
o v 1

# ---- sistema
if [ -r /etc/os-release ]; then . /etc/os-release; fi
o os.id "${ID:-}"; o os.like "${ID_LIKE:-}"; o os.version "${VERSION_ID:-}"; o os.name "${PRETTY_NAME:-}"
o kernel "$(uname -r)"; o arch "$(uname -m)"; o hostname "$(hostname 2>/dev/null || uname -n)"
o uptime_s "$(cut -d. -f1 /proc/uptime)"
o nproc "$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)"
o load "$(cut -d' ' -f1-3 /proc/loadavg)"
awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/ { sub(":", "", $1); print "mem." $1 "\t" $2 }' /proc/meminfo
df -P -k -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | awk 'NR > 1 { print "disk\t" $6 " " $2 " " $3 " " $4 }'
df -P -i -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs -x vfat 2>/dev/null | awk 'NR > 1 && $2 > 0 { print "inode\t" $6 " " $2 " " $3 }'
if has systemctl && [ -d /run/systemd/system ]; then
  o systemd 1
  systemctl --failed --no-legend --plain 2>/dev/null | awk 'NF { print "failed\t" $1 }'
  for u in auditd firewalld chronyd chrony systemd-timesyncd ntpd ntp fail2ban unattended-upgrades dnf-automatic.timer dnf-automatic-install.timer apt-daily-upgrade.timer; do
    o "unit.$u" "$(systemctl is-active "$u" 2>/dev/null | head -1)"
  done
  o ntp "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
else
  o systemd 0
fi
OOM=$( (S journalctl -k --since -7d -q || dmesg 2>/dev/null) | grep -ciE 'out of memory|oom-kill|killed process')
o oom "${OOM:-}"

# ---- reinício pendente
if [ -f /var/run/reboot-required ]; then o reboot 1
elif has needs-restarting; then needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ] && o reboot 1 || o reboot 0
else o reboot 0; fi
o kernel_latest "$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's|/boot/vmlinuz-||' | sort -V | tail -1)"

# ---- SSH (configuração efetiva com sshd -T; sem sudo, o ficheiro)
SSHD=$(S sshd -T)
if [ -n "$SSHD" ]; then
  o ssh.source sshd-T
  printf '%s\n' "$SSHD" | awk '$1 ~ /^(permitrootlogin|passwordauthentication|x11forwarding|maxauthtries|permitemptypasswords|kbdinteractiveauthentication|challengeresponseauthentication|allowtcpforwarding|clientaliveinterval|logingracetime|protocol|ciphers|macs)$/ { print "ssh." $1 "\t" $2 }'
elif [ -r /etc/ssh/sshd_config ]; then
  o ssh.source ficheiro
  cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | awk 'tolower($1) ~ /^(permitrootlogin|passwordauthentication|x11forwarding|maxauthtries|permitemptypasswords|kbdinteractiveauthentication|challengeresponseauthentication|allowtcpforwarding)$/ { k = tolower($1); if (!(k in seen)) { seen[k] = 1; print "ssh." k "\t" tolower($2) } }'
else
  o ssh.source nenhum
fi

# ---- firewall
if has ufw; then o fw.ufw "$(S ufw status | head -1)"; fi
if has firewall-cmd; then o fw.firewalld "$(systemctl is-active firewalld 2>/dev/null)"; fi
if has nft; then o fw.nft_input "$(S nft list ruleset | grep -c 'hook input')"; fi
if has iptables; then
  IPT=$(S iptables -S INPUT)
  [ -n "$IPT" ] && o fw.iptables "$(printf '%s\n' "$IPT" | awk '/^-P INPUT/ { p = $3 } /^-A INPUT/ { n++ } END { print p " " n + 0 }')"
fi

# ---- controlo de acesso obrigatório
if has getenforce; then o mac.selinux "$(getenforce 2>/dev/null)"; fi
if [ -r /sys/module/apparmor/parameters/enabled ]; then o mac.apparmor "$(cat /sys/module/apparmor/parameters/enabled)"; fi

# ---- contas e permissões
awk -F: '$3 == 0 { print "uid0\t" $1 }' /etc/passwd
awk -F: '($7 !~ /(nologin|false|sync|shutdown|halt)$/) && ($3 >= 1000 || $3 == 0) { n++ } END { print "shell_users\t" n + 0 }' /etc/passwd
for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/ssh/sshd_config /etc/crontab /etc/sudoers; do
  [ -e "$f" ] && o perm "$(stat -c '%n %a %U %G' "$f" 2>/dev/null)"
done

# ---- kernel (sysctl)
for k in kernel.randomize_va_space net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects \
         net.ipv4.conf.all.accept_source_route net.ipv4.tcp_syncookies fs.suid_dumpable kernel.kptr_restrict kernel.dmesg_restrict \
         net.ipv4.conf.all.rp_filter fs.protected_symlinks fs.protected_hardlinks; do
  o "sysctl.$k" "$(sysctl -n "$k" 2>/dev/null)"
done

# ---- portas a escutar
if has ss; then ss -Htuln 2>/dev/null | awk '{ print "listen\t" $1 " " $5 }' | sort -u; fi

# ---- atualizações automáticas
if has apt-config; then o auto.apt "$(apt-config dump 2>/dev/null | awk -F'"' '/^APT::Periodic::Unattended-Upgrade / { print $2 }')"; fi

# ---- atualizações pendentes
if has apt-get; then
  o pkg apt
  S apt-get update -qq >/dev/null && o pkg.refreshed 1 || o pkg.refreshed 0
  o pkg.lists_age_s "$(( $(date +%s) - $(stat -c %Y /var/lib/apt/lists 2>/dev/null || date +%s) ))"
  apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | awk '/^Inst / { sub(/^Inst /, ""); print "aptinst\t" $0 }'
elif has dnf || has yum; then
  P=dnf; has dnf || P=yum
  o pkg "$P"
  S "$P" -q makecache >/dev/null && o pkg.refreshed 1 || o pkg.refreshed 0
  "$P" -q -C --security updateinfo list --available 2>/dev/null | awk 'NF >= 3 { print "updsec\t" $3 }'
  "$P" -q -C check-update 2>/dev/null | awk 'NF == 3 && $1 ~ /\./ { print "upd\t" $1 " " $2 " std" }'
elif has zypper; then
  o pkg zypper
  zypper -q --non-interactive lu 2>/dev/null | awk -F'|' 'NR > 2 && NF > 4 { gsub(/ /, "", $3); gsub(/ /, "", $5); print "upd\t" $3 " " $5 " std" }'
else
  o pkg desconhecido
fi

# ---- auditorias externas (se existirem)
if has lynis; then
  o lynis.present 1
  if [ "${VF_LYNIS:-0}" = 1 ]; then
    S lynis audit system --quick --no-colors --quiet >/dev/null
  fi
  S cat /var/log/lynis-report.dat | awk -F= '/^hardening_index=/ { print "lynis.index\t" $2 } /^report_datetime_end=/ { print "lynis.at\t" $2 }'
else
  o lynis.present 0
fi
has oscap && o oscap.present 1 || o oscap.present 0

o sudo.rules "$(sudo -n -l 2>/dev/null | grep -c NOPASSWD)"
o end 1
