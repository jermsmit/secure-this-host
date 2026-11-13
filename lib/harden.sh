# shellcheck shell=bash disable=SC2034,SC2154
# (Variables are shared between the lib files through secure-this-host.sh,
# so checked one file at a time ShellCheck sees them as unset or unused.)
# harden.sh - extra hardening: kernel network settings, AppArmor check, audit
# logging, fail2ban, unneeded services and Docker's firewall bypass.
#
# Part of secure-this-host. Copyright (c) 2026 jermsmit. MIT License.

SYSCTL_CONF="/etc/sysctl.d/60-secure-this-host.conf"
AUDIT_RULES="/etc/audit/rules.d/60-secure-this-host.rules"
F2B_JAIL="/etc/fail2ban/jail.d/60-secure-this-host.local"
UFW_AFTER="/etc/ufw/after.rules"
DOCKER_BEGIN="# BEGIN secure-this-host docker"
DOCKER_END="# END secure-this-host docker"
# Services a server rarely needs. Each is only offered if it is enabled.
UNNEEDED_SERVICES="avahi-daemon cups cups-browsed rpcbind bluetooth"

harden_questions() {
  step "Extra hardening"
  note "Kernel network settings (ignore redirects and source routing, SYN cookies,"
  note "hide kernel pointers) and audit logging of changes to accounts, sudo and SSH."
  ask_yn EXTRA_HARDENING "Apply extra hardening? (recommended)" yes

  # fail2ban only helps when SSH is reachable from more than the tailnet.
  if [[ ${LAN_SSH:-no} != no ]]; then
    [[ ${FAIL2BAN:-} == auto ]] && FAIL2BAN=""
    ask_yn FAIL2BAN "Install fail2ban to block addresses with repeated failed SSH logins?" yes
  else
    if [[ -z ${FAIL2BAN:-} || ${FAIL2BAN:-} == auto ]]; then FAIL2BAN=no; fi
  fi

  local found; found=$(enabled_unneeded_services)
  if [[ -n $found ]]; then
    note "These services are enabled but rarely needed on a server: $found"
    note "(rpcbind is needed for NFS; cups for printing.)"
    ask_yn DISABLE_SERVICES "Disable them?" yes
  else
    if [[ -z ${DISABLE_SERVICES:-} ]]; then DISABLE_SERVICES=no; fi
  fi

  if [[ ${DOCKER_PRESENT:-no} == yes ]]; then
    note "Docker publishes container ports around ufw. Docker firewall handling makes"
    note "published ports obey this firewall: only the public ports you listed, plus the"
    note "tailnet, can reach containers. Containers that rely on other open ports stop"
    note "being reachable from outside."
    ask_yn DOCKER_FIREWALL "Make published Docker ports obey the firewall?" no
  else
    if [[ -z ${DOCKER_FIREWALL:-} ]]; then DOCKER_FIREWALL=no; fi
  fi
  return 0
}

enabled_unneeded_services() {
  local s out=()
  for s in $UNNEEDED_SERVICES; do
    systemctl is-enabled --quiet "$s.service" 2>/dev/null && out+=("$s")
  done
  printf '%s' "${out[*]}"
}

apparmor_enabled() {
  [[ $(cat "$(p /sys/module/apparmor/parameters/enabled)" 2>/dev/null) == Y ]]
}

sysctl_render() {
  cat <<EOF
# Managed by secure-this-host - $STH_URL
# Network: ignore ICMP redirects and source-routed packets, use SYN cookies.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
# Reverse-path filtering in loose mode (2). Strict mode (1) breaks Tailscale
# and Docker routing.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
# Kernel: hide kernel addresses and logs from non-root users, keep address
# randomisation on, no core dumps from setuid programs.
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
}

# Watch rules only for paths that exist: a watch on a missing path makes
# augenrules fail to load the whole rule set.
audit_render() {
  local path key arches=(b64)
  [[ $(uname -m) == x86_64 ]] && arches+=(b32)
  printf '## Managed by secure-this-host - %s\n' "$STH_URL"
  printf '## Changes to accounts, sudo, SSH, login records, time and kernel modules.\n'
  while read -r path key; do
    [[ -e $(p "$path") ]] && printf -- '-w %s -p wa -k %s\n' "$path" "$key"
  done <<'EOF'
/etc/passwd identity
/etc/group identity
/etc/shadow identity
/etc/gshadow identity
/etc/sudoers sudoers
/etc/sudoers.d sudoers
/etc/ssh/sshd_config sshd
/etc/ssh/sshd_config.d sshd
/var/log/lastlog logins
/var/log/wtmp logins
/var/log/btmp logins
/etc/localtime time-change
EOF
  local a
  for a in "${arches[@]}"; do
    printf -- '-a always,exit -F arch=%s -S adjtimex,settimeofday,clock_settime -k time-change\n' "$a"
    printf -- '-a always,exit -F arch=%s -S init_module,finit_module,delete_module -k modules\n' "$a"
  done
}

f2b_render() {
  local ignore="127.0.0.1/8 ::1 $TS_V4_RANGE $TS_V6_RANGE"
  cat <<EOF
# Managed by secure-this-host - $STH_URL
# Ban an address for 1 hour after 5 failed SSH logins in 10 minutes.
# Tailnet addresses are never banned, so you can't lock yourself out.
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
banaction = ufw
ignoreip = $ignore

[sshd]
enabled = true
backend = systemd
EOF
}

docker_render() {
  local port proto
  printf '%s\n' "$DOCKER_BEGIN"
  cat <<'EOF'
# Published container ports obey the firewall: replies, traffic from containers
# and the tailnet pass; new outside connections reach only the listed ports.
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -i docker0 -j RETURN
-A DOCKER-USER -i br-+ -j RETURN
-A DOCKER-USER -i tailscale0 -j RETURN
EOF
  if [[ ${PUBLIC_PORTS:-none} != none ]]; then
    for port in $PUBLIC_PORTS; do
      proto=${port#*/} port=${port%/*}
      printf -- '-A DOCKER-USER -p %s -m conntrack --ctorigdstport %s --ctdir ORIGINAL -j RETURN\n' "$proto" "$port"
    done
  fi
  cat <<'EOF'
-A DOCKER-USER -m conntrack --ctstate NEW -j DROP
-A DOCKER-USER -j RETURN
COMMIT
EOF
  printf '%s\n' "$DOCKER_END"
}

# strip_docker_block FILE - print FILE without our block.
strip_docker_block() {
  awk -v b="$DOCKER_BEGIN" -v e="$DOCKER_END" '$0 == b {skip = 1; next} $0 == e {skip = 0; next} !skip' "$1"
}

docker_apply() {
  local real; real=$(p "$UFW_AFTER")
  [[ -f $real || $DRY_RUN == 1 ]] || die "$UFW_AFTER not found (is ufw installed?)"
  if [[ $DRY_RUN == 1 ]]; then run write-block "$UFW_AFTER"; run ufw reload; return 0; fi
  local new; new=$(strip_docker_block "$real"; docker_render)
  if [[ $(cat "$real") == "$new" ]]; then ok "Docker firewall rules already in place"; return 0; fi
  backup_track "$UFW_AFTER"
  printf '%s\n' "$new" >"$real"
  state_set docker_block yes
  run ufw reload >/dev/null
  ok "Published Docker ports now obey the firewall"
}

docker_remove() {
  local real; real=$(p "$UFW_AFTER")
  [[ -f $real ]] && grep -qxF "$DOCKER_BEGIN" "$real" || return 0
  if [[ $DRY_RUN == 1 ]]; then run remove-block "$UFW_AFTER"; return 0; fi
  backup_track "$UFW_AFTER"
  local new; new=$(strip_docker_block "$real")
  printf '%s\n' "$new" >"$real"
  state_set docker_block no
  run ufw reload >/dev/null
  ok "Removed the Docker firewall block from $UFW_AFTER"
}

harden_apply() {
  if [[ $EXTRA_HARDENING == yes ]]; then
    step "Kernel settings"
    sysctl_render | write_file "$SYSCTL_CONF" 644
    run sysctl -q -e -p "$SYSCTL_CONF" >/dev/null || warn "Some kernel settings could not be applied now; they apply at next boot."
    ok "Kernel network and memory settings applied"

    if apparmor_enabled; then ok "AppArmor is enabled"
    else warn "AppArmor is not enabled. Ubuntu enables it by default; check your kernel boot options."
    fi

    step "Audit logging"
    apt_install auditd
    audit_render | write_file "$AUDIT_RULES" 640
    run systemctl enable --now auditd.service >/dev/null 2>&1 || true
    if run augenrules --load >/dev/null 2>&1; then
      ok "Audit rules loaded (search them with: sudo ausearch -k sshd)"
    else
      warn "Audit rules could not be loaded now (rules may be locked until reboot)."
    fi
  else
    remove_owned "$SYSCTL_CONF"
    remove_owned "$AUDIT_RULES"
  fi

  if [[ $FAIL2BAN == yes ]]; then
    step "fail2ban"
    apt_install fail2ban python3-systemd
    f2b_render | write_file "$F2B_JAIL" 644
    run systemctl enable fail2ban.service >/dev/null 2>&1 || true
    run systemctl restart fail2ban.service || warn "fail2ban did not start; check: sudo journalctl -u fail2ban"
    ok "fail2ban is watching SSH logins"
  else
    remove_owned "$F2B_JAIL"
  fi

  if [[ ${DISABLE_SERVICES:-no} == yes ]]; then
    local found s; found=$(enabled_unneeded_services)
    if [[ -n $found ]]; then
      step "Unneeded services"
      local prev; prev=$(state_get disabled_services)
      for s in $found; do
        run systemctl disable --now "$s.service" >/dev/null 2>&1 || warn "Could not disable $s"
        ok "Disabled $s"
        [[ " $prev " == *" $s "* ]] || prev="${prev:+$prev }$s"
      done
      backup_meta disabled_services "$found"
      state_set disabled_services "$prev"
    fi
  fi

  if [[ ${DOCKER_FIREWALL:-no} == yes ]]; then
    step "Docker firewall"
    docker_apply
  else
    docker_remove
  fi
  return 0
}
