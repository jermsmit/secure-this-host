# shellcheck shell=bash disable=SC2034,SC2154
# (Variables are shared between the lib files through secure-this-host.sh,
# so checked one file at a time ShellCheck sees them as unset or unused.)
# ssh.sh - OpenSSH hardening through a drop-in file.
#
# Ubuntu's sshd_config includes /etc/ssh/sshd_config.d/*.conf on its first
# line, and sshd keeps the FIRST value it reads for each setting. Our file is
# named 00-... so it is read before files like 50-cloud-init.conf, which can
# turn password login back on.
#
# Part of secure-this-host. Copyright (c) 2026 jermsmit. MIT License.

SSH_DROPIN="/etc/ssh/sshd_config.d/00-secure-this-host.conf"

ssh_questions() {
  step "SSH login method"
  note "OpenSSH keys: you log in with your SSH key, and only over Tailscale${LAN_NOTE:-}."
  note "Tailscale SSH: no SSH keys; Tailscale checks who you are using your tailnet login"
  note "and access rules. OpenSSH stays installed and hardened as a fallback."
  ask_choice SSH_METHOD "Which login method should admins use?" openssh \
    "openssh|SSH keys over Tailscale (recommended)" \
    "tailscale|Tailscale SSH (identity-based, no keys)"
}

# ssh_allow_sources - networks allowed in AllowUsers (one per line).
ssh_allow_sources() {
  printf '%s\n' 127.0.0.1 ::1 "$TS_V4_RANGE" "$TS_V6_RANGE"
  if [[ ${LAN_SSH:-no} != no && -n ${LAN_SSH_SOURCE:-} ]]; then printf '%s\n' "$LAN_SSH_SOURCE"; fi
}

ssh_render() {
  local u src allow=""
  for u in $SSH_ALLOW_USERS; do
    while IFS= read -r src; do allow+=" $u@$src"; done < <(ssh_allow_sources)
  done
  cat <<EOF
# Managed by secure-this-host (sth) - $STH_URL
# Change it by re-running: sudo sth    Remove it with: sudo sth uninstall
# sshd keeps the first value it reads; this file is read before all others.

# Authentication: public keys only, never root, never passwords.
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AuthenticationMethods publickey

# Limit login attempts; drop dead connections after about 10 minutes.
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Less attack surface. TCP forwarding stays on: a bastion forwards (ssh -J).
X11Forwarding no

# Who may log in, and from which networks: localhost, the tailnet${LAN_SSH_SOURCE:+ and the LAN}.
AllowUsers${allow}
EOF
}

sshd_test() {
  # sshd -t fails if the privilege separation directory is missing, which is
  # normal on Ubuntu 24.04+ while ssh.socket hasn't started sshd yet.
  [[ -d $(p /run/sshd) ]] || mkdir -p -m 0755 "$(p /run/sshd)"
  sshd -t 2>&1
}

ssh_apply() {
  step "Hardening OpenSSH"
  ssh_render | write_file "$SSH_DROPIN" 644
  if [[ $DRY_RUN == 1 ]]; then run sshd -t; run systemctl try-reload-or-restart ssh.service; return 0; fi
  local out
  if ! out=$(sshd_test); then
    error "sshd rejected the new configuration:"
    printf '    %s\n' "$out" >&2
    die "SSH configuration test failed"
  fi
  ok "sshd -t passed"
  ssh_check_effective || die "Another SSH setting overrides the hardening (see above)."
  run systemctl try-reload-or-restart ssh.service
  ok "SSH reloaded; existing sessions stay open"
}

# ssh_effective KEY - the value sshd will actually use (lower-case key).
# sshd -T prints list settings such as AllowUsers one entry per line, so all
# matching lines are joined with spaces.
ssh_effective() {
  sshd -T 2>/dev/null | awk -v k="$1" '
    tolower($1) == k { $1 = ""; sub(/^ /, ""); out = out (out == "" ? "" : " ") $0 }
    END { print out }'
}

ssh_check_effective() {
  local key want got bad=0
  while read -r key want; do
    got=$(ssh_effective "$key")
    if [[ $got != "$want" ]]; then
      error "sshd uses '$key ${got:-?}', expected '$want'. Check other files in /etc/ssh/sshd_config.d/."
      bad=1
    fi
  done <<'EOF'
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
authenticationmethods publickey
EOF
  (( bad == 0 ))
}
