# shellcheck shell=bash
# verify.sh - read-only checks of the system's EFFECTIVE state.
# Exit status 0 only when no check fails. Warnings don't fail the run.
#
# Part of secure-this-host. Copyright (c) 2026 jermsmit. MIT License.

V_PASS=0 V_FAIL=0 V_WARN=0
V_JSON=()
V_FORMAT=text

_vrec() {   # _vrec STATUS NAME DETAIL
  local status=$1 name=$2 detail=${3:-}
  case $status in PASS) V_PASS=$((V_PASS + 1)) ;; FAIL) V_FAIL=$((V_FAIL + 1)) ;; WARN) V_WARN=$((V_WARN + 1)) ;; esac
  if [[ $V_FORMAT == json ]]; then
    V_JSON+=("$(printf '{"status":"%s","check":"%s","detail":"%s"}' "$status" "$(json_esc "$name")" "$(json_esc "$detail")")")
    return 0
  fi
  local color=$C_GREEN
  [[ $status == FAIL ]] && color=$C_RED
  [[ $status == WARN ]] && color=$C_YELLOW
  printf '  %s%-4s%s  %s' "$color" "$status" "$C_RESET" "$name"
  [[ -n $detail ]] && printf '  %s(%s)%s' "$C_DIM" "$detail" "$C_RESET"
  printf '\n'
}
json_esc() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "${s//$'\t'/ }"; }

# vcheck NAME DETAIL CMD... - PASS if CMD succeeds, else FAIL.
vcheck() { local n=$1 d=$2; shift 2; if "$@" >/dev/null 2>&1; then _vrec PASS "$n" "$d"; else _vrec FAIL "$n" "$d"; fi; }

ssh_is() { [[ $(ssh_effective "$1") == "$2" ]]; }

v_ssh() {
  if ! have sshd; then _vrec FAIL "OpenSSH server installed"; return 0; fi
  vcheck "SSH configuration is valid" "sshd -t" sshd_test
  vcheck "Root login disabled" "PermitRootLogin no" ssh_is permitrootlogin no
  vcheck "Password login disabled" "PasswordAuthentication no" ssh_is passwordauthentication no
  vcheck "Keyboard-interactive login disabled" "KbdInteractiveAuthentication no" ssh_is kbdinteractiveauthentication no
  vcheck "Public-key login only" "AuthenticationMethods publickey" ssh_is authenticationmethods publickey
  local allow; allow=$(ssh_effective allowusers)
  if [[ -z $allow ]]; then
    _vrec FAIL "SSH limited to allowed accounts and networks" "no AllowUsers"
  elif [[ -n ${SSH_ALLOW_USERS:-} ]]; then
    local u src missing=""
    for u in $SSH_ALLOW_USERS; do
      while IFS= read -r src; do
        [[ " $allow " == *" $u@$src "* ]] || missing+=" $u@$src"
      done < <(ssh_allow_sources)
    done
    if [[ -z $missing ]]; then _vrec PASS "SSH limited to allowed accounts and networks" "AllowUsers"
    else _vrec FAIL "SSH limited to allowed accounts and networks" "missing:$missing"
    fi
  else
    _vrec PASS "SSH limited by AllowUsers" "$allow"
  fi
}

v_keys() {
  local u home dir file mode
  for u in ${SSH_ALLOW_USERS:-${ADMIN_USER:-}}; do
    user_exists "$u" || continue
    home=$(user_home "$u"); dir="$(p "$home")/.ssh"; file="$dir/authorized_keys"
    if [[ ! -f $file ]]; then
      [[ $u == "${ADMIN_USER:-}" ]] && _vrec FAIL "$u has an SSH key" "no authorized_keys"
      continue
    fi
    mode=$(stat -c %a "$file")
    if [[ $(stat -c %a "$dir") == 700 && $mode =~ ^[46]00$ ]]; then
      _vrec PASS "$u key file permissions" ".ssh 700, authorized_keys $mode"
    else
      _vrec FAIL "$u key file permissions" ".ssh $(stat -c %a "$dir"), authorized_keys $mode"
    fi
    if (( $(count_keys "$file") > 0 )); then _vrec PASS "$u has an SSH key"
    else _vrec FAIL "$u has an SSH key" "no valid keys"
    fi
  done
}

v_firewall() {
  if ! have ufw; then _vrec FAIL "Firewall (ufw) installed"; return 0; fi
  local status; status=$(ufw status verbose 2>/dev/null || true)
  if grep -q '^Status: active' <<<"$status"; then _vrec PASS "Firewall active"; else _vrec FAIL "Firewall active"; fi
  if grep -q 'Default: deny (incoming)' <<<"$status"; then _vrec PASS "Incoming traffic denied by default"
  else _vrec FAIL "Incoming traffic denied by default"
  fi
  if fw_added_rules | grep -q "^allow in on tailscale0 to any port 22 proto tcp"; then
    _vrec PASS "SSH allowed over Tailscale"
  else
    _vrec FAIL "SSH allowed over Tailscale" "no ufw rule for tailscale0 port 22"
  fi
  local risky; risky=$(fw_risky_rules)
  if [[ -z $risky ]]; then _vrec PASS "SSH not open to the public"
  else _vrec FAIL "SSH not open to the public" "$(tr '\n' ';' <<<"$risky")"
  fi
  if have iptables && iptables -S INPUT 2>/dev/null | grep -q -- '-j ts-input'; then
    _vrec FAIL "Tailscale traffic goes through ufw" "ts-input accepts tailscale0 first; run: sudo tailscale set --netfilter-mode=nodivert"
  elif have tailscale; then
    _vrec PASS "Tailscale traffic goes through ufw"
  fi
}

v_tailscale() {
  if ! have tailscale; then _vrec FAIL "Tailscale installed"; return 0; fi
  if tailscale status --json 2>/dev/null | grep -Eq '"BackendState":[[:space:]]*"Running"'; then
    _vrec PASS "Tailscale connected" "$(tailscale ip -4 2>/dev/null | head -n 1)"
  else
    _vrec FAIL "Tailscale connected"
  fi
  if [[ ${SSH_METHOD:-} == tailscale ]]; then
    if tailscale debug prefs 2>/dev/null | grep -Eq '"RunSSH":[[:space:]]*true'; then _vrec PASS "Tailscale SSH on"
    else _vrec FAIL "Tailscale SSH on"
    fi
  fi
}

v_updates() {
  [[ ${AUTO_UPDATES:-yes} == no ]] && { _vrec WARN "Automatic security updates" "turned off by choice"; return 0; }
  local uu
  uu=$(apt-config shell X APT::Periodic::Unattended-Upgrade 2>/dev/null | sed -n "s/^X='\(.*\)'$/\1/p")
  if pkg_installed unattended-upgrades && [[ $uu == 1 ]]; then _vrec PASS "Automatic security updates"
  else _vrec FAIL "Automatic security updates" "unattended-upgrades=${uu:-unset}"
  fi
  if [[ -e $(p /var/run/reboot-required) ]]; then _vrec WARN "No reboot pending" "a reboot is needed to finish updates"; fi
}

sysctl_is() { [[ $(sysctl -n "$1" 2>/dev/null) == "$2" ]]; }

v_harden() {
  [[ ${EXTRA_HARDENING:-no} == yes ]] || return 0
  local k v bad=""
  while read -r k v; do sysctl_is "$k" "$v" || bad+=" $k"; done <<'EOF'
net.ipv4.tcp_syncookies 1
net.ipv4.conf.all.accept_redirects 0
net.ipv4.conf.all.accept_source_route 0
kernel.kptr_restrict 1
kernel.dmesg_restrict 1
fs.suid_dumpable 0
EOF
  if [[ -z $bad ]]; then _vrec PASS "Kernel hardening settings"; else _vrec FAIL "Kernel hardening settings" "differs:$bad"; fi
  if apparmor_enabled; then _vrec PASS "AppArmor enabled"; else _vrec WARN "AppArmor enabled" "not enabled"; fi
  if systemctl is-active --quiet auditd.service 2>/dev/null; then _vrec PASS "Audit logging running"
  else _vrec FAIL "Audit logging running"
  fi
  if [[ ${FAIL2BAN:-no} == yes ]]; then
    if systemctl is-active --quiet fail2ban.service 2>/dev/null; then _vrec PASS "fail2ban running"
    else _vrec FAIL "fail2ban running"
    fi
  fi
}

# Every listening port should be covered by a rule or be local-only.
v_listeners() {
  have ss || return 0
  local allowed=" 22 " port addr proto extra=""
  if [[ ${PUBLIC_PORTS:-none} != none ]]; then
    for port in $PUBLIC_PORTS; do allowed+="${port%/*} "; done
  fi
  while read -r proto addr; do
    port=${addr##*:}
    case $addr in 127.*|\[::1\]*|::1*|*%lo:*) continue ;; esac
    case $addr in 100.*|\[fd7a:115c:a1e0:*) continue ;; esac   # tailnet-only listeners
    [[ $allowed == *" $port "* ]] && continue
    # DHCP clients and Tailscale's WireGuard port are expected and harmless.
    [[ $proto == udp && " 68 546 41641 " == *" $port "* ]] && continue
    extra+=" $port/$proto"
  done < <(ss -H -tuln 2>/dev/null | awk '{print $1, $5}' | sort -u)
  if [[ -z $extra ]]; then _vrec PASS "No unexpected listening ports"
  else _vrec WARN "Listening ports not opened in the firewall" "${extra# } (blocked by ufw, but check you need them)"
  fi
}

v_lynis() {
  if ! have lynis; then _vrec WARN "Lynis audit" "not installed: sudo apt install lynis"; return 0; fi
  local idx
  idx=$(lynis audit system --quick --no-colors 2>/dev/null | sed -n 's/.*Hardening index : \([0-9]*\).*/\1/p' | head -n 1)
  _vrec PASS "Lynis hardening index" "${idx:-unknown}/100"
}

cmd_verify() {
  local lynis=0 a
  for a in "$@"; do
    case $a in
      --json) V_FORMAT=json ;;
      --lynis) lynis=1 ;;
      *) die "Unknown verify option: $a" ;;
    esac
  done
  require_root
  local answers; answers=$(p "$ANSWERS_FILE")
  if [[ -f $answers ]]; then load_config "$answers"; fi
  [[ $V_FORMAT == text ]] && step "secure-this-host verify"
  v_ssh; v_keys; v_firewall; v_tailscale; v_updates; v_harden; v_listeners
  (( lynis )) && v_lynis
  if [[ $V_FORMAT == json ]]; then
    local IFS=,
    printf '{"version":"%s","pass":%d,"fail":%d,"warn":%d,"checks":[%s]}\n' "$STH_VERSION" "$V_PASS" "$V_FAIL" "$V_WARN" "${V_JSON[*]}"
  else
    printf '\n  %d passed, %d failed, %d warnings\n' "$V_PASS" "$V_FAIL" "$V_WARN"
  fi
  (( V_FAIL == 0 ))
}
