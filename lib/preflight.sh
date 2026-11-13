# shellcheck shell=bash disable=SC2034,SC2154
# (Variables are shared between the lib files through secure-this-host.sh,
# so checked one file at a time ShellCheck sees them as unset or unused.)
# preflight.sh - look at the server before changing anything.
# Sets OS_*, CONN_*, LAN_*, UFW_*, TS_*, DOCKER_PRESENT and FOREIGN_FIREWALL.
#
# Part of secure-this-host. Copyright (c) 2026 jermsmit. MIT License.

SUPPORTED_VERSIONS="24.04 26.04"

check_os() {
  OS_ID=$(os_field ID)
  OS_VERSION=$(os_field VERSION_ID)
  OS_CODENAME=$(os_field VERSION_CODENAME)
  [[ $OS_ID == ubuntu ]] || die "Unsupported OS '${OS_ID:-unknown}'. secure-this-host supports Ubuntu $SUPPORTED_VERSIONS LTS."
  case " $SUPPORTED_VERSIONS " in
    *" $OS_VERSION "*) ok "Ubuntu $OS_VERSION LTS ($OS_CODENAME)" ;;
    *) die "Unsupported Ubuntu version '$OS_VERSION'. Supported: $SUPPORTED_VERSIONS LTS." ;;
  esac
  have systemctl || die "systemd is required."
  have apt-get || die "apt is required."
}

# detect_ssh_connection - how is the person running this connected?
# sudo usually strips SSH_CONNECTION, so walk up the process tree and read
# it from the login shell's environment.
detect_ssh_connection() {
  local conn=${SSH_CONNECTION:-} pid=$$ ppid i
  if [[ -z $conn && -z ${STH_TEST:-} ]]; then
    for ((i = 0; i < 12; i++)); do
      ppid=$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null) || break
      [[ -n $ppid && $ppid != 0 && $ppid != 1 ]] || break
      conn=$(tr '\0' '\n' <"/proc/$ppid/environ" 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p' | head -n 1) || true
      [[ -n $conn ]] && break
      pid=$ppid
    done
  fi
  CONN_RAW=$conn
  if [[ -z $conn ]]; then
    CONN_TYPE=console CONN_CLIENT_IP="" CONN_SERVER_IP=""
    return 0
  fi
  read -r CONN_CLIENT_IP _ CONN_SERVER_IP _ <<<"$conn"
  if is_tailscale_ipv4 "$CONN_SERVER_IP" || [[ $CONN_SERVER_IP == fd7a:115c:a1e0:* ]]; then
    CONN_TYPE=tailscale
  elif is_private_ipv4 "$CONN_SERVER_IP"; then
    CONN_TYPE=lan
  elif [[ $CONN_SERVER_IP == 127.* || $CONN_SERVER_IP == ::1 ]]; then
    CONN_TYPE=local
  else
    CONN_TYPE=public
  fi
}

# detect_lan - first private IPv4 network on a physical-looking interface.
detect_lan() {
  LAN_IFACE="" LAN_ADDR="" LAN_CIDR=""
  have ip || return 0
  local _n ifc _fam addr
  while read -r _n ifc _fam addr _; do
    case $ifc in tailscale*|docker*|br-*|veth*|virbr*|lxc*|lxd*|cni*|flannel*|wg*|lo) continue ;; esac
    is_private_ipv4 "${addr%/*}" || continue
    LAN_IFACE=$ifc LAN_ADDR=${addr%/*} LAN_CIDR=$(cidr_network "$addr")
    return 0
  done < <(ip -4 -o addr show scope global 2>/dev/null)
}

detect_firewall() {
  UFW_INSTALLED=no UFW_ACTIVE=no FOREIGN_FIREWALL=""
  if have ufw; then
    UFW_INSTALLED=yes
    if ufw status 2>/dev/null | grep -q '^Status: active'; then UFW_ACTIVE=yes; fi
  fi
  # Another firewall manager would fight with ufw: stop rather than merge.
  if systemctl is-enabled --quiet nftables 2>/dev/null && [[ -s $(p /etc/nftables.conf) ]] \
     && grep -Eq '^[[:space:]]*(chain|table)' "$(p /etc/nftables.conf)"; then
    FOREIGN_FIREWALL="nftables (/etc/nftables.conf)"
  elif systemctl is-enabled --quiet netfilter-persistent 2>/dev/null; then
    FOREIGN_FIREWALL="iptables-persistent (netfilter-persistent)"
  elif systemctl is-enabled --quiet firewalld 2>/dev/null; then
    FOREIGN_FIREWALL="firewalld"
  fi
}

detect_docker() {
  DOCKER_PRESENT=no
  if have docker || have dockerd || systemctl is-enabled --quiet docker 2>/dev/null \
     || systemctl is-enabled --quiet containerd 2>/dev/null; then
    DOCKER_PRESENT=yes
  fi
}

detect_tailscale() {
  TS_INSTALLED=no TS_RUNNING=no TS_IP4=""
  have tailscale || return 0
  TS_INSTALLED=yes
  if tailscale status --json 2>/dev/null | grep -Eq '"BackendState":[[:space:]]*"Running"'; then
    TS_RUNNING=yes
    TS_IP4=$(tailscale ip -4 2>/dev/null | head -n 1) || TS_IP4=""
  fi
}

check_sshd_include() {
  local cfg; cfg=$(p /etc/ssh/sshd_config)
  [[ -f $cfg ]] || die "OpenSSH server is not installed (/etc/ssh/sshd_config missing). Install it with: sudo apt install openssh-server"
  # Ubuntu's sshd_config includes the drop-in directory on its first lines.
  # sshd uses the first value it reads, so the Include must come before any
  # other setting for our drop-in to win.
  local first
  first=$(grep -Ev '^[[:space:]]*(#|$)' "$cfg" | head -n 1)
  if [[ ! $first =~ ^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf ]]; then
    die "/etc/ssh/sshd_config must start with 'Include /etc/ssh/sshd_config.d/*.conf' (Ubuntu's default). Add it as the first setting and re-run."
  fi
}

run_preflight() {
  step "Pre-flight checks"
  check_os
  check_sshd_include
  ok "sshd reads /etc/ssh/sshd_config.d/ first"
  detect_ssh_connection
  case $CONN_TYPE in
    console) ok "Running from a local console (no SSH session detected)" ;;
    tailscale) ok "Connected over Tailscale ($CONN_CLIENT_IP -> $CONN_SERVER_IP)" ;;
    lan) ok "Connected over the local network ($CONN_CLIENT_IP -> $CONN_SERVER_IP)" ;;
    public) warn "Connected over a public address ($CONN_CLIENT_IP -> $CONN_SERVER_IP). After hardening, SSH will only work over Tailscale${LAN_SSH:+ or your LAN}." ;;
    local) ok "Connected over localhost" ;;
  esac
  detect_lan
  [[ -n $LAN_CIDR ]] && ok "Local network: $LAN_CIDR on $LAN_IFACE"
  detect_firewall
  [[ -n $FOREIGN_FIREWALL ]] && die "Another firewall manager is active: $FOREIGN_FIREWALL. secure-this-host manages the firewall with ufw and won't merge with it. Disable it first, or harden the firewall by hand."
  if [[ $UFW_ACTIVE == yes ]]; then
    ok "ufw is active; existing rules will be kept"
  else
    ok "ufw is not active yet"
  fi
  detect_docker
  [[ $DOCKER_PRESENT == yes ]] && warn "Docker detected. Ports that containers publish bypass ufw unless you enable Docker firewall handling."
  detect_tailscale
  if [[ $TS_RUNNING == yes ]]; then ok "Tailscale is connected (${TS_IP4:-no IPv4})"
  elif [[ $TS_INSTALLED == yes ]]; then info "Tailscale is installed but not connected"
  else info "Tailscale is not installed yet"
  fi
  return 0
}
