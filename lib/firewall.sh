# shellcheck shell=bash
# firewall.sh - ufw: deny incoming by default, SSH only over Tailscale (and
# the opt-in LAN source), plus the public ports you list.
#
# Every rule we add carries a comment starting with "sth:" so it can be found
# and removed again. Rules you added yourself are left alone, except rules
# that open SSH to everyone, which we offer to remove.
#
# Part of secure-this-host. Copyright (c) 2026 jermsmit. MIT License.

firewall_questions() {
  step "Network access"
  if [[ $SERVER_TYPE == onprem ]]; then
    local lan_desc="The whole local network"
    [[ -n ${LAN_CIDR:-} ]] && lan_desc+=" ($LAN_CIDR)"
    note "Tailscale is the main way in. Allowing your LAN as well gives you a way in if"
    note "Tailscale is down, but trusts every device on that network to reach SSH."
    ask_choice LAN_SSH "Allow SSH from the local network too?" no \
      "no|Tailscale only (most secure)" \
      "subnet|$lan_desc" \
      "host|One admin computer (a single IP address)"
    case $LAN_SSH in
      subnet) ask LAN_SSH_SOURCE "Local network (CIDR)" "${LAN_CIDR:-}" valid_lan_source ;;
      host)
        local def=""
        [[ ${CONN_TYPE:-} == lan ]] && def=$CONN_CLIENT_IP
        ask LAN_SSH_SOURCE "Admin computer's IP address" "$def" valid_lan_source ;;
    esac
  else
    if [[ -z ${LAN_SSH:-} ]]; then LAN_SSH=no; fi
    if [[ $LAN_SSH != no ]]; then
      ask LAN_SSH_SOURCE "Private network allowed to reach SSH (CIDR)" "" valid_lan_source
      warn "Cloud server with SSH allowed from private network $LAN_SSH_SOURCE (from config)."
    fi
  fi
  if [[ $LAN_SSH == no ]]; then LAN_SSH_SOURCE=""; fi

  note "Public ports are reachable by anyone on the internet. List only services you"
  note "run on purpose, e.g. 80,443 for a web server. SSH (22) can't be listed here."
  ask PUBLIC_PORTS "Ports to open to the internet, or 'none'" none valid_port_list
  PUBLIC_PORTS=$(normalise_ports "$PUBLIC_PORTS")
  [[ -z $PUBLIC_PORTS ]] && PUBLIC_PORTS=none

  local risky; risky=$(fw_risky_rules)
  if [[ -n $risky ]]; then
    warn "These existing ufw rules open SSH to everyone:"
    local r
    while IFS= read -r r; do printf '      ufw %s\n' "$r" >&2; done <<<"$risky"
    ask_yn REMOVE_OPEN_SSH_RULES "Remove them? (recommended)" yes
    [[ $REMOVE_OPEN_SSH_RULES == no ]] && warn "Kept. 'sth verify' will report SSH as open to the public."
  fi
  return 0
}

# Rule specs as ufw prints them in `ufw show added`, without "ufw " and without the comment.
fw_desired_rules() {
  printf '%s\n' "allow in on tailscale0 to any port 22 proto tcp"
  if [[ ${LAN_SSH:-no} != no && -n ${LAN_SSH_SOURCE:-} ]]; then
    printf '%s\n' "allow from $LAN_SSH_SOURCE to any port 22 proto tcp"
  fi
  local port
  if [[ ${PUBLIC_PORTS:-none} != none ]]; then
    for port in $PUBLIC_PORTS; do printf '%s\n' "allow $port"; done
  fi
}

fw_comment_for() {
  case $1 in
    *"on tailscale0"*) printf 'sth: ssh over tailscale' ;;
    *"port 22"*) printf 'sth: ssh from lan' ;;
    *) printf 'sth: public' ;;
  esac
}

# fw_added_rules - all user rules, one spec per line, comments kept.
fw_added_rules() { ufw show added 2>/dev/null | sed -n 's/^ufw //p'; }

strip_comment() { sed -E "s/ comment '[^']*'\$//"; }

fw_our_rules() { fw_added_rules | grep -F "comment 'sth:" | strip_comment || true; }

# fw_risky_rules - existing rules (not ours) that expose SSH on every interface.
fw_risky_rules() {
  have ufw || return 0
  local spec
  while IFS= read -r spec; do
    [[ -n $spec ]] || continue
    if [[ $spec =~ ^(allow|limit)(\ in)?\ (22|22/tcp|ssh|ssh/tcp|OpenSSH)$ ]] \
      || [[ $spec =~ ^(allow|limit)(\ in)?(\ from\ any)?\ to\ any\ port\ (22|ssh)(\ proto\ tcp)?$ ]] \
      || { [[ $spec =~ ^(allow|limit)\ in\ on\ ([^ ]+)\ to\ any\ port\ (22|ssh)(\ proto\ tcp)?$ ]] && [[ ${BASH_REMATCH[2]} != tailscale0 ]]; }; then
      printf '%s\n' "$spec"
    fi
  done < <(fw_added_rules | grep -vF "comment 'sth:" | strip_comment)
}

ufw_spec() {   # ufw_spec ACTION "SPEC" [COMMENT] - run ufw with a rule spec
  local action=$1 spec=$2 comment=${3:-} words
  read -ra words <<<"$spec"
  if [[ $action == add ]]; then
    run ufw "${words[@]}" comment "$comment" >/dev/null
  else
    run ufw --force delete "${words[@]}" >/dev/null
  fi
}

firewall_apply() {
  step "Firewall (ufw)"
  apt_install ufw
  # Snapshot ufw so a rollback restores the exact previous rules.
  backup_track_tree /etc/ufw
  backup_track /etc/default/ufw
  local was_active=no
  if ufw status 2>/dev/null | grep -q '^Status: active'; then was_active=yes; fi
  backup_meta ufw_was_active "$was_active"
  [[ $was_active == no ]] && state_set ufw_enabled_by_sth yes

  run ufw default deny incoming >/dev/null
  run ufw default allow outgoing >/dev/null
  ok "Default policy: deny incoming, allow outgoing"

  # Replace our rules only when the wanted set changed (keeps re-runs quiet).
  local want have_now spec
  want=$(fw_desired_rules | sort)
  have_now=$(fw_our_rules | sort)
  if [[ $want != "$have_now" ]]; then
    while IFS= read -r spec; do
      if [[ -n $spec ]]; then ufw_spec delete "$spec"; fi
    done <<<"$have_now"
    while IFS= read -r spec; do
      if [[ -n $spec ]]; then ufw_spec add "$spec" "$(fw_comment_for "$spec")"; fi
    done <<<"$want"
  fi
  while IFS= read -r spec; do ok "Rule: $spec"; done <<<"$want"

  if [[ ${REMOVE_OPEN_SSH_RULES:-no} == yes ]]; then
    while IFS= read -r spec; do
      [[ -n $spec ]] || continue
      ufw_spec delete "$spec"
      ok "Removed: ufw $spec"
    done < <(fw_risky_rules)
  fi

  run ufw logging low >/dev/null
  if [[ $was_active == no ]]; then
    run ufw --force enable >/dev/null
    ok "ufw enabled (existing connections stay open)"
  else
    ok "ufw was already active; rules updated live"
  fi

  # Tailscale's default netfilter mode accepts everything arriving on
  # tailscale0 before ufw sees it. nodivert keeps Tailscale's chains unused,
  # so the rules above also apply to other devices on your tailnet.
  ts_set_nodivert
}
