# shellcheck shell=bash
# tailscale.sh - install Tailscale from its signed apt repository, join the
# tailnet with a tag, print the matching access policy, and (optionally)
# turn on Tailscale SSH.
#
# Part of secure-this-host. Copyright (c) 2026 jermsmit. MIT License.

TS_REPO="https://pkgs.tailscale.com/stable/ubuntu"
TS_KEYRING="/usr/share/keyrings/tailscale-archive-keyring.gpg"
TS_LIST="/etc/apt/sources.list.d/tailscale.list"
TS_AUTH_MODE=""
TS_AUTHKEY_TMP=""

tailscale_questions() {
  step "Tailscale"
  ask TS_TAG "Tailscale tag for this server" "tag:server" valid_ts_tag
  if [[ ${TS_RUNNING:-no} == yes ]]; then
    ok "Already joined to a tailnet (${TS_IP4:-}); the current login is kept."
    return 0
  fi
  if [[ -n ${TS_AUTHKEY_FILE:-} ]]; then
    [[ -r $TS_AUTHKEY_FILE ]] || die "Cannot read TS_AUTHKEY_FILE: $TS_AUTHKEY_FILE"
    TS_AUTH_MODE=keyfile
    note "Joining with the auth key in $TS_AUTHKEY_FILE"
    return 0
  fi
  [[ $ASSUME_YES == 1 ]] && die "Unattended runs need TS_AUTHKEY_FILE (a file containing a Tailscale auth key)."
  ask_choice TS_AUTH_MODE "How should this server join your tailnet?" link \
    "link|Show a login link to open in your browser (recommended)" \
    "key|Paste an auth key from the Tailscale admin console"
  if [[ $TS_AUTH_MODE == key ]]; then
    local key=""
    printf '  Auth key (input hidden): '
    IFS= read -rs key || true
    printf '\n'
    [[ $key =~ ^tskey-[A-Za-z0-9-]+$ ]] || die "That doesn't look like a Tailscale auth key (tskey-...)."
    # Keep the key out of the process list and logs: hand it over in a file.
    mkdir -p -m 0700 "$(p "$RUN_DIR")"
    TS_AUTHKEY_TMP=$(mktemp "$(p "$RUN_DIR")/authkey.XXXXXX")
    chmod 600 "$TS_AUTHKEY_TMP"
    printf '%s' "$key" >"$TS_AUTHKEY_TMP"
    key=""
  fi
}

# ts_acl_snippet TAG METHOD "USERS" [check|accept] - the policy to paste into
# the Tailscale admin console (Access controls).
ts_acl_snippet() {
  local tag=$1 method=$2 users=$3 action=${4:-check} u list="" sep=""
  for u in $users; do list+="${list:+, }\"$u\""; done
  if [[ $method == tailscale ]]; then sep=","; fi
  cat <<EOF
{
  // Who may apply the tag to a device.
  "tagOwners": {
    "$tag": ["autogroup:admin"]
  },
  "grants": [
    // Tailnet admins may reach SSH (port 22) on servers tagged $tag.
    { "src": ["autogroup:admin"], "dst": ["$tag"], "ip": ["tcp:22"] }
  ]$sep
EOF
  if [[ $method == tailscale ]]; then
    cat <<EOF
  "ssh": [
    // Tailscale SSH: "check" makes admins sign in again every 12 hours.
    { "action": "$action", "src": ["autogroup:admin"], "dst": ["$tag"], "users": [$list] }
  ]
EOF
  fi
  printf '}\n'
}

ts_print_policy() {
  step "Tailscale access policy"
  note "Paste this into the Tailscale admin console > Access controls (merge it with"
  note "your policy). For zero trust, also remove the default allow-all grant"
  note '{"src": ["*"], "dst": ["*"], "ip": ["*"]}, or every device can reach this one.'
  printf '\n'
  ts_acl_snippet "$TS_TAG" "$SSH_METHOD" "$SSH_ALLOW_USERS" | sed 's/^/    /'
  printf '\n'
}

# ts_repo_codename - the release name to use for Tailscale's repository.
ts_repo_codename() {
  local codename=${OS_CODENAME:-$(os_field VERSION_CODENAME)}
  if [[ $DRY_RUN == 0 ]] && ! curl -fsS --max-time 20 -o /dev/null "$TS_REPO/dists/$codename/InRelease"; then
    warn "Tailscale has no repository for '$codename' yet; using the 24.04 (noble) one."
    codename=noble
  fi
  printf '%s' "$codename"
}

ts_write_repo() {   # ts_write_repo CODENAME - signing key + sources list
  local codename=$1 line
  line="deb [signed-by=$TS_KEYRING] $TS_REPO $codename main"
  if [[ -f $(p "$TS_LIST") && $(cat "$(p "$TS_LIST")") == "$line" && -s $(p "$TS_KEYRING") ]]; then
    return 0
  fi
  if [[ $DRY_RUN == 1 ]]; then
    run curl -fsSL "$TS_REPO/$codename.noarmor.gpg" -o "$TS_KEYRING"
    run write "$TS_LIST"
    return 0
  fi
  # Download to a temporary file first so a failed download can't leave a broken keyring.
  local tmp; tmp=$(mktemp)
  curl -fsSL --max-time 30 "$TS_REPO/$codename.noarmor.gpg" -o "$tmp" || { rm -f "$tmp"; die "Could not download the Tailscale signing key."; }
  [[ -s $tmp ]] || { rm -f "$tmp"; die "The downloaded Tailscale signing key is empty."; }
  install -D -m 0644 "$tmp" "$(p "$TS_KEYRING")"
  rm -f "$tmp"
  mkdir -p "$(p "${TS_LIST%/*}")"
  printf '%s\n' "$line" >"$(p "$TS_LIST")"
  chmod 644 "$(p "$TS_LIST")"
  ok "Tailscale repository: $TS_REPO ($codename)"
  APT_UPDATED=0      # new repository: refresh the package lists
}

ts_install() {
  if have tailscale; then
    # Installed from our repository: keep it pointed at this release (matters
    # after an Ubuntu upgrade, which disables or leaves the old name in place).
    if [[ -f $(p "$TS_LIST") ]]; then
      apt_install curl ca-certificates
      ts_write_repo "$(ts_repo_codename)"
    fi
    ok "Tailscale is installed"
    return 0
  fi
  apt_install curl ca-certificates
  ts_write_repo "$(ts_repo_codename)"
  apt_install tailscale
  run systemctl enable --now tailscaled.service
}

ts_wait_running() {
  local i
  [[ $DRY_RUN == 1 ]] && { TS_IP4=${TS_IP4:-100.64.0.1}; return 0; }
  for ((i = 0; i < 30; i++)); do
    if tailscale status --json 2>/dev/null | grep -Eq '"BackendState":[[:space:]]*"Running"'; then
      TS_IP4=$(tailscale ip -4 2>/dev/null | head -n 1) || TS_IP4=""
      TS_RUNNING=yes
      return 0
    fi
    sleep 2
  done
  return 1
}

tailscale_apply() {
  step "Joining Tailscale"
  ts_install
  if [[ ${TS_RUNNING:-no} == yes ]]; then
    ok "Tailscale already connected (${TS_IP4:-})"
    ts_print_policy
    if ! ts_self_has_tag "$TS_TAG"; then
      warn "This server is not tagged $TS_TAG, so the policy above won't apply to it yet."
      warn "Tag it with: sudo tailscale up --advertise-tags=$TS_TAG"
      warn "(tailscale prints the full command if you use other flags)."
    fi
    return 0
  fi
  ts_print_policy
  if [[ $ASSUME_YES == 0 && $DRY_RUN == 0 ]]; then
    note "The tag must exist in your policy before this server can use it."
    printf '  Press Enter once the policy is saved... '
    local _x; _x=""; _read_line _x
  fi
  local args=(up "--advertise-tags=$TS_TAG")
  case $TS_AUTH_MODE in
    keyfile) args+=("--auth-key=file:$TS_AUTHKEY_FILE") ;;
    key) args+=("--auth-key=file:$TS_AUTHKEY_TMP") ;;
    link) note "A login link appears next. Open it on any device and sign in." ;;
  esac
  local rc=0
  run tailscale "${args[@]}" || rc=$?
  if [[ -n $TS_AUTHKEY_TMP ]]; then rm -f "$TS_AUTHKEY_TMP"; TS_AUTHKEY_TMP=""; fi
  (( rc == 0 )) || die "tailscale up failed (exit $rc). If it mentions tags, check that $TS_TAG is in your policy's tagOwners."
  ts_wait_running || die "Tailscale did not reach the Running state."
  ok "Connected to your tailnet as $TS_IP4"
  note "Tagged devices normally have key expiry turned off. Check it in the admin console (Machines)."
}

# ts_self_has_tag TAG - does this node carry TAG? (unknown counts as no)
ts_self_has_tag() {
  [[ $DRY_RUN == 1 ]] && return 0
  have python3 || return 1
  tailscale status --json 2>/dev/null | python3 -c '
import json, sys
try:
    tags = (json.load(sys.stdin).get("Self") or {}).get("Tags") or []
except ValueError:
    sys.exit(1)
sys.exit(0 if sys.argv[1] in tags else 1)' "$1"
}

# Tailscale's netfilter mode as a word: on, nodivert, off, or unknown.
ts_netfilter_mode() {
  local n
  n=$(tailscale debug prefs 2>/dev/null | grep -Eo '"NetfilterMode":[[:space:]]*[0-9]+' | grep -Eo '[0-9]+$' || true)
  case $n in 0) printf off ;; 1) printf nodivert ;; 2) printf on ;; *) printf unknown ;; esac
}

ts_set_nodivert() {
  have tailscale || [[ $DRY_RUN == 1 ]] || return 0
  local mode=unknown
  [[ $DRY_RUN == 0 ]] && mode=$(ts_netfilter_mode)
  if [[ $mode == nodivert ]]; then ok "Tailscale traffic already goes through ufw (netfilter nodivert)"; return 0; fi
  backup_meta ts_netfilter_prev "$mode"
  state_set ts_netfilter_prev "$mode"
  run tailscale set --netfilter-mode=nodivert
  ok "Tailscale traffic now goes through ufw (netfilter mode nodivert)"
}

# Turned on last: Tailscale SSH takes over port 22 on the Tailscale address,
# and any OpenSSH session already using that address stops responding.
ts_ssh_apply() {
  [[ $SSH_METHOD == tailscale ]] || return 0
  step "Tailscale SSH"
  if [[ $DRY_RUN == 0 ]] && tailscale debug prefs 2>/dev/null | grep -Eq '"RunSSH":[[:space:]]*true'; then
    ok "Tailscale SSH is already on"
    return 0
  fi
  backup_meta ts_ssh_enabled_by_sth yes
  state_set ts_ssh_enabled_by_sth yes
  run tailscale set --ssh
  ok "Tailscale SSH is on"
}
