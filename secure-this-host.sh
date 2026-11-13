#!/usr/bin/env bash
# secure-this-host (sth) - interactive zero-trust hardening for Ubuntu LTS.
#
#   sudo ./secure-this-host.sh            interactive setup (installs the `sth` command)
#   sudo sth verify                       PASS/FAIL report
#   sudo sth help                         all commands and options
#
# https://github.com/jermsmit/secure-this-host
# Copyright (c) 2026 jermsmit. MIT License.

set -Eeuo pipefail
umask 022

SELF=$(readlink -f "${BASH_SOURCE[0]}")
STH_HOME=$(dirname "$SELF")
for _m in common preflight users ssh firewall tailscale updates harden rollback verify; do
  # shellcheck source=/dev/null
  source "$STH_HOME/lib/$_m.sh"
done
unset _m

# Defaults (a --config file or flags may set these first)
: "${ROLLBACK_WINDOW:=5}"
: "${CONFIRM_MODE:=new-session}"
APPLY_STARTED=0

usage() {
  cat <<EOF
secure-this-host $STH_VERSION - zero-trust hardening for Ubuntu 24.04 and 26.04 LTS
by $STH_AUTHOR - $STH_URL

Usage: sudo sth [COMMAND] [OPTIONS]

Commands:
  install            Interactive setup, review, apply with automatic rollback (default)
  verify             Read-only PASS/FAIL report of the current state
  confirm CODE       Cancel the rollback timer from a NEW login (proves you can log in)
  rollback           Restore the most recent backup set
  uninstall          Remove everything secure-this-host added
  acl                Print a Tailscale access policy snippet
  version            Show the version and author
  help               Show this help

Install options:
  --dry-run              Show every change without making any
  --config FILE          Read answers from FILE (see examples/answers.example.conf)
  --yes                  No prompts: take answers from --config, defaults for the rest
  --rollback-window MIN  Minutes before an unconfirmed run is undone (2-30, default 5)
  --verbose              Print each command as it runs

Verify options:   --json   machine-readable output     --lynis   also run a Lynis audit
Rollback options: --backup DIR   restore a specific backup set
ACL options:      --tag TAG  --users "a b"  --tailscale-ssh  --accept
EOF
}

cmd_version() { printf 'secure-this-host %s\nCopyright (c) 2026 %s - %s\nMIT License\n' "$STH_VERSION" "$STH_AUTHOR" "$STH_URL"; }

# --------------------------------------------------------------------------
# install
# --------------------------------------------------------------------------
banner() {
  printf '\n%s  secure-this-host %s%s  zero-trust hardening for Ubuntu LTS\n' "$C_BOLD" "$STH_VERSION" "$C_RESET"
  printf '  by %s - %s\n' "$STH_AUTHOR" "$STH_URL"
  [[ $DRY_RUN == 1 ]] && printf '\n  %sDRY RUN: nothing will be changed.%s\n' "$C_YELLOW" "$C_RESET"
  printf '\n  Nothing changes until you approve the summary at the end. Press Enter to\n'
  printf '  accept the [default] shown for each question.\n'
}

server_type_question() {
  step "Where is this server?"
  ask_choice SERVER_TYPE "Pick the closest match:" onprem \
    "cloud|Cloud server or VPS (backup access: the provider's web console)" \
    "onprem|Home or office server (backup access: keyboard and screen, or LAN)"
  if [[ $SERVER_TYPE == cloud ]]; then
    note "Before applying, open your provider's web or serial console in another tab."
    note "It is your way in if both SSH and Tailscale fail."
  fi
  return 0
}

review() {
  step "Review"
  local lan="no (Tailscale only)"
  [[ $LAN_SSH != no ]] && lan="$LAN_SSH_SOURCE"
  cat <<EOF
  Server type ............. $SERVER_TYPE
  Admin account ........... $ADMIN_USER$( [[ $CREATE_ADMIN == yes ]] && ! user_exists "$ADMIN_USER" && printf ' (new)' )
  SSH logins allowed for .. $SSH_ALLOW_USERS
  Login method ............ $( [[ $SSH_METHOD == tailscale ]] && printf 'Tailscale SSH (+ hardened OpenSSH fallback)' || printf 'OpenSSH keys over Tailscale' )
  Tailscale tag ........... $TS_TAG
  SSH from local network .. $lan
  Public ports ............ $PUBLIC_PORTS
  Security updates ........ $AUTO_UPDATES$( [[ $AUTO_REBOOT == yes ]] && printf ', reboot at %s when needed' "$AUTO_REBOOT_TIME" )
  Extra hardening ......... $EXTRA_HARDENING (kernel settings, audit logging)
  fail2ban ................ $FAIL2BAN
  Disable unneeded services $DISABLE_SERVICES
  Docker firewall ......... $DOCKER_FIREWALL
  Rollback window ......... $ROLLBACK_WINDOW minutes

  Files this run adds or changes (all backed up first):
    $SSH_DROPIN
    /etc/ufw/ (firewall rules)
    $UPDATES_CONF
EOF
  [[ $EXTRA_HARDENING == yes ]] && printf '    %s\n    %s\n' "$SYSCTL_CONF" "$AUDIT_RULES"
  [[ $FAIL2BAN == yes ]] && printf '    %s\n' "$F2B_JAIL"
  [[ $DOCKER_FIREWALL == yes ]] && printf '    %s (marked block)\n' "$UFW_AFTER"
  printf '\n'
  return 0
}

# Warnings that need an explicit yes before anything changes.
safety_gates() {
  local who=${SUDO_USER:-}
  if [[ $CONN_TYPE != console && -n $who && $who != root && " $SSH_ALLOW_USERS " != *" $who "* ]]; then
    warn "You are logged in as '$who', which is NOT in the allowed SSH accounts ($SSH_ALLOW_USERS)."
    warn "New SSH logins as '$who' will be refused."
    confirm "Continue anyway?" || die "Cancelled. Add $who to the allowed accounts and re-run."
  fi
  if [[ $SSH_METHOD == tailscale && $CONN_TYPE == tailscale ]]; then
    warn "You are connected with OpenSSH over Tailscale. Turning on Tailscale SSH takes over"
    warn "that address, so THIS session will stop responding at the end of the run."
    warn "Confirm from a new Tailscale SSH login: ssh $ADMIN_USER@${TS_IP4:-<tailscale-ip>}"
    confirm "Continue?" || die "Cancelled. Run it from the console or a LAN/public login instead."
  fi
  if [[ $CONN_TYPE == public ]]; then
    warn "This session stays open, but new SSH logins from the internet will be refused."
  fi
  if [[ $CONN_TYPE == lan && $LAN_SSH == no ]]; then
    warn "This session stays open, but new SSH logins from the LAN will be refused."
  fi
  return 0
}

self_install() {
  [[ $DRY_RUN == 1 ]] && { run install "$STH_HOME" "$INSTALL_LIB"; return 0; }
  local dest; dest=$(p "$INSTALL_LIB")
  if [[ $STH_HOME != "$dest" ]]; then
    mkdir -p "$dest/lib"
    install -m 0755 "$STH_HOME/secure-this-host.sh" "$dest/secure-this-host.sh"
    install -m 0644 "$STH_HOME"/lib/*.sh "$dest/lib/"
    [[ -f $STH_HOME/LICENSE ]] && install -m 0644 "$STH_HOME/LICENSE" "$dest/LICENSE"
  fi
  mkdir -p "$(p "${INSTALL_BIN%/*}")"
  ln -sfn "$INSTALL_LIB/secure-this-host.sh" "$(p "$INSTALL_BIN")"
  ok "Installed the sth command ($INSTALL_BIN)"
}

# If anything fails after changes started, undo them right away instead of
# waiting for the timer.
on_exit() {
  local rc=$?
  if (( rc != 0 && APPLY_STARTED == 1 )) && [[ $DRY_RUN == 0 ]]; then
    APPLY_STARTED=0
    error "The run failed (exit $rc). Rolling back now..."
    cancel_rollback
    do_rollback "$BACKUP_DIR" && warn "Rolled back to the state before this run ($BACKUP_DIR)."
  fi
  if [[ -n ${TS_AUTHKEY_TMP:-} ]]; then rm -f "$TS_AUTHKEY_TMP"; fi
}

cmd_install() {
  require_root
  trap on_exit EXIT
  valid_minutes "$ROLLBACK_WINDOW" || die "--rollback-window must be 2 to 30 minutes."
  ROLLBACK_WINDOW=$((10#$ROLLBACK_WINDOW))
  case $CONFIRM_MODE in new-session|none) ;; *) die "CONFIRM_MODE must be new-session or none." ;; esac
  if rollback_pending; then
    die "A previous run is still waiting for confirmation. Confirm it (sudo sth confirm CODE) or wait for its rollback."
  fi
  banner
  run_preflight

  server_type_question
  users_questions
  ssh_questions
  tailscale_questions
  firewall_questions
  updates_questions
  harden_questions
  review
  safety_gates
  if [[ $DRY_RUN == 0 ]]; then
    confirm "Apply these changes?" || die "Cancelled. Nothing was changed."
  fi

  self_install
  begin_backup
  backup_meta started "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  backup_meta connection "${CONN_RAW:-console}"
  # Our own state is part of the backup too, so a rollback leaves no stale answers.
  backup_track "$STATE_DIR/state"; backup_track "$ANSWERS_FILE"; backup_track "$MANIFEST_FILE"
  APPLY_STARTED=1

  tailscale_apply      # first: gives the tailnet path that the new rules rely on
  users_apply
  arm_rollback         # from here on, an unconfirmed run undoes itself
  ssh_apply
  firewall_apply
  updates_apply
  harden_apply
  if [[ $DRY_RUN == 0 ]]; then
    mkdir -p -m 0700 "$(p "$STATE_DIR")"
    render_answers | write_file "$ANSWERS_FILE" 600
    state_set last_backup "$BACKUP_DIR"
    state_set version "$STH_VERSION"
  fi
  # Turning on Tailscale SSH freezes an OpenSSH session that uses the
  # Tailscale address, so show the confirmation code before that happens.
  if [[ $SSH_METHOD == tailscale && $CONN_TYPE == tailscale && $DRY_RUN == 0 && $CONFIRM_MODE != none ]]; then
    show_confirm_instructions
  fi
  ts_ssh_apply         # last: it takes over SSH on the Tailscale address
  APPLY_STARTED=0      # failures after this point are left to the timer

  if [[ $DRY_RUN == 1 ]]; then
    step "Dry run finished: nothing was changed."
    return 0
  fi
  wait_for_confirmation
  printf '\n'
  cmd_verify || warn "Some checks failed: see above."
  step "Done"
  info "Answers saved to $ANSWERS_FILE (re-run with: sudo sth --config $ANSWERS_FILE)"
  info "Check the server any time with: sudo sth verify"
}

# --------------------------------------------------------------------------
# uninstall
# --------------------------------------------------------------------------
cmd_uninstall() {
  require_root
  step "Uninstall secure-this-host"
  info "Removes the files and firewall rules secure-this-host added. Packages it"
  info "installed (ufw, Tailscale, auditd, fail2ban) and accounts stay installed."
  warn "Without the SSH drop-in, sshd falls back to its other settings, which may allow"
  warn "password logins again. Harden it another way if this server stays online."
  confirm "Uninstall now?" || die "Cancelled."
  rollback_pending && cancel_rollback

  begin_backup
  local f m; m=$(p "$MANIFEST_FILE")
  if [[ -f $m ]]; then
    while IFS= read -r f; do
      [[ -n $f ]] || continue
      # Keep sudo rules: removing one could leave a password-less admin without sudo.
      if [[ $f == /etc/sudoers.d/* ]]; then note "Kept $f (so the admin keeps sudo)"; continue; fi
      remove_owned "$f"
    done <"$m"
  fi
  if have ufw; then
    backup_track_tree /etc/ufw
    local spec
    while IFS= read -r spec; do
      if [[ -n $spec ]]; then ufw_spec delete "$spec"; ok "Removed rule: $spec"; fi
    done < <(fw_our_rules)
    docker_remove
    if [[ $(state_get ufw_enabled_by_sth) == yes ]]; then
      local off=""
      ask_yn off "secure-this-host turned ufw on. Turn the firewall off again? (not recommended)" no
      [[ $off == yes ]] && run ufw --force disable
    fi
  fi
  if have tailscale; then
    if [[ $(state_get ts_ssh_enabled_by_sth) == yes ]]; then run tailscale set --ssh=false; ok "Tailscale SSH turned off"; fi
    if [[ $(state_get ts_netfilter_prev) =~ ^(on|unknown)$ ]]; then
      run tailscale set --netfilter-mode=on
      ok "Tailscale netfilter mode back to its default (on)"
    fi
  fi
  local svc
  for svc in $(state_get disabled_services); do
    run systemctl enable --now "$svc.service" >/dev/null 2>&1 || true
    ok "Re-enabled $svc"
  done
  if sshd_test >/dev/null; then run systemctl try-reload-or-restart ssh.service; fi
  run sysctl -q --system >/dev/null 2>&1 || true
  if have augenrules; then run augenrules --load >/dev/null 2>&1 || true; fi
  if [[ $DRY_RUN == 0 ]]; then
    rm -rf "$(p "$STATE_DIR")" "$(p "$INSTALL_LIB")"
    rm -f "$(p "$INSTALL_BIN")"
  fi
  ok "Uninstalled. Backups stay in $BACKUP_BASE; the last one is $BACKUP_DIR"
}

# --------------------------------------------------------------------------
# acl
# --------------------------------------------------------------------------
cmd_acl() {
  local tag=tag:server users="" method=openssh action=check
  while (( $# )); do
    case $1 in
      --tag) tag=${2:-}; shift ;;
      --users) users=${2:-}; shift ;;
      --tailscale-ssh) method=tailscale ;;
      --accept) action=accept ;;
      *) die "Unknown acl option: $1" ;;
    esac
    shift
  done
  valid_ts_tag "$tag" || die "Tags look like tag:server"
  if [[ -z $users ]]; then
    local answers; answers=$(p "$ANSWERS_FILE")
    if [[ -r $answers ]]; then load_config "$answers"; users=${SSH_ALLOW_USERS:-}; fi
  fi
  [[ -n $users ]] || users=${SUDO_USER:-admin}
  valid_user_list "$users" || die "--users must be a list of account names"
  ts_acl_snippet "$tag" "$method" "$users" "$action"
}

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
main() {
  local cmd=install args=()
  exec {STH_OUT_FD}>&1
  if (( $# )) && [[ $1 != -* ]]; then cmd=$1; shift; fi
  while (( $# )); do
    case $1 in
      --dry-run) DRY_RUN=1 ;;
      --yes|-y) ASSUME_YES=1 ;;
      --verbose|-v) VERBOSE=1 ;;
      --config) [[ -n ${2:-} ]] || die "--config needs a file"; load_config "$2"; shift ;;
      --rollback-window) ROLLBACK_WINDOW=${2:-}; shift ;;
      -h|--help) cmd=help ;;
      --version) cmd=version ;;
      *) args+=("$1") ;;
    esac
    shift
  done
  if [[ $ASSUME_YES == 1 && $cmd == install && -z ${SERVER_TYPE:-} ]]; then
    die "--yes needs --config FILE with at least SERVER_TYPE set."
  fi
  case $cmd in
    install) (( ${#args[@]} == 0 )) || die "Unknown option: ${args[0]}"; cmd_install ;;
    verify) cmd_verify "${args[@]}" ;;
    confirm) cmd_confirm "${args[@]}" ;;
    rollback) cmd_rollback "${args[@]}" ;;
    uninstall) cmd_uninstall ;;
    acl) cmd_acl "${args[@]}" ;;
    version) cmd_version ;;
    help) usage ;;
    *) usage >&2; die "Unknown command: $cmd" ;;
  esac
}

main "$@"
