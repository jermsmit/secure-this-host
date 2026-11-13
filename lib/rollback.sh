# shellcheck shell=bash
# rollback.sh - the safety net. Before SSH or the firewall change, a systemd
# timer is armed that restores the backup set. Confirming from a NEW login
# (sudo sth confirm CODE) cancels it; that login is the proof you are not
# locked out.
#
# Part of secure-this-host. Copyright (c) 2026 jermsmit. MIT License.

CONFIRM_CODE=""

rb_files() {   # paths of the run-time files (tmpfs, gone after reboot)
  RB_DIR=$(p "$RUN_DIR")
  RB_PENDING="$RB_DIR/pending"            # backup set waiting for confirmation
  RB_CODE="$RB_DIR/confirm-code"
  RB_CONN="$RB_DIR/installer-connection"
  RB_CONFIRMED="$RB_DIR/confirmed"
  RB_ROLLED="$RB_DIR/rolled-back"
  RB_LOCK="$RB_DIR/lock"
}

rollback_pending() { rb_files; [[ -s $RB_PENDING ]]; }

arm_rollback() {
  rb_files
  local minutes=$ROLLBACK_WINDOW
  step "Arming automatic rollback ($minutes minutes)"
  if [[ $DRY_RUN == 1 ]]; then
    run systemd-run --unit="$ROLLBACK_UNIT" --on-active="${minutes}m" "$INSTALL_BIN" rollback --auto
    return 0
  fi
  mkdir -p -m 0700 "$RB_DIR"
  rm -f "$RB_CONFIRMED" "$RB_ROLLED"
  CONFIRM_CODE=$(random_code)
  [[ ${#CONFIRM_CODE} == 6 ]] || die "Could not generate a confirmation code."
  ( umask 077; printf '%s\n' "$CONFIRM_CODE" >"$RB_CODE"; printf '%s\n' "${CONN_RAW:-}" >"$RB_CONN" )
  printf '%s\n' "$BACKUP_DIR" >"$RB_PENDING"
  # A leftover unit from an earlier run would make systemd-run fail.
  systemctl stop "$ROLLBACK_UNIT.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "$ROLLBACK_UNIT.service" "$ROLLBACK_UNIT.timer" >/dev/null 2>&1 || true
  run systemd-run --quiet --unit="$ROLLBACK_UNIT" \
    --description="secure-this-host automatic rollback" \
    --on-active="${minutes}m" --timer-property=AccuracySec=1s \
    "$INSTALL_BIN" rollback --auto >/dev/null \
    || die "Could not arm the rollback timer (systemd-run failed). Nothing was changed."
  ok "Rollback timer armed: changes are undone in $minutes minutes unless confirmed"
}

cancel_rollback() {
  rb_files
  [[ $DRY_RUN == 1 ]] && return 0
  systemctl stop "$ROLLBACK_UNIT.timer" >/dev/null 2>&1 || true
  rm -f "$RB_PENDING" "$RB_CODE" "$RB_CONN"
}

# cmd_confirm CODE [--force]
cmd_confirm() {
  require_root
  rb_files
  local code=${1:-} force=${2:-}
  rollback_pending || die "Nothing is waiting for confirmation."
  [[ -n $code ]] || die "Usage: sudo sth confirm CODE   (the code is shown in the installer's window)"
  [[ ${code^^} == "$(cat "$RB_CODE")" ]] || die "That code doesn't match. Check the installer's window."
  detect_ssh_connection
  local installer; installer=$(cat "$RB_CONN" 2>/dev/null || true)
  if [[ $force != --force ]]; then
    if [[ -n $installer && $CONN_RAW == "$installer" ]]; then
      die "Confirm from a NEW login, not the installer's session. A new login proves SSH still works."
    fi
    if [[ -n $installer && $CONN_TYPE == console ]]; then
      warn "No SSH session detected for this login. Confirming only proves SSH works if"
      warn "you logged in over SSH or Tailscale SSH just now."
    fi
  fi
  systemctl stop "$ROLLBACK_UNIT.timer" >/dev/null 2>&1 || true
  : >"$RB_CONFIRMED"
  rm -f "$RB_PENDING" "$RB_CODE" "$RB_CONN"
  _log CONFIRM "confirmed from ${CONN_RAW:-console}"
  ok "Confirmed. The rollback timer is cancelled and the changes are kept."
}

CONFIRM_SHOWN=0

# show_confirm_instructions - how to prove the new setup works.
show_confirm_instructions() {
  (( CONFIRM_SHOWN )) && return 0
  CONFIRM_SHOWN=1
  local target=${TS_IP4:-$(hostname)} user=$ADMIN_USER
  step "Prove you can still log in"
  printf '\n  Keep this window open. In a NEW terminal, log in over Tailscale:\n\n'
  printf '      %sssh %s@%s%s\n\n' "$C_BOLD" "$user" "$target" "$C_RESET"
  if [[ ${LAN_SSH:-no} != no && -n ${LAN_ADDR:-} ]]; then
    printf '  (or from your LAN: ssh %s@%s)\n\n' "$user" "$LAN_ADDR"
  fi
  printf '  Then run:\n\n      %ssudo sth confirm %s%s\n\n' "$C_BOLD" "$CONFIRM_CODE" "$C_RESET"
  printf '  If you can not log in, do nothing: in %s minutes every change is undone.\n' "$ROLLBACK_WINDOW"
}

# wait_for_confirmation - wait for `sth confirm` from a new login.
wait_for_confirmation() {
  rb_files
  if [[ ${CONFIRM_MODE:-new-session} == none ]]; then
    cancel_rollback
    warn "CONFIRM_MODE=none: rollback timer cancelled without a test login."
    return 0
  fi
  [[ $DRY_RUN == 1 ]] && return 0
  show_confirm_instructions
  local deadline=$(( $(date +%s) + ROLLBACK_WINDOW * 60 + 60 ))
  trap 'printf "\n"; warn "Stopped waiting. The rollback timer is still running: confirm with sudo sth confirm $CONFIRM_CODE"; exit 130' INT
  while (( $(date +%s) < deadline )); do
    if [[ -e $RB_CONFIRMED ]]; then printf '\n'; ok "Confirmed from a new login"; trap - INT; return 0; fi
    if [[ -e $RB_ROLLED ]]; then printf '\n'; trap - INT; die "No confirmation arrived in time: the changes were rolled back."; fi
    sleep 2
  done
  trap - INT
  die "Timed out waiting. Check 'systemctl status $ROLLBACK_UNIT.timer' and $LOG_FILE."
}

# do_rollback BACKUP_DIR - restore files and bring services back in line.
do_rollback() {
  local set=$1 was_active svc
  rb_files
  mkdir -p -m 0700 "$RB_DIR"
  exec 9>"$RB_LOCK"
  flock -w 30 9 || die "Another secure-this-host process holds the lock."
  [[ -d $(p "$set") ]] || die "Backup set not found: $set"
  _log ROLLBACK "restoring $set"
  restore_backup "$set"

  was_active=$(backup_get_meta "$set" ufw_was_active)
  if have ufw && [[ -n $was_active ]]; then
    if [[ $was_active == yes ]]; then ufw reload >/dev/null 2>&1 || true
    else ufw --force disable >/dev/null 2>&1 || true
    fi
  fi
  if have tailscale; then
    if [[ $(backup_get_meta "$set" ts_ssh_enabled_by_sth) == yes ]]; then
      tailscale set --ssh=false >/dev/null 2>&1 || true
      state_set ts_ssh_enabled_by_sth no
    fi
    case $(backup_get_meta "$set" ts_netfilter_prev) in
      on|unknown) tailscale set --netfilter-mode=on >/dev/null 2>&1 || true ;;
      off) tailscale set --netfilter-mode=off >/dev/null 2>&1 || true ;;
    esac
  fi
  for svc in $(backup_get_meta "$set" disabled_services); do
    systemctl enable --now "$svc.service" >/dev/null 2>&1 || true
  done
  [[ -d $(p /run/sshd) ]] || mkdir -p -m 0755 "$(p /run/sshd)"
  if sshd -t >/dev/null 2>&1; then
    systemctl try-reload-or-restart ssh.service >/dev/null 2>&1 || true
  else
    _log ERROR "sshd -t failed after rollback; ssh not reloaded"
  fi
  sysctl -q --system >/dev/null 2>&1 || true
  systemctl try-restart fail2ban.service >/dev/null 2>&1 || true
  if have augenrules; then augenrules --load >/dev/null 2>&1 || true; fi

  rm -f "$RB_PENDING" "$RB_CODE" "$RB_CONN"
  : >"$RB_ROLLED"
  _log ROLLBACK "done: $set"
  if have wall && [[ ${ROLLBACK_AUTO:-0} == 1 ]]; then
    printf 'secure-this-host: no confirmation arrived, so the hardening changes were rolled back.\nBackup set: %s\n' "$set" | wall 2>/dev/null || true
  fi
}

cmd_rollback() {
  require_root
  rb_files
  local set="" auto=0
  while (( $# )); do
    case $1 in
      --auto) auto=1 ;;
      --backup) set=${2:-}; shift ;;
      *) die "Unknown rollback option: $1" ;;
    esac
    shift
  done
  if (( auto )); then
    # Fired by the timer: only act on a run that is still unconfirmed.
    rollback_pending || exit 0
    set=$(cat "$RB_PENDING")
    ROLLBACK_AUTO=1 do_rollback "$set"
    exit 0
  fi
  [[ -n $set ]] || set=$(latest_backup)
  [[ -n $set ]] || die "No backup sets found in $BACKUP_BASE."
  step "Rollback"
  info "This restores every file from backup set $set"
  info "and reloads SSH, ufw, Tailscale settings and services to match."
  confirm "Roll back now?" || die "Cancelled."
  cancel_rollback
  do_rollback "$set"
  ok "Rolled back to $set"
}
