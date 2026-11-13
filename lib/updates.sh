# shellcheck shell=bash disable=SC2034,SC2154
# (Variables are shared between the lib files through secure-this-host.sh,
# so checked one file at a time ShellCheck sees them as unset or unused.)
# updates.sh - automatic security updates with unattended-upgrades.
#
# Ubuntu's 50unattended-upgrades already limits automatic upgrades to the
# security pocket. Our 52-... file is read after Ubuntu's 20auto-upgrades and
# 50unattended-upgrades, so its values win.
#
# Part of secure-this-host. Copyright (c) 2026 jermsmit. MIT License.

UPDATES_CONF="/etc/apt/apt.conf.d/52secure-this-host"

updates_questions() {
  step "Security updates"
  ask_yn AUTO_UPDATES "Install security updates automatically every day? (recommended)" yes
  if [[ $AUTO_UPDATES == yes ]]; then
    note "Some updates (kernel, core libraries) only take effect after a reboot."
    ask_yn AUTO_REBOOT "Reboot automatically when an update needs it?" no
    if [[ $AUTO_REBOOT == yes ]]; then
      ask AUTO_REBOOT_TIME "Reboot time (24-hour HH:MM, server time)" "03:30" valid_time
    fi
  else
    AUTO_REBOOT=no
  fi
  return 0
}

updates_render() {
  cat <<EOF
// Managed by secure-this-host - $STH_URL
// Daily package list refresh and security upgrades.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  if [[ $AUTO_REBOOT == yes ]]; then
    printf 'Unattended-Upgrade::Automatic-Reboot "true";\n'
    printf 'Unattended-Upgrade::Automatic-Reboot-Time "%s";\n' "$AUTO_REBOOT_TIME"
  else
    printf 'Unattended-Upgrade::Automatic-Reboot "false";\n'
  fi
}

updates_apply() {
  step "Security updates"
  if [[ $AUTO_UPDATES != yes ]]; then
    remove_owned "$UPDATES_CONF"
    warn "Automatic security updates not configured (you chose no)."
    return 0
  fi
  apt_install unattended-upgrades
  updates_render | write_file "$UPDATES_CONF" 644
  run systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
  if [[ $AUTO_REBOOT == yes ]]; then
    ok "Daily security updates on; reboots at $AUTO_REBOOT_TIME when needed"
  else
    ok "Daily security updates on; no automatic reboots"
  fi
}
