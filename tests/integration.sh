#!/usr/bin/env bash
# integration.sh - end-to-end runs of secure-this-host against fake system
# commands (tests/stubs/fake) inside a throwaway root directory.
# Run: bash tests/integration.sh        (needs bash 5, coreutils, python3)
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
export STUBS="$HERE/stubs"
PASS=0 FAIL=0 CURRENT=""
KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb3Hx1yGm2wq8n0e5Vv9Yc8m1o3pYk6m3wq0aF5m6n7 alice@laptop"
KEY2="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKq8m2Zp4nN1v7tY3xW0cB5dE6fG7hJ8kL9mN0pQ1rS2 bob@desk"

# Only these real tools are visible to the code under test, so whatever is
# installed on the machine running the tests (docker, ufw, ...) can't leak in.
SYS_BIN=$(mktemp -d)
for tool in bash sh cat cp mv rm mkdir chmod ln install readlink dirname basename mktemp date stat \
            find sort head tail cut tr sed awk grep wc touch uname hostname flock sleep env md5sum \
            diff python3 tee timeout true false cmp ls; do
  ln -s "$(command -v "$tool")" "$SYS_BIN/$tool"
done
trap 'rm -rf "$SYS_BIN"' EXIT

ok_()   { PASS=$((PASS + 1)); }
bad_()  { FAIL=$((FAIL + 1)); printf '    FAIL [%s] %s\n' "$CURRENT" "$*"; }
check() { local d=$1; shift; if "$@"; then ok_; else bad_ "$d"; fi; }
has_line() { grep -qF -- "$2" "$1" 2>/dev/null; }
no_line()  { ! grep -qF -- "$2" "$1" 2>/dev/null; }

new_env() {   # new_env NAME [ubuntu-version]
  CURRENT=$1
  printf '  - %s\n' "$1"
  T=$(mktemp -d)
  export STH_ROOT="$T/root" STUB_STATE="$T/state" STH_TEST=1 NO_COLOR=1
  export PATH="$STUB_STATE/bin:$T/bin:$SYS_BIN"
  unset SSH_CONNECTION SUDO_USER FAKE_EXTRA_LISTENER
  mkdir -p "$T/bin" "$STUB_STATE/bin"
  local c
  for c in dpkg-query apt-get apt-config curl iptables sshd systemctl systemd-run getent id useradd \
           usermod passwd chown visudo sysctl ip ss wall ufw; do
    ln -s "$STUBS/fake" "$T/bin/$c"
  done
  local r=$STH_ROOT
  mkdir -p "$r"/etc/{ssh/sshd_config.d,ufw,default,apt/apt.conf.d,sudoers.d,sysctl.d} "$r/sys/module/apparmor/parameters" \
           "$r"/run "$r"/var/log "$r/home/alice/.ssh"
  printf 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="%s"\nVERSION_CODENAME=%s\n' "${2:-24.04}" "$([[ ${2:-24.04} == 26.04 ]] && echo resolute || echo noble)" >"$r/etc/os-release"
  printf 'Include /etc/ssh/sshd_config.d/*.conf\n\nKbdInteractiveAuthentication no\nUsePAM yes\nX11Forwarding yes\n' >"$r/etc/ssh/sshd_config"
  printf 'ENABLED=no\n' >"$r/etc/ufw/ufw.conf"
  printf 'IPV6=yes\nDEFAULT_INPUT_POLICY="ACCEPT"\n' >"$r/etc/default/ufw"
  printf '*filter\n:ufw-after-input - [0:0]\n# do not delete the COMMIT line\nCOMMIT\n' >"$r/etc/ufw/after.rules"
  printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' >"$r/etc/apt/apt.conf.d/20auto-upgrades"
  echo Y >"$r/sys/module/apparmor/parameters/enabled"
  touch "$r/etc/passwd" "$r/etc/group" "$r/etc/shadow" "$r/etc/sudoers"
  echo "alice:x:1000:1000::/home/alice:/bin/bash" >"$STUB_STATE/passwd"
  echo "alice sudo" >"$STUB_STATE/groups_alice"
  printf '%s\n' "$KEY" >"$r/home/alice/.ssh/authorized_keys"
  chmod 700 "$r/home/alice/.ssh"; chmod 600 "$r/home/alice/.ssh/authorized_keys"
  : >"$STUB_STATE/pkg_openssh-server"; : >"$STUB_STATE/pkg_ufw"; : >"$STUB_STATE/pkg_unattended-upgrades"
  U="$STH_ROOT/etc/ufw/user.rules.fake"
}

sth()  { bash "$REPO/secure-this-host.sh" "$@"; }
installed_sth() { bash "$STH_ROOT/usr/local/lib/secure-this-host/secure-this-host.sh" "$@"; }
code() { cat "$STH_ROOT/run/secure-this-host/confirm-code" 2>/dev/null; }
wait_text() { local i; for ((i = 0; i < 100; i++)); do grep -qF "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
wait_for() { local i; for ((i = 0; i < 100; i++)); do [[ -e $1 ]] && return 0; sleep 0.1; done; return 1; }

# run_bg INPUT_FILE ARGS... - start the installer in the background.
run_bg() { local in=$1; shift; sth "$@" <"$in" >"$T/out.log" 2>&1 & BG=$!; }

finish_bg() {   # wait for the background installer, set RC
  local i; for ((i = 0; i < 150; i++)); do kill -0 "$BG" 2>/dev/null || break; sleep 0.1; done
  if kill -0 "$BG" 2>/dev/null; then kill "$BG"; RC=124; else wait "$BG"; RC=$?; fi
}

answers() { printf '%s\n' "$@" >"$T/in.txt"; }

echo "integration tests"

# ---------------------------------------------------------------------------
new_env "clean home server, interactive, LAN subnet + port 443"
export SSH_CONNECTION="192.168.1.20 51000 192.168.1.50 22" SUDO_USER=alice
# server type, create admin?, username, add key?, allowed users, method, tag,
# auth mode, LAN, LAN cidr, ports, auto updates, auto reboot, extra hardening,
# fail2ban, apply?, press enter after policy
answers "" "" "" "" "" "" "" "" subnet "" 443 "" "" "" "" y ""
run_bg "$T/in.txt"
if wait_for "$STH_ROOT/run/secure-this-host/confirm-code"; then
  # Confirm from the SAME session must be refused...
  SSH_CONNECTION="192.168.1.20 51000 192.168.1.50 22" installed_sth confirm "$(code)" >"$T/c1.log" 2>&1
  check "confirm from installer session refused" has_line "$T/c1.log" "NEW login"
  # ...a wrong code too...
  SSH_CONNECTION="100.90.1.2 40000 100.101.102.103 22" installed_sth confirm ZZZZZZ >"$T/c2.log" 2>&1
  check "wrong code refused" has_line "$T/c2.log" "doesn't match"
  # ...and a new login over Tailscale works.
  SSH_CONNECTION="100.90.1.2 40000 100.101.102.103 22" installed_sth confirm "$(code)" >"$T/c3.log" 2>&1
  check "confirm from new session accepted" has_line "$T/c3.log" "Confirmed"
else
  bad_ "installer never reached the confirmation step"; cat "$T/out.log"
fi
finish_bg
check "installer exit 0 (got $RC)" test "$RC" -eq 0
D="$STH_ROOT/etc/ssh/sshd_config.d/00-secure-this-host.conf"
check "drop-in written" test -f "$D"
check "drop-in: no passwords" has_line "$D" "PasswordAuthentication no"
check "drop-in: AllowUsers tailnet" has_line "$D" "alice@100.64.0.0/10"
check "drop-in: AllowUsers LAN" has_line "$D" "alice@192.168.1.0/24"
check "ufw: ssh over tailscale" has_line "$U" "allow in on tailscale0 to any port 22 proto tcp comment 'sth: ssh over tailscale'"
check "ufw: ssh from lan" has_line "$U" "allow from 192.168.1.0/24 to any port 22 proto tcp comment 'sth: ssh from lan'"
check "ufw: public 443" has_line "$U" "allow 443/tcp comment 'sth: public'"
check "ufw enabled" test -e "$STUB_STATE/ufw_active"
check "ufw default deny" has_line "$STH_ROOT/etc/default/ufw" 'DEFAULT_INPUT_POLICY="DROP"'
check "tailscale joined with tag" has_line "$STUB_STATE/calls.log" "tailscale up --advertise-tags=tag:server"
check "tailscale nodivert" grep -qx nodivert "$STUB_STATE/ts_netfilter"
check "tailscale repo uses codename" has_line "$STH_ROOT/etc/apt/sources.list.d/tailscale.list" "stable/ubuntu noble main"
check "updates config" has_line "$STH_ROOT/etc/apt/apt.conf.d/52secure-this-host" 'Unattended-Upgrade::Automatic-Reboot "false";'
check "sysctl config" has_line "$STH_ROOT/etc/sysctl.d/60-secure-this-host.conf" "net.ipv4.tcp_syncookies = 1"
check "audit rules skip missing paths" no_line "$STH_ROOT/etc/audit/rules.d/60-secure-this-host.rules" "/var/log/lastlog"
check "audit rules watch sshd" has_line "$STH_ROOT/etc/audit/rules.d/60-secure-this-host.rules" "-w /etc/ssh/sshd_config.d -p wa -k sshd"
check "fail2ban jail (LAN SSH on)" has_line "$STH_ROOT/etc/fail2ban/jail.d/60-secure-this-host.local" "banaction = ufw"
check "answers saved" has_line "$STH_ROOT/var/lib/secure-this-host/answers.conf" 'LAN_SSH_SOURCE="192.168.1.0/24"'
check "verify ran and passed" has_line "$T/out.log" "0 failed"
check "policy snippet printed" has_line "$T/out.log" '"tag:server": ["autogroup:admin"]'
check "sth command installed" test -L "$STH_ROOT/usr/local/sbin/sth"
check "rollback timer cancelled" test ! -e "$STUB_STATE/timer_sth-rollback"
ORDER=$(grep -nE '^(tailscale up|systemd-run|ufw --force enable|tailscale set --netfilter)' "$STUB_STATE/calls.log" | cut -d: -f2 | cut -c1-14 | tr '\n' '|')
check "apply order: join, arm timer, firewall, nodivert ($ORDER)" test "$ORDER" == "tailscale up -|systemd-run --|ufw --force en|tailscale set |"

# Second run with the saved answers: nothing should change.
cp -a "$STH_ROOT/etc" "$T/etc.before"
sth --config "$STH_ROOT/var/lib/secure-this-host/answers.conf" --yes --rollback-window 2 >"$T/run2.log" 2>&1 &
BG=$!
if wait_for "$STH_ROOT/run/secure-this-host/confirm-code"; then
  SSH_CONNECTION="100.90.1.2 40001 100.101.102.103 22" installed_sth confirm "$(code)" >/dev/null 2>&1
fi
finish_bg
check "second run exit 0 (got $RC)" test "$RC" -eq 0
check "second run: /etc unchanged" diff -r "$T/etc.before" "$STH_ROOT/etc"
check "second run: verify passes" sth verify
check "verify --json is valid JSON" bash -c 'bash "$0/secure-this-host.sh" verify --json | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"fail\"] == 0"' "$REPO"

# Uninstall: our files and rules go, the user's stay.
echo "allow 8080/tcp" >>"$U"
printf 'y\nn\n' | installed_sth uninstall >"$T/un.log" 2>&1
check "uninstall exit 0" test $? -eq 0
check "uninstall: drop-in removed" test ! -e "$D"
check "uninstall: sth rules removed" no_line "$U" "sth:"
check "uninstall: user rule kept" has_line "$U" "allow 8080/tcp"
check "uninstall: ufw left on" test -e "$STUB_STATE/ufw_active"
check "uninstall: netfilter back to on" grep -qx on "$STUB_STATE/ts_netfilter"
check "uninstall: state removed" test ! -d "$STH_ROOT/var/lib/secure-this-host"
check "uninstall: command removed" test ! -e "$STH_ROOT/usr/local/sbin/sth"
rm -rf "$T"

# ---------------------------------------------------------------------------
new_env "existing server: cloud-init password drop-in, open SSH rules, Docker, no confirm -> auto rollback"
export SSH_CONNECTION="203.0.113.9 50000 198.51.100.7 22" SUDO_USER=alice
printf 'PasswordAuthentication yes\n' >"$STH_ROOT/etc/ssh/sshd_config.d/50-cloud-init.conf"
printf 'allow 22/tcp\nallow OpenSSH\nallow 80/tcp\n' >"$STH_ROOT/etc/ufw/user.rules.fake"
: >"$STUB_STATE/ufw_active"; : >"$STUB_STATE/docker"; : >"$STUB_STATE/enabled_docker"; : >"$STUB_STATE/enabled_cups"
: >"$STUB_STATE/ts_running"; ln -s "$STUBS/fake" "$STUB_STATE/bin/tailscale"; : >"$STUB_STATE/pkg_tailscale"
cp -a "$STH_ROOT/etc" "$T/etc.orig"
# server type cloud, create?, user, add key?, allowed, method, tag, ports, remove risky?,
# updates, reboot?, reboot time, extra, disable services?, docker fw?, apply?
answers cloud "" "" "" "" "" "" "80,443" "" "" y 04:15 "" "" y y
run_bg "$T/in.txt" --rollback-window 2
if wait_for "$STH_ROOT/run/secure-this-host/confirm-code" && wait_text "$T/out.log" "Prove you can still log in"; then
  check "risky rules removed" no_line "$U" "allow 22/tcp"
  check "OpenSSH profile rule removed" no_line "$U" "allow OpenSSH"
  check "user's port 80 rule kept" grep -qx "allow 80/tcp" "$U"
  check "effective PasswordAuthentication no (00 file wins)" bash -c 'sshd -T | grep -qx "passwordauthentication no"'
  check "docker block in after.rules" has_line "$STH_ROOT/etc/ufw/after.rules" "--ctorigdstport 443 --ctdir ORIGINAL -j RETURN"
  check "cups disabled" test ! -e "$STUB_STATE/enabled_cups"
  check "reboot window" has_line "$STH_ROOT/etc/apt/apt.conf.d/52secure-this-host" 'Automatic-Reboot-Time "04:15"'
  check "no fail2ban (no LAN SSH)" test ! -e "$STH_ROOT/etc/fail2ban/jail.d/60-secure-this-host.local"
  check "warned about public session" has_line "$T/out.log" "new SSH logins from the internet will be refused"
  # Nobody confirms: fire the timer the way systemd would.
  TIMER_CMD=$(cat "$STUB_STATE/timer_sth-rollback")
  check "timer runs 'sth rollback --auto'" test "$TIMER_CMD" == "/usr/local/sbin/sth rollback --auto"
  installed_sth rollback --auto >"$T/rb.log" 2>&1
else
  bad_ "installer never reached the confirmation step"; cat "$T/out.log"
fi
finish_bg
check "installer reports rollback (exit $RC)" has_line "$T/out.log" "rolled back"
check "rollback: /etc back to original" diff -r -x 'audit' -x 'fail2ban' -x 'sources.list.d' "$T/etc.orig" "$STH_ROOT/etc"
check "rollback: ufw still active" test -e "$STUB_STATE/ufw_active"
check "rollback: netfilter back to on" grep -qx on "$STUB_STATE/ts_netfilter"
check "rollback: cups re-enabled" test -e "$STUB_STATE/enabled_cups"
check "rollback: no stale answers left" test ! -e "$STH_ROOT/var/lib/secure-this-host/answers.conf"
check "warned that existing node is untagged" has_line "$T/out.log" "is not tagged tag:server"
check "rollback: confirm now refused" bash -c '! bash "$0" confirm ABCDEF >/dev/null 2>&1' "$STH_ROOT/usr/local/lib/secure-this-host/secure-this-host.sh"
rm -rf "$T"

# ---------------------------------------------------------------------------
new_env "failure mid-run (sshd -t rejects) -> immediate rollback"
export SSH_CONNECTION="192.168.1.20 51000 192.168.1.50 22" SUDO_USER=alice
: >"$STUB_STATE/sshd_fail"
cp -a "$STH_ROOT/etc" "$T/etc.orig"
answers "" "" "" "" "" "" "" "" "" none "" "" n y ""
sth <"$T/in.txt" >"$T/out.log" 2>&1; RC=$?
check "exit non-zero" test "$RC" -ne 0
check "reported and rolled back" has_line "$T/out.log" "Rolled back to the state before this run"
check "drop-in removed again" test ! -e "$STH_ROOT/etc/ssh/sshd_config.d/00-secure-this-host.conf"
check "/etc restored" diff -r -x 'sources.list.d' "$T/etc.orig" "$STH_ROOT/etc"
check "ufw not left enabled" test ! -e "$STUB_STATE/ufw_active"
check "timer cancelled" test ! -e "$STUB_STATE/timer_sth-rollback"
rm -rf "$T"

# ---------------------------------------------------------------------------
new_env "dry run changes nothing (and catches an admin without a console password)"
export SSH_CONNECTION="192.168.1.20 51000 192.168.1.50 22" SUDO_USER=alice
echo L >"$STUB_STATE/pwstatus_alice"
( cd "$STH_ROOT" && find . -type f -exec md5sum {} + | sort ) >"$T/before"
# type, create?, user, set console password?, add key?, allowed, method, tag, auth, LAN | ports | updates, reboot, extra
answers "" "" "" "" "" "" "" "" "" "" 443 "" "" ""
sth --dry-run <"$T/in.txt" >"$T/out.log" 2>&1; RC=$?
( cd "$STH_ROOT" && find . -type f -exec md5sum {} + | sort ) >"$T/after"
check "dry run exit 0 (got $RC)" test "$RC" -eq 0
check "dry run: no file changed" diff "$T/before" "$T/after"
check "dry run: shows planned ufw command" has_line "$T/out.log" "[dry-run] ufw allow in on tailscale0"
check "dry run: no ufw calls that change state" no_line "$STUB_STATE/calls.log" "ufw --force enable"
check "warns: admin has no console password" has_line "$T/out.log" "can't log in at a console"
check "offers to set it (dry run shows passwd)" has_line "$T/out.log" "[dry-run] passwd alice"
rm -rf "$T"

# ---------------------------------------------------------------------------
new_env "unattended cloud run: new admin, auth key file, Tailscale SSH, 26.04" 26.04
unset SUDO_USER
printf 'tskey-auth-kSECRET123-abcdef\n' >"$T/authkey"
printf '%s\n' "$KEY2" >"$T/bob.pub"
cat >"$T/answers.conf" <<EOF
SERVER_TYPE=cloud
CREATE_ADMIN=yes
ADMIN_USER=bob
ADMIN_SUDO_NOPASSWD=yes
ADMIN_PUBKEY_FILE=$T/bob.pub
SSH_METHOD=tailscale
TS_AUTHKEY_FILE=$T/authkey
PUBLIC_PORTS="none"
CONFIRM_MODE=none
EOF
sth --config "$T/answers.conf" --yes >"$T/out.log" 2>&1; RC=$?
check "exit 0 (got $RC)" test "$RC" -eq 0
check "bob created in sudo" has_line "$STUB_STATE/calls.log" "useradd --create-home --shell /bin/bash --groups sudo bob"
check "bob key installed" has_line "$STH_ROOT/home/bob/.ssh/authorized_keys" "bob@desk"
check "sudoers drop-in mode 440" test "$(stat -c %a "$STH_ROOT/etc/sudoers.d/60-secure-this-host-bob")" == 440
check "auth key passed by file" test "$(cat "$STUB_STATE/ts_authkey_seen")" == "tskey-auth-kSECRET123-abcdef"
check "auth key never logged" bash -c '! grep -rq kSECRET123 "$0/var/log" "$0/var/lib" "$1/calls.log"' "$STH_ROOT" "$STUB_STATE"
check "auth key not in saved answers" no_line "$STH_ROOT/var/lib/secure-this-host/answers.conf" "TS_AUTHKEY_FILE"
check "resolute repo" has_line "$STH_ROOT/etc/apt/sources.list.d/tailscale.list" "stable/ubuntu resolute main"
check "Tailscale SSH on" test -e "$STUB_STATE/ts_ssh"
SSH_AT=$(grep -n '^tailscale set --ssh$' "$STUB_STATE/calls.log" | cut -d: -f1)
CHANGE_AT=$(grep -nE '^(ufw (allow|default|--force|logging)|augenrules|sysctl -q -e|tailscale set --netfilter|systemd-run)' "$STUB_STATE/calls.log" | tail -n 1 | cut -d: -f1)
check "Tailscale SSH turned on after every other change ($SSH_AT > $CHANGE_AT)" test "${SSH_AT:-0}" -gt "${CHANGE_AT:-999999}"
check "policy snippet has ssh check rule" has_line "$T/out.log" '"action": "check"'
check "CONFIRM_MODE=none cancels timer" test ! -e "$STUB_STATE/timer_sth-rollback"
printf 'deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu noble main\n' >"$STH_ROOT/etc/apt/sources.list.d/tailscale.list"
sth --config "$T/answers.conf" --yes >"$T/out2.log" 2>&1
check "re-run after release upgrade fixes repo codename" has_line "$STH_ROOT/etc/apt/sources.list.d/tailscale.list" "stable/ubuntu resolute main"
check "verify: Tailscale SSH check" bash -c 'bash "$0/secure-this-host.sh" verify | grep -q "PASS  Tailscale SSH on"' "$REPO"
printf 'y\nn\n' | installed_sth uninstall >"$T/un.log" 2>&1
check "uninstall keeps the admin's sudo rule" test -f "$STH_ROOT/etc/sudoers.d/60-secure-this-host-bob"
check "uninstall turns Tailscale SSH off" test ! -e "$STUB_STATE/ts_ssh"
rm -rf "$T"

# ---------------------------------------------------------------------------
new_env "Tailscale SSH chosen while connected over Tailscale: code shown before takeover"
export SSH_CONNECTION="100.90.1.2 40000 100.101.102.103 22" SUDO_USER=alice
: >"$STUB_STATE/ts_running"; printf 'tag:server' >"$STUB_STATE/ts_tags"
ln -s "$STUBS/fake" "$STUB_STATE/bin/tailscale"; : >"$STUB_STATE/pkg_tailscale"
printf 'SERVER_TYPE=onprem\nADMIN_USER=alice\nCREATE_ADMIN=no\nSSH_METHOD=tailscale\nLAN_SSH=no\nPUBLIC_PORTS=none\n' >"$T/a.conf"
sth --config "$T/a.conf" --yes </dev/null >"$T/out.log" 2>&1 &
BG=$!
if wait_text "$T/out.log" "Confirmed from a new login" || { wait_for "$STH_ROOT/run/secure-this-host/confirm-code" && \
   SSH_CONNECTION="100.90.1.3 40100 100.101.102.103 22" installed_sth confirm "$(code)" >/dev/null 2>&1; }; then :; fi
finish_bg
check "exit 0 (got $RC)" test "$RC" -eq 0
check "warned this session will freeze" has_line "$T/out.log" "THIS session will stop responding"
CODE_AT=$(grep -n 'sudo sth confirm' "$T/out.log" | head -n 1 | cut -d: -f1)
TSSH_AT=$(grep -n '==> Tailscale SSH' "$T/out.log" | head -n 1 | cut -d: -f1)
check "confirm code printed before Tailscale SSH turns on ($CODE_AT < $TSSH_AT)" test "${CODE_AT:-999}" -lt "${TSSH_AT:-0}"
check "tagged node: no untagged warning" no_line "$T/out.log" "is not tagged"
check "answers saved before waiting" has_line "$STH_ROOT/var/lib/secure-this-host/answers.conf" 'SSH_METHOD="tailscale"'
rm -rf "$T"

# ---------------------------------------------------------------------------
new_env "verify catches problems"
: >"$STUB_STATE/ts_running"; ln -s "$STUBS/fake" "$STUB_STATE/bin/tailscale"
printf 'PasswordAuthentication yes\n' >"$STH_ROOT/etc/ssh/sshd_config.d/00-aaa.conf"
echo "allow 22/tcp" >"$STH_ROOT/etc/ufw/user.rules.fake"; : >"$STUB_STATE/ufw_active"
export FAKE_EXTRA_LISTENER=5432
sth verify >"$T/v.log" 2>&1; RC=$?
check "verify exits non-zero" test "$RC" -ne 0
check "flags password login" has_line "$T/v.log" "FAIL  Password login disabled"
check "flags public SSH rule" has_line "$T/v.log" "FAIL  SSH not open to the public"
check "flags tailnet bypassing ufw" has_line "$T/v.log" "FAIL  Tailscale traffic goes through ufw"
check "warns about port 5432" has_line "$T/v.log" "5432/tcp"
rm -rf "$T"

# ---------------------------------------------------------------------------
new_env "acl command and config safety"
sth acl --users "alice bob" --tailscale-ssh >"$T/acl.txt" 2>&1
check "acl output is valid HuJSON" python3 -c '
import json, re, sys
t = re.sub(r"//[^\n]*", "", open(sys.argv[1]).read())
d = json.loads(t)
assert d["tagOwners"]["tag:server"] == ["autogroup:admin"]
assert d["grants"][0]["ip"] == ["tcp:22"]
assert d["ssh"][0]["users"] == ["alice", "bob"]' "$T/acl.txt"
sth acl --users alice >"$T/acl2.txt" 2>&1
check "acl without Tailscale SSH has no ssh block" python3 -c '
import json, re, sys
d = json.loads(re.sub(r"//[^\n]*", "", open(sys.argv[1]).read())); assert "ssh" not in d' "$T/acl2.txt"
printf 'SERVER_TYPE=cloud\nEVIL=1\n' >"$T/bad.conf"
check "unknown config key refused" bash -c '! bash "$0/secure-this-host.sh" --config "$1" --yes >/dev/null 2>&1' "$REPO" "$T/bad.conf"
printf 'ID=ubuntu\nVERSION_ID="22.04"\n' >"$STH_ROOT/etc/os-release"
check "Ubuntu 22.04 refused" bash -c 'bash "$0/secure-this-host.sh" </dev/null 2>&1 | grep -q "Unsupported Ubuntu version"' "$REPO"
check "version shows credit" bash -c 'bash "$0/secure-this-host.sh" --version | grep -q "Copyright (c) 2026 jermsmit"' "$REPO"
rm -rf "$T"

echo "integration tests: $PASS passed, $FAIL failed"
(( FAIL == 0 ))
