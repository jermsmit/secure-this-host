#!/usr/bin/env bash
# unit.sh - tests for the pure helper functions in lib/common.sh.
# Run: bash tests/unit.sh
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export NO_COLOR=1 STH_TEST=1
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

PASS=0 FAIL=0
# In GitHub Actions, failures also show as annotations on the run page.
gh_err() { if [[ ${GITHUB_ACTIONS:-} == true ]]; then printf '::error title=unit test::%s\n' "$*"; fi; }
yes_() { if "$@"; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); echo "FAIL (expected valid): $*"; fi; }
no_()  { if "$@"; then FAIL=$((FAIL + 1)); echo "FAIL (expected invalid): $*"; else PASS=$((PASS + 1)); fi; }
eq_()  { if [[ $1 == "$2" ]]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); echo "FAIL: '$1' != '$2' ($3)"; fi; }

# usernames
yes_ valid_username alice;  yes_ valid_username deploy_1;  yes_ valid_username _svc
no_ valid_username root;    no_ valid_username Alice;     no_ valid_username "a b"
no_ valid_username "";      no_ valid_username 1abc;      no_ valid_username "$(printf 'a%.0s' {1..40})"
yes_ valid_user_list "alice bob";  no_ valid_user_list "alice root";  no_ valid_user_list ""

# IPv4 and CIDR
yes_ valid_ipv4 192.168.1.10; yes_ valid_ipv4 0.0.0.0; yes_ valid_ipv4 255.255.255.255
no_ valid_ipv4 256.1.1.1;     no_ valid_ipv4 1.2.3;    no_ valid_ipv4 01.2.3.4;  no_ valid_ipv4 "1.2.3.4 "
yes_ valid_cidr4 10.0.0.0/8;  no_ valid_cidr4 10.0.0.0/33; no_ valid_cidr4 10.0.0.0
yes_ cidr_contains 100.64.0.0/10 100.101.5.9;  no_ cidr_contains 100.64.0.0/10 100.128.0.1
yes_ cidr_contains 0.0.0.0/0 8.8.8.8
eq_ "$(cidr_network 192.168.1.77/24)" 192.168.1.0/24 "cidr_network /24"
eq_ "$(cidr_network 10.1.2.3/8)" 10.0.0.0/8 "cidr_network /8"
eq_ "$(cidr_network 172.20.5.5/32)" 172.20.5.5/32 "cidr_network /32"
eq_ "$(int_to_ip "$(ip_to_int 172.16.254.3)")" 172.16.254.3 "ip round trip"
yes_ is_private_ipv4 172.31.255.255; no_ is_private_ipv4 172.32.0.1; no_ is_private_ipv4 8.8.8.8
yes_ is_tailscale_ipv4 100.100.100.100; no_ is_tailscale_ipv4 192.168.1.1

# LAN sources: private only, network address only, not wider than the block
yes_ valid_lan_source 192.168.1.0/24; yes_ valid_lan_source 192.168.1.25
yes_ valid_lan_source 10.0.0.0/8;     yes_ valid_lan_source 172.16.0.0/12
no_ valid_lan_source 10.0.0.0/7;      no_ valid_lan_source 0.0.0.0/0
no_ valid_lan_source 192.168.1.5/24;  no_ valid_lan_source 8.8.8.0/24
no_ valid_lan_source 100.64.0.0/10;   no_ valid_lan_source 172.0.0.0/8

# ports
yes_ valid_port_list "80 443";  yes_ valid_port_list "80,443/tcp, 51820/udp";  yes_ valid_port_list none
no_ valid_port_list 22;         no_ valid_port_list "22/tcp";  no_ valid_port_list 0
no_ valid_port_list 65536;      no_ valid_port_list "80/sctp"; no_ valid_port_list "";  no_ valid_port_list 080
eq_ "$(normalise_ports '80, 443 53/udp')" "80/tcp 443/tcp 53/udp" "normalise_ports"
eq_ "$(normalise_ports none)" "" "normalise_ports none"

# misc validators
yes_ valid_time 03:30; yes_ valid_time 23:59; no_ valid_time 24:00; no_ valid_time 3:30
yes_ valid_minutes 5;  yes_ valid_minutes 30; no_ valid_minutes 1; no_ valid_minutes 31; no_ valid_minutes 5m
yes_ valid_minutes 08
yes_ valid_ts_tag tag:server; no_ valid_ts_tag server; no_ valid_ts_tag "tag:bad tag"

# public keys (format check; ssh-keygen is used when installed)
K="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb3Hx1yGm2wq8n0e5Vv9Yc8m1o3pYk6m3wq0aF5m6n7 alice@laptop"
yes_ valid_pubkey "$K"
no_ valid_pubkey "-----BEGIN OPENSSH PRIVATE KEY-----"
no_ valid_pubkey "ssh-dss AAAAB3NzaC1kc3MAAACBAP alice"
no_ valid_pubkey "not a key"

# random confirmation code
c=$(random_code); [[ $c =~ ^[A-HJ-NP-Z2-9]{6}$ ]] && PASS=$((PASS + 1)) || { FAIL=$((FAIL + 1)); echo "FAIL: random_code '$c'"; }

# config parser: quotes, comments, CRLF, unknown keys refused, no code execution
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
printf '%s\n' '# comment' '' 'SERVER_TYPE=cloud' 'ADMIN_USER="alice"' "PUBLIC_PORTS='80 443'  " \
  'LAN_SSH=no'$'\r' 'ROLLBACK_WINDOW=$(touch '"$T"'/pwned)' >"$T/ok.conf"
( load_config "$T/ok.conf"
  [[ $SERVER_TYPE == cloud && $ADMIN_USER == alice && $PUBLIC_PORTS == "80 443" && $LAN_SSH == no ]] ) \
  && PASS=$((PASS + 1)) || { FAIL=$((FAIL + 1)); echo "FAIL: load_config values"; }
[[ ! -e $T/pwned ]] && PASS=$((PASS + 1)) || { FAIL=$((FAIL + 1)); echo "FAIL: config executed code"; }
printf '%s\n' 'ROLLBACK_WINDOW=5    # minutes' 'TS_TAG="tag:a#b"  # note' 'ADMIN_USER=bob#x' >"$T/c.conf"
( load_config "$T/c.conf"; [[ $ROLLBACK_WINDOW == 5 && $TS_TAG == "tag:a#b" && $ADMIN_USER == "bob#x" ]] ) \
  && PASS=$((PASS + 1)) || { FAIL=$((FAIL + 1)); echo "FAIL: inline comments"; }
( load_config "$HERE/../examples/answers.example.conf"
  [[ $SERVER_TYPE == cloud && $ROLLBACK_WINDOW == 5 && $CONFIRM_MODE == new-session && $SSH_ALLOW_USERS == alice ]] ) \
  && PASS=$((PASS + 1)) || { FAIL=$((FAIL + 1)); echo "FAIL: example answers file"; }
printf 'EVIL_KEY=1\n' >"$T/bad.conf"
( load_config "$T/bad.conf" ) >/dev/null 2>&1 && { FAIL=$((FAIL + 1)); echo "FAIL: unknown key accepted"; } || PASS=$((PASS + 1))
printf 'not a line\n' >"$T/bad2.conf"
( load_config "$T/bad2.conf" ) >/dev/null 2>&1 && { FAIL=$((FAIL + 1)); echo "FAIL: bad line accepted"; } || PASS=$((PASS + 1))

# prompts: config value wins, --yes takes default, invalid config value dies
( FOO=cloud; ask_choice FOO "Type?" onprem "cloud|c" "onprem|o" >/dev/null; [[ $FOO == cloud ]] ) && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL: ask_choice config"; }
( ASSUME_YES=1; unset BAR; ask_yn BAR "Q?" no >/dev/null; [[ $BAR == no ]] ) && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL: ask_yn --yes"; }
# BAZ is read by name inside ask_yn, which ShellCheck can't see.
# shellcheck disable=SC2034
( BAZ=maybe; ask_yn BAZ "Q?" no ) >/dev/null 2>&1 && { FAIL=$((FAIL+1)); echo "FAIL: ask_yn bad config"; } || PASS=$((PASS+1))
( unset Q1; ask Q1 "Port?" "" valid_port_list <<<$'22\n443' >/dev/null 2>&1; [[ $Q1 == 443 ]] ) && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL: ask re-prompts on invalid"; }
( unset Q2; ask_choice Q2 "Pick" b "a|x" "b|y" <<<'1' >/dev/null; [[ $Q2 == a ]] ) && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL: ask_choice by number"; }

# backup and restore round trip inside a temp root
export STH_ROOT="$T/root"; mkdir -p "$STH_ROOT/etc/x"
echo original >"$STH_ROOT/etc/x/a.conf"
( begin_backup >/dev/null
  echo changed | write_file /etc/x/a.conf 644
  echo new | write_file /etc/x/b.conf 600
  [[ $(cat "$STH_ROOT/etc/x/a.conf") == changed && -f $STH_ROOT/etc/x/b.conf ]] || exit 1
  [[ $(stat -c %a "$STH_ROOT/etc/x/b.conf") == 600 ]] || exit 1
  restore_backup "$BACKUP_DIR"
  [[ $(cat "$STH_ROOT/etc/x/a.conf") == original && ! -e $STH_ROOT/etc/x/b.conf ]] ) \
  && PASS=$((PASS + 1)) || { FAIL=$((FAIL + 1)); echo "FAIL: backup/restore round trip"; }
eq_ "$(latest_backup | cut -c1-30)" "/var/backups/secure-this-host/" "latest_backup"
unset STH_ROOT

echo "unit tests: $PASS passed, $FAIL failed"
(( FAIL == 0 )) || gh_err "$FAIL unit test(s) failed; see the step log"
(( FAIL == 0 ))
