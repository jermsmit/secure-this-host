# shellcheck shell=bash disable=SC2034,SC2154
# (Variables are shared between the lib files through secure-this-host.sh,
# so checked one file at a time ShellCheck sees them as unset or unused.)
# common.sh - shared helpers: logging, prompts, dry-run, files, backups,
# config parsing and input validation.
#
# Part of secure-this-host - https://github.com/jermsmit/secure-this-host
# Copyright (c) 2026 jermsmit. MIT License.

STH_VERSION="1.0.0"
STH_AUTHOR="jermsmit"
STH_URL="https://github.com/jermsmit/secure-this-host"

# STH_ROOT prefixes every file path. It is empty on a real system and is only
# set by the test suite so that tests never touch the real /etc.
: "${STH_ROOT:=}"
: "${DRY_RUN:=0}"
: "${ASSUME_YES:=0}"
: "${VERBOSE:=0}"

STATE_DIR="/var/lib/secure-this-host"
ANSWERS_FILE="$STATE_DIR/answers.conf"
MANIFEST_FILE="$STATE_DIR/manifest"
BACKUP_BASE="/var/backups/secure-this-host"
RUN_DIR="/run/secure-this-host"
LOG_FILE="/var/log/secure-this-host.log"
INSTALL_LIB="/usr/local/lib/secure-this-host"
INSTALL_BIN="/usr/local/sbin/sth"
RULE_TAG="sth"                       # prefix of every ufw rule comment we add
ROLLBACK_UNIT="sth-rollback"

# Tailscale address ranges (IPv4 CGNAT range and IPv6 ULA range).
TS_V4_RANGE="100.64.0.0/10"
TS_V6_RANGE="fd7a:115c:a1e0::/48"

# --------------------------------------------------------------------------
# Output and logging
# --------------------------------------------------------------------------
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  C_RED=$'\e[31m' C_GREEN=$'\e[32m' C_YELLOW=$'\e[33m' C_BOLD=$'\e[1m' C_DIM=$'\e[2m' C_RESET=$'\e[0m'
else
  C_RED="" C_GREEN="" C_YELLOW="" C_BOLD="" C_DIM="" C_RESET=""
fi

# p PATH - the real on-disk location of PATH (adds the test prefix).
p() { printf '%s%s' "$STH_ROOT" "$1"; }

_log() {
  [[ $DRY_RUN == 1 ]] && return 0
  local f; f=$(p "$LOG_FILE")
  { mkdir -p "${f%/*}" && printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" >>"$f"; } 2>/dev/null || true
}
info()  { printf '  %s\n' "$*"; _log INFO "$*"; }
ok()    { printf '  %s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; _log OK "$*"; }
warn()  { printf '  %s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; _log WARN "$*"; }
error() { printf '  %s✗%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; _log ERROR "$*"; }
die()   { error "$*"; exit 1; }
step()  { printf '\n%s==> %s%s\n' "$C_BOLD" "$*" "$C_RESET"; _log STEP "$*"; }
note()  { printf '  %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
debug() { if [[ $VERBOSE == 1 ]]; then printf '    [debug] %s\n' "$*" >&2; fi; return 0; }

# Dry-run lines go to the terminal's original stdout (fd saved by the main
# script) so they still show when a command's own output is sent to /dev/null.
dry() { printf '    %s[dry-run]%s %s\n' "$C_DIM" "$C_RESET" "$*" >&"${STH_OUT_FD:-1}"; }

# run CMD... - run a command, or only print it in dry-run mode.
# Never pass secrets as arguments: they would be printed and logged.
run() {
  if [[ $DRY_RUN == 1 ]]; then dry "$*"; return 0; fi
  debug "run: $*"
  _log RUN "$*"
  "$@"
}

have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------
# Prompts. Each prompt stores its answer in a named variable. If the variable
# is already set (from --config) the prompt is skipped. With --yes, the
# default is taken. Answers are validated in every case.
# --------------------------------------------------------------------------

# _read_line VAR - read one line from the terminal (or stdin in tests).
_read_line() {
  local __line=""
  if ! IFS= read -r __line; then
    die "No input available (stdin closed). Use --config FILE --yes for unattended runs."
  fi
  printf -v "$1" '%s' "$__line"
}

# ask VAR "Question" DEFAULT [VALIDATOR]
ask() {
  local __var=$1 __q=$2 __def=${3:-} __check=${4:-} __ans
  if [[ -n ${!__var:-} ]]; then
    if [[ -n $__check ]] && ! "$__check" "${!__var}"; then
      die "Config value for $__var is invalid: '${!__var}'"
    fi
    note "$__q ${!__var} (from config)"
    return 0
  fi
  if [[ $ASSUME_YES == 1 ]]; then
    [[ -n $__def ]] || die "$__var is required with --yes; set it in the config file."
    if [[ -n $__check ]] && ! "$__check" "$__def"; then die "Default for $__var is invalid: '$__def'"; fi
    printf -v "$__var" '%s' "$__def"
    note "$__q $__def (default)"
    return 0
  fi
  while true; do
    if [[ -n $__def ]]; then printf '  %s [%s]: ' "$__q" "$__def"; else printf '  %s: ' "$__q"; fi
    _read_line __ans
    [[ -z $__ans ]] && __ans=$__def
    if [[ -z $__ans ]]; then warn "An answer is required."; continue; fi
    if [[ -n $__check ]] && ! "$__check" "$__ans"; then warn "'$__ans' is not valid. Try again."; continue; fi
    printf -v "$__var" '%s' "$__ans"
    return 0
  done
}

# ask_yn VAR "Question" yes|no  -> VAR becomes "yes" or "no"
ask_yn() {
  local __var=$1 __q=$2 __def=$3 __ans
  if [[ -n ${!__var:-} ]]; then
    case ${!__var} in yes|no) note "$__q ${!__var} (from config)"; return 0 ;; esac
    die "Config value for $__var must be yes or no, got '${!__var}'"
  fi
  if [[ $ASSUME_YES == 1 ]]; then printf -v "$__var" '%s' "$__def"; note "$__q $__def (default)"; return 0; fi
  local hint="y/N"; [[ $__def == yes ]] && hint="Y/n"
  while true; do
    printf '  %s [%s]: ' "$__q" "$hint"
    _read_line __ans
    case ${__ans,,} in
      "") printf -v "$__var" '%s' "$__def"; return 0 ;;
      y|yes) printf -v "$__var" yes; return 0 ;;
      n|no) printf -v "$__var" no; return 0 ;;
      *) warn "Please answer y or n." ;;
    esac
  done
}

# ask_choice VAR "Question" DEFAULT "value|description" ...
ask_choice() {
  local __var=$1 __q=$2 __def=$3; shift 3
  local -a vals=() descs=()
  local o i __ans
  for o in "$@"; do vals+=("${o%%|*}"); descs+=("${o#*|}"); done
  if [[ -n ${!__var:-} ]]; then
    for i in "${vals[@]}"; do
      if [[ $i == "${!__var}" ]]; then note "$__q ${!__var} (from config)"; return 0; fi
    done
    die "Config value for $__var must be one of: ${vals[*]} (got '${!__var}')"
  fi
  if [[ $ASSUME_YES == 1 ]]; then printf -v "$__var" '%s' "$__def"; note "$__q $__def (default)"; return 0; fi
  printf '  %s\n' "$__q"
  for i in "${!vals[@]}"; do
    local mark=" "; [[ ${vals[$i]} == "$__def" ]] && mark="*"
    printf '   %s %d) %-12s %s\n' "$mark" "$((i + 1))" "${vals[$i]}" "${descs[$i]}"
  done
  while true; do
    printf '  Choice [%s]: ' "$__def"
    _read_line __ans
    [[ -z $__ans ]] && __ans=$__def
    if [[ $__ans =~ ^[0-9]+$ ]] && (( __ans >= 1 && __ans <= ${#vals[@]} )); then
      printf -v "$__var" '%s' "${vals[$((__ans - 1))]}"; return 0
    fi
    for i in "${vals[@]}"; do
      if [[ $i == "$__ans" ]]; then printf -v "$__var" '%s' "$__ans"; return 0; fi
    done
    warn "Pick a number from 1 to ${#vals[@]}."
  done
}

# confirm "Question" - yes/no gate that defaults to no. --yes answers yes.
confirm() {
  local __c=""
  [[ $ASSUME_YES == 1 ]] && return 0
  ask_yn __c "$1" no
  [[ $__c == yes ]]
}

# --------------------------------------------------------------------------
# Config files: KEY=VALUE lines, parsed without `source` so a config file
# can never run code. Unknown keys are rejected.
# --------------------------------------------------------------------------
CONFIG_KEYS=(
  SERVER_TYPE ADMIN_USER CREATE_ADMIN ADMIN_SUDO_NOPASSWD ADMIN_PUBKEY ADMIN_PUBKEY_FILE
  SSH_ALLOW_USERS SSH_METHOD TS_AUTHKEY_FILE TS_TAG LAN_SSH LAN_SSH_SOURCE PUBLIC_PORTS
  REMOVE_OPEN_SSH_RULES AUTO_UPDATES AUTO_REBOOT AUTO_REBOOT_TIME EXTRA_HARDENING
  FAIL2BAN DISABLE_SERVICES DOCKER_FIREWALL ROLLBACK_WINDOW CONFIRM_MODE
)

is_config_key() {
  local k
  for k in "${CONFIG_KEYS[@]}"; do [[ $k == "$1" ]] && return 0; done
  return 1
}

# load_config FILE - set variables from FILE.
load_config() {
  local file=$1 line key val n=0
  [[ -r $file ]] || die "Cannot read config file: $file"
  while IFS= read -r line || [[ -n $line ]]; do
    n=$((n + 1))
    line=${line%$'\r'}
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ ! $line =~ ^[[:space:]]*([A-Z][A-Z0-9_]*)=(.*)$ ]]; then
      die "$file line $n: expected KEY=VALUE"
    fi
    key=${BASH_REMATCH[1]} val=${BASH_REMATCH[2]}
    # Quoted values keep everything inside the quotes. Unquoted values lose an
    # inline " # comment" and surrounding whitespace.
    val=${val%"${val##*[![:space:]]}"}
    if [[ $val =~ ^\"([^\"]*)\"([[:space:]]+#.*)?$ || $val =~ ^\'([^\']*)\'([[:space:]]+#.*)?$ ]]; then
      val=${BASH_REMATCH[1]}
    else
      [[ $val =~ ^(.*[^[:space:]])?[[:space:]]+#.*$ ]] && val=${BASH_REMATCH[1]}
      [[ $val == \#* ]] && val=""
    fi
    is_config_key "$key" || die "$file line $n: unknown setting '$key'"
    printf -v "$key" '%s' "$val"
  done <"$file"
}

# render_answers - the current answers as a config file (never secrets).
render_answers() {
  local k
  printf '# secure-this-host answers\n'
  printf '# Re-use with: sudo sth --config %s\n' "$ANSWERS_FILE"
  for k in "${CONFIG_KEYS[@]}"; do
    [[ $k == TS_AUTHKEY_FILE ]] && continue      # path to a secret: not saved
    if [[ -n ${!k:-} ]]; then printf '%s="%s"\n' "$k" "${!k}"; fi
  done
}

# --------------------------------------------------------------------------
# Validators (return 0 when valid)
# --------------------------------------------------------------------------
valid_username() { [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ && $1 != root ]]; }

valid_user_list() {
  local u
  [[ -n $1 ]] || return 1
  for u in $1; do valid_username "$u" || return 1; done
}

valid_ipv4() {
  local ip=$1 o
  [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do
    [[ $o =~ ^(0|[1-9][0-9]*)$ ]] || return 1      # no leading zeros
    (( o <= 255 )) || return 1
  done
}

ip_to_int() {
  local IFS=. a b c d
  read -r a b c d <<<"$1"
  printf '%d' $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

int_to_ip() {
  local n=$1
  printf '%d.%d.%d.%d' $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) $(( (n >> 8) & 255 )) $(( n & 255 ))
}

valid_cidr4() {
  [[ $1 =~ ^([0-9.]+)/([0-9]{1,2})$ ]] || return 1
  # Copy the captures first: valid_ipv4 runs its own regex and overwrites BASH_REMATCH.
  local ip=${BASH_REMATCH[1]} pfx=${BASH_REMATCH[2]}
  valid_ipv4 "$ip" && (( 10#$pfx <= 32 ))
}

# cidr_contains NET/PREFIX IP - is IP inside the network?
cidr_contains() {
  local net=${1%/*} pfx=${1#*/} mask
  (( pfx == 0 )) && return 0
  mask=$(( (0xFFFFFFFF << (32 - pfx)) & 0xFFFFFFFF ))
  (( ($(ip_to_int "$net") & mask) == ($(ip_to_int "$2") & mask) ))
}

# cidr_network IP/PREFIX - normalise to the network address (192.168.1.7/24 -> 192.168.1.0/24)
cidr_network() {
  local ip=${1%/*} pfx=${1#*/} mask
  mask=$(( (0xFFFFFFFF << (32 - pfx)) & 0xFFFFFFFF ))
  (( pfx == 0 )) && mask=0
  printf '%s/%s' "$(int_to_ip $(( $(ip_to_int "$ip") & mask )))" "$pfx"
}

is_private_ipv4() {
  valid_ipv4 "$1" || return 1
  cidr_contains 10.0.0.0/8 "$1" || cidr_contains 172.16.0.0/12 "$1" || cidr_contains 192.168.0.0/16 "$1"
}

is_tailscale_ipv4() { valid_ipv4 "$1" && cidr_contains "$TS_V4_RANGE" "$1"; }

# A LAN source must be a single private IPv4 address or a private network no
# larger than its RFC 1918 block (so 10.0.0.0/7 or 0.0.0.0/0 are refused).
valid_lan_source() {
  local s=$1 ip pfx
  if valid_ipv4 "$s"; then is_private_ipv4 "$s"; return; fi
  valid_cidr4 "$s" || return 1
  ip=${s%/*} pfx=${s#*/}
  [[ $(cidr_network "$s") == "$s" ]] || return 1      # must be the network address
  if cidr_contains 10.0.0.0/8 "$ip"; then (( pfx >= 8 )); return; fi
  if cidr_contains 172.16.0.0/12 "$ip"; then (( pfx >= 12 )); return; fi
  if cidr_contains 192.168.0.0/16 "$ip"; then (( pfx >= 16 )); return; fi
  return 1
}

# Port list: space- or comma-separated items like 443, 443/tcp, 51820/udp.
# Port 22 is never accepted here: SSH is handled separately.
valid_port_list() {
  local item port list=${1//,/ }
  [[ $list == none ]] && return 0
  [[ -n ${list// /} ]] || return 1
  for item in $list; do
    [[ $item =~ ^([0-9]{1,5})(/(tcp|udp))?$ ]] || return 1
    port=${BASH_REMATCH[1]}
    [[ $port =~ ^[1-9][0-9]*$ ]] || return 1
    (( port >= 1 && port <= 65535 )) || return 1
    (( port != 22 )) || return 1
  done
}

# normalise_ports "80, 443 53/udp" -> "80/tcp 443/tcp 53/udp" (or empty for none)
normalise_ports() {
  local item out=() list=${1//,/ }
  [[ $list == none ]] && return 0
  for item in $list; do
    [[ $item == */* ]] || item="$item/tcp"
    out+=("$item")
  done
  printf '%s' "${out[*]}"
}

valid_time() { [[ $1 =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; }
valid_minutes() { [[ $1 =~ ^[0-9]+$ ]] && (( 10#$1 >= 2 && 10#$1 <= 30 )); }
valid_ts_tag() { [[ $1 =~ ^tag:[A-Za-z0-9][A-Za-z0-9-]{0,62}$ ]]; }

# valid_pubkey "LINE" - one OpenSSH public key line. Private keys are refused.
valid_pubkey() {
  local line=$1 tmp bits
  [[ $line == *PRIVATE* ]] && return 1
  [[ $line =~ ^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa)\ [A-Za-z0-9+/]+={0,3}(\ .*)?$ ]] || return 1
  if have ssh-keygen; then
    tmp=$(mktemp) || return 1
    printf '%s\n' "$line" >"$tmp"
    bits=$(ssh-keygen -l -f "$tmp" 2>/dev/null | awk '{print $1}')
    rm -f "$tmp"
    [[ -n $bits ]] || return 1
    # Refuse RSA keys shorter than 2048 bits.
    if [[ $line == ssh-rsa\ * ]] && (( bits < 2048 )); then return 1; fi
  fi
  return 0
}

# --------------------------------------------------------------------------
# Files we own (drop-ins). Every write is recorded in the backup set first,
# so rollback can restore the previous content or remove a new file.
# --------------------------------------------------------------------------

# write_file PATH MODE  (content on stdin)
write_file() {
  local path=$1 mode=$2 real tmp content
  real=$(p "$path")
  content=$(cat)
  if [[ -f $real ]] && [[ $(cat "$real") == "$content" ]]; then
    debug "unchanged: $path"
    return 0
  fi
  if [[ $DRY_RUN == 1 ]]; then
    dry "write $path (mode $mode)"
    return 0
  fi
  backup_track "$path"
  mkdir -p "${real%/*}"
  tmp=$(mktemp "${real%/*}/.sth.XXXXXX")
  printf '%s\n' "$content" >"$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$real"
  manifest_add "$path"
  _log WRITE "$path"
}

# remove_owned PATH - delete a file we created (tracked for rollback).
remove_owned() {
  local path=$1
  [[ -e $(p "$path") ]] || return 0
  if [[ $DRY_RUN == 1 ]]; then dry "remove $path"; return 0; fi
  backup_track "$path"
  rm -f "$(p "$path")"
  _log REMOVE "$path"
}

manifest_add() {
  local m; m=$(p "$MANIFEST_FILE")
  mkdir -p "${m%/*}"
  touch "$m"
  grep -qxF "$1" "$m" || printf '%s\n' "$1" >>"$m"
}

# --------------------------------------------------------------------------
# Backup sets: /var/backups/secure-this-host/<timestamp>/
#   files/<path>  copies of files as they were
#   absent        paths that did not exist (removed again on rollback)
#   tracked       every path in this set
#   meta          KEY=VALUE facts (ufw state, who ran it)
# --------------------------------------------------------------------------
BACKUP_DIR=""

begin_backup() {
  [[ $DRY_RUN == 1 ]] && { BACKUP_DIR="(dry-run)"; return 0; }
  local ts; ts=$(date -u +%Y%m%dT%H%M%SZ)
  BACKUP_DIR="$BACKUP_BASE/$ts"
  local real; real=$(p "$BACKUP_DIR")
  # Two runs in the same second get a suffix.
  local i=1; while [[ -e $real ]]; do real=$(p "$BACKUP_DIR-$i"); i=$((i + 1)); done
  BACKUP_DIR=${real#"$STH_ROOT"}
  mkdir -p "$real/files"
  chmod 700 "$(p "$BACKUP_BASE")" "$real"
  : >"$real/absent"; : >"$real/tracked"; : >"$real/meta"
  info "Backup set: $BACKUP_DIR"
}

backup_meta() {
  [[ $DRY_RUN == 1 || -z $BACKUP_DIR ]] && return 0
  printf '%s=%s\n' "$1" "$2" >>"$(p "$BACKUP_DIR")/meta"
}

backup_get_meta() {   # backup_get_meta DIR KEY
  local f; f="$(p "$1")/meta"
  [[ -f $f ]] || return 0
  awk -F= -v k="$2" '$1 == k { v = substr($0, length(k) + 2) } END { if (v != "") print v }' "$f"
}

backup_track() {
  local path=$1 set real
  [[ $DRY_RUN == 1 ]] && return 0
  [[ -n $BACKUP_DIR ]] || die "internal error: backup_track before begin_backup ($path)"
  set=$(p "$BACKUP_DIR")
  grep -qxF "$path" "$set/tracked" && return 0
  printf '%s\n' "$path" >>"$set/tracked"
  real=$(p "$path")
  if [[ -e $real ]]; then
    mkdir -p "$set/files${path%/*}"
    cp -a "$real" "$set/files$path"
  else
    printf '%s\n' "$path" >>"$set/absent"
  fi
}

# backup_track_tree DIR - track every regular file under DIR.
backup_track_tree() {
  local dir=$1 f
  [[ -d $(p "$dir") ]] || return 0
  while IFS= read -r -d '' f; do
    backup_track "${f#"$STH_ROOT"}"
  done < <(find "$(p "$dir")" -type f -print0)
}

# restore_backup DIR - put every tracked file back as it was.
restore_backup() {
  local set path
  set=$(p "$1")
  [[ -f $set/tracked ]] || die "Not a backup set: $1"
  while IFS= read -r path; do
    [[ -n $path ]] || continue
    rm -f "$(p "$path")"
  done <"$set/absent"
  while IFS= read -r path; do
    [[ -n $path && -e $set/files$path ]] || continue
    mkdir -p "$(p "${path%/*}")"
    cp -a "$set/files$path" "$(p "$path")"
  done <"$set/tracked"
}

latest_backup() {
  local d
  d=$(find "$(p "$BACKUP_BASE")" -mindepth 1 -maxdepth 1 -type d -name '20*' 2>/dev/null | sort | tail -n 1)
  if [[ -n $d ]]; then printf '%s' "${d#"$STH_ROOT"}"; fi
}

# --------------------------------------------------------------------------
# Misc
# --------------------------------------------------------------------------
# random_code - 6 characters, no look-alikes (0/O, 1/I). `|| true` because
# head closing the pipe makes tr exit with SIGPIPE under pipefail.
random_code() {
  local c
  c=$(LC_ALL=C tr -dc 'A-HJ-NP-Z2-9' </dev/urandom 2>/dev/null | head -c 6 || true)
  printf '%s' "$c"
}

os_field() {   # os_field KEY - read a field from /etc/os-release without sourcing it
  local f; f=$(p /etc/os-release)
  [[ -r $f ]] || return 0
  awk -F= -v k="$1" '$1 == k { v = $2; gsub(/^"|"$/, "", v); print v }' "$f"
}

require_root() {
  [[ ${STH_TEST:-0} == 1 ]] && return 0
  (( EUID == 0 )) || die "Run this with sudo, e.g.: sudo sth"
}

# --------------------------------------------------------------------------
# Packages
# --------------------------------------------------------------------------
APT_UPDATED=0
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }

# apt_install PKG... - install only the packages that are missing.
apt_install() {
  local missing=() pkg
  for pkg in "$@"; do pkg_installed "$pkg" || missing+=("$pkg"); done
  (( ${#missing[@]} )) || return 0
  if [[ $APT_UPDATED == 0 ]]; then
    run env DEBIAN_FRONTEND=noninteractive apt-get update -q || die "apt-get update failed. Check the internet connection."
    APT_UPDATED=1
  fi
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${missing[@]}" || die "Could not install: ${missing[*]}"
  ok "Installed ${missing[*]}"
}

# State that must survive between runs (for uninstall): KEY=VALUE lines.
state_set() {
  [[ $DRY_RUN == 1 ]] && return 0
  local f; f=$(p "$STATE_DIR/state")
  mkdir -p "${f%/*}"; touch "$f"
  grep -v "^$1=" "$f" >"$f.tmp" || true
  printf '%s=%s\n' "$1" "$2" >>"$f.tmp"
  mv -f "$f.tmp" "$f"
}
state_get() {
  local f; f=$(p "$STATE_DIR/state")
  [[ -f $f ]] || return 0
  awk -F= -v k="$1" '$1 == k { v = substr($0, length(k) + 2) } END { if (v != "") print v }' "$f"
}
