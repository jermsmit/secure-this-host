# shellcheck shell=bash disable=SC2034,SC2154
# (Variables are shared between the lib files through secure-this-host.sh,
# so checked one file at a time ShellCheck sees them as unset or unused.)
# users.sh - the admin account and its SSH key.
#
# Part of secure-this-host. Copyright (c) 2026 jermsmit. MIT License.

user_exists() { getent passwd "$1" >/dev/null 2>&1; }
user_home() { getent passwd "$1" | cut -d: -f6; }
user_in_group() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx "$2"; }
# password_status USER - P (usable), L (locked), NP (none), or empty if unknown.
password_status() { passwd -S "$1" 2>/dev/null | awk '{print $2}'; }

# count_keys FILE - number of valid public key lines in an authorized_keys file.
count_keys() {
  local f=$1 line n=0 key
  [[ -f $f ]] || { printf 0; return 0; }
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    # Lines may start with options (from="...",no-pty ...): take the key part.
    key=$(grep -Eo '(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) [A-Za-z0-9+/]+={0,3}.*' <<<"$line" || true)
    [[ -n $key ]] && valid_pubkey "$key" && n=$((n + 1))
  done <"$f"
  printf '%d' "$n"
}

users_questions() {
  step "Admin account"
  local default_user=${SUDO_USER:-}
  [[ $default_user == root ]] && default_user=""
  local create_default=no
  [[ -z $default_user ]] && create_default=yes
  ask_yn CREATE_ADMIN "Create a new admin account?" "$create_default"
  if [[ $CREATE_ADMIN == no ]]; then
    ask ADMIN_USER "Existing admin username" "$default_user" valid_existing_user
  else
    ask ADMIN_USER "New admin username" "" valid_username
    if user_exists "$ADMIN_USER"; then
      note "$ADMIN_USER already exists; it will be reused."
    else
      ask_yn ADMIN_SUDO_NOPASSWD "Let $ADMIN_USER use sudo without a password? (No = you set a password next)" no
      if [[ $ADMIN_SUDO_NOPASSWD == no && $ASSUME_YES == 1 ]]; then
        die "Unattended runs can't set a password. Use an existing account, or set ADMIN_SUDO_NOPASSWD=yes."
      fi
    fi
  fi

  # A console (provider web console, keyboard and screen) needs a password:
  # SSH keys only work over SSH. Without one, the backup way in is useless.
  if user_exists "$ADMIN_USER"; then
    local pw; pw=$(password_status "$ADMIN_USER")
    if [[ $pw == L || $pw == NP ]]; then
      warn "$ADMIN_USER has no password, so it can't log in at a console (SSH keys only work over SSH)."
      warn "The console is your way back in if SSH and Tailscale both fail."
      if [[ $ASSUME_YES == 0 ]]; then
        ask_yn SET_CONSOLE_PW "Set a password for $ADMIN_USER when applying? (recommended)" yes
      fi
    fi
  fi

  # SSH key
  local home="" existing=0
  if user_exists "$ADMIN_USER"; then
    home=$(user_home "$ADMIN_USER")
    existing=$(count_keys "$(p "$home")/.ssh/authorized_keys")
  fi
  if [[ -z ${ADMIN_PUBKEY:-} && -n ${ADMIN_PUBKEY_FILE:-} ]]; then
    [[ -r $ADMIN_PUBKEY_FILE ]] || die "Cannot read ADMIN_PUBKEY_FILE: $ADMIN_PUBKEY_FILE"
    ADMIN_PUBKEY=$(grep -Ev '^[[:space:]]*(#|$)' "$ADMIN_PUBKEY_FILE" | head -n 1)
  fi
  if [[ -n ${ADMIN_PUBKEY:-} ]]; then
    valid_pubkey "$ADMIN_PUBKEY" || die "ADMIN_PUBKEY is not a valid OpenSSH public key."
    ok "Public key from config will be installed for $ADMIN_USER"
  elif (( existing > 0 )); then
    ok "$ADMIN_USER already has $existing valid SSH key(s)"
    local add=""
    if [[ $ASSUME_YES == 0 ]]; then ask_yn add "Add another public key?" no; fi
    if [[ $add == yes ]]; then
      ask ADMIN_PUBKEY "Paste the public key (one line, starts with ssh-ed25519)" "" valid_pubkey
    fi
  else
    note "$ADMIN_USER has no SSH key yet. On your own computer, show your public key with:"
    note "    cat ~/.ssh/id_ed25519.pub     (create one first with: ssh-keygen -t ed25519)"
    ask ADMIN_PUBKEY "Paste the public key (one line, starts with ssh-ed25519)" "" valid_pubkey
  fi

  ask SSH_ALLOW_USERS "Accounts allowed to log in over SSH (space-separated)" "$ADMIN_USER" valid_user_list
  if [[ " $SSH_ALLOW_USERS " != *" $ADMIN_USER "* ]]; then
    SSH_ALLOW_USERS="$ADMIN_USER $SSH_ALLOW_USERS"
    note "Added $ADMIN_USER to the allowed accounts."
  fi
  local u
  for u in $SSH_ALLOW_USERS; do
    [[ $u == "$ADMIN_USER" ]] && continue
    user_exists "$u" || warn "Account '$u' doesn't exist yet; it will be allowed once created."
  done
}

valid_existing_user() {
  valid_username "$1" || return 1
  if ! user_exists "$1"; then warn "No account named '$1' on this server."; return 1; fi
}

users_apply() {
  step "Admin account: $ADMIN_USER"
  local user=$ADMIN_USER home
  if ! user_exists "$user"; then
    run useradd --create-home --shell /bin/bash --groups sudo "$user"
    ok "Created $user (member of sudo)"
    if [[ ${ADMIN_SUDO_NOPASSWD:-no} == yes ]]; then
      sudoers_nopasswd "$user"
    elif [[ $DRY_RUN == 0 ]]; then
      info "Set a password for $user. It is used for sudo only; SSH stays key-only."
      local tries=0
      until passwd "$user"; do
        tries=$((tries + 1)); (( tries < 3 )) || die "Password was not set for $user."
      done
    fi
  else
    if ! user_in_group "$user" sudo; then
      run usermod --append --groups sudo "$user"
      ok "Added $user to the sudo group"
    else
      ok "$user exists and can use sudo"
    fi
    if [[ ${SET_CONSOLE_PW:-no} == yes ]]; then
      if [[ $DRY_RUN == 1 ]]; then
        run passwd "$user"
      else
        info "Set a console password for $user (used at a console and for sudo; SSH stays key-only)."
        local tries=0
        until passwd "$user"; do
          tries=$((tries + 1)); (( tries < 3 )) || { warn "Password not set; console login won't work for $user."; break; }
        done
      fi
    fi
  fi

  if [[ -n ${ADMIN_PUBKEY:-} ]]; then
    home=$(user_home "$user")
    [[ -n $home || $DRY_RUN == 1 ]] || die "Cannot find the home directory of $user"
    install_pubkey "$user" "${home:-/home/$user}" "$ADMIN_PUBKEY"
  fi
}

sudoers_nopasswd() {
  local user=$1 path="/etc/sudoers.d/60-secure-this-host-$1" tmp
  local content="# Managed by secure-this-host
$user ALL=(ALL:ALL) NOPASSWD: ALL"
  if [[ $DRY_RUN == 1 ]]; then run write "$path"; return 0; fi
  # A broken sudoers file locks everyone out of sudo: check it before installing.
  tmp=$(mktemp)
  printf '%s\n' "$content" >"$tmp"
  if ! visudo -cf "$tmp" >/dev/null; then rm -f "$tmp"; die "Generated sudoers rule failed visudo check."; fi
  rm -f "$tmp"
  printf '%s' "$content" | write_file "$path" 440
  ok "sudo without password enabled for $user"
}

install_pubkey() {
  local user=$1 home=$2 key=$3 dir file
  dir="$home/.ssh" file="$home/.ssh/authorized_keys"
  if [[ $DRY_RUN == 1 ]]; then run add-key "$file"; return 0; fi
  local keypart; keypart=$(awk '{print $1" "$2}' <<<"$key")
  if [[ -f $(p "$file") ]] && grep -qF "$keypart" "$(p "$file")"; then
    ok "Key already present in $file"
    return 0
  fi
  backup_track "$file"
  mkdir -p "$(p "$dir")"
  printf '%s\n' "$key" >>"$(p "$file")"
  chmod 700 "$(p "$dir")"
  chmod 600 "$(p "$file")"
  chown -R "$user:$(id -gn "$user")" "$(p "$dir")"
  ok "Installed public key in $file"
}
