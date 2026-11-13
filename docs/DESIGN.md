# secure-this-host: design

Author: [jermsmit](https://github.com/jermsmit) · Status: implemented in v1.0.0

## Goal

One interactive Bash script that gives a clean or existing Ubuntu LTS server a hardened, zero-trust baseline. It must be safe to run over SSH, safe to run twice, and fully reversible.

## Decisions

| Question | Decision |
|---|---|
| Supported systems | Ubuntu 24.04 LTS (noble) and 26.04 LTS (resolute), amd64 and arm64 |
| Server types | `cloud` and `onprem`. The LAN SSH question is only asked for `onprem` |
| Admin login method | Asked during setup: OpenSSH keys over Tailscale (default) or Tailscale SSH |
| Where SSH is reachable | Enforced by ufw on `tailscale0` plus an opt-in private LAN source, with `AllowUsers user@network` inside sshd as a second layer. `ListenAddress` is not used: it races Tailscale at boot and breaks on DHCP changes |
| Tailnet filtering | Tailscale netfilter mode `nodivert`, so ufw also filters traffic from other tailnet devices |
| Rollback window | 5 minutes by default, 2 to 30 with `--rollback-window` or `ROLLBACK_WINDOW` |
| Automatic reboots | Asked; off unless you say yes, at a chosen time |
| Tailscale policy | Printed before joining (the tag must exist first); `sth acl` prints it any time |
| Docker | Detected and warned about; opt-in `DOCKER-USER` handling |
| Command name | `sth`, installed as `/usr/local/sbin/sth` |
| Language | Bash, no dependencies beyond a stock Ubuntu server |
| License | MIT, Copyright (c) 2026 jermsmit |

## Apply order

The order is chosen so you always have a way back in:

1. **Pre-flight, questions, review.** Nothing changes until the summary is approved.
2. **Self-install** of the `sth` command (needed by the rollback timer and `sth confirm`).
3. **Backup set** created; our own state and answers files are tracked too.
4. **Tailscale join** first, so the tailnet path exists before anything is restricted.
5. **Admin account and key.**
6. **Rollback timer armed.** From here an unconfirmed run undoes itself.
7. **SSH drop-in**, tested with `sshd -t` and checked with `sshd -T` before reloading.
8. **Firewall**, then Tailscale `nodivert`.
9. **Updates, kernel settings, audit, fail2ban, services, Docker.**
10. **Answers saved.** If needed, the confirmation code is shown now.
11. **Tailscale SSH last.** It freezes OpenSSH sessions on the Tailscale address.
12. **Wait for `sth confirm` from a new login**, then verify.

Any failure in steps 3 to 11 triggers an immediate rollback through the `EXIT` trap.

## Files

| Path | Owner | Removed by uninstall |
|---|---|---|
| `/etc/ssh/sshd_config.d/00-secure-this-host.conf` | sth | yes |
| `/etc/apt/apt.conf.d/52secure-this-host` | sth | yes |
| `/etc/sysctl.d/60-secure-this-host.conf` | sth | yes |
| `/etc/audit/rules.d/60-secure-this-host.rules` | sth | yes |
| `/etc/fail2ban/jail.d/60-secure-this-host.local` | sth | yes |
| `/etc/sudoers.d/60-secure-this-host-USER` (only with `ADMIN_SUDO_NOPASSWD=yes`) | sth | no (kept so the admin keeps sudo) |
| ufw rules with comments starting `sth:` | sth | yes |
| Block between `# BEGIN/END secure-this-host docker` in `/etc/ufw/after.rules` | sth | yes |
| `/etc/apt/sources.list.d/tailscale.list`, keyring | Tailscale repo | no (Tailscale stays installed) |
| `/var/lib/secure-this-host/` (answers, manifest, state) | sth | yes |
| `/var/backups/secure-this-host/` | sth | no (kept for reference) |
| `/var/log/secure-this-host.log` | sth | no |

## Testing

- `tests/unit.sh`: validators, config parser (including that config files can't run code), prompts, backup/restore.
- `tests/integration.sh`: the real script run against fake system commands in a temporary root. It covers 8 scenarios and checks results, apply order and the absence of side effects.
- CI: ShellCheck and both suites on every push.
- Before a release: a manual run on 24.04 and 26.04 VMs, both clean and existing, including a reboot after confirming.
