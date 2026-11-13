# secure-this-host

**Zero-trust hardening for Ubuntu 24.04 and 26.04 LTS, in one interactive script.**

Created by [jermsmit](https://github.com/jermsmit) · MIT License · [github.com/jermsmit/secure-this-host](https://github.com/jermsmit/secure-this-host)

Run it on a clean or existing Ubuntu server, at home, in an office or in the cloud. Admin SSH ends up reachable only over [Tailscale](https://tailscale.com) (plus an optional LAN range), every inbound port is closed unless you list it, and `sth verify` checks the result with a PASS/FAIL report. If the new setup would lock you out, every change is undone automatically.

```
sudo ./secure-this-host.sh            # interactive setup; installs the `sth` command
sudo sth verify                       # PASS/FAIL report, any time
```

> **What this is and isn't.** It gives a server a hardened, zero-trust *baseline*. It doesn't make anything "production ready" by itself: backups, monitoring, application hardening and secrets management are still your job (see [After hardening](#after-hardening)).

## Zero-trust principles

1. **Identity over location.** Admin access requires a Tailscale identity *and* an SSH key (or Tailscale SSH), never just "can reach port 22".
2. **Deny by default.** The firewall drops all inbound traffic, including from other tailnet devices, except SSH over Tailscale and the ports you open on purpose.
3. **Verify, don't assume.** Checks read the *effective* state (`sshd -T`, `ufw status`, `sysctl`), not just the files the script wrote.

## Quick start

On the server, as a user who can `sudo`:

```bash
git clone https://github.com/jermsmit/secure-this-host
cd secure-this-host
sudo ./secure-this-host.sh --dry-run     # optional: see every change first
sudo ./secure-this-host.sh
```

You need: Ubuntu 24.04 or 26.04 LTS, `openssh-server`, internet access, a Tailscale account, and an SSH public key on your own computer (`cat ~/.ssh/id_ed25519.pub`; create one with `ssh-keygen -t ed25519`).

Have a backup way in before you start: the provider's web console for a cloud server, or a keyboard and screen for a home or office server.

## What the setup asks

Every question has a safe default, so pressing Enter all the way through gives the strictest result. Nothing changes until you approve the summary.

1. **Where is this server?** Cloud or home/office. Home/office servers get the LAN question.
2. **Admin account.** Reuse your sudo account or create one, add an SSH key, choose which accounts may log in over SSH.
3. **Login method.** OpenSSH keys over Tailscale (default), or Tailscale SSH (identity-based, no keys).
4. **Tailscale.** Tag (`tag:server`), then join with a login link or an auth key. The auth key is read hidden and passed to Tailscale in a file, never on the command line.
5. **SSH from the local network** (home/office only, off by default). Choose the whole subnet or one admin computer. Only private address ranges are accepted.
6. **Public ports.** None by default. Port 22 can't be listed. Existing rules that open SSH to everyone are offered for removal.
7. **Security updates.** Daily, on by default. Automatic reboots only if you say yes, at a time you choose.
8. **Extra hardening.** Kernel network settings and audit logging; fail2ban when SSH is reachable from the LAN; disable unneeded services; Docker firewall handling if Docker is installed.

## What it changes

| Area | Change | Where |
|---|---|---|
| SSH | Root login off, passwords and keyboard-interactive off, public key only, `MaxAuthTries 3`, `AllowUsers` limited to your accounts from localhost, the tailnet and the opt-in LAN range | `/etc/ssh/sshd_config.d/00-secure-this-host.conf` |
| Firewall | ufw: deny incoming; SSH only on `tailscale0` (+ LAN source); your public ports | ufw rules tagged `sth:` |
| Tailscale | Signed apt repo, join with tag, netfilter mode `nodivert` so ufw also filters tailnet traffic, optional Tailscale SSH | `/etc/apt/sources.list.d/tailscale.list` |
| Updates | unattended-upgrades daily, optional reboot window | `/etc/apt/apt.conf.d/52secure-this-host` |
| Kernel | No ICMP redirects or source routing, SYN cookies, loose reverse-path filter, hidden kernel pointers and logs | `/etc/sysctl.d/60-secure-this-host.conf` |
| Audit | auditd watching accounts, sudoers, SSH config, login records, time and kernel modules | `/etc/audit/rules.d/60-secure-this-host.rules` |
| fail2ban | SSH jail using ufw; tailnet addresses never banned (only when LAN SSH is on) | `/etc/fail2ban/jail.d/60-secure-this-host.local` |
| Docker | Published container ports obey the firewall (opt-in) | marked block in `/etc/ufw/after.rules` |

Every file is backed up before it's touched, to `/var/backups/secure-this-host/<timestamp>/`.

## The safety net

The script usually runs over SSH while it changes SSH and the firewall. These safeguards stop it from locking you out:

1. **Pre-flight checks.** It refuses unsupported systems and other firewall managers (nftables, iptables-persistent, firewalld). It requires a valid SSH key for the admin account and detects how you're connected.
2. **Tailscale first.** The server joins your tailnet before anything is restricted.
3. **Rollback timer.** A `systemd-run` timer (5 minutes by default; `--rollback-window 2-30`) is armed before SSH or the firewall change.
4. **Prove it.** You open a **new** terminal, log in over Tailscale and run `sudo sth confirm CODE`. Confirming from the installer's own session is refused, because it proves nothing.
5. **No confirmation → automatic rollback.** Files, ufw state, Tailscale settings and services go back to how they were.
6. **Failure → immediate rollback.** If any step fails mid-run (for example `sshd -t` rejects the config), everything is undone at once.

## Commands

| Command | What it does |
|---|---|
| `sudo sth` | Interactive setup (same as `install`) |
| `sudo sth verify [--json] [--lynis]` | Read-only PASS/FAIL report; exit status 0 only if nothing fails |
| `sudo sth confirm CODE` | Cancel the rollback timer from a new login |
| `sudo sth rollback [--backup DIR]` | Restore the latest (or a chosen) backup set |
| `sudo sth uninstall` | Remove every file and ufw rule secure-this-host added |
| `sth acl [--tag T] [--users "a b"] [--tailscale-ssh]` | Print a Tailscale access policy snippet |
| `sth version` | Version and author |

Install options: `--dry-run`, `--config FILE`, `--yes`, `--rollback-window MIN`, `--verbose`.

## Tailscale access policy

Before joining, the script prints a policy snippet to paste into the Tailscale admin console (**Access controls**). It defines `tag:server` and lets only tailnet admins reach SSH on it. In Tailscale SSH mode it adds an `ssh` rule with `check`, which makes admins sign in again every 12 hours. Print it again any time with `sth acl`.

For real zero trust, also remove the default allow-all grant (`{"src": ["*"], "dst": ["*"], "ip": ["*"]}`) from your policy. Otherwise every device in your tailnet can reach this one.

## Unattended runs and cloud-init

Save your answers, or start from [`examples/answers.example.conf`](examples/answers.example.conf):

```bash
sudo sth --config answers.conf --yes
```

Config files are parsed as plain `KEY=VALUE` lines, never executed, and unknown keys are refused. [`examples/cloud-init.yaml`](examples/cloud-init.yaml) hardens a new cloud server on first boot with a one-off, pre-approved Tailscale auth key.

## Docker

Docker publishes container ports by writing its own iptables rules, which skip ufw entirely. The script warns when Docker is installed. With **Docker firewall handling** on, published ports only accept new connections on your listed public ports or over Tailscale. Containers that rely on other published ports stop being reachable from outside, so test before turning it on.

## After hardening

- Keep your backup access (provider console, physical console) working.
- Set up backups and monitoring; this script does neither.
- Harden each service you expose (TLS, authentication, its own updates).
- Run `sudo sth verify` after changes and after release upgrades.
- After upgrading Ubuntu (for example 24.04 → 26.04), re-run `sudo sth` so the Tailscale repository points at the new release.

## Known limits

- **Reboot during the rollback window.** The rollback timer is in memory. If the server reboots before you confirm, the changes stay and there's no timer. Use the console and `sudo sth rollback` if needed.
- **Kernel settings after rollback.** Removing the sysctl file takes effect at the next boot.
- **Already-joined servers** keep their Tailscale login. Tag them yourself with `sudo tailscale up --advertise-tags=tag:server` so the policy applies.
- **Settings are CIS-inspired, not CIS-certified.** For certified compliance use Ubuntu Security Guide (Ubuntu Pro).

## Testing

```bash
bash tests/unit.sh          # validators, config parser, backup/restore
bash tests/integration.sh   # full runs against fake system commands
```

The integration tests run the real script inside a throwaway directory, with fake `ufw`, `sshd`, `tailscale`, `systemctl` and friends ([`tests/stubs/fake`](tests/stubs/fake)). Nothing on the test machine changes. They cover:

- a clean install and an idempotent second run
- an existing server with a password-enabling cloud-init drop-in, open SSH rules and Docker
- the rollback timer firing, and a failure mid-run
- dry runs, unattended cloud runs on 26.04, Tailscale SSH, uninstall, and verify catching problems

CI runs ShellCheck plus both suites on every push. The fakes can't prove behaviour on a real kernel, so test on a VM before trusting it with a server you care about.

## Lessons behind the design

- **sshd keeps the first value it reads.** Ubuntu includes `sshd_config.d/*.conf` before everything else, and cloud images often ship `50-cloud-init.conf` with `PasswordAuthentication yes`. Naming the drop-in `00-…` makes it win, and verify proves it with `sshd -T`.
- **Firewall rules beat `ListenAddress`.** Binding SSH to the Tailscale IP fails when Tailscale starts after SSH at boot, and binding to a LAN IP breaks when DHCP changes it. ufw on the `tailscale0` interface has neither problem.
- **Tailscale and Docker both bypass ufw by default.** Tailscale accepts everything on `tailscale0` before ufw sees it (fixed with netfilter mode `nodivert`), and Docker routes published ports around ufw (fixed with the `DOCKER-USER` chain).
- **`sshd -t` needs `/run/sshd`.** On Ubuntu 24.04+ SSH is socket-activated, so that directory may not exist yet.
- **Turning on Tailscale SSH freezes OpenSSH sessions on the Tailscale address.** It's done last, after the confirmation code is shown.

## Project layout

```
secure-this-host/
├── secure-this-host.sh      # entry point: commands, setup flow, apply order
├── lib/
│   ├── common.sh            # logging, prompts, config parser, validators, backups
│   ├── preflight.sh         # OS, connection, LAN, firewall, Docker, Tailscale detection
│   ├── users.sh             # admin account and SSH key
│   ├── ssh.sh               # sshd drop-in and effective-setting checks
│   ├── firewall.sh          # ufw rules
│   ├── tailscale.sh         # repo, join, policy snippet, nodivert, Tailscale SSH
│   ├── updates.sh           # unattended-upgrades
│   ├── harden.sh            # sysctl, AppArmor, auditd, fail2ban, services, Docker
│   ├── rollback.sh          # timer, confirm, restore
│   └── verify.sh            # PASS/FAIL checks
├── examples/                # answers file and cloud-init
├── docs/                    # design and threat model
└── tests/                   # unit + integration tests and fake system commands
```

## License

MIT, Copyright (c) 2026 [jermsmit](https://github.com/jermsmit). You may use, change and share this code, but you must keep the copyright notice. See [LICENSE](LICENSE).
