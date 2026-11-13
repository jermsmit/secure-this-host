# Changelog

## 1.0.0 (2026-11-12)

First release as an interactive hardening script, by [jermsmit](https://github.com/jermsmit). Replaces the earlier "bastion host" write-up; the demo web service and screenshots were removed.

- Interactive setup for Ubuntu 24.04 and 26.04 LTS on cloud and home/office servers.
- SSH: key-only, no root, `AllowUsers` limited to localhost, the tailnet and an opt-in LAN source.
- Firewall: ufw deny-by-default, SSH only over Tailscale, listed public ports, removal of rules that open SSH to everyone.
- Tailscale: signed apt repository, tagged join, access policy snippet, netfilter `nodivert`, optional Tailscale SSH.
- Automatic security updates with optional reboot window.
- Extra hardening: kernel settings, AppArmor check, auditd rules, fail2ban, unneeded services, Docker firewall handling.
- Safety net: backups, rollback timer, `sth confirm` from a new login, immediate rollback on failure.
- Commands: `verify` (text and JSON), `confirm`, `rollback`, `uninstall`, `acl`, `version`.
- Unattended runs with `--config --yes`, and a cloud-init example.
- Unit and integration test suites with fake system commands; CI with ShellCheck.
