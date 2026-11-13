# Threat model

What secure-this-host defends against, what it doesn't, and what it trusts.

## Assets

- Administrative access to the server (SSH, sudo).
- The services the server exposes on purpose.
- The integrity of the system configuration.

## Trust assumptions

- **Tailscale's control plane and your tailnet admins.** Admin access is granted to tailnet identities. Whoever controls your Tailscale account or policy controls who can reach SSH. Protect it with a strong login and MFA.
- **Your SSH private key** (OpenSSH mode) stays on your own devices and has a passphrase.
- **The provider console or physical access** is your out-of-band recovery path.
- **Ubuntu's and Tailscale's package signing.** Packages come from signed apt repositories over HTTPS.

## Threats addressed

| Threat | Mitigation |
|---|---|
| Internet-wide SSH scanning and brute force | SSH is not reachable from the internet: ufw allows port 22 only on `tailscale0` (and an opt-in private LAN source) |
| Password guessing, credential stuffing | Password and keyboard-interactive login off; public key only (or Tailscale identity) |
| Root account compromise over SSH | `PermitRootLogin no`; admin uses sudo |
| Other tailnet devices probing the server | Netfilter `nodivert` makes ufw filter tailnet traffic (only SSH allowed); the printed policy limits SSH to tailnet admins |
| A compromised device on the home/office LAN | LAN SSH is off by default; when on, it is limited to one private subnet or one IP, still key-only, plus fail2ban |
| A cloud-init drop-in re-enabling passwords | Our `00-` drop-in is read first; verify checks the effective value with `sshd -T` |
| Docker bypassing the firewall | Detected and warned about; opt-in `DOCKER-USER` rules |
| Unpatched vulnerabilities | Daily unattended security upgrades |
| Silent changes to accounts, sudo or SSH config | auditd watches with search keys (`ausearch -k sshd`) |
| Locking yourself out while hardening | Rollback timer, confirmation from a new login, immediate rollback on failure |
| Secrets leaking through the script | Auth keys are read hidden and passed by file; never logged, never saved in answers |

## Not addressed

- Vulnerabilities in the services you expose publicly (web apps, databases). Harden and patch them separately.
- A compromised Tailscale admin account or a stolen, unprotected SSH key.
- Physical attacks, malicious hypervisors or cloud providers.
- Data loss: there are no backups of your data.
- Local privilege escalation beyond the kernel settings applied.
- Compliance certification (CIS, PCI, etc.).
