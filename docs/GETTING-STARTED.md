# Getting started: a step-by-step guide

This guide walks you through your first run of secure-this-host, from making an SSH key to the final PASS/FAIL report. It assumes no prior experience. Plan on about 30 minutes.

> [!TIP]
> Practice on a test virtual machine first (VirtualBox, UTM, Multipass, or a cheap cloud server you can delete). Then run it on a server you care about.

**Contents**

1. [What you need](#what-you-need)
2. [Make an SSH key on your computer](#1-make-an-ssh-key-on-your-computer)
3. [Put the key on the server and test it](#2-put-the-key-on-the-server-and-test-it)
4. [Make sure you can log in at the console](#3-make-sure-you-can-log-in-at-the-console)
5. [Take a snapshot](#4-take-a-snapshot)
6. [Set up Tailscale on your computer](#5-set-up-tailscale-on-your-computer)
7. [Get secure-this-host onto the server](#6-get-secure-this-host-onto-the-server)
8. [Do a dry run](#7-do-a-dry-run)
9. [Run it for real](#8-run-it-for-real)
10. [Confirm from a second terminal](#9-confirm-from-a-second-terminal)
11. [Check the result](#10-check-the-result)
12. [If something goes wrong](#if-something-goes-wrong)
13. [Words used in this guide](#words-used-in-this-guide)

---

## What you need

| | What | Why |
|---|---|---|
| 🖥️ | An Ubuntu **24.04 or 26.04 LTS** server you can log in to with `sudo` | The script supports these releases only |
| 💻 | **Your own computer** (Windows, macOS or Linux) | You'll make your SSH key and log in from here |
| 🔑 | An **SSH key** | Password logins get turned off |
| 🌐 | A free **Tailscale account**, with the Tailscale app on your computer | After hardening, SSH only works over Tailscale |
| 🛟 | **Backup access** with a password: the provider's web console, or a keyboard and screen | Your way in if SSH and Tailscale both fail |

---

## 1. Make an SSH key on your computer

An SSH key is a pair of files. The **private key** stays on your computer and proves who you are. The **public key** goes on the server. Make the key on **your computer**, not on the server.

**macOS or Linux:** open Terminal. **Windows 10/11:** open PowerShell (OpenSSH is built in).

```bash
ssh-keygen -t ed25519 -C "you@example.com"
```

- `-t ed25519` picks a modern, short, strong key type.
- `-C "you@example.com"` is only a label so you can tell keys apart later. Your email works, or something like `"laptop-2026"`.
- Press **Enter** to accept the default file location.
- **Type a passphrase** when asked. It protects the key if your computer is ever lost or stolen.

This creates two files in the `.ssh` folder of your home directory:

| File | What it is | Share it? |
|---|---|---|
| `id_ed25519` | Private key | ❌ **Never.** Don't paste, email or upload it anywhere. |
| `id_ed25519.pub` | Public key | ✅ Yes. This is what servers need. |

> [!CAUTION]
> If a file or message contains `PRIVATE KEY`, it's the private key. Stop and don't share it. The script refuses private keys if you paste one by mistake.

To show your **public** key:

```bash
cat ~/.ssh/id_ed25519.pub                       # macOS / Linux
type $env:USERPROFILE\.ssh\id_ed25519.pub       # Windows PowerShell
```

It's one line that starts with `ssh-ed25519`.

> [!TIP]
> Tired of typing your passphrase? Add the key to your SSH agent once per login session: `ssh-add ~/.ssh/id_ed25519`. On Windows the agent service is off by default; turn it on in an **administrator** PowerShell with `Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent`.

---

## 2. Put the key on the server and test it

The script can install your key for you (it asks you to paste it). It's still worth doing this first: it proves key login works **before** passwords are switched off.

**macOS / Linux:**

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub you@SERVER_IP
```

**Windows PowerShell:**

```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh you@SERVER_IP "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

Now **test it**:

```bash
ssh you@SERVER_IP
```

It should ask for your **key passphrase** (or nothing, if the agent has it), **not** the server password. If it asks for the server password, the key isn't working yet. Fix that before going on.

---

## 3. Make sure you can log in at the console

A console is the provider's web, serial or recovery console for a cloud server, or a keyboard and screen for a home or office server. It doesn't use SSH, so **SSH keys don't work there; you need a password.**

Many cloud images create the default account (often `ubuntu`) with **no password**. Then the console can't help you. Set one now:

```bash
sudo passwd $USER
```

> [!IMPORTANT]
> Test it: open the console and log in with that username and password. If you can't, your safety net has a hole. The script also checks this and offers to set a password if your admin account has none.

---

## 4. Take a snapshot

If your provider or hypervisor supports snapshots, take one now. It's the fastest way back to "before" if anything surprises you. secure-this-host also backs up every file it changes, but a snapshot covers everything.

---

## 5. Set up Tailscale on your computer

Tailscale makes a private network (your **tailnet**) between your devices. After hardening, the server only accepts SSH over this network. You don't need to install anything on the server: the script does that.

1. Sign up at **[tailscale.com](https://tailscale.com)** with Google, Microsoft, GitHub, Apple or another provider.
2. **Turn on two-factor login** for that account at your provider. That login now controls admin access to your server.
3. Install the Tailscale app on **your computer** from **[tailscale.com/download](https://tailscale.com/download)** and sign in.
4. Check it's connected: the app shows **Connected**, or run `tailscale status`.

> [!NOTE]
> With MagicDNS (on by default), you can reach devices by name, for example `ssh you@myserver`, instead of a `100.x.y.z` address.

---

## 6. Get secure-this-host onto the server

**With git** (on the server):

```bash
sudo apt install -y git
git clone https://github.com/jermsmit/secure-this-host
cd secure-this-host
```

**Or copy the zip** from your computer, then unzip it on the server:

```bash
scp secure-this-host.zip you@SERVER_IP:~      # on your computer
sudo apt install -y unzip                     # on the server
unzip secure-this-host.zip && cd secure-this-host
```

> [!NOTE]
> Keep the `lib/` folder next to `secure-this-host.sh`. The script needs it.

---

## 7. Do a dry run

A dry run asks all the questions and shows every change it **would** make, without changing anything:

```bash
sudo ./secure-this-host.sh --dry-run
```

Read through the questions and the plan. Every question has a safe default in `[brackets]`. Press **Enter** to accept it.

---

## 8. Run it for real

> [!TIP]
> Optional but handy: start a `tmux` session first (`tmux new -s sth`). If your connection drops, log back in and run `tmux attach -t sth` to pick up where you were. The rollback timer protects you either way.

```bash
sudo ./secure-this-host.sh
```

Along the way:

- **Review screen.** Nothing has changed yet. Type `y` to apply.
- **Access policy.** The script prints a block of text starting with `{`. In the Tailscale admin console, open **Access controls**, paste it in (merge it with what's there), save, then press **Enter** in the terminal.
- **Login link.** Open the link it shows on any device and sign in. This adds the server to your tailnet.
- **Confirmation code.** At the end it shows a 6-character code and waits. **Leave this window open.**

---

## 9. Confirm from a second terminal

This step proves you can still get in. Keep the first window open, and open a **new** terminal on your computer:

```text
 ┌─ Terminal 1 (the installer) ──────────┐   ┌─ Terminal 2 (new) ──────────────────────┐
 │ ==> Prove you can still log in         │   │ $ ssh you@myserver                      │
 │   sudo sth confirm K7P3QX              │   │ you@myserver:~$ sudo sth confirm K7P3QX │
 │ (waiting...)                           │   │ ✓ Confirmed.                            │
 │ ✓ Confirmed from a new login           │   │                                         │
 └────────────────────────────────────────┘   └─────────────────────────────────────────┘
```

> [!WARNING]
> Confirming from the installer's own window is refused, because it proves nothing. If you can't log in from the new terminal, **do nothing**: after 5 minutes every change is undone automatically, and you can try again.

---

## 10. Check the result

The installer prints a report when it finishes. Run it again any time:

```bash
sudo sth verify
```

| Result | Meaning |
|---|---|
| **PASS** | Checked and correct |
| **FAIL** | Not as expected; the message says what to look at |
| **WARN** | Worth knowing, not a failure (e.g. a reboot is pending) |

---

## If something goes wrong

| What you see | What to do |
|---|---|
| Can't log in from the new terminal | Wait 5 minutes for the automatic rollback, then check Tailscale is connected on your computer and try again |
| `tailscale up failed` … `tags` | The access policy wasn't saved, or doesn't contain `tag:server`. Paste it again in **Access controls** and re-run |
| `That code doesn't match` | Copy the 6-character code exactly as the installer's window shows it |
| `Confirm from a NEW login` | You ran confirm in the installer's window. Use a second terminal |
| Locked out completely | Log in at the console with your password and run `sudo sth rollback` |
| Want to undo everything | `sudo sth uninstall` removes every file and firewall rule secure-this-host added |

---

## Words used in this guide

| Word | Meaning |
|---|---|
| **SSH** | The standard way to log in to a Linux server remotely |
| **SSH key** | A pair of files that proves who you are without a password |
| **Tailnet** | Your private Tailscale network of devices |
| **Tag** | A label (`tag:server`) that access rules can target |
| **Access policy (ACL)** | The rules in Tailscale's admin console that say who may reach what |
| **ufw** | Ubuntu's firewall tool |
| **Console** | A way to log in that doesn't use the network: the provider's web console, or a keyboard and screen |
| **Rollback** | Putting every changed file and setting back the way it was |

---

Created by [jermsmit](https://github.com/jermsmit) · [secure-this-host](https://github.com/jermsmit/secure-this-host) · MIT License
