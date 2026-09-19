# 🔄 Updates-Bot

![Updates-Bot Banner](./assets/banner.png)

A Discord bot that orchestrates system updates across multiple homelab servers via Ansible, with real-time progress reporting.

## ✨ Key Features

- **Ansible playbook execution:** triggers package updates on managed nodes from a Discord command.
- **Live progress embeds:** updates the Discord message in real time while the playbook runs, instead of only reporting on completion.
- **Per-run logs:** saves an independent log for each run for later auditing.
- **Phased update detection:** supports Ubuntu's phased update rollout system, avoiding false negatives when a package hasn't yet been released to a given machine.
- **WOL-aware daily orchestration:** before the 12:00 sweep, asks WOL-Bot to reserve and wake the NAS/homeserver with bounded retries, waits for Ansible readiness, and safely skips only the host that never came back.
- **Proxmox in the same sweep:** the hypervisor and its guests update alongside the rest of the fleet. Nothing ever reboots itself — the hypervisor play detects an installed-but-unbooted kernel and the bot reports it, because rebooting there takes every guest down with it.
- **Unregistered LXC alert:** compares `pct list` against the host registry and flags containers that are running but that nobody is updating, so a forgotten LXC doesn't rot silently.

## 🧰 Stack

- Python
- discord.py
- Ansible (invoked as a subprocess or via API)

## 🚀 Installation

```bash
git clone https://github.com/Lucacux/Updates-Bot.git
cd Updates-Bot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
ansible-galaxy collection install -r ansible/requirements.yml
cp .env.example .env  # fill in your real values
cp ansible/inventory/hosts.ini.example ansible/inventory/hosts.ini  # fill in your real hosts
python main.py
```

## ⚙️ Environment Variables

See `.env.example` — bot token, reporting channel, and update schedule.

See `ansible/inventory/hosts.ini.example` — the Ansible inventory: your Arch/Ubuntu/Debian hosts, plus the Proxmox hypervisor and its VM/LXC groups, SSH user, port, and private key path.

### Daily WOL flow

The automatic `all` run coordinates with the local WOL-Bot CLI:

1. Acquire an expiring maintenance lease for `media` and `nas`; WOL-Bot postpones scheduled shutdown while it is active.
2. If a host is offline, send up to three WOL attempts and wait for boot.
3. Confirm the operating system through Ansible `wait_for_connection`.
4. Ping the hosts that never sleep (the Proxmox hypervisor and its guests); an unreachable one is dropped from the run with a reason instead of failing the whole playbook.
5. Run `update_all.yml` with an Ansible `--limit` containing only ready hosts.
6. Release both leases in a `finally` block. If this bot crashes, their TTL still expires automatically.

Proxmox hosts have no `wol_key`, so they skip steps 1–3 and only go through the ping in step 4.

## ➕ Adding a host

Package-manager support (`flavor` in `config.py`) is a small dict entry in `playbooks.py` (`_CHECK`) — `pacman`/`apt`/`apk` today, more can be added the same way. Registering a host is always one `Host(...)` entry in `config.py` plus one inventory line, no other code change. Two recipes, pick based on how safe unattended updates are for that host:

1. **Reuse a target** (a general-purpose box of a flavor already covered): reuse an existing `target` (`arch`/`ubuntu`/`debian`) and add the host to that same inventory group. It rides along with `!update run <target>`, `!update run all`, and the daily auto-update.
2. **New target**: its own playbook and inventory group, and an `import_playbook` line in `update_all.yml` so the daily sweep picks it up. `update_all.yml` imports the per-target playbooks instead of repeating their plays, so there is only ever one definition of how a group updates.
3. **Must never update unattended**: same as 2, but don't import it from `update_all.yml` and add the target to `config.MANUAL_ONLY_TARGETS` so `all` doesn't list it as if the cron touched it. That set is empty today.

LXCs on Proxmox without their own SSH server are reached via `community.proxmox.proxmox_pct_remote` (SSH to the Proxmox host + `pct exec`) — see the `[lxc_alpine]` example in `hosts.ini.example`. The remote user must be able to run `pct` without sudo; when it can't, paramiko reports `Private key file is encrypted`, which is misleading — check that the user exists on the Proxmox host first.

Hosts that live on the Proxmox machine also go into `config.PROXMOX_TARGETS` and `update_proxmox_all.yml`, so `!update run proxmox` updates hypervisor and guests in one command while each still works individually. Guests carry `proxmox_vmid` and `proxmox_kind`; the LXC ones are what `pct list` is compared against to flag unregistered containers.

## 📄 License

Personal infrastructure project — free to use as reference.
