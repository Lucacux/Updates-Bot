# 🔄 Updates-Bot

![Updates-Bot Banner](./assets/banner.png)

A Discord bot that orchestrates system updates across multiple homelab servers via Ansible, with real-time progress reporting.

## ✨ Key Features

- **Ansible playbook execution:** triggers package updates on managed nodes from a Discord command.
- **Live progress embeds:** updates the Discord message in real time while the playbook runs, instead of only reporting on completion.
- **Per-run logs:** saves an independent log for each run for later auditing.
- **Phased update detection:** supports Ubuntu's phased update rollout system, avoiding false negatives when a package hasn't yet been released to a given machine.

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

See `ansible/inventory/hosts.ini.example` — the Ansible inventory: your Arch/Ubuntu/Debian hosts, plus the Proxmox VM/LXC groups, SSH user, port, and private key path.

## ➕ Adding a host

Package-manager support (`flavor` in `config.py`) is a small dict entry in `playbooks.py` (`_CHECK`) — `pacman`/`apt`/`apk` today, more can be added the same way. Registering a host is always one `Host(...)` entry in `config.py` plus one inventory line, no other code change. Two recipes, pick based on how safe unattended updates are for that host:

1. **Fine to sweep automatically** (a general-purpose box you don't mind rebooting on the daily schedule): reuse an existing `target` (`arch`/`ubuntu`/`debian`) and add the host to that same inventory group. It rides along with `!update run <target>`, `!update run all`, and the daily auto-update.
2. **Sensitive — must never update unattended** (e.g. a VM/LXC something else depends on, like a monitoring stack): give it its own `target` with its own playbook/inventory group, and don't reference that group from `update_all.yml`. It only updates via an explicit `!update run <target>`.

LXCs on Proxmox without their own SSH server are reached via `community.proxmox.proxmox_pct_remote` (SSH to the Proxmox host + `pct exec`) — see the `[lxc-alpine]` example in `hosts.ini.example`.

## 📄 License

Personal infrastructure project — free to use as reference.
