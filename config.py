"""Configuración centralizada: entorno, paths de estado y registro de hosts.

Todos los efectos de import viven acá (leer env, crear LOGS_DIR). Si falta el
token o el channel, el arranque falla con un error claro — igual que antes, pero
explícito. Ningún otro módulo debe leer os.getenv directamente.

El registro HOSTS vuelve data-driven lo que antes estaba cableado como
"arch=server-mbp / ubuntu=pentium" repartido por todo main.py. Agregar un host
es sumar una entrada acá (+ inventario Ansible en el host), no cirugía.
"""
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()

# ── Entorno (error de arranque si falta lo imprescindible) ─────────────
TOKEN = os.getenv('DISCORD_TOKEN')
_CHANNEL_RAW = os.getenv('DISCORD_CHANNEL_ID')
if not TOKEN or not _CHANNEL_RAW:
    raise RuntimeError(
        'Faltan DISCORD_TOKEN y/o DISCORD_CHANNEL_ID en el entorno (.env). '
        'El bot no puede arrancar sin ellos.'
    )
CHANNEL_ID = int(_CHANNEL_RAW)
UPDATE_HOUR = int(os.getenv('UPDATE_HOUR', '12'))

# ── Estado en el host (fuera de git; NO mover ni renombrar) ────────────
ANSIBLE_DIR = os.path.expanduser('~/discord-bot-updates/ansible')
HISTORY_FILE = os.path.expanduser('~/discord-bot-updates/history.json')
LOGS_DIR = os.path.expanduser('~/discord-bot-updates/logs')
os.makedirs(LOGS_DIR, exist_ok=True)


# ── Registro de hosts ──────────────────────────────────────────────────
@dataclass(frozen=True)
class Host:
    """Un host a actualizar. Captura como dato todo lo que antes estaba hardcodeado.

    - name:         nombre de inventario Ansible (aparece como `[name]` en el
                    output del playbook) y nombre visible en los embeds.
    - short:        etiqueta corta usada en `!update history`.
    - flavor:       'pacman' | 'apt'. Determina cómo se chequean pendientes y
                    cómo se parsean los paquetes actualizados.
    - pkg_key:      clave ÚNICA del host en el dict `packages` y en history.json.
                    server-mbp/pentium mantienen 'arch'/'ubuntu' por compat con
                    el historial ya escrito; hosts nuevos usan una clave propia.
    - target:       valor de `!update run <target>`. Varios hosts pueden
                    compartir target (p. ej. dos hosts Arch → target 'arch'):
                    corren el mismo playbook de grupo y se reportan por separado.
    - playbook:     playbook para ese target (los hosts que comparten target
                    comparten playbook, que apunta al grupo Ansible).
    - play_marker:  substring del output que indica que arrancó la PLAY del
                    grupo (para el estado "en progreso" en vivo).

    Nota de escalabilidad: el chequeo de pendientes apunta por HOST (ansible
    <name>), no por grupo, así N hosts del mismo grupo no colisionan.
    """
    name: str
    short: str
    flavor: str
    pkg_key: str
    target: str
    playbook: str
    play_marker: str


HOSTS = [
    Host(
        name='server-mbp', short='mbp', flavor='pacman',
        pkg_key='arch', target='arch',
        playbook='update_arch.yml', play_marker='PLAY [Update Arch',
    ),
    Host(
        name='pentium', short='pentium', flavor='apt',
        pkg_key='ubuntu', target='ubuntu',
        playbook='update_ubuntu.yml', play_marker='PLAY [Update Ubuntu',
    ),
    # sempron@192.168.2.20 — Debian Trixie (apt), grupo Ansible propio [debian].
    Host(
        name='sempron', short='sempron', flavor='apt',
        pkg_key='debian', target='debian',
        playbook='update_debian.yml', play_marker='PLAY [Update Debian',
    ),
    # debian-monitoring@192.168.1.60 — VM Debian en Proxmox (HP Pavilion,
    # 192.168.1.70), corre Prometheus+Grafana. Target propio 'proxmox-debian'
    # (NO 'debian'): un reboot pendiente ahí tumba el monitoreo en silencio,
    # así que queda afuera de `update_all.yml` — solo se actualiza con
    # `!update run proxmox-debian`, nunca por el cron diario ni por `all`.
    Host(
        name='debian-monitoring', short='monitor', flavor='apt',
        pkg_key='monitoring-vm', target='proxmox-debian',
        playbook='update_proxmox_debian.yml', play_marker='PLAY [Update Proxmox Debian',
    ),
    # alpine-monitoring — LXC Alpine (vmid 101) en el mismo Proxmox, sin SSH
    # propio por diseño: Ansible llega vía `community.proxmox.proxmox_pct_remote`
    # (SSH al host Proxmox + `pct exec`), ver ansible/inventory/hosts.ini.example.
    # Mismo motivo que arriba para el target propio 'lxc-alpine' (manual-only).
    Host(
        name='alpine-monitoring', short='alpine', flavor='apk',
        pkg_key='alpine-monitoring', target='lxc-alpine',
        playbook='update_alpine.yml', play_marker='PLAY [Update Alpine',
    ),
    # ── Cómo sumar el próximo host ──────────────────────────────────────
    # Dos recetas según qué tan seguro sea auto-actualizarlo sin supervisión:
    #
    # 1) Recurso más para agregar a la flota normal (ej. otra laptop Arch):
    #    reusar un target EXISTENTE ('arch'/'ubuntu'/'debian') + sumar la
    #    entrada al mismo grupo del inventario. Se actualiza junto con el
    #    resto en `!update run <target>`, `!update run all` y el cron diario.
    #    Host(name='arch-laptop', short='laptop', flavor='pacman',
    #         pkg_key='arch-laptop', target='arch',
    #         playbook='update_arch.yml', play_marker='PLAY [Update Arch'),
    #
    # 2) Host sensible que NO debe rebootear sin supervisión (como los dos de
    #    Proxmox de arriba): target NUEVO con su propio playbook/grupo, sin
    #    tocar `update_all.yml` → solo `!update run <target>` manual.
    #    pkg_key siempre debe ser único en toda la lista.
    #
    # Si varios hosts manual-only conviven en el mismo Proxmox y tiene sentido
    # actualizarlos juntos con un solo comando (sin que eso los meta en el
    # sweep automático), agregalos a MANUAL_ONLY_TARGETS más abajo y sumá su
    # play a update_proxmox_all.yml — así queda `!update run proxmox` además
    # de cada `!update run <target>` individual.
]

ALL_PLAYBOOK = 'update_all.yml'

# ── Mapas derivados (robustos a varios hosts por target) ───────────────
HOST_BY_KEY = {h.pkg_key: h for h in HOSTS}
# Orden de targets preservando aparición, sin duplicados.
TARGET_KEYS = list(dict.fromkeys(h.target for h in HOSTS))


def _hosts_for(target):
    return [h for h in HOSTS if h.target == target]


# Targets manual-only: sus hosts NO están en update_all.yml (a propósito, ver
# los comentarios junto a cada Host de arriba) — 'all' no debe listarlos como
# si el cron diario los tocara.
MANUAL_ONLY_TARGETS = {'proxmox-debian', 'lxc-alpine'}

PLAYBOOKS = {'all': ALL_PLAYBOOK, **{t: _hosts_for(t)[0].playbook for t in TARGET_KEYS}}
TARGETS_STR = {
    'all': ' + '.join(h.name for h in HOSTS if h.target not in MANUAL_ONLY_TARGETS),
    **{t: ' + '.join(h.name for h in _hosts_for(t)) for t in TARGET_KEYS},
}

# Target compuesto manual-only: agrupa los guests de Proxmox para poder
# actualizarlos juntos con `!update run proxmox` sin sumarlos a `update_all.yml`.
# Cada uno sigue siendo corrible por separado con su propio target
# ('proxmox-debian', 'lxc-alpine') — esto es solo una conveniencia extra.
PLAYBOOKS['proxmox'] = 'update_proxmox_all.yml'
TARGETS_STR['proxmox'] = ' + '.join(h.name for h in HOSTS if h.target in MANUAL_ONLY_TARGETS)


def _fmt_targets(keys):
    ticked = [f'`{k}`' for k in keys]
    if len(ticked) == 1:
        return ticked[0]
    return ', '.join(ticked[:-1]) + ' o ' + ticked[-1]


# Textos de targets, derivados de HOSTS para que no queden stale al sumar hosts.
VALID_TARGETS_MSG = _fmt_targets(list(PLAYBOOKS))          # `all`, `arch`, `ubuntu`, `debian` o `proxmox`
RUN_TARGETS_HINT = '|'.join(TARGET_KEYS + ['proxmox', 'all'])  # arch|ubuntu|debian|proxmox|all
