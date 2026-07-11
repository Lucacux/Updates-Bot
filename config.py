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
    # ── Próximo host: laptop Arch server ──────────────────────────────
    # Sumar acá una entrada y su línea en el inventario ([arch] o grupo propio):
    # Host(name='arch-laptop', short='laptop', flavor='pacman',
    #      pkg_key='arch-laptop', target='arch',
    #      playbook='update_arch.yml', play_marker='PLAY [Update Arch'),
    # Comparte target/playbook 'arch' con server-mbp (se actualizan juntos con
    # `!update run arch`) y se reporta como host propio. pkg_key debe ser único.
]

ALL_PLAYBOOK = 'update_all.yml'

# ── Mapas derivados (robustos a varios hosts por target) ───────────────
HOST_BY_KEY = {h.pkg_key: h for h in HOSTS}
# Orden de targets preservando aparición, sin duplicados.
TARGET_KEYS = list(dict.fromkeys(h.target for h in HOSTS))


def _hosts_for(target):
    return [h for h in HOSTS if h.target == target]


PLAYBOOKS = {'all': ALL_PLAYBOOK, **{t: _hosts_for(t)[0].playbook for t in TARGET_KEYS}}
TARGETS_STR = {
    'all': ' + '.join(h.name for h in HOSTS),
    **{t: ' + '.join(h.name for h in _hosts_for(t)) for t in TARGET_KEYS},
}


def _fmt_targets(keys):
    ticked = [f'`{k}`' for k in keys]
    if len(ticked) == 1:
        return ticked[0]
    return ', '.join(ticked[:-1]) + ' o ' + ticked[-1]


# Textos de targets, derivados de HOSTS para que no queden stale al sumar hosts.
VALID_TARGETS_MSG = _fmt_targets(list(PLAYBOOKS))          # `all`, `arch`, `ubuntu` o `debian`
RUN_TARGETS_HINT = '|'.join(TARGET_KEYS + ['all'])         # arch|ubuntu|debian|all
