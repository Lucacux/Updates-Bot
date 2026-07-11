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
    - check_group:  grupo Ansible contra el que corre `ansible <grupo> -m shell`.
    - pkg_key:      clave del host en el dict `packages` y en history.json.
                    Se mantiene 'arch'/'ubuntu' por compatibilidad con el
                    historial ya escrito.
    - target:       valor de `!update run <target>` que apunta a este host.
    - playbook:     playbook de un solo host para ese target.
    - play_marker:  substring del output que indica que arrancó la PLAY de este
                    host (para el estado "en progreso" en vivo).
    """
    name: str
    short: str
    flavor: str
    check_group: str
    pkg_key: str
    target: str
    playbook: str
    play_marker: str


HOSTS = [
    Host(
        name='server-mbp', short='mbp', flavor='pacman',
        check_group='arch', pkg_key='arch', target='arch',
        playbook='update_arch.yml', play_marker='PLAY [Update Arch',
    ),
    Host(
        name='pentium', short='pentium', flavor='apt',
        check_group='ubuntu', pkg_key='ubuntu', target='ubuntu',
        playbook='update_ubuntu.yml', play_marker='PLAY [Update Ubuntu',
    ),
]

ALL_PLAYBOOK = 'update_all.yml'

# Mapas derivados que usan los comandos (target -> playbook / label del target).
HOST_BY_KEY = {h.pkg_key: h for h in HOSTS}
PLAYBOOKS = {'all': ALL_PLAYBOOK, **{h.target: h.playbook for h in HOSTS}}
TARGETS_STR = {'all': ' + '.join(h.name for h in HOSTS), **{h.target: h.name for h in HOSTS}}
