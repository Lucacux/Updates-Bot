"""Ejecución de Ansible y parsing de resultados.

Concentra todo el acople con Ansible: chequeo de pendientes, ejecución de
playbooks, parseo del output y clasificación/formateo de paquetes. El estado
"hay un update corriendo" queda encapsulado en PlaybookRunner (antes era un
global `update_running` mutado adentro de la función).

No renombrar playbooks ni tocar los markers de parsing (`PLAY [Update Arch`,
`PLAY [Update Ubuntu`, `TASK [`): otras piezas dependen de ellos.
"""
import asyncio
import json
import re
import subprocess
from datetime import datetime

import config
from storage import save_history, save_log


# ==========================================
# CHEQUEO DE PENDIENTES (sin instalar nada)
# ==========================================
# Estrategia por flavor: comando shell + cómo extraer los nombres de paquete.
def _parse_pacman_pending(raw):
    return [l.strip() for l in raw.splitlines() if ' -> ' in l]


def _parse_apt_pending(raw):
    lines = []
    for l in raw.splitlines():
        if '/' in l and '[upgradable' in l:
            pkg_name = l.split('/')[0].strip()
            if pkg_name:
                lines.append(pkg_name)
    return lines


_CHECK = {
    'pacman': {
        'shell': 'pacman -Sy --noconfirm -q 2>/dev/null; '
                 'pacman -Qu 2>/dev/null || echo "NO_UPDATES"',
        'parse': _parse_pacman_pending,
    },
    'apt': {
        'shell': 'apt-get update -qq 2>/dev/null; '
                 'apt list --upgradable 2>/dev/null | grep -v "^Listing" || echo "NO_UPDATES"',
        'parse': _parse_apt_pending,
    },
}


async def check_pending_updates():
    """Devuelve {pkg_key: [paquetes], pkg_key+'_raw': salida cruda} por host."""
    pending = {}
    for host in config.HOSTS:
        pending[host.pkg_key] = []
        pending[f'{host.pkg_key}_raw'] = ''

    for host in config.HOSTS:
        strat = _CHECK[host.flavor]
        try:
            # Apunta por HOST (no por grupo): N hosts del mismo grupo no colisionan
            # en el primer bloque `>>`.
            result = await asyncio.to_thread(
                subprocess.run,
                ['ansible', host.name, '-m', 'shell', '-a', strat['shell']],
                capture_output=True, text=True, cwd=config.ANSIBLE_DIR
            )
            if '>>' in result.stdout:
                raw = result.stdout.split('>>', 1)[1].strip()
            else:
                raw = result.stdout.strip()

            pending[f'{host.pkg_key}_raw'] = raw
            pending[host.pkg_key] = strat['parse'](raw)
        except Exception as e:
            pending[f'{host.pkg_key}_raw'] = f'Error: {e}'

    return pending


# ==========================================
# CLASIFICACIÓN Y FORMATEO DE PAQUETES
# ==========================================
def classify_packages(packages):
    security_keywords = ['security', 'libgnutls', 'openssl', 'openssh', 'libssl',
                         'curl', 'wget', 'sudo', 'polkit', 'systemd']
    security, normal = [], []
    for pkg in packages:
        if any(k in pkg.lower() for k in security_keywords):
            security.append(pkg)
        else:
            normal.append(pkg)
    return security, normal


def format_packages(pkgs, limit=8):
    """
    Formatea una lista de paquetes para mostrar en un embed de Discord.
    Distingue paquetes instalados de los diferidos por phasing.
    Retorna (texto, cantidad_reales) donde cantidad_reales excluye los phased.
    """
    if not pkgs:
        return 'Sin cambios', 0

    real = [p for p in pkgs if not p.endswith('(phased)')]
    phased = [p.replace(' (phased)', '') for p in pkgs if p.endswith('(phased)')]

    lines = []
    shown = 0
    for p in real[:limit]:
        lines.append(f'`{p}`')
        shown += 1
    if len(real) > limit:
        lines.append(f'_...y {len(real) - limit} más_')

    if phased:
        if lines:
            lines.append('')
        lines.append('⏸ **Diferidos (phasing):**')
        for p in phased[:3]:
            lines.append(f'`{p}`')

    if not lines:
        return 'Sin cambios', 0

    return '\n'.join(lines), len(real)


def parse_upgraded_packages(output_lines, host_type):
    """
    Extrae nombres de paquetes actualizados del output de ansible-playbook.

    Ansible escribe el resultado en UNA SOLA LINEA con formato:
      ok: [hostname] => {"changed": true/false, "stdout": "...", ...}

    Para apt: parsea stdout buscando paquetes instalados por dpkg.
    Para pacman: usa el campo 'packages' del modulo pacman de Ansible.
    Tambien detecta paquetes diferidos por phasing de Ubuntu.
    """
    host_key = config.HOST_BY_KEY[host_type].name

    for line in output_lines:
        if f'[{host_key}]' not in line or '=>' not in line:
            continue
        try:
            json_str = line[line.index('=>') + 2:].strip()
            data = json.loads(json_str)
        except (ValueError, json.JSONDecodeError):
            continue

        # --- Modulo pacman (Arch): campo 'packages' con lista de nombres ---
        if 'packages' in data and isinstance(data['packages'], list):
            pkgs = [p for p in data['packages'] if isinstance(p, str) and p.strip()]
            if pkgs:
                return pkgs

        # --- Modulo apt (Ubuntu): parsear stdout ---
        stdout = data.get('stdout', '')
        if not stdout:
            continue

        installed = re.findall(r'Setting up\s+([a-z0-9][a-z0-9.+\-]+)\s+\(', stdout)
        if installed:
            return list(dict.fromkeys(installed))

        phased = re.findall(r'deferred due to phasing:\n((?:\s{2}\S+\n?)+)', stdout)
        if phased:
            names = phased[0].split()
            return [f'{p} (phased)' for p in names if p.strip()]

    return []


# ==========================================
# EJECUCIÓN DE PLAYBOOKS
# ==========================================
class PlaybookRunner:
    """Ejecuta playbooks y lleva el estado 'hay un update corriendo'.

    Encapsula lo que antes era el global `update_running`. `running` es un simple
    flag (no un Lock que bloquee): reproduce exactamente el comportamiento previo
    — `!update run` lo consulta y se niega si está corriendo; el update diario no
    consulta nada y arranca igual.
    """

    def __init__(self):
        self._running = False

    @property
    def running(self):
        return self._running

    async def run(self, playbook, status_msg=None):
        self._running = True
        start = datetime.now()
        timestamp_str = start.strftime('%Y%m%d_%H%M%S')
        full_output = []

        try:
            proc = await asyncio.create_subprocess_exec(
                'ansible-playbook', f'playbooks/{playbook}', '-v',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=config.ANSIBLE_DIR
            )

            current_host = None
            current_task = None
            last_edit = datetime.now()

            async def refresh_status():
                if not status_msg or not current_host or not current_task:
                    return
                import discord
                elapsed = (datetime.now() - start).seconds
                mins, secs = elapsed // 60, elapsed % 60
                dur_str = f'{mins}m {secs}s' if mins > 0 else f'{secs}s'
                embed = discord.Embed(
                    title='⚙️ Update en progreso...',
                    color=0x3498db,
                    timestamp=datetime.now()
                )
                embed.add_field(name='🖥 Host', value=f'`{current_host}`', inline=True)
                embed.add_field(name='📋 Tarea', value=f'`{current_task}`', inline=True)
                embed.add_field(name='⏱ Transcurrido', value=f'`{dur_str}`', inline=True)
                embed.set_footer(text='Se actualiza cada 15s')
                try:
                    await status_msg.edit(embed=embed)
                except Exception:
                    pass

            async for line in proc.stdout:
                decoded = line.decode('utf-8', errors='ignore').strip()
                full_output.append(decoded)

                for host in config.HOSTS:
                    if host.play_marker in decoded:
                        current_host = host.name
                if 'TASK [' in decoded:
                    current_task = decoded.split('TASK [')[1].split(']')[0]

                if status_msg and (datetime.now() - last_edit).seconds >= 15:
                    await refresh_status()
                    last_edit = datetime.now()

            await proc.wait()
            duration = (datetime.now() - start).seconds
            success = proc.returncode == 0

            results = {
                host.pkg_key: parse_upgraded_packages(full_output, host.pkg_key)
                for host in config.HOSTS
            }

            log_content = '\n'.join(full_output)
            save_log(timestamp_str, log_content)

            entry = {
                'timestamp': start.isoformat(),
                'playbook': playbook,
                'duration': duration,
                'success': success,
                'packages': results,
                'log_file': f'update_{timestamp_str}.log'
            }
            save_history(entry)
            return success, duration, results

        finally:
            self._running = False
