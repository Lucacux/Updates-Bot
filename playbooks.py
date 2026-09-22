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


def _parse_apk_pending(raw):
    return [l.split()[0] for l in raw.splitlines() if '[upgradable from:' in l]


def _adhoc(host, module, args):
    """Comando `ansible` ad-hoc contra UN host, con become si hace falta.

    Sin become, `pacman -Sy`, `apt-get update` y `pct list` fallan por permisos
    y el error se pierde: el chequeo devuelve un caché viejo o una lista vacía
    en vez de romper. Se subreportaba en silencio, que es el peor modo de falla
    para algo cuyo trabajo es avisar.
    """
    cmd = ['ansible', host.name, '-m', module, '-a', args]
    if host.check_become:
        cmd.append('--become')
    return cmd


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
    'apk': {
        'shell': 'apk update -q 2>/dev/null; '
                 'apk list --upgradable 2>/dev/null || echo "NO_UPDATES"',
        'parse': _parse_apk_pending,
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
                _adhoc(host, 'shell', strat['shell']),
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
# LXC NO REGISTRADOS
# ==========================================
def _parse_pct_list(raw):
    """VMIDs corriendo según `pct list`, como [(vmid, nombre)].

    La salida trae una cabecera y una columna Lock que casi siempre está
    vacía, así que se parsea por posición de los dos primeros campos y el
    nombre se toma del último:

        VMID       Status     Lock         Name
        101        running                 alpine-monitoring
    """
    running = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        if parts[1] != 'running':
            continue
        vmid = int(parts[0])
        name = parts[-1] if len(parts) > 2 else f'vmid {vmid}'
        running.append((vmid, name))
    return running


async def check_unregistered_lxc():
    """LXC corriendo en el Proxmox que nadie sumó al registro de config.

    Sin esto, crear un contenedor y olvidarse de agregarlo al inventario lo
    deja sin actualizar para siempre y sin que nada lo diga. Devuelve
    [(vmid, nombre)]; lista vacía también cuando el chequeo no se pudo hacer
    (no hay host Proxmox registrado, o Ansible no llegó) — es un aviso extra,
    no tiene por qué romper el reporte.

    OJO: `pct list` pide root (habla con pmxcfs por IPC), así que esto depende
    de que el host Proxmox tenga `check_become=True`. Sin become devuelve
    `ipcc_send_rec failed`, rc != 0, y el aviso no se dispara nunca.
    """
    host = config.PROXMOX_HOST
    if host is None:
        return []
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            _adhoc(host, 'shell', 'pct list'),
            capture_output=True, text=True, cwd=config.ANSIBLE_DIR
        )
    except Exception:
        return []
    if result.returncode != 0:
        return []
    raw = result.stdout.split('>>', 1)[1] if '>>' in result.stdout else result.stdout
    return [
        (vmid, name)
        for vmid, name in _parse_pct_list(raw)
        if vmid not in config.REGISTERED_LXC_VMIDS
    ]


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

        # --- Modulo pacman (Arch) y apk (Alpine): campo 'packages' con lista de nombres ---
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


# Lo que imprime la tarea "Detectar si quedó un kernel sin bootear" de
# update_proxmox_host.yml. Se compara contra el `stdout` de la tarea y no
# contra la línea entera, porque el `cmd` que Ansible incluye en el JSON trae
# el script completo — y adentro está el literal.
REBOOT_MARKER = 'REBOOT_REQUIRED'


def parse_reboot_required(output_lines):
    """Hosts que quedaron con un kernel instalado pero sin bootear.

    Nada se reinicia solo: el aviso es para que el reinicio se decida a mano,
    que en el hypervisor significa tirar abajo todos los guests.
    """
    pending = []
    for host in config.HOSTS:
        for line in output_lines:
            if f'[{host.name}]' not in line or '=>' not in line:
                continue
            try:
                data = json.loads(line[line.index('=>') + 2:].strip())
            except (ValueError, json.JSONDecodeError):
                continue
            if str(data.get('stdout', '')).strip() == REBOOT_MARKER:
                pending.append(host.name)
                break
    return pending


# ==========================================
# EJECUCIÓN DE PLAYBOOKS
# ==========================================
def build_playbook_command(playbook, limit_hosts=None):
    cmd = ['ansible-playbook', f'playbooks/{playbook}', '-v']
    if limit_hosts:
        cmd.extend(['--limit', ','.join(limit_hosts)])
    return cmd


class PlaybookRunner:
    """Ejecuta playbooks y lleva el estado 'hay un update corriendo'.

    La reserva cubre también el preflight WOL del update diario. Así un comando
    manual no puede arrancar mientras el automático todavía espera el boot.
    """

    def __init__(self):
        self._running = False

    @property
    def running(self):
        return self._running

    def reserve(self):
        """Reserva el runner antes de un preflight largo (WOL/boot/SSH)."""
        if self._running:
            return False
        self._running = True
        return True

    def release(self):
        self._running = False

    async def run(
        self,
        playbook,
        status_msg=None,
        *,
        limit_hosts=None,
        history_metadata=None,
        reserved=False,
    ):
        """Corre el playbook. Devuelve (success, duración, paquetes, reinicios)."""
        if not reserved and not self.reserve():
            raise RuntimeError('Ya hay un update en curso')
        start = datetime.now()
        timestamp_str = start.strftime('%Y%m%d_%H%M%S')
        full_output = []

        try:
            cmd = build_playbook_command(playbook, limit_hosts)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
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
            reboot_required = parse_reboot_required(full_output)

            log_content = '\n'.join(full_output)
            save_log(timestamp_str, log_content)

            entry = {
                'timestamp': start.isoformat(),
                'playbook': playbook,
                'duration': duration,
                'success': success,
                'packages': results,
                'reboot_required': reboot_required,
                'log_file': f'update_{timestamp_str}.log'
            }
            if history_metadata:
                entry.update(history_metadata)
            save_history(entry)
            return success, duration, results, reboot_required

        finally:
            if not reserved:
                self.release()
