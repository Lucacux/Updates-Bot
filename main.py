# deploy-test 2026-07-08: no-op para validar auto-update por timer (desatendido). Seguro de borrar.
import discord
from discord.ext import commands, tasks
import asyncio
import subprocess
import json
import os
import re
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv('DISCORD_TOKEN')
CHANNEL_ID = int(os.getenv('DISCORD_CHANNEL_ID'))
UPDATE_HOUR = int(os.getenv('UPDATE_HOUR', '12'))

ANSIBLE_DIR = os.path.expanduser('~/discord-bot-updates/ansible')
HISTORY_FILE = os.path.expanduser('~/discord-bot-updates/history.json')
LOGS_DIR = os.path.expanduser('~/discord-bot-updates/logs')
os.makedirs(LOGS_DIR, exist_ok=True)

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

update_running = False

# ==========================================
# HISTORIAL Y LOGS
# ==========================================
def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE) as f:
        return json.load(f)

def save_history(entry):
    history = load_history()
    history.append(entry)
    history = history[-20:]
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def save_log(timestamp_str, content):
    filename = os.path.join(LOGS_DIR, f'update_{timestamp_str}.log')
    with open(filename, 'w') as f:
        f.write(content)
    return filename

# ==========================================
# HELPERS
# ==========================================
async def check_pending_updates():
    pending = {'arch': [], 'ubuntu': [], 'arch_raw': '', 'ubuntu_raw': ''}

    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ['ansible', 'arch', '-m', 'shell',
             '-a', 'pacman -Sy --noconfirm -q 2>/dev/null; pacman -Qu 2>/dev/null || echo "NO_UPDATES"'],
            capture_output=True, text=True, cwd=ANSIBLE_DIR
        )
        raw = ''
        if '>>' in result.stdout:
            raw = result.stdout.split('>>', 1)[1].strip()
        else:
            raw = result.stdout.strip()

        pending['arch_raw'] = raw
        lines = [l.strip() for l in raw.splitlines() if ' -> ' in l]
        pending['arch'] = lines
    except Exception as e:
        pending['arch_raw'] = f'Error: {e}'

    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ['ansible', 'ubuntu', '-m', 'shell',
             '-a', 'apt-get update -qq 2>/dev/null; apt list --upgradable 2>/dev/null | grep -v "^Listing" || echo "NO_UPDATES"'],
            capture_output=True, text=True, cwd=ANSIBLE_DIR
        )
        raw = ''
        if '>>' in result.stdout:
            raw = result.stdout.split('>>', 1)[1].strip()
        else:
            raw = result.stdout.strip()

        pending['ubuntu_raw'] = raw
        lines = []
        for l in raw.splitlines():
            if '/' in l and '[upgradable' in l:
                pkg_name = l.split('/')[0].strip()
                if pkg_name:
                    lines.append(pkg_name)
        pending['ubuntu'] = lines
    except Exception as e:
        pending['ubuntu_raw'] = f'Error: {e}'

    return pending

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
    host_key = 'server-mbp' if host_type == 'arch' else 'pentium'

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

async def run_playbook(playbook, status_msg=None):
    global update_running
    update_running = True
    start = datetime.now()
    timestamp_str = start.strftime('%Y%m%d_%H%M%S')
    full_output = []

    try:
        proc = await asyncio.create_subprocess_exec(
            'ansible-playbook', f'playbooks/{playbook}', '-v',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=ANSIBLE_DIR
        )

        current_host = None
        current_task = None
        results = {'arch': [], 'ubuntu': []}
        last_edit = datetime.now()

        async def refresh_status():
            if not status_msg or not current_host or not current_task:
                return
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

            if 'PLAY [Update Arch' in decoded:
                current_host = 'server-mbp'
            elif 'PLAY [Update Ubuntu' in decoded:
                current_host = 'pentium'
            if 'TASK [' in decoded:
                current_task = decoded.split('TASK [')[1].split(']')[0]

            if status_msg and (datetime.now() - last_edit).seconds >= 15:
                await refresh_status()
                last_edit = datetime.now()

        await proc.wait()
        duration = (datetime.now() - start).seconds
        success = proc.returncode == 0

        results['arch'] = parse_upgraded_packages(full_output, 'arch')
        results['ubuntu'] = parse_upgraded_packages(full_output, 'ubuntu')

        log_content = '\n'.join(full_output)
        log_file = save_log(timestamp_str, log_content)

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
        update_running = False

# ==========================================
# EVENTOS
# ==========================================
@bot.event
async def on_ready():
    print(f'Updates-Bot ONLINE: {bot.user}')
    if not daily_auto_update.is_running():
        daily_auto_update.start()
    if not check_updates_task.is_running():
        check_updates_task.start()
    channel = bot.get_channel(CHANNEL_ID)
    if channel:
        embed = discord.Embed(
            title='🤖 Updates-Bot ONLINE',
            description='Bot de actualizaciones listo.',
            color=0x2ecc71,
            timestamp=datetime.now()
        )
        embed.add_field(name='Comandos', value=(
            '`!update check` — paquetes pendientes\n'
            '`!update run [arch|ubuntu|all]` — ejecutar update\n'
            '`!update status` — estado actual\n'
            '`!update history` — historial de updates\n'
            '`!update log <id>` — ver log de un update\n'
            '`!update next` — próximo update automático'
        ), inline=False)
        embed.add_field(
            name='⏰ Update automático',
            value=f'Todos los días a las {UPDATE_HOUR:02d}:00',
            inline=False
        )
        await channel.send(embed=embed)

# ==========================================
# COMANDOS
# ==========================================
@bot.group(name='update', invoke_without_command=True)
async def update_group(ctx):
    await ctx.send('Usá `!update check`, `!update run`, `!update status`, `!update history`, `!update log <id>` o `!update next`.')

@update_group.command(name='status')
async def update_status(ctx):
    if update_running:
        embed = discord.Embed(
            title='⚙️ Update en progreso',
            description='Hay un update corriendo ahora mismo.',
            color=0xe67e22
        )
    else:
        embed = discord.Embed(
            title='✅ Sin updates en curso',
            description='No hay ningún update corriendo.',
            color=0x2ecc71
        )
    await ctx.send(embed=embed)

@update_group.command(name='check')
async def update_check(ctx):
    msg = await ctx.send('🔍 Sincronizando bases de datos y verificando paquetes...')
    pending = await check_pending_updates()
    arch_pkgs = pending['arch']
    ubuntu_pkgs = pending['ubuntu']
    total = len(arch_pkgs) + len(ubuntu_pkgs)

    embed = discord.Embed(
        title='✅ Todo actualizado' if total == 0 else f'📦 {total} actualizaciones pendientes',
        color=0x2ecc71 if total == 0 else 0xe67e22,
        timestamp=datetime.now()
    )

    if arch_pkgs:
        sec, norm = classify_packages(arch_pkgs)
        val = ''
        if sec:
            val += '🔴 **Seguridad:**\n' + '\n'.join(f'`{p}`' for p in sec[:5]) + '\n'
        if norm:
            val += '🟡 **Normal:**\n' + '\n'.join(f'`{p}`' for p in norm[:5])
        if len(arch_pkgs) > 10:
            val += f'\n_...y {len(arch_pkgs) - 10} más_'
        embed.add_field(name=f'🖥 server-mbp ({len(arch_pkgs)} pendientes)', value=val, inline=False)
    else:
        raw = pending['arch_raw']
        confirm = raw if raw and raw != 'NO_UPDATES' else 'Sin actualizaciones pendientes.'
        embed.add_field(
            name='🖥 server-mbp ✅',
            value=f'```\n{confirm[:300]}\n```',
            inline=False
        )

    if ubuntu_pkgs:
        sec, norm = classify_packages(ubuntu_pkgs)
        val = ''
        if sec:
            val += '🔴 **Seguridad:**\n' + '\n'.join(f'`{p}`' for p in sec[:5]) + '\n'
        if norm:
            val += '🟡 **Normal:**\n' + '\n'.join(f'`{p}`' for p in norm[:5])
        if len(ubuntu_pkgs) > 10:
            val += f'\n_...y {len(ubuntu_pkgs) - 10} más_'
        embed.add_field(name=f'🖥 pentium ({len(ubuntu_pkgs)} pendientes)', value=val, inline=False)
    else:
        raw = pending['ubuntu_raw']
        confirm = raw if raw and raw != 'NO_UPDATES' else 'Sin actualizaciones pendientes.'
        embed.add_field(
            name='🖥 pentium ✅',
            value=f'```\n{confirm[:300]}\n```',
            inline=False
        )

    await msg.edit(content=None, embed=embed)

@update_group.command(name='run')
async def update_run(ctx, target: str = 'all'):
    global update_running
    if update_running:
        return await ctx.send('⚠️ Ya hay un update en curso. Usá `!update status`.')

    playbooks = {
        'all': 'update_all.yml',
        'arch': 'update_arch.yml',
        'ubuntu': 'update_ubuntu.yml'
    }
    if target not in playbooks:
        return await ctx.send('❌ Target inválido. Usá `all`, `arch` o `ubuntu`.')

    targets_str = {
        'all': 'server-mbp + pentium',
        'arch': 'server-mbp',
        'ubuntu': 'pentium'
    }

    embed = discord.Embed(
        title='🔄 Update iniciado',
        description=f'Actualizando **{targets_str[target]}**...',
        color=0x3498db,
        timestamp=datetime.now()
    )
    embed.set_footer(text='El mensaje se actualizará cada 15 segundos.')
    msg = await ctx.send(embed=embed)

    success, duration, packages = await run_playbook(playbooks[target], status_msg=msg)

    mins, secs = duration // 60, duration % 60
    duration_str = f'{mins}m {secs}s' if mins > 0 else f'{secs}s'

    history = load_history()
    past = [h for h in history[:-1] if h.get('playbook') == playbooks[target] and h.get('success')]
    avg_str = ''
    if past:
        avg = sum(h['duration'] for h in past[-5:]) // len(past[-5:])
        avg_mins, avg_secs = avg // 60, avg % 60
        avg_str = f'{avg_mins}m {avg_secs}s' if avg_mins > 0 else f'{avg_secs}s'

    result_embed = discord.Embed(
        title='✅ Update completado' if success else '❌ Update fallido',
        color=0x2ecc71 if success else 0xe74c3c,
        timestamp=datetime.now()
    )
    result_embed.add_field(name='⏱ Duración', value=duration_str, inline=True)
    if avg_str:
        result_embed.add_field(name='📊 Promedio histórico', value=avg_str, inline=True)

    arch_val, _ = format_packages(packages['arch'])
    ubuntu_val, _ = format_packages(packages['ubuntu'])

    result_embed.add_field(name='🖥 server-mbp', value=arch_val, inline=False)
    result_embed.add_field(name='🖥 pentium', value=ubuntu_val, inline=False)
    await msg.edit(embed=result_embed)

@update_group.command(name='history')
async def update_history(ctx):
    history = load_history()
    if not history:
        return await ctx.send('📭 Sin historial todavía.')
    embed = discord.Embed(
        title='📋 Historial de updates',
        description='Usá `!update log <id>` para ver el log completo de cada entrada.',
        color=0x3498db,
        timestamp=datetime.now()
    )
    recent = list(reversed(history[-8:]))
    for i, entry in enumerate(recent, start=1):
        ts = datetime.fromisoformat(entry['timestamp']).strftime('%d/%m %H:%M')
        duration = entry.get('duration', 0)
        mins, secs = duration // 60, duration % 60
        dur_str = f'{mins}m {secs}s' if mins > 0 else f'{secs}s'
        status = '✅' if entry.get('success') else '❌'
        pkgs_arch = len(entry.get('packages', {}).get('arch', []))
        pkgs_ubuntu = len(entry.get('packages', {}).get('ubuntu', []))
        embed.add_field(
            name=f'{status} #{i} — {ts}',
            value=f'⏱ `{dur_str}` | mbp: `{pkgs_arch} pkgs` | pentium: `{pkgs_ubuntu} pkgs`',
            inline=False
        )
    await ctx.send(embed=embed)

@update_group.command(name='log')
async def update_log(ctx, entry_id: int):
    history = load_history()
    if not history:
        return await ctx.send('📭 Sin historial todavía.')

    # El ID que ve el usuario en !update history es 1-based desde el más reciente
    recent = list(reversed(history[-8:]))
    if entry_id < 1 or entry_id > len(recent):
        return await ctx.send(f'❌ ID inválido. Usá un número entre 1 y {len(recent)}.')

    entry = recent[entry_id - 1]
    log_file = os.path.join(LOGS_DIR, entry.get('log_file', ''))

    if not entry.get('log_file') or not os.path.exists(log_file):
        return await ctx.send('❌ No hay archivo de log para esta entrada.')

    with open(log_file) as f:
        content = f.read()

    ts = datetime.fromisoformat(entry['timestamp']).strftime('%d/%m %H:%M')
    status = '✅' if entry.get('success') else '❌'

    # Discord tiene límite de 2000 chars por mensaje.
    # Mostramos el final del log donde están los resultados importantes.
    MAX_CHARS = 1800
    if len(content) > MAX_CHARS:
        snippet = '...[truncado — se muestra el final]\n' + content[-MAX_CHARS:]
    else:
        snippet = content

    await ctx.send(
        f'**{status} Log #{entry_id} — {ts}** (`{entry["log_file"]}`)\n'
        f'```\n{snippet}\n```'
    )

@update_group.command(name='next')
async def update_next(ctx):
    now = datetime.now()
    next_update = now.replace(hour=UPDATE_HOUR, minute=0, second=0, microsecond=0)
    if now >= next_update:
        next_update += timedelta(days=1)

    delta = next_update - now
    hours = delta.seconds // 3600
    mins = (delta.seconds % 3600) // 60

    msg = await ctx.send('🔍 Verificando pendientes...')
    pending = await check_pending_updates()

    embed = discord.Embed(
        title='⏰ Próximo update automático',
        color=0x3498db,
        timestamp=datetime.now()
    )
    embed.add_field(
        name='📅 Fecha',
        value=next_update.strftime('%A %d/%m a las %H:%M'),
        inline=False
    )
    embed.add_field(name='⏳ Tiempo restante', value=f'{delta.days}d {hours}h {mins}m', inline=True)
    embed.add_field(
        name='📦 Pendientes ahora',
        value=f'server-mbp: `{len(pending["arch"])}` | pentium: `{len(pending["ubuntu"])}`',
        inline=False
    )
    await msg.edit(content=None, embed=embed)

# ==========================================
# TAREAS AUTOMÁTICAS
# ==========================================

@tasks.loop(minutes=1)
async def check_updates_task():
    """
    Corre a las 10:00 todos los días.
    Solo reporta paquetes pendientes sin instalar nada.
    """
    now = datetime.now()
    if now.hour != 10 or now.minute != 0:
        return
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        return

    pending = await check_pending_updates()
    arch_pkgs = pending['arch']
    ubuntu_pkgs = pending['ubuntu']
    total = len(arch_pkgs) + len(ubuntu_pkgs)

    if total == 0:
        return

    embed = discord.Embed(
        title=f'📋 Reporte diario — ⚠️ {total} pendientes',
        color=0xe67e22,
        timestamp=datetime.now()
    )

    if arch_pkgs:
        sec, norm = classify_packages(arch_pkgs)
        val = ''
        if sec:
            val += '🔴 **Seguridad:**\n' + '\n'.join(f'`{p}`' for p in sec[:5]) + '\n'
        if norm:
            val += '🟡 **Normal:**\n' + '\n'.join(f'`{p}`' for p in norm[:5])
        embed.add_field(name=f'🖥 server-mbp ({len(arch_pkgs)} pendientes)', value=val, inline=False)
    else:
        embed.add_field(name='🖥 server-mbp ✅', value='Sin actualizaciones pendientes.', inline=False)

    if ubuntu_pkgs:
        sec, norm = classify_packages(ubuntu_pkgs)
        val = ''
        if sec:
            val += '🔴 **Seguridad:**\n' + '\n'.join(f'`{p}`' for p in sec[:5]) + '\n'
        if norm:
            val += '🟡 **Normal:**\n' + '\n'.join(f'`{p}`' for p in norm[:5])
        embed.add_field(name=f'🖥 pentium ({len(ubuntu_pkgs)} pendientes)', value=val, inline=False)
    else:
        embed.add_field(name='🖥 pentium ✅', value='Sin actualizaciones pendientes.', inline=False)

    embed.set_footer(text='El update automático corre a las 12:00.')
    await channel.send(embed=embed)


@tasks.loop(minutes=1)
async def daily_auto_update():
    """
    Corre todos los días a UPDATE_HOUR (default 12:00).
    Siempre ejecuta el playbook completo, sin verificar pendientes antes.
    """
    now = datetime.now()
    if now.hour != UPDATE_HOUR or now.minute != 0:
        return

    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        return

    embed = discord.Embed(
        title='🤖 Update diario automático iniciado',
        description='Actualizando todos los servidores...',
        color=0x3498db,
        timestamp=datetime.now()
    )
    embed.set_footer(text='El mensaje se actualizará cada 15 segundos.')
    msg = await channel.send(embed=embed)

    success, duration, packages = await run_playbook('update_all.yml', status_msg=msg)

    mins, secs = duration // 60, duration % 60
    arch_val, _ = format_packages(packages['arch'])
    ubuntu_val, _ = format_packages(packages['ubuntu'])

    # Obtener el ID del log recién guardado (última entrada del historial)
    history = load_history()
    log_id = len(history)  # es la entrada más reciente, ID #1 en !update history

    result_embed = discord.Embed(
        title='✅ Update diario completado' if success else '❌ Update diario fallido',
        color=0x2ecc71 if success else 0xe74c3c,
        timestamp=datetime.now()
    )
    result_embed.add_field(
        name='⏱ Duración',
        value=f'{mins}m {secs}s' if mins > 0 else f'{secs}s',
        inline=True
    )
    result_embed.add_field(
        name='📄 Log',
        value=f'`!update log 1`',
        inline=True
    )
    result_embed.add_field(name='🖥 server-mbp', value=arch_val, inline=False)
    result_embed.add_field(name='🖥 pentium', value=ubuntu_val, inline=False)
    await msg.edit(embed=result_embed)


bot.run(TOKEN)
