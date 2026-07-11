"""Cog con el grupo `!update` y sus subcomandos: status, check, run, history,
log, next. Mismos nombres, firmas y salida que antes."""
import os
from datetime import datetime, timedelta

import discord
from discord.ext import commands

import config
import reporting
from playbooks import check_pending_updates
from storage import load_history


class UpdateCommands(commands.Cog):
    def __init__(self, bot, runner):
        self.bot = bot
        self.runner = runner

    @commands.group(name='update', invoke_without_command=True)
    async def update_group(self, ctx):
        await ctx.send('Usá `!update check`, `!update run`, `!update status`, `!update history`, `!update log <id>` o `!update next`.')

    @update_group.command(name='status')
    async def update_status(self, ctx):
        if self.runner.running:
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
    async def update_check(self, ctx):
        msg = await ctx.send('🔍 Sincronizando bases de datos y verificando paquetes...')
        pending = await check_pending_updates()
        total = sum(len(pending[h.pkg_key]) for h in config.HOSTS)

        embed = discord.Embed(
            title='✅ Todo actualizado' if total == 0 else f'📦 {total} actualizaciones pendientes',
            color=0x2ecc71 if total == 0 else 0xe67e22,
            timestamp=datetime.now()
        )
        reporting.add_pending_fields(embed, pending, with_raw=True, show_overflow=True)
        await msg.edit(content=None, embed=embed)

    @update_group.command(name='run')
    async def update_run(self, ctx, target: str = 'all'):
        if self.runner.running:
            return await ctx.send('⚠️ Ya hay un update en curso. Usá `!update status`.')

        if target not in config.PLAYBOOKS:
            return await ctx.send(f'❌ Target inválido. Usá {config.VALID_TARGETS_MSG}.')

        embed = discord.Embed(
            title='🔄 Update iniciado',
            description=f'Actualizando **{config.TARGETS_STR[target]}**...',
            color=0x3498db,
            timestamp=datetime.now()
        )
        embed.set_footer(text='El mensaje se actualizará cada 15 segundos.')
        msg = await ctx.send(embed=embed)

        success, duration, packages = await self.runner.run(config.PLAYBOOKS[target], status_msg=msg)

        mins, secs = duration // 60, duration % 60
        duration_str = f'{mins}m {secs}s' if mins > 0 else f'{secs}s'

        history = load_history()
        past = [h for h in history[:-1] if h.get('playbook') == config.PLAYBOOKS[target] and h.get('success')]
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

        reporting.add_result_fields(result_embed, packages)
        await msg.edit(embed=result_embed)

    @update_group.command(name='history')
    async def update_history(self, ctx):
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
            embed.add_field(
                name=f'{status} #{i} — {ts}',
                value=f'⏱ `{dur_str}` | {reporting.history_summary(entry)}',
                inline=False
            )
        await ctx.send(embed=embed)

    @update_group.command(name='log')
    async def update_log(self, ctx, entry_id: int):
        history = load_history()
        if not history:
            return await ctx.send('📭 Sin historial todavía.')

        # El ID que ve el usuario en !update history es 1-based desde el más reciente
        recent = list(reversed(history[-8:]))
        if entry_id < 1 or entry_id > len(recent):
            return await ctx.send(f'❌ ID inválido. Usá un número entre 1 y {len(recent)}.')

        entry = recent[entry_id - 1]
        log_file = os.path.join(config.LOGS_DIR, entry.get('log_file', ''))

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
    async def update_next(self, ctx):
        now = datetime.now()
        next_update = now.replace(hour=config.UPDATE_HOUR, minute=0, second=0, microsecond=0)
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
            value=reporting.pending_summary(pending),
            inline=False
        )
        await msg.edit(content=None, embed=embed)
