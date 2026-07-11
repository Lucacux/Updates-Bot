"""Cog con las tareas automáticas y el arranque.

- on_ready: arranca los loops y manda el embed de "ONLINE".
- check_updates_task: 10:00, reporta pendientes sin instalar nada.
- daily_auto_update: UPDATE_HOUR (default 12:00), corre el playbook completo.
"""
from datetime import datetime

import discord
from discord.ext import commands, tasks

import config
import reporting
from playbooks import check_pending_updates


class UpdateTasks(commands.Cog):
    def __init__(self, bot, runner):
        self.bot = bot
        self.runner = runner

    def cog_unload(self):
        self.daily_auto_update.cancel()
        self.check_updates_task.cancel()

    @commands.Cog.listener()
    async def on_ready(self):
        print(f'Updates-Bot ONLINE: {self.bot.user}')
        if not self.daily_auto_update.is_running():
            self.daily_auto_update.start()
        if not self.check_updates_task.is_running():
            self.check_updates_task.start()
        channel = self.bot.get_channel(config.CHANNEL_ID)
        if channel:
            embed = discord.Embed(
                title='🤖 Updates-Bot ONLINE',
                description='Bot de actualizaciones listo.',
                color=0x2ecc71,
                timestamp=datetime.now()
            )
            embed.add_field(name='Comandos', value=(
                '`!update check` — paquetes pendientes\n'
                f'`!update run [{config.RUN_TARGETS_HINT}]` — ejecutar update\n'
                '`!update status` — estado actual\n'
                '`!update history` — historial de updates\n'
                '`!update log <id>` — ver log de un update\n'
                '`!update next` — próximo update automático'
            ), inline=False)
            embed.add_field(
                name='⏰ Update automático',
                value=f'Todos los días a las {config.UPDATE_HOUR:02d}:00',
                inline=False
            )
            await channel.send(embed=embed)

    @tasks.loop(minutes=1)
    async def check_updates_task(self):
        """
        Corre a las 10:00 todos los días.
        Solo reporta paquetes pendientes sin instalar nada.
        """
        now = datetime.now()
        if now.hour != 10 or now.minute != 0:
            return
        channel = self.bot.get_channel(config.CHANNEL_ID)
        if not channel:
            return

        pending = await check_pending_updates()
        total = sum(len(pending[h.pkg_key]) for h in config.HOSTS)

        if total == 0:
            return

        embed = discord.Embed(
            title=f'📋 Reporte diario — ⚠️ {total} pendientes',
            color=0xe67e22,
            timestamp=datetime.now()
        )
        reporting.add_pending_fields(embed, pending, with_raw=False, show_overflow=False)
        embed.set_footer(text='El update automático corre a las 12:00.')
        await channel.send(embed=embed)

    @tasks.loop(minutes=1)
    async def daily_auto_update(self):
        """
        Corre todos los días a UPDATE_HOUR (default 12:00).
        Siempre ejecuta el playbook completo, sin verificar pendientes antes.
        """
        now = datetime.now()
        if now.hour != config.UPDATE_HOUR or now.minute != 0:
            return

        channel = self.bot.get_channel(config.CHANNEL_ID)
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

        success, duration, packages = await self.runner.run(config.ALL_PLAYBOOK, status_msg=msg)

        mins, secs = duration // 60, duration % 60

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
        reporting.add_result_fields(result_embed, packages)
        await msg.edit(embed=result_embed)
