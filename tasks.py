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
from availability import automatic_hosts, prepare_daily_fleet, release_maintenance
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
        Corre todos los días a UPDATE_HOUR (default 12:00). Antes del playbook:
        reserva NAS/homeserver contra apagados, intenta WOL con reintentos y
        espera a que Ansible confirme el SO. Los que no vuelven se omiten sin
        hacer fallar la actualización del resto.
        """
        now = datetime.now()
        if now.hour != config.UPDATE_HOUR or now.minute != 0:
            return

        channel = self.bot.get_channel(config.CHANNEL_ID)
        if not channel:
            return

        if not self.runner.reserve():
            await channel.send(embed=discord.Embed(
                title='⏭ Update diario omitido',
                description='Ya había otro update en curso al llegar el horario automático.',
                color=0xf1c40f,
                timestamp=datetime.now(),
            ))
            return

        msg = None
        preparation = None
        release_warnings = []
        try:
            embed = discord.Embed(
                title='🔌 Preparando update diario',
                description=(
                    'Reservando la ventana de mantenimiento y comprobando '
                    '**homeserver + NAS**.\n'
                    'Si alguno está apagado, WOL puede extender esta etapa varios minutos.'
                ),
                color=0x3498db,
                timestamp=datetime.now()
            )
            embed.set_footer(text='Proxmox es manual-only y no participa de este flujo.')
            msg = await channel.send(embed=embed)

            preparation = await prepare_daily_fleet()
            ready_text = ', '.join(preparation.ready_hosts) or 'ninguno'
            skipped_text = (
                '\n'.join(f'• **{host}**: {reason}' for host, reason in preparation.skipped_hosts.items())
                or 'ninguno'
            )
            progress = discord.Embed(
                title='🤖 Update diario automático iniciado',
                description=(
                    f'**Listos:** {ready_text}\n'
                    f'**Omitidos:** {skipped_text}\n\n'
                    'Ejecutando Ansible sobre los hosts listos...'
                ),
                color=0x3498db,
                timestamp=datetime.now(),
            )
            progress.set_footer(text='El mensaje se actualizará cada 15 segundos.')
            await msg.edit(embed=progress)

            success, duration, packages = await self.runner.run(
                config.ALL_PLAYBOOK,
                status_msg=msg,
                limit_hosts=preparation.ready_hosts,
                history_metadata={
                    'skipped_hosts': preparation.skipped_hosts,
                    'woken_hosts': preparation.woken_hosts,
                },
                reserved=True,
            )

            mins, secs = duration // 60, duration % 60
            partial = bool(preparation.skipped_hosts)
            if not success:
                title, color = '❌ Update diario fallido', 0xe74c3c
            elif partial:
                title, color = '⚠️ Update diario parcial', 0xf1c40f
            else:
                title, color = '✅ Update diario completado', 0x2ecc71

            result_embed = discord.Embed(
                title=title,
                color=color,
                timestamp=datetime.now()
            )
            result_embed.add_field(
                name='⏱ Duración de Ansible',
                value=f'{mins}m {secs}s' if mins > 0 else f'{secs}s',
                inline=True
            )
            result_embed.add_field(
                name='📄 Log',
                value='`!update log 1`',
                inline=True
            )
            if preparation.woken_hosts:
                result_embed.add_field(
                    name='🔌 Encendidos por WOL',
                    value=', '.join(preparation.woken_hosts),
                    inline=False,
                )
            reporting.add_result_fields(
                result_embed,
                packages,
                hosts=automatic_hosts(),
                skipped_hosts=preparation.skipped_hosts,
            )
            await msg.edit(embed=result_embed)
        except Exception as exc:
            if msg:
                await msg.edit(embed=discord.Embed(
                    title='❌ Falló la preparación del update diario',
                    description=f'`{type(exc).__name__}: {str(exc)[:800]}`',
                    color=0xe74c3c,
                    timestamp=datetime.now(),
                ))
        finally:
            try:
                if preparation:
                    release_warnings = await release_maintenance(preparation.held_wol_keys)
            finally:
                self.runner.release()
            if release_warnings:
                await channel.send(embed=discord.Embed(
                    title='⚠️ Reservas de mantenimiento con liberación pendiente',
                    description='\n'.join(release_warnings)[:4000],
                    color=0xf1c40f,
                    timestamp=datetime.now(),
                ))
