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
from playbooks import check_pending_updates, check_unregistered_lxc


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
            # Grupo aparte: el SO se actualiza solo, las imágenes las aprobás vos.
            embed.add_field(name='Imágenes Docker', value=(
                '`!docker status` — imágenes con actualización disponible\n'
                '`!docker show <id>` — CVEs y riesgo de una propuesta\n'
                '`!docker fix` — aplicar en lote lo de riesgo bajo\n'
                '`!docker apply <id>` — aprobar una sola\n'
                '`!docker history` / `!docker log <n>` — qué se hizo y con qué salida'
            ), inline=False)
            embed.add_field(name='Vulnerabilidades', value=(
                '`!cve status` — qué se puede arreglar, por host\n'
                '`!cve host <nombre>` — dónde se concentra el problema\n'
                '`!cve images` — imágenes con CVEs, con y sin parche\n'
                '`!cve scan` — reescanear ahora'
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
        orphan_lxc = await check_unregistered_lxc()

        # Sin pendientes no hay nada que reportar, salvo que haya aparecido un
        # LXC que nadie está actualizando: eso sí hay que decirlo.
        if total == 0 and not orphan_lxc:
            return

        embed = discord.Embed(
            title=(
                '📋 Reporte diario — 🧩 LXC sin registrar'
                if total == 0 else f'📋 Reporte diario — ⚠️ {total} pendientes'
            ),
            color=0xe67e22,
            timestamp=datetime.now()
        )
        if total:
            reporting.add_pending_fields(embed, pending, with_raw=False, show_overflow=False)
        reporting.add_unregistered_lxc_field(embed, orphan_lxc)
        embed.set_footer(text=f'El update automático corre a las {config.UPDATE_HOUR:02d}:00.')
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
                    '**homeserver + NAS**, más un ping a los que están siempre '
                    'prendidos (**pve** y sus guests).\n'
                    'Si alguno está apagado, WOL puede extender esta etapa varios minutos.'
                ),
                color=0x3498db,
                timestamp=datetime.now()
            )
            embed.set_footer(
                text='Proxmox (hypervisor + guests) también entra; nada se reinicia solo.'
            )
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

            success, duration, packages, reboot_hosts = await self.runner.run(
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
            reporting.add_reboot_required_field(result_embed, reboot_hosts)
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
