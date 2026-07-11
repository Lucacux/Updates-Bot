"""Entrypoint de Updates-Bot.

Se sigue arrancando con `python main.py` (así lo invoca el systemd del host).
Acá solo: se crea el bot, se registran los cogs y se arranca. Toda la lógica
vive en los módulos (config, storage, playbooks, reporting, commands, tasks).
"""
import discord
from discord.ext import commands

import config
from playbooks import PlaybookRunner
from commands import UpdateCommands
from tasks import UpdateTasks


def build_bot():
    intents = discord.Intents.default()
    intents.message_content = True
    bot = commands.Bot(command_prefix='!', intents=intents)

    # Estado compartido "hay un update corriendo" entre comandos y tareas.
    runner = PlaybookRunner()

    @bot.event
    async def setup_hook():
        await bot.add_cog(UpdateCommands(bot, runner))
        await bot.add_cog(UpdateTasks(bot, runner))

    return bot


if __name__ == '__main__':
    build_bot().run(config.TOKEN)
