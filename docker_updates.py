"""Cog con el grupo `!docker`: propuestas de actualización de imágenes Docker.

De dónde salen los datos: el `image_advisor` de Vuln-Sentinel corre en cada host
con Docker (timer diario) y deja su análisis en un JSON local. Este cog no
analiza nada — lee ese archivo, lo muestra, y ejecuta `apply_update.py` cuando
vos aprobás una propuesta.

Por qué se lee por Ansible y no por HTTP: el bot ya tiene Ansible configurado
contra toda la flota, con las llaves y el inventario que ya funcionan. Un
endpoint HTTP nuevo sería un puerto más que abrir, otra regla de firewall
cross-VLAN y un servicio más que puede caerse. `ansible <host> -m shell -a cat`
usa el camino que ya existe y funciona igual para server-mbp (conexión local)
que para pentium (SSH).

Diferencia importante con `!update`: los paquetes del SO se actualizan solos
todos los días; las imágenes Docker NO. Acá siempre hay una persona que aprueba,
porque un contenedor que no vuelve a levantar se lleva puesto un servicio entero
y, si guarda datos, un rollback no deshace lo que la versión nueva ya escribió.
"""
import asyncio
import json
import subprocess
from datetime import datetime

import discord
from discord.ext import commands

import config

# Colores por veredicto — mismos códigos que usa el resto del bot.
_VERDICT_COLOR = {
    'apply': 0x2ecc71,             # verde: cierra CVEs y es barato
    'apply-with-care': 0xf1c40f,   # amarillo: cierra CVEs, leé el changelog
    'plan': 0xe67e22,              # naranja: cierra CVEs pero es riesgoso
    'review': 0x3498db,            # azul: falta información
    'optional': 0x95a5a6,          # gris: no urge
    'skip': 0x7f8c8d,              # gris oscuro: no vale la pena
}
_VERDICT_ICON = {
    'apply': '🟢', 'apply-with-care': '🟡', 'plan': '🟠',
    'review': '🔵', 'optional': '⚪', 'skip': '⚫',
}
_RISK_ICON = {'low': '🟢', 'medium': '🟡', 'high': '🔴'}


def _fmt_move(p):
    """Cómo se describe el cambio.

    Un refresco de digest deja el tag igual (`8.1` → `8.1`), que leído así
    parece un error. Se muestra distinto: lo que cambia es el contenido, no el
    número.
    """
    if p['kind'] == 'digest':
        return f'`{p["image"]["from_tag"]}` — mismo tag, digest nuevo'
    return f'`{p["image"]["from_tag"]}` → `{p["image"]["to_tag"]}` ({p["jump"]})'


def _fmt_delta(delta):
    """Resumen corto del cambio de CVEs: solo lo que mejora o empeora."""
    if not delta:
        return 'sin datos'
    parts = []
    for sev in ('critical', 'high'):
        value = delta.get(sev, 0)
        if value:
            parts.append(f'{sev[0].upper()}{value:+d}')
    return ' '.join(parts) if parts else 'sin cambios en C/H'


async def _ansible_shell(host, command, timeout=900):
    """Corre un comando en `host` por Ansible y devuelve (ok, salida).

    Ansible ad-hoc contesta `host | SUCCESS | rc=0 >>` y después el stdout real;
    nos quedamos con lo que viene después del `>>`, igual que playbooks.py.
    """
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ['ansible', host, '-m', 'shell', '-a', command],
            capture_output=True, text=True, cwd=config.ANSIBLE_DIR, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f'timeout de {timeout}s esperando a {host}'
    out = result.stdout.split('>>', 1)[1].strip() if '>>' in result.stdout else result.stdout.strip()
    return result.returncode == 0, out or result.stderr.strip()


class DockerUpdates(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        # Un solo apply a la vez en toda la flota: dos `docker compose up`
        # simultáneos sobre el mismo proyecto se pisan.
        self._applying = False

    # ── Lectura de propuestas ──────────────────────────────────────────
    async def _load_all(self):
        """Devuelve (propuestas, errores) juntando todos los hosts con Docker.

        Un host caído no invalida al resto: se reporta como error y seguimos con
        los demás. Es el mismo criterio que el resto del bot con la flota.
        """
        proposals, errors = [], []
        for host in config.DOCKER_HOSTS:
            ok, out = await _ansible_shell(host, f'cat {config.ADVISOR_PROPOSALS}', timeout=60)
            if not ok:
                errors.append(f'{host}: sin análisis todavía o host inalcanzable')
                continue
            try:
                payload = json.loads(out)
            except ValueError:
                errors.append(f'{host}: el archivo de propuestas no es JSON válido')
                continue
            for p in payload.get('proposals') or []:
                p['_generated_at'] = payload.get('generated_at', 0)
                proposals.append(p)
        order = {'apply': 0, 'apply-with-care': 1, 'plan': 2, 'review': 3, 'optional': 4, 'skip': 5}
        proposals.sort(key=lambda p: order.get(p['verdict']['action'], 9))
        return proposals, errors

    async def _find(self, pid):
        proposals, _ = await self._load_all()
        for p in proposals:
            if p['id'] == pid:
                return p
        return None

    # ── Comandos ───────────────────────────────────────────────────────
    @commands.group(name='docker', invoke_without_command=True)
    async def docker_group(self, ctx):
        await ctx.send(
            'Usá `!docker status`, `!docker show <id>`, `!docker apply <id>` o `!docker scan`.'
        )

    @docker_group.command(name='status')
    async def docker_status(self, ctx):
        msg = await ctx.send('🔍 Leyendo el análisis de imágenes...')
        proposals, errors = await self._load_all()

        actionable = [p for p in proposals if p['verdict']['action'] in ('apply', 'apply-with-care', 'plan')]
        embed = discord.Embed(
            title='🐳 Sin actualizaciones de imagen pendientes' if not actionable
                  else f'🐳 {len(actionable)} imagen(es) con actualización disponible',
            description='Los paquetes del SO se actualizan solos; las imágenes Docker las aprobás vos.\n'
                        'Detalle con `!docker show <id>`, aplicar con `!docker apply <id>`.',
            color=0x2ecc71 if not actionable else 0x3498db,
            timestamp=datetime.now(),
        )

        for p in proposals[:12]:
            icon = _VERDICT_ICON.get(p['verdict']['action'], '•')
            risk = _RISK_ICON.get(p['risk']['tier'], '')
            lock = '' if p['actionable'] else ' 🔒'
            embed.add_field(
                name=f'{icon} `{p["id"]}` {p["container"][:40]}{lock}',
                value=(f'{_fmt_move(p)} · '
                       f'{risk} riesgo {p["risk"]["tier"]} · CVEs {_fmt_delta(p["cve"]["delta"])}\n'
                       f'{p["verdict"]["summary"]}'),
                inline=False,
            )

        if len(proposals) > 12:
            embed.add_field(name='…', value=f'y {len(proposals) - 12} más', inline=False)
        if any(not p['actionable'] for p in proposals):
            embed.add_field(
                name='🔒 Sobre los bloqueados',
                value='Los administra Dokploy o son contenedores sueltos: se avisan, pero se '
                      'actualizan desde su panel, no desde acá.',
                inline=False,
            )
        if errors:
            embed.add_field(name='⚠️ Hosts sin datos', value='\n'.join(errors), inline=False)

        await msg.edit(content=None, embed=embed)

    @docker_group.command(name='show')
    async def docker_show(self, ctx, pid: str):
        p = await self._find(pid)
        if not p:
            return await ctx.send(f'❌ No encontré la propuesta `{pid}`. Mirá `!docker status`.')

        before, after = p['cve'].get('before'), p['cve'].get('after')
        embed = discord.Embed(
            title=f'🐳 {p["container"]}',
            description=(f'`{p["image"]["from"]}` — mismo tag, digest nuevo'
                         if p['kind'] == 'digest' else
                         f'`{p["image"]["from"]}` → `{p["image"]["to"]}`')
                        + f'\n**{p["verdict"]["summary"]}**',
            color=_VERDICT_COLOR.get(p['verdict']['action'], 0x3498db),
            timestamp=datetime.now(),
        )
        embed.add_field(name='🖥 Host', value=p['host'], inline=True)
        embed.add_field(name='📦 Tipo de cambio', value=p['jump'], inline=True)
        embed.add_field(
            name=f'{_RISK_ICON.get(p["risk"]["tier"], "")} Riesgo',
            value=f'{p["risk"]["tier"]} (score {p["risk"]["score"]}, confianza ~{p["risk"]["confidence"]}%)',
            inline=True,
        )

        if before and after:
            embed.add_field(
                name='🛡 CVEs (ahora → después)',
                value='\n'.join(
                    f'**{sev.capitalize()}**: {before.get(sev, 0)} → {after.get(sev, 0)} '
                    f'({after.get(sev, 0) - before.get(sev, 0):+d})'
                    for sev in ('critical', 'high', 'medium')
                ),
                inline=False,
            )

        embed.add_field(name='⚖️ Por qué ese riesgo',
                        value='\n'.join(f'• {r}' for r in p['risk']['reasons'])[:1024], inline=False)
        if p['urgency']['reasons']:
            embed.add_field(name='🔥 Por qué esa urgencia',
                            value='\n'.join(f'• {r}' for r in p['urgency']['reasons'])[:1024], inline=False)
        if p['image'].get('newest_tag') and p['image']['newest_tag'] != p['image']['to_tag']:
            embed.add_field(
                name='ℹ️ La más nueva que existe',
                value=f'`{p["image"]["newest_tag"]}` — no la propongo por defecto porque cruza de major.',
                inline=False,
            )
        if not p['actionable']:
            embed.add_field(name='🔒 No aplicable desde acá', value=p['blocked_reason'], inline=False)
        else:
            extra = ' forzar' if p['risk']['tier'] == 'high' else ''
            embed.set_footer(text=f'Aplicar con: !docker apply {p["id"]}{extra}')

        await ctx.send(embed=embed)

    @docker_group.command(name='apply')
    async def docker_apply(self, ctx, pid: str, confirm: str = ''):
        if self._applying:
            return await ctx.send('⚠️ Ya hay una actualización de imagen en curso. Esperá a que termine.')

        p = await self._find(pid)
        if not p:
            return await ctx.send(f'❌ No encontré la propuesta `{pid}`. Mirá `!docker status`.')
        if not p['actionable']:
            return await ctx.send(f'🔒 No puedo aplicarla: {p["blocked_reason"]}.')

        high = p['risk']['tier'] == 'high'
        if high and confirm.lower() not in ('forzar', 'force'):
            return await ctx.send(
                f'🔴 **{p["container"]}** es riesgo alto: {p["verdict"]["summary"]}\n'
                + '\n'.join(f'• {r}' for r in p['risk']['reasons'])
                + f'\n\nSi ya tenés backup y querés seguir igual: `!docker apply {pid} forzar`'
            )

        embed = discord.Embed(
            title='🐳 Actualizando imagen',
            description=f'**{p["container"]}** en `{p["host"]}`\n'
                        f'`{p["image"]["from"]}` → `{p["image"]["to"]}`\n\n'
                        'Si no vuelve sano, se revierte solo.',
            color=0x3498db,
            timestamp=datetime.now(),
        )
        msg = await ctx.send(embed=embed)

        flags = '--yes' + (' --allow-high-risk' if high else '')
        self._applying = True
        try:
            ok, out = await _ansible_shell(p['host'], f'apply_update.py {pid} {flags}', timeout=1200)
        finally:
            self._applying = False

        tail = out[-1000:] if len(out) > 1000 else out
        rolled_back = 'rollback' in out.lower() or 'revirtiendo' in out.lower()
        result = discord.Embed(
            title='🐳 Imagen actualizada' if ok else
                  ('🐳 Revertido — el servicio no volvió sano' if rolled_back else '🐳 No se pudo aplicar'),
            description=f'**{p["container"]}** en `{p["host"]}`',
            color=0x2ecc71 if ok else (0xe67e22 if rolled_back else 0xe74c3c),
            timestamp=datetime.now(),
        )
        result.add_field(name='📋 Salida', value=f'```\n{tail}\n```'[:1024], inline=False)
        if ok:
            result.set_footer(text='Corré !docker scan para recalcular el análisis.')
        await msg.edit(embed=result)

    @docker_group.command(name='scan')
    async def docker_scan(self, ctx):
        msg = await ctx.send('🔍 Recalculando el análisis de imágenes (puede tardar varios minutos)...')
        results = []
        for host in config.DOCKER_HOSTS:
            ok, out = await _ansible_shell(
                host, 'sudo systemctl start image-advisor.service', timeout=1800)
            results.append(f'{"✅" if ok else "❌"} {host}' + ('' if ok else f': {out[:120]}'))
        embed = discord.Embed(
            title='🐳 Análisis de imágenes actualizado',
            description='\n'.join(results) + '\n\nMirá el resultado con `!docker status`.',
            color=0x3498db,
            timestamp=datetime.now(),
        )
        await msg.edit(content=None, embed=embed)
