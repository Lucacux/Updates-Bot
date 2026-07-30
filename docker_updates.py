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

Precisamente porque hay una persona decidiendo, hace falta trazabilidad: quién
aprobó qué, cuándo, con qué números a la vista y cómo terminó. `!docker history`
y `!docker log` leen el registro que deja `apply_update.py` en cada host. Ese
registro incluye los intentos **rechazados**, que son los que más se extrañan
después: "¿por qué esto sigue desactualizado?" se contesta con un rechazo
guardado, no con la ausencia de un éxito.
"""
import io
import json
from datetime import datetime

import discord
from discord.ext import commands

import config
import remote

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

# Cómo terminó cada intento, en el historial. `refused` y `dry_run` no cambiaron
# nada en el host, pero se registran igual: son parte de la traza de decisiones.
_RESULT = {
    'applied':         ('✅', 'aplicado',            0x2ecc71),
    'rolled_back':     ('↩️', 'revertido',           0xe67e22),
    'rollback_failed': ('🔥', 'rollback falló',      0xe74c3c),
    'refused':         ('🚫', 'rechazado',           0x95a5a6),
    'dry_run':         ('🧪', 'simulacro',           0x3498db),
    'error':           ('❌', 'error',               0xe74c3c),
}


def _result_of(entry):
    return _RESULT.get(entry.get('result'), ('•', entry.get('result', '?'), 0x95a5a6))


def _actor(author):
    """Identidad de quien aprueba, en forma segura para pasar por shell.

    El nombre de Discord lo elige el usuario, y acá termina dentro de un
    `ansible -m shell`: sin filtrar, un nick con backticks o `;` sería inyección
    de comandos en toda la flota. Se deja solo lo que identifica y no ejecuta.
    """
    safe = ''.join(c for c in str(author) if c.isalnum() or c in '._-')
    return f'discord:{safe[:48] or author.id}'


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


# Vive en remote.py porque `!cve` lee los suyos por el mismo camino.
_ansible_shell = remote.ansible_shell


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

    async def _load_history(self):
        """Historial de aplicaciones de toda la flota, del más nuevo al más viejo.

        Cada host guarda el suyo (lo escribe apply_update.py ahí mismo, junto al
        servicio que tocó). El bot los junta para la vista, pero no los copia a
        ningún lado: la fuente de verdad sigue siendo el host donde pasó.
        """
        entries, errors = [], []
        for host in config.DOCKER_HOSTS:
            ok, out = await _ansible_shell(host, f'cat {config.ADVISOR_HISTORY}', timeout=60)
            if not ok:
                errors.append(f'{host}: sin historial todavía o host inalcanzable')
                continue
            try:
                payload = json.loads(out)
            except ValueError:
                errors.append(f'{host}: el historial no es JSON válido')
                continue
            for seq, e in enumerate(payload):
                e['_host'] = host
                e['_seq'] = seq          # orden de escritura dentro de su host
                entries.append(e)
        # El timestamp tiene resolución de un segundo, así que dos eventos
        # seguidos empatan y el orden quedaría librado a la estabilidad del
        # sort. Se desempata por posición en el archivo, que es el orden real
        # en que se escribieron.
        entries.sort(key=lambda e: (e.get('at', 0), e['_seq']), reverse=True)
        return entries, errors

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
            'Usá `!docker status`, `!docker show <id>`, `!docker apply <id>`, '
            '`!docker scan`, `!docker history` o `!docker log <n>`.'
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

        actor = _actor(ctx.author)
        embed = discord.Embed(
            title='🐳 Actualizando imagen',
            description=f'**{p["container"]}** en `{p["host"]}`\n'
                        f'`{p["image"]["from"]}` → `{p["image"]["to"]}`\n\n'
                        'Si no vuelve sano, se revierte solo.',
            color=0x3498db,
            timestamp=datetime.now(),
        )
        embed.set_footer(text=f'Aprobado por {ctx.author} · queda en !docker history')
        msg = await ctx.send(embed=embed)

        flags = f'--yes --actor {actor}' + (' --allow-high-risk' if high else '')
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
        result.add_field(
            name='🧾 Queda registrado',
            value=f'Aprobado por **{ctx.author}**. Log completo con `!docker log 1`.',
            inline=False,
        )
        if ok:
            result.set_footer(text='Corré !docker scan para recalcular el análisis.')
        await msg.edit(embed=result)

    @docker_group.command(name='fix')
    async def docker_fix(self, ctx, confirm: str = ''):
        """Aplica en lote todo lo verde: riesgo bajo y que cierre Critical/High.

        Deliberadamente no toca las amarillas. Una propuesta `apply-with-care`
        cierra CVEs igual, pero suele ser un contenedor con datos persistentes
        donde el rollback restaura la imagen y no lo que la versión nueva ya
        escribió en el volumen. Esas se aprueban de a una, a propósito.
        """
        if self._applying:
            return await ctx.send('⚠️ Ya hay una actualización en curso. Esperá a que termine.')

        proposals, errors = await self._load_all()
        green = [p for p in proposals
                 if p['verdict']['action'] == 'apply' and p['actionable']
                 and p['risk']['tier'] == 'low'
                 and ((p['cve'].get('delta') or {}).get('critical', 0) < 0
                      or (p['cve'].get('delta') or {}).get('high', 0) < 0)]
        green_ids = {p['id'] for p in green}
        rest = [p for p in proposals
                if p['id'] not in green_ids
                and p['verdict']['action'] in ('apply-with-care', 'plan')]

        if not green:
            embed = discord.Embed(
                title='🐳 Nada para aplicar en lote',
                description='No hay propuestas de riesgo bajo que cierren Critical o High.'
                            + ('\n\nSí hay otras que requieren tu criterio:' if rest else ''),
                color=0x95a5a6, timestamp=datetime.now())
            for p in rest[:6]:
                embed.add_field(
                    name=f'🟡 `{p["id"]}` {p["container"][:40]}',
                    value=f'{_fmt_move(p)} · CVEs {_fmt_delta(p["cve"]["delta"])}\n'
                          f'Aprobá con `!docker apply {p["id"]}`',
                    inline=False)
            if errors:
                embed.add_field(name='⚠️ Hosts sin datos', value='\n'.join(errors), inline=False)
            return await ctx.send(embed=embed)

        # Confirmación explícita: el lote toca varios servicios seguidos, así
        # que no puede dispararse con un solo comando escrito de memoria.
        if confirm.lower() not in ('ya', 'si', 'sí', 'yes'):
            embed = discord.Embed(
                title=f'🐳 Voy a aplicar {len(green)} de {len(proposals)} propuestas',
                description='Riesgo bajo y cierran CVEs. Cada una se verifica y se '
                            'revierte sola si el servicio no vuelve sano.\n'
                            '**Confirmá con `!docker fix ya`**',
                color=0x2ecc71, timestamp=datetime.now())
            for p in green:
                embed.add_field(
                    name=f'✅ {p["container"][:40]} en `{p["host"]}`',
                    value=f'{_fmt_move(p)}\nCVEs {_fmt_delta(p["cve"]["delta"])} · riesgo bajo',
                    inline=False)
            if rest:
                embed.add_field(
                    name='⏸ Quedan afuera (aprobá una por una)',
                    value='\n'.join(f'🟡 `{p["id"]}` {p["container"][:34]} — '
                                    f'{_fmt_delta(p["cve"]["delta"])}' for p in rest[:6]),
                    inline=False)
            return await ctx.send(embed=embed)

        actor = _actor(ctx.author)
        msg = await ctx.send(embed=discord.Embed(
            title=f'🐳 Aplicando {len(green)} actualización(es)...',
            description='\n'.join(f'⏳ {p["container"]}' for p in green),
            color=0x3498db, timestamp=datetime.now()))

        done, stopped = [], None
        self._applying = True
        try:
            for p in green:
                ok, out = await _ansible_shell(
                    p['host'], f'apply_update.py {p["id"]} --yes --actor {actor}', timeout=1200)
                done.append((p, ok, out))
                if not ok:
                    # Se corta al primer fallo: si una imagen no volvió sana, el
                    # host ya no está en el estado que el análisis suponía, y
                    # seguir aplicando sería decidir sobre información vieja.
                    stopped = p
                    break
        finally:
            self._applying = False

        ok_count = sum(1 for _, ok, _ in done if ok)
        result = discord.Embed(
            title=f'🐳 {ok_count} de {len(green)} aplicadas',
            description=('Se cortó al primer fallo: el resto quedó sin tocar.'
                         if stopped else 'Todas verificadas y sanas.'),
            color=0x2ecc71 if not stopped else 0xe67e22,
            timestamp=datetime.now())
        for p, ok, out in done:
            icon = '✅' if ok else ('↩️' if 'rollback' in out.lower() else '❌')
            result.add_field(
                name=f'{icon} {p["container"][:40]}',
                value=f'{_fmt_move(p)}\n' + ('CVEs ' + _fmt_delta(p['cve']['delta'])
                                             if ok else f'```{out[-300:]}```'),
                inline=False)
        result.set_footer(text='Detalle en !docker history · recalculá con !docker scan')
        await msg.edit(embed=result)

    @docker_group.command(name='history')
    async def docker_history(self, ctx, limit: int = 10):
        """Quién aprobó qué, cuándo y cómo terminó."""
        limit = max(1, min(limit, 20))
        msg = await ctx.send('🧾 Leyendo el historial...')
        entries, errors = await self._load_history()

        if not entries:
            embed = discord.Embed(
                title='🐳 Sin actualizaciones de imagen registradas',
                description='Todavía no se aplicó ninguna propuesta. Mirá `!docker status`.',
                color=0x95a5a6, timestamp=datetime.now(),
            )
            if errors:
                embed.add_field(name='⚠️ Hosts sin datos', value='\n'.join(errors), inline=False)
            return await msg.edit(content=None, embed=embed)

        shown = entries[:limit]
        applied = sum(1 for e in entries if e.get('result') == 'applied')
        embed = discord.Embed(
            title=f'🐳 Historial de imágenes — {len(entries)} registro(s)',
            description=f'{applied} aplicada(s) con éxito. El número entre corchetes es el '
                        'que va en `!docker log <n>`.',
            color=0x3498db, timestamp=datetime.now(),
        )

        for i, e in enumerate(shown, start=1):
            icon, label, _ = _result_of(e)
            when = datetime.fromtimestamp(e.get('at', 0)).strftime('%d/%m %H:%M')
            move = (f'`{e["from"]}` → `{e["to"]}`'
                    if e.get('from') and e.get('to') and e['from'] != e['to']
                    else f'`{e.get("from") or e.get("id")}`')
            line = f'{move}\n👤 {e.get("actor", "?")} · 🖥 {e["_host"]} · 🕑 {when}'
            if e.get('cve_delta'):
                delta = _fmt_delta(e['cve_delta'])
                if delta not in ('sin datos', 'sin cambios en C/H'):
                    line += f' · 🛡 {delta}'
            if e.get('detail') and e.get('result') != 'applied':
                line += f'\n↳ {e["detail"][:160]}'
            embed.add_field(
                name=f'{icon} [{i}] {e.get("container") or e.get("id")} — {label}',
                value=line, inline=False,
            )

        if errors:
            embed.add_field(name='⚠️ Hosts sin datos', value='\n'.join(errors), inline=False)
        embed.set_footer(text='Incluye los intentos rechazados: también son parte de la traza.')
        await msg.edit(content=None, embed=embed)

    @docker_group.command(name='log')
    async def docker_log(self, ctx, index: int = 1):
        """Transcripción completa de una corrida del historial."""
        entries, _ = await self._load_history()
        if not entries:
            return await ctx.send('❌ Todavía no hay nada en el historial.')
        if not 1 <= index <= len(entries):
            return await ctx.send(f'❌ Elegí un número entre 1 y {len(entries)} (mirá `!docker history`).')

        entry = entries[index - 1]
        icon, label, color = _result_of(entry)
        when = datetime.fromtimestamp(entry.get('at', 0)).strftime('%d/%m/%Y %H:%M:%S')
        name = entry.get('log_file')
        if not name:
            # Un rechazo corta antes de ejecutar nada, así que no hay
            # transcripción que mostrar: el motivo ES todo el registro.
            return await ctx.send(embed=discord.Embed(
                title=f'{icon} {entry.get("container") or entry.get("id")} — {label}',
                description=f'👤 **{entry.get("actor", "?")}** · 🖥 `{entry["_host"]}` · 🕑 {when}\n\n'
                            f'No hay transcripción porque no se ejecutó nada.\n'
                            f'**Motivo:** {entry.get("detail") or "sin detalle"}',
                color=color, timestamp=datetime.now(),
            ))
        # El nombre sale de nuestro propio JSON, pero igual se acota a un basename:
        # el path va a parar a un shell y no hay razón para dejarlo salir del directorio.
        name = name.replace('/', '').replace('..', '')
        ok, out = await _ansible_shell(
            entry['_host'], f'cat {config.ADVISOR_LOGS_DIR}/{name}', timeout=60)
        if not ok:
            return await ctx.send(f'❌ No pude leer el log en `{entry["_host"]}`: {out[:300]}')

        embed = discord.Embed(
            title=f'{icon} {entry.get("container") or entry.get("id")} — {label}',
            description=f'👤 **{entry.get("actor", "?")}** · 🖥 `{entry["_host"]}` · 🕑 {when}',
            color=color, timestamp=datetime.now(),
        )
        if entry.get('summary'):
            embed.add_field(name='⚖️ Veredicto al momento de aprobar',
                            value=f'{entry["summary"]} (riesgo {entry.get("risk_tier", "?")})',
                            inline=False)
        if entry.get('cve_before') and entry.get('cve_after'):
            before, after = entry['cve_before'], entry['cve_after']
            embed.add_field(
                name='🛡 CVEs esperados',
                value='\n'.join(
                    f'**{sev.capitalize()}**: {before.get(sev, 0)} → {after.get(sev, 0)}'
                    for sev in ('critical', 'high')),
                inline=False)

        # El log entero como adjunto en vez de recortado en el embed: la parte
        # interesante de una corrida fallida casi nunca está en las últimas líneas.
        buf = io.BytesIO(out.encode('utf-8', errors='replace'))
        await ctx.send(embed=embed, file=discord.File(buf, filename=name))

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
