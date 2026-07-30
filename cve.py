"""Cog con el grupo `!cve`: estado de vulnerabilidades de la flota, desde el celular.

Hasta ahora los CVEs solo se veían en Grafana. Eso obliga a abrir un dashboard
para contestar preguntas que son de una línea, y deja de funcionar justo cuando
Prometheus o Grafana están caídos — que es cuando más querés mirar. Este cog lee
los `.prom` que Vuln-Sentinel escribe en cada host: la fuente original, por el
mismo camino de Ansible que ya usa `!docker`.

La pregunta que este cog contesta y el resto no:

  `!docker status` muestra las imágenes que **tienen** una actualización
  disponible. Es una lista de acciones posibles, y por diseño esconde todo lo
  que no se puede accionar. Pero una imagen con 40 Critical y **sin fix** sigue
  siendo un riesgo que hay que conocer — no aparece ahí, y no aparecer se lee
  igual que estar sana.

Por eso `!cve images` cruza las dos fuentes y marca cada imagen con si hay
solución o no. Esa distinción — "vulnerable y hay parche" vs "vulnerable y no
hay nada que hacer todavía" — es la que decide si esto es una tarea o una
decisión de arquitectura.

Formato pensado para pantalla de celular: pocos campos, líneas cortas, nada de
tablas anchas que Discord parte al medio en mobile.
"""
import json
import os
import re
import time
from datetime import datetime

import discord
from discord.ext import commands, tasks

import config
import remote

_SEVERITIES = ('critical', 'high', 'medium', 'low')
_LABEL_RE = re.compile(r'(\w+)="([^"]*)"')
_SAMPLE_RE = re.compile(r'^([a-zA-Z_:][\w:]*)(?:\{(.*)\})?\s+(-?[\d.eE+]+|NaN)$')


def _parse_prom(text):
    """Parser mínimo del formato textfile de Prometheus.

    Alcanza con lo que Vuln-Sentinel escribe: muestras planas con labels entre
    llaves. No pretende ser un parser general (no maneja exemplars ni escapes
    raros) — si el formato cambiara, es mejor que falle acá y no que invente.
    """
    samples = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = _SAMPLE_RE.match(line)
        if not m:
            continue
        name, raw_labels, value = m.groups()
        try:
            value = float(value)
        except ValueError:
            continue
        samples.append((name, dict(_LABEL_RE.findall(raw_labels or '')), value))
    return samples


def _norm_image(ref):
    """Normaliza una referencia para poder cruzar las dos fuentes.

    El exportador de CVEs y el advisor nombran la misma imagen distinto: uno
    reporta `dokploy/dokploy:v0.29.8@sha256:…` y el otro `dokploy/dokploy:v0.29.8`,
    y `aquasec/trivy` aparece con y sin `:latest`. Sin normalizar, el cruce falla
    justo en las imágenes que más importan.
    """
    ref = (ref or '').split('@', 1)[0].strip()
    if ref and ':' not in ref.split('/')[-1]:
        ref += ':latest'
    return ref


def _summarize(text):
    """Resume el .prom de un host.

    Las tres cuentas del SO son distintas y se muestran distinto:
      total       todo lo que el escáner encontró
      published   existe una versión arreglada en algún lado
      actionable  el gestor de paquetes tiene ese update esperando → `!update run` lo cierra

    La diferencia entre las dos últimas no es un detalle: en pentium hay 684
    High con fix publicado y 0 accionables, porque viven en paquetes de un
    kernel viejo que la distro ya dejó atrás. Mostrar `published` como si fuera
    accionable sería una alarma que nunca se puede apagar.
    """
    os_sev = {s: 0 for s in _SEVERITIES}
    published = {s: 0 for s in _SEVERITIES}
    actionable = {s: 0 for s in _SEVERITIES}
    packages, act_packages, images, last_run, scanners = 0, 0, {}, 0, set()
    pkg_cves = {}
    pending_known = True

    for name, labels, value in _parse_prom(text):
        if name == 'cve_vulnerabilities_total':
            sev = labels.get('severity')
            if sev in os_sev:
                os_sev[sev] += int(value)
            scanners.add(labels.get('scanner', '?'))
        elif name == 'cve_fix_published_total':
            if labels.get('severity') in published:
                published[labels['severity']] += int(value)
        elif name == 'cve_actionable_total':
            if labels.get('severity') in actionable:
                actionable[labels['severity']] += int(value)
        elif name == 'cve_actionable_packages_total':
            act_packages += int(value)
        elif name == 'cve_pending_updates_known':
            pending_known = bool(value)
        elif name == 'cve_vulnerable_packages_total':
            packages += int(value)
        elif name == 'cve_scan_last_run_timestamp_seconds':
            last_run = max(last_run, int(value))
        elif name == 'cve_vulnerability_info':
            pkg = labels.get('package', '?')
            entry = pkg_cves.setdefault(
                pkg, {'total': 0, 'worst': 'low', 'actionable': False})
            entry['total'] += 1
            if labels.get('actionable') == 'true':
                entry['actionable'] = True
            for sev in _SEVERITIES:            # de peor a mejor
                if labels.get('severity') == sev:
                    if _SEVERITIES.index(sev) < _SEVERITIES.index(entry['worst']):
                        entry['worst'] = sev
                    break
        elif name == 'cve_image_vulnerabilities_total':
            img = _norm_image(labels.get('image', ''))
            if not img:
                continue
            bucket = images.setdefault(img, {s: 0 for s in _SEVERITIES})
            sev = labels.get('severity')
            if sev in bucket:
                # Una misma imagen puede aparecer con y sin `:latest`; el max()
                # evita duplicar el conteo al normalizarlas a la misma clave.
                bucket[sev] = max(bucket[sev], int(value))

    return {
        'os': os_sev, 'published': published, 'actionable': actionable,
        'packages': packages, 'actionable_packages': act_packages,
        'images': images, 'last_run': last_run, 'scanners': sorted(scanners),
        'pkg_cves': pkg_cves, 'pending_known': pending_known,
    }


def _age(ts):
    if not ts:
        return 'nunca'
    hours = (time.time() - ts) / 3600
    if hours < 1:
        return f'hace {int(hours * 60)}min'
    if hours < 48:
        return f'hace {int(hours)}h'
    return f'hace {int(hours / 24)}d'


def _light(d, stale):
    """Semáforo por lo que se puede hacer, no por el tamaño del número.

    Un host con 38 Critical que ningún update cierra no es una emergencia: es
    una condición conocida. Pintarlo de rojo junto a uno que sí tiene un fix
    esperando entrena a ignorar el rojo.
    """
    if stale:
        return '⚪'
    if d['actionable']['critical']:
        return '🔴'
    if d['actionable']['high']:
        return '🟠'
    if d['os']['critical'] or d['os']['high']:
        return '🟡'          # hay exposición, pero no hay nada que aplicar
    return '🟢'


def _load_seen():
    try:
        with open(config.CVE_ALERT_STATE) as f:
            return set(json.load(f))
    except (OSError, ValueError):
        return set()


def _save_seen(seen):
    tmp = f'{config.CVE_ALERT_STATE}.tmp'
    try:
        with open(tmp, 'w') as f:
            json.dump(sorted(seen), f, indent=2)
        os.replace(tmp, config.CVE_ALERT_STATE)
    except OSError as e:
        print(f'no pude guardar el estado de avisos de CVE: {e}')


class CVE(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.watch_actionable.start()

    def cog_unload(self):
        self.watch_actionable.cancel()

    # ── Aviso proactivo ────────────────────────────────────────────────
    @tasks.loop(hours=config.CVE_ALERT_EVERY_HOURS)
    async def watch_actionable(self):
        """Avisa una vez cuando aparece algo accionable nuevo, y se calla.

        La alternativa —repetir el estado todos los días— es lo que convierte
        un aviso en ruido de fondo: si te llega lo mismo cada mañana, dejás de
        leerlo justo antes del día que cambia.

        Solo entra acá lo que se puede cerrar: paquetes con update pendiente que
        cierra CVEs, e imágenes con propuesta verde. Todo lo que no tiene parche
        publicado se ve en `!cve status` cuando lo buscás, pero no interrumpe.
        """
        channel = self.bot.get_channel(config.CHANNEL_ID)
        if not channel:
            return

        current, items = {}, []
        data, _ = await self._load()
        for host, d in data.items():
            for pkg, info in d['pkg_cves'].items():
                if info['actionable']:
                    sig = f'os:{host}:{pkg}'
                    current[sig] = ('os', host, pkg, info)
        for host in config.DOCKER_HOSTS:
            for p in await self._green_proposals(host):
                sig = f'docker:{host}:{p["container"]}:{p["image"]["to"]}'
                current[sig] = ('docker', host, p['container'], p)

        seen = _load_seen()
        new = [v for sig, v in current.items() if sig not in seen]
        # Se guarda exactamente lo que hay ahora, no la unión con lo anterior:
        # así, cuando un problema se resuelve, su firma se olvida y vuelve a
        # avisar si reaparece más adelante.
        _save_seen(set(current))

        if not new:
            return

        embed = discord.Embed(
            title='🛡 Hay algo nuevo que se puede arreglar',
            description='Solo aparece lo que tiene solución disponible. '
                        'No vuelvo a avisar de esto salvo que cambie.',
            color=0xe67e22, timestamp=datetime.now(),
        )
        os_new = [v for v in new if v[0] == 'os']
        docker_new = [v for v in new if v[0] == 'docker']

        if os_new:
            by_host = {}
            for _, host, pkg, _info in os_new:
                by_host.setdefault(host, []).append(pkg)
            embed.add_field(
                name='📦 Paquetes del SO',
                value='\n'.join(f'`{h}`: ' + ', '.join(f'`{p}`' for p in pkgs[:6])
                                + (f' y {len(pkgs) - 6} más' if len(pkgs) > 6 else '')
                                for h, pkgs in by_host.items())
                      + '\n→ `!update run all` los cierra',
                inline=False)

        for _, host, container, p in docker_new[:6]:
            embed.add_field(
                name=f'🐳 {container} en `{host}`',
                value=f'`{p["image"]["from_tag"]}` → `{p["image"]["to_tag"]}` · '
                      f'riesgo {p["risk"]["tier"]}\n{p["verdict"]["summary"]}',
                inline=False)
        if docker_new:
            embed.add_field(name='Aplicar', value='`!docker fix` aplica las de riesgo bajo en lote.',
                            inline=False)
        await channel.send(embed=embed)

    @watch_actionable.before_loop
    async def _before(self):
        await self.bot.wait_until_ready()

    async def _green_proposals(self, host):
        """Propuestas de imagen de riesgo bajo que cierran Critical o High."""
        ok, out = await remote.read_file(host, config.ADVISOR_PROPOSALS)
        if not ok:
            return []
        try:
            payload = json.loads(out)
        except ValueError:
            return []
        green = []
        for p in payload.get('proposals') or []:
            delta = p['cve'].get('delta') or {}
            if (p['verdict']['action'] == 'apply' and p['actionable']
                    and p['risk']['tier'] == 'low'
                    and (delta.get('critical', 0) < 0 or delta.get('high', 0) < 0)):
                green.append(p)
        return green

    # ── Lectura ────────────────────────────────────────────────────────
    async def _load(self, hosts=None):
        """Resumen de CVEs por host. Un host caído no invalida al resto."""
        data, errors = {}, []
        for host in (hosts or config.CVE_HOSTS):
            ok, out = await remote.read_file(host, config.CVE_METRICS)
            if not ok:
                errors.append(f'{host}: sin escaneo o inalcanzable')
                continue
            data[host] = _summarize(out)
        return data, errors

    async def _fixes(self, host):
        """Mapa imagen normalizada → qué se sabe de su arreglo.

        Sale del advisor, no del escáner: es la otra mitad del cruce.
        """
        fixes = {}
        if host not in config.DOCKER_HOSTS:
            return fixes
        ok, out = await remote.read_file(host, config.ADVISOR_PROPOSALS)
        if not ok:
            return fixes
        try:
            payload = json.loads(out)
        except ValueError:
            return fixes
        for p in payload.get('proposals') or []:
            fixes[_norm_image(p['image']['from'])] = {
                'kind': 'fix', 'id': p['id'], 'to': p['image']['to_tag'],
                'digest_only': p['kind'] == 'digest',
                'verdict': p['verdict']['action'],
                'actionable': p['actionable'], 'delta': (p['cve'].get('delta') or {}),
            }
        for s in payload.get('skipped') or []:
            # La razón viene prefijada con el repo ("library/foo: private…"),
            # que acá ya se ve en el nombre de la imagen justo arriba.
            reason = (s.get('reason') or '').split(': ', 1)[-1]
            fixes.setdefault(_norm_image(s.get('image', '')),
                             {'kind': 'none', 'reason': reason})
        return fixes

    # ── Comandos ───────────────────────────────────────────────────────
    @commands.group(name='cve', invoke_without_command=True)
    async def cve_group(self, ctx):
        await ctx.send(
            'Usá `!cve status`, `!cve host <nombre>`, `!cve images [host]` o `!cve scan`.'
        )

    @cve_group.command(name='status')
    async def cve_status(self, ctx):
        """Semáforo de toda la flota."""
        msg = await ctx.send('🛡 Leyendo el estado de vulnerabilidades...')
        data, errors = await self._load()

        act_total = sum(d['actionable']['critical'] + d['actionable']['high']
                        for d in data.values())
        embed = discord.Embed(
            title='🛡 Estado de vulnerabilidades',
            description=(f'**{act_total} CVE(s) que un update cierra ahora.** Corré `!update run all`.'
                         if act_total else
                         'Ningún CVE del SO se cierra con un update: todo lo que queda '
                         'no tiene parche publicado todavía.')
                        + '\nDetalle con `!cve host <nombre>` · imágenes con `!cve images`.',
            color=0xe74c3c if act_total else (0x2ecc71 if data else 0x95a5a6),
            timestamp=datetime.now(),
        )

        for host, d in data.items():
            stale = d['last_run'] and (time.time() - d['last_run']) / 3600 > config.CVE_STALE_HOURS
            os_sev, act = d['os'], d['actionable']
            img_crit = sum(1 for v in d['images'].values() if v['critical'])
            lines = []
            if act['critical'] or act['high']:
                lines.append(f'✅ **Se arregla con update:** {act["critical"]}C · {act["high"]}H '
                             f'({d["actionable_packages"]} paquete/s)')
            else:
                lines.append('✅ **Se arregla con update:** nada pendiente')
            lines.append(f'📊 Total detectado: {os_sev["critical"]}C · {os_sev["high"]}H '
                         f'en {d["packages"]} paquete(s)')
            if d['images']:
                lines.append(f'🐳 Imágenes: {img_crit} con Critical de {len(d["images"])}')
            lines.append(f'🕑 {_age(d["last_run"])}' + ('  ⚠️ **desactualizado**' if stale else ''))
            if not d['pending_known']:
                lines.append('⚠️ no pude leer los updates pendientes: "se arregla" es incierto')
            embed.add_field(
                name=f'{_light(d, stale)} {host}',
                value='\n'.join(lines), inline=False,
            )

        if errors:
            embed.add_field(name='⚠️ Sin datos', value='\n'.join(errors), inline=False)
        embed.set_footer(
            text='🔴 hay Critical que un update cierra · 🟡 hay exposición sin parche disponible')
        await msg.edit(content=None, embed=embed)

    @cve_group.command(name='host')
    async def cve_host(self, ctx, host: str):
        """Detalle de un host: qué paquetes concentran el problema."""
        if host not in config.CVE_HOSTS:
            return await ctx.send(
                f'❌ No conozco `{host}`. Tengo: ' + ', '.join(f'`{h}`' for h in config.CVE_HOSTS))

        msg = await ctx.send(f'🛡 Leyendo `{host}`...')
        data, errors = await self._load([host])
        if host not in data:
            return await msg.edit(content=f'❌ {errors[0] if errors else "sin datos"}')

        d = data[host]
        stale = d['last_run'] and (time.time() - d['last_run']) / 3600 > config.CVE_STALE_HOURS
        act = d['actionable']
        embed = discord.Embed(
            title=f'{_light(d, stale)} {host}',
            description=f'Escaneado {_age(d["last_run"])} con '
                        f'{", ".join(d["scanners"]) or "—"}.',
            color=0xe74c3c if (act['critical'] or act['high']) else 0x3498db,
            timestamp=datetime.now(),
        )
        embed.add_field(
            name='✅ Lo que un update cierra ahora',
            value=(f'**Critical**: {act["critical"]} · **High**: {act["high"]}\n'
                   f'en {d["actionable_packages"]} paquete(s) con update pendiente'
                   if act['critical'] or act['high'] else
                   'Nada: no hay updates pendientes que cierren CVEs.'),
            inline=False,
        )
        # Las tres cuentas juntas son la explicación de por qué el número grande
        # no se puede bajar. Sin esto, "1426 High" parece negligencia.
        embed.add_field(
            name='📊 Total detectado',
            value='\n'.join(f'**{s.capitalize()}**: {d["os"][s]}'
                            for s in ('critical', 'high', 'medium'))
                  + f'\nen {d["packages"]} paquete(s)\n'
                  + f'_{d["published"]["critical"]}C · {d["published"]["high"]}H tienen fix '
                    'publicado pero no instalable acá (paquetes que la distro ya dejó atrás)._',
            inline=False,
        )

        # El top de paquetes convierte un número grande en algo accionable: en
        # pentium, casi todos los High viven en paquetes de un kernel viejo, y
        # eso cambia por completo qué hacer al respecto.
        top = sorted(d['pkg_cves'].items(),
                     key=lambda kv: (kv[1]['actionable'], kv[1]['total']), reverse=True)[:8]
        if top:
            icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '⚪'}
            embed.add_field(
                name='🎯 Dónde se concentra',
                value='\n'.join(
                    f'{icons.get(v["worst"], "•")} `{p}` — {v["total"]} CVE(s)'
                    + ('  ✅ tiene update' if v['actionable'] else '')
                    for p, v in top),
                inline=False,
            )

        if stale:
            embed.add_field(
                name='⚠️ Escaneo viejo',
                value=f'Más de {config.CVE_STALE_HOURS}h. Refrescá con `!cve scan`.',
                inline=False)
        if host in config.HOST_BY_NAME:
            embed.set_footer(text=f'Actualizar paquetes: !update run {config.HOST_BY_NAME[host].target}')
        await msg.edit(content=None, embed=embed)

    @cve_group.command(name='images')
    async def cve_images(self, ctx, host: str = None):
        """Imágenes ordenadas por riesgo, marcando cuáles tienen arreglo."""
        hosts = [host] if host else config.DOCKER_HOSTS
        for h in hosts:
            if h not in config.CVE_HOSTS:
                return await ctx.send(
                    f'❌ No conozco `{h}`. Tengo: ' + ', '.join(f'`{x}`' for x in config.CVE_HOSTS))

        msg = await ctx.send('🛡 Cruzando CVEs con las actualizaciones disponibles...')
        data, errors = await self._load(hosts)

        rows = []
        for h, d in data.items():
            fixes = await self._fixes(h)
            for img, sev in d['images'].items():
                if not (sev['critical'] or sev['high']):
                    continue
                rows.append((h, img, sev, fixes.get(img)))
        rows.sort(key=lambda r: (r[2]['critical'], r[2]['high']), reverse=True)

        fixable = sum(1 for r in rows if r[3] and r[3]['kind'] == 'fix')
        embed = discord.Embed(
            title='🛡 Imágenes con Critical o High',
            description=(f'{len(rows)} imagen(es) afectadas; **{fixable} con actualización '
                         f'disponible**.\nLas demás no tienen fix publicado todavía.'
                         if rows else 'Ninguna imagen con Critical o High. 🎉'),
            color=0xe74c3c if rows else 0x2ecc71,
            timestamp=datetime.now(),
        )

        for h, img, sev, fix in rows[:10]:
            name = img if len(img) <= 44 else img[:41] + '…'
            line = f'**{sev["critical"]}C · {sev["high"]}H** · `{h}`'
            if fix and fix['kind'] == 'fix':
                delta = ' '.join(f'{s[0].upper()}{fix["delta"].get(s, 0):+d}'
                                 for s in ('critical', 'high') if fix['delta'].get(s))
                lock = '🔒 ' if not fix['actionable'] else ''
                # Un refresco de digest deja el tag igual: "hay update → `16`"
                # se lee como un error si no se dice qué cambió.
                move = ('mismo tag, digest nuevo' if fix['digest_only']
                        else f'hay update → `{fix["to"]}`')
                line += (f'\n✅ {lock}{move}'
                         + (f' ({delta})' if delta else '')
                         + (f' · `!docker show {fix["id"]}`' if fix['actionable'] else ''))
                if fix['verdict'] == 'skip':
                    line += '\n   _el advisor no lo recomienda: no mejora los CVEs_'
            elif fix and fix['kind'] == 'none':
                line += f'\n⛔ sin fix: {fix["reason"][:90]}'
            else:
                line += '\n➖ sin propuesta (no la analiza el advisor)'
            embed.add_field(name=f'🐳 {name}', value=line, inline=False)

        if len(rows) > 10:
            embed.add_field(name='…', value=f'y {len(rows) - 10} más', inline=False)
        if errors:
            embed.add_field(name='⚠️ Sin datos', value='\n'.join(errors), inline=False)
        embed.set_footer(text='✅ hay parche · ⛔ no hay · 🔒 lo maneja Dokploy')
        await msg.edit(content=None, embed=embed)

    @cve_group.command(name='scan')
    async def cve_scan(self, ctx):
        """Vuelve a escanear ahora, sin esperar al timer."""
        msg = await ctx.send('🔍 Reescaneando la flota (puede tardar varios minutos)...')
        results = []
        for host in config.CVE_HOSTS:
            ok, out = await remote.ansible_shell(
                host, 'sudo systemctl start cve-exporter.service', timeout=1800)
            results.append(f'{"✅" if ok else "❌"} {host}' + ('' if ok else f': {out[:100]}'))
        await msg.edit(content=None, embed=discord.Embed(
            title='🛡 Reescaneo terminado',
            description='\n'.join(results) + '\n\nMirá el resultado con `!cve status`.',
            color=0x3498db, timestamp=datetime.now(),
        ))
