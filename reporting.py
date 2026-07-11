"""Construcción de los campos de embed por host.

Centraliza el loop sobre config.HOSTS para que la salida (títulos de field,
truncados, ramas "sin pendientes") viva en un solo lugar y agregar un host no
implique tocar cada comando. Los textos son idénticos a los que main.py emitía
inline para server-mbp/pentium.
"""
import config
from playbooks import classify_packages, format_packages


def _pending_value(pkgs, show_overflow):
    """Bloque 🔴 Seguridad / 🟡 Normal de un host con pendientes."""
    sec, norm = classify_packages(pkgs)
    val = ''
    if sec:
        val += '🔴 **Seguridad:**\n' + '\n'.join(f'`{p}`' for p in sec[:5]) + '\n'
    if norm:
        val += '🟡 **Normal:**\n' + '\n'.join(f'`{p}`' for p in norm[:5])
    if show_overflow and len(pkgs) > 10:
        val += f'\n_...y {len(pkgs) - 10} más_'
    return val


def add_pending_fields(embed, pending, *, with_raw, show_overflow):
    """Agrega un field por host con sus paquetes pendientes.

    - with_raw=True  (comando !update check): sin pendientes muestra la salida
      cruda en codeblock.
    - with_raw=False (reporte diario): sin pendientes muestra texto plano.
    - show_overflow: agrega '_...y N más_' cuando hay >10 pendientes (solo check).
    """
    for host in config.HOSTS:
        pkgs = pending.get(host.pkg_key, [])
        if pkgs:
            embed.add_field(
                name=f'🖥 {host.name} ({len(pkgs)} pendientes)',
                value=_pending_value(pkgs, show_overflow),
                inline=False
            )
        elif with_raw:
            raw = pending.get(f'{host.pkg_key}_raw', '')
            confirm = raw if raw and raw != 'NO_UPDATES' else 'Sin actualizaciones pendientes.'
            embed.add_field(
                name=f'🖥 {host.name} ✅',
                value=f'```\n{confirm[:300]}\n```',
                inline=False
            )
        else:
            embed.add_field(
                name=f'🖥 {host.name} ✅',
                value='Sin actualizaciones pendientes.',
                inline=False
            )


def add_result_fields(embed, packages):
    """Agrega un field por host con los paquetes actualizados (embed final)."""
    for host in config.HOSTS:
        val, _ = format_packages(packages.get(host.pkg_key, []))
        embed.add_field(name=f'🖥 {host.name}', value=val, inline=False)


def pending_summary(pending):
    """Línea 'server-mbp: `N` | pentium: `M`' para !update next."""
    return ' | '.join(
        f'{host.name}: `{len(pending.get(host.pkg_key, []))}`' for host in config.HOSTS
    )


def history_summary(entry):
    """Línea 'mbp: `X pkgs` | pentium: `Y pkgs`' para !update history."""
    pkgs = entry.get('packages', {})
    return ' | '.join(
        f'{host.short}: `{len(pkgs.get(host.pkg_key, []))} pkgs`' for host in config.HOSTS
    )
