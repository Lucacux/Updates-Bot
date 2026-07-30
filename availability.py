"""Preflight del update diario en cooperación con WOL-Bot.

Solo los hosts que declaran ``wol_key`` en config pasan por este flujo. Proxmox
no declara ninguno y, además, sus guests son manual-only: queda fuera tanto del
WOL como del barrido diario.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field

import config


@dataclass
class FleetPreparation:
    ready_hosts: list[str] = field(default_factory=list)
    skipped_hosts: dict[str, str] = field(default_factory=dict)
    held_wol_keys: list[str] = field(default_factory=list)
    woken_hosts: list[str] = field(default_factory=list)


def automatic_hosts():
    return [h for h in config.HOSTS if h.target not in config.MANUAL_ONLY_TARGETS]


async def _run_process(
    *args: str,
    timeout: int,
    cwd: str | None = None,
) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (FileNotFoundError, PermissionError) as exc:
        return 127, '', str(exc)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, '', f'timeout de {timeout}s'
    return (
        proc.returncode,
        stdout.decode('utf-8', errors='replace').strip(),
        stderr.decode('utf-8', errors='replace').strip(),
    )


async def _wolctl(*args: str, timeout: int = 30) -> tuple[int, str, str]:
    return await _run_process(
        config.WOL_PYTHON,
        config.WOL_CTL,
        *args,
        timeout=timeout,
    )


async def _acquire(host) -> tuple[bool, str]:
    rc, out, err = await _wolctl(
        'maintenance-acquire',
        host.wol_key,
        '--owner', config.WOL_MAINTENANCE_OWNER,
        '--ttl', str(config.WOL_MAINTENANCE_TTL_SECS),
    )
    return rc == 0, err or out or f'wolctl terminó con código {rc}'


async def _ensure_online(host) -> tuple[bool, bool, str]:
    total_timeout = (
        config.WOL_ATTEMPTS * config.WOL_ATTEMPT_TIMEOUT_SECS
        + config.WOL_BOOT_GRACE_SECS
        + 30
    )
    rc, out, err = await _wolctl(
        'ensure-online',
        host.wol_key,
        '--attempts', str(config.WOL_ATTEMPTS),
        '--attempt-timeout', str(config.WOL_ATTEMPT_TIMEOUT_SECS),
        '--poll-seconds', str(config.WOL_POLL_SECS),
        '--boot-grace', str(config.WOL_BOOT_GRACE_SECS),
        '--json',
        timeout=total_timeout,
    )
    try:
        payload = json.loads(out)
    except (TypeError, ValueError):
        payload = {}
    reason = payload.get('reason') or err or out or f'wolctl terminó con código {rc}'
    woken = bool(payload.get('ready') and not payload.get('already_online'))
    return rc == 0 and bool(payload.get('ready')), woken, reason


async def _ansible_ready(host) -> tuple[bool, str]:
    timeout = config.WOL_ANSIBLE_READY_TIMEOUT_SECS
    rc, out, err = await _run_process(
        'ansible',
        host.name,
        '-m', 'wait_for_connection',
        '-a', f'timeout={timeout} connect_timeout=5 sleep=5',
        timeout=timeout + 30,
        cwd=config.ANSIBLE_DIR,
    )
    return rc == 0, err or out or f'Ansible terminó con código {rc}'


async def _prepare_wol_host(host) -> tuple[object, bool, bool, str]:
    ready, woken, reason = await _ensure_online(host)
    if not ready:
        return host, False, woken, reason
    ansible_ok, ansible_detail = await _ansible_ready(host)
    if not ansible_ok:
        return host, False, woken, f'encendió, pero Ansible no quedó listo: {ansible_detail[:180]}'
    return host, True, woken, reason


async def prepare_daily_fleet() -> FleetPreparation:
    """Reserva, enciende en paralelo y devuelve el límite seguro de Ansible."""
    result = FleetPreparation()
    wol_hosts = [h for h in automatic_hosts() if h.wol_key]
    result.ready_hosts.extend(h.name for h in automatic_hosts() if not h.wol_key)

    acquired = await asyncio.gather(*(_acquire(host) for host in wol_hosts))
    eligible = []
    for host, (ok, detail) in zip(wol_hosts, acquired):
        if ok:
            result.held_wol_keys.append(host.wol_key)
            eligible.append(host)
        else:
            result.skipped_hosts[host.name] = (
                f'no se pudo reservar la ventana de mantenimiento: {detail[:180]}'
            )

    prepared = await asyncio.gather(*(_prepare_wol_host(host) for host in eligible))
    for host, ready, woken, reason in prepared:
        if ready:
            result.ready_hosts.append(host.name)
            if woken:
                result.woken_hosts.append(host.name)
        else:
            result.skipped_hosts[host.name] = reason[:300]

    return result


async def release_maintenance(wol_keys: list[str]) -> list[str]:
    """Libera todas las reservas; devuelve advertencias, nunca lanza."""
    async def release_one(wol_key):
        rc, out, err = await _wolctl(
            'maintenance-release',
            wol_key,
            '--owner', config.WOL_MAINTENANCE_OWNER,
        )
        return None if rc == 0 else f'{wol_key}: {err or out or f"código {rc}"}'

    results = await asyncio.gather(*(release_one(key) for key in wol_keys))
    return [warning for warning in results if warning]
