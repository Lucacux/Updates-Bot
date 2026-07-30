"""Lectura de archivos de estado en los hosts, por Ansible.

Los cogs `!docker` y `!cve` leen archivos que viven en cada host (propuestas,
historial, métricas del textfile collector). Todos lo hacen por el mismo camino:
Ansible ad-hoc, reusando el inventario y las llaves que el bot ya tiene.

Por qué no HTTP: sería un puerto más que abrir, otra regla de firewall
cross-VLAN y otro servicio que se puede caer. Por qué no Prometheus: los `.prom`
del textfile collector son la fuente original, y siguen ahí aunque Prometheus o
Grafana estén caídos — que es justo cuando querés mirar el estado de la flota.
"""
import asyncio
import subprocess

import config


async def ansible_shell(host, command, timeout=900):
    """Corre un comando en `host` y devuelve (ok, salida).

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


async def read_file(host, path, timeout=60):
    """Lee un archivo del host. (ok, contenido)."""
    return await ansible_shell(host, f'cat {path}', timeout=timeout)
