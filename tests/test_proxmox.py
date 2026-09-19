"""Lo que se rompe en silencio si alguien toca Proxmox sin mirar el resto.

Cubre las tres piezas nuevas: que el hypervisor y sus guests estén realmente en
el barrido automático, que el aviso de reinicio pendiente no se confunda con el
script que lo detecta, y que un LXC nuevo no pase desapercibido.
"""
import json
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("DISCORD_TOKEN", "test")
os.environ.setdefault("DISCORD_CHANNEL_ID", "1")

import config
from availability import automatic_hosts
from playbooks import _parse_pct_list, check_unregistered_lxc, parse_reboot_required


class ProxmoxInSweepTests(unittest.TestCase):
    def test_hypervisor_and_guests_are_automatic(self):
        automatic = {h.name for h in automatic_hosts()}
        for host in ("pve", "debian-monitoring", "alpine-monitoring"):
            self.assertIn(host, automatic)

    def test_no_manual_only_targets_left(self):
        self.assertEqual(config.MANUAL_ONLY_TARGETS, frozenset())

    def test_every_host_has_a_playbook_and_a_unique_key(self):
        keys = [h.pkg_key for h in config.HOSTS]
        self.assertEqual(len(keys), len(set(keys)))
        for host in config.HOSTS:
            self.assertEqual(config.PLAYBOOKS[host.target], host.playbook)

    def test_composite_proxmox_target_covers_the_whole_machine(self):
        self.assertEqual(
            config.TARGETS_STR["proxmox"],
            "pve + debian-monitoring + alpine-monitoring",
        )


class RebootRequiredTests(unittest.TestCase):
    def _line(self, host, payload):
        return f"ok: [{host}] => {json.dumps(payload)}"

    def test_reports_host_with_unbooted_kernel(self):
        lines = [self._line("pve", {"changed": False, "stdout": "REBOOT_REQUIRED"})]
        self.assertEqual(parse_reboot_required(lines), ["pve"])

    def test_empty_stdout_means_nothing_pending(self):
        lines = [self._line("pve", {"changed": False, "stdout": ""})]
        self.assertEqual(parse_reboot_required(lines), [])

    def test_marker_inside_the_script_is_not_a_hit(self):
        """El `cmd` que Ansible incluye trae el literal: sólo cuenta el stdout."""
        lines = [self._line("pve", {
            "cmd": "if [ -f /var/run/reboot-required ]; then echo REBOOT_REQUIRED; fi",
            "stdout": "",
        })]
        self.assertEqual(parse_reboot_required(lines), [])


class UnregisteredLxcTests(unittest.IsolatedAsyncioTestCase):
    PCT_LIST = (
        "VMID       Status     Lock         Name\n"
        "101        running                 alpine-monitoring\n"
        "104        running                 lxc-nuevo\n"
        "105        stopped                 lxc-apagado\n"
    )

    def test_parses_only_running_containers(self):
        self.assertEqual(
            _parse_pct_list(self.PCT_LIST),
            [(101, "alpine-monitoring"), (104, "lxc-nuevo")],
        )

    async def test_flags_the_container_nobody_registered(self):
        with patch("playbooks.asyncio.to_thread") as to_thread:
            to_thread.return_value = type(
                "Result", (), {"returncode": 0, "stdout": f">> {self.PCT_LIST}"}
            )()
            orphans = await check_unregistered_lxc()
        self.assertEqual(orphans, [(104, "lxc-nuevo")])

    async def test_ansible_failure_is_not_fatal(self):
        """El aviso es extra: si no se pudo chequear, el reporte sale igual."""
        with patch("playbooks.asyncio.to_thread") as to_thread:
            to_thread.return_value = type(
                "Result", (), {"returncode": 4, "stdout": ""}
            )()
            self.assertEqual(await check_unregistered_lxc(), [])


if __name__ == "__main__":
    unittest.main()
