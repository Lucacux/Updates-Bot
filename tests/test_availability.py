import os
import unittest
from unittest.mock import AsyncMock, patch

os.environ.setdefault("DISCORD_TOKEN", "test")
os.environ.setdefault("DISCORD_CHANNEL_ID", "1")

from availability import prepare_daily_fleet, release_maintenance


class AvailabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_nas_is_skipped_without_dropping_other_hosts(self):
        async def fake_wolctl(*args, timeout=30):
            command, server = args[0], args[1]
            if command == "maintenance-acquire":
                return 0, "{}", ""
            if command == "ensure-online" and server == "media":
                return 0, (
                    '{"server_key":"media","ready":true,"already_online":false,'
                    '"wol_attempts":1,"reason":"encendido por WOL"}'
                ), ""
            if command == "ensure-online" and server == "nas":
                return 4, (
                    '{"server_key":"nas","ready":false,"already_online":false,'
                    '"wol_attempts":3,"reason":"sin respuesta después de 3 intentos WOL"}'
                ), ""
            raise AssertionError(args)

        with (
            patch("availability._wolctl", new=fake_wolctl),
            patch("availability._ansible_ready", new=AsyncMock(return_value=(True, "ok"))),
        ):
            result = await prepare_daily_fleet()

        self.assertEqual(set(result.ready_hosts), {"server-mbp", "pentium"})
        self.assertIn("sempron", result.skipped_hosts)
        self.assertEqual(set(result.held_wol_keys), {"media", "nas"})
        self.assertEqual(result.woken_hosts, ["pentium"])

    async def test_release_is_best_effort(self):
        async def fake_wolctl(*args, timeout=30):
            server = args[1]
            return (0, "{}", "") if server == "media" else (6, "", "not owner")

        with patch("availability._wolctl", new=fake_wolctl):
            warnings = await release_maintenance(["media", "nas"])
        self.assertEqual(warnings, ["nas: not owner"])
