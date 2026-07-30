import os
import unittest

os.environ.setdefault("DISCORD_TOKEN", "test")
os.environ.setdefault("DISCORD_CHANNEL_ID", "1")

from playbooks import build_playbook_command


class PlaybookCommandTests(unittest.TestCase):
    def test_limit_contains_only_ready_hosts(self):
        command = build_playbook_command(
            "update_all.yml",
            ["server-mbp", "pentium"],
        )
        self.assertEqual(
            command,
            [
                "ansible-playbook",
                "playbooks/update_all.yml",
                "-v",
                "--limit",
                "server-mbp,pentium",
            ],
        )

    def test_manual_run_without_limit_is_unchanged(self):
        self.assertEqual(
            build_playbook_command("update_ubuntu.yml"),
            ["ansible-playbook", "playbooks/update_ubuntu.yml", "-v"],
        )
