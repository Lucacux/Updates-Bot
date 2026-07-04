# Updates-Bot

Updates-Bot is an automated infrastructure maintenance Discord bot that leverages Ansible to manage and apply system updates across a fleet of servers. It operates on a dual execution model: running scheduled daily automation while remaining fully controllable through manual commands.

## Key Features

* **Scheduled Automation:** Automatically triggers and applies updates across all defined servers every day at 12:00.
* **On-Demand Manual Overrides:** Allows administrators to manually trigger checks, track histories, or force updates for specific distros (e.g., `arch`, `ubuntu`, or `all`) at any time.
* **Ansible-Driven Backend:** Runs playbooks under the hood to safely execute package updates and system maintenance tasks.
* **Detailed Logging & Reports:** Features deep execution tracking with unique log IDs and integrates with monitoring systems for real-time status reporting.
