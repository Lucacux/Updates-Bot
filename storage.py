"""Historial y logs de updates, persistidos en el host (fuera de git).

Formato de history.json intacto: claves timestamp, playbook, duration, success,
packages, log_file. Naming de logs intacto: update_<YYYYMMDD_HHMMSS>.log.
"""
import json
import os

import config


def load_history():
    if not os.path.exists(config.HISTORY_FILE):
        return []
    with open(config.HISTORY_FILE) as f:
        return json.load(f)


def save_history(entry):
    history = load_history()
    history.append(entry)
    history = history[-20:]
    with open(config.HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)


def save_log(timestamp_str, content):
    filename = os.path.join(config.LOGS_DIR, f'update_{timestamp_str}.log')
    with open(filename, 'w') as f:
        f.write(content)
    return filename
