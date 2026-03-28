"""Configuration management."""

import json
from pathlib import Path
from typing import Any

from .constants import CONF_PATH


def load_config() -> dict[str, Any]:
    """Load configuration from JSON file."""
    if CONF_PATH.exists():
        try:
            with open(CONF_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {
        "org_name": "NetWatch",
        "org_unit": "Monitoramento",
        "operator": "Operador",
        "default_range": "192.168.1.0/24",
        "scan_timeout": 30,
        "auto_refresh": False,
        "refresh_sec": 15,
        "alert_new": True,
        "alert_suspect": True,
        "enable_port_scan": False,
        "port_scan_args": "-sV --top-ports 50 -T4 --max-retries 1 --host-timeout 8s",
        "theme_accent": "cyan",
        "sudo_ok": None,
    }


def save_config(conf: dict[str, Any]) -> None:
    """Save configuration to JSON file."""
    with open(CONF_PATH, "w", encoding="utf-8") as f:
        json.dump(conf, f, indent=2, ensure_ascii=False)
