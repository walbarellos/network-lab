"""Core module - Constants, configuration, and utilities."""

from .constants import (
    APP_VERSION,
    THREAT_LEVELS,
    DEVICE_CATEGORIES,
    RISK_PORTS,
    OWNERS,
    VENDOR_HINTS,
    DEFAULT_RANGE,
    DB_PATH,
    LOG_PATH,
    CONF_PATH,
)
from .config import load_config, save_config
from .vendor import vendor_hint, suggest_owner, owner_badge_html

__all__ = [
    "APP_VERSION",
    "THREAT_LEVELS",
    "DEVICE_CATEGORIES",
    "RISK_PORTS",
    "OWNERS",
    "VENDOR_HINTS",
    "DEFAULT_RANGE",
    "DB_PATH",
    "LOG_PATH",
    "CONF_PATH",
    "load_config",
    "save_config",
    "vendor_hint",
    "suggest_owner",
    "owner_badge_html",
]
