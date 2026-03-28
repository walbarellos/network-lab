"""Device domain entity."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TypedDict


class DeviceStatus(str, Enum):
    """Device status enumeration."""
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class DevicePorts(TypedDict):
    """Port information for a device."""
    port: int
    service: str
    state: str
    version: str


class Device(TypedDict):
    """Device entity - represents a network device."""
    ip: str
    mac: str
    hostname: str | None
    vendor: str | None
    status: str
    ports: list[DevicePorts]
    first_seen: int
    last_seen: int
    os_hint: str | None
    risk_score: int
    risk_level: str


class KnownDevice(TypedDict):
    """Known device metadata (from DB)."""
    name: str
    category: str
    owner: str
    notes: str
    fcm_token: str | None
    blocked: bool


def create_device(
    ip: str,
    mac: str,
    hostname: str | None = None,
    vendor: str | None = None,
    ports: list | None = None,
    os_hint: str | None = None,
) -> Device:
    """Factory function to create a new device."""
    now = int(datetime.now().timestamp())
    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "vendor": vendor,
        "status": "up",
        "ports": ports or [],
        "first_seen": now,
        "last_seen": now,
        "os_hint": os_hint,
        "risk_score": 0,
        "risk_level": "INFO",
    }


def device_key(device: Device) -> str:
    """Generate unique key for device (MAC address normalized)."""
    return (device.get("mac") or "").upper().replace(":", "-").replace(":", "").strip()
