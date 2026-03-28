"""Event domain entity."""

from datetime import datetime
from enum import Enum
from typing import TypedDict


class EventLevel(str, Enum):
    """Event severity level."""
    CRITICAL = "CRÍTICO"
    HIGH = "ALTO"
    MEDIUM = "MÉDIO"
    LOW = "BAIXO"
    INFO = "INFO"


class Event(TypedDict):
    """Event entity - represents a security/network event."""
    id: str
    timestamp: int
    level: str
    message: str
    mac: str
    ip: str
    details: dict


def create_event(
    level: str,
    message: str,
    mac: str = "",
    ip: str = "",
    details: dict | None = None,
) -> Event:
    """Factory function to create a new event."""
    now = int(datetime.now().timestamp())
    import hashlib
    event_id = hashlib.md5(f"{now}{message}{mac}".encode()).hexdigest()[:12]
    return {
        "id": event_id,
        "timestamp": now,
        "level": level,
        "message": message,
        "mac": mac,
        "ip": ip,
        "details": details or {},
    }
