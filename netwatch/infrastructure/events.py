"""Event store persistence layer."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.constants import LOG_PATH
from ..domain.event import Event, EventLevel, create_event


class EventStore:
    """Manages event log persistence."""

    def __init__(self, log_path: Path | None = None):
        self.log_path = log_path or LOG_PATH
        self._max_events = 1000

    def load(self) -> list[dict]:
        """Load events from JSON file."""
        if self.log_path.exists():
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return []

    def save(self, events: list[dict]) -> None:
        """Save events to JSON file."""
        events = events[-self._max_events:]
        with open(self.log_path, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, ensure_ascii=False)

    def add(
        self,
        events: list[dict],
        level: str,
        message: str,
        mac: str = "",
        ip: str = "",
    ) -> list[dict]:
        """Add a new event to the store."""
        event = create_event(level, message, mac, ip)
        events.append(event)
        return events

    def get_recent(self, events: list[dict], count: int = 50) -> list[dict]:
        """Get most recent events."""
        return sorted(events, key=lambda x: x.get("timestamp", 0), reverse=True)[:count]

    def get_by_level(self, events: list[dict], level: str) -> list[dict]:
        """Get events filtered by level."""
        return [e for e in events if e.get("level") == level]

    def clear(self, events: list[dict]) -> list[dict]:
        """Clear all events."""
        return []
