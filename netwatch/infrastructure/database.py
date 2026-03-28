"""Database persistence layer."""

import json
from pathlib import Path
from typing import Any

from ..core.constants import DB_PATH


class DatabaseManager:
    """Manages device database persistence."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DB_PATH

    def load(self) -> dict[str, Any]:
        """Load database from JSON file."""
        if self.db_path.exists():
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return self._empty_db()

    def save(self, db: dict[str, Any]) -> None:
        """Save database to JSON file."""
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2, ensure_ascii=False)

    def _empty_db(self) -> dict[str, Any]:
        """Return empty database structure."""
        return {
            "seen": {},
            "known": {},
            "suspects": [],
            "blocked": [],
        }

    def update_device(self, db: dict, mac_key: str, device: dict) -> None:
        """Update or insert device in database."""
        existing = db["seen"].get(mac_key)
        if existing:
            device["first_seen"] = existing.get("first_seen", device.get("first_seen"))
        db["seen"][mac_key] = device

    def get_known_device(self, db: dict, mac_key: str) -> dict | None:
        """Get known device metadata."""
        return db.get("known", {}).get(mac_key)

    def set_known_device(self, db: dict, mac_key: str, metadata: dict) -> None:
        """Set known device metadata."""
        if "known" not in db:
            db["known"] = {}
        db["known"][mac_key] = metadata

    def get_all_devices(self, db: dict) -> list[dict]:
        """Get all seen devices as list."""
        return list(db.get("seen", {}).values())

    def clear_all(self, db: dict) -> None:
        """Clear all devices from database."""
        db["seen"] = {}
        db["known"] = {}
        db["suspects"] = []
        db["blocked"] = []
