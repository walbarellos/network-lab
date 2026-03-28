"""Vendor and owner identification utilities."""

from .constants import VENDOR_HINTS, OWNERS


def vendor_hint(vendor: str | None) -> str:
    """Return suggested device type based on vendor."""
    if not vendor:
        return "Desconhecido"
    v = vendor.upper()
    for key, hint in VENDOR_HINTS.items():
        if key in v:
            return hint
    return vendor


def suggest_owner(vendor: str | None, hostname: str | None, db: dict, mac_key: str) -> str:
    """
    Suggest owner based on intelligent patterns:
    - If already classified: return current
    - If vendor/hostname suggests home network device: 'familia'
    - Otherwise: 'desconhecido'
    """
    known = db.get("known", {}).get(mac_key, {})
    if known.get("owner"):
        return known["owner"]

    v = (vendor or "").upper()
    h = (hostname or "").lower()

    if any(x in v for x in ("TP-LINK", "INTELBRAS", "MIKROTIK", "ARUBA", "CISCO", "TPLINK")):
        return "familia"
    if any(x in h for x in ("router", "gateway", "modem", "tplink", "intelbras")):
        return "familia"

    return "desconhecido"


def owner_badge_html(owner_key: str) -> str:
    """Return colored badge HTML for owner."""
    o = OWNERS.get(owner_key, OWNERS["desconhecido"])
    color = o["color"]
    label = o["label"]
    icon = o["icon"]
    return (
        f'<span style="display:inline-flex;align-items:center;gap:4px;'
        f'padding:2px 8px;border-radius:3px;font-size:0.72rem;'
        f'font-family:var(--font-mono);font-weight:700;'
        f'background:{color}18;color:{color};border:1px solid {color}44;">'
        f'{icon} {label}</span>'
    )
