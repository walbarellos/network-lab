"""Risk assessment value object."""

from dataclasses import dataclass
from typing import TypedDict


class RiskAssessment(TypedDict):
    """Risk assessment result."""
    score: int
    level: str
    factors: list[str]


def calculate_risk_score(device: dict, db: dict) -> tuple[int, str]:
    """
    Calculate risk score for a device.
    Returns (score, level).
    """
    from ..core.constants import THREAT_LEVELS, RISK_PORTS
    
    score = 0
    factors = []

    ports = device.get("ports", [])
    for port_info in ports:
        port = port_info.get("port", 0)
        if port in RISK_PORTS:
            service, risk = RISK_PORTS[port]
            score += {"CRÍTICO": 25, "ALTO": 15, "MÉDIO": 8, "BAIXO": 3, "INFO": 1}.get(risk, 5)
            factors.append(f"Porta {port} ({service}): {risk}")

    known = db.get("known", {}).get(device.get("mac", "").upper().replace(":", "-").replace(":", ""), {})
    if known.get("blocked"):
        score += 50
        factors.append("Dispositivo bloqueado")
    elif known.get("owner") == "intruso":
        score += 40
        factors.append("Intruso identificado")

    if not device.get("hostname"):
        score += 5
        factors.append("Sem hostname")

    vendor = (device.get("vendor") or "").lower()
    if any(x in vendor for x in ("unknown", "empty", "null")):
        score += 10
        factors.append("Vendor desconhecido")

    level = "INFO"
    for lvl, info in sorted(THREAT_LEVELS.items(), key=lambda x: -x[1]["priority"]):
        if score >= {"CRÍTICO": 60, "ALTO": 40, "MÉDIO": 20, "BAIXO": 10, "INFO": 0}[lvl]:
            level = lvl
            break

    return min(score, 100), level
