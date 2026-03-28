"""Risk calculation service."""

from ..core.constants import RISK_PORTS, THREAT_LEVELS


class RiskCalculator:
    """Calculates risk scores for network devices."""

    def calculate(self, device: dict, db: dict) -> tuple[int, str]:
        """
        Calculate risk score for a device.
        Returns (score, level).
        """
        score = 0

        ports = device.get("ports", [])
        for port_info in ports:
            port = port_info.get("port", 0)
            if port in RISK_PORTS:
                _, risk = RISK_PORTS[port]
                score += {
                    "CRÍTICO": 25,
                    "ALTO": 15,
                    "MÉDIO": 8,
                    "BAIXO": 3,
                    "INFO": 1,
                }.get(risk, 5)

        mac_key = device.get("mac", "").upper().replace(":", "-").replace(":", "")
        known = db.get("known", {}).get(mac_key, {})
        
        if known.get("blocked"):
            score += 50
        elif known.get("owner") == "intruso":
            score += 40

        if not device.get("hostname"):
            score += 5

        vendor = (device.get("vendor") or "").lower()
        if any(x in vendor for x in ("unknown", "empty", "null")):
            score += 10

        level = self._score_to_level(score)
        return min(score, 100), level

    def _score_to_level(self, score: int) -> str:
        """Convert numeric score to threat level."""
        if score >= 60:
            return "CRÍTICO"
        if score >= 40:
            return "ALTO"
        if score >= 20:
            return "MÉDIO"
        if score >= 10:
            return "BAIXO"
        return "INFO"
