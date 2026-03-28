"""Application constants and configuration defaults."""

from pathlib import Path
from typing import TypedDict


APP_VERSION = "2.1.0"
DEFAULT_RANGE = "192.168.1.0/24"
DB_PATH = Path("netwatch_db.json")
LOG_PATH = Path("netwatch_events.json")
CONF_PATH = Path("netwatch_config.json")


class ThreatLevel(TypedDict):
    color: str
    icon: str
    priority: int


THREAT_LEVELS: dict[str, ThreatLevel] = {
    "CRÍTICO": {"color": "#FF1744", "icon": "🔴", "priority": 4},
    "ALTO": {"color": "#FF6D00", "icon": "🟠", "priority": 3},
    "MÉDIO": {"color": "#FFD600", "icon": "🟡", "priority": 2},
    "BAIXO": {"color": "#00E676", "icon": "🟢", "priority": 1},
    "INFO": {"color": "#40C4FF", "icon": "🔵", "priority": 0},
}


DEVICE_CATEGORIES = [
    "Desconhecido",
    "Servidor",
    "Roteador/Gateway",
    "Switch",
    "Estação de Trabalho",
    "Notebook",
    "Smartphone/Tablet",
    "Câmera IP",
    "Impressora",
    "IoT/Outros",
    "Suspeito",
]


RISK_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "ALTO"),
    23: ("Telnet", "CRÍTICO"),
    25: ("SMTP", "MÉDIO"),
    80: ("HTTP", "BAIXO"),
    110: ("POP3", "MÉDIO"),
    135: ("RPC", "ALTO"),
    139: ("NetBIOS", "ALTO"),
    443: ("HTTPS", "INFO"),
    445: ("SMB", "ALTO"),
    512: ("rexec", "CRÍTICO"),
    513: ("rlogin", "CRÍTICO"),
    514: ("rsh", "CRÍTICO"),
    1433: ("MSSQL", "ALTO"),
    3306: ("MySQL", "ALTO"),
    3389: ("RDP", "ALTO"),
    4444: ("Metasploit?", "CRÍTICO"),
    5900: ("VNC", "ALTO"),
    6379: ("Redis", "ALTO"),
    8080: ("HTTP-Alt", "MÉDIO"),
    8443: ("HTTPS-Alt", "BAIXO"),
    27017: ("MongoDB", "ALTO"),
}


class OwnerInfo(TypedDict):
    label: str
    icon: str
    color: str
    priority: int


OWNERS: dict[str, OwnerInfo] = {
    "eu": {"label": "Meu dispositivo", "icon": "👤", "color": "#00D4FF", "priority": 0},
    "mae": {"label": "Dispositivo da Mãe", "icon": "👩", "color": "#FF80AB", "priority": 1},
    "familia": {"label": "Família/Casa", "icon": "🏠", "color": "#69F0AE", "priority": 2},
    "visitante": {"label": "Visitante autorizado", "icon": "🤝", "color": "#FFD740", "priority": 3},
    "desconhecido": {"label": "Desconhecido", "icon": "❓", "color": "#7A96B8", "priority": 4},
    "intruso": {"label": "INTRUSO", "icon": "🚨", "color": "#FF1744", "priority": 5},
}


VENDOR_HINTS: dict[str, str] = {
    "APPLE": "Smartphone/Notebook (Apple)",
    "IPHONE": "iPhone",
    "IPAD": "iPad",
    "SAMSUNG": "Smartphone/Tablet (Samsung)",
    "GOOGLE": "Chromecast / Android",
    "ANDROID": "Smartphone Android",
    "AMAZON": "Echo/Alexa/Kindle",
    "TP-LINK": "Roteador/Switch",
    "TPLINK": "Roteador/Switch",
    "INTELBRAS": "Câmera/Roteador (Intelbras)",
    "MIKROTIK": "Roteador (MikroTik)",
    "ARUBA": "Access Point",
    "CISCO": "Switch/Roteador (Cisco)",
    "INTEL": "PC/Notebook (Intel)",
    "REALTEK": "PC (Realtek NIC)",
    "DELL": "Notebook/Desktop (Dell)",
    "LENOVO": "Notebook (Lenovo)",
    "HP": "Notebook/Impressora (HP)",
    "HEWLETT": "Notebook/Impressora (HP)",
    "ACER": "Notebook (Acer)",
    "ASUS": "Notebook/Roteador (Asus)",
    "LG ELEC": "Smart TV (LG)",
    "TCL": "Smart TV (TCL)",
    "SONY": "TV/Console (Sony)",
    "XIAOMI": "Smartphone (Xiaomi)",
    "RASPBERRY": "Raspberry Pi",
    "VMWARE": "Máquina Virtual",
    "VIRTUALBO": "Máquina Virtual",
    "BROADCOM": "Smartphone/IoT (Broadcom)",
}
