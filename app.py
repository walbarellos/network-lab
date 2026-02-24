"""
╔══════════════════════════════════════════════════════════════════╗
║         NETWATCH — CENTRAL DE MONITORAMENTO DE REDE             ║
║         Sistema Profissional de Segurança de Redes              ║
╚══════════════════════════════════════════════════════════════════╝

Desenvolvido para uso em ambientes de segurança pública.
Requer: Python 3.10+, Nmap, sudo privileges para scans MAC/vendor.
"""

import json
import time
import subprocess
import xml.etree.ElementTree as ET
import hashlib
import csv
import io
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
import os

import pandas as pd
import streamlit as st
import streamlit.components.v1 as st_components
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

import messaging

# ─── Importações opcionais ────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph,
        Spacer, HRFlowable
    )
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIG & CONSTANTES
# ═══════════════════════════════════════════════════════════════════════════════

APP_VERSION = "2.0.0"
DEFAULT_RANGE = "192.168.1.0/24"
DB_PATH   = Path("netwatch_db.json")
LOG_PATH  = Path("netwatch_events.json")
CONF_PATH = Path("netwatch_config.json")

THREAT_LEVELS = {
    "CRÍTICO":  {"color": "#FF1744", "icon": "🔴", "priority": 4},
    "ALTO":     {"color": "#FF6D00", "icon": "🟠", "priority": 3},
    "MÉDIO":    {"color": "#FFD600", "icon": "🟡", "priority": 2},
    "BAIXO":    {"color": "#00E676", "icon": "🟢", "priority": 1},
    "INFO":     {"color": "#40C4FF", "icon": "🔵", "priority": 0},
}

DEVICE_CATEGORIES = [
    "Desconhecido", "Servidor", "Roteador/Gateway", "Switch",
    "Estação de Trabalho", "Notebook", "Smartphone/Tablet",
    "Câmera IP", "Impressora", "IoT/Outros", "Suspeito"
]

RISK_PORTS = {
    21: ("FTP", "ALTO"), 23: ("Telnet", "CRÍTICO"), 25: ("SMTP", "MÉDIO"),
    80: ("HTTP", "BAIXO"), 110: ("POP3", "MÉDIO"), 135: ("RPC", "ALTO"),
    139: ("NetBIOS", "ALTO"), 443: ("HTTPS", "INFO"), 445: ("SMB", "ALTO"),
    512: ("rexec", "CRÍTICO"), 513: ("rlogin", "CRÍTICO"), 514: ("rsh", "CRÍTICO"),
    1433: ("MSSQL", "ALTO"), 3306: ("MySQL", "ALTO"), 3389: ("RDP", "ALTO"),
    4444: ("Metasploit?", "CRÍTICO"), 5900: ("VNC", "ALTO"),
    6379: ("Redis", "ALTO"), 8080: ("HTTP-Alt", "MÉDIO"),
    8443: ("HTTPS-Alt", "BAIXO"), 27017: ("MongoDB", "ALTO"),
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SISTEMA DE PROPRIETÁRIOS
# ═══════════════════════════════════════════════════════════════════════════════

OWNERS = {
    "eu":          {"label": "Meu dispositivo",    "icon": "👤", "color": "#00D4FF", "priority": 0},
    "mae":         {"label": "Dispositivo da Mãe", "icon": "👩", "color": "#FF80AB", "priority": 1},
    "familia":     {"label": "Família/Casa",        "icon": "🏠", "color": "#69F0AE", "priority": 2},
    "visitante":   {"label": "Visitante autorizado","icon": "🤝", "color": "#FFD740", "priority": 3},
    "desconhecido":{"label": "Desconhecido",        "icon": "❓", "color": "#7A96B8", "priority": 4},
    "intruso":     {"label": "INTRUSO",             "icon": "🚨", "color": "#FF1744", "priority": 5},
}

# Vendor fingerprinting — OUI prefixes (3 bytes do MAC) → fabricante comum
# Usado para sugerir automaticamente o tipo de dispositivo
VENDOR_HINTS: dict[str, str] = {
    # Apple
    "APPLE":    "Smartphone/Notebook (Apple)",
    "IPHONE":   "iPhone",
    "IPAD":     "iPad",
    # Samsung
    "SAMSUNG":  "Smartphone/Tablet (Samsung)",
    # Google / Android
    "GOOGLE":   "Chromecast / Android",
    "ANDROID":  "Smartphone Android",
    # Amazon
    "AMAZON":   "Echo/Alexa/Kindle",
    # TP-Link / Roteadores comuns
    "TP-LINK":  "Roteador/Switch",
    "TPLINK":   "Roteador/Switch",
    "INTELBRAS":"Câmera/Roteador (Intelbras)",
    # Mikrotik
    "MIKROTIK": "Roteador (MikroTik)",
    # Aruba / Cisco
    "ARUBA":    "Access Point",
    "CISCO":    "Switch/Roteador (Cisco)",
    # Notebooks comuns
    "INTEL":    "PC/Notebook (Intel)",
    "REALTEK":  "PC (Realtek NIC)",
    "DELL":     "Notebook/Desktop (Dell)",
    "LENOVO":   "Notebook (Lenovo)",
    "HP":       "Notebook/Impressora (HP)",
    "HEWLETT":  "Notebook/Impressora (HP)",
    "ACER":     "Notebook (Acer)",
    "ASUS":     "Notebook/Roteador (Asus)",
    # Smart TV / streaming
    "LG ELEC":  "Smart TV (LG)",
    "TCL":      "Smart TV (TCL)",
    "SONY":     "TV/Console (Sony)",
    # Xiaomi / Redmi
    "XIAOMI":   "Smartphone (Xiaomi)",
    # Outros
    "RASPBERRY":"Raspberry Pi",
    "VMWARE":   "Máquina Virtual",
    "VIRTUALBO":"Máquina Virtual",
    "BROADCOM": "Smartphone/IoT (Broadcom)",
}

def vendor_hint(vendor: str) -> str:
    """Retorna sugestão de tipo de dispositivo baseado no vendor."""
    v = (vendor or "").upper()
    for key, hint in VENDOR_HINTS.items():
        if key in v:
            return hint
    return vendor or "Desconhecido"

def suggest_owner(vendor: str, hostname: str, db: dict, mac_key: str) -> str:
    """
    Sugere proprietário baseado em padrões inteligentes:
    - Se já foi classificado: retorna o atual
    - Se vendor/hostname sugere dispositivo de rede da casa: 'familia'
    - Caso contrário: 'desconhecido'
    """
    known = db.get("known", {}).get(mac_key, {})
    if known.get("owner"):
        return known["owner"]

    v = (vendor or "").upper()
    h = (hostname or "").lower()

    # Roteador/gateway geralmente é da família
    if any(x in v for x in ("TP-LINK","INTELBRAS","MIKROTIK","ARUBA","CISCO","TPLINK")):
        return "familia"
    if any(x in h for x in ("router","gateway","modem","tplink","intelbras")):
        return "familia"

    return "desconhecido"

def owner_badge_html(owner_key: str) -> str:
    """Retorna HTML de badge colorido para o proprietário."""
    o = OWNERS.get(owner_key, OWNERS["desconhecido"])
    color = o["color"]
    label = o["label"]
    icon  = o["icon"]
    return (
        f'<span style="display:inline-flex;align-items:center;gap:4px;'
        f'padding:2px 8px;border-radius:3px;font-size:0.72rem;'
        f'font-family:var(--font-mono);font-weight:700;'
        f'background:{color}18;color:{color};border:1px solid {color}44;">'
        f'{icon} {label}</span>'
    )

DARK_CSS = """
<style>
/* ─── Imports ─────────────────────────────────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap');

/* ─── Variables ───────────────────────────────────────────────────────────── */
:root {
    --bg-primary:    #070B14;
    --bg-secondary:  #0D1526;
    --bg-card:       #111B2E;
    --bg-elevated:   #162038;
    --border:        #1E3A5F;
    --border-bright: #2A5080;
    --cyan:          #00D4FF;
    --cyan-dim:      #007BA8;
    --amber:         #FFB800;
    --amber-dim:     #7A5800;
    --green:         #00FF87;
    --green-dim:     #007A42;
    --red:           #FF1744;
    --red-dim:       #7A0020;
    --orange:        #FF6D00;
    --text-primary:  #E0EAF5;
    --text-secondary: #7A96B8;
    --text-dim:      #3D5A7A;
    --font-display:  'Rajdhani', sans-serif;
    --font-mono:     'Share Tech Mono', monospace;
    --font-body:     'Exo 2', sans-serif;
    --scan-duration: 2s;
}

/* ─── Base ────────────────────────────────────────────────────────────────── */
.stApp {
    background: var(--bg-primary) !important;
    font-family: var(--font-body) !important;
    color: var(--text-primary) !important;
}

/* ─── Animated grid background ────────────────────────────────────────────── */
.stApp::before {
    content: '';
    position: fixed; top:0; left:0; width:100%; height:100%;
    background-image:
        linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none; z-index: 0;
    animation: gridPulse 8s ease-in-out infinite;
}
@keyframes gridPulse {
    0%, 100% { opacity: 0.6; }
    50%       { opacity: 1; }
}

/* ─── Typography ──────────────────────────────────────────────────────────── */
h1, h2, h3 {
    font-family: var(--font-display) !important;
    letter-spacing: 0.05em !important;
    text-transform: uppercase !important;
}
h1 { color: var(--cyan) !important; font-size: 2rem !important; font-weight: 700 !important; }
h2 { color: var(--text-primary) !important; font-size: 1.3rem !important; font-weight: 600 !important; border-bottom: 1px solid var(--border) !important; padding-bottom: 6px !important; margin-top: 1.5rem !important; }
h3 { color: var(--cyan-dim) !important; font-size: 1.1rem !important; font-weight: 500 !important; }

/* ─── Sidebar ─────────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background: var(--bg-secondary) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { color: var(--text-primary) !important; }

/* ─── Metric cards ────────────────────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    padding: 14px 18px !important;
    position: relative !important;
    overflow: hidden !important;
}
[data-testid="stMetric"]::before {
    content: ''; position: absolute; top:0; left:0;
    width: 3px; height: 100%;
    background: linear-gradient(180deg, var(--cyan), var(--cyan-dim));
}
[data-testid="stMetricLabel"] > div {
    font-family: var(--font-display) !important;
    font-size: 0.75rem !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    color: var(--text-secondary) !important;
}
[data-testid="stMetricValue"] > div {
    font-family: var(--font-display) !important;
    font-size: 2rem !important;
    font-weight: 700 !important;
    color: var(--cyan) !important;
    line-height: 1.1 !important;
}
[data-testid="stMetricDelta"] > div { font-size: 0.8rem !important; }

/* ─── Buttons ─────────────────────────────────────────────────────────────── */
.stButton > button {
    background: transparent !important;
    border: 1px solid var(--cyan-dim) !important;
    color: var(--cyan) !important;
    font-family: var(--font-display) !important;
    font-weight: 600 !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
    border-radius: 4px !important;
    transition: all 0.2s ease !important;
}
.stButton > button:hover {
    background: rgba(0,212,255,0.1) !important;
    border-color: var(--cyan) !important;
    box-shadow: 0 0 15px rgba(0,212,255,0.2) !important;
    transform: translateY(-1px) !important;
}
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #003A5C, #005A8A) !important;
    border-color: var(--cyan) !important;
    box-shadow: 0 0 20px rgba(0,212,255,0.15) !important;
}

/* ─── Inputs ──────────────────────────────────────────────────────────────── */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stSelectbox > div > div,
.stMultiSelect > div > div {
    background: var(--bg-elevated) !important;
    border: 1px solid var(--border) !important;
    border-radius: 4px !important;
    color: var(--text-primary) !important;
    font-family: var(--font-mono) !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: var(--cyan) !important;
    box-shadow: 0 0 8px rgba(0,212,255,0.15) !important;
}

/* ─── Dataframe ───────────────────────────────────────────────────────────── */
.stDataFrame {
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    overflow: hidden !important;
}
.stDataFrame thead th {
    background: var(--bg-elevated) !important;
    color: var(--cyan) !important;
    font-family: var(--font-display) !important;
    font-size: 0.8rem !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    border-bottom: 1px solid var(--border-bright) !important;
}
.stDataFrame tbody tr:hover { background: rgba(0,212,255,0.05) !important; }
.stDataFrame tbody td {
    font-family: var(--font-mono) !important;
    font-size: 0.82rem !important;
    color: var(--text-primary) !important;
    border-bottom: 1px solid rgba(30,58,95,0.5) !important;
}

/* ─── Tabs ────────────────────────────────────────────────────────────────── */
[data-testid="stTabs"] > div:first-child {
    border-bottom: 1px solid var(--border) !important;
    gap: 4px !important;
}
[data-testid="stTabs"] button {
    font-family: var(--font-display) !important;
    font-weight: 600 !important;
    letter-spacing: 0.05em !important;
    text-transform: uppercase !important;
    color: var(--text-secondary) !important;
    border: none !important;
    border-bottom: 2px solid transparent !important;
    background: transparent !important;
    padding: 8px 16px !important;
    transition: all 0.2s !important;
}
[data-testid="stTabs"] button:hover {
    color: var(--cyan) !important;
    background: rgba(0,212,255,0.05) !important;
}
[data-testid="stTabs"] button[aria-selected="true"] {
    color: var(--cyan) !important;
    border-bottom-color: var(--cyan) !important;
}

/* ─── Alerts / Info boxes ─────────────────────────────────────────────────── */
.stAlert {
    border-radius: 4px !important;
    font-family: var(--font-body) !important;
    border-left-width: 3px !important;
}
.stSuccess { border-color: var(--green) !important; background: rgba(0,255,135,0.05) !important; }
.stWarning { border-color: var(--amber) !important; background: rgba(255,184,0,0.06) !important; }
.stError   { border-color: var(--red) !important;   background: rgba(255,23,68,0.06) !important; }
.stInfo    { border-color: var(--cyan) !important;  background: rgba(0,212,255,0.06) !important; }

/* ─── Expander ────────────────────────────────────────────────────────────── */
[data-testid="stExpander"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
}
[data-testid="stExpander"] summary {
    font-family: var(--font-display) !important;
    font-weight: 600 !important;
    letter-spacing: 0.05em !important;
    color: var(--cyan-dim) !important;
}

/* ─── Divider ─────────────────────────────────────────────────────────────── */
hr { border-color: var(--border) !important; }

/* ─── Checkbox ────────────────────────────────────────────────────────────── */
.stCheckbox > label { font-family: var(--font-body) !important; color: var(--text-primary) !important; }
.stCheckbox input:checked + div { background: var(--cyan) !important; border-color: var(--cyan) !important; }

/* ─── Scrollbar ───────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-secondary); }
::-webkit-scrollbar-thumb { background: var(--border-bright); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--cyan-dim); }

/* ─── Custom components ───────────────────────────────────────────────────── */
.nw-header {
    display: flex; align-items: center; gap: 16px;
    padding: 20px 0 16px 0; margin-bottom: 8px;
    border-bottom: 1px solid var(--border);
}
.nw-logo {
    font-family: var(--font-display); font-size: 2.2rem;
    font-weight: 700; color: var(--cyan);
    text-shadow: 0 0 20px rgba(0,212,255,0.4);
    letter-spacing: 0.1em; text-transform: uppercase;
}
.nw-logo-sub {
    font-family: var(--font-mono); font-size: 0.7rem;
    color: var(--text-secondary); letter-spacing: 0.15em;
    text-transform: uppercase; margin-top: 2px;
}
.nw-badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 3px 10px; border-radius: 3px; font-size: 0.72rem;
    font-family: var(--font-mono); font-weight: 700;
    letter-spacing: 0.08em; text-transform: uppercase;
}
.badge-online  { background: rgba(0,255,135,0.1); color: var(--green); border: 1px solid rgba(0,255,135,0.3); }
.badge-unknown { background: rgba(255,184,0,0.1); color: var(--amber); border: 1px solid rgba(255,184,0,0.3); }
.badge-suspect { background: rgba(255,23,68,0.1); color: var(--red); border: 1px solid rgba(255,23,68,0.3); }
.badge-known   { background: rgba(0,212,255,0.1); color: var(--cyan); border: 1px solid rgba(0,212,255,0.3); }
.badge-offline { background: rgba(61,90,122,0.2); color: var(--text-dim); border: 1px solid rgba(61,90,122,0.3); }

.nw-event-card {
    padding: 10px 14px; margin: 4px 0;
    border-radius: 4px; border-left: 3px solid;
    background: var(--bg-card); font-size: 0.85rem;
    font-family: var(--font-body);
}
.event-critical { border-color: var(--red); }
.event-high     { border-color: var(--orange); }
.event-medium   { border-color: var(--amber); }
.event-low      { border-color: var(--green); }
.event-info     { border-color: var(--cyan); }
.event-time {
    font-family: var(--font-mono); font-size: 0.75rem;
    color: var(--text-secondary); float: right;
}

.nw-risk-bar {
    height: 6px; border-radius: 3px; overflow: hidden;
    background: var(--bg-elevated); margin-top: 4px;
}
.nw-risk-fill {
    height: 100%; border-radius: 3px;
    transition: width 0.6s ease;
}

.nw-scan-pulse {
    display: inline-block; width: 8px; height: 8px;
    border-radius: 50%; background: var(--green);
    animation: pulse 1.5s ease-in-out infinite;
    margin-right: 6px;
}
@keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); box-shadow: 0 0 0 0 rgba(0,255,135,0.4); }
    50%       { opacity: 0.7; transform: scale(0.9); box-shadow: 0 0 0 4px rgba(0,255,135,0); }
}

.nw-status-offline { color: var(--text-dim); }
.nw-status-online  { color: var(--green); }
.nw-status-suspect { color: var(--red); }

.nw-section-label {
    font-family: var(--font-mono); font-size: 0.7rem;
    color: var(--text-dim); letter-spacing: 0.15em;
    text-transform: uppercase; margin-bottom: 12px;
    display: flex; align-items: center; gap: 8px;
}
.nw-section-label::before {
    content: ''; display: inline-block; width: 20px;
    height: 1px; background: var(--border-bright);
}
.nw-section-label::after {
    content: ''; flex: 1; height: 1px;
    background: linear-gradient(to right, var(--border), transparent);
}

.nw-topology-node {
    display: inline-block; padding: 6px 12px;
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: 4px; font-family: var(--font-mono);
    font-size: 0.75rem; margin: 4px;
}

.nw-checklist-item {
    display: flex; align-items: flex-start; gap: 10px;
    padding: 8px 12px; margin: 3px 0;
    background: var(--bg-card); border-radius: 4px;
    border-left: 2px solid var(--border);
}

/* ─── Sidebar overrides ───────────────────────────────────────────────────── */
.sidebar-title {
    font-family: var(--font-display) !important;
    font-size: 0.7rem !important;
    letter-spacing: 0.2em !important;
    text-transform: uppercase !important;
    color: var(--text-dim) !important;
    margin: 12px 0 4px 0 !important;
}

/* ─── Owner / Proprietário badges ────────────────────────────────────────── */
.owner-eu         { background:rgba(0,212,255,0.1);  color:#00D4FF; border:1px solid rgba(0,212,255,0.3); }
.owner-mae        { background:rgba(255,128,171,0.1); color:#FF80AB; border:1px solid rgba(255,128,171,0.3); }
.owner-familia    { background:rgba(105,240,174,0.1); color:#69F0AE; border:1px solid rgba(105,240,174,0.3); }
.owner-visitante  { background:rgba(255,215,64,0.1);  color:#FFD740; border:1px solid rgba(255,215,64,0.3); }
.owner-desconhecido { background:rgba(122,150,184,0.1); color:#7A96B8; border:1px solid rgba(122,150,184,0.3); }
.owner-intruso    { background:rgba(255,23,68,0.15);  color:#FF1744; border:1px solid rgba(255,23,68,0.4);
                    animation: intruso-pulse 1.5s ease-in-out infinite; }
@keyframes intruso-pulse {
    0%,100% { box-shadow: 0 0 0 0 rgba(255,23,68,0.3); }
    50%      { box-shadow: 0 0 0 5px rgba(255,23,68,0); }
}

/* ─── Family map cards ────────────────────────────────────────────────────── */
.nw-owner-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
    margin-bottom: 10px;
}
.nw-owner-card-header {
    font-family: var(--font-display);
    font-size: 1rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    margin-bottom: 10px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
}
.nw-device-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    border-radius: 20px;
    font-family: var(--font-mono);
    font-size: 0.78rem;
    margin: 3px;
    cursor: default;
}
.nw-intruder-banner {
    background: linear-gradient(135deg, rgba(255,23,68,0.15), rgba(255,109,0,0.1));
    border: 1px solid rgba(255,23,68,0.5);
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 12px;
    animation: intruso-pulse 2s ease-in-out infinite;
}
/* NÃO esconde header inteiro — ele contém o botão de abrir/fechar sidebar    */
footer { visibility: hidden !important; }
#MainMenu { visibility: hidden !important; }
.viewerBadge_container__1QSob { display: none !important; }
[data-testid="stDecoration"] { display: none !important; }
[data-testid="stStatusWidget"] { display: none !important; }

/* Esconde só o texto "Deploy" e afins dentro do header, mas mantém o toggle */
[data-testid="stToolbar"] { display: none !important; }

/* ─── Sidebar toggle button — sempre visível e estilizado ────────────────── */
[data-testid="collapsedControl"],
button[kind="header"] {
    color: var(--cyan) !important;
    background: var(--bg-secondary) !important;
    border: 1px solid var(--border) !important;
    border-radius: 4px !important;
}
[data-testid="collapsedControl"]:hover {
    background: var(--bg-elevated) !important;
    box-shadow: 0 0 10px rgba(0,212,255,0.2) !important;
}
</style>
"""

# ═══════════════════════════════════════════════════════════════════════════════
#  PERSISTÊNCIA
# ═══════════════════════════════════════════════════════════════════════════════

def load_db() -> dict:
    if DB_PATH.exists():
        try:
            return json.loads(DB_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "known":    {},   # mac_key → {name, category, notes, operator, ts_added}
        "seen":     {},   # mac_key → {ip, vendor, hostname, last_seen, first_seen, risk_score, ports}
        "blocked":  [],   # lista de mac_keys
        "suspects": [],   # lista de mac_keys
    }

def save_db(db: dict) -> None:
    DB_PATH.write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")

def load_events() -> list:
    if LOG_PATH.exists():
        try:
            return json.loads(LOG_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []

def save_events(events: list) -> None:
    # Mantém últimos 5000 eventos
    LOG_PATH.write_text(
        json.dumps(events[-5000:], indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

def load_config() -> dict:
    auto_range = detect_local_network()
    defaults = {
        "org_name":         "Segurança Pública",
        "org_unit":         "Central de Monitoramento",
        "operator":         "Operador",
        "default_range":    auto_range,
        "scan_timeout":     90,
        "auto_refresh":     False,
        "refresh_sec":      60,
        "alert_new":        True,
        "alert_suspect":    True,
        "enable_port_scan": False,
        "port_scan_args":   "-sV --top-ports 50 -T4 --max-retries 1 --host-timeout 8s",
        "theme_accent":     "cyan",
        "sudo_ok":          None,
    }
    if CONF_PATH.exists():
        try:
            saved = json.loads(CONF_PATH.read_text(encoding="utf-8"))
            defaults.update(saved)
            # Se o range salvo parece ser o default genérico antigo (192.168.1.0/24)
            # OU não bate com a rede atual detectada, reaplica o auto-detect
            saved_range = saved.get("default_range", "")
            if saved_range in ("192.168.1.0/24", DEFAULT_RANGE, ""):
                defaults["default_range"] = auto_range
        except Exception:
            pass
    return defaults
    if CONF_PATH.exists():
        try:
            saved = json.loads(CONF_PATH.read_text(encoding="utf-8"))
            defaults.update(saved)
        except Exception:
            pass
    return defaults

def save_config(conf: dict) -> None:
    CONF_PATH.write_text(json.dumps(conf, indent=2, ensure_ascii=False), encoding="utf-8")

def log_event(events: list, level: str, message: str, mac: str = "", ip: str = "") -> list:
    events.append({
        "ts":      int(time.time()),
        "level":   level,
        "message": message,
        "mac":     mac,
        "ip":      ip,
    })
    return events

# ═══════════════════════════════════════════════════════════════════════════════
#  SCAN ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

import socket
import ipaddress

def _can_sudo_nmap_nopass() -> bool:
    """
    Verifica silenciosamente se 'sudo nmap' roda sem pedir senha.
    Usa --version (rápido, sem scan real).
    """
    try:
        r = subprocess.run(
            ["sudo", "-n", "nmap", "--version"],
            capture_output=True, text=True, timeout=5
        )
        return r.returncode == 0
    except Exception:
        return False

def _nmap_cmd(use_sudo: bool, *args) -> list[str]:
    """Monta comando nmap com ou sem sudo."""
    base = ["sudo", "-n", "nmap"] if use_sudo else ["nmap"]
    return base + list(args)

def detect_local_network() -> str:
    """
    Detecta a rede local usando múltiplos métodos, do mais confiável ao menos.
    Retorna ex: '192.168.100.0/24'
    """
    import subprocess as _sp

    # Método 1: socket UDP (mais rápido, não abre conexão real)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("1.1.1.1", 80))
        local_ip = s.getsockname()[0]
        s.close()
        if not local_ip.startswith("127."):
            net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            return str(net)
    except Exception:
        pass

    # Método 2: hostname -I (Linux)
    try:
        r = _sp.run(["hostname", "-I"], capture_output=True, text=True, timeout=3)
        for part in r.stdout.strip().split():
            try:
                ip = ipaddress.IPv4Address(part)
                if not ip.is_loopback and not ip.is_link_local:
                    net = ipaddress.IPv4Network(f"{part}/24", strict=False)
                    return str(net)
            except Exception:
                pass
    except Exception:
        pass

    # Método 3: ip route (Linux)
    try:
        r = _sp.run(["ip", "route", "show", "default"],
                    capture_output=True, text=True, timeout=3)
        # ex: "default via 192.168.100.1 dev eth0 src 192.168.100.2"
        for token in r.stdout.split():
            try:
                ip = ipaddress.IPv4Address(token)
                if not ip.is_loopback:
                    net = ipaddress.IPv4Network(f"{token}/24", strict=False)
                    return str(net)
            except Exception:
                pass
    except Exception:
        pass

    return DEFAULT_RANGE

def run_nmap_discovery(target: str, use_sudo: bool, timeout_s: int = 60) -> str:
    """
    Fase 1 — Host discovery (-sn).
    Flags de timing agressivas para não travar:
      -T4              : timing agressivo
      --max-retries 1  : não retenta hosts que não respondem
      --host-timeout 5s: desiste de cada host após 5s
    Com sudo obtém MAC/vendor; sem sudo só obtém IPs (mas funciona sempre).
    """
    cmd = _nmap_cmd(use_sudo,
        "-sn", target,
        "-T4", "--max-retries", "1", "--host-timeout", "5s",
        "-oX", "-"
    )
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Scan expirou após {timeout_s}s. "
            "Tente uma faixa menor (ex: 192.168.100.0/24) ou aumente o timeout nas Configurações."
        )
    if p.returncode not in (0, 1):
        err = p.stderr.strip()
        if "password" in err.lower() or "sudoers" in err.lower():
            raise RuntimeError("SUDO_NEEDS_PASSWORD")
        raise RuntimeError(err or "Falha no Nmap (discovery).")
    return p.stdout

def run_nmap_portscan_batch(ips: list[str], args: str,
                             use_sudo: bool, timeout_s: int = 240) -> str:
    """
    Fase 2 (opcional) — Port scan nos IPs já descobertos.
    """
    if not ips:
        return "<nmaprun></nmaprun>"
    cmd = _nmap_cmd(use_sudo, *args.split(), *ips, "-oX", "-")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return "<nmaprun></nmaprun>"
    if p.returncode not in (0, 1):
        return "<nmaprun></nmaprun>"
    return p.stdout

def run_port_scan(ip: str, args: str, use_sudo: bool) -> str:
    """Scan de portas em um único IP (aba Dispositivos)."""
    cmd = _nmap_cmd(use_sudo, *args.split(), ip, "-oX", "-")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        return "<nmaprun></nmaprun>"
    return p.stdout

def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parseia XML do nmap para lista de dispositivos."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise ValueError(f"XML inválido: {e}")

    devices = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue

        ip = mac = vendor = hostname = None
        ports_found = []

        for addr in host.findall("address"):
            t = addr.attrib.get("addrtype")
            if t == "ipv4":   ip = addr.attrib.get("addr")
            elif t == "mac":
                mac    = addr.attrib.get("addr", "").upper()
                vendor = addr.attrib.get("vendor", "")

        hn = host.find("hostnames")
        if hn is not None:
            h = hn.find("hostname")
            if h is not None:
                hostname = h.attrib.get("name")

        # Portas (se disponível)
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                s = port.find("state")
                if s is not None and s.attrib.get("state") == "open":
                    portid = int(port.attrib.get("portid", 0))
                    svc = port.find("service")
                    svc_name = svc.attrib.get("name", "") if svc is not None else ""
                    ports_found.append({"port": portid, "service": svc_name})

        if ip:
            devices.append({
                "ip":        ip,
                "mac":       mac or "",
                "vendor":    vendor or "Desconhecido",
                "hostname":  hostname or "",
                "last_seen": int(time.time()),
                "ports":     ports_found,
            })
    return devices

def calculate_risk_score(device: dict, db: dict) -> tuple[int, str]:
    """Calcula risk score 0-100 e nível de ameaça."""
    mac_key = device["mac"] or f"NO_MAC::{device['ip']}"
    score = 0

    # Dispositivo desconhecido = +30
    if mac_key not in db.get("known", {}):
        score += 30
    # Suspeito = +50
    if mac_key in db.get("suspects", []):
        score += 50
    # Bloqueado = +70
    if mac_key in db.get("blocked", []):
        score += 70

    # Portas de risco
    seen_info = db.get("seen", {}).get(mac_key, {})
    ports = device.get("ports") or seen_info.get("ports", [])
    for p in ports:
        portid = p.get("port", 0)
        if portid in RISK_PORTS:
            _, risk = RISK_PORTS[portid]
            score += {"CRÍTICO": 20, "ALTO": 10, "MÉDIO": 5, "BAIXO": 2}.get(risk, 1)

    score = min(score, 100)

    if score >= 70: level = "CRÍTICO"
    elif score >= 50: level = "ALTO"
    elif score >= 25: level = "MÉDIO"
    elif score > 0:   level = "BAIXO"
    else:              level = "INFO"

    return score, level

def mac_key_of(d: dict) -> str:
    return d["mac"] if d["mac"] else f"NO_MAC::{d['ip']}"

# ═══════════════════════════════════════════════════════════════════════════════
#  RELATÓRIO PDF
# ═══════════════════════════════════════════════════════════════════════════════

def generate_pdf_report(db: dict, events: list, conf: dict, devices: list) -> bytes:
    """Gera relatório PDF profissional."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=2*cm, bottomMargin=2*cm,
        leftMargin=2.2*cm, rightMargin=2.2*cm,
        title="NetWatch — Relatório de Monitoramento"
    )

    styles = getSampleStyleSheet()
    content = []

    # Estilos
    title_style = ParagraphStyle(
        "NetWatchTitle", parent=styles["Title"],
        fontSize=22, textColor=colors.HexColor("#004A7C"),
        spaceAfter=6, fontName="Helvetica-Bold",
        letterSpacing=2
    )
    section_style = ParagraphStyle(
        "NetWatchSection", parent=styles["Heading2"],
        fontSize=12, textColor=colors.HexColor("#002A4C"),
        spaceBefore=14, spaceAfter=6, fontName="Helvetica-Bold",
        borderPad=4, backColor=colors.HexColor("#E8F4FD"),
        leftIndent=-10, rightIndent=-10
    )
    body_style = ParagraphStyle(
        "NetWatchBody", parent=styles["Normal"],
        fontSize=9, spaceAfter=4, fontName="Helvetica",
        textColor=colors.HexColor("#1A1A2E")
    )
    mono_style = ParagraphStyle(
        "NetWatchMono", parent=styles["Normal"],
        fontSize=8, fontName="Courier",
        textColor=colors.HexColor("#1A3A5C")
    )

    now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    current_macs = set(mac_key_of(d) for d in devices)

    # ── Cabeçalho ──────────────────────────────────────────────────
    content.append(Paragraph("NETWATCH", title_style))
    content.append(Paragraph("RELATÓRIO DE MONITORAMENTO DE REDE", ParagraphStyle(
        "sub", parent=styles["Normal"], fontSize=10,
        textColor=colors.HexColor("#004A7C"), fontName="Helvetica",
        letterSpacing=2, spaceAfter=12
    )))
    content.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#004A7C")))
    content.append(Spacer(1, 8))

    meta = [
        ["Organização", conf.get("org_name", "—")],
        ["Unidade",      conf.get("org_unit", "—")],
        ["Operador",     conf.get("operator", "—")],
        ["Data/Hora",    now_str],
        ["Rede alvo",    conf.get("default_range", "—")],
        ["Dispositivos online", str(len(devices))],
        ["Total histórico",     str(len(db.get("seen", {})))],
        ["Dispositivos conhecidos", str(len(db.get("known", {})))],
        ["Suspeitos", str(len(db.get("suspects", [])))],
    ]
    meta_table = Table(meta, colWidths=[5*cm, 12*cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#E8F4FD")),
        ("TEXTCOLOR",  (0,0), (0,-1), colors.HexColor("#003060")),
        ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",   (1,0), (1,-1), "Courier"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, colors.HexColor("#F5FAFF")]),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#C0D8EC")),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",(0,0), (-1,-1), 8),
        ("RIGHTPADDING",(0,0), (-1,-1), 8),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
    ]))
    content.append(meta_table)
    content.append(Spacer(1, 16))

    # ── Dispositivos ───────────────────────────────────────────────
    content.append(Paragraph("DISPOSITIVOS DETECTADOS", section_style))

    dev_rows = [["IP", "MAC", "Vendor/Hostname", "Status", "Risco", "Last Seen"]]
    for mac_k, info in db.get("seen", {}).items():
        status = "Online" if mac_k in current_macs else "Offline"
        known = db.get("known", {}).get(mac_k, {})
        name = known.get("name", "")
        is_suspect = mac_k in db.get("suspects", [])
        vendor_txt = info.get("vendor", "—")
        if name: vendor_txt += f" ({name})"
        if info.get("hostname"): vendor_txt += f"\n{info.get('hostname')}"
        risk_txt = "🔴 SUSPEITO" if is_suspect else ("✅ Conhecido" if mac_k in db.get("known", {}) else "— Desconhecido")
        mac_display = mac_k if not mac_k.startswith("NO_MAC::") else "(sem MAC)"
        ts = info.get("last_seen", 0)
        ts_str = datetime.fromtimestamp(ts).strftime("%d/%m %H:%M") if ts else "—"

        dev_rows.append([
            info.get("ip", "—"),
            mac_display,
            vendor_txt[:40],
            status,
            risk_txt,
            ts_str,
        ])

    dev_table = Table(dev_rows, colWidths=[3*cm, 4.5*cm, 4.5*cm, 2*cm, 3*cm, 2.5*cm])
    dev_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#003060")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("FONTNAME",   (0,1), (-1,-1), "Courier"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F0F8FF")]),
        ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#C0D8EC")),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",(0,0), (-1,-1), 5),
        ("RIGHTPADDING",(0,0), (-1,-1), 5),
        ("TOPPADDING", (0,0), (-1,-1), 3),
        ("BOTTOMPADDING",(0,0), (-1,-1), 3),
        ("ALIGN",      (3,0), (3,-1), "CENTER"),
    ]))
    content.append(dev_table)
    content.append(Spacer(1, 16))

    # ── Eventos recentes ───────────────────────────────────────────
    content.append(Paragraph("EVENTOS RECENTES (ÚLTIMOS 20)", section_style))
    ev_rows = [["Data/Hora", "Nível", "Mensagem", "IP"]]
    for ev in reversed(events[-20:]):
        ts = ev.get("ts", 0)
        ts_str = datetime.fromtimestamp(ts).strftime("%d/%m %H:%M:%S") if ts else "—"
        ev_rows.append([ts_str, ev.get("level",""), ev.get("message","")[:60], ev.get("ip","")])

    ev_table = Table(ev_rows, colWidths=[3.5*cm, 2.5*cm, 10*cm, 3*cm])
    ev_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#003060")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F0F8FF")]),
        ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#C0D8EC")),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",(0,0), (-1,-1), 5),
        ("TOPPADDING", (0,0), (-1,-1), 3),
        ("BOTTOMPADDING",(0,0), (-1,-1), 3),
    ]))
    content.append(ev_table)
    content.append(Spacer(1, 16))

    # ── Rodapé ─────────────────────────────────────────────────────
    content.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#C0D8EC")))
    content.append(Spacer(1, 6))
    content.append(Paragraph(
        f"NetWatch v{APP_VERSION} — Documento gerado em {now_str} — USO RESTRITO / OFICIAL",
        ParagraphStyle("footer", parent=styles["Normal"], fontSize=7,
                       textColor=colors.HexColor("#6A8AAA"), fontName="Helvetica")
    ))

    doc.build(content)
    return buffer.getvalue()

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS DE UI
# ═══════════════════════════════════════════════════════════════════════════════

def ts_fmt(ts: int, fmt: str = "%d/%m/%Y %H:%M:%S") -> str:
    if not ts: return "—"
    return datetime.fromtimestamp(ts).strftime(fmt)

def ts_ago(ts: int) -> str:
    if not ts: return "—"
    d = int(time.time()) - ts
    if d < 60:    return f"{d}s atrás"
    if d < 3600:  return f"{d//60}min atrás"
    if d < 86400: return f"{d//3600}h atrás"
    return f"{d//86400}d atrás"

def risk_color(level: str) -> str:
    return THREAT_LEVELS.get(level, {}).get("color", "#7A96B8")

def event_css_class(level: str) -> str:
    return {
        "CRÍTICO": "event-critical", "ALTO": "event-high",
        "MÉDIO": "event-medium", "BAIXO": "event-low", "INFO": "event-info"
    }.get(level, "event-info")

def render_event_card(ev: dict):
    ts  = ev.get("ts", 0)
    lvl = ev.get("level", "INFO")
    msg = ev.get("message", "")
    ip  = ev.get("ip", "")
    icon = THREAT_LEVELS.get(lvl, {}).get("icon", "🔵")
    cls  = event_css_class(lvl)
    detail = f" &nbsp;·&nbsp; <code>{ip}</code>" if ip else ""
    st.markdown(f"""
    <div class="nw-event-card {cls}">
        <span class="event-time">{ts_fmt(ts, "%d/%m %H:%M:%S")}</span>
        {icon} <strong>[{lvl}]</strong> {msg}{detail}
    </div>
    """, unsafe_allow_html=True)

def section_label(text: str):
    st.markdown(f'<div class="nw-section-label">{text}</div>', unsafe_allow_html=True)

def render_risk_bar(score: int, level: str):
    color = risk_color(level)
    st.markdown(f"""
    <div class="nw-risk-bar">
        <div class="nw-risk-fill" style="width:{score}%; background:{color};"></div>
    </div>
    """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  GRÁFICOS — matplotlib dark theme
# ═══════════════════════════════════════════════════════════════════════════════

BG_PRIMARY   = "#070B14"
BG_CARD      = "#111B2E"
BG_ELEVATED  = "#162038"
BORDER_COL   = "#1E3A5F"
TEXT_PRIMARY = "#E0EAF5"
TEXT_DIM     = "#3D5A7A"
CYAN         = "#00D4FF"
AMBER        = "#FFB800"
GREEN        = "#00FF87"
RED_COL      = "#FF1744"
ORANGE       = "#FF6D00"

LEVEL_COLORS = {
    "CRÍTICO": RED_COL, "ALTO": ORANGE, "MÉDIO": AMBER,
    "BAIXO": GREEN, "INFO": CYAN,
}

def _base_fig(w=6, h=3.2):
    """Cria figure com fundo escuro padrão NetWatch."""
    fig, ax = plt.subplots(figsize=(w, h))
    fig.patch.set_facecolor(BG_CARD)
    ax.set_facecolor(BG_CARD)
    for spine in ax.spines.values():
        spine.set_edgecolor(BORDER_COL)
    ax.tick_params(colors=TEXT_PRIMARY, labelsize=8)
    ax.xaxis.label.set_color(TEXT_PRIMARY)
    ax.yaxis.label.set_color(TEXT_PRIMARY)
    return fig, ax

def chart_risk_donut(risk_counts: dict) -> plt.Figure:
    """Donut chart de distribuição de risco."""
    labels = [k for k, v in risk_counts.items() if v > 0]
    sizes  = [v for v in risk_counts.values() if v > 0]
    colors_list = [LEVEL_COLORS.get(l, CYAN) for l in labels]

    if not sizes:
        fig, ax = _base_fig(4, 3)
        ax.text(0.5, 0.5, "Sem dados", ha="center", va="center",
                color=TEXT_DIM, fontsize=11, transform=ax.transAxes)
        ax.axis("off")
        return fig

    fig, ax = plt.subplots(figsize=(4, 3.2))
    fig.patch.set_facecolor(BG_CARD)
    ax.set_facecolor(BG_CARD)

    wedges, texts, autotexts = ax.pie(
        sizes, labels=None, colors=colors_list,
        autopct=lambda p: f"{p:.0f}%" if p > 5 else "",
        startangle=90, pctdistance=0.75,
        wedgeprops={"linewidth": 1.5, "edgecolor": BG_PRIMARY, "width": 0.5},
    )
    for at in autotexts:
        at.set_color(BG_PRIMARY)
        at.set_fontsize(8)
        at.set_fontweight("bold")

    # Legenda
    legend_patches = [
        mpatches.Patch(color=LEVEL_COLORS.get(l, CYAN), label=f"{l}  {v}")
        for l, v in zip(labels, sizes)
    ]
    ax.legend(handles=legend_patches, loc="lower center",
              bbox_to_anchor=(0.5, -0.18), ncol=3,
              fontsize=7.5, frameon=False,
              labelcolor=TEXT_PRIMARY)

    # Total no centro
    total = sum(sizes)
    ax.text(0, 0, str(total), ha="center", va="center",
            color=CYAN, fontsize=18, fontweight="bold")
    ax.text(0, -0.22, "dispositivos", ha="center", va="center",
            color=TEXT_DIM, fontsize=7)

    ax.set_title("Distribuição de Risco", color=TEXT_PRIMARY,
                 fontsize=9, pad=8, fontweight="bold", loc="left")
    plt.tight_layout(pad=0.5)
    return fig

def chart_vendor_hbar(vendor_map: dict, max_items: int = 8) -> plt.Figure:
    """Horizontal bar chart de vendors."""
    top = sorted(vendor_map.items(), key=lambda x: x[1], reverse=True)[:max_items]
    if not top:
        fig, ax = _base_fig(5, 2.5)
        ax.text(0.5, 0.5, "Sem dados", ha="center", va="center",
                color=TEXT_DIM, fontsize=11, transform=ax.transAxes)
        ax.axis("off")
        return fig

    labels_v = [t[0][:22] for t in top]
    values_v = [t[1] for t in top]
    # Gradiente de cores por posição
    bar_colors = [CYAN if i == 0 else (
        "#0099BB" if i == 1 else "#006688" if i == 2 else BORDER_COL
    ) for i in range(len(labels_v))]

    fig, ax = _base_fig(5, max(2.2, len(top) * 0.42 + 0.4))
    bars = ax.barh(labels_v[::-1], values_v[::-1], color=bar_colors[::-1],
                   height=0.6, edgecolor="none")

    # Valores no fim de cada barra
    for bar, val in zip(bars, values_v[::-1]):
        ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", ha="left",
                color=CYAN, fontsize=8, fontweight="bold")

    ax.set_xlim(0, max(values_v) * 1.25)
    ax.set_xlabel("Quantidade", color=TEXT_DIM, fontsize=7)
    ax.set_title("Vendors Detectados", color=TEXT_PRIMARY,
                 fontsize=9, pad=8, fontweight="bold", loc="left")
    ax.grid(axis="x", color=BORDER_COL, linewidth=0.5, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_visible(False)
    plt.tight_layout(pad=0.5)
    return fig

def chart_events_timeline(events: list, last_n: int = 40) -> plt.Figure:
    """Scatter timeline de eventos recentes por nível."""
    recent = events[-last_n:] if events else []
    if not recent:
        fig, ax = _base_fig(7, 2)
        ax.text(0.5, 0.5, "Sem eventos ainda", ha="center", va="center",
                color=TEXT_DIM, fontsize=10, transform=ax.transAxes)
        ax.axis("off")
        return fig

    level_y = {"CRÍTICO": 4, "ALTO": 3, "MÉDIO": 2, "BAIXO": 1, "INFO": 0}
    fig, ax = _base_fig(7, 2.8)

    xs, ys, cs, ss = [], [], [], []
    for ev in recent:
        ts  = ev.get("ts", 0)
        lvl = ev.get("level", "INFO")
        xs.append(datetime.fromtimestamp(ts))
        ys.append(level_y.get(lvl, 0))
        cs.append(LEVEL_COLORS.get(lvl, CYAN))
        ss.append(60 if lvl in ("CRÍTICO","ALTO") else 30)

    ax.scatter(xs, ys, c=cs, s=ss, zorder=3, edgecolors="none", alpha=0.85)
    ax.plot(xs, ys, color=BORDER_COL, linewidth=0.5, zorder=2, alpha=0.4)

    ax.set_yticks(list(level_y.values()))
    ax.set_yticklabels(list(level_y.keys()), fontsize=7.5)
    for tick, lvl in zip(ax.get_yticklabels(), level_y.keys()):
        tick.set_color(LEVEL_COLORS.get(lvl, CYAN))

    ax.grid(axis="y", color=BORDER_COL, linewidth=0.4, linestyle="--", alpha=0.4)
    ax.grid(axis="x", color=BORDER_COL, linewidth=0.3, linestyle=":", alpha=0.3)
    for spine in ax.spines.values():
        spine.set_visible(False)

    import matplotlib.dates as mdates
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    fig.autofmt_xdate(rotation=30, ha="right")
    ax.set_title("Timeline de Eventos", color=TEXT_PRIMARY,
                 fontsize=9, pad=6, fontweight="bold", loc="left")
    plt.tight_layout(pad=0.5)
    return fig

def chart_ports_hbar(port_freq: dict, max_items: int = 12) -> plt.Figure:
    """Horizontal bar chart de portas abertas."""
    top = sorted(port_freq.items(), key=lambda x: x[1], reverse=True)[:max_items]
    if not top:
        fig, ax = _base_fig(6, 2)
        ax.text(0.5, 0.5, "Sem dados de portas", ha="center", va="center",
                color=TEXT_DIM, fontsize=10, transform=ax.transAxes)
        ax.axis("off")
        return fig

    labels_p = [t[0][:28] for t in top]
    values_p = [t[1] for t in top]

    # Cores baseadas no risco da porta
    def port_color(label):
        for portid, (svc, risk) in RISK_PORTS.items():
            if str(portid) in label or svc.lower() in label.lower():
                return LEVEL_COLORS.get(risk, CYAN)
        return "#006688"

    bar_colors_p = [port_color(l) for l in labels_p]

    fig, ax = _base_fig(6, max(2.5, len(top) * 0.44 + 0.5))
    bars = ax.barh(labels_p[::-1], values_p[::-1],
                   color=bar_colors_p[::-1], height=0.62, edgecolor="none")

    for bar, val in zip(bars, values_p[::-1]):
        ax.text(bar.get_width() + 0.03, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", ha="left",
                color=CYAN, fontsize=8, fontweight="bold")

    ax.set_xlim(0, max(values_p) * 1.3)
    ax.set_xlabel("Ocorrências", color=TEXT_DIM, fontsize=7)
    ax.set_title("Portas Abertas — Top " + str(len(top)),
                 color=TEXT_PRIMARY, fontsize=9, pad=8, fontweight="bold", loc="left")
    ax.grid(axis="x", color=BORDER_COL, linewidth=0.5, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_visible(False)
    plt.tight_layout(pad=0.5)
    return fig

# ═══════════════════════════════════════════════════════════════════════════════
#  INICIALIZAÇÃO
# ═══════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="NetWatch — Central de Monitoramento",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
st.markdown(DARK_CSS, unsafe_allow_html=True)

db     = load_db()
events = load_events()
conf   = load_config()

# ═══════════════════════════════════════════════════════════════════════════════
#  CABEÇALHO PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════════

def get_system_status() -> str:
    """Verifica se nmap está disponível."""
    try:
        r = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
        return r.stdout.split("\n")[0] if r.returncode == 0 else "Nmap não encontrado"
    except Exception:
        return "Nmap não encontrado"

status_indicator = '<span class="nw-scan-pulse"></span>'
now_str = datetime.now().strftime("%d/%m/%Y — %H:%M:%S")

st.markdown(f"""
<div class="nw-header">
    <div>
        <div class="nw-logo">🛡️ NETWATCH</div>
        <div class="nw-logo-sub">{conf.get('org_name','Sistema')} · {conf.get('org_unit','Monitoramento')} · v{APP_VERSION}</div>
    </div>
    <div style="flex:1"></div>
    <div style="text-align:right">
        {status_indicator}<span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-secondary)">{now_str}</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown(f"""
    <div style="text-align:center; padding: 12px 0 8px 0;">
        <div style="font-family:var(--font-display); font-size:1.4rem; font-weight:700;
                    color:var(--cyan); letter-spacing:0.15em;">NETWATCH</div>
        <div style="font-family:var(--font-mono); font-size:0.65rem; color:var(--text-dim);
                    letter-spacing:0.1em; margin-top:2px;">CENTRAL DE SEGURANÇA</div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    st.markdown('<div class="sidebar-title">Alvo do Scan</div>', unsafe_allow_html=True)

    # Botão de auto-detecção
    col_range, col_detect = st.columns([3, 1])
    with col_detect:
        if st.button("⟳", help="Detectar rede automaticamente", width="stretch"):
            detected = detect_local_network()
            conf["default_range"] = detected
            save_config(conf)
            st.rerun()

    with col_range:
        target_range = st.text_input(
            "Faixa de Rede",
            value=conf.get("default_range", detect_local_network()),
            label_visibility="collapsed",
        )

    st.markdown('<div class="sidebar-title">Controles</div>', unsafe_allow_html=True)
    col_run, col_stop = st.columns(2)
    with col_run:
        run_now = st.button("▶ SCAN", width="stretch")
    with col_stop:
        clear_scan = st.button("✕ LIMPAR", width="stretch")

    st.markdown('<div class="sidebar-title">Auto-Refresh</div>', unsafe_allow_html=True)
    auto_refresh = st.checkbox("Ativo", value=conf.get("auto_refresh", False))
    refresh_sec  = st.select_slider(
        "Intervalo", options=[15, 30, 60, 120, 300],
        value=conf.get("refresh_sec", 60),
        format_func=lambda x: f"{x}s"
    )

    st.markdown('<div class="sidebar-title">Scan Avançado</div>', unsafe_allow_html=True)
    enable_port_scan = st.checkbox(
        "Scan de Portas", value=conf.get("enable_port_scan", False)
    )
    port_scan_args = st.text_input(
        "Args Nmap", value=conf.get("port_scan_args", "-sV --top-ports 50 -T4 --max-retries 1 --host-timeout 8s"),
        label_visibility="collapsed"
    )
    scan_timeout_val = conf.get("scan_timeout", 90)
    # Garante que o valor salvo está na lista de opções
    timeout_options = [30, 45, 60, 90, 120, 180, 240]
    if scan_timeout_val not in timeout_options:
        scan_timeout_val = 90
    scan_timeout = st.select_slider(
        "Timeout do scan",
        options=timeout_options,
        value=scan_timeout_val,
        format_func=lambda x: f"{x}s",
    )
    if enable_port_scan:
        st.markdown("""
        <div style="font-family:var(--font-mono); font-size:0.68rem; color:var(--amber);
                    background:rgba(255,184,0,0.07); border:1px solid rgba(255,184,0,0.2);
                    border-radius:4px; padding:6px 8px; margin-top:4px; line-height:1.5;">
            ⚡ Modo 2 fases:<br>
            1. Discovery rápido (/24)<br>
            2. Port scan só nos hosts ativos<br>
            <span style="color:var(--text-dim)">Mais lento, mais detalhes.</span>
        </div>
        """, unsafe_allow_html=True)

    st.divider()
    st.markdown('<div class="sidebar-title">Operador</div>', unsafe_allow_html=True)
    operator = st.text_input("Nome do Operador", value=conf.get("operator", "Operador"), label_visibility="collapsed")

    # Status do sistema
    st.divider()
    nmap_ver   = get_system_status()
    is_nmap_ok = "não encontrado" not in nmap_ver.lower()
    sudo_state = st.session_state.get("sudo_ok", None)

    sudo_icon  = "✓" if sudo_state else ("✗" if sudo_state is False else "?")
    sudo_color = "var(--green)" if sudo_state else ("var(--red)" if sudo_state is False else "var(--amber)")
    sudo_label = "sudo OK (MAC/Vendor)" if sudo_state else ("sem sudo (só IPs)" if sudo_state is False else "não testado")

    st.markdown(f"""
    <div style="font-family:var(--font-mono); font-size:0.7rem;
                color:{'var(--green)' if is_nmap_ok else 'var(--red)'}; margin-bottom:4px;">
        {'✓' if is_nmap_ok else '✗'} {nmap_ver[:38] if is_nmap_ok else 'Nmap não instalado'}
    </div>
    <div style="font-family:var(--font-mono); font-size:0.7rem;
                color:{sudo_color}; margin-bottom:4px;">
        {sudo_icon} {sudo_label}
    </div>
    <div style="font-family:var(--font-mono); font-size:0.7rem;
                color:{'var(--green)' if REPORTLAB_OK else 'var(--amber)'};">
        {'✓ ReportLab OK' if REPORTLAB_OK else '⚠ ReportLab ausente'}
    </div>
    """, unsafe_allow_html=True)

    # Salva config
    conf.update({
        "default_range":    target_range,
        "auto_refresh":     auto_refresh,
        "refresh_sec":      refresh_sec,
        "operator":         operator,
        "enable_port_scan": enable_port_scan,
        "port_scan_args":   port_scan_args,
        "scan_timeout":     scan_timeout,
    })
    save_config(conf)

# ═══════════════════════════════════════════════════════════════════════════════
#  LÓGICA DE SCAN
# ═══════════════════════════════════════════════════════════════════════════════

if clear_scan:
    if "last_scan" in st.session_state:
        del st.session_state["last_scan"]
    if "sudo_ok" in st.session_state:
        del st.session_state["sudo_ok"]
    st.rerun()

# ── Detecta sudo uma vez por sessão ────────────────────────────────────────
if "sudo_ok" not in st.session_state:
    st.session_state["sudo_ok"] = _can_sudo_nmap_nopass()

use_sudo: bool = st.session_state["sudo_ok"]

# Banner de status do sudo (uma vez, persistente na sessão)
if not use_sudo:
    st.warning(
        "⚠️ **nmap sem privilégios root** — IPs serão detectados, "
        "mas endereços MAC e vendors podem não aparecer.  \n"
        "Para ativar root: execute o comando abaixo no terminal e reinicie o app:",
        icon="🔑"
    )
    st.code(
        f"echo '{os.environ.get('USER','walbarellos')} ALL=(ALL) NOPASSWD: /usr/bin/nmap' "
        "| sudo tee /etc/sudoers.d/netwatch-nmap",
        language="bash"
    )

scan_timeout = conf.get("scan_timeout", 60)

if run_now or ("last_scan" not in st.session_state):
    try:
        # ── FASE 1: Discovery (ping scan, sempre rápido) ───────────────────
        with st.spinner(f"📡 Fase 1/2 — Discovery em {target_range}  ·  timeout {scan_timeout}s..."):
            try:
                xml_discovery = run_nmap_discovery(target_range, use_sudo, scan_timeout)
            except RuntimeError as e:
                if "SUDO_NEEDS_PASSWORD" in str(e):
                    # Sudo pediu senha — tenta sem sudo
                    st.session_state["sudo_ok"] = False
                    use_sudo = False
                    xml_discovery = run_nmap_discovery(target_range, False, scan_timeout)
                else:
                    raise

            scanned = parse_nmap_xml(xml_discovery)

        # ── FASE 2: Port scan opcional — só nos IPs já descobertos ────────
        if enable_port_scan and scanned:
            alive_ips = [d["ip"] for d in scanned]
            n = len(alive_ips)
            with st.spinner(f"🔌 Fase 2/2 — Port scan em {n} host(s) ativos..."):
                xml_ports = run_nmap_portscan_batch(
                    alive_ips, port_scan_args, use_sudo
                )
                scanned_ports = parse_nmap_xml(xml_ports)

            port_map: dict[str, list] = {d["ip"]: d.get("ports", []) for d in scanned_ports}
            for d in scanned:
                if d["ip"] in port_map:
                    d["ports"] = port_map[d["ip"]]
                    ps = next((x for x in scanned_ports if x["ip"] == d["ip"]), {})
                    if not d["vendor"] and ps.get("vendor"):
                        d["vendor"] = ps["vendor"]
                    if not d["hostname"] and ps.get("hostname"):
                        d["hostname"] = ps["hostname"]

        st.session_state["last_scan"]      = scanned
        st.session_state["last_scan_time"] = int(time.time())
        st.session_state["scan_range"]     = target_range

        # ── DIFF ENGINE — compara com scan anterior ────────────────────────
        # prev_live_keys = IPs/MACs que estavam ONLINE no scan anterior
        prev_live_keys: set = st.session_state.get("live_keys", set())
        curr_live_keys: set = {mac_key_of(d) for d in scanned}

        # Dispositivos que ENTRARAM na rede agora
        joined_keys = curr_live_keys - prev_live_keys
        # Dispositivos que SAÍRAM da rede
        left_keys   = prev_live_keys - curr_live_keys

        # É o primeiro scan da sessão? Se sim, não gera alertas de "entrou"
        # (evita flood de toasts ao iniciar o app)
        is_first_scan = len(prev_live_keys) == 0

        toasts_to_fire = []  # (msg, icon) — fire depois de save
        popup_alerts_to_fire = [] # Lista para alertas pop-up de alta prioridade

        for mk in joined_keys:
            d_info = next((d for d in scanned if mac_key_of(d) == mk), None)
            ip     = d_info["ip"] if d_info else mk
            vendor = (d_info["vendor"] if d_info else "") or "Desconhecido"
            known  = db["known"].get(mk, {})
            name   = known.get("name", "")

            # Classifica gravidade do evento de entrada
            if mk in db.get("blocked", []):
                lvl = "CRÍTICO"
                msg = f"🚫 BLOQUEADO entrou na rede: {ip} ({vendor})"
                events = log_event(events, lvl, msg, mac=mk, ip=ip)
                if not is_first_scan:
                    toasts_to_fire.append((f"🚫 BLOQUEADO: {ip} {name}", "🔴"))
                    popup_alerts_to_fire.append(f"ALERTA CRÍTICO: Dispositivo BLOQUEADO conectou-se à rede!\nIP: {ip}\nVendor: {vendor}")

            elif mk in db.get("suspects", []):
                lvl = "ALTO"
                msg = f"⚠ SUSPEITO conectou: {ip} ({vendor})"
                events = log_event(events, lvl, msg, mac=mk, ip=ip)
                if not is_first_scan:
                    toasts_to_fire.append((f"⚠️ SUSPEITO online: {ip}", "🟠"))
                    popup_alerts_to_fire.append(f"ALERTA: Dispositivo SUSPEITO online!\nIP: {ip}\nVendor: {vendor}")

            elif mk not in db.get("known", {}):
                lvl = "MÉDIO"
                msg = f"Novo dispositivo: {ip} ({vendor})"
                events = log_event(events, lvl, msg, mac=mk, ip=ip)
                if not is_first_scan:
                    toasts_to_fire.append((f"🆕 Novo na rede: {ip} · {vendor}", "🟡"))
                    popup_alerts_to_fire.append(f"NOVO DISPOSITIVO DETECTADO:\nIP: {ip}\nVendor: {vendor}\n\nClassifique este dispositivo na aba 'Dispositivos'.")
            else:
                events = log_event(events, "INFO",
                    f"Dispositivo conhecido conectou: {name or ip}", mac=mk, ip=ip)

        for mk in left_keys:
            info  = db["seen"].get(mk, {})
            ip    = info.get("ip", mk)
            known = db["known"].get(mk, {})
            name  = known.get("name", "")
            label = name or info.get("vendor") or ip

            if mk in db.get("suspects", []) or mk in db.get("blocked", []):
                events = log_event(events, "INFO",
                    f"Dispositivo de risco saiu da rede: {ip}", mac=mk, ip=ip)
                if not is_first_scan:
                    toasts_to_fire.append((f"📴 Saiu: {label}", "🔵"))
            else:
                events = log_event(events, "INFO",
                    f"Dispositivo saiu da rede: {ip} ({label})", mac=mk, ip=ip)
                if not is_first_scan:
                    toasts_to_fire.append((f"📴 {label} saiu da rede", "⚫"))

        # Atualiza live_keys na sessão
        st.session_state["live_keys"] = curr_live_keys

        # Atualiza seen
        prev_db_keys = set(db["seen"].keys())
        for d in scanned:
            mk = mac_key_of(d)
            prev = db["seen"].get(mk, {})
            risk_score, risk_level = calculate_risk_score(d, db)
            db["seen"][mk] = {
                "ip":         d["ip"],
                "vendor":     d["vendor"],
                "hostname":   d["hostname"],
                "last_seen":  d["last_seen"],
                "first_seen": prev.get("first_seen", d["last_seen"]),
                "risk_score": risk_score,
                "risk_level": risk_level,
                "ports":      d.get("ports") or prev.get("ports", []),
            }

        phase_txt = " (com port scan)" if enable_port_scan else ""
        events = log_event(events, "INFO",
            f"Scan concluído{phase_txt}: {len(scanned)} dispositivos em {target_range}",
            ip=target_range)
        save_db(db)
        save_events(events)

        # ── Dispara toasts APÓS salvar ─────────────────────────────────────
        for msg, icon in toasts_to_fire:
            st.toast(msg, icon=icon)

        # ── Dispara alertas pop-up de alta prioridade ──────────────────────
        if popup_alerts_to_fire:
            # Junta todos os alertas em uma única mensagem, separados por linhas
            alert_text = "\\n\\n".join(popup_alerts_to_fire)
            # Escapa caracteres que podem quebrar o JavaScript
            alert_text = alert_text.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"').replace("\n", "\\n")
            
            st_components.html(f'''
                <script>
                // O timeout garante que o script rode após o Streamlit terminar de renderizar
                // outros elementos, tornando o alerta menos propenso a bloquear a UI.
                setTimeout(function() {{
                    alert('{alert_text}');
                }}, 200);
                </script>
            ''', height=0)

        # ── Alerta sonoro via JavaScript (se teve entradas/saídas críticas) ─
        has_critical = any(
            mk in db.get("blocked", []) or mk in db.get("suspects", [])
            for mk in (joined_keys | left_keys)
        ) and not is_first_scan
        has_new = bool(joined_keys) and not is_first_scan

        if has_critical or has_new:
            # Beep via Web Audio API — sem dependências externas
            beep_freq  = 880 if has_critical else 440
            beep_count = 3   if has_critical else 1
            st_components.html(f"""
            <script>
            (function() {{
                try {{
                    var ctx = new (window.AudioContext || window.webkitAudioContext)();
                    var play = function(t, freq, dur) {{
                        var osc  = ctx.createOscillator();
                        var gain = ctx.createGain();
                        osc.connect(gain);
                        gain.connect(ctx.destination);
                        osc.type = 'sine';
                        osc.frequency.setValueAtTime(freq, t);
                        gain.gain.setValueAtTime(0.18, t);
                        gain.gain.exponentialRampToValueAtTime(0.001, t + dur);
                        osc.start(t);
                        osc.stop(t + dur + 0.05);
                    }};
                    var now = ctx.currentTime;
                    for (var i = 0; i < {beep_count}; i++) {{
                        play(now + i * 0.28, {beep_freq}, 0.18);
                    }}
                }} catch(e) {{}}
            }})();
            </script>
            """, height=0)

    except FileNotFoundError:
        st.error("❌ Nmap não encontrado. Instale: `sudo pacman -S nmap` ou `sudo apt install nmap`")
        st.stop()
    except RuntimeError as e:
        st.error(f"❌ Erro no scan: {e}")
        st.stop()
    except Exception as e:
        st.error(f"❌ Erro inesperado: {e}")
        st.stop()

devices    = st.session_state.get("last_scan", [])
scan_time  = st.session_state.get("last_scan_time", 0)
scan_range = st.session_state.get("scan_range", target_range)

current_macs = set(mac_key_of(d) for d in devices)
unknown_keys  = [k for k in current_macs if k not in db["known"]]
suspect_keys  = [k for k in current_macs if k in db.get("suspects", [])]
blocked_keys  = [k for k in current_macs if k in db.get("blocked", [])]

# ═══════════════════════════════════════════════════════════════════════════════
#  MÉTRICAS GLOBAIS
# ═══════════════════════════════════════════════════════════════════════════════

section_label("STATUS GERAL DA REDE")

col_m1, col_m2, col_m3, col_m4, col_m5, col_m6 = st.columns(6)
col_m1.metric("Online Agora",    len(devices),             delta=None)
col_m2.metric("Desconhecidos",   len(unknown_keys),         delta=None)
col_m3.metric("Suspeitos",       len(suspect_keys),         delta=None)
col_m4.metric("Bloqueados",      len(blocked_keys),         delta=None)
col_m5.metric("Total Histórico", len(db["seen"]),           delta=None)
col_m6.metric("Último Scan",     ts_fmt(scan_time, "%H:%M:%S") if scan_time else "—", delta=None)

# Alertas de destaque
if blocked_keys:
    st.error(f"🚨 **CRÍTICO** — {len(blocked_keys)} dispositivo(s) BLOQUEADO(S) detectado(s) na rede!")
if suspect_keys:
    st.warning(f"⚠️ **ALERTA** — {len(suspect_keys)} dispositivo(s) SUSPEITO(S) online!")
if unknown_keys:
    st.info(f"ℹ️ **INFO** — {len(unknown_keys)} dispositivo(s) não identificado(s). Revise e classifique.")

# ═══════════════════════════════════════════════════════════════════════════════
#  ABAS PRINCIPAIS
# ═══════════════════════════════════════════════════════════════════════════════

tab_dash, tab_family, tab_devices, tab_alerts, tab_ports, tab_report, tab_config = st.tabs([
    "⬡  DASHBOARD",
    "👨‍👩‍👦  FAMÍLIA",
    "🖥  DISPOSITIVOS",
    "🚨  EVENTOS",
    "🔌  PORTAS & SERVIÇOS",
    "📋  RELATÓRIOS",
    "⚙  CONFIGURAÇÕES",
])

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 — DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

with tab_dash:
    # ── Linha de gráficos de topo ───────────────────────────────────────────
    gcol1, gcol2, gcol3 = st.columns([1.3, 1.7, 2.0])

    with gcol1:
        # Donut de risco
        risk_counts = {"CRÍTICO":0, "ALTO":0, "MÉDIO":0, "BAIXO":0, "INFO":0}
        for d in devices:
            mk = mac_key_of(d)
            rl = db["seen"].get(mk, {}).get("risk_level", "INFO")
            if not db["known"].get(mk):
                rl = db["seen"].get(mk, {}).get("risk_level", "MÉDIO")
            risk_counts[rl] = risk_counts.get(rl, 0) + 1
        # Se nenhum device ainda, mostra histórico
        if not devices and db["seen"]:
            for mk, info in db["seen"].items():
                rl = info.get("risk_level", "INFO")
                risk_counts[rl] = risk_counts.get(rl, 0) + 1

        fig_donut = chart_risk_donut(risk_counts)
        st.pyplot(fig_donut, width="stretch")
        plt.close(fig_donut)

    with gcol2:
        # Vendors
        vendor_map: dict[str, int] = {}
        source = devices if devices else []
        for d in source:
            v = d["vendor"] or "Desconhecido"
            vendor_map[v] = vendor_map.get(v, 0) + 1
        if not vendor_map and db["seen"]:
            for info in db["seen"].values():
                v = info.get("vendor") or "Desconhecido"
                vendor_map[v] = vendor_map.get(v, 0) + 1

        fig_vendor = chart_vendor_hbar(vendor_map)
        st.pyplot(fig_vendor, width="stretch")
        plt.close(fig_vendor)

    with gcol3:
        # Timeline de eventos
        fig_timeline = chart_events_timeline(events)
        st.pyplot(fig_timeline, width="stretch")
        plt.close(fig_timeline)

    st.divider()

    # ── Tabela de dispositivos + feed de eventos ────────────────────────────
    col_left, col_right = st.columns([3, 1])

    with col_left:
        section_label("DISPOSITIVOS ATIVOS")

        rows = []
        # IPs que acabaram de entrar neste scan (para badge visual ★)
        curr_live = st.session_state.get("live_keys", set())
        prev_snap = st.session_state.get("prev_live_snapshot", curr_live)
        joined_now = curr_live - prev_snap
        st.session_state["prev_live_snapshot"] = curr_live.copy()

        for d in sorted(devices, key=lambda x: (
            0 if mac_key_of(x) in db.get("blocked",[]) else
            1 if mac_key_of(x) in db.get("suspects",[]) else
            2 if mac_key_of(x) not in db.get("known",{}) else 3,
            x["ip"]
        )):
            mk = mac_key_of(d)
            known  = db["known"].get(mk, {})
            seen   = db["seen"].get(mk, {})
            risk   = seen.get("risk_score", 0)
            rlvl   = seen.get("risk_level", "INFO")
            icon   = THREAT_LEVELS.get(rlvl, {}).get("icon", "🔵")

            if mk in db.get("blocked", []):    tag = "🚫 BLOQUEADO"
            elif mk in db.get("suspects", []): tag = "⚠️ SUSPEITO"
            elif mk in db.get("known", {}):    tag = "✅ CONHECIDO"
            else:                               tag = "❓ DESCONHECIDO"

            # Badge de novo dispositivo detectado neste ciclo
            ip_label = f"★ {d['ip']}" if mk in joined_now else d["ip"]

            rows.append({
                "⚠": f"{icon} {risk:3d}",
                "IP": ip_label,
                "Nome / Vendor": (known.get("name") or d["vendor"] or "—")[:30],
                "Hostname": (d["hostname"] or "—")[:25],
                "Categoria": known.get("category", "—"),
                "MAC": d["mac"] or "(sem MAC)",
                "Classificação": tag,
                "Visto": ts_ago(d["last_seen"]),
            })

        if rows:
            df_dash = pd.DataFrame(rows)
            st.dataframe(
                df_dash,
                width="stretch",
                hide_index=True,
                height=min(420, 38 + len(rows) * 36),
                column_config={
                    "⚠": st.column_config.TextColumn("⚠ Risco", width="small"),
                    "IP": st.column_config.TextColumn("IP", width="small"),
                    "Classificação": st.column_config.TextColumn("Status", width="medium"),
                }
            )
        else:
            st.markdown("""
            <div style="text-align:center; padding:60px 20px; background:var(--bg-card);
                        border:1px dashed var(--border); border-radius:6px;">
                <div style="font-family:var(--font-display); font-size:1.1rem;
                            color:var(--text-dim); letter-spacing:0.1em;">
                    AGUARDANDO SCAN
                </div>
                <div style="font-family:var(--font-mono); font-size:0.75rem;
                            color:var(--text-dim); margin-top:8px;">
                    Clique em ▶ SCAN na barra lateral
                </div>
            </div>
            """, unsafe_allow_html=True)

        # Dispositivos offline
        offline_keys = [k for k in db["seen"] if k not in current_macs]
        if offline_keys:
            with st.expander(f"📴 Offline no histórico — {len(offline_keys)} dispositivo(s)"):
                off_rows = []
                for mk in offline_keys:
                    info  = db["seen"][mk]
                    known = db["known"].get(mk, {})
                    off_rows.append({
                        "IP": info.get("ip","—"),
                        "Nome": known.get("name","—"),
                        "Vendor": info.get("vendor","—"),
                        "Risco": info.get("risk_level","—"),
                        "Última vez": ts_fmt(info.get("last_seen",0), "%d/%m %H:%M"),
                    })
                st.dataframe(pd.DataFrame(off_rows), width="stretch", hide_index=True)

    with col_right:
        # ── Feed de eventos ─────────────────────────────────────────────────
        section_label("FEED DE ALERTAS")

        # Mini contadores por nível
        cnt_html = ""
        for lvl in ["CRÍTICO","ALTO","MÉDIO"]:
            cnt = sum(1 for e in events if e.get("level") == lvl)
            if cnt == 0: continue
            col = LEVEL_COLORS.get(lvl, CYAN)
            icon = THREAT_LEVELS[lvl]["icon"]
            cnt_html += f"""
            <span style="display:inline-flex; align-items:center; gap:4px;
                         padding:3px 8px; background:rgba(0,0,0,0.3);
                         border:1px solid {col}33; border-radius:3px;
                         font-family:var(--font-mono); font-size:0.72rem;
                         color:{col}; margin:2px;">
                {icon} {cnt}
            </span>"""
        if cnt_html:
            st.markdown(f'<div style="margin-bottom:10px">{cnt_html}</div>',
                        unsafe_allow_html=True)

        for ev in list(reversed(events))[:12]:
            render_event_card(ev)

        if not events:
            st.markdown("""
            <div style="text-align:center; padding:30px 10px; color:var(--text-dim);
                        font-family:var(--font-mono); font-size:0.75rem;">
                Nenhum evento ainda
            </div>
            """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 — FAMÍLIA (Mapa de Propriedade)
# ═══════════════════════════════════════════════════════════════════════════════

with tab_family:

    # ── Calcula grupos ──────────────────────────────────────────────────────
    owner_groups: dict[str, list[dict]] = {k: [] for k in OWNERS}
    all_seen_keys = set(db["seen"].keys())

    for mk in all_seen_keys:
        info  = db["seen"][mk]
        known = db["known"].get(mk, {})
        owner = known.get("owner") or suggest_owner(
            info.get("vendor",""), info.get("hostname",""), db, mk
        )
        if owner not in owner_groups:
            owner = "desconhecido"
        owner_groups[owner].append({
            "mac_key": mk,
            "ip":      info.get("ip","—"),
            "name":    known.get("name",""),
            "vendor":  info.get("vendor",""),
            "hostname":info.get("hostname",""),
            "online":  mk in current_macs,
            "risk":    info.get("risk_level","INFO"),
            "last_seen": info.get("last_seen",0),
        })

    # Intrusos = sem dono + online + não são roteador/infra
    intruders = [d for d in owner_groups.get("intruso",[]) if d["online"]]
    unknown_online = [d for d in owner_groups.get("desconhecido",[]) if d["online"]]

    # ── Banner de alerta de intrusos ────────────────────────────────────────
    if intruders:
        st.markdown(f"""
        <div class="nw-intruder-banner">
            <div style="font-family:var(--font-display); font-size:1.2rem; font-weight:700;
                        color:#FF1744; letter-spacing:0.08em;">
                🚨 INTRUSO(S) DETECTADO(S) NA REDE — {len(intruders)} DISPOSITIVO(S)
            </div>
            <div style="font-family:var(--font-mono); font-size:0.82rem;
                        color:var(--text-secondary); margin-top:6px;">
                {'  ·  '.join(d['ip'] + (' ('+d['name']+')' if d['name'] else '') for d in intruders)}
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Métricas por proprietário ───────────────────────────────────────────
    section_label("RESUMO POR PROPRIETÁRIO")
    owner_cols = st.columns(len(OWNERS))
    for col, (ok, ov) in zip(owner_cols, OWNERS.items()):
        total   = len(owner_groups.get(ok, []))
        online  = sum(1 for d in owner_groups.get(ok,[]) if d["online"])
        col.markdown(f"""
        <div style="background:var(--bg-card); border:1px solid {ov['color']}33;
                    border-top:3px solid {ov['color']}; border-radius:6px;
                    padding:12px 10px; text-align:center;">
            <div style="font-size:1.5rem">{ov['icon']}</div>
            <div style="font-family:var(--font-display); font-size:0.72rem;
                        color:{ov['color']}; letter-spacing:0.08em;
                        text-transform:uppercase; margin-top:4px;">
                {ov['label']}
            </div>
            <div style="font-family:var(--font-display); font-size:1.6rem;
                        font-weight:700; color:var(--text-primary); line-height:1.1;">
                {online}<span style="font-size:0.85rem; color:var(--text-dim)">/{total}</span>
            </div>
            <div style="font-family:var(--font-mono); font-size:0.65rem;
                        color:var(--text-dim);">online/total</div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    # ── Mapa visual de dispositivos por dono ────────────────────────────────
    section_label("MAPA DE DISPOSITIVOS POR PROPRIETÁRIO")

    for owner_key, owner_data in OWNERS.items():
        devices_in_group = owner_groups.get(owner_key, [])
        if not devices_in_group:
            continue

        color = owner_data["color"]
        icon  = owner_data["icon"]
        label = owner_data["label"]
        n_online = sum(1 for d in devices_in_group if d["online"])

        # Card por grupo
        chips_html = ""
        for d in sorted(devices_in_group, key=lambda x: (0 if x["online"] else 1, x["ip"])):
            status_dot = f'<span style="color:{color}">●</span>' if d["online"] else '<span style="color:var(--text-dim)">○</span>'
            display_name = d["name"] or vendor_hint(d["vendor"]) or d["ip"]
            hint = vendor_hint(d["vendor"])
            risk_icon = THREAT_LEVELS.get(d["risk"], {}).get("icon", "")
            chips_html += f"""
            <span class="nw-device-chip"
                  style="background:{color}0F; border:1px solid {color}33;
                         color:var(--text-primary);"
                  title="{d['ip']} · {d['vendor']} · {d['hostname']} · Última vez: {ts_ago(d['last_seen'])}">
                {status_dot} {risk_icon} {display_name[:22]}
                <span style="font-size:0.65rem; color:var(--text-dim)">
                    {d['ip']}
                </span>
            </span>"""

        st.markdown(f"""
        <div class="nw-owner-card" style="border-color:{color}33; border-left:3px solid {color};">
            <div class="nw-owner-card-header" style="color:{color};">
                {icon} {label}
                <span style="font-size:0.75rem; font-weight:400; color:var(--text-secondary);
                             margin-left:10px; text-transform:none; letter-spacing:0;">
                    {n_online} online · {len(devices_in_group)} total
                </span>
            </div>
            <div>{chips_html if chips_html else '<span style="color:var(--text-dim);font-size:0.8rem">Nenhum dispositivo</span>'}</div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    # ── Ferramenta de classificação rápida ──────────────────────────────────
    section_label("CLASSIFICAÇÃO RÁPIDA")
    st.markdown("""
    <div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--text-secondary);
                margin-bottom:12px;">
    Dispositivos ainda <b style="color:var(--amber)">desconhecidos ou sem dono</b> — identifique-os:
    </div>
    """, unsafe_allow_html=True)

    # Pega todos sem owner definido que estejam online
    unclassified = [
        d for d in owner_groups.get("desconhecido", [])
        if not db["known"].get(d["mac_key"], {}).get("owner")
    ]

    if not unclassified:
        st.success("✅ Todos os dispositivos estão classificados!")
    else:
        for d in sorted(unclassified, key=lambda x: (0 if x["online"] else 1, x["ip"])):
            mk = d["mac_key"]
            hint_txt = vendor_hint(d["vendor"])
            with st.expander(
                f"{'🟢' if d['online'] else '⚫'} {d['ip']}  —  {d['name'] or hint_txt}",
                expanded=d["online"]
            ):
                fcol1, fcol2, fcol3 = st.columns([2, 2, 3])

                with fcol1:
                    st.markdown(f"""
                    <div style="font-family:var(--font-mono); font-size:0.8rem;
                                line-height:2; color:var(--text-secondary);">
                        <b style="color:var(--text-primary);">IP:</b> {d['ip']}<br>
                        <b style="color:var(--text-primary);">Vendor:</b> {d['vendor'] or '—'}<br>
                        <b style="color:var(--text-primary);">Tipo:</b> {hint_txt}<br>
                        <b style="color:var(--text-primary);">Hostname:</b> {d['hostname'] or '—'}<br>
                        <b style="color:var(--text-primary);">Última vez:</b> {ts_ago(d['last_seen'])}
                    </div>
                    """, unsafe_allow_html=True)

                with fcol2:
                    new_owner = st.selectbox(
                        "Proprietário",
                        options=list(OWNERS.keys()),
                        format_func=lambda k: f"{OWNERS[k]['icon']} {OWNERS[k]['label']}",
                        key=f"fam_owner_{mk}",
                        index=list(OWNERS.keys()).index(
                            db["known"].get(mk, {}).get("owner", "desconhecido")
                        ) if db["known"].get(mk, {}).get("owner", "desconhecido") in OWNERS else 4
                    )
                    new_name = st.text_input(
                        "Nome do dispositivo",
                        value=db["known"].get(mk, {}).get("name", ""),
                        placeholder=f"Ex.: Celular da {OWNERS.get(new_owner,{}).get('label','')}",
                        key=f"fam_name_{mk}"
                    )

                with fcol3:
                    new_cat = st.selectbox(
                        "Categoria",
                        options=DEVICE_CATEGORIES,
                        index=DEVICE_CATEGORIES.index(
                            db["known"].get(mk, {}).get("category", "Desconhecido")
                        ) if db["known"].get(mk, {}).get("category") in DEVICE_CATEGORIES else 0,
                        key=f"fam_cat_{mk}"
                    )
                    new_notes = st.text_area(
                        "Notas",
                        value=db["known"].get(mk, {}).get("notes", ""),
                        height=68,
                        placeholder="Ex.: iPhone preto encontrado na rede em 17/02",
                        key=f"fam_notes_{mk}"
                    )

                    b1, b2 = st.columns(2)
                    with b1:
                        if st.button("💾 Salvar", key=f"fam_save_{mk}", width="stretch"):
                            existing = db["known"].get(mk, {})
                            db["known"][mk] = {
                                **existing,
                                "name":     new_name.strip(),
                                "owner":    new_owner,
                                "category": new_cat,
                                "notes":    new_notes.strip(),
                                "operator": operator,
                                "ts_added": existing.get("ts_added", int(time.time())),
                            }
                            # Remove de suspeitos/bloqueados se classificado como conhecido
                            if new_owner not in ("intruso", "desconhecido"):
                                if mk in db.get("suspects",[]): db["suspects"].remove(mk)
                            if new_owner == "intruso":
                                if mk not in db.get("suspects",[]): db.setdefault("suspects",[]).append(mk)
                            events_upd = log_event(
                                events, "INFO",
                                f"Dispositivo classificado: {d['ip']} → {OWNERS[new_owner]['label']}"
                                + (f" ({new_name})" if new_name else ""),
                                mac=mk, ip=d["ip"]
                            )
                            save_db(db)
                            save_events(events_upd)
                            st.success("Salvo!")
                            st.rerun()
                    with b2:
                        if st.button("🚨 Intruso", key=f"fam_intr_{mk}", width="stretch"):
                            db["known"][mk] = {
                                **db["known"].get(mk, {}),
                                "owner":    "intruso",
                                "name":     new_name.strip() or f"INTRUSO {d['ip']}",
                                "category": "Suspeito",
                                "operator": operator,
                                "ts_added": int(time.time()),
                            }
                            if mk not in db.get("suspects",[]): db.setdefault("suspects",[]).append(mk)
                            events_upd = log_event(
                                events, "ALTO",
                                f"Dispositivo marcado como INTRUSO: {d['ip']} ({d['vendor']})",
                                mac=mk, ip=d["ip"]
                            )
                            save_db(db)
                            save_events(events_upd)
                            st.error("Marcado como intruso!")
                            st.rerun()

    # ── Gráfico de pizza por proprietário ───────────────────────────────────
    if any(owner_groups.values()):
        st.divider()
        section_label("DISTRIBUIÇÃO DE PROPRIEDADE")

        owner_counts = {k: len(v) for k, v in owner_groups.items() if v}
        if owner_counts:
            import matplotlib.pyplot as plt
            import matplotlib.patches as mpatches

            labels_o  = [OWNERS[k]["label"] for k in owner_counts]
            values_o  = list(owner_counts.values())
            colors_o  = [OWNERS[k]["color"] for k in owner_counts]

            fig_own, ax_own = plt.subplots(figsize=(5, 3.2))
            fig_own.patch.set_facecolor(BG_CARD)
            ax_own.set_facecolor(BG_CARD)

            wedges, _, autotexts = ax_own.pie(
                values_o, labels=None, colors=colors_o,
                autopct=lambda p: f"{p:.0f}%" if p > 5 else "",
                startangle=90, pctdistance=0.72,
                wedgeprops={"linewidth":1.5, "edgecolor":BG_PRIMARY, "width":0.5},
            )
            for at in autotexts:
                at.set_color(BG_PRIMARY)
                at.set_fontsize(8)
                at.set_fontweight("bold")

            patches = [
                mpatches.Patch(color=OWNERS[k]["color"],
                               label=f"{OWNERS[k]['icon']} {OWNERS[k]['label']}  {v}")
                for k, v in owner_counts.items()
            ]
            ax_own.legend(handles=patches, loc="lower center",
                          bbox_to_anchor=(0.5, -0.22), ncol=3,
                          fontsize=7.5, frameon=False, labelcolor=TEXT_PRIMARY)

            total_own = sum(values_o)
            ax_own.text(0, 0, str(total_own), ha="center", va="center",
                        color=CYAN, fontsize=18, fontweight="bold")
            ax_own.text(0, -0.22, "dispositivos", ha="center", va="center",
                        color=TEXT_DIM, fontsize=7)
            ax_own.set_title("Propriedade dos Dispositivos", color=TEXT_PRIMARY,
                             fontsize=9, pad=8, fontweight="bold", loc="left")

            plt.tight_layout(pad=0.5)
            _, chart_col, _ = st.columns([1, 2, 1])
            with chart_col:
                st.pyplot(fig_own)
            plt.close(fig_own)

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 — DISPOSITIVOS (gestão completa)
# ═══════════════════════════════════════════════════════════════════════════════

with tab_devices:
    col_dev_left, col_dev_right = st.columns([1, 1])

    with col_dev_left:
        section_label("SELECIONAR DISPOSITIVO")

        all_keys = sorted(db["seen"].keys(),
            key=lambda k: (0 if k in current_macs else 1, db["seen"][k].get("ip",""))
        )
        labels = []
        for k in all_keys:
            info  = db["seen"][k]
            known = db["known"].get(k, {})
            name  = known.get("name","")
            ip    = info.get("ip","?")
            online = "●" if k in current_macs else "○"
            labels.append(f"{online} {ip}  {name or '(sem nome)'}")

        if not all_keys:
            st.info("Execute um scan para ver dispositivos.")
        else:
            sel_idx = st.selectbox(
                "Dispositivo",
                range(len(all_keys)),
                format_func=lambda i: labels[i],
                label_visibility="collapsed",
                key="selected_device_idx"
            )
            selected_key  = all_keys[sel_idx]
            selected_info = db["seen"].get(selected_key, {})
            selected_known = db["known"].get(selected_key, {})

            # ── Painel de detalhe — sem HTML complexo ──────────────────────
            is_online  = selected_key in current_macs
            is_known   = selected_key in db["known"]
            is_suspect = selected_key in db.get("suspects", [])
            is_blocked = selected_key in db.get("blocked", [])

            risk_score = selected_info.get("risk_score", 0)
            risk_level = selected_info.get("risk_level", "INFO")
            rcolor     = risk_color(risk_level)

            # Card principal com containers nativos
            with st.container():
                # IP + status badges
                ip_display = selected_info.get("ip", "—")
                mac_display = selected_key if not selected_key.startswith("NO_MAC::") else "(sem MAC)"

                status_parts = []
                if is_online:  status_parts.append("🟢 ONLINE")
                else:          status_parts.append("⚫ OFFLINE")
                if is_known:   status_parts.append("✅ CONHECIDO")
                if is_suspect: status_parts.append("⚠️ SUSPEITO")
                if is_blocked: status_parts.append("🚫 BLOQUEADO")

                # IP grande + status
                st.markdown(
                    f"<span style='font-family:var(--font-mono);font-size:1.2rem;"
                    f"color:var(--cyan);font-weight:700;'>{ip_display}</span>"
                    f"&nbsp;&nbsp;<span style='font-family:var(--font-mono);"
                    f"font-size:0.72rem;color:var(--text-secondary);'>{mac_display}</span>",
                    unsafe_allow_html=True
                )
                st.write("  ".join(status_parts))

                # Detalhes em colunas nativas
                d1, d2 = st.columns(2)
                d1.metric("Vendor",   selected_info.get("vendor", "—") or "—")
                d2.metric("Hostname", selected_info.get("hostname", "—") or "—")
                d3, d4 = st.columns(2)
                d3.metric("Primeira vez", ts_fmt(selected_info.get("first_seen", 0), "%d/%m %H:%M"))
                d4.metric("Última vez",   ts_fmt(selected_info.get("last_seen",  0), "%d/%m %H:%M"))

                # Barra de risco
                st.markdown(
                    f"<div style='font-family:var(--font-display);font-size:0.8rem;"
                    f"color:{rcolor};margin-top:4px;'>RISCO: {risk_level} &nbsp;"
                    f"<span style='color:var(--text-secondary)'>{risk_score}/100</span></div>",
                    unsafe_allow_html=True
                )
                render_risk_bar(risk_score, risk_level)

            # Portas abertas
            ports_data = selected_info.get("ports", [])
            if ports_data:
                st.markdown("**Portas abertas:**")
                p_rows = []
                for p in ports_data:
                    portid = p.get("port",0)
                    svc    = p.get("service","")
                    if portid in RISK_PORTS:
                        _, risk_p = RISK_PORTS[portid]
                        icon_p = THREAT_LEVELS.get(risk_p, {}).get("icon","")
                    else:
                        icon_p = "⚪"
                        risk_p = "INFO"
                    p_rows.append({"Porta": portid, "Serviço": svc, "Risco": f"{icon_p} {risk_p}"})
                st.dataframe(pd.DataFrame(p_rows), width="stretch", hide_index=True, height=180)

    with col_dev_right:
        if all_keys:
            section_label("GERENCIAR DISPOSITIVO")

            name_val  = st.text_input("Nome amigável", value=selected_known.get("name",""), placeholder="Ex.: Câmera Sala 1")

            # Proprietário — dropdown com ícones
            cur_owner = selected_known.get("owner", "desconhecido")
            owner_options = list(OWNERS.keys())
            owner_val = st.selectbox(
                "Proprietário",
                options=owner_options,
                format_func=lambda k: f"{OWNERS[k]['icon']} {OWNERS[k]['label']}",
                index=owner_options.index(cur_owner) if cur_owner in owner_options else 4,
            )

            cat_val   = st.selectbox("Categoria",
                DEVICE_CATEGORIES,
                index=DEVICE_CATEGORIES.index(selected_known.get("category","Desconhecido"))
                      if selected_known.get("category") in DEVICE_CATEGORIES else 0
            )
            notes_val = st.text_area("Notas / Observações",
                value=selected_known.get("notes",""),
                height=80, placeholder="Ex.: Dispositivo de terceiros autorizado em 15/01"
            )

            c1, c2, c3 = st.columns(3)
            with c1:
                if st.button("✅ Marcar Conhecido", width="stretch"):
                    db["known"][selected_key] = {
                        **db["known"].get(selected_key, {}),
                        "name":      name_val.strip(),
                        "owner":     owner_val,
                        "category":  cat_val,
                        "notes":     notes_val.strip(),
                        "operator":  operator,
                        "ts_added":  db["known"].get(selected_key, {}).get("ts_added", int(time.time())),
                    }
                    if selected_key in db.get("suspects", []): db["suspects"].remove(selected_key)
                    if selected_key in db.get("blocked", []):  db["blocked"].remove(selected_key)
                    o_label = OWNERS.get(owner_val, {}).get("label", owner_val)
                    events = log_event(events, "INFO",
                        f"Dispositivo salvo: {selected_info.get('ip','')} → {o_label} ({name_val})",
                        mac=selected_key, ip=selected_info.get("ip",""))
                    save_db(db); save_events(events)
                    st.success("Salvo!")
                    st.rerun()

            with c2:
                if st.button("⚠️ Marcar Suspeito", width="stretch"):
                    if selected_key not in db.get("suspects", []):
                        db.setdefault("suspects", []).append(selected_key)
                    events = log_event(events, "ALTO",
                        f"Dispositivo marcado como SUSPEITO: {selected_info.get('ip','')}",
                        mac=selected_key, ip=selected_info.get("ip",""))
                    save_db(db); save_events(events)
                    st.warning("Marcado como suspeito.")
                    st.rerun()

            with c3:
                if st.button("🚫 Bloquear", width="stretch"):
                    if selected_key not in db.get("blocked", []):
                        db.setdefault("blocked", []).append(selected_key)
                    events = log_event(events, "CRÍTICO",
                        f"Dispositivo BLOQUEADO: {selected_info.get('ip','')}",
                        mac=selected_key, ip=selected_info.get("ip",""))
                    save_db(db); save_events(events)
                    st.error("Dispositivo bloqueado.")
                    st.rerun()

            st.divider()
            c4, c5 = st.columns(2)
            with c4:
                if st.button("↺ Remover classificação", width="stretch"):
                    db.get("known",    {}).pop(selected_key, None)
                    if selected_key in db.get("suspects", []): db["suspects"].remove(selected_key)
                    if selected_key in db.get("blocked", []):  db["blocked"].remove(selected_key)
                    save_db(db)
                    st.info("Classificação removida.")
                    st.rerun()
            with c5:
                if st.button("🗑 Remover do histórico", width="stretch"):
                    db.get("seen",    {}).pop(selected_key, None)
                    db.get("known",   {}).pop(selected_key, None)
                    if selected_key in db.get("suspects", []): db["suspects"].remove(selected_key)
                    if selected_key in db.get("blocked", []):  db["blocked"].remove(selected_key)
                    if selected_key in current_macs: current_macs.discard(selected_key)
                    save_db(db)
                    st.info("Removido.")
                    st.rerun()

            # ── Envio de Mensagens (FCM) ───────────────────────────────────
            section_label("MENSAGEM PARA DISPOSITIVO (FCM)")

            # Initialize FCM once when the tab is loaded, but do it silently.
            # The sending function will handle user-facing errors if it's not configured.
            if not messaging.is_fcm_initialized():
                messaging.init_fcm()

            fcm_token = st.text_input(
                "FCM Token do Dispositivo",
                value=selected_known.get("fcm_token", ""),
                placeholder="Cole o token de registro do Firebase aqui",
                help="O token FCM é obtido pelo app complementar no dispositivo Android."
            )

            # Save the token automatically if it's changed
            if fcm_token != selected_known.get("fcm_token", ""):
                db["known"][selected_key] = {
                    **selected_known,
                    "fcm_token": fcm_token.strip(),
                }
                save_db(db)
                st.toast("✅ Token FCM salvo!")
                # Re-fetch known info to ensure UI is consistent
                selected_known = db["known"].get(selected_key, {})


            msg_title = st.text_input("Título da Mensagem", value="Alerta NetWatch")
            msg_body = st.text_area(
                "Corpo da Mensagem",
                value=f"Atenção: uma atividade no seu dispositivo {selected_info.get('ip', '')} requer sua atenção.",
                height=100
            )

            if st.button("🚀 Enviar Mensagem FCM", width="stretch"):
                if not fcm_token:
                    st.warning("Nenhum token FCM fornecido. Impossível enviar mensagem.")
                else:
                    with st.spinner("Enviando mensagem..."):
                        messaging.send_fcm_message(
                            token=fcm_token,
                            title=msg_title,
                            body=msg_body,
                            data={"device_mac": selected_key, "ip": selected_info.get("ip", "")}
                        )

            # ── Scan de porta individual ───────────────────────────────────
            section_label("SCAN DE PORTA NESTE DISPOSITIVO")
            quick_args = st.text_input("Args nmap", value="-sV --top-ports 100 -T4",
                                       label_visibility="collapsed")
            if st.button("🔍 Executar Scan de Portas", width="stretch"):
                target_ip = selected_info.get("ip")
                if target_ip:
                    with st.spinner(f"Escaneando {target_ip}..."):
                        try:
                            xml_r = run_port_scan(target_ip, quick_args, use_sudo)
                            devs_r = parse_nmap_xml(xml_r)
                            if devs_r:
                                ports_r = devs_r[0].get("ports", [])
                                db["seen"][selected_key]["ports"] = ports_r
                                risk_s, risk_l = calculate_risk_score(devs_r[0], db)
                                db["seen"][selected_key]["risk_score"] = risk_s
                                db["seen"][selected_key]["risk_level"] = risk_l
                                save_db(db)
                                st.success(f"{len(ports_r)} porta(s) abertas encontradas.")
                                st.rerun()
                            else:
                                st.info("Host não respondeu ou sem portas abertas.")
                        except Exception as e:
                            st.error(f"Erro: {e}")
                else:
                    st.warning("IP não disponível.")

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 — EVENTOS
# ═══════════════════════════════════════════════════════════════════════════════

with tab_alerts:
    col_ev_l, col_ev_r = st.columns([2, 1])

    with col_ev_l:
        section_label("LOG DE EVENTOS")

        filter_level = st.multiselect(
            "Filtrar nível",
            options=["CRÍTICO","ALTO","MÉDIO","BAIXO","INFO"],
            default=["CRÍTICO","ALTO","MÉDIO","BAIXO","INFO"],
        )

        filtered_events = [e for e in reversed(events) if e.get("level","INFO") in filter_level]
        st.caption(f"{len(filtered_events)} eventos (de {len(events)} total)")

        for ev in filtered_events[:100]:
            render_event_card(ev)

        if not filtered_events:
            st.info("Nenhum evento no filtro selecionado.")

    with col_ev_r:
        # Timeline mini no topo
        if events:
            fig_ev = chart_events_timeline(events, last_n=30)
            st.pyplot(fig_ev, width="stretch")
            plt.close(fig_ev)
            st.divider()

        section_label("CONTAGEM POR NÍVEL")
        for lvl in ["CRÍTICO","ALTO","MÉDIO","BAIXO","INFO"]:
            cnt = sum(1 for e in events if e.get("level") == lvl)
            if cnt == 0: continue
            color = risk_color(lvl)
            icon  = THREAT_LEVELS[lvl]["icon"]
            st.markdown(f"""
            <div style="display:flex; justify-content:space-between; padding:6px 10px;
                        background:var(--bg-card); border-radius:4px; margin-bottom:4px;
                        border-left:3px solid {color};">
                <span style="font-family:var(--font-display); color:{color}">{icon} {lvl}</span>
                <span style="font-family:var(--font-mono); color:var(--text-secondary)">{cnt}</span>
            </div>
            """, unsafe_allow_html=True)

        st.divider()
        section_label("AÇÕES")

        if st.button("📥 Exportar Log (CSV)", width="stretch"):
            if events:
                csv_buf = io.StringIO()
                w = csv.DictWriter(csv_buf, fieldnames=["ts","level","message","mac","ip"])
                w.writeheader()
                for ev in events:
                    row = {**ev, "ts": ts_fmt(ev.get("ts",0))}
                    w.writerow(row)
                st.download_button(
                    "⬇ Baixar CSV",
                    csv_buf.getvalue().encode(),
                    "netwatch_events.csv",
                    "text/csv",
                    width="stretch"
                )
            else:
                st.info("Nenhum evento para exportar.")

        if st.button("🗑 Limpar Log", width="stretch"):
            events = []
            save_events(events)
            st.success("Log limpo.")
            st.rerun()

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4 — PORTAS & SERVIÇOS
# ═══════════════════════════════════════════════════════════════════════════════

with tab_ports:
    section_label("INVENTÁRIO DE PORTAS ABERTAS")

    all_ports_rows = []
    for mk, info in db["seen"].items():
        known  = db["known"].get(mk, {})
        name   = known.get("name", "")
        ip     = info.get("ip","—")
        vendor = info.get("vendor","—")
        is_online = mk in current_macs

        for p in info.get("ports", []):
            pid  = p.get("port",0)
            svc  = p.get("service","")
            if pid in RISK_PORTS:
                svc_known, risk_p = RISK_PORTS[pid]
                svc = svc_known if not svc else svc
            else:
                risk_p = "INFO"
            icon_p = THREAT_LEVELS.get(risk_p, {}).get("icon","⚪")
            all_ports_rows.append({
                "Nível Risco": f"{icon_p} {risk_p}",
                "IP": ip,
                "Porta": pid,
                "Serviço": svc,
                "Dispositivo": name or vendor,
                "Status": "🟢 Online" if is_online else "⚫ Offline",
            })

    if all_ports_rows:
        df_ports = pd.DataFrame(all_ports_rows).sort_values(
            by="Nível Risco", key=lambda x: x.map({
                f"{THREAT_LEVELS[l]['icon']} {l}": 4-i for i,l in enumerate(["CRÍTICO","ALTO","MÉDIO","BAIXO","INFO"])
            }).fillna(0), ascending=False
        )
        st.dataframe(df_ports, width="stretch", hide_index=True, height=500)

        # Portas mais comuns — gráfico real
        port_freq = {}
        for r in all_ports_rows:
            svc_label = r["Serviço"] or str(r["Porta"])
            k = f"{r['Porta']}  {svc_label}"
            port_freq[k] = port_freq.get(k, 0) + 1

        fig_ports = chart_ports_hbar(port_freq)
        st.pyplot(fig_ports, width="stretch")
        plt.close(fig_ports)
    else:
        st.info("Execute um scan com **Scan de Portas** habilitado (sidebar) ou use o scan individual na aba Dispositivos.")
        st.markdown("""
        **Como habilitar:**
        1. Na barra lateral, ative **Scan de Portas**
        2. Ajuste os argumentos Nmap se necessário (padrão: `-sV --top-ports 50 -T4`)
        3. Clique em **▶ SCAN**
        """)

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 5 — RELATÓRIOS
# ═══════════════════════════════════════════════════════════════════════════════

with tab_report:
    col_rep_l, col_rep_r = st.columns([1, 1])

    with col_rep_l:
        section_label("RELATÓRIO PDF")

        if not REPORTLAB_OK:
            st.warning("ReportLab não instalado. Execute: `pip install reportlab`")
        else:
            st.markdown("""
            Gera relatório oficial em PDF incluindo:
            - Dados da organização e operador
            - Tabela completa de dispositivos detectados
            - Eventos recentes
            - Carimbo de data/hora e identificação
            """)
            if st.button("📄 Gerar Relatório PDF", width="stretch"):
                with st.spinner("Gerando PDF..."):
                    try:
                        pdf_bytes = generate_pdf_report(db, events, conf, devices)
                        fname = f"netwatch_relatorio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                        st.download_button(
                            f"⬇ Baixar {fname}",
                            pdf_bytes, fname, "application/pdf",
                            width="stretch"
                        )
                        events = log_event(events, "INFO",
                            f"Relatório PDF gerado por {operator}")
                        save_events(events)
                    except Exception as e:
                        st.error(f"Erro ao gerar PDF: {e}")

    with col_rep_r:
        section_label("EXPORTAR DADOS")

        # CSV completo
        all_rows = []
        for mk, info in db["seen"].items():
            known = db["known"].get(mk, {})
            all_rows.append({
                "IP":           info.get("ip",""),
                "MAC":          mk if not mk.startswith("NO_MAC::") else "",
                "Vendor":       info.get("vendor",""),
                "Hostname":     info.get("hostname",""),
                "Nome":         known.get("name",""),
                "Categoria":    known.get("category",""),
                "Status":       "Conhecido" if mk in db["known"] else ("Suspeito" if mk in db.get("suspects",[]) else "Desconhecido"),
                "Risco":        info.get("risk_level","—"),
                "Risk Score":   info.get("risk_score",""),
                "First Seen":   ts_fmt(info.get("first_seen",0)),
                "Last Seen":    ts_fmt(info.get("last_seen",0)),
                "Notas":        known.get("notes",""),
                "Online Agora": "Sim" if mk in current_macs else "Não",
            })

        if all_rows:
            df_export = pd.DataFrame(all_rows)
            csv_str = df_export.to_csv(index=False)
            fname_csv = f"netwatch_dispositivos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            st.download_button(
                "⬇ Exportar CSV (Dispositivos)",
                csv_str.encode(), fname_csv, "text/csv",
                width="stretch"
            )

            json_str = json.dumps({"exported_at": ts_fmt(int(time.time())),
                                   "devices": all_rows}, indent=2, ensure_ascii=False)
            fname_json = f"netwatch_dispositivos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            st.download_button(
                "⬇ Exportar JSON (Dispositivos)",
                json_str.encode(), fname_json, "application/json",
                width="stretch"
            )
        else:
            st.info("Execute um scan para habilitar exportação.")

        st.divider()
        section_label("BACKUP DO BANCO DE DADOS")
        if st.button("💾 Backup DB Completo (JSON)", width="stretch"):
            backup = json.dumps(db, indent=2, ensure_ascii=False)
            st.download_button(
                "⬇ Baixar Backup",
                backup.encode(),
                f"netwatch_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "application/json",
                width="stretch"
            )

    # ── Hardening Checklist ─────────────────────────────────────────────────
    st.subheader("🔒 Checklist de Hardening de Rede")
    section_label("REVISE PERIODICAMENTE")

    checklist_items = [
        ("CRÍTICO", "Senha padrão do roteador alterada"),
        ("CRÍTICO", "Wi-Fi protegido com WPA3 ou WPA2 (nunca WEP/aberto)"),
        ("CRÍTICO", "WPS (Wi-Fi Protected Setup) desativado"),
        ("ALTO",    "Gerenciamento remoto do roteador desativado"),
        ("ALTO",    "Firmware de todos os dispositivos atualizado"),
        ("ALTO",    "Serviços desnecessários (Telnet, FTP, RDP) bloqueados"),
        ("MÉDIO",   "VLAN separada para dispositivos IoT"),
        ("MÉDIO",   "Log de acesso habilitado no roteador"),
        ("MÉDIO",   "Firewall habilitado em todos os endpoints"),
        ("BAIXO",   "SSID não revela informações da organização"),
        ("BAIXO",   "Revisão mensal de dispositivos desconhecidos"),
        ("BAIXO",   "Certificados SSL/TLS atualizados em servidores internos"),
        ("INFO",    "Inventário físico de ativos de rede atualizado"),
        ("INFO",    "Política de uso aceitável documentada"),
    ]

    checklist_state = st.session_state.get("checklist", {})
    for i, (risk, item) in enumerate(checklist_items):
        color  = risk_color(risk)
        icon   = THREAT_LEVELS.get(risk, {}).get("icon","")
        key_c  = f"chk_{i}"
        is_done = checklist_state.get(key_c, False)

        checked = st.checkbox(f"{icon} [{risk}] {item}", value=is_done, key=key_c)
        checklist_state[key_c] = checked

    done_count = sum(1 for v in checklist_state.values() if v)
    total_count = len(checklist_items)
    pct = int(done_count / max(total_count, 1) * 100)
    st.metric("Conformidade", f"{pct}%", delta=f"{done_count}/{total_count} itens")

    st.session_state["checklist"] = checklist_state

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 6 — CONFIGURAÇÕES
# ═══════════════════════════════════════════════════════════════════════════════

with tab_config:
    col_cfg_l, col_cfg_r = st.columns(2)

    with col_cfg_l:
        section_label("IDENTIFICAÇÃO DA ORGANIZAÇÃO")
        org_name = st.text_input("Nome da Organização", value=conf.get("org_name",""))
        org_unit = st.text_input("Unidade/Departamento",  value=conf.get("org_unit",""))
        op_name  = st.text_input("Operador Padrão",       value=conf.get("operator",""))

        section_label("ALERTAS")
        alert_new     = st.checkbox("Alertar novos dispositivos",  value=conf.get("alert_new", True))
        alert_suspect = st.checkbox("Alertar dispositivos suspeitos", value=conf.get("alert_suspect", True))

        if st.button("💾 Salvar Configurações", width="stretch"):
            conf.update({
                "org_name": org_name, "org_unit": org_unit,
                "operator": op_name, "alert_new": alert_new,
                "alert_suspect": alert_suspect,
            })
            save_config(conf)
            st.success("Configurações salvas.")

        # ── Configuração de sudo ─────────────────────────────────────────
        st.divider()
        section_label("PERMISSÃO SUDO PARA NMAP")

        sudo_is_ok = st.session_state.get("sudo_ok", False)
        if sudo_is_ok:
            st.success("✅ nmap já roda com sudo sem senha. MAC e Vendor funcionando.")
        else:
            st.error("❌ sudo não configurado — scans sem MAC/Vendor.")
            st.markdown("""
            <div style="background:var(--bg-elevated); border:1px solid var(--border-bright);
                        border-radius:6px; padding:14px; font-size:0.85rem; margin-top:8px;">
                <b style="color:var(--cyan);">Como empresas fazem:</b><br><br>
                O método profissional é <code>sudoers NOPASSWD</code> — autoriza
                <em>apenas o comando nmap</em> para <em>apenas este usuário</em>,
                sem expor a senha e sem dar root geral.
            </div>
            """, unsafe_allow_html=True)

            st.markdown("**Execute no terminal:**")
            linux_user = os.environ.get("USER", "walbarellos")
            nmap_path_r = subprocess.run(["which", "nmap"], capture_output=True, text=True)
            nmap_bin = nmap_path_r.stdout.strip() or "/usr/bin/nmap"

            st.code(
                f"echo '{linux_user} ALL=(ALL) NOPASSWD: {nmap_bin}' "
                f"| sudo tee /etc/sudoers.d/netwatch-nmap\n"
                f"sudo chmod 440 /etc/sudoers.d/netwatch-nmap",
                language="bash"
            )

            st.markdown("**Ou, se souber a senha, configure aqui:**")
            sudo_pass = st.text_input(
                "Senha sudo (usada uma vez para configurar)",
                type="password",
                placeholder="Digite sua senha sudo",
                key="cfg_sudo_pass"
            )
            if st.button("🔑 Configurar NOPASSWD automaticamente", width="stretch"):
                if sudo_pass:
                    linux_user = os.environ.get("USER", "walbarellos")
                    nmap_path_r = subprocess.run(["which", "nmap"], capture_output=True, text=True)
                    nmap_bin = nmap_path_r.stdout.strip() or "/usr/bin/nmap"
                    rule = f"{linux_user} ALL=(ALL) NOPASSWD: {nmap_bin}\n"
                    sudoers_file = "/etc/sudoers.d/netwatch-nmap"

                    try:
                        # Escreve a regra usando sudo -S (lê senha do stdin)
                        write_cmd = ["sudo", "-S", "tee", sudoers_file]
                        p1 = subprocess.run(
                            write_cmd,
                            input=f"{sudo_pass}\n{rule}",
                            capture_output=True, text=True, timeout=10
                        )
                        chmod_cmd = ["sudo", "-S", "chmod", "440", sudoers_file]
                        p2 = subprocess.run(
                            chmod_cmd,
                            input=f"{sudo_pass}\n",
                            capture_output=True, text=True, timeout=10
                        )
                        # Testa se funcionou
                        if _can_sudo_nmap_nopass():
                            st.session_state["sudo_ok"] = True
                            st.success("✅ Configurado! Reinicie o scan.")
                            st.rerun()
                        else:
                            st.warning(
                                "Arquivo criado, mas sudo ainda pede senha. "
                                "Verifique se o arquivo foi criado corretamente:\n"
                                f"`cat {sudoers_file}`"
                            )
                    except subprocess.TimeoutExpired:
                        st.error("Timeout — senha incorreta ou sudo bloqueado.")
                    except Exception as e:
                        st.error(f"Erro: {e}")
                else:
                    st.warning("Digite a senha sudo acima.")

    with col_cfg_r:
        section_label("INFORMAÇÕES DO SISTEMA")
        st.markdown(f"""
        <div style="background:var(--bg-card); border:1px solid var(--border);
                    border-radius:6px; padding:16px; font-family:var(--font-mono);
                    font-size:0.8rem; line-height:2;">
            <span style="color:var(--text-secondary)">Versão:</span>
            <span style="color:var(--cyan)"> NetWatch v{APP_VERSION}</span><br>
            <span style="color:var(--text-secondary)">Nmap:</span>
            <span style="color:var(--green)"> {get_system_status()}</span><br>
            <span style="color:var(--text-secondary)">ReportLab:</span>
            <span style="color:{'var(--green)' if REPORTLAB_OK else 'var(--amber)'}"> {'OK' if REPORTLAB_OK else 'Não instalado'}</span><br>
            <span style="color:var(--text-secondary)">DB Path:</span>
            <span style="color:var(--cyan)"> {DB_PATH.absolute()}</span><br>
            <span style="color:var(--text-secondary)">Log Path:</span>
            <span style="color:var(--cyan)"> {LOG_PATH.absolute()}</span><br>
            <span style="color:var(--text-secondary)">Conf Path:</span>
            <span style="color:var(--cyan)"> {CONF_PATH.absolute()}</span><br>
            <span style="color:var(--text-secondary)">Total dispositivos:</span>
            <span style="color:var(--text-primary)"> {len(db['seen'])}</span><br>
            <span style="color:var(--text-secondary)">Total eventos:</span>
            <span style="color:var(--text-primary)"> {len(events)}</span><br>
        </div>
        """, unsafe_allow_html=True)

        section_label("ZONA DE RISCO — RESET")
        with st.expander("⚠️ Operações Destrutivas"):
            st.warning("Estas ações são irreversíveis!")
            if st.button("🗑 Limpar TODOS os dispositivos do DB"):
                db["seen"] = {}; db["known"] = {}
                db["suspects"] = []; db["blocked"] = []
                save_db(db)
                if "last_scan" in st.session_state:
                    del st.session_state["last_scan"]
                st.success("DB resetado.")
                st.rerun()

# ═══════════════════════════════════════════════════════════════════════════════
#  AUTO-REFRESH
# ═══════════════════════════════════════════════════════════════════════════════

if auto_refresh:
    st.markdown(f"""
    <div style="position:fixed; bottom:16px; right:16px;
                background:var(--bg-card); border:1px solid var(--border);
                border-radius:4px; padding:6px 12px;
                font-family:var(--font-mono); font-size:0.72rem;
                color:var(--text-secondary);">
        <span class="nw-scan-pulse"></span>Auto-refresh: {refresh_sec}s
    </div>
    """, unsafe_allow_html=True)
    time.sleep(refresh_sec)
    st.rerun()
