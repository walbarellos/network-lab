"""UI component helpers."""

import streamlit as st
from datetime import datetime
from typing import Any

from ..core.constants import THREAT_LEVELS, OWNERS


def section_label(text: str):
    """Render a section header label."""
    st.markdown(
        f'<h2 style="margin-top:0;">{text}</h2>',
        unsafe_allow_html=True,
    )


def risk_color(level: str) -> str:
    """Get hex color for threat level."""
    return THREAT_LEVELS.get(level, THREAT_LEVELS["INFO"])["color"]


def event_css_class(level: str) -> str:
    """Get CSS class for event level."""
    return f"nw-event-{level.lower()}"


def render_event_card(ev: dict[str, Any]):
    """Render a single event card."""
    level = ev.get("level", "INFO")
    color = risk_color(level)
    ts = datetime.fromtimestamp(ev.get("timestamp", 0)).strftime("%d/%m %H:%M:%S")

    st.markdown(
        f"""
        <div style="background:var(--bg-card); border-left:3px solid {color};
                    border-radius:4px; padding:10px 14px; margin:6px 0;
                    font-family:var(--font-mono); font-size:0.82rem;">
            <span style="color:{color}; font-weight:700;">[{level}]</span>
            <span style="color:var(--text-secondary); margin-left:8px;">{ts}</span>
            <div style="margin-top:4px; color:var(--text-primary);">{ev.get('message', '')}</div>
            <div style="margin-top:2px; font-size:0.72rem; color:var(--text-dim);">
                IP: {ev.get('ip', '-')} | MAC: {ev.get('mac', '-')[:17]}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_risk_bar(score: int, level: str):
    """Render a risk score bar."""
    color = risk_color(level)
    pct = min(score, 100)

    st.markdown(
        f"""
        <div style="background:var(--bg-elevated); border-radius:4px; height:24px;
                    overflow:hidden; margin:4px 0; position:relative;">
            <div style="background:{color}; width:{pct}%; height:100%;
                        transition:width 0.3s ease;"></div>
            <span style="position:absolute; top:50%; left:8px; transform:translateY(-50%);
                        font-size:0.72rem; font-weight:700; color:{color};">{level} ({score})</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


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


def format_timestamp(ts: int, fmt: str = "%d/%m/%Y %H:%M:%S") -> str:
    """Format Unix timestamp to string."""
    return datetime.fromtimestamp(ts).strftime(fmt)


def ts_ago(ts: int) -> str:
    """Get human-readable time ago string."""
    diff = int(datetime.now().timestamp()) - ts
    if diff < 60:
        return f"{diff}s atrás"
    if diff < 3600:
        return f"{diff // 60}m atrás"
    if diff < 86400:
        return f"{diff // 3600}h atrás"
    return f"{diff // 86400}d atrás"
