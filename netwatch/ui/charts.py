"""Chart visualization components."""

import matplotlib
import matplotlib.pyplot as plt
from datetime import datetime
from collections import Counter

matplotlib.use("Agg")


def chart_risk_donut(risk_counts: dict) -> plt.Figure:
    """Create risk distribution donut chart."""
    fig, ax = plt.subplots(figsize=(5, 3))

    levels = ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "INFO"]
    colors_map = {
        "CRÍTICO": "#FF1744",
        "ALTO": "#FF6D00",
        "MÉDIO": "#FFD600",
        "BAIXO": "#00E676",
        "INFO": "#40C4FF",
    }

    values = [risk_counts.get(lvl, 0) for lvl in levels]
    colors = [colors_map[lvl] for lvl in levels]

    if sum(values) == 0:
        values = [1]
        colors = ["#1E3A5F"]

    wedges, _ = ax.pie(
        values,
        colors=colors,
        startangle=90,
        wedgeprops=dict(width=0.4, edgecolor="#070B14", linewidth=2),
    )

    ax.text(0, 0, f"{sum(values)}", ha="center", va="center", fontsize=16, fontweight="bold", color="#00D4FF")

    ax.legend(wedges, [f"{l} ({v})" for l, v in zip(levels, values) if v > 0],
              loc="center left", bbox_to_anchor=(1, 0.5), fontsize=8, frameon=False)

    fig.patch.set_facecolor("#070B14")
    ax.set_facecolor("#070B14")
    ax.tick_params(colors="#7A96B8")

    return fig


def chart_vendor_hbar(vendor_map: dict, max_items: int = 8) -> plt.Figure:
    """Create vendor distribution horizontal bar chart."""
    fig, ax = plt.subplots(figsize=(6, 3.2))

    items = sorted(vendor_map.items(), key=lambda x: -x[1])[:max_items]
    vendors = [v[0][:20] for v in items]
    counts = [v[1] for v in items]

    colors = ["#00D4FF"] * len(vendors)
    ax.barh(vendors, counts, color=colors, edgecolor="#007BA8", height=0.6)

    ax.invert_yaxis()
    ax.set_xlabel("Dispositivos", fontsize=9, color="#7A96B8")
    ax.tick_params(colors="#7A96B8", labelsize=8)
    for spine in ax.spines.values():
        spine.set_color("#1E3A5F")

    fig.patch.set_facecolor("#070B14")
    ax.set_facecolor("#070B14")

    return fig


def chart_ports_hbar(port_freq: dict, max_items: int = 12) -> plt.Figure:
    """Create port frequency horizontal bar chart."""
    fig, ax = plt.subplots(figsize=(6, 3.2))

    items = sorted(port_freq.items(), key=lambda x: -x[1])[:max_items]
    ports = [f"{p[0]} ({p[2]})" if len(p) > 2 else str(p[0]) for p in items]
    counts = [p[1] for p in items]

    colors = ["#FF6D00"] * len(ports)
    ax.barh(ports, counts, color=colors, edgecolor="#7A5800", height=0.6)

    ax.invert_yaxis()
    ax.set_xlabel("Ocorrências", fontsize=9, color="#7A96B8")
    ax.tick_params(colors="#7A96B8", labelsize=8)
    for spine in ax.spines.values():
        spine.set_color("#1E3A5F")

    fig.patch.set_facecolor("#070B14")
    ax.set_facecolor("#070B14")

    return fig


def chart_events_timeline(events: list, last_n: int = 40) -> plt.Figure:
    """Create events timeline chart."""
    fig, ax = plt.subplots(figsize=(6, 2.5))

    recent = sorted(events, key=lambda x: x.get("timestamp", 0), reverse=True)[:last_n][::-1]

    levels = {"CRÍTICO": 4, "ALTO": 3, "MÉDIO": 2, "BAIXO": 1, "INFO": 0}
    colors_map = {
        "CRÍTICO": "#FF1744",
        "ALTO": "#FF6D00",
        "MÉDIO": "#FFD600",
        "BAIXO": "#00E676",
        "INFO": "#40C4FF",
    }

    y_values = []
    colors = []
    labels = []

    for ev in recent:
        level = ev.get("level", "INFO")
        y_values.append(levels.get(level, 0))
        colors.append(colors_map.get(level, "#40C4FF"))
        ts = datetime.fromtimestamp(ev.get("timestamp", 0)).strftime("%d/%H:%M")
        labels.append(ts)

    ax.bar(range(len(y_values)), y_values, color=colors, width=0.7, edgecolor="none")

    ax.set_yticks([0, 1, 2, 3, 4])
    ax.set_yticklabels(["INFO", "BAIXO", "MÉDIO", "ALTO", "CRÍTICO"], fontsize=8, color="#7A96B8")
    ax.set_xticks(range(0, len(labels), max(1, len(labels) // 5)))
    ax.set_xticklabels([labels[i] for i in range(0, len(labels), max(1, len(labels) // 5))], fontsize=7, color="#7A96B8", rotation=45)

    for spine in ax.spines.values():
        spine.set_color("#1E3A5F")

    fig.patch.set_facecolor("#070B14")
    ax.set_facecolor("#070B14")

    return fig
