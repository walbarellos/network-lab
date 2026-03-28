"""
NetWatch - Central de Monitoramento de Rede
Sistema Profissional de Segurança de Redes v2.1

Arquitetura modularizada:
- netwatch.core: Constantes, configurações
- netwatch.domain: Entidades de domínio
- netwatch.infrastructure: Persistência
- netwatch.services: Lógica de negócio
- netwatch.ui: Componentes de interface
"""

import streamlit as st

from netwatch.core import (
    APP_VERSION,
    DEFAULT_RANGE,
    DEVICE_CATEGORIES,
    OWNERS,
    load_config,
    save_config,
    vendor_hint,
    suggest_owner,
)
from netwatch.infrastructure import DatabaseManager, EventStore
from netwatch.services import NetworkScanner, RiskCalculator, ReportGenerator
from netwatch.ui import (
    DARK_CSS,
    section_label,
    risk_color,
    render_event_card,
    render_risk_bar,
    chart_risk_donut,
    chart_vendor_hbar,
    chart_ports_hbar,
    chart_events_timeline,
)

import messaging
import time
from datetime import datetime
from collections import Counter

st.set_page_config(
    page_title="NetWatch - Monitor de Rede",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(DARK_CSS, unsafe_allow_html=True)

db_manager = DatabaseManager()
event_store = EventStore()
scanner = NetworkScanner()
risk_calc = RiskCalculator()
report_gen = ReportGenerator()

if "db" not in st.session_state:
    st.session_state["db"] = db_manager.load()
if "events" not in st.session_state:
    st.session_state["events"] = event_store.load()

conf = load_config()
if not conf.get("sudo_ok"):
    conf["sudo_ok"] = scanner.can_use_sudo()
    save_config(conf)

st.title("🛡️ NetWatch")
st.caption(f"v{APP_VERSION} | Central de Monitoramento de Rede")

with st.sidebar:
    st.header("⚙️ Configuração")
    target = st.text_input(
        "Alvo",
        value=conf.get("default_range", DEFAULT_RANGE),
        placeholder="192.168.1.0/24",
    )

    use_sudo = conf.get("sudo_ok", False)
    if conf.get("sudo_ok") is None:
        use_sudo = st.checkbox("Usar sudo (para MAC/vendor)", value=False)
        conf["sudo_ok"] = use_sudo
        save_config(conf)
    else:
        st.caption(f"Modo sudo: {'✓ Ativo' if conf['sudo_ok'] else '✗ Inativo'}")

    auto_refresh = st.toggle("Auto-refresh", value=conf.get("auto_refresh", False))
    refresh_sec = st.slider("Intervalo (s)", 5, 60, conf.get("refresh_sec", 15))

    st.divider()
    st.subheader("📡 Scanner")
    if st.button("🔍 Iniciar Scan", type="primary", use_container_width=True):
        with st.spinner("Escaneando rede..."):
            xml = scanner.run_discovery(target, timeout_s=conf.get("scan_timeout", 30))
            devices = scanner.parse_discovery_results(xml)

            new_count = 0
            for dev in devices:
                mac_key = dev.get("mac", "").upper().replace(":", "-").replace(":", "")
                if not mac_key:
                    continue

                old = st.session_state["db"]["seen"].get(mac_key)
                if not old:
                    new_count += 1
                    st.session_state["events"] = event_store.add(
                        st.session_state["events"],
                        "INFO",
                        f"Novo dispositivo detectado: {dev.get('ip')}",
                        mac_key,
                        dev.get("ip"),
                    )

                dev["vendor"] = vendor_hint(dev.get("vendor"))
                dev["risk_score"], dev["risk_level"] = risk_calc.calculate(dev, st.session_state["db"])

                st.session_state["db"]["seen"][mac_key] = dev

            if new_count > 0:
                st.success(f"{new_count} novo(s) dispositivo(s)!")

            db_manager.save(st.session_state["db"])
            event_store.save(st.session_state["events"])

            st.session_state["last_scan"] = datetime.now()

    if "last_scan" in st.session_state:
        st.caption(f"Último scan: {st.session_state['last_scan'].strftime('%H:%M:%S')}")

    st.divider()
    st.subheader("🔧 Operações")
    if st.button("📄 Gerar Relatório"):
        pdf = report_gen.generate(
            list(st.session_state["db"]["seen"].values()),
            st.session_state["events"],
            conf,
        )
        if pdf:
            st.download_button(
                "⬇️ Baixar PDF",
                data=pdf,
                file_name=f"netwatch_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
            )
        else:
            st.error("ReportLab não disponível.")

    with st.expander("🗑️ Limpar Dados"):
        if st.button("Resetar DB"):
            st.session_state["db"] = db_manager._empty_db()
            st.session_state["events"] = []
            db_manager.save(st.session_state["db"])
            event_store.save(st.session_state["events"])
            st.success("Dados resetados!")

devices = list(st.session_state["db"]["seen"].values())
events = st.session_state["events"]

if devices:
    c1, c2, c3, c4 = st.columns(4)
    risk_counts = Counter(d.get("risk_level", "INFO") for d in devices)
    with c1:
        st.metric("Dispositivos", len(devices))
    with c2:
        st.metric("Online", sum(1 for d in devices if d.get("status") == "up"))
    with c3:
        high_risk = sum(1 for d in devices if d.get("risk_level") in ("CRÍTICO", "ALTO"))
        st.metric("Alto Risco", high_risk, delta_color="inverse")
    with c4:
        st.metric("Eventos", len(events))

    col_charts = st.columns([1, 1])
    with col_charts[0]:
        fig = chart_risk_donut(dict(risk_counts))
        st.pyplot(fig)
    with col_charts[1]:
        vendor_map = Counter(d.get("vendor", "Desconhecido") for d in devices)
        fig = chart_vendor_hbar(dict(vendor_map))
        st.pyplot(fig)

section_label("📟 Dispositivos")

if devices:
    df_data = []
    for d in devices:
        mac_key = d.get("mac", "").upper().replace(":", "-").replace(":", "")
        known = st.session_state["db"]["known"].get(mac_key, {})
        df_data.append({
            "IP": d.get("ip", "-"),
            "MAC": d.get("mac", "-")[:17],
            "Hostname": d.get("hostname", "-") or "-",
            "Vendor": d.get("vendor", "-") or "-",
            "Nível": d.get("risk_level", "INFO"),
            "Score": d.get("risk_score", 0),
            "Proprietário": known.get("owner", "desconhecido"),
        })

    st.dataframe(
        df_data,
        column_config={
            "Nível": st.column_config.TextColumn("Nível", help="Nível de risco",),
            "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d"),
        },
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("Nenhum dispositivo encontrado. Execute um scan.")

section_label("📰 Eventos Recentes")
if events:
    recent = sorted(events, key=lambda x: x.get("timestamp", 0), reverse=True)[:15]
    for ev in recent:
        render_event_card(ev)

    fig = chart_events_timeline(events)
    st.pyplot(fig)
else:
    st.info("Nenhum evento registrado.")

if auto_refresh:
    st.markdown(
        f'<div style="position:fixed; bottom:16px; right:16px; background:var(--bg-card); '
        f'border:1px solid var(--border); border-radius:4px; padding:6px 12px; '
        f'font-family:var(--font-mono); font-size:0.72rem; color:var(--text-secondary);">'
        f'<span class="nw-scan-pulse"></span>Auto-refresh: {refresh_sec}s</div>',
        unsafe_allow_html=True,
    )
    time.sleep(refresh_sec)
    st.rerun()
