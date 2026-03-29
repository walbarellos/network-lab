"""
NetWatch v2.1 - Central de Monitoramento de Rede
Sistema de Segurança e Investigação para REDE LOCAL
"""

import streamlit as st
from netwatch.core import (
    APP_VERSION,
    DEFAULT_RANGE,
    OWNERS,
    RISK_PORTS,
    load_config,
    save_config,
    vendor_hint,
)
from netwatch.infrastructure import DatabaseManager, EventStore
from netwatch.services import RiskCalculator, ReportGenerator, NetworkSniffer
from netwatch.ui import DARK_CSS

import subprocess
import json
import re
import os
from datetime import datetime, timedelta

st.set_page_config(
    page_title="🛡️ NetWatch",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(DARK_CSS, unsafe_allow_html=True)

db_manager = DatabaseManager()
event_store = EventStore()
risk_calc = RiskCalculator()
report_gen = ReportGenerator()
sniffer = NetworkSniffer()

if "db" not in st.session_state:
    st.session_state["db"] = db_manager.load()
if "events" not in st.session_state:
    st.session_state["events"] = event_store.load()
if "logs" not in st.session_state:
    st.session_state["logs"] = []

conf = load_config()


def add_log(msg: str, level: str = "info"):
    ts = datetime.now().strftime("%H:%M:%S")
    st.session_state["logs"].append({"ts": ts, "msg": msg, "level": level})
    if len(st.session_state["logs"]) > 20:
        st.session_state["logs"] = st.session_state["logs"][-20:]


def get_local_network() -> str:
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=3
        )
        if "via" in result.stdout:
            gateway = result.stdout.split()[2]
            return gateway.rsplit(".", 1)[0] + ".0/24"
    except:
        pass
    return "192.168.100.0/24"


def detect_device_type(ip: str) -> str:
    """Detecta tipo de dispositivo por fingerprinting."""
    try:
        result = subprocess.run(
            ["sudo", "nmap", "-O", "-sV", "--top-ports", "15", "-T4", ip],
            capture_output=True, text=True, timeout=25
        )
        
        output = result.stdout.lower()
        
        if "android" in output:
            return "Android"
        elif "iphone" in output or "ipad" in output:
            return "iPhone/iPad"
        elif "ubuntu" in output or "debian" in output:
            return "Linux (Ubuntu/Debian)"
        elif "raspbian" in output:
            return "Raspberry Pi"
        elif "windows" in output:
            return "Windows"
        elif "macbook" in output or "imac" in output:
            return "Mac"
        elif "cisco" in output or "router" in output:
            return "Roteador"
        
        ports = re.findall(r'(\d+)/open', output)
        if "554" in ports or "8554" in ports:
            return "Câmera IP"
        if "22" in ports:
            return "Servidor/Linux"
        if "1883" in ports or "8883" in ports:
            return "IoT"
            
    except:
        pass
    return "Desconhecido"


def run_full_scan(target: str):
    """Scan completo rápido."""
    try:
        add_log("Iniciando scan completo...")
        
        result = subprocess.run(
            ["sudo", "nmap", "-sn", "-PR", "-oX", "-", target],
            capture_output=True, text=True, timeout=30
        )
        
        output = result.stdout or result.stderr
        devices_found = []
        
        if output:
            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(output)
            except ET.ParseError:
                add_log("Erro ao processar XML do nmap", "error")
                return []
            
            for host in root.findall(".//host"):
                status = host.find("status")
                if status is None or status.get("state") != "up":
                    continue
                
                ip_elem = host.find(".//address[@addrtype='ipv4']")
                ip_addr = ip_elem.get("addr") if ip_elem is not None else None
                
                if not ip_addr:
                    continue
                
                mac_elem = host.find(".//address[@addrtype='mac']")
                mac_addr = mac_elem.get("addr") if mac_elem is not None else ""
                vendor = mac_elem.get("vendor") if mac_elem is not None else None
                
                hostname_elem = host.find(".//hostname")
                hostname = hostname_elem.get("name") if hostname_elem is not None else None
                
                os_elem = host.find(".//osmatch")
                os_match = os_elem.get("name") if os_elem is not None else None
                
                device_type = "Desconhecido"
                if mac_addr:
                    mac_prefix = mac_addr.replace(":", "").upper()[:6]
                    device_type = vendor_hint(mac_prefix)
                
                vendor = vendor_hint(vendor or hostname or os_match or device_type)
                
                mac_key = mac_addr.upper().replace(":", "-") if mac_addr else ip_addr.replace(".", "-")
                
                now = int(datetime.now().timestamp())
                device = {
                    "ip": ip_addr,
                    "mac": mac_addr,
                    "hostname": hostname,
                    "vendor": vendor,
                    "device_type": device_type,
                    "os": os_match,
                    "status": "up",
                    "ports": [],
                    "first_seen": now,
                    "last_seen": now,
                }
                
                device["risk_score"], device["risk_level"] = risk_calc.calculate(device, st.session_state["db"])
                devices_found.append((mac_key, device))
                
                add_log(f"Encontrado: {ip_addr} ({device_type})")
        
        return devices_found
        
    except Exception as e:
        add_log(f"Erro scan: {e}", "error")
        return []


st.title("🛡️ NetWatch")
st.caption(f"v{APP_VERSION} | Monitoramento de Rede Local")

with st.sidebar:
    st.header("🎛️ Controle")
    
    target = get_local_network()
    st.markdown(f"**📡 Rede:** `{target}`")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔍 Escanear", type="primary", use_container_width=True):
            with st.spinner("Escaneando com detecção automática..."):
                devices_found = run_full_scan(target)
                
                new_count = 0
                for mac_key, device in devices_found:
                    old = st.session_state["db"]["seen"].get(mac_key)
                    
                    if not old:
                        new_count += 1
                        st.session_state["events"].append({
                            "id": str(datetime.now().timestamp()),
                            "timestamp": int(datetime.now().timestamp()),
                            "level": "INFO",
                            "message": f"Novo: {device['ip']} ({device.get('device_type', device['vendor'])})",
                            "mac": device.get("mac", ""),
                            "ip": device.get("ip", ""),
                        })
                    
                    device["ports"] = old.get("ports", []) if old else []
                    st.session_state["db"]["seen"][mac_key] = device
                
                db_manager.save(st.session_state["db"])
                event_store.save(st.session_state["events"])
                st.session_state["last_scan"] = datetime.now()
                
                add_log(f"Scan completo: {len(devices_found)} dispositivos")
                if new_count > 0:
                    add_log(f"{new_count} novos!", "success")
                    st.toast(f"🆕 {new_count} novo(s) dispositivo(s)!")
                
                st.rerun()
    
    with col2:
        if st.button("🔄", use_container_width=True, help="Atualizar"):
            st.rerun()
    
    st.divider()
    
    modo = st.radio("Menu:", ["Dashboard", "Dispositivos", "Histórico", "Ferramentas", "Configuração"])
    
    st.divider()
    
    st.subheader("📝 Atividade")
    for log in st.session_state["logs"][-5:]:
        icon = {"info": "ℹ️", "success": "✅", "error": "❌"}.get(log["level"], "ℹ️")
        st.caption(f"{log['ts']} {icon} {log['msg']}")


devices = list(st.session_state["db"]["seen"].values())
events = st.session_state["events"]


if modo == "Dashboard":
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📱 Dispositivos", len(devices))
    with col2:
        online = sum(1 for d in devices if d.get("status") == "up")
        st.metric("🟢 Online", online)
    with col3:
        alerts = sum(1 for d in devices if d.get("risk_level") in ("CRÍTICO", "ALTO"))
        st.metric("⚠️ Alertas", alerts)
    with col4:
        st.metric("📝 Eventos", len(events))

    st.divider()
    
    c1, c2 = st.columns([2, 1])
    
    with c1:
        st.subheader("🚨 Dispositivos")
        
        if not devices:
            st.info("Nenhum dispositivo. Clique em ESCANEAR.")
        else:
            for d in sorted(devices, key=lambda x: x.get("last_seen", 0), reverse=True)[:10]:
                risk = d.get("risk_level", "INFO")
                color = {"CRÍTICO": "#FF1744", "ALTO": "#FF6D00", "MÉDIO": "#FFD600", "BAIXO": "#00E676", "INFO": "#40C4FF"}.get(risk, "#40C4FF")
                device_type = d.get("device_type", d.get("vendor", "Desconhecido"))
                
                st.markdown(f"""
                <div style="background: linear-gradient(90deg, {color}15, transparent);
                            border-left: 4px solid {color}; border-radius: 8px;
                            padding: 10px 14px; margin: 4px 0;">
                    <div style="display: flex; justify-content: space-between;">
                        <span style="font-weight: bold;">📡 {d.get('ip')}</span>
                        <span style="background: {color}22; color: {color}; 
                                    padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;">{risk}</span>
                    </div>
                    <div style="color: var(--text-secondary); font-size: 0.85rem;">
                        {device_type} | {d.get('mac', 'N/A')[:17] if d.get('mac') else 'Sem MAC'}
                    </div>
                </div>
                """, unsafe_allow_html=True)
    
    with c2:
        st.subheader("📜 Eventos")
        if events:
            for ev in sorted(events, key=lambda x: x.get("timestamp", 0), reverse=True)[:8]:
                ts = datetime.fromtimestamp(ev.get("timestamp", 0)).strftime("%H:%M")
                st.caption(f"🕐 {ts} | {ev.get('message', '')[:30]}...")
        else:
            st.info("Sem eventos")


elif modo == "Dispositivos":
    st.subheader("📱 Dispositivos")
    
    if not devices:
        st.info("Execute um scan primeiro.")
    else:
        device_type_filter = st.selectbox(
            "Filtrar por tipo:",
            ["Todos", "Android", "iPhone/iPad", "Linux", "Windows", "Raspberry Pi", "Câmera IP", "IoT", "Roteador", "Servidor"]
        )
        
        filtered = devices
        if device_type_filter != "Todos":
            filtered = [d for d in devices if device_type_filter.lower() in (d.get("device_type", d.get("vendor", "")).lower())]
        
        st.markdown(f"**{len(filtered)} dispositivo(s)**")
        
        for i, d in enumerate(filtered):
            mac_key = d.get("mac", "").upper().replace(":", "-") if d.get("mac") else d.get("ip", "").replace(".", "-")
            known = st.session_state["db"]["known"].get(mac_key, {})
            owner = known.get("owner", "desconhecido")
            
            with st.expander(f"📡 {d.get('ip')} | {d.get('device_type', d.get('vendor'))} | {d.get('risk_level', 'INFO')}"):
                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    st.metric("MAC", d.get("mac", "N/A")[:17] if d.get("mac") else "N/A")
                with c2:
                    st.metric("Hostname", d.get("hostname", "N/A") or "N/A")
                with c3:
                    st.metric("Tipo", d.get("device_type", "N/A") or "N/A")
                with c4:
                    st.metric("Score", f"{d.get('risk_score', 0)}/100")
                
                if d.get("ports"):
                    st.markdown("**Portas:**")
                    for p in d.get("ports", [])[:5]:
                        st.code(f"Porta {p.get('port')} - {p.get('service')}")
                
                st.divider()
                
                col_a, col_b = st.columns(2)
                
                with col_a:
                    owner_opts = list(OWNERS.keys())
                    new_owner = st.selectbox(
                        "Proprietário",
                        owner_opts,
                        index=owner_opts.index(owner) if owner in owner_opts else 3,
                        key=f"owner_{i}"
                    )
                    if new_owner != owner:
                        known["owner"] = new_owner
                        st.session_state["db"]["known"][mac_key] = known
                        db_manager.save(st.session_state["db"])
                        add_log(f"{d.get('ip')} -> {new_owner}")
                        st.rerun()
                
                with col_b:
                    blocked = known.get("blocked", False)
                    if blocked:
                        if st.button("✅ Desbloquear", key=f"unb_{i}"):
                            known["blocked"] = False
                            st.session_state["db"]["known"][mac_key] = known
                            db_manager.save(st.session_state["db"])
                            st.rerun()
                    else:
                        if st.button("🚫 Bloquear", key=f"blk_{i}"):
                            known["blocked"] = True
                            st.session_state["db"]["known"][mac_key] = known
                            db_manager.save(st.session_state["db"])
                            st.rerun()


elif modo == "Histórico":
    st.subheader("📜 Histórico de Eventos")
    
    if not events:
        st.info("Nenhum evento registrado.")
    else:
        filtro_data = st.selectbox(
            "Período:",
            ["Hoje", "Últimas 24h", "Última semana", "Todos"]
        )
        
        now = datetime.now().timestamp()
        if filtro_data == "Hoje":
            inicio = datetime.now().replace(hour=0, minute=0, second=0).timestamp()
        elif filtro_data == "Últimas 24h":
            inicio = now - 86400
        elif filtro_data == "Última semana":
            inicio = now - 604800
        else:
            inicio = 0
        
        filtrados = [e for e in events if e.get("timestamp", 0) >= inicio]
        
        st.markdown(f"**{len(filtrados)} evento(s)**")
        
        for ev in sorted(filtrados, key=lambda x: x.get("timestamp", 0), reverse=True):
            ts = datetime.fromtimestamp(ev.get("timestamp", 0)).strftime("%d/%m %H:%M")
            level = ev.get("level", "INFO")
            color = {"CRÍTICO": "#FF1744", "ALTO": "#FF6D00", "MÉDIO": "#FFD600", "BAIXO": "#00E676", "INFO": "#40C4FF"}.get(level, "#40C4FF")
            
            st.markdown(f"""
            <div style="background: var(--bg-card); border-left: 3px solid {color};
                        border-radius: 4px; padding: 8px 12px; margin: 4px 0;">
                <span style="color: {color}; font-weight: bold;">[{level}]</span>
                <span style="color: var(--text-secondary); margin-left: 8px; font-size: 0.8rem;">{ts}</span>
                <div style="margin-top: 2px;">{ev.get('message', '')}</div>
            </div>
            """, unsafe_allow_html=True)


elif modo == "Ferramentas":
    st.subheader("🛠️ Ferramentas de Rede")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📡 Sniffer (tcpdump)")
        st.warning("⚠️ Requer senha sudo")
        
        iface = st.selectbox("Interface", ["any", "eno1", "wlan0", "eno1"], index=0)
        count = st.slider("Pacotes", 5, 30, 10)
        
        if st.button("🎬 Capturar com tcpdump", type="primary"):
            with st.spinner("Capturando... (digite a senha sudo)"):
                try:
                    result = subprocess.run(
                        ["sudo", "tcpdump", "-i", iface, "-c", str(count), "-l", "-n", "--immediate-mode"],
                        capture_output=True, text=True, timeout=15
                    )
                    
                    if result.stdout:
                        st.success("Capturado!")
                        st.code(result.stdout[:5000])
                        add_log(f"tcpdump: {count} pacotes")
                    else:
                        st.warning("Nenhum pacote")
                        
                except subprocess.TimeoutExpired:
                    st.warning("Timeout - tente novamente")
                except Exception as e:
                    st.error(f"Erro: {e}")
        
        st.markdown("### 📊 Tabela ARP")
        if st.button("🔄 Atualizar ARP"):
            with st.spinner("Lendo..."):
                try:
                    result = subprocess.run(
                        ["ip", "neigh", "show"],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.stdout:
                        for line in result.stdout.split("\n"):
                            if line and "FAILED" not in line:
                                parts = line.split()
                                if len(parts) >= 4:
                                    st.code(f"{parts[0]} → {parts[4]}")
                except Exception as e:
                    st.error(f"Erro: {e}")
        
        st.markdown("### 🔗 Conexões Ativas")
        if st.button("🔄 Ver Conexões"):
            with st.spinner("Listando..."):
                try:
                    result = subprocess.run(
                        ["ss", "-tunap"],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.stdout:
                        for line in result.stdout.split("\n")[:15]:
                            if line:
                                st.code(line[:120])
                except Exception as e:
                    st.error(f"Erro: {e}")
    
    with col2:
        st.markdown("### 🔍 Scan de Portas (nmap)")
        if devices:
            target_ip = st.selectbox("Selecione IP:", [d.get("ip") for d in devices])
            
            if st.button("🔬 Escanear Portas"):
                with st.spinner(f"Escaneando {target_ip}..."):
                    try:
                        result = subprocess.run(
                            ["sudo", "nmap", "-sV", "-sC", "-p", "1-1000", "-T4", target_ip],
                            capture_output=True, text=True, timeout=60
                        )
                        
                        if result.stdout:
                            st.code(result.stdout[:5000])
                            add_log(f"Scan portas: {target_ip}")
                    except Exception as e:
                        st.error(f"Erro: {e}")
        else:
            st.info("Execute scan primeiro")
        
        st.markdown("### 🌐 Informações da Rede")
        
        try:
            result = subprocess.run(["ip", "route", "show"], capture_output=True, text=True, timeout=3)
            st.code(result.stdout[:1500])
        except:
            pass
    
    with col2:
        st.markdown("### 📤 Exportar")
        
        if st.button("📥 Exportar JSON"):
            data = {
                "devices": devices,
                "events": events,
                "exported_at": datetime.now().isoformat()
            }
            st.download_button(
                "⬇️ Baixar JSON",
                data=json.dumps(data, indent=2, ensure_ascii=False),
                file_name=f"netwatch_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                mime="application/json"
            )
        
        if st.button("📥 Exportar CSV"):
            csv = "IP,MAC,Device Type,Vendor,Risk Level,Score,Last Seen\n"
            for d in devices:
                csv += f"{d.get('ip')},{d.get('mac','')},{d.get('device_type','')},{d.get('vendor','')},{d.get('risk_level','')},{d.get('risk_score',0)},{d.get('last_seen',0)}\n"
            st.download_button(
                "⬇️ Baixar CSV",
                data=csv,
                file_name=f"netwatch_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                mime="text/csv"
            )
        
        if st.button("📊 Gerar PDF"):
            pdf = report_gen.generate(devices, events, conf)
            if pdf:
                st.download_button(
                    "⬇️ Baixar PDF",
                    data=pdf,
                    file_name=f"netwatch_{datetime.now().strftime('%Y%m%d')}.pdf",
                    mime="application/pdf"
                )
    
    st.divider()
    
    st.subheader("🤖 Monitor de Bots")
    
    bot_ips = [d.get("ip") for d in devices if d.get("ip")]
    
    col_b1, col_b2 = st.columns(2)
    
    with col_b1:
        st.markdown("#### 📡 Monitorar Todos")
        if st.button("🎯 Capturar Tráfego de Todos", type="primary"):
            if bot_ips:
                with st.spinner(f"Capturando de {len(bot_ips)} dispositivos..."):
                    result = sniffer.monitor_multiple(bot_ips, count=100)
                    for ip, data in result.items():
                        packets = data.get("packets", 0)
                        if packets > 0:
                            protocols = data.get("protocols", {})
                            http = data.get("http_sessions", [])
                            dns = data.get("dns_queries", [])
                            
                            with st.expander(f"📱 {ip} ({packets} pacotes)"):
                                st.write(f"**Protocolos:** {protocols}")
                                if http:
                                    st.write("**HTTP Sessions:**")
                                    for s in http[:3]:
                                        st.caption(f"{s.get('method')} {s.get('full_url', '')}")
                                if dns:
                                    st.write("**DNS Queries:**")
                                    for q in dns[:5]:
                                        st.caption(f"{q.get('domain', '')}")
                    add_log(f"Monitorados {len(bot_ips)} dispositivos")
            else:
                st.warning("Execute scan primeiro")
        
        st.markdown("#### 🎛️ Filtros Rápidos")
        filter_type = st.selectbox(
            "Tipo de filtro:",
            ["Tudo (exceto SSH)", "Apenas HTTP", "DNS", "ADB Android", "ARP", "ICMP"]
        )
        
        filter_map = {
            "Tudo (exceto SSH)": "not port 22",
            "Apenas HTTP": "tcp port 80 or tcp port 8080",
            "DNS": "port 53",
            "ADB Android": "tcp port 5555",
            "ARP": "arp",
            "ICMP": "icmp"
        }
        
        filter_btn = st.button("🔍 Capturar com Filtro")
        if filter_btn:
            with st.spinner(f"Capturando com filtro: {filter_type}"):
                pkts = sniffer.capture_packets(count=30, filter_exp=filter_map[filter_type], ascii_payload=True)
                if pkts:
                    st.success(f"{len(pkts)} pacotes capturados")
                    for p in pkts[:10]:
                        st.code(f"{p.get('timestamp', '')} | {p.get('protocol', '')} | {p.get('source', '')} > {p.get('destination', '')}")
                else:
                    st.warning("Nenhum pacote")
    
    with col_b2:
        st.markdown("#### 🔍 Monitorar com MITM")
        st.caption("⚠️ Requer arpspoof (ARP spoofing)")
        if devices:
            target_bot = st.selectbox("Selecione bot:", [d.get("ip") for d in devices])
            
            if st.button("🎯 Capturar Tráfego") and target_bot:
                with st.spinner(f"MITM + capturando {target_bot}..."):
                    try:
                        result = sniffer.monitor_device_mitm(target_bot, "192.168.100.1", count=200)
                    except Exception as e:
                        st.error(f"Erro MITM: {e}")
                        st.info("Execute: sudo pacman -S dsniff")
                        result = {"packets_captured": 0, "protocols": {}, "http_sessions": [], "dns_queries": []}
                    
                    st.metric("Pacotes", result.get("packets_captured", 0))
                    
                    protocols = result.get("protocols", {})
                    if protocols:
                        st.write("**Tráfego por protocolo:**")
                        for proto, count in protocols.items():
                            st.caption(f"{proto}: {count}")
                    
                    http_sessions = result.get("http_sessions", [])
                    if http_sessions:
                        st.write("**HTTP Sessions detectadas:**")
                        for s in http_sessions[:5]:
                            st.caption(f"{s.get('method')} {s.get('full_url', '')}")
                    
                    dns_queries = result.get("dns_queries", [])
                    if dns_queries:
                        st.write("**DNS queries:**")
                        for q in dns_queries[:5]:
                            st.caption(f"{q.get('domain', '')}")
                    
                    arp_anomalies = result.get("arp_anomalies", [])
                    if arp_anomalies:
                        st.error("⚠️ Anomalias ARP detectadas!")
                        for a in arp_anomalies:
                            st.code(f"{a.get('type')}: {a.get('description')}")
                    
                    add_log(f"Monitorado: {target_bot}")
        else:
            st.info("Execute scan primeiro")
        
        st.markdown("#### 💾 Salvar PCAP")
        if st.button("📦 Salvar .pcap"):
            with st.spinner("Salvando captura..."):
                import tempfile
                pcap_path = tempfile.mktemp(suffix=".pcap")
                success = sniffer.capture_to_pcap(pcap_path, count=200, filter_exp="not port 22")
                if success and os.path.exists(pcap_path):
                    with open(pcap_path, "rb") as f:
                        st.download_button(
                            "⬇️ Baixar PCAP",
                            data=f.read(),
                            file_name=f"capture_{datetime.now().strftime('%Y%m%d_%H%M')}.pcap",
                            mime="application/vnd.tcpdump.pcap"
                        )
                    add_log("PCAP salvo")


elif modo == "Configuração":
    st.subheader("⚙️ Configurações")
    
    st.write(f"Dispositivos: {len(devices)}")
    st.write(f"Eventos: {len(events)}")
    st.write(f"Último scan: {st.session_state.get('last_scan', 'Nunca')}")
    
    st.divider()
    
    if st.button("Resetar Tudo", type="primary"):
        st.session_state["db"] = db_manager._empty_db()
        st.session_state["events"] = []
        db_manager.save(st.session_state["db"])
        event_store.save([])
        add_log("Sistema resetado", "warning")
        st.success("Resetado!")
        st.rerun()
