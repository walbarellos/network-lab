"""Network sniffing and traffic analysis tools."""

import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .mitm import ARPMITMSession


class NetworkSniffer:
    """Captura e análise de tráfego de rede."""

    HTTP_PORTS = {80, 8080, 8000, 8008, 3000, 5000}
    ADB_PORT = 5555

    def __init__(self, interface: str = "eno1"):
        self.interface = interface

    # ── interfaces ────────────────────────────────────────────────────────

    def get_interfaces(self) -> list[str]:
        try:
            result = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True, text=True, timeout=5,
            )
            ifaces = re.findall(r"^\d+:\s+(\S+):", result.stdout, re.MULTILINE)
            return [i.rstrip(":") for i in ifaces if i not in ("lo", "lo:")]
        except Exception:
            return ["eno1", "wlan0", "any"]

    # ── core capture ──────────────────────────────────────────────────────

    def capture_packets(
        self,
        count: int = 30,
        filter_exp: str = "",
        ascii_payload: bool = False,
        timeout: int = 30,
    ) -> list[dict]:
        cmd = [
            "tcpdump",
            "-i", self.interface,
            "-n", "-l", "-tttt",
            "-c", str(count),
        ]
        if ascii_payload:
            cmd.append("-A")
        if filter_exp:
            cmd.extend(shlex.split(filter_exp))
        else:
            cmd.extend(shlex.split("not port 22"))

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return self._parse_tcpdump(result.stdout, ascii_payload)
        except subprocess.TimeoutExpired:
            return [{"error": "Timeout — rede silenciosa ou filtro muito restritivo"}]
        except Exception as e:
            return [{"error": str(e)}]

    def capture_to_pcap(
        self,
        output_path: str,
        count: int = 500,
        filter_exp: str = "",
        timeout: int = 60,
    ) -> bool:
        cmd = [
            "tcpdump",
            "-i", self.interface,
            "-n", "-c", str(count),
            "-w", output_path,
        ]
        if filter_exp:
            cmd.extend(shlex.split(filter_exp))
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout)
            return result.returncode == 0
        except Exception:
            return False

    # ── parser ────────────────────────────────────────────────────────────

    def _parse_tcpdump(self, output: str, has_payload: bool = False) -> list[dict]:
        packets: list[dict] = []
        lines = output.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line or line.startswith("tcpdump"):
                i += 1
                continue
            ts_match = re.match(
                r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(IP6?|ARP|ICMP6?)\s+(.*)",
                line,
            )
            if not ts_match:
                i += 1
                continue
            timestamp, proto_raw, rest = ts_match.group(1), ts_match.group(2), ts_match.group(3)
            if proto_raw == "ARP":
                packets.append({
                    "timestamp": timestamp, "protocol": "ARP",
                    "source": "", "destination": "", "info": rest.strip(),
                    "payload_ascii": "", "flags": "", "length": 0,
                })
                i += 1
                continue
            flow_match = re.match(r"(\S+)\s+>\s+(\S+?):\s*(.*)", rest)
            if not flow_match:
                i += 1
                continue
            src, dst, info = flow_match.group(1), flow_match.group(2), flow_match.group(3)
            protocol = self._detect_protocol(src, dst, info, proto_raw)
            flags_m = re.search(r"Flags\s+\[([^\]]+)\]", info)
            flags = flags_m.group(1) if flags_m else ""
            len_m = re.search(r"length\s+(\d+)", info)
            length = int(len_m.group(1)) if len_m else 0
            payload_lines: list[str] = []
            if has_payload and length > 0:
                j = i + 1
                while j < len(lines):
                    nl = lines[j]
                    if re.match(r"^\d{4}-\d{2}-\d{2}", nl) or nl.startswith("tcpdump"):
                        break
                    if nl.strip():
                        payload_lines.append(nl)
                    j += 1
                i = j
            else:
                i += 1
            packets.append({
                "timestamp": timestamp, "protocol": protocol,
                "source": src, "destination": dst, "info": info,
                "flags": flags, "length": length,
                "payload_ascii": "\n".join(payload_lines),
            })
        return packets

    def _detect_protocol(self, src: str, dst: str, info: str, ip_version: str) -> str:
        def port_of(addr: str) -> int:
            try:
                return int(addr.rsplit(".", 1)[-1])
            except ValueError:
                return 0
        sp, dp = port_of(src), port_of(dst)
        if sp in self.HTTP_PORTS or dp in self.HTTP_PORTS: return "HTTP"
        if sp == 53 or dp == 53: return "DNS"
        if sp == self.ADB_PORT or dp == self.ADB_PORT: return "ADB"
        if sp == 443 or dp == 443: return "HTTPS"
        if sp in (67, 68) or dp in (67, 68): return "DHCP"
        if "ICMP" in ip_version.upper(): return "ICMP"
        return ip_version

    # ── extractors ────────────────────────────────────────────────────────

    def extract_http_sessions(self, packets: list[dict]) -> list[dict]:
        sessions: list[dict] = []
        for pkt in packets:
            payload = pkt.get("payload_ascii", "")
            if not payload:
                continue
            req_m = re.match(
                r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+",
                payload, re.IGNORECASE,
            )
            if req_m:
                method, path = req_m.group(1).upper(), req_m.group(2)
                host_m = re.search(r"^Host:\s*(.+)$", payload, re.MULTILINE | re.IGNORECASE)
                host = host_m.group(1).strip() if host_m else pkt.get("destination", "")
                basic_creds = None
                auth_m = re.search(r"Authorization:\s*Basic\s+(\S+)", payload, re.IGNORECASE)
                if auth_m:
                    import base64
                    try:
                        basic_creds = base64.b64decode(auth_m.group(1)).decode("utf-8", errors="replace")
                    except Exception:
                        basic_creds = auth_m.group(1)
                sep = "\r\n\r\n" if "\r\n\r\n" in payload else "\n\n"
                body = payload.split(sep, 1)[-1].strip()[:500] if sep in payload else ""
                sessions.append({
                    "type": "request", "timestamp": pkt.get("timestamp", ""),
                    "source": pkt.get("source", ""), "method": method,
                    "host": host, "path": path, "basic_auth": basic_creds,
                    "body": body, "full_url": f"http://{host}{path}",
                })
            resp_m = re.match(r"HTTP/[\d.]+\s+(\d{3})\s+(.*)", payload)
            if resp_m:
                sessions.append({
                    "type": "response", "timestamp": pkt.get("timestamp", ""),
                    "destination": pkt.get("destination", ""),
                    "status_code": int(resp_m.group(1)),
                    "status_text": resp_m.group(2).strip(),
                    "body_preview": payload[-300:],
                })
        return sessions

    def extract_dns_queries(self, packets: list[dict]) -> list[dict]:
        queries: list[dict] = []
        for pkt in packets:
            if pkt.get("protocol") != "DNS":
                continue
            info = pkt.get("info", "")
            for qtype in ("AAAA", "A"):
                m = re.search(rf"{qtype}\?\s+(\S+)\.", info)
                if m:
                    queries.append({
                        "timestamp": pkt.get("timestamp", ""),
                        "source": pkt.get("source", ""),
                        "domain": m.group(1), "type": qtype,
                    })
                    break
        return queries

    def detect_arp_anomalies(self, packets: list[dict]) -> list[dict]:
        ip_to_macs: dict[str, set[str]] = {}
        for pkt in packets:
            if pkt.get("protocol") != "ARP":
                continue
            m = re.search(r"Reply\s+(\S+)\s+is-at\s+([0-9a-f:]{17})", pkt.get("info", ""), re.IGNORECASE)
            if m:
                ip_to_macs.setdefault(m.group(1), set()).add(m.group(2).lower())
        return [
            {
                "type": "ARP_SPOOF_SUSPECTED", "ip": ip, "macs_seen": list(macs),
                "severity": "ALTO",
                "description": f"IP {ip} respondeu com {len(macs)} MACs diferentes",
            }
            for ip, macs in ip_to_macs.items() if len(macs) > 1
        ]

    # ── device monitoring ─────────────────────────────────────────────────

    def monitor_device(self, ip: str, count: int = 200, ascii_payload: bool = True) -> dict:
        good = [
            p for p in self.capture_packets(
                count=count,
                filter_exp=f"host {ip} and not port 22",
                ascii_payload=ascii_payload,
                timeout=45,
            )
            if "error" not in p
        ]
        protocols: dict[str, int] = {}
        total_bytes = 0
        for p in good:
            k = p.get("protocol", "UNK")
            protocols[k] = protocols.get(k, 0) + 1
            total_bytes += p.get("length", 0)
        return {
            "target": ip,
            "packets_captured": len(good),
            "total_bytes_approx": total_bytes,
            "protocols": protocols,
            "http_sessions": self.extract_http_sessions(good) if ascii_payload else [],
            "dns_queries": self.extract_dns_queries(good),
            "arp_anomalies": self.detect_arp_anomalies(good),
            "sample_packets": good[:50],
        }

    def monitor_device_mitm(
        self,
        ip: str,
        gateway: str,
        count: int = 300,
        backend: str = "arpspoof",
    ) -> dict:
        """
        Captura tráfego de dispositivo em rede switched via ARP MITM.
        backend: "arpspoof" (dsniff) ou "ettercap"
        """
        from .mitm import ARPMITMSession, EttercapMITMSession
        Session = ARPMITMSession if backend == "arpspoof" else EttercapMITMSession
        with Session(self.interface, ip, gateway):
            return self.monitor_device(ip, count=count, ascii_payload=True)

    def monitor_multiple(self, ips: list[str], count: int = 200) -> dict:
        if not ips:
            return {}
        host_filter = " or ".join(f"host {ip}" for ip in ips)
        packets = self.capture_packets(
            count=count,
            filter_exp=f"({host_filter}) and not port 22",
            ascii_payload=True, timeout=60,
        )
        by_device: dict[str, list[dict]] = {ip: [] for ip in ips}
        for pkt in packets:
            if "error" in pkt:
                continue
            for ip in ips:
                if ip in pkt.get("source", "") or ip in pkt.get("destination", ""):
                    by_device[ip].append(pkt)
                    break
        result: dict = {}
        for ip, pkts in by_device.items():
            protocols: dict[str, int] = {}
            for p in pkts:
                k = p.get("protocol", "UNK")
                protocols[k] = protocols.get(k, 0) + 1
            result[ip] = {
                "packets": len(pkts), "protocols": protocols,
                "http_sessions": self.extract_http_sessions(pkts),
                "dns_queries": self.extract_dns_queries(pkts),
            }
        return result

    # ── ARP / connections ─────────────────────────────────────────────────

    def scan_arp(self) -> list[dict]:
        try:
            result = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5)
            devices: list[dict] = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 5:
                    continue
                ip = parts[0]
                try:
                    idx = parts.index("lladdr")
                    mac, state = parts[idx + 1], parts[-1]
                except (ValueError, IndexError):
                    mac, state = "N/A", "N/A"
                devices.append({"ip": ip, "mac": mac, "state": state})
            return devices
        except Exception:
            return []

    def get_connections(self) -> list[dict]:
        try:
            result = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=5)
            connections: list[dict] = []
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 6:
                    continue
                connections.append({
                    "protocol": parts[0], "state": parts[1],
                    "local": parts[4], "peer": parts[5],
                    "process": parts[6] if len(parts) > 6 else "",
                })
            return connections[:50]
        except Exception:
            return []

    def build_http_demo_filter(self, target_ips: list[str] | None = None) -> str:
        port_filter = " or ".join(f"tcp port {p}" for p in self.HTTP_PORTS)
        if target_ips:
            host_filter = " or ".join(f"host {ip}" for ip in target_ips)
            return f"({port_filter}) and ({host_filter})"
        return f"({port_filter})"

    def build_adb_filter(self, target_ips: list[str] | None = None) -> str:
        base = f"tcp port {self.ADB_PORT}"
        if target_ips:
            return f"{base} and ({' or '.join(f'host {ip}' for ip in target_ips)})"
        return base


# ── utilitários ───────────────────────────────────────────────────────────

def check_tcpdump_available() -> bool:
    return subprocess.run(["which", "tcpdump"], capture_output=True).returncode == 0


def filter_presets() -> dict[str, str]:
    return {
        "Tudo (exceto SSH)": "not port 22",
        "HTTP não-criptografado": "tcp port 80 or tcp port 8080 or tcp port 8000",
        "DNS (domínios acessados)": "port 53",
        "ARP": "arp",
        "ADB Android (porta 5555)": "tcp port 5555",
        "ICMP (pings)": "icmp or icmp6",
        "HTTPS": "tcp port 443",
    }
