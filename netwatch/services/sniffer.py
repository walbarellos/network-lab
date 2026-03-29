"""Network sniffing and traffic analysis tools."""

import re
import shlex
import subprocess
import tempfile
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Generator


@dataclass
class Packet:
    timestamp: str
    protocol: str
    source: str
    destination: str
    info: str
    payload_ascii: str = ""
    flags: str = ""
    length: int = 0

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class NetworkSniffer:
    """Captura e análise de tráfego de rede."""

    HTTP_PORTS = {80, 8080, 8000, 8008, 3000, 5000}
    ADB_PORT = 5555

    def __init__(self, interface: str = "eno1"):
        self.interface = interface

    def get_interfaces(self) -> list[str]:
        """Lista interfaces de rede disponíveis."""
        try:
            result = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            ifaces = re.findall(r"^\d+:\s+(\S+):", result.stdout, re.MULTILINE)
            return [i.rstrip(":") for i in ifaces if i not in ("lo", "lo:")]
        except Exception:
            return ["eno1", "wlan0", "any"]

    def capture_packets(
        self,
        count: int = 30,
        filter_exp: str = "",
        ascii_payload: bool = False,
        timeout: int = 30,
    ) -> list[dict]:
        cmd = [
            "sudo", "tcpdump",
            "-i", self.interface,
            "-n",
            "-l",
            "-tttt",
            "-c", str(count),
        ]

        if ascii_payload:
            cmd.append("-A")

        if filter_exp:
            cmd.extend(shlex.split(filter_exp))
        else:
            cmd.extend(["not", "port", "22"])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            import time
            start = time.time()
            stdout_lines = []
            while time.time() - start < timeout:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                stdout_lines.append(line)
                if len(stdout_lines) >= count:
                    break
            
            proc.terminate()
            stdout = "".join(stdout_lines)
            
            return self._parse_tcpdump(stdout, ascii_payload)
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
            "sudo", "tcpdump",
            "-i", self.interface,
            "-n",
            "-c", str(count),
            "-w", output_path,
        ]
        if filter_exp:
            cmd.extend(shlex.split(filter_exp))

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout)
            return result.returncode == 0
        except Exception:
            return False

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

            timestamp = ts_match.group(1)
            proto_raw = ts_match.group(2)
            rest = ts_match.group(3)

            if proto_raw == "ARP":
                packets.append({
                    "timestamp": timestamp,
                    "protocol": "ARP",
                    "source": "",
                    "destination": "",
                    "info": rest.strip(),
                    "payload_ascii": "",
                    "flags": "",
                    "length": 0,
                })
                i += 1
                continue

            flow_match = re.match(r"(\S+)\s+>\s+(\S+?):\s*(.*)", rest)
            if not flow_match:
                i += 1
                continue

            src = flow_match.group(1)
            dst = flow_match.group(2)
            info = flow_match.group(3)

            protocol = self._detect_protocol(src, dst, info, proto_raw)

            flags = ""
            flags_match = re.search(r"Flags\s+\[([^\]]+)\]", info)
            if flags_match:
                flags = flags_match.group(1)

            length = 0
            len_match = re.search(r"length\s+(\d+)", info)
            if len_match:
                length = int(len_match.group(1))

            payload_lines: list[str] = []
            if has_payload and length > 0:
                j = i + 1
                while j < len(lines):
                    next_line = lines[j]
                    if re.match(r"^\d{4}-\d{2}-\d{2}", next_line) or next_line.startswith("tcpdump"):
                        break
                    if next_line.strip():
                        payload_lines.append(next_line)
                    j += 1
                i = j
            else:
                i += 1

            payload_ascii = "\n".join(payload_lines)

            packets.append({
                "timestamp": timestamp,
                "protocol": protocol,
                "source": src,
                "destination": dst,
                "info": info,
                "flags": flags,
                "length": length,
                "payload_ascii": payload_ascii,
            })

        return packets

    def _detect_protocol(self, src: str, dst: str, info: str, ip_version: str) -> str:
        def port_of(addr: str) -> int:
            parts = addr.rsplit(".", 1)
            try:
                return int(parts[-1])
            except ValueError:
                return 0

        sport = port_of(src)
        dport = port_of(dst)

        if sport in self.HTTP_PORTS or dport in self.HTTP_PORTS:
            return "HTTP"
        if sport == 53 or dport == 53:
            return "DNS"
        if sport == self.ADB_PORT or dport == self.ADB_PORT:
            return "ADB"
        if sport == 443 or dport == 443:
            return "HTTPS"
        if sport == 67 or sport == 68 or dport == 67 or dport == 68:
            return "DHCP"
        if "ICMP" in ip_version.upper() or "icmp" in info.lower():
            return "ICMP"
        if "UDP" in info.upper() or "udp" in info.lower():
            return "UDP"
        return ip_version

    def extract_http_sessions(self, packets: list[dict]) -> list[dict]:
        sessions: list[dict] = []

        for pkt in packets:
            payload = pkt.get("payload_ascii", "")
            if not payload:
                continue

            req_match = re.match(
                r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+",
                payload,
                re.IGNORECASE,
            )
            if req_match:
                method = req_match.group(1).upper()
                path = req_match.group(2)

                host_match = re.search(r"^Host:\s*(.+)$", payload, re.MULTILINE | re.IGNORECASE)
                host = host_match.group(1).strip() if host_match else pkt.get("destination", "")

                auth_match = re.search(r"Authorization:\s*Basic\s+(\S+)", payload, re.IGNORECASE)
                basic_creds = None
                if auth_match:
                    import base64
                    try:
                        basic_creds = base64.b64decode(auth_match.group(1)).decode("utf-8", errors="replace")
                    except Exception:
                        basic_creds = auth_match.group(1)

                body = ""
                if "\r\n\r\n" in payload:
                    body = payload.split("\r\n\r\n", 1)[-1].strip()
                elif "\n\n" in payload:
                    body = payload.split("\n\n", 1)[-1].strip()

                sessions.append({
                    "type": "request",
                    "timestamp": pkt.get("timestamp", ""),
                    "source": pkt.get("source", ""),
                    "method": method,
                    "host": host,
                    "path": path,
                    "basic_auth": basic_creds,
                    "body": body[:500] if body else "",
                    "full_url": f"http://{host}{path}",
                })

            resp_match = re.match(r"HTTP/[\d.]+\s+(\d{3})\s+(.*)", payload)
            if resp_match:
                sessions.append({
                    "type": "response",
                    "timestamp": pkt.get("timestamp", ""),
                    "destination": pkt.get("destination", ""),
                    "status_code": int(resp_match.group(1)),
                    "status_text": resp_match.group(2).strip(),
                    "body_preview": payload[-300:],
                })

        return sessions

    def extract_dns_queries(self, packets: list[dict]) -> list[dict]:
        queries: list[dict] = []

        for pkt in packets:
            if pkt.get("protocol") != "DNS":
                continue
            payload = pkt.get("payload_ascii", "")
            info = pkt.get("info", "")

            domain_match = re.search(r"A\?\s+(\S+)\.", info)
            if domain_match:
                queries.append({
                    "timestamp": pkt.get("timestamp", ""),
                    "source": pkt.get("source", ""),
                    "domain": domain_match.group(1),
                    "type": "A",
                })
                continue

            aaaa_match = re.search(r"AAAA\?\s+(\S+)\.", info)
            if aaaa_match:
                queries.append({
                    "timestamp": pkt.get("timestamp", ""),
                    "source": pkt.get("source", ""),
                    "domain": aaaa_match.group(1),
                    "type": "AAAA",
                })

        return queries

    def detect_arp_anomalies(self, duration_packets: list[dict]) -> list[dict]:
        ip_to_macs: dict[str, set[str]] = {}
        anomalies: list[dict] = []

        for pkt in duration_packets:
            if pkt.get("protocol") != "ARP":
                continue
            info = pkt.get("info", "")

            reply_match = re.search(r"Reply\s+(\S+)\s+is-at\s+([0-9a-f:]{17})", info, re.IGNORECASE)
            if reply_match:
                ip = reply_match.group(1)
                mac = reply_match.group(2).lower()
                ip_to_macs.setdefault(ip, set()).add(mac)

        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                anomalies.append({
                    "type": "ARP_SPOOF_SUSPECTED",
                    "ip": ip,
                    "macs_seen": list(macs),
                    "severity": "ALTO",
                    "description": f"IP {ip} respondeu com {len(macs)} MACs diferentes",
                })

        return anomalies

    def monitor_device(self, ip: str, count: int = 200, ascii_payload: bool = True) -> dict:
        filter_exp = f"host {ip} and not port 22"
        packets = self.capture_packets(
            count=count,
            filter_exp=filter_exp,
            ascii_payload=ascii_payload,
            timeout=45,
        )

        protocols: dict[str, int] = {}
        total_bytes = 0

        for p in packets:
            if "error" in p:
                continue
            proto = p.get("protocol", "UNK")
            protocols[proto] = protocols.get(proto, 0) + 1
            total_bytes += p.get("length", 0)

        http_sessions = self.extract_http_sessions(packets) if ascii_payload else []
        dns_queries = self.extract_dns_queries(packets)
        arp_anomalies = self.detect_arp_anomalies(packets)

        return {
            "target": ip,
            "packets_captured": len([p for p in packets if "error" not in p]),
            "total_bytes_approx": total_bytes,
            "protocols": protocols,
            "http_sessions": http_sessions,
            "dns_queries": dns_queries,
            "arp_anomalies": arp_anomalies,
            "sample_packets": [p for p in packets if "error" not in p][:50],
        }

    def monitor_multiple(self, ips: list[str], count: int = 200) -> dict:
        if not ips:
            return {}

        host_filter = " or ".join(f"host {ip}" for ip in ips)
        filter_exp = f"({host_filter}) and not port 22"

        packets = self.capture_packets(
            count=count,
            filter_exp=filter_exp,
            ascii_payload=True,
            timeout=60,
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
                proto = p.get("protocol", "UNK")
                protocols[proto] = protocols.get(proto, 0) + 1

            result[ip] = {
                "packets": len(pkts),
                "protocols": protocols,
                "http_sessions": self.extract_http_sessions(pkts),
                "dns_queries": self.extract_dns_queries(pkts),
            }

        return result

    def scan_arp(self) -> list[dict]:
        try:
            result = subprocess.run(
                ["ip", "neigh", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            devices: list[dict] = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 5:
                    continue
                ip = parts[0]
                try:
                    lladdr_idx = parts.index("lladdr")
                    mac = parts[lladdr_idx + 1]
                    state = parts[-1]
                except (ValueError, IndexError):
                    mac = "N/A"
                    state = "N/A"
                devices.append({"ip": ip, "mac": mac, "state": state})
            return devices
        except Exception:
            return []

    def get_connections(self) -> list[dict]:
        try:
            result = subprocess.run(
                ["ss", "-tunap"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            connections: list[dict] = []
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 6:
                    continue
                connections.append({
                    "protocol": parts[0],
                    "state": parts[1],
                    "local": parts[4],
                    "peer": parts[5],
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
            host_filter = " or ".join(f"host {ip}" for ip in target_ips)
            return f"{base} and ({host_filter})"
        return base

    def monitor_device_mitm(self, ip: str, gateway: str, count: int = 300) -> dict:
        """Monitora dispositivo com ARP MITM (funciona em rede switched)."""
        from netwatch.services.mitm import ARPMITMSession
        
        own_ip = "192.168.100.2"
        
        mitm = ARPMITMSession(self.interface, ip, gateway, wait_s=5.0)
        mitm.start()
        
        packets = self.capture_packets(
            count=count,
            filter_exp=f"host {ip} and not port 22",
            ascii_payload=True,
            timeout=60,
        )
        
        mitm.stop()
        
        protocols: dict[str, int] = {}
        total_bytes = 0

        for p in packets:
            if "error" in p:
                continue
            proto = p.get("protocol", "UNK")
            protocols[proto] = protocols.get(proto, 0) + 1
            total_bytes += p.get("length", 0)

        http_sessions = self.extract_http_sessions(packets)
        dns_queries = self.extract_dns_queries(packets)
        arp_anomalies = self.detect_arp_anomalies(packets)

        return {
            "target": ip,
            "packets_captured": len([p for p in packets if "error" not in p]),
            "total_bytes_approx": total_bytes,
            "protocols": protocols,
            "http_sessions": http_sessions,
            "dns_queries": dns_queries,
            "arp_anomalies": arp_anomalies,
            "sample_packets": [p for p in packets if "error" not in p][:50],
        }


def check_tcpdump_available() -> bool:
    try:
        result = subprocess.run(["which", "tcpdump"], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def filter_presets() -> dict[str, str]:
    return {
        "Tudo (exceto SSH)": "not port 22",
        "Apenas HTTP (não-criptografado)": "tcp port 80 or tcp port 8080 or tcp port 8000",
        "DNS (domínios acessados)": "port 53",
        "ARP (detecção de dispositivos)": "arp",
        "ADB Android (porta 5555)": "tcp port 5555",
        "ICMP (pings)": "icmp or icmp6",
    }
