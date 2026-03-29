"""Network scanning service using nmap."""

import subprocess
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any

from ..domain.device import create_device, DevicePorts


class NetworkScanner:
    """Handles network discovery and port scanning with nmap."""

    def __init__(self, use_sudo: bool = False):
        self.use_sudo = use_sudo

    def can_use_sudo(self) -> bool:
        """Check if sudo is available for nmap."""
        try:
            result = subprocess.run(
                ["sudo", "-n", "nmap", "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def detect_local_network(self) -> str:
        """Detect local network range from default gateway."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            line = result.stdout.strip()
            if not line:
                return "192.168.1.0/24"
            parts = line.split()
            if "via" in parts:
                gateway_idx = parts.index("via") + 1
                gateway = parts[gateway_idx]
                return gateway.rsplit(".", 1)[0] + ".0/24"
        except Exception:
            pass
        return "192.168.1.0/24"

    def run_discovery(self, target: str, timeout_s: int = 60) -> str:
        """Run nmap discovery scan on target network."""
        
        if self.use_sudo:
            cmd = self._build_command(["-sn", "-PR", "-oX", "-"], target, timeout_s)
        else:
            cmd = ["nmap", "-sn", "-oX", "-", f"--host-timeout={timeout_s}s", target]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_s + 10,
            )
            
            if result.stdout.strip():
                return result.stdout
            
            result2 = subprocess.run(
                ["nmap", "-sP", "-oX", "-", f"--host-timeout={timeout_s}s", target],
                capture_output=True,
                text=True,
                timeout=timeout_s + 10,
            )
            return result2.stdout or ""
        except subprocess.TimeoutExpired:
            return ""
        except Exception:
            return ""

    def run_arp_scan(self, target: str) -> str:
        """Run ARP scan to get MAC addresses."""
        if self.use_sudo:
            cmd = ["sudo", "nmap", "-sn", "-PR", "-oX", "-", "--host-timeout=30s", target]
        else:
            cmd = ["nmap", "-sn", "-PR", "-oX", "-", "--host-timeout=30s", target]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=40,
            )
            return result.stdout
        except Exception:
            return ""

    def run_quick_scan(self, target: str) -> str:
        """Quick port scan to find active hosts."""
        cmd = ["nmap", "-sT", "-p", "22,80,443,5555,8000,8080", "-oX", "-", "--host-timeout=15s", target]
        if self.use_sudo:
            cmd = ["sudo"] + cmd
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=25,
            )
            return result.stdout
        except Exception:
            return ""

    def get_device_hostname(self, ip: str) -> str | None:
        """Get hostname via reverse DNS."""
        try:
            result = subprocess.run(
                ["nslookup", ip],
                capture_output=True,
                text=True,
                timeout=5,
            )
            match = re.search(r"name\s*=\s*(.+)\.", result.stdout)
            if match:
                return match.group(1).strip()
        except Exception:
            pass
        
        try:
            result = subprocess.run(
                ["host", ip],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                match = re.search(r"pointer\s+(.+)\.", result.stdout)
                if match:
                    return match.group(1).strip()
        except Exception:
            pass
        
        return None

    def run_port_scan(
        self, ip: str, args: str = "-sV --top-ports 100 -T4", timeout_s: int = 30
    ) -> str:
        """Run port scan on specific IP."""
        cmd = self._build_command(args.split(), ip, timeout_s)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_s + 10,
            )
            return result.stdout
        except Exception:
            return ""

    def parse_discovery_results(self, xml_output: str) -> list[dict[str, Any]]:
        """Parse nmap XML output into device list."""
        devices = []
        if not xml_output:
            return devices

        try:
            root = ET.fromstring(xml_output)
            for host in root.findall(".//host"):
                status = host.find("status")
                if status is None or status.get("state") != "up":
                    continue

                ip_elem = host.find(".//address[@addrtype='ipv4']")
                ip_addr = ip_elem.get("addr") if ip_elem is not None else None

                mac_elem = host.find(".//address[@addrtype='mac']")
                mac_addr = mac_elem.get("addr") if mac_elem is not None else None
                vendor = mac_elem.get("vendor") if mac_elem is not None else None

                hostname_elem = host.find(".//hostname")
                hostname = (
                    hostname_elem.get("name") if hostname_elem is not None else None
                )

                if ip_addr:
                    device = create_device(
                        ip=ip_addr,
                        mac=mac_addr or "",
                        hostname=hostname,
                        vendor=vendor,
                    )
                    devices.append(device)

        except ET.ParseError:
            pass

        return devices

    def parse_port_results(
        self, xml_output: str, device: dict
    ) -> list[DevicePorts]:
        """Parse port scan results and update device."""
        ports = []
        if not xml_output:
            return ports

        try:
            root = ET.fromstring(xml_output)
            for port in root.findall(".//port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                state_elem = port.find("state")
                service_elem = port.find("service")

                port_info: DevicePorts = {
                    "port": int(port_id) if port_id else 0,
                    "service": service_elem.get("name", "unknown") if service_elem is not None else "unknown",
                    "state": state_elem.get("state", "unknown") if state_elem is not None else "unknown",
                    "version": service_elem.get("version", "") if service_elem is not None else "",
                }
                ports.append(port_info)

        except ET.ParseError:
            pass

        return ports

    def _build_command(self, args: list[str], target: str, timeout: int) -> list[str]:
        """Build nmap command with optional sudo."""
        base = ["nmap"] + args + [f"--host-timeout={timeout}s", target]
        if self.use_sudo:
            return ["sudo"] + base
        return base
