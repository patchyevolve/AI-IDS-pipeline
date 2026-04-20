"""
Target Scanner — discovers live hosts on the local subnet.
Uses ARP ping via scapy if available, falls back to ICMP ping,
falls back to a static subnet sweep (synthetic mode).

Only scans the local /24 subnet of the machine's default interface.
Results cached and refreshed every RESCAN_INTERVAL seconds.
"""
import socket
import threading
import time
import ipaddress
import subprocess
import sys

RESCAN_INTERVAL = 120   # seconds between rescans
SCAN_TIMEOUT    = 1.0   # per-host timeout


def _get_local_subnet() -> str:
    """Returns e.g. '192.168.1.0/24' for the default interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        # Assume /24
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def _arp_scan(subnet: str, timeout: float = 2.0) -> list:
    """ARP scan via scapy — most reliable on LAN."""
    try:
        from scapy.all import ARP, Ether, srp
        net = ipaddress.ip_network(subnet, strict=False)
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
        answered, _ = srp(pkt, timeout=timeout, verbose=False)
        return [rcv.psrc for _, rcv in answered]
    except Exception:
        return []


def _ping_scan(subnet: str) -> list:
    """ICMP ping sweep — works without scapy."""
    live = []
    net  = ipaddress.ip_network(subnet, strict=False)
    hosts = list(net.hosts())[:254]

    def _ping(ip):
        try:
            flag = "-n" if sys.platform == "win32" else "-c"
            r = subprocess.run(
                ["ping", flag, "1", "-w", "500", str(ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1.5,
            )
            if r.returncode == 0:
                live.append(str(ip))
        except Exception:
            pass

    threads = [threading.Thread(target=_ping, args=(h,), daemon=True) for h in hosts]
    for t in threads: t.start()
    for t in threads: t.join(timeout=2.0)
    return live


def _synthetic_hosts(subnet: str, n: int = 8) -> list:
    """Return n fake IPs in the subnet for synthetic mode."""
    import random
    net   = ipaddress.ip_network(subnet, strict=False)
    hosts = list(net.hosts())
    return [str(h) for h in random.sample(hosts, min(n, len(hosts)))]


class TargetScanner:
    def __init__(self, synthetic: bool = False):
        self.synthetic  = synthetic
        self.subnet     = _get_local_subnet()
        self._targets:  list = []
        self._lock      = threading.Lock()
        self._running   = False
        self._thread    = None

    def start(self):
        self._running = True
        self._scan()   # initial scan
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            time.sleep(RESCAN_INTERVAL)
            self._scan()

    def _scan(self):
        if self.synthetic:
            found = _synthetic_hosts(self.subnet)
        else:
            found = _arp_scan(self.subnet)
            if not found:
                found = _ping_scan(self.subnet)
            if not found:
                found = _synthetic_hosts(self.subnet)

        # Always include a few synthetic IPs so attacker has targets even on quiet nets
        if len(found) < 3:
            found += _synthetic_hosts(self.subnet, 4)

        with self._lock:
            self._targets = list(set(found))

    def get_targets(self) -> list:
        with self._lock:
            return list(self._targets) if self._targets else _synthetic_hosts(self.subnet, 4)

    def random_target(self) -> str:
        targets = self.get_targets()
        import random
        return random.choice(targets)
