"""
Packet Sender — sends real network packets from the attacker machine
to a target IP using scapy. These packets travel over the actual
network (Wi-Fi/hotspot) and get captured by the IDS machine's
live scapy capture — no port 9875 needed.

Used by run_attacker.py --real <TARGET_IP>
"""
import random
import time
import threading
from datetime import datetime

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Raw,
        send, RandShort, conf
    )
    conf.verb = 0   # suppress scapy output
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

import socket as _socket


def _check_scapy():
    if not SCAPY_OK:
        raise RuntimeError(
            "scapy not installed — run: python -m pip install scapy\n"
            "Also needs Npcap (Windows) or root (Linux) to send raw packets."
        )


class PacketSender:
    """
    Sends real packets to a target IP based on attack profiles.
    The IDS machine captures these via its live Wi-Fi capture.
    """

    def __init__(self, target_ip: str, on_status=None, rate_limit: float = 0.3):
        self.target_ip  = target_ip
        self.on_status  = on_status or (lambda m: None)
        self.rate_limit = rate_limit
        self._running   = False
        self._stats     = {"sent": 0, "errors": 0}
        self._lock      = threading.Lock()

    def start_profile(self, profile_name: str, params: dict,
                      count: int = 0, duration: float = 0):
        """
        Send packets matching a profile.
        count=0 and duration=0 means run until stop() is called.
        """
        _check_scapy()
        self._running = True
        t = threading.Thread(
            target=self._send_loop,
            args=(profile_name, params, count, duration),
            daemon=True,
        )
        t.start()
        return t

    def stop(self):
        self._running = False

    @property
    def stats(self):
        with self._lock:
            return dict(self._stats)

    def _send_loop(self, profile_name: str, params: dict,
                   count: int, duration: float):
        sent     = 0
        start    = time.time()
        target   = self.target_ip
        proto    = params.get("protocol", 6)
        port_dst = params.get("port_dst", 80)
        flags    = params.get("flags", 0x02)
        rate     = params.get("rate_hz", 100)
        b_in     = params.get("bytes_in", 100)

        # Convert flags int to scapy flag string
        flag_map = {0x02: "S", 0x18: "PA", 0x10: "A", 0x04: "R", 0x00: ""}
        tcp_flags = flag_map.get(flags, "S")

        delay = max(0.001, 1.0 / max(rate, 1))

        self.on_status(
            f"[packet-sender] sending {profile_name} → {target}  "
            f"proto={'TCP' if proto==6 else 'UDP'}  port={port_dst}  "
            f"rate={rate}/s"
        )

        while self._running:
            if count > 0 and sent >= count:
                break
            if duration > 0 and (time.time() - start) >= duration:
                break

            try:
                src_port = random.randint(1024, 65535)
                if port_dst == -1:
                    port_dst = random.randint(1, 65535)

                payload_size = max(0, int(b_in * random.uniform(0.8, 1.2)) - 40)
                payload = Raw(load=bytes(random.getrandbits(8)
                                        for _ in range(payload_size))) \
                          if payload_size > 0 else b""

                if proto == 6:   # TCP
                    pkt = (IP(dst=target) /
                           TCP(sport=src_port, dport=port_dst, flags=tcp_flags) /
                           payload)
                elif proto == 17:  # UDP
                    pkt = (IP(dst=target) /
                           UDP(sport=src_port, dport=port_dst) /
                           payload)
                else:
                    pkt = IP(dst=target) / ICMP()

                send(pkt, verbose=False)
                sent += 1
                with self._lock:
                    self._stats["sent"] += 1

            except Exception as e:
                with self._lock:
                    self._stats["errors"] += 1
                self.on_status(f"[packet-sender] send error: {e}")
                time.sleep(0.5)
                continue

            time.sleep(delay * random.uniform(0.8, 1.2))

        self.on_status(f"[packet-sender] {profile_name} done — sent {sent} packets")
