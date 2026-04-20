"""
IDS Bridge — reads live network events from the C++ IDS capture pipeline
via a local socket (or falls back to synthetic data if not connected).

The C++ side (ids_capture.hpp + ids.hpp) writes JSON events to
127.0.0.1:9876 when connected. This bridge:
  1. Receives raw Event JSON from the C++ IDS
  2. Converts to Python dicts matching ids_types.hpp structures
  3. Emits to the AI pipeline (CNN → RNN → Decoder)
  4. Sends refined decisions back to IDS via port 9877

For direct Python capture (no C++ IDS), set mode="direct" and
provide interface + bpf_filter — uses scapy if available.
"""
import socket
import json
import threading
import time
import random
import math
import sys
from datetime import datetime

IDS_EVENT_PORT    = 9876   # C++ IDS → Python (inbound events)
IDS_DECISION_PORT = 9877   # Python → C++ IDS (refined decisions)
BUFFER_SIZE       = 65536

EVENT_TYPES = [
    "NetworkPacket", "SysLog", "ProcessEvent", "AuthEvent",
    "FileAccess", "ApiCall", "Signal", "Unknown"
]

DECISION_MAP = {
    0: "Ignore", 1: "Log", 2: "Alert", 3: "Block", 4: "Escalate"
}

class IDSBridge:
    def __init__(self, event_bus, interface: str = "", scapy_name: str = "",
                 bpf_filter: str = "", mode: str = "synthetic", on_status=None):
        self.event_bus  = event_bus
        self.interface  = interface
        self.scapy_name = scapy_name or interface   # NPF GUID on Windows
        self.bpf_filter = bpf_filter
        self.mode       = mode
        self.on_status  = on_status
        self.connected  = False
        self.running    = False
        self._sock      = None
        self._dec_sock  = None
        self._stats     = {
            "packets_received": 0,
            "packets_dropped":  0,
            "bytes_total":      0,
            "alerts_sent":      0,
            "interface":        interface or "—",
            "filter":           bpf_filter or "all",
            "last_src":         "—",
            "last_dst":         "—",
            "last_proto":       "—",
            "last_entropy":     0.0,
            "last_anomaly":     0.0,
        }

    @property
    def stats(self):
        return dict(self._stats)

    def start(self):
        self.running = True
        # ✓ FIX: Always listen for remote attacker events on port 9875
        # This allows remote attacker to send events regardless of live/synthetic mode
        threading.Thread(target=self._listen_loop, daemon=True, name="remote-listener").start()
        
        if self.mode in ("live", "direct"):
            # "live" = scapy direct capture (setup screen label), "direct" = same thing
            threading.Thread(target=self._direct_capture, daemon=True).start()
        else:
            threading.Thread(target=self._synthetic_fallback, daemon=True).start()

    def stop(self):
        self.running = False
        if self._sock:
            try: self._sock.close()
            except: pass

    # Inbound: receive IDS events
    def _listen_loop(self):
        while self.running:
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("127.0.0.1", IDS_EVENT_PORT))
                srv.listen(1)
                srv.settimeout(2.0)
                if self.on_status:
                    self.on_status(f"Listening on 127.0.0.1:{IDS_EVENT_PORT}")
                conn, addr = srv.accept()
                self.connected = True
                self._sock = conn
                if self.on_status:
                    self.on_status(f"IDS connected from {addr[0]}")
                buf = ""
                while self.running:
                    chunk = conn.recv(BUFFER_SIZE).decode("utf-8", errors="ignore")
                    if not chunk:
                        break
                    buf += chunk
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        line = line.strip()
                        if line:
                            self._handle_event(line)
                self.connected = False
                conn.close()
                srv.close()
            except socket.timeout:
                pass
            except Exception as e:
                self.connected = False
                if self.on_status:
                    self.on_status(f"Socket error: {e}")
                time.sleep(1.0)

    def _handle_event(self, raw_json: str):
        try:
            ev = json.loads(raw_json)
            self._stats["packets_received"] += 1
            self._stats["bytes_total"]      += ev.get("payload", {}).get("bytes_in", 0)
            self._stats["last_src"]          = ev.get("source", "—")
            self._stats["last_dst"]          = ev.get("destination", "—")
            self._stats["last_proto"]        = str(ev.get("payload", {}).get("protocol", "—"))
            self._stats["last_entropy"]      = ev.get("payload", {}).get("entropy", 0.0)
            self._stats["interface"]         = ev.get("interface", "live")

            # ✓ FIX: Preserve original metadata from remote attacker
            # REASON: Metadata contains atk_tag needed for feedback matching
            metadata = dict(ev.get("metadata", {}))  # Make a copy to avoid modifying original
            if not metadata:
                metadata = {}
            # Add interface info to metadata but preserve all existing keys (including atk_tag)
            metadata["interface"] = ev.get("interface", "live")

            # Emit to AI pipeline
            self.event_bus.emit("network_event", {
                "type":        "network_event",
                "source":      ev.get("source", ""),
                "destination": ev.get("destination", ""),
                "event_type":  ev.get("event_type", "NetworkPacket"),
                "payload":     ev.get("payload", {}),
                "metadata":    metadata,  # ✓ FIX: Preserve original metadata
                "timestamp":   datetime.now().isoformat(),
                "live":        True,
            })
        except Exception:
            self._stats["packets_dropped"] += 1

    # Outbound: send refined decisions back to IDS
    def send_decision(self, decision: dict):
        """
        decision = {
          "source": "1.2.3.4",
          "decision": "Block"|"Alert"|"Ignore"|...,
          "confidence": 0.92,
          "attack_class": "DoS/DDoS",
          "explanation": "...",
          "timestamp": "..."
        }
        """
        try:
            if not self._dec_sock:
                self._dec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._dec_sock.connect(("127.0.0.1", IDS_DECISION_PORT))
            payload = json.dumps(decision) + "\n"
            self._dec_sock.sendall(payload.encode())
        except Exception:
            self._dec_sock = None   # reconnect next time
        finally:
            self._stats["alerts_sent"] += 1  # count regardless of socket success

    # Synthetic fallback when IDS not connected
    def _direct_capture(self):
        """
        Direct packet capture via scapy on self.interface + self.bpf_filter.
        Windows: requires Npcap (https://npcap.com) installed with WinPcap compat mode.
        Linux:   requires root/CAP_NET_RAW.
        """
        try:
            from scapy.all import sniff, IP, TCP, UDP, Raw, conf as scapy_conf
        except ImportError:
            if self.on_status:
                self.on_status("scapy not installed — pip install scapy — using synthetic")
            self._synthetic_fallback()
            return

        # Windows: check Npcap is available
        if sys.platform == "win32":
            try:
                from scapy.arch.windows import get_windows_if_list
                ifaces = get_windows_if_list()
                if not ifaces:
                    raise RuntimeError("No Npcap interfaces found")
            except Exception as e:
                if self.on_status:
                    self.on_status(
                        f"Npcap not found ({e}). "
                        "Install from https://npcap.com — using synthetic"
                    )
                self._synthetic_fallback()
                return

        # Use scapy_name (NPF GUID on Windows, friendly name on Linux)
        capture_iface = self.scapy_name or self.interface or None

        self.connected = True
        self._stats["interface"] = self.interface or capture_iface or "auto"
        self._stats["filter"]    = self.bpf_filter or "all"
        if self.on_status:
            self.on_status(
                f"Capturing on '{self.interface}'  "
                f"filter: \"{self.bpf_filter or 'all'}\""
            )

        import math as _math
        from collections import Counter

        def _pkt_handler(pkt):
            if not self.running:
                return
            if not pkt.haslayer(IP):
                return
            ip = pkt[IP]

            # Always update stats
            self._stats["packets_received"] += 1
            self._stats["bytes_total"]      += len(pkt)
            self._stats["last_src"]          = ip.src
            self._stats["last_dst"]          = ip.dst
            self._stats["last_proto"]        = str(ip.proto)

            payload_bytes = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            entropy = 0.0
            if payload_bytes:
                counts = Counter(payload_bytes)
                total  = len(payload_bytes)
                entropy = -sum(
                    (c / total) * _math.log2(c / total)
                    for c in counts.values()
                ) / 8.0

            flags = port_src = port_dst = 0
            if pkt.haslayer(TCP):
                flags    = int(pkt[TCP].flags)
                port_src = pkt[TCP].sport
                port_dst = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                port_src = pkt[UDP].sport
                port_dst = pkt[UDP].dport

            self._stats["last_entropy"] = round(entropy, 4)
            self.event_bus.emit("network_event", {
                "type":        "network_event",
                "source":      ip.src,
                "destination": ip.dst,
                "event_type":  "NetworkPacket",
                "payload": {
                    "bytes_in":  len(pkt),
                    "bytes_out": 0,
                    "port_src":  port_src,
                    "port_dst":  port_dst,
                    "protocol":  ip.proto,
                    "flags":     flags,
                    "entropy":   round(entropy, 4),
                    "rate_hz":   float(len(pkt)),
                },
                "metadata":    {"interface": self.interface},
                "timestamp":   datetime.now().isoformat(),
                "live":        True,
            })

        try:
            sniff(
                iface       = capture_iface,
                filter      = self.bpf_filter or None,
                prn         = _pkt_handler,
                store       = False,
                stop_filter = lambda _: not self.running,
            )
        except PermissionError:
            self.connected = False
            msg = ("Permission denied — run as Administrator (right-click terminal → Run as administrator)")
            print(f"[bridge] {msg}", flush=True)
            if self.on_status:
                self.on_status(msg)
            self._synthetic_fallback()
        except Exception as e:
            self.connected = False
            msg = f"Capture error: {type(e).__name__}: {e} — falling back to synthetic"
            print(f"[bridge] {msg}", flush=True)
            if self.on_status:
                self.on_status(msg)
            self._synthetic_fallback()

    # Synthetic fallback
    def _synthetic_fallback(self):
        """
        Generates realistic network events from real threat patterns (CSV-based).
        Falls back to random profiles if CSV patterns not available.
        """
        # Try to load real threat patterns from CSV
        synthetic_patterns = self._load_synthetic_patterns()
        
        # Fallback to random profiles if no patterns loaded
        ATTACK_PROFILES = [
            # (label, bytes_in, port_dst, entropy, rate_hz, flags, proto)
            ("normal",      200,  443, 0.3, 50,   0x18, 6),
            ("normal",      150,   80, 0.2, 30,   0x18, 6),
            ("DoS",        1400,   80, 0.1, 9000, 0x02, 6),
            ("PortScan",     60,    0, 0.0, 500,  0x02, 6),
            ("Exfiltration",900,  443, 0.95, 200, 0x18, 6),
            ("BruteForce",  120,   22, 0.4, 300,  0x02, 6),
            ("C2Beacon",    300, 8080, 0.85, 10,  0x18, 6),
            ("DNSTunnel",   512,   53, 0.92, 80,  0x00, 17),
        ]
        SOURCES = [
            "192.168.1.10", "10.0.0.5", "172.16.0.3",
            "203.0.113.42", "198.51.100.7", "192.0.2.99"
        ]
        
        frame = 0
        while self.running:
            if self.connected:
                time.sleep(0.1)
                continue

            frame += 1
            
            # Use real patterns if available, otherwise random
            if synthetic_patterns:
                pattern = random.choice(synthetic_patterns)
                label = pattern.get("threat_type", "unknown")
                b_in = pattern.get("bytes", 500)
                port = 443 if pattern.get("protocol") == "HTTPS" else 80
                entropy = 0.7  # Real attacks have higher entropy
                rate = 100
                flags = 0x18
                proto = 6
                src = pattern.get("source", random.choice(SOURCES))
                dst = pattern.get("destination", f"10.0.0.{random.randint(1, 50)}")
            else:
                profile = random.choices(
                    ATTACK_PROFILES,
                    weights=[40, 30, 5, 5, 5, 5, 5, 5]
                )[0]
                label, b_in, port, entropy, rate, flags, proto = profile
                src = random.choice(SOURCES)
                dst = f"10.0.0.{random.randint(1, 50)}"

            noise = lambda v, pct=0.2: v * (1 + random.uniform(-pct, pct))

            ev = {
                "type":        "network_event",
                "source":      src,
                "destination": dst,
                "event_type":  "NetworkPacket",
                "payload": {
                    "bytes_in":  int(noise(b_in)),
                    "bytes_out": int(noise(b_in * 0.3)),
                    "port_src":  random.randint(1024, 65535),
                    "port_dst":  port if port else random.randint(1, 1024),
                    "protocol":  proto,
                    "flags":     flags,
                    "entropy":   round(min(1.0, noise(entropy, 0.1)), 4),
                    "rate_hz":   round(noise(rate), 2),
                },
                "metadata":    {"label": label, "synthetic": True},
                "timestamp":   datetime.now().isoformat(),
                "live":        False,
            }
            self._stats["packets_received"] += 1
            self._stats["bytes_total"]      += ev["payload"]["bytes_in"]
            self._stats["last_src"]          = ev["source"]
            self._stats["last_dst"]          = ev["destination"]
            self._stats["last_proto"]        = str(proto)
            self._stats["last_entropy"]      = ev["payload"]["entropy"]
            self._stats["interface"]         = "synthetic"

            self.event_bus.emit("network_event", ev)
            time.sleep(random.uniform(0.8, 1.4))
    
    def _load_synthetic_patterns(self) -> list:
        """Load synthetic attack patterns from CSV-generated file."""
        try:
            import json
            from pathlib import Path
            
            db_dir = Path(__file__).parent.parent / "database"
            synthetic_file = db_dir / "synthetic_from_csv.jsonl"
            
            if not synthetic_file.exists():
                return []
            
            patterns = []
            with open(synthetic_file, 'r') as f:
                for line in f:
                    try:
                        pattern = json.loads(line)
                        patterns.append(pattern)
                    except:
                        pass
            
            if patterns:
                print(f"[bridge] Loaded {len(patterns)} real threat patterns from CSV", flush=True)
            
            return patterns
        except Exception as e:
            print(f"[bridge] Could not load synthetic patterns: {e}", flush=True)
            return []
