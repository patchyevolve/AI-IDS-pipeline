"""
Remote Attack Listener — TCP server that receives attack events from a
remote attacker machine and injects them into the local IDS pipeline.

Protocol: newline-delimited JSON, one network_event per line.
Port: 9875 (ATTACKER_PORT)

The remote attacker (run_attacker.py --remote <IDS_IP>) connects here,
sends events, and the IDS pipeline processes them exactly like live
or synthetic traffic — CNN → RNN → Decoder → DB → Dashboard.
"""
import socket
import threading
import json
import time
from datetime import datetime

ATTACKER_PORT = 9875
BUFFER_SIZE   = 65536


class RemoteAttackListener:
    """
    Listens on 0.0.0.0:9875 for incoming attacker connections.
    Each connected attacker gets its own reader thread.
    Events are emitted onto the shared event_bus as "network_event".
    """

    def __init__(self, event_bus, port: int = ATTACKER_PORT, on_status=None):
        self.event_bus  = event_bus
        self.port       = port
        self.on_status  = on_status or (lambda m: None)
        self._server    = None
        self._running   = False
        self._clients:  list = []
        self._lock      = threading.Lock()
        self._stats     = {
            "connected_attackers": 0,
            "events_received":     0,
            "last_attacker_ip":    "—",
        }

    def start(self):
        self._running = True
        self._server  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._server.bind(("0.0.0.0", self.port))
            self._server.listen(8)
            self._server.settimeout(1.0)
            t = threading.Thread(target=self._accept_loop, daemon=True)
            t.start()
            self.on_status(f"[remote-listener] listening on 0.0.0.0:{self.port}")
        except OSError as e:
            self.on_status(f"[remote-listener] bind failed: {e}")

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass

    @property
    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    # Accept loop
    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server.accept()
                ip = addr[0]
                self.on_status(f"[remote-listener] attacker connected from {ip}")
                with self._lock:
                    self._stats["connected_attackers"] += 1
                    self._stats["last_attacker_ip"]     = ip
                t = threading.Thread(
                    target=self._client_reader,
                    args=(conn, ip),
                    daemon=True,
                )
                t.start()
                with self._lock:
                    self._clients.append(t)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    self.on_status(f"[remote-listener] accept error: {e}")

    # Per-client reader
    def _client_reader(self, conn: socket.socket, ip: str):
        buf = b""
        try:
            conn.settimeout(5.0)
            while self._running:
                try:
                    chunk = conn.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    buf += chunk
                    # Process all complete newline-delimited JSON lines
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line.decode("utf-8"))
                            # Tag as remote so dashboard can show origin
                            ev["remote_attacker_ip"] = ip
                            ev["live"] = False
                            if "timestamp" not in ev:
                                ev["timestamp"] = datetime.now().isoformat()
                            self.event_bus.emit("network_event", ev)
                            with self._lock:
                                self._stats["events_received"] += 1
                        except json.JSONDecodeError:
                            pass
                except socket.timeout:
                    continue
        except Exception as e:
            self.on_status(f"[remote-listener] client {ip} disconnected: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass
            with self._lock:
                self._stats["connected_attackers"] = max(
                    0, self._stats["connected_attackers"] - 1)
            self.on_status(f"[remote-listener] attacker {ip} disconnected")
