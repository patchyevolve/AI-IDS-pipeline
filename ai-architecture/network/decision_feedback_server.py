"""
Decision Feedback Server — listens on port 9878 for remote attacker
feedback connections, then streams decoder_output events back to them
so the remote mutator can score fitness.
"""
import socket
import threading
import json

FEEDBACK_PORT = 9878


class DecisionFeedbackServer:
    def __init__(self, event_bus, port: int = FEEDBACK_PORT, on_status=None):
        self.event_bus = event_bus
        self.port      = port
        self.on_status = on_status or (lambda m: None)
        self._clients: list = []   # list of connected sockets
        self._lock     = threading.Lock()
        self._running  = False

        # Subscribe to decoder output — broadcast to all remote attackers
        self.event_bus.subscribe("decoder_output", self._on_decision)

    def start(self):
        self._running = True
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self.on_status(f"[feedback-server] listening on 0.0.0.0:{self.port}")

    def stop(self):
        self._running = False

    def _accept_loop(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", self.port))
            srv.listen(8)
            srv.settimeout(1.0)
            while self._running:
                try:
                    conn, addr = srv.accept()
                    self.on_status(
                        f"[feedback-server] attacker feedback connected from {addr[0]}")
                    with self._lock:
                        self._clients.append(conn)
                except socket.timeout:
                    continue
        except Exception as e:
            self.on_status(f"[feedback-server] error: {e}")
        finally:
            srv.close()

    def _on_decision(self, data: dict):
        """Broadcast decoder decision to all connected remote attackers."""
        # ✓ FIX: Include metadata with atk_tag so attacker can match feedback to attacks
        # REASON: Without atk_tag, attacker can't correlate decisions to sent attacks
        metadata = data.get("metadata", {})
        
        # Note: Benign traffic from bridge won't have atk_tag (expected)
        # Only attacker-generated events have atk_tag for feedback correlation
        
        line = (json.dumps({
            "frame_id":    data.get("frame_id"),
            "decision":    data.get("decision"),
            "confidence":  data.get("confidence"),
            "attack_class":data.get("attack_class"),
            "source":      data.get("source"),
            "timestamp":   data.get("timestamp"),
            "metadata":    metadata,  # ✓ CRITICAL: Include metadata with atk_tag
        }) + "\n").encode("utf-8")

        dead = []
        with self._lock:
            for conn in self._clients:
                try:
                    conn.sendall(line)
                except Exception:
                    dead.append(conn)
            for d in dead:
                self._clients.remove(d)
                try:
                    d.close()
                except Exception:
                    pass
