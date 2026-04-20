"""
Remote Attack Sender — connects to a running IDS machine (run.py)
and streams attack events over TCP instead of a local event bus.

Used by run_attacker.py --remote <IDS_IP>
"""
import socket
import json
import threading
import time

ATTACKER_PORT = 9875
RECONNECT_DELAY = 3.0


class RemoteAttackSender:
    """
    Drop-in replacement for EventBus.emit("network_event", ev).
    Serializes events as newline-delimited JSON and sends to IDS machine.
    Also maintains a local event bus for the mutator feedback loop
    (decoder_output events come back over a second connection on port 9878).
    """

    def __init__(self, ids_host: str, port: int = ATTACKER_PORT,
                 feedback_port: int = 9878, on_status=None):
        self.ids_host      = ids_host
        self.port          = port
        self.feedback_port = feedback_port
        self.on_status     = on_status or (lambda m: None)
        self._sock         = None
        self._lock         = threading.Lock()
        self._running      = False
        self._connected    = False
        self._send_queue:  list = []
        self._callbacks:   dict = {}   # event_type → [cb]
        self._stats        = {"sent": 0, "dropped": 0, "reconnects": 0}

    def start(self):
        self._running = True
        threading.Thread(target=self._connect_loop, daemon=True).start()

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    @property
    def connected(self) -> bool:
        return self._connected

    # EventBus-compatible interface
    def emit(self, event_type: str, data: dict):
        """Called by AttackEngine._fire() — sends event to IDS machine."""
        if event_type != "network_event":
            return
        line = json.dumps(data) + "\n"
        with self._lock:
            if self._connected and self._sock:
                try:
                    self._sock.sendall(line.encode("utf-8"))
                    self._stats["sent"] += 1
                    return
                except Exception:
                    self._connected = False
                    self._sock = None
            self._stats["dropped"] += 1

    def subscribe(self, event_type: str, callback):
        """
        AttackEngine subscribes to 'decoder_output' for feedback.
        We store the callback and fire it when feedback arrives.
        """
        if event_type not in self._callbacks:
            self._callbacks[event_type] = []
        self._callbacks[event_type].append(callback)

    def _fire_local(self, event_type: str, data: dict):
        for cb in self._callbacks.get(event_type, []):
            try:
                cb(data)
            except Exception:
                pass

    # Connection loop
    def _connect_loop(self):
        while self._running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((self.ids_host, self.port))
                sock.settimeout(None)
                with self._lock:
                    self._sock      = sock
                    self._connected = True
                self.on_status(
                    f"[remote-sender] connected to IDS at {self.ids_host}:{self.port}")

                # Start feedback listener for decoder decisions
                threading.Thread(
                    target=self._feedback_loop, daemon=True).start()

                # Keep alive — wait until disconnected
                while self._running and self._connected:
                    time.sleep(0.5)

            except Exception as e:
                self._connected = False
                self._stats["reconnects"] += 1
                self.on_status(
                    f"[remote-sender] cannot reach IDS at {self.ids_host}:{self.port} "
                    f"— retrying in {RECONNECT_DELAY}s ({e})")
                time.sleep(RECONNECT_DELAY)

    # Feedback loop — receives decoder decisions from IDS
    def _feedback_loop(self):
        """
        IDS machine sends back decoder_output JSON on port 9878
        so the mutator can score fitness remotely.
        """
        try:
            fb_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            fb_sock.settimeout(5.0)
            fb_sock.connect((self.ids_host, self.feedback_port))
            fb_sock.settimeout(None)
            self.on_status(
                f"[remote-sender] feedback channel open on port {self.feedback_port}")
            buf = b""
            feedback_count = [0]  # ✓ FIX: Track feedback received
            while self._running and self._connected:
                try:
                    chunk = fb_sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line.decode("utf-8"))
                            feedback_count[0] += 1
                            # ✓ DEBUG: Check if metadata has atk_tag
                            metadata = ev.get("metadata", {})
                            if not metadata or "atk_tag" not in metadata:
                                self.on_status(f"[remote-sender] WARNING: received event without atk_tag in metadata: {metadata}")
                            # ✓ FIX: Log feedback reception
                            if feedback_count[0] % 50 == 0:
                                self.on_status(f"[remote-sender] received {feedback_count[0]} feedback events")
                            self._fire_local("decoder_output", ev)
                        except json.JSONDecodeError as e:
                            self.on_status(f"[remote-sender] JSON decode error: {e}")
                except socket.timeout:
                    continue
        except Exception as e:
            self.on_status(f"[remote-sender] feedback channel closed: {e}")

    @property
    def stats(self) -> dict:
        with self._lock:
            return {**self._stats, "connected": self._connected}
