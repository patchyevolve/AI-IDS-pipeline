"""
cpp_bridge.py — drop-in adapter between the existing Python pipeline
and the compiled C++ ids_pipeline extension.

Usage in run.py:
    from cpp_bridge import CppPipeline
    pipeline = CppPipeline(bus)
    bus.subscribe("network_event", pipeline.on_network_event)

The C++ IDS.ingest() call releases the GIL, so the EventBus worker
thread is free to receive new events while C++ processes the current one.
Decisions are emitted back onto the event bus as normal decoder_output
events so the dashboard and attacker work unchanged.
"""
from __future__ import annotations
import time
from datetime import datetime

try:
    import ids_pipeline as cpp
    CPP_AVAILABLE = True
except ImportError:
    CPP_AVAILABLE = False
    cpp = None  # type: ignore


DECISION_STR = {0: "Ignore", 1: "Log", 2: "Alert", 3: "Block", 4: "Escalate"}


class CppPipeline:
    """
    Wraps ids_pipeline.IDS and bridges it to the existing event bus.

    Replaces CNNEngine + RNNEngine + HybridDecoder + DatabaseEngine
    with a single C++ call per frame.  The Python DB engine is still
    used for the dashboard stats / signature export side-channel.
    """

    def __init__(self, event_bus, db=None, bridge=None,
                 cfg: "cpp.IDSConfig | None" = None):
        if not CPP_AVAILABLE:
            raise RuntimeError(
                "ids_pipeline C++ extension not found.\n"
                "Build it first:  python ai-architecture/cpp/build.py"
            )
        self.event_bus = event_bus
        self.db        = db        # optional Python DB for stats/export
        self.bridge    = bridge    # optional IDSBridge for send_decision
        self._ids      = cpp.IDS(cfg or cpp.IDSConfig())
        self._counter  = 0

        # Sync Python DB signatures to C++ Memory on startup
        if self.db:
            self._sync_signatures_to_cpp()

        # Wire C++ alert callbacks → event bus
        self._ids.on_alert(self._on_cpp_alert)
        self._ids.on_block(lambda src: None)      # handled via on_alert
        self._ids.on_escalate(self._on_cpp_alert)

    # ── Main entry point ──────────────────────────────────────────────────────
    def on_network_event(self, ev: dict):
        """Subscribe this to bus 'network_event' instead of the Python pipeline."""
        self._counter += 1
        ev["frame_id"] = self._counter

        # Convert Python dict → C++ Event (fast path via make_event)
        cpp_ev = cpp.make_event(ev)

        # ingest() releases the GIL — other Python threads run freely
        state = self._ids.ingest(cpp_ev)

        # Build a decoder_output-compatible dict for the dashboard
        d = state.to_dict()
        d.update({
            "type":        "decoder_output",
            "frame_id":    self._counter,
            "source":      ev.get("source", ""),
            "destination": ev.get("destination", ""),
            "decision":    "Ignore",   # overwritten by alert callback if triggered
            "confidence":  d["anomaly_score"],
            "attack_class":"none",
            "explanation": f"[cpp] score={d['anomaly_score']:.3f} drift={d['drift_score']:.3f}",
            "timestamp":   datetime.now().isoformat(),
            "metadata":    ev.get("metadata", {}),
            "feature_vector": state.local.embedding,
            "entropy":     d["entropy"],
            "rate_hz":     ev.get("payload", {}).get("rate_hz", 0.0),
            "port_dst":    ev.get("payload", {}).get("port_dst", 0),
            "protocol":    ev.get("payload", {}).get("protocol", 0),
            "flags":       ev.get("payload", {}).get("flags", 0),
            "db_hits":     0,
            "corr_score":  0.0,
            "campaign_id": "",
        })

        self.event_bus.emit("decoder_output", d)

        # Update Python DB stats if available (non-blocking — DB has its own write thread)
        if self.db:
            self.db.log_prediction(d)

    # ── C++ alert callback ────────────────────────────────────────────────────
    def _on_cpp_alert(self, alert: "cpp.Alert"):
        """Called from C++ pipeline thread — GIL already re-acquired by binding."""
        decision = DECISION_STR.get(int(alert.decision), "Alert")
        ad = alert.to_dict()
        ad["type"]      = "decoder_output"
        ad["decision"]  = decision
        ad["timestamp"] = datetime.now().isoformat()

        self.event_bus.emit("decoder_output", ad)

        if self.bridge and decision in ("Alert", "Block", "Escalate"):
            self.bridge.send_decision({
                "source":       alert.source,
                "decision":     decision,
                "confidence":   alert.confidence,
                "attack_class": alert.attack_class,
                "explanation":  alert.explanation,
                "timestamp":    ad["timestamp"],
            })

    # ── Stats passthrough ─────────────────────────────────────────────────────
    def metrics(self) -> dict:
        return self._ids.metrics()

    def latency_stats(self) -> dict:
        return self._ids.latency_stats()

    def health(self) -> dict:
        return self._ids.health()

    def memory_size(self) -> int:
        return self._ids.memory_size()

    def save_state(self, path: str) -> bool:
        return self._ids.save_state(path)

    def load_state(self, path: str) -> bool:
        return self._ids.load_state(path)
