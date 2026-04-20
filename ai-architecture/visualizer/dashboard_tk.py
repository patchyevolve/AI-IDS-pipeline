"""
Tkinter fallback dashboard — works on Python 3.14 without pygame.
Same live data, simpler visuals. Auto-used when pygame is not installed.
"""
import tkinter as tk
from tkinter import ttk
import threading
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

REFRESH_MS = 300   # UI refresh interval

# Decision colors (tkinter hex)
DEC_COLORS = {
    "Ignore":   "#505564",
    "Log":      "#00c8ff",
    "Alert":    "#ffc800",
    "Block":    "#ff5050",
    "Escalate": "#ff28c8",
}
C_CNN  = "#00c8ff"
C_RNN  = "#00ff8c"
C_DEC  = "#ffc800"
C_DB   = "#c850ff"
C_BG   = "#0a0c14"
C_PANEL= "#121626"
C_DIM  = "#505564"
C_WHITE= "#e6e6e6"

def _bar(val: float, width: int = 24) -> str:
    filled = int(val * width)
    return "█" * filled + "░" * (width - filled)


class LiveDashboard:
    def __init__(self, root: tk.Tk, state: dict, lock):
        self.root  = root
        self.state = state
        self.lock  = lock
        root.title("AI-IDS — Live Architecture Dashboard")
        root.configure(bg=C_BG)
        root.geometry("1400x820")
        root.resizable(True, True)
        self._build()
        self._refresh()

    def _label(self, parent, text="", color=C_WHITE, font=("Consolas", 11),
               anchor="w", **kw):
        l = tk.Label(parent, text=text, fg=color, bg=C_PANEL,
                     font=font, anchor=anchor, **kw)
        return l

    def _frame(self, parent, title, color, col, row, colspan=1):
        outer = tk.Frame(parent, bg=color, padx=1, pady=1)
        outer.grid(row=row, column=col, columnspan=colspan,
                   padx=6, pady=6, sticky="nsew")
        inner = tk.Frame(outer, bg=C_PANEL, padx=8, pady=6)
        inner.pack(fill="both", expand=True)
        tk.Label(inner, text=title, fg=color, bg=C_PANEL,
                 font=("Consolas", 13, "bold"), anchor="w").pack(fill="x")
        tk.Frame(inner, bg=color, height=1).pack(fill="x", pady=3)
        return inner

    def _build(self):
        root = self.root
        root.columnconfigure(0, weight=1)
        root.columnconfigure(1, weight=1)
        root.columnconfigure(2, weight=1)
        root.columnconfigure(3, weight=1)
        root.rowconfigure(0, weight=0)
        root.rowconfigure(1, weight=2)
        root.rowconfigure(2, weight=1)
        root.rowconfigure(3, weight=1)

        # Title
        tk.Label(root, text="◈  IDS CAPTURE → CNN → RNN → HYBRID DECODER → REFINED DB → IDS",
                 fg=C_WHITE, bg=C_BG, font=("Consolas", 14, "bold")).grid(
                 row=0, column=0, columnspan=4, pady=8)

        # CNN panel
        cnn_f = self._frame(root, "🔷  CNN ENGINE", C_CNN, col=0, row=1)
        self._cnn = {}
        for key in ["Frame", "Layer", "Shape", "Act", "Act bar", "Src IP"]:
            row_f = tk.Frame(cnn_f, bg=C_PANEL)
            row_f.pack(fill="x", pady=1)
            tk.Label(row_f, text=f"{key:<10}", fg=C_DIM, bg=C_PANEL,
                     font=("Consolas", 11), width=10, anchor="w").pack(side="left")
            v = tk.Label(row_f, text="—", fg=C_CNN, bg=C_PANEL,
                         font=("Consolas", 11), anchor="w")
            v.pack(side="left", fill="x", expand=True)
            self._cnn[key] = v
        # Activation history (text sparkline)
        tk.Label(cnn_f, text="history", fg=C_DIM, bg=C_PANEL,
                 font=("Consolas", 10)).pack(anchor="w")
        self._cnn_hist = tk.Label(cnn_f, text="", fg=C_CNN, bg=C_PANEL,
                                  font=("Consolas", 9), anchor="w", wraplength=300)
        self._cnn_hist.pack(fill="x")

        # RNN panel
        rnn_f = self._frame(root, "🔶  RNN ENGINE", C_RNN, col=1, row=1)
        self._rnn = {}
        for key in ["Seq Len", "Forget", "Input", "Output", "Cell E", "Trend"]:
            row_f = tk.Frame(rnn_f, bg=C_PANEL)
            row_f.pack(fill="x", pady=1)
            tk.Label(row_f, text=f"{key:<10}", fg=C_DIM, bg=C_PANEL,
                     font=("Consolas", 11), width=10, anchor="w").pack(side="left")
            v = tk.Label(row_f, text="—", fg=C_RNN, bg=C_PANEL,
                         font=("Consolas", 11), anchor="w")
            v.pack(side="left", fill="x", expand=True)
            self._rnn[key] = v
        tk.Label(rnn_f, text="gate wave", fg=C_DIM, bg=C_PANEL,
                 font=("Consolas", 10)).pack(anchor="w")
        self._rnn_wave = tk.Label(rnn_f, text="", fg=C_RNN, bg=C_PANEL,
                                  font=("Consolas", 9), anchor="w", wraplength=300)
        self._rnn_wave.pack(fill="x")

        # Decoder panel
        self._dec_frame_outer = tk.Frame(root, bg=C_DEC, padx=1, pady=1)
        self._dec_frame_outer.grid(row=1, column=2, padx=6, pady=6, sticky="nsew")
        dec_inner = tk.Frame(self._dec_frame_outer, bg=C_PANEL, padx=8, pady=6)
        dec_inner.pack(fill="both", expand=True)
        tk.Label(dec_inner, text="🔮  HYBRID DECODER", fg=C_DEC, bg=C_PANEL,
                 font=("Consolas", 13, "bold"), anchor="w").pack(fill="x")
        tk.Frame(dec_inner, bg=C_DEC, height=1).pack(fill="x", pady=3)

        self._dec_decision = tk.Label(dec_inner, text="IGNORE", fg=C_DEC, bg=C_PANEL,
                                      font=("Consolas", 28, "bold"))
        self._dec_decision.pack(pady=4)
        self._dec_attack = tk.Label(dec_inner, text="—", fg=C_WHITE, bg=C_PANEL,
                                    font=("Consolas", 11))
        self._dec_attack.pack()
        self._dec = {}
        for key in ["Source", "Confidence", "Attention", "DB Memory", "DB Hits"]:
            row_f = tk.Frame(dec_inner, bg=C_PANEL)
            row_f.pack(fill="x", pady=1)
            tk.Label(row_f, text=f"{key:<12}", fg=C_DIM, bg=C_PANEL,
                     font=("Consolas", 11), width=12, anchor="w").pack(side="left")
            v = tk.Label(row_f, text="—", fg=C_DEC, bg=C_PANEL,
                         font=("Consolas", 11), anchor="w")
            v.pack(side="left", fill="x", expand=True)
            self._dec[key] = v
        # Prob bars
        tk.Label(dec_inner, text="class probabilities", fg=C_DIM, bg=C_PANEL,
                 font=("Consolas", 10)).pack(anchor="w", pady=(6, 0))
        self._dec_probs = tk.Label(dec_inner, text="", fg=C_DEC, bg=C_PANEL,
                                   font=("Consolas", 9), anchor="w", justify="left")
        self._dec_probs.pack(fill="x")

        # DB panel
        db_f = self._frame(root, "🗄  REFINED DB → IDS", C_DB, col=3, row=1)
        self._db_conn = tk.Label(db_f, text="● SYNTHETIC", fg=C_DIM, bg=C_PANEL,
                                 font=("Consolas", 11, "bold"))
        self._db_conn.pack(anchor="w")
        self._db = {}
        for key in ["DB Size", "Threats", "Sigs→IDS", "Top Class",
                    "Avg Conf", "Pkts", "Last Src", "Entropy", "Alerts→IDS"]:
            row_f = tk.Frame(db_f, bg=C_PANEL)
            row_f.pack(fill="x", pady=1)
            tk.Label(row_f, text=f"{key:<12}", fg=C_DIM, bg=C_PANEL,
                     font=("Consolas", 11), width=12, anchor="w").pack(side="left")
            v = tk.Label(row_f, text="—", fg=C_DB, bg=C_PANEL,
                         font=("Consolas", 11), anchor="w")
            v.pack(side="left", fill="x", expand=True)
            self._db[key] = v
        tk.Label(db_f, text="conf history", fg=C_DIM, bg=C_PANEL,
                 font=("Consolas", 10)).pack(anchor="w", pady=(6, 0))
        self._db_hist = tk.Label(db_f, text="", fg=C_DB, bg=C_PANEL,
                                 font=("Consolas", 9), anchor="w", wraplength=300)
        self._db_hist.pack(fill="x")

        # Event log
        log_outer = tk.Frame(root, bg=C_DIM, padx=1, pady=1)
        log_outer.grid(row=2, column=0, columnspan=4, padx=6, pady=4, sticky="nsew")
        log_inner = tk.Frame(log_outer, bg=C_PANEL, padx=8, pady=4)
        log_inner.pack(fill="both", expand=True)
        tk.Label(log_inner, text="📡  LIVE EVENT STREAM", fg=C_WHITE, bg=C_PANEL,
                 font=("Consolas", 12, "bold")).pack(anchor="w")
        self._log_text = tk.Text(log_inner, height=6, bg=C_BG, fg=C_WHITE,
                                 font=("Consolas", 10), state="disabled",
                                 relief="flat", wrap="none")
        self._log_text.pack(fill="both", expand=True)
        self._log_text.tag_config("CNN",  foreground=C_CNN)
        self._log_text.tag_config("RNN",  foreground=C_RNN)
        self._log_text.tag_config("DEC",  foreground=C_DEC)
        self._log_text.tag_config("DB",   foreground=C_DB)
        self._log_text.tag_config("IDS",  foreground=C_DB)

        # Stats bar
        stats_outer = tk.Frame(root, bg=C_DIM, padx=1, pady=1)
        stats_outer.grid(row=3, column=0, columnspan=4, padx=6, pady=4, sticky="nsew")
        stats_inner = tk.Frame(stats_outer, bg=C_PANEL, padx=8, pady=4)
        stats_inner.pack(fill="both", expand=True)
        tk.Label(stats_inner, text="📊  SYSTEM STATS", fg=C_WHITE, bg=C_PANEL,
                 font=("Consolas", 12, "bold")).pack(anchor="w")
        self._stats_label = tk.Label(stats_inner, text="", fg=C_DIM, bg=C_PANEL,
                                     font=("Consolas", 11), anchor="w", justify="left")
        self._stats_label.pack(fill="x")

    def _sparkline(self, data: list, width: int = 40) -> str:
        if not data:
            return ""
        BLOCKS = " ▁▂▃▄▅▆▇█"
        mn, mx = min(data), max(data)
        rng = mx - mn or 1
        recent = data[-width:]
        return "".join(BLOCKS[int((v - mn) / rng * 8)] for v in recent)

    def _refresh(self):
        with self.lock:
            s = {k: v for k, v in self.state.items()}

        # CNN
        self._cnn["Frame"].config(text=str(s.get("frame_id", 0)))
        self._cnn["Layer"].config(text=s.get("cnn_layer", "—"))
        self._cnn["Shape"].config(text=s.get("cnn_shape", "—"))
        act = s.get("cnn_activation", 0.0)
        self._cnn["Act"].config(text=f"{act:.4f}")
        self._cnn["Act bar"].config(text=_bar(act))
        self._cnn["Src IP"].config(text=s.get("ids_last_src", "—"))
        self._cnn_hist.config(text=self._sparkline(s.get("cnn_act_history", [])))

        # RNN
        self._rnn["Seq Len"].config(text=str(s.get("rnn_seq_len", 0)))
        self._rnn["Forget"].config(text=_bar(s.get("rnn_forget", 0.0), 20))
        self._rnn["Input"].config(text=_bar(s.get("rnn_input", 0.0), 20))
        self._rnn["Output"].config(text=_bar(s.get("rnn_output_g", 0.0), 20))
        self._rnn["Cell E"].config(text=f"{s.get('rnn_output_g', 0.0):.4f}")
        self._rnn["Trend"].config(text=f"{s.get('rnn_output_g', 0.0):.4f}")
        self._rnn_wave.config(text=self._sparkline(s.get("rnn_wave", [])))

        # Decoder — color by decision
        dec = s.get("decoder_decision", "Ignore")
        col = DEC_COLORS.get(dec, C_DEC)
        self._dec_frame_outer.config(bg=col)
        self._dec_decision.config(text=dec.upper(), fg=col)
        self._dec_attack.config(text=s.get("decoder_pred", "—"))
        self._dec["Source"].config(text=s.get("decoder_source", "—")[:22])
        self._dec["Confidence"].config(
            text=f"{s.get('decoder_conf', 0.0):.1%}  {_bar(s.get('decoder_conf', 0.0), 16)}")
        self._dec["Attention"].config(text=f"{s.get('decoder_attn', 0.0):.4f}")
        self._dec["DB Memory"].config(
            text="✓ ACTIVE" if s.get("decoder_mem") else "✗ NONE",
            fg=C_RNN if s.get("decoder_mem") else C_DIM)
        self._dec["DB Hits"].config(text=str(s.get("decoder_db_hits", 0)))
        probs = s.get("decoder_probs", {})
        prob_lines = "\n".join(
            f"{k:<22} {_bar(v, 14)} {v:.0%}"
            for k, v in sorted(probs.items(), key=lambda x: -x[1])
        )
        self._dec_probs.config(text=prob_lines)

        # DB
        ids_live = s.get("ids_connected", False)
        self._db_conn.config(
            text="● LIVE NETWORK" if ids_live else "● SYNTHETIC",
            fg=C_RNN if ids_live else C_DIM)
        self._db["DB Size"].config(text=str(s.get("db_size", 0)))
        self._db["Threats"].config(text=str(s.get("db_threat_count", 0)))
        self._db["Sigs→IDS"].config(text=str(s.get("db_sigs_exported", 0)))
        self._db["Top Class"].config(text=s.get("db_top_label", "—")[:18])
        self._db["Avg Conf"].config(
            text=f"{s.get('db_avg_conf', 0.0):.4f}  {_bar(s.get('db_avg_conf', 0.0), 12)}")
        self._db["Pkts"].config(text=str(s.get("ids_pkts", 0)))
        self._db["Last Src"].config(text=s.get("ids_last_src", "—"))
        self._db["Entropy"].config(text=f"{s.get('ids_last_entropy', 0.0):.4f}")
        self._db["Alerts→IDS"].config(text=str(s.get("ids_alerts_sent", 0)))
        self._db_hist.config(text=self._sparkline(s.get("db_history", [])))

        # Event log
        logs = s.get("flow_log", [])[-12:]
        self._log_text.config(state="normal")
        self._log_text.delete("1.0", "end")
        for entry in logs:
            tag_map = {"[CNN]": "CNN", "[RNN]": "RNN", "[DEC]": "DEC",
                       "[DB ]": "DB",  "[IDS]": "IDS"}
            tag = tag_map.get(entry.get("tag", ""), "")
            line = f"{entry.get('tag','')}  {entry.get('msg','')}\n"
            self._log_text.insert("end", line, tag)
        self._log_text.config(state="disabled")

        # Stats bar
        dec_col = DEC_COLORS.get(dec, C_DEC)
        stats_txt = (
            f"Frame={s.get('frame_id',0):>5}  |  "
            f"Interface={s.get('ids_interface','—'):<14}  |  "
            f"CNN act={s.get('cnn_activation',0.0):.4f}  |  "
            f"RNN seq={s.get('rnn_seq_len',0)}  |  "
            f"Decision={dec:<10}  |  "
            f"Attack={s.get('decoder_pred','—'):<28}  |  "
            f"Conf={s.get('decoder_conf',0.0):.1%}  |  "
            f"DB={s.get('db_size',0)}  |  "
            f"Sigs→IDS={s.get('db_sigs_exported',0)}"
        )
        self._stats_label.config(text=stats_txt, fg=dec_col)

        self.root.after(REFRESH_MS, self._refresh)


def main(bus=None, cnn=None, rnn=None, decoder=None, db=None, bridge=None):
    from event_bus import EventBus
    from cnn.cnn_engine import CNNEngine
    from rnn.rnn_engine import RNNEngine
    from decoder.decoder_engine import HybridDecoder
    from database.db_engine import DatabaseEngine
    from network.ids_bridge import IDSBridge
    import threading

    # Shared state + lock + callbacks (from dashboard, pygame already confirmed available)
    from visualizer.dashboard import (
        state, lock,
        on_cnn_layer, on_cnn_features, on_rnn_context,
        on_decoder_output, on_db_logged, on_db_retrieved, on_ids_export
    )

    standalone = bus is None
    if standalone:
        bus     = EventBus()
        cnn     = CNNEngine(bus)
        rnn     = RNNEngine(bus)
        decoder = HybridDecoder(bus)
        db      = DatabaseEngine(bus)
        bridge  = IDSBridge(bus)
        bridge.start()

    bus.subscribe("cnn_layer_output", on_cnn_layer)
    bus.subscribe("cnn_features",     on_cnn_features)
    bus.subscribe("rnn_context",      on_rnn_context)
    bus.subscribe("decoder_output",   on_decoder_output)
    bus.subscribe("db_logged",        on_db_logged)
    bus.subscribe("db_retrieved",     on_db_retrieved)
    bus.subscribe("ids_export",       on_ids_export)

    if standalone:
        import time as _time
        _counter = [0]
        def on_network_event(ev):
            _counter[0] += 1
            ev["frame_id"] = _counter[0]
            cnn_out = cnn.process_event(ev)
            rnn_out = rnn.process_features(cnn_out)
            db_mem  = db.retrieve_memory(cnn_out["feature_vector"],
                                         ev.get("source", ""), _counter[0])
            dec_out = decoder.decode(cnn_out, rnn_out, db_mem["retrieved"])
            dec_out["feature_vector"] = cnn_out["feature_vector"]
            dec_out["entropy"]  = cnn_out.get("entropy", 0.0)
            dec_out["rate_hz"]  = cnn_out.get("rate_hz",  0.0)
            dec_out["port_dst"] = cnn_out.get("port_dst", 0)
            dec_out["protocol"] = cnn_out.get("protocol", 0)
            dec_out["flags"]    = cnn_out.get("flags",    0)
            db.log_prediction(dec_out)
            stats = db.get_stats()
            with lock:
                state["db_top_label"]    = stats.get("top_label", "—") or "—"
                state["db_avg_conf"]     = stats.get("avg_confidence", 0.0)
                state["db_threat_count"] = stats.get("threat_count", 0)
        bus.subscribe("network_event", on_network_event)

    # Bridge stats polling
    def poll_bridge():
        while state["running"]:
            if bridge:
                st = bridge.stats
                with lock:
                    state["ids_connected"]    = bridge.connected
                    state["ids_interface"]    = st.get("interface", "—")
                    state["ids_pkts"]         = st.get("packets_received", 0)
                    state["ids_bytes"]        = st.get("bytes_total", 0)
                    state["ids_alerts_sent"]  = st.get("alerts_sent", 0)
                    state["ids_last_src"]     = st.get("last_src", "—")
                    state["ids_last_entropy"] = st.get("last_entropy", 0.0)
            _time.sleep(0.5)

    threading.Thread(target=poll_bridge, daemon=True).start()

    root = tk.Tk()
    root.protocol("WM_DELETE_WINDOW", lambda: (state.update({"running": False}), root.destroy()))
    LiveDashboard(root, state, lock)
    root.mainloop()


if __name__ == "__main__":
    main()
