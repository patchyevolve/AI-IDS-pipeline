"""
Entry point — shows network setup screen, then launches live dashboard.
Run: python run.py
     python run.py --synthetic      (skip setup, use synthetic data)
     python run.py --reset          (force setup screen even if config saved)
Requires: pip install pygame psutil scapy
"""
import sys
import os
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))

# Auto-elevate on Windows for live capture
def _is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return True  # non-Windows or can't check — assume OK

def _relaunch_as_admin():
    import ctypes
    script = os.path.abspath(__file__)
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    # ShellExecute with 'runas' triggers the UAC prompt
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}" {params}', None, 1
    )
    if ret <= 32:
        print("[run.py] UAC elevation failed or was cancelled.")
    sys.exit(0)

if sys.platform == "win32" and "--synthetic" not in sys.argv and not _is_admin():
    print("[run.py] Live capture needs admin rights — requesting elevation...")
    _relaunch_as_admin()

from event_bus import EventBus
from cnn.cnn_engine import CNNEngine
from rnn.rnn_engine import RNNEngine
from decoder.decoder_engine import HybridDecoder
from decoder.mutation_predictor import MutationAwareDecoder
from database.db_engine import DatabaseEngine
from network.ids_bridge import IDSBridge


def _attack_session_report(attacker, db):
    """
    Called when --attack session ends.
    Prints a summary, saves JSON report, and force-writes evaded
    profiles into the DB so the IDS is aware of them next run.
    """
    import json
    from datetime import datetime
    from database.db_engine import ThreatRecord

    REPORT_PATH = os.path.join(os.path.dirname(__file__),
                               "attacker", "session_report.json")

    st       = attacker.stats
    outcomes = attacker.recent_outcomes(500)
    pop      = attacker.population_stats()

    # Tally by profile
    by_profile: dict = {}
    for o in outcomes:
        pn = o.get("profile", "unknown")
        if pn not in by_profile:
            by_profile[pn] = {"sent": 0, "blocked": 0, "evaded": 0,
                               "alerted": 0, "classes": {}}
        by_profile[pn]["sent"] += 1
        d = o.get("decision", "Ignore")
        if d in ("Block", "Escalate"):
            by_profile[pn]["blocked"] += 1
        elif d in ("Ignore", "Log"):
            by_profile[pn]["evaded"]  += 1
        else:
            by_profile[pn]["alerted"] += 1
        cls = o.get("attack_class", "none")
        by_profile[pn]["classes"][cls] = \
            by_profile[pn]["classes"].get(cls, 0) + 1

    evaded_profiles = sorted(
        [{"profile": k, **v,
          "evasion_rate": round(v["evaded"] / max(v["sent"], 1), 3)}
         for k, v in by_profile.items()],
        key=lambda x: -x["evasion_rate"],
    )
    top_evaders = [p for p in evaded_profiles if p["evasion_rate"] > 0.5]

    report = {
        "session_end":      datetime.now().isoformat(),
        "total_sent":       st["total_sent"],
        "total_blocked":    st["total_blocked"],
        "total_evaded":     st["total_evaded"],
        "total_alerted":    st["total_alerted"],
        "generations":      st["generation"],
        "evaded_profiles":  evaded_profiles,
        "top_evaders":      top_evaders,
        "population_final": pop,
        "db_stats":         db.get_stats(),
    }

    # Print to console
    sep = "─" * 60
    print(f"\n{sep}")
    print("  ATTACK SESSION REPORT")
    print(sep)
    print(f"  Total sent : {st['total_sent']}")
    print(f"  Blocked    : {st['total_blocked']}")
    print(f"  Evaded     : {st['total_evaded']}")
    print(f"  Alerted    : {st['total_alerted']}")
    print(f"  Generations: {st['generation']}")
    print(f"\n  PROFILES THAT EVADED IDS (evasion > 50%)")
    print(sep)
    for p in top_evaders:
        print(f"  {p['profile'][:35]:<35}  "
              f"evaded={p['evaded']}/{p['sent']}  "
              f"rate={p['evasion_rate']:.0%}  "
              f"classes={list(p['classes'].keys())}")
    if not top_evaders:
        print("  (none — IDS blocked everything)")

    # Save JSON
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report saved → {REPORT_PATH}")

    # Write evaders into DB so IDS learns
    # Use real feature vectors and attack classes from decoder output
    # so retrieval similarity matching is meaningful next run.
    def _to_class(name, decoder_class):
        # Prefer the actual decoder class if it's not "none"
        if decoder_class and decoder_class not in ("none", "Normal", "—"):
            return decoder_class
        n = name.lower()
        if "dos" in n or "flood" in n:   return "DoS/DDoS"
        if "scan" in n:                  return "PortScan"
        if "brute" in n:                 return "BruteForce/CredentialStuffing"
        if "c2" in n or "beacon" in n:   return "EncryptedC2/Exfiltration"
        if "exfil" in n:                 return "EncryptedC2/Exfiltration"
        if "dns" in n:                   return "DNSTunnel"
        if "lateral" in n or "smb" in n: return "LateralMovement/Persistence"
        return "UnknownHighSeverity"

    written = 0
    # Write one record per evaded outcome that has a real embedding
    for o in outcomes:
        d = o.get("decision", "Ignore")
        if d not in ("Ignore", "Log"):
            continue  # only evaded events
        fv = o.get("feature_vector", [])
        if not fv or len(fv) < 8:
            fv = [0.85] * 64  # fallback if not captured
        attack_class = _to_class(o.get("profile", ""), o.get("attack_class", "none"))
        rec = ThreatRecord(
            embedding    = fv,
            source       = o.get("target", "attacker-session"),
            destination  = "ids-awareness",
            attack_class = attack_class,
            decision     = "Block",          # teach IDS to block this next time
            confidence   = max(0.75, o.get("confidence", 0.75)),
            anomaly_trend= 0.80,
            entropy      = 0.90,
            rate_hz      = 500.0,
            port_dst     = 0,
            protocol     = 6,
            flags        = 0x02,
            explanation  = (f"[session-evader] profile={o.get('profile','')} "
                            f"class={attack_class} conf={o.get('confidence',0):.3f}"),
            timestamp    = o.get("timestamp", datetime.now().isoformat()),
            frame_id     = -1,
        )
        # Write directly to global store (force — bypasses write gate)
        db.memory.global_store.insert(rec)
        # Also write to ip scope keyed by attacker source
        db.memory.ip_store[rec.source].insert(rec)
        written += 1

    if written:
        count = db.export_ids_signatures()
        print(f"  {written} evaded events → IDS DB  |  {count} signatures exported")
    print(sep + "\n")


def run_pipeline(bus, cnn, rnn, decoder, db, bridge, validator=None):
    from visualizer.dashboard import state, lock

    # Background thread: export signatures + push DB stats to dashboard
    # Runs every 5s so it never blocks the pipeline hot path
    def _bg_tasks():
        while True:
            time.sleep(5.0)
            try:
                count = db.export_ids_signatures()
                stats = db.get_stats()
                with lock:
                    state["db_top_label"]    = stats.get("top_label", "—") or "—"
                    state["db_avg_conf"]     = stats.get("avg_confidence", 0.0)
                    state["db_threat_count"] = stats.get("threat_count", 0)
                    state["db_class_counts"] = stats.get("class_counts", {})
                    state["db_sigs_exported"] = count
                    
                    # Add validation metrics if available
                    if validator:
                        metrics = validator.get_metrics()
                        state["validation_accuracy"] = metrics.get("accuracy", 0)
                        state["validation_fpr"] = metrics.get("fpr", 0)
                        state["validation_fnr"] = metrics.get("fnr", 0)
                        state["validation_events"] = metrics.get("total_events", 0)
                
                bus.emit("ids_export", {
                    "type":      "ids_export",
                    "count":     count,
                    "timestamp": time.strftime("%H:%M:%S"),
                })
            except RuntimeError as e:
                if "cannot schedule new futures" in str(e):
                    break
            except Exception as e:
                print(f"[bg_tasks] {e}")
    threading.Thread(target=_bg_tasks, daemon=True, name="bg-tasks").start()

    def on_network_event(ev):
        fid  = ev.get("frame_id", 0)
        meta = ev.get("metadata", {})

        cnn_out = cnn.process_event(ev)
        rnn_out = rnn.process_features(cnn_out)
        db_mem  = db.retrieve_memory(
            embedding   = cnn_out["feature_vector"],
            source      = ev.get("source", ""),
            destination = ev.get("destination", ""),
            port_dst    = cnn_out.get("port_dst", 0),
            frame_id    = fid,
        )
        # ✓ Use mutation-aware decoder
        if isinstance(decoder, MutationAwareDecoder):
            dec_out = decoder.decode_with_mutation_awareness(cnn_out, rnn_out, db_mem["retrieved"], metadata=meta)
        else:
            dec_out = decoder.decode(cnn_out, rnn_out, db_mem["retrieved"], metadata=meta)
        dec_out["feature_vector"] = cnn_out["feature_vector"]
        dec_out["entropy"]        = cnn_out.get("entropy", 0.0)
        dec_out["rate_hz"]        = cnn_out.get("rate_hz",  0.0)
        dec_out["port_dst"]       = cnn_out.get("port_dst", 0)
        dec_out["protocol"]       = cnn_out.get("protocol", 0)
        dec_out["flags"]          = cnn_out.get("flags",    0)

        db.log_prediction(dec_out)

        # ✓ VALIDATE: Check if decision is correct (if validator enabled)
        if validator and meta.get("is_attack") is not None:
            validator.validate_and_correct({
                "is_attack": meta.get("is_attack", False),
                "decision": dec_out["decision"],
                "attack_class": meta.get("attack_class", "unknown"),
                "confidence": dec_out["confidence"],
                "feature_vector": cnn_out["feature_vector"],
                "source": ev.get("source", ""),
                "destination": ev.get("destination", ""),
                "port_dst": cnn_out.get("port_dst", 0),
                "protocol": cnn_out.get("protocol", 0),
                "flags": cnn_out.get("flags", 0),
                "rate_hz": cnn_out.get("rate_hz", 0.0),
                "timestamp": dec_out.get("timestamp", ""),
            })

        # Lightweight per-event state update (no file I/O, no stats recompute)
        with lock:
            state["decoder_db_hits"] = dec_out.get("db_hits", 0)
            state["db_size"]         = db.memory.total_size()

        if dec_out["decision"] in ("Alert", "Block", "Escalate"):
            bridge.send_decision({
                "source":       dec_out.get("source", ""),
                "decision":     dec_out["decision"],
                "confidence":   dec_out["confidence"],
                "attack_class": dec_out["attack_class"],
                "explanation":  dec_out["explanation"],
                "timestamp":    dec_out["timestamp"],
            })

    # Frame counter — runs on EventBus worker thread (already off capture thread)
    _counter = [0]
    def on_network_event_counted(ev):
        _counter[0] += 1
        ev["frame_id"] = _counter[0]
        on_network_event(ev)

    bus.subscribe("network_event", on_network_event_counted)

    # ✓ FIX 2: Start DecisionFeedbackServer for attacker feedback loop
    # REASON: Attacker needs to receive IDS decisions to learn and evolve
    # This server broadcasts decoder_output events to remote attackers on port 9878
    from network.decision_feedback_server import DecisionFeedbackServer
    feedback_server = DecisionFeedbackServer(bus, port=9878, on_status=lambda m: print(f"[feedback-server] {m}"))
    feedback_server.start()
    print("[run_pipeline] DecisionFeedbackServer started on port 9878")

def main():
    args = sys.argv[1:]
    force_synthetic = "--synthetic" in args
    force_reset     = "--reset"     in args
    enable_attacker = "--attack"    in args
    use_cpp         = "--cpp"       in args
    enable_validation = "--validate" in args

    if force_synthetic:
        cfg = {"interface": "", "filter": "", "mode": "synthetic"}
    else:
        # Show setup screen
        from network.setup_screen import run_setup
        cfg = run_setup(skip_if_saved=not force_reset)
        if cfg is None:
            print("Setup cancelled.")
            return

    print(f"\n  Interface : {cfg.get('interface') or '(none)'}")
    print(f"  Filter    : {cfg.get('filter')    or 'all traffic'}")
    print(f"  Mode      : {cfg.get('mode', 'synthetic')}\n")

    bus     = EventBus()
    cnn     = CNNEngine(bus)
    rnn     = RNNEngine(bus)
    db      = DatabaseEngine(bus)
    base_decoder = HybridDecoder(bus)
    decoder = MutationAwareDecoder(base_decoder, db)  # ✓ Wrap with mutation prediction
    bridge  = IDSBridge(
        event_bus  = bus,
        interface  = cfg.get("interface",  ""),
        scapy_name = cfg.get("scapy_name", ""),
        bpf_filter = cfg.get("filter",     ""),
        mode       = cfg.get("mode",       "synthetic"),
        on_status  = lambda msg: print(f"[bridge] {msg}"),
    )

    # Optional: Enable validation with auto-correction
    validator = None
    if enable_validation or enable_attacker:
        # ✓ Use TrainingValidator for real-time validation during training
        # It receives ground truth from attacker metadata (is_attack, attack_class)
        # It auto-corrects database when FN/FP detected
        from validation.training_validator import TrainingValidator
        validator = TrainingValidator(bus, db=db, output_dir="validation")
        print("[run.py] Validation enabled — tracking FP/FN and auto-correcting database")

    bridge.start()
    run_pipeline(bus, cnn, rnn, decoder, db, bridge, validator=validator)

    # Optional: replace Python pipeline with C++ backend
    if use_cpp:
        from cpp_bridge import CppPipeline, CPP_AVAILABLE
        if CPP_AVAILABLE:
            cpp_pipeline = CppPipeline(bus, db=db, bridge=bridge)
            # Unsubscribe the Python pipeline's network_event handler
            # and replace with the C++ one
            bus._subscribers["network_event"].clear()
            bus.subscribe("network_event", cpp_pipeline.on_network_event)
            print("[run.py] C++ pipeline active — Python CNN/RNN/Decoder bypassed")
        else:
            print("[run.py] --cpp requested but ids_pipeline.pyd not found — using Python pipeline")
            print("         Build it: python ai-architecture/cpp/build.py")

    # Remote attack listener — accepts events from attacker laptops
    from network.remote_attack_listener import RemoteAttackListener
    from network.decision_feedback_server import DecisionFeedbackServer
    remote_listener = RemoteAttackListener(
        bus, on_status=lambda m: print(m))
    remote_listener.start()
    feedback_server = DecisionFeedbackServer(
        bus, on_status=lambda m: print(m))
    feedback_server.start()

    # Optional attack engine
    attacker = None
    if enable_attacker:
        from attacker.attack_engine import AttackEngine
        attacker = AttackEngine(
            event_bus         = bus,
            synthetic_targets = force_synthetic,
            rate_limit        = 0.4,
            on_status         = lambda m: print(f"[attacker] {m}"),
        )
        attacker.start()
        attacker._duration_s = int(sys.argv[sys.argv.index("--duration") + 1]) if "--duration" in sys.argv else None
        attacker._start_time = time.time()
        print("[attacker] Attack engine running — profiles will evolve based on IDS decisions")

    # Auto-select dashboard: pygame if available, tkinter otherwise
    if "--cli" in sys.argv:
        from visualizer.fast_cli import main as dashboard_main
        print("[dashboard] using High-Performance CLI")
    else:
        try:
            import pygame  # noqa: F401
            from visualizer.dashboard import main as dashboard_main
            print("[dashboard] using pygame")
        except ImportError:
            from visualizer.dashboard_tk import main as dashboard_main
            print("[dashboard] pygame not available — using tkinter fallback")
            print("            To get the HD dashboard: pip install pygame")
            print("            (requires Python ≤ 3.13 until pygame adds 3.14 wheels)\n")

    dashboard_main(bus=bus, cnn=cnn, rnn=rnn, decoder=decoder, db=db,
                   bridge=bridge, attacker=attacker)

    # Post-session: attack report + IDS awareness update
    if attacker:
        attacker.stop()
        # Sleep to let final events flush before generating report
        time.sleep(1.0)
        _attack_session_report(attacker, db)
    
    # Print validation summary if enabled
    if validator:
        validator.print_summary()
        validator.tracker.save_report()
        
    import os
    os._exit(0)


if __name__ == "__main__":
    main()
