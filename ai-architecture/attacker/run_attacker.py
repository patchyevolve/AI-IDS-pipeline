"""
Standalone Attack CLI — runs independently of the IDS dashboard.

Usage:
    python attacker/run_attacker.py [options]

Options:
    --rate FLOAT        Min seconds between attacks (default 0.4)
    --duration INT      Run for N seconds then stop (default: run until Ctrl+C)
    --profile NAME      Only use this profile (default: all, evolved)
    --target IP         Force a specific target IP (default: auto-scan subnet)
    --synthetic         Skip ARP scan, use fake target IPs
    --no-evolve         Disable genetic mutation (fixed profiles only)
    --evolve-every INT  Evolve population every N attacks (default 30)
    --list-profiles     Print all base profiles and exit

Output:
    Console live feed + attacker/attack_log.jsonl
    End-of-session report printed to console + saved to attacker/session_report.json
"""
import sys
import os
import time
import signal
import argparse
import threading
import json
from datetime import datetime

# Allow running from repo root or from attacker/ folder
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

from event_bus import EventBus
from cnn.cnn_engine import CNNEngine
from rnn.rnn_engine import RNNEngine
from decoder.decoder_engine import HybridDecoder
from database.db_engine import DatabaseEngine
from attacker.attack_engine import AttackEngine

REPORT_FILE = os.path.join(_HERE, "session_report.json")


# Minimal pipeline (no bridge, no dashboard) with performance tracking
def _build_pipeline(bus):
    cnn     = CNNEngine(bus)
    rnn     = RNNEngine(bus)
    decoder = HybridDecoder(bus)
    db      = DatabaseEngine(bus)

    _counter = [0]
    
    # Performance Stats
    perf_stats = {
        "cnn_ms": [],
        "rnn_ms": [],
        "db_ms": [],
        "decoder_ms": [],
        "total_ms": []
    }

    def on_event(ev):
        _counter[0] += 1
        ev["frame_id"] = _counter[0]
        
        t0 = time.perf_counter()
        
        cnn_out = cnn.process_event(ev)
        t1 = time.perf_counter()
        
        rnn_out = rnn.process_features(cnn_out)
        t2 = time.perf_counter()
        
        db_mem  = db.retrieve_memory(
            embedding   = cnn_out["feature_vector"],
            source      = ev.get("source", ""),
            destination = ev.get("destination", ""),
            port_dst    = cnn_out.get("port_dst", 0),
            frame_id    = _counter[0],
        )
        t3 = time.perf_counter()
        
        dec_out = decoder.decode(cnn_out, rnn_out, db_mem["retrieved"])
        t4 = time.perf_counter()
        
        dec_out["feature_vector"] = cnn_out["feature_vector"]
        dec_out["entropy"]        = cnn_out.get("entropy", 0.0)
        dec_out["rate_hz"]        = cnn_out.get("rate_hz", 0.0)
        dec_out["port_dst"]       = cnn_out.get("port_dst", 0)
        dec_out["protocol"]       = cnn_out.get("protocol", 0)
        dec_out["flags"]          = cnn_out.get("flags", 0)
        
        # ✓ GROUND TRUTH: Attacker sends is_attack and attack_class in metadata
        # This allows validator to check if IDS decision was correct
        metadata = ev.get("metadata", {})
        dec_out["metadata"] = metadata
        
        db.log_prediction(dec_out)
        
        t5 = time.perf_counter()
        
        # Track ms
        perf_stats["cnn_ms"].append((t1 - t0) * 1000)
        perf_stats["rnn_ms"].append((t2 - t1) * 1000)
        perf_stats["db_ms"].append((t3 - t2) * 1000)
        perf_stats["decoder_ms"].append((t4 - t3) * 1000)
        perf_stats["total_ms"].append((t5 - t0) * 1000)

    bus.subscribe("network_event", on_event)
    return cnn, rnn, decoder, db, perf_stats


# Session report
def _build_report(attacker: AttackEngine, db, start_time: float) -> dict:
    elapsed   = round(time.time() - start_time, 1)
    st        = attacker.stats
    outcomes  = attacker.recent_outcomes(200)
    pop       = attacker.population_stats()

    # Group outcomes by profile
    by_profile: dict = {}
    for o in outcomes:
        pn = o.get("profile", "unknown")
        if pn not in by_profile:
            by_profile[pn] = {"sent": 0, "blocked": 0, "evaded": 0,
                               "alerted": 0, "attack_classes": {}}
        by_profile[pn]["sent"] += 1
        d = o.get("decision", "Ignore")
        if d in ("Block", "Escalate"):
            by_profile[pn]["blocked"] += 1
        elif d in ("Ignore", "Log"):
            by_profile[pn]["evaded"]  += 1
        else:
            by_profile[pn]["alerted"] += 1
        cls = o.get("attack_class", "none")
        by_profile[pn]["attack_classes"][cls] = \
            by_profile[pn]["attack_classes"].get(cls, 0) + 1

    # Evaded profiles sorted by evasion count
    evaded_profiles = sorted(
        [{"profile": k, **v, "evasion_rate": round(v["evaded"] / max(v["sent"], 1), 3)}
         for k, v in by_profile.items()],
        key=lambda x: -x["evasion_rate"],
    )

    db_stats = db.get_stats()

    report = {
        "session": {
            "start":        datetime.fromtimestamp(start_time).isoformat(),
            "end":          datetime.now().isoformat(),
            "duration_s":   elapsed,
            "total_sent":   st["total_sent"],
            "total_blocked":st["total_blocked"],
            "total_evaded": st["total_evaded"],
            "total_alerted":st["total_alerted"],
            "generations":  st["generation"],
        },
        "evaded_profiles":  evaded_profiles,
        "top_evaders": [p for p in evaded_profiles if p["evasion_rate"] > 0.5][:5],
        "population_final": pop,
        "db_stats":         db_stats,
    }
    return report


def _print_report(report: dict, perf_stats: dict = None, db=None):
    sep = "─" * 60
    s   = report["session"]
    print(f"\n{sep}")
    print("  ATTACK SESSION REPORT")
    print(sep)
    print(f"  Duration   : {s['duration_s']}s")
    print(f"  Total sent : {s['total_sent']}")
    print(f"  Blocked    : {s['total_blocked']}")
    print(f"  Evaded     : {s['total_evaded']}")
    print(f"  Alerted    : {s['total_alerted']}")
    print(f"  Generations: {s['generations']}")
    
    if perf_stats and len(perf_stats["total_ms"]) > 0:
        def avg(l): return sum(l)/len(l) if l else 0
        print(f"\n  PIPELINE PERFORMANCE STATS (Average)")
        print(sep)
        print(f"  CNN Engine (Gate+Atk+AE) : {avg(perf_stats['cnn_ms']):.3f} ms")
        print(f"  RNN Engine (SSM Context) : {avg(perf_stats['rnn_ms']):.3f} ms")
        print(f"  DB Engine (Graph Search) : {avg(perf_stats['db_ms']):.3f} ms")
        print(f"  Decoder (Meta-learning)  : {avg(perf_stats['decoder_ms']):.3f} ms")
        print(f"  Total End-to-End Latency : {avg(perf_stats['total_ms']):.3f} ms per event")
        
    print(f"\n  PROFILES THAT EVADED IDS (evasion > 50%)")
    print(sep)
    evaders = report.get("top_evaders", [])
    if not evaders:
        print("  (none — IDS blocked everything)")
    else:
        for ev in evaders:
            row = (f"{ev['profile']:<36} evaded={ev['evaded']}/{ev['sent']}  "
                   f"rate={ev['evasion_rate']*100:.0f}%  classes={ev.get('attack_classes', [])}")
            print(f"  {row}")

    print(f"\n  Report saved → {REPORT_FILE}")
    if db:
        print(f"  {s['total_evaded']} evaded events → IDS DB  |  {db.export_ids_signatures()} signatures exported")
    print(sep)
    
    # Force process exit to avoid zombie threads keeping it alive
    import os
    os._exit(0)


def _write_evaders_to_db(report: dict, db):
    """
    Force-write evaded attack profiles into the DB as high-confidence
    threat records so the IDS is aware of them next session.
    """
    from database.db_engine import ThreatRecord
    import time as _t

    written = 0
    for p in report["top_evaders"]:
        profile_name = p["profile"]
        # Synthesize a threat record for each evaded profile
        rec = ThreatRecord(
            id           = None,
            embedding    = [0.9] * 64,   # high-signal placeholder embedding
            source       = "attacker-session",
            destination  = "ids-awareness",
            attack_class = _profile_to_class(profile_name),
            decision     = "Block",       # force-write as if it should be blocked
            confidence   = 0.85,
            anomaly_trend= 0.80,
            entropy      = 0.90,
            rate_hz      = 500.0,
            port_dst     = 0,
            protocol     = 6,
            flags        = 0x02,
            explanation  = f"[session-report] evaded profile={profile_name} "
                           f"rate={p['evasion_rate']:.0%}",
            timestamp    = datetime.now().isoformat(),
            frame_id     = -1,
        )
        # Bypass write gate — force into global store
        db.memory.global_store.insert(rec)
        db.memory.ip_store["attacker-session"].insert(rec)
        written += 1

    if written:
        db.export_ids_signatures()
        print(f"[attacker] {written} evaded profiles written to IDS DB + signatures exported")


def _profile_to_class(name: str) -> str:
    name_l = name.lower()
    if "dos" in name_l or "flood" in name_l:    return "DoS/DDoS"
    if "scan" in name_l:                         return "PortScan"
    if "brute" in name_l:                        return "BruteForce/CredentialStuffing"
    if "c2" in name_l or "beacon" in name_l:     return "EncryptedC2/Exfiltration"
    if "exfil" in name_l:                        return "EncryptedC2/Exfiltration"
    if "dns" in name_l:                          return "DNSTunnel"
    if "lateral" in name_l or "smb" in name_l:  return "LateralMovement/Persistence"
    if "slow" in name_l:                         return "DoS/DDoS"
    return "UnknownHighSeverity"


# Live console feed
_DECISION_COLOR = {
    "Ignore":   "\033[90m",   # grey
    "Log":      "\033[36m",   # cyan
    "Alert":    "\033[33m",   # yellow
    "Block":    "\033[31m",   # red
    "Escalate": "\033[35m",   # magenta
}
_RESET = "\033[0m"

def _live_printer(attacker: AttackEngine, stop_event: threading.Event):
    last_sent = 0
    while not stop_event.is_set():
        time.sleep(1.0)
        st = attacker.stats
        sent = st["total_sent"]
        if sent == last_sent:
            continue
        last_sent = sent
        d     = st["last_decision"]
        col   = _DECISION_COLOR.get(d, "")
        evade_pct = (st["total_evaded"] / max(sent, 1)) * 100
        print(f"  [{sent:>5}] {col}{d:<9}{_RESET}  "
              f"profile={st['last_profile'][:25]:<25}  "
              f"target={st['last_target']:<16}  "
              f"evaded={evade_pct:.0f}%  gen={st['generation']}")


# Main
def main():
    from attacker.attack_profiles import BASE_PROFILES
    
    parser = argparse.ArgumentParser(
        description="Standalone IDS Attack Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--rate",         type=float, default=0.4,
                        help="Min seconds between attacks (default 0.4)")
    parser.add_argument("--duration",     type=int,   default=0,
                        help="Run for N seconds then stop (0 = until Ctrl+C)")
    parser.add_argument("--profile",      type=str,   default="",
                        help="Lock to one profile name")
    parser.add_argument("--target",       type=str,   default="",
                        help="Force a specific target IP")
    parser.add_argument("--synthetic",    action="store_true",
                        help="Use fake target IPs (no ARP scan)")
    parser.add_argument("--no-evolve",    action="store_true",
                        help="Disable genetic mutation")
    parser.add_argument("--evolve-every", type=int,   default=30,
                        help="Evolve every N attacks (default 30)")
    parser.add_argument("--real",         type=str,   default="",
                        help="Send REAL packets to this IP (captured by IDS live Wi-Fi). "
                             "Requires scapy + Npcap/root. No port 9875 needed.")
    parser.add_argument("--remote",       type=str,   default="",
                        help="IDS machine IP — stream events to that machine's pipeline")
    parser.add_argument("--remote-port",  type=int,   default=9875,
                        help="Remote listener port (default 9875)")
    parser.add_argument("--list-profiles",action="store_true",
                        help="Print base profiles and exit")
    args = parser.parse_args()

    if args.list_profiles:
        print("\nBase attack profiles:")
        for name, p in BASE_PROFILES.items():
            print(f"  {name:<30}  port={p['port_dst']}  "
                  f"rate={p['rate_hz']}  entropy={p['entropy']}")
        return

    remote_mode = bool(args.remote)
    real_mode   = bool(args.real)

    print("\n  IDS Attack Generator — Standalone")
    print(f"  rate={args.rate}s  "
          f"duration={'inf' if not args.duration else args.duration}s  "
          f"evolve={'off' if args.no_evolve else f'every {args.evolve_every}'}")
    if real_mode:
        print(f"  mode=REAL PACKETS  target={args.real}")
        print(f"  Packets travel over Wi-Fi — IDS captures them via live scapy")
    elif remote_mode:
        print(f"  mode=REMOTE  ids={args.remote}:{args.remote_port}")
    else:
        print(f"  mode=LOCAL  targets={'synthetic' if args.synthetic else 'auto-scan'}"
              + (f"  forced={args.target}" if args.target else ""))
    print(f"  profile={'all (evolved)' if not args.profile else args.profile}\n")

    start_time = time.time()

    # Real packet mode
    if real_mode:
        from attacker.packet_sender import PacketSender
        from attacker.mutator import MutationEngine

        mutator = MutationEngine()
        sender  = PacketSender(
            target_ip  = args.real,
            on_status  = lambda m: print(f"  {m}"),
            rate_limit = args.rate,
        )
        stop_event = threading.Event()

        def _shutdown_real(sig=None, frame=None):
            stop_event.set()
            sender.stop()

        signal.signal(signal.SIGINT,  _shutdown_real)
        signal.signal(signal.SIGTERM, _shutdown_real)

        print(f"  Sending real packets to {args.real} — press Ctrl+C to stop\n")
        attack_count = 0
        active_threads = []

        try:
            while not stop_event.is_set():
                pf = mutator.select_profile() if not args.profile else \
                     next((p for p in mutator.population if p.name == args.profile),
                          mutator.select_profile())

                t = sender.start_profile(
                    pf.name, pf.params,
                    count=random.randint(10, 40),
                )
                active_threads.append(t)
                attack_count += 1

                if args.duration > 0 and \
                   (time.time() - start_time) >= args.duration:
                    break

                time.sleep(random.uniform(args.rate, args.rate * 3))

                if attack_count % args.evolve_every == 0 and not args.no_evolve:
                    mutator.evolve()
                    print(f"  [evolved] gen={mutator._gen}  "
                          f"pop={len(mutator.population)}")

        except SystemExit:
            pass

        sender.stop()
        st = sender.stats
        print(f"\n  Done — real packets sent={st['sent']}  errors={st['errors']}")
        print(f"  Check the IDS dashboard on the other machine.\n")
        return

    # Remote mode: use TCP sender as the event bus
    if remote_mode:
        from attacker.remote_sender import RemoteAttackSender
        bus = RemoteAttackSender(
            ids_host     = args.remote,
            port         = args.remote_port,
            feedback_port= args.remote_port + 3,   # 9878
            on_status    = lambda m: print(f"  {m}"),
        )
        bus.start()
        db = None   # no local DB in remote mode — IDS machine owns it
        print(f"  Connecting to IDS at {args.remote}:{args.remote_port} ...")
        import time as _t; _t.sleep(1.5)   # give connection time
        perf_stats = None
    else:
        from event_bus import EventBus
        bus = EventBus()
        _, _, _, db, perf_stats = _build_pipeline(bus)

    attacker = AttackEngine(
        event_bus         = bus,
        synthetic_targets = args.synthetic or bool(args.target) or remote_mode,
        rate_limit        = args.rate,
        evolve_interval   = args.evolve_every if not args.no_evolve else 999999,
        locked_profile    = args.profile or None,
        forced_target     = args.target  or None,
        on_status         = lambda m: print(f"  {m}"),
    )

    stop_event = threading.Event()
    attacker.start()
    attacker._duration_s = args.duration
    attacker._start_time = start_time

    printer = threading.Thread(
        target=_live_printer, args=(attacker, stop_event), daemon=True)
    printer.start()

    def _shutdown(sig=None, frame=None):
        stop_event.set()
        attacker.stop()
        
        # Allow pipeline queues to flush
        time.sleep(1.0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        while getattr(attacker, '_running', True) and not stop_event.is_set() and (not args.duration or (time.time() - start_time) < args.duration):
            time.sleep(0.2)
    except KeyboardInterrupt:
        stop_event.set()
    except SystemExit:
        pass

    _shutdown()

    # End-of-session report
    if not remote_mode and db is not None:
        report = _build_report(attacker, db, start_time)
        _print_report(report, perf_stats, db)
        with open(REPORT_FILE, "w") as f:
            json.dump(report, f, indent=2)
        _write_evaders_to_db(report, db)
        db.export_ids_signatures()
    else:
        # Remote mode — build and save report locally too
        # ✓ FIX: Write session_report.json even in remote mode
        st = attacker.stats
        sent = st["total_sent"]
        evade_pct = (st["total_evaded"] / max(sent, 1)) * 100
        
        # Build report from attacker stats
        outcomes = attacker.recent_outcomes(200)
        by_profile = {}
        for o in outcomes:
            pn = o.get("profile", "unknown")
            if pn not in by_profile:
                by_profile[pn] = {"sent": 0, "blocked": 0, "evaded": 0, "alerted": 0}
            by_profile[pn]["sent"] += 1
            d = o.get("decision", "Ignore")
            if d in ("Block", "Escalate"):
                by_profile[pn]["blocked"] += 1
            elif d in ("Ignore", "Log"):
                by_profile[pn]["evaded"] += 1
            else:
                by_profile[pn]["alerted"] += 1
        
        evaded_profiles = sorted(
            [{"profile": k, **v, "evasion_rate": round(v["evaded"] / max(v["sent"], 1), 3)}
             for k, v in by_profile.items()],
            key=lambda x: -x["evasion_rate"],
        )
        
        report = {
            "session": {
                "start": datetime.fromtimestamp(start_time).isoformat(),
                "end": datetime.now().isoformat(),
                "duration_s": round(time.time() - start_time, 1),
                "total_sent": sent,
                "total_blocked": st["total_blocked"],
                "total_evaded": st["total_evaded"],
                "total_alerted": st["total_alerted"],
                "generations": st["generation"],
            },
            "evaded_profiles": evaded_profiles,
            "top_evaders": [p for p in evaded_profiles if p["evasion_rate"] > 0.5][:5],
            "population_final": attacker.population_stats(),
        }
        
        # Write report locally
        with open(REPORT_FILE, "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n  Session ended — sent={sent}  "
              f"evaded={st['total_evaded']} ({evade_pct:.0f}%)  "
              f"blocked={st['total_blocked']}  gen={st['generation']}")
        print(f"  Report saved to: {REPORT_FILE}\n")

    # Force process exit to avoid zombie threads keeping it alive
    import os
    os._exit(0)


if __name__ == "__main__":
    main()
